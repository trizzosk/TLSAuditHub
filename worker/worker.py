from celery import Celery
from sslyze import (
    HttpProxySettings,
    Scanner,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ServerNetworkLocation,
    ServerScanRequest,
)
from sqlalchemy import text
from shared.database import SessionLocal
from datetime import datetime, timedelta
import ipaddress
import os
import socket
import uuid
import json
import re
import ssl
import inspect
from concurrent.futures import ThreadPoolExecutor, as_completed
from fnmatch import fnmatchcase
from diff import diff_sets, diff_dict
from normalize import normalize_scan

from celery.schedules import crontab
import dns.resolver
import whois
from urllib.request import (
    HTTPHandler,
    HTTPSHandler,
    HTTPRedirectHandler,
    Request,
    build_opener,
    urlopen,
)
from urllib.error import HTTPError, URLError
import urllib.parse

DNS_SCOPE_VALUES = {"system", "private", "public"}

celery = Celery(
    "worker",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0"),
)

celery.conf.beat_schedule = {
    "evaluate-scan-schedule-every-minute": {
        "task": "worker.maybe_run_scheduled_scans",
        "schedule": crontab(minute="*"),
        "args": (),
    }
}


def ensure_scheduler_config_table(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS scheduler_config (
                id INT PRIMARY KEY DEFAULT 1,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                frequency TEXT NOT NULL DEFAULT 'daily',
                day_of_week INT NOT NULL DEFAULT 1,
                hour INT NOT NULL DEFAULT 2,
                minute INT NOT NULL DEFAULT 0,
                interval_minutes INT NOT NULL DEFAULT 1440,
                last_run_at TIMESTAMP NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT now(),
                CONSTRAINT scheduler_config_singleton CHECK (id = 1),
                CONSTRAINT scheduler_frequency_valid CHECK (
                    frequency IN ('hourly', 'daily', 'weekly', 'interval')
                ),
                CONSTRAINT scheduler_day_valid CHECK (day_of_week BETWEEN 0 AND 6),
                CONSTRAINT scheduler_hour_valid CHECK (hour BETWEEN 0 AND 23),
                CONSTRAINT scheduler_minute_valid CHECK (minute BETWEEN 0 AND 59),
                CONSTRAINT scheduler_interval_valid CHECK (
                    interval_minutes BETWEEN 1 AND 10080
                )
            )
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO scheduler_config
            (id, enabled, frequency, day_of_week, hour, minute, interval_minutes)
            VALUES (1, TRUE, 'daily', 1, 2, 0, 1440)
            ON CONFLICT (id) DO NOTHING
            """
        )
    )
    db.commit()


def ensure_scans_error_message_column(db):
    db.execute(
        text(
            """
            ALTER TABLE scans
            ADD COLUMN IF NOT EXISTS error_message TEXT
            """
        )
    )
    db.commit()


def _py_weekday_from_sunday_first(day_of_week: int) -> int:
    # Python weekday: Monday=0..Sunday=6; config stores Sunday=0..Saturday=6.
    return (int(day_of_week) + 6) % 7


def _latest_scheduled_slot(now: datetime, config: dict) -> datetime | None:
    frequency = str(config.get("frequency") or "daily").strip().lower()
    hour = int(config.get("hour") or 0)
    minute = int(config.get("minute") or 0)

    if frequency == "hourly":
        slot = now.replace(minute=minute, second=0, microsecond=0)
        if slot > now:
            slot -= timedelta(hours=1)
        return slot

    if frequency == "daily":
        slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if slot > now:
            slot -= timedelta(days=1)
        return slot

    if frequency == "weekly":
        target_weekday = _py_weekday_from_sunday_first(
            int(config.get("day_of_week") or 0)
        )
        slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        days_back = (slot.weekday() - target_weekday) % 7
        slot -= timedelta(days=days_back)
        if slot > now:
            slot -= timedelta(days=7)
        return slot

    return None


def _is_schedule_due(now: datetime, config: dict, last_run_at) -> tuple[bool, str]:
    if not bool(config.get("enabled")):
        return False, "disabled"

    frequency = str(config.get("frequency") or "daily").strip().lower()
    if frequency == "interval":
        interval_minutes = max(1, int(config.get("interval_minutes") or 1))
        if last_run_at is None:
            return True, "first_interval_run"
        if now - last_run_at >= timedelta(minutes=interval_minutes):
            return True, "interval_elapsed"
        return False, "interval_not_elapsed"

    slot = _latest_scheduled_slot(now, config)
    if slot is None:
        return False, "unsupported_frequency"
    if last_run_at is None:
        return True, "first_slot_run"
    if last_run_at < slot:
        return True, "new_slot_due"
    return False, "already_ran_for_slot"


@celery.task
def maybe_run_scheduled_scans():
    db = SessionLocal()
    now = datetime.utcnow().replace(second=0, microsecond=0)
    try:
        ensure_scheduler_config_table(db)
        row = db.execute(
            text(
                """
                SELECT
                  enabled,
                  frequency,
                  day_of_week,
                  hour,
                  minute,
                  interval_minutes,
                  last_run_at
                FROM scheduler_config
                WHERE id = 1
                FOR UPDATE
                """
            )
        ).fetchone()
        if not row:
            return {"status": "skipped", "reason": "missing_config"}

        data = dict(row._mapping)
        config = {
            "enabled": bool(data.get("enabled")),
            "frequency": data.get("frequency") or "daily",
            "day_of_week": int(data.get("day_of_week") or 0),
            "hour": int(data.get("hour") or 0),
            "minute": int(data.get("minute") or 0),
            "interval_minutes": int(data.get("interval_minutes") or 1),
        }
        due, reason = _is_schedule_due(now, config, data.get("last_run_at"))
        if not due:
            db.rollback()
            return {"status": "skipped", "reason": reason}

        db.execute(
            text(
                """
                UPDATE scheduler_config
                SET last_run_at=:run_at, updated_at=now()
                WHERE id = 1
                """
            ),
            {"run_at": now},
        )
        db.commit()
    finally:
        db.close()

    run_scheduled_scans.delay()
    return {"status": "queued", "reason": "due"}

@celery.task
def run_scheduled_scans():
    db = SessionLocal()
    try:
        _ensure_targets_check_columns(db)
        rows = db.execute(
            text(
                """
                SELECT id
                FROM targets
                WHERE enabled = true
                  AND tls_checks_enabled = true
                """
            )
        ).fetchall()
    finally:
        db.close()

    for row in rows:
        run_scan.delay(str(row._mapping["id"]))


@celery.task
def run_scan(target_id: str):
    db = SessionLocal()
    scan_id = None

    try:
        _ensure_targets_dns_scope_column(db)
        _ensure_targets_check_columns(db)
        ensure_scans_error_message_column(db)
        target_row = db.execute(
            text(
                """
                SELECT hostname, port, dns_scope, tls_checks_enabled
                FROM targets
                WHERE id=:id
                """
            ),
            {"id": target_id},
        ).fetchone()
        if not target_row:
            return
        target = target_row._mapping
        if not bool(target.get("tls_checks_enabled")):
            return

        scan_id = str(uuid.uuid4())
        db.execute(
            text("""
                INSERT INTO scans (id, target_id, started_at, status)
                VALUES (:sid, :tid, :start, 'running')
            """),
            {"sid": scan_id, "tid": target_id, "start": datetime.utcnow()},
        )
        db.commit()

        proxy_cfg = _get_proxy_config(db)
        proxy_settings = None
        if (
            proxy_cfg["enabled"]
            and proxy_cfg["host"]
            and proxy_cfg["port"] > 0
            and _should_use_proxy(target["hostname"], proxy_cfg)
        ):
            proxy_settings = HttpProxySettings(
                hostname=proxy_cfg["host"],
                port=proxy_cfg["port"],
                basic_auth_user=proxy_cfg["username"] or None,
                basic_auth_password=proxy_cfg["password"] or None,
            )

        scanner = Scanner()
        dns_scope = _normalize_dns_scope(target.get("dns_scope"))
        resolved_ip = _resolve_scan_ip(target["hostname"], dns_scope)
        server_location = _make_server_location(
            hostname=target["hostname"],
            port=target["port"],
            proxy_settings=proxy_settings,
            resolved_ip=resolved_ip,
        )
        scan_commands = {
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.HTTP_HEADERS,
            ScanCommand.HEARTBLEED,
            ScanCommand.ROBOT,
            ScanCommand.SESSION_RENEGOTIATION,
            ScanCommand.TLS_COMPRESSION,
            ScanCommand.TLS_FALLBACK_SCSV,
        }
        if hasattr(ScanCommand, "ELLIPTIC_CURVES"):
            scan_commands.add(ScanCommand.ELLIPTIC_CURVES)

        request = ServerScanRequest(
            server_location=server_location,
            scan_commands=scan_commands,
        )
        scanner.queue_scans([request])

        for server_result in scanner.get_results():
            for plugin_name, plugin_result in _extract_plugin_results(
                server_result, target["hostname"], target["port"]
            ):
                db.execute(
                    text("""
                        INSERT INTO scan_results (scan_id, plugin, result)
                        VALUES (:sid, :p, CAST(:r AS jsonb))
                    """),
                    {
                        "sid": scan_id,
                        "p": plugin_name,
                        "r": json.dumps(plugin_result),
                    },
                )

        db.execute(
            text("""
                UPDATE scans
                SET finished_at=:end, status='done', error_message=NULL
                WHERE id=:sid
            """),
            {"end": datetime.utcnow(), "sid": scan_id},
        )
        db.commit()

        prev_scan = db.execute(
            text("""
            SELECT id FROM scans
            WHERE target_id=:tid AND status='done'
            ORDER BY finished_at DESC
            OFFSET 1 LIMIT 1
            """),
            {"tid": target_id},
        ).fetchone()

        if prev_scan:
            prev_scan_id = prev_scan._mapping["id"]
            old_norm = normalize_scan(load_results(db, prev_scan_id))
            new_norm = normalize_scan(load_results(db, scan_id))

            diff = {}

            cipher_diff = diff_sets(
                old_norm["cipher_suites"], new_norm["cipher_suites"]
            )
            if cipher_diff["added"] or cipher_diff["removed"]:
                diff["cipher_suites"] = cipher_diff

            tls_diff = diff_sets(
                old_norm["tls_versions"], new_norm["tls_versions"]
            )
            if tls_diff["added"] or tls_diff["removed"]:
                diff["tls_versions"] = tls_diff

            cert_diff = diff_dict(
                old_norm["certificate"], new_norm["certificate"]
            )
            if cert_diff:
                diff["certificate"] = {"changed": cert_diff}

            if diff:
                db.execute(
                    text("""
                        INSERT INTO scan_diffs
                        (target_id, old_scan_id, new_scan_id, diff)
                        VALUES (:tid, :old, :new, CAST(:diff AS jsonb))
                    """),
                    {
                        "tid": target_id,
                        "old": prev_scan_id,
                        "new": scan_id,
                        "diff": json.dumps(diff),
                    },
                )
                db.commit()
    except Exception as exc:
        if scan_id:
            db.execute(
                text("""
                    UPDATE scans
                    SET finished_at=:end, status='failed', error_message=:err
                    WHERE id=:sid
                """),
                {
                    "end": datetime.utcnow(),
                    "sid": scan_id,
                    "err": str(exc)[:2000],
                },
            )
            db.commit()
        raise
    finally:
        db.close()


@celery.task
def run_dns_lookup(target_id: str):
    db = SessionLocal()
    try:
        _ensure_target_dns_table(db)
        _ensure_targets_dns_scope_column(db)
        _ensure_targets_check_columns(db)
        row = db.execute(
            text(
                """
                SELECT hostname, dns_scope
                FROM targets
                WHERE id=:id
                """
            ),
            {"id": target_id},
        ).fetchone()
        if not row:
            return
        hostname = row._mapping["hostname"]
        dns_scope = _normalize_dns_scope(row._mapping.get("dns_scope"))
        dkim_cfg = _get_dkim_config(db)
        payload = _build_dns_payload(hostname, dns_scope, dkim_cfg)
        db.execute(
            text(
                """
                INSERT INTO target_dns (target_id, data, updated_at)
                VALUES (:tid, CAST(:data AS jsonb), now())
                ON CONFLICT (target_id)
                DO UPDATE SET data=EXCLUDED.data, updated_at=now()
                """
            ),
            {"tid": target_id, "data": json.dumps(payload)},
        )
        db.commit()
    finally:
        db.close()


def _extract_plugin_results(server_result, hostname, port):
    if not server_result.scan_result:
        return []

    extracted = []

    def _enum_name(value):
        name = getattr(value, "name", None)
        if name:
            return str(name)
        return str(value or "").strip()

    cert_attempt = server_result.scan_result.certificate_info
    if (
        cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and cert_attempt.result is not None
    ):
        extracted.append(
            (
                "certificate_info",
                _serialize_certificate_info(cert_attempt.result),
            )
        )

    ssl2_attempt = server_result.scan_result.ssl_2_0_cipher_suites
    if ssl2_attempt.result is not None:
        extracted.append(
            (
                "ssl_2_0_cipher_suites",
                {
                    "accepted_cipher_suites": [
                        item.cipher_suite.name
                        for item in ssl2_attempt.result.accepted_cipher_suites
                    ],
                    "is_protocol_supported": bool(
                        ssl2_attempt.result.is_tls_version_supported
                    ),
                },
            )
        )

    ssl3_attempt = server_result.scan_result.ssl_3_0_cipher_suites
    if ssl3_attempt.result is not None:
        extracted.append(
            (
                "ssl_3_0_cipher_suites",
                {
                    "accepted_cipher_suites": [
                        item.cipher_suite.name
                        for item in ssl3_attempt.result.accepted_cipher_suites
                    ],
                    "is_protocol_supported": bool(
                        ssl3_attempt.result.is_tls_version_supported
                    ),
                },
            )
        )

    tls10_attempt = server_result.scan_result.tls_1_0_cipher_suites
    if tls10_attempt.result is not None:
        extracted.append(
            (
                "tls_1_0_cipher_suites",
                {
                    "accepted_cipher_suites": [
                        item.cipher_suite.name
                        for item in tls10_attempt.result.accepted_cipher_suites
                    ],
                    "is_protocol_supported": bool(
                        tls10_attempt.result.is_tls_version_supported
                    ),
                },
            )
        )

    tls11_attempt = server_result.scan_result.tls_1_1_cipher_suites
    if tls11_attempt.result is not None:
        extracted.append(
            (
                "tls_1_1_cipher_suites",
                {
                    "accepted_cipher_suites": [
                        item.cipher_suite.name
                        for item in tls11_attempt.result.accepted_cipher_suites
                    ],
                    "is_protocol_supported": bool(
                        tls11_attempt.result.is_tls_version_supported
                    ),
                },
            )
        )

    tls12_attempt = server_result.scan_result.tls_1_2_cipher_suites
    if tls12_attempt.result is not None:
        extracted.append(
            (
                "tls_1_2_cipher_suites",
                {
                    "accepted_cipher_suites": [
                        item.cipher_suite.name
                        for item in tls12_attempt.result.accepted_cipher_suites
                    ],
                    "is_protocol_supported": bool(
                        tls12_attempt.result.is_tls_version_supported
                    ),
                },
            )
        )

    tls13_attempt = server_result.scan_result.tls_1_3_cipher_suites
    if tls13_attempt.result is not None:
        extracted.append(
            (
                "tls_1_3_cipher_suites",
                {
                    "accepted_cipher_suites": [
                        item.cipher_suite.name
                        for item in tls13_attempt.result.accepted_cipher_suites
                    ],
                    "is_protocol_supported": bool(
                        tls13_attempt.result.is_tls_version_supported
                    ),
                },
            )
        )

    curve_attempt = getattr(server_result.scan_result, "elliptic_curves", None)
    if curve_attempt is not None and curve_attempt.result is not None:
        groups = []
        seen = set()
        for attr_name in (
            "supported_curves",
            "accepted_curves",
            "supported_groups",
            "accepted_groups",
            "curves",
        ):
            values = getattr(curve_attempt.result, attr_name, None) or []
            for value in values:
                name = _enum_name(value)
                if not name:
                    continue
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                groups.append(name)

        extracted.append(
            (
                "elliptic_curves",
                {
                    "supported_groups": groups,
                    "groups_count": len(groups),
                },
            )
        )

    headers_attempt = server_result.scan_result.http_headers
    if headers_attempt.result is not None:
        extracted.append(
            (
                "http_headers",
                _serialize_http_headers(
                    headers_attempt.result, hostname, port
                ),
            )
        )

    heartbleed_attempt = server_result.scan_result.heartbleed
    if heartbleed_attempt.result is not None:
        extracted.append(
            (
                "heartbleed",
                {
                    "is_vulnerable_to_heartbleed": bool(
                        heartbleed_attempt.result.is_vulnerable_to_heartbleed
                    ),
                },
            )
        )

    robot_attempt = server_result.scan_result.robot
    if robot_attempt.result is not None:
        extracted.append(
            (
                "robot",
                {
                    "robot_result": str(robot_attempt.result.robot_result.value),
                },
            )
        )

    reneg_attempt = server_result.scan_result.session_renegotiation
    if reneg_attempt.result is not None:
        extracted.append(
            (
                "session_renegotiation",
                {
                    "supports_secure_renegotiation": bool(
                        reneg_attempt.result.supports_secure_renegotiation
                    ),
                    "is_vulnerable_to_client_renegotiation_dos": bool(
                        reneg_attempt.result
                        .is_vulnerable_to_client_renegotiation_dos
                    ),
                    "client_renegotiations_success_count": int(
                        reneg_attempt.result.client_renegotiations_success_count
                    ),
                },
            )
        )

    compression_attempt = server_result.scan_result.tls_compression
    if compression_attempt.result is not None:
        extracted.append(
            (
                "tls_compression",
                {
                    "supports_compression": bool(
                        compression_attempt.result.supports_compression
                    ),
                },
            )
        )

    fallback_attempt = server_result.scan_result.tls_fallback_scsv
    if fallback_attempt.result is not None:
        extracted.append(
            (
                "tls_fallback_scsv",
                {
                    "supports_fallback_scsv": bool(
                        fallback_attempt.result.supports_fallback_scsv
                    ),
                },
            )
        )

    return extracted


def _get_proxy_config(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS proxy_config (
                id INT PRIMARY KEY DEFAULT 1,
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                host TEXT NOT NULL DEFAULT '',
                port INT NOT NULL DEFAULT 8080,
                username TEXT NOT NULL DEFAULT '',
                password TEXT NOT NULL DEFAULT '',
                no_proxy_patterns TEXT NOT NULL DEFAULT '',
                updated_at TIMESTAMP NOT NULL DEFAULT now(),
                CONSTRAINT proxy_config_singleton CHECK (id = 1)
            )
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE proxy_config
            ADD COLUMN IF NOT EXISTS no_proxy_patterns TEXT NOT NULL DEFAULT ''
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO proxy_config
            (id, enabled, host, port, username, password, no_proxy_patterns)
            VALUES (1, FALSE, '', 8080, '', '', '')
            ON CONFLICT (id) DO NOTHING
            """
        )
    )
    db.commit()

    row = db.execute(
        text(
            """
            SELECT enabled, host, port, username, password, no_proxy_patterns
            FROM proxy_config
            WHERE id = 1
            """
        )
    ).fetchone()
    data = dict(row._mapping)
    return {
        "enabled": bool(data["enabled"]),
        "host": (data["host"] or "").strip(),
        "port": int(data["port"] or 0),
        "username": (data["username"] or "").strip(),
        "password": data["password"] or "",
        "no_proxy_patterns": data["no_proxy_patterns"] or "",
    }


def _get_dkim_config(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS dkim_config (
                id INT PRIMARY KEY DEFAULT 1,
                selectors_text TEXT NOT NULL DEFAULT '',
                updated_at TIMESTAMP NOT NULL DEFAULT now(),
                CONSTRAINT dkim_config_singleton CHECK (id = 1)
            )
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO dkim_config (id, selectors_text)
            VALUES (1, :selectors_text)
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {"selectors_text": os.environ.get("DKIM_SELECTORS", "")},
    )
    db.commit()

    row = db.execute(
        text(
            """
            SELECT selectors_text, updated_at
            FROM dkim_config
            WHERE id = 1
            """
        )
    ).fetchone()
    data = dict(row._mapping) if row else {}
    return {
        "selectors_text": str(data.get("selectors_text") or ""),
        "updated_at": data.get("updated_at"),
    }


def _ensure_target_dns_table(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS target_dns (
                target_id UUID PRIMARY KEY REFERENCES targets(id),
                data JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMP NOT NULL DEFAULT now()
            )
            """
        )
    )
    db.commit()


def _ensure_targets_dns_scope_column(db):
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD COLUMN IF NOT EXISTS dns_scope TEXT NOT NULL DEFAULT 'system'
            """
        )
    )
    db.execute(
        text(
            """
            UPDATE targets
            SET dns_scope='system'
            WHERE dns_scope IS NULL OR trim(dns_scope) = ''
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE targets
            DROP CONSTRAINT IF EXISTS targets_dns_scope_check
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD CONSTRAINT targets_dns_scope_check
            CHECK (dns_scope IN ('system', 'private', 'public'))
            """
        )
    )
    db.commit()


def _ensure_targets_check_columns(db):
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD COLUMN IF NOT EXISTS dns_checks_enabled BOOLEAN NOT NULL DEFAULT TRUE
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD COLUMN IF NOT EXISTS tls_checks_enabled BOOLEAN NOT NULL DEFAULT TRUE
            """
        )
    )
    db.execute(
        text(
            """
            UPDATE targets
            SET dns_checks_enabled=TRUE
            WHERE dns_checks_enabled IS NULL
            """
        )
    )
    db.execute(
        text(
            """
            UPDATE targets
            SET tls_checks_enabled=TRUE
            WHERE tls_checks_enabled IS NULL
            """
        )
    )
    db.commit()


def _safe_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def _split_csv_env(value):
    if not value:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _env_float(name, default):
    raw = os.environ.get(name, str(default))
    try:
        return float(raw)
    except Exception:
        return float(default)


def _env_int(name, default, minimum=1):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except Exception:
        value = int(default)
    return max(minimum, value)


def _dns_config():
    nameservers = _split_csv_env(os.environ.get("DNS_NAMESERVERS", ""))
    lifetime = _env_float("DNS_LIFETIME_SECONDS", 8)
    timeout = _env_float("DNS_TIMEOUT_SECONDS", 3)
    attempts = _env_int("DNS_ATTEMPTS", 2, minimum=1)
    use_search = os.environ.get("DNS_USE_SEARCH", "true").strip().lower() in {
        "1", "true", "yes", "on"
    }
    return {
        "nameservers": nameservers,
        "lifetime": lifetime,
        "timeout": timeout,
        "attempts": attempts,
        "use_search": use_search,
    }


def _normalize_dns_scope(value):
    scope = str(value or "system").strip().lower()
    if scope not in DNS_SCOPE_VALUES:
        return "system"
    return scope


def _dns_config_for_scope(scope):
    base = _dns_config()
    scope_name = _normalize_dns_scope(scope)
    if scope_name == "private":
        private_ns = _split_csv_env(os.environ.get("DNS_PRIVATE_NAMESERVERS", ""))
        if private_ns:
            base["nameservers"] = private_ns
    elif scope_name == "public":
        public_ns = _split_csv_env(os.environ.get("DNS_PUBLIC_NAMESERVERS", ""))
        if public_ns:
            base["nameservers"] = public_ns
    base["scope"] = scope_name
    return base


def _build_dns_resolver(cfg):
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = cfg["lifetime"]
    resolver.timeout = cfg["timeout"]
    resolver.use_search_by_default = cfg["use_search"]
    if cfg["nameservers"]:
        resolver.nameservers = cfg["nameservers"]
    return resolver


def _resolve_scan_ip(hostname, dns_scope):
    host = str(hostname or "").strip()
    if not host:
        return ""
    if _is_ip_address(host):
        return host
    if _normalize_dns_scope(dns_scope) == "system":
        return ""

    cfg = _dns_config_for_scope(dns_scope)
    resolver = _build_dns_resolver(cfg)
    attempts = cfg["attempts"]
    a_records, _ = _resolve_records(host, "A", resolver, attempts)
    if a_records:
        return str(a_records[0])
    aaaa_records, _ = _resolve_records(host, "AAAA", resolver, attempts)
    if aaaa_records:
        return str(aaaa_records[0])
    return ""


def _make_server_location(hostname, port, proxy_settings, resolved_ip=""):
    kwargs = {
        "hostname": hostname,
        "port": port,
        "http_proxy_settings": proxy_settings,
    }
    # SSLyze does not allow ip_address together with http_proxy_settings.
    # When proxy is enabled, proxy performs DNS resolution itself.
    if resolved_ip and proxy_settings is None:
        try:
            params = inspect.signature(ServerNetworkLocation).parameters
            if "ip_address" in params:
                kwargs["ip_address"] = resolved_ip
        except Exception:
            pass
    return ServerNetworkLocation(**kwargs)


def _classify_dns_error(exc):
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "NXDOMAIN"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "NO_ANSWER"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "NO_NAMESERVERS"
    if isinstance(exc, dns.exception.Timeout):
        return "TIMEOUT"
    return exc.__class__.__name__.upper()


def _resolve_records(name, rdtype, resolver, attempts):
    last_exc = None
    tries = max(1, int(attempts))
    for attempt in range(1, tries + 1):
        try:
            answers = resolver.resolve(name, rdtype)
            records = []
            for rdata in answers:
                if rdtype == "NS":
                    records.append(str(rdata.target).rstrip("."))
                elif rdtype == "MX":
                    records.append(
                        {
                            "preference": int(rdata.preference),
                            "exchange": str(rdata.exchange).rstrip("."),
                        }
                    )
                elif rdtype == "TXT":
                    parts = []
                    if hasattr(rdata, "strings"):
                        for part in rdata.strings:
                            if isinstance(part, bytes):
                                parts.append(part.decode(errors="replace"))
                            else:
                                parts.append(str(part))
                    else:
                        parts.append(str(rdata))
                    records.append("".join(parts))
                else:
                    records.append(str(rdata))
            return records, {
                "ok": True,
                "error_code": "",
                "error": "",
                "attempts": attempt,
                "query": {"name": name, "type": rdtype},
            }
        except Exception as exc:
            last_exc = exc
            code = _classify_dns_error(exc)
            # Retrying NXDOMAIN/NO_ANSWER is not useful.
            if code in {"NXDOMAIN", "NO_ANSWER"}:
                break

    return [], {
        "ok": False,
        "error_code": _classify_dns_error(last_exc) if last_exc else "UNKNOWN",
        "error": str(last_exc) if last_exc else "Unknown DNS resolution error",
        "attempts": tries,
        "query": {"name": name, "type": rdtype},
    }


def _resolve_soa_for_host_or_zone(hostname, resolver, attempts):
    host = str(hostname or "").strip().rstrip(".")
    if not host:
        return [], "", {
            "ok": False,
            "error_code": "EMPTY_HOST",
            "error": "Hostname is empty",
            "attempts": 0,
            "query": {"name": "", "type": "SOA"},
            "searched": [],
        }

    labels = [part for part in host.split(".") if part]
    # Query host first, then parent zones until TLD boundary.
    candidates = [
        ".".join(labels[i:]) for i in range(0, max(len(labels) - 1, 1))
    ]
    searched = []
    last_meta = None
    for candidate in candidates:
        searched.append(candidate)
        records, meta = _resolve_records(candidate, "SOA", resolver, attempts)
        last_meta = meta
        if records:
            meta["searched"] = searched
            return records, candidate, meta
        # Stop early for hard DNS failures; continue for empty-answer style results.
        if meta["error_code"] not in {"NO_ANSWER", "NXDOMAIN"}:
            meta["searched"] = searched
            return [], "", meta

    if not last_meta:
        last_meta = {
            "ok": False,
            "error_code": "SOA_NOT_FOUND",
            "error": "SOA not found on host or parent zones",
            "attempts": 0,
            "query": {"name": host, "type": "SOA"},
        }
    last_meta["searched"] = searched
    return [], "", last_meta


def _whois_skip_suffixes():
    return [
        s.lower()
        for s in _split_csv_env(
            os.environ.get(
                "WHOIS_SKIP_SUFFIXES",
                ".internal,.local,.corp,.lan,.home,localhost",
            )
        )
    ]


def _should_skip_whois(hostname, is_ip):
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host:
        return True, "empty_host"
    if is_ip:
        return True, "ip_address"
    if "." not in host:
        return True, "single_label_hostname"
    for suffix in _whois_skip_suffixes():
        if host == suffix.lstrip(".") or host.endswith(suffix):
            return True, f"internal_suffix:{suffix}"
    return False, ""


def _resolve_host_ips(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception as exc:
        return [], {
            "ok": False,
            "error_code": exc.__class__.__name__.upper(),
            "error": str(exc),
        }

    addresses = []
    seen = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = str(sockaddr[0])
        if ip in seen:
            continue
        seen.add(ip)
        addresses.append(ip)
    return addresses, {"ok": True, "error_code": "", "error": ""}


def _reverse_ipv4_for_dnsbl(ip_value):
    try:
        ip_obj = ipaddress.ip_address(str(ip_value or "").strip())
    except Exception:
        return ""
    if ip_obj.version != 4:
        return ""
    octets = str(ip_obj).split(".")
    if len(octets) != 4:
        return ""
    return ".".join(reversed(octets))


def _query_txt_single(name, resolver, attempts):
    records, meta = _resolve_records(name, "TXT", resolver, attempts)
    value = str(records[0]).strip() if records else ""
    return value, meta


def _query_a_single(name, resolver, attempts):
    records, meta = _resolve_records(name, "A", resolver, attempts)
    value = str(records[0]).strip() if records else ""
    return value, meta


def _lookup_ip_asn_country(ip_value, resolver, attempts):
    reversed_ip = _reverse_ipv4_for_dnsbl(ip_value)
    if not reversed_ip:
        return {
            "ip": str(ip_value or ""),
            "asn": "",
            "asn_name": "",
            "prefix": "",
            "country": "",
            "registry": "",
            "allocated": "",
            "query": {"ok": False, "error_code": "UNSUPPORTED_IP_VERSION", "error": "Only IPv4 is currently supported"},
        }

    qname = f"{reversed_ip}.origin.asn.cymru.com"
    txt_value, meta = _query_txt_single(qname, resolver, attempts)
    parsed = {
        "ip": str(ip_value or ""),
        "asn": "",
        "asn_name": "",
        "prefix": "",
        "country": "",
        "registry": "",
        "allocated": "",
        "query": meta,
    }
    if not txt_value:
        return parsed

    # Team Cymru format: "AS | BGP Prefix | CC | Registry | Allocated | AS Name"
    parts = [part.strip() for part in txt_value.strip('"').split("|")]
    if parts:
        parsed["asn"] = parts[0]
    if len(parts) > 1:
        parsed["prefix"] = parts[1]
    if len(parts) > 2:
        parsed["country"] = parts[2]
    if len(parts) > 3:
        parsed["registry"] = parts[3]
    if len(parts) > 4:
        parsed["allocated"] = parts[4]
    if len(parts) > 5:
        parsed["asn_name"] = parts[5]
    return parsed


def _blacklist_dns_zones_env(name, default_value):
    return _split_csv_env(os.environ.get(name, default_value))


def _reputation_enabled():
    return str(os.environ.get("REPUTATION_ENABLE", "true")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _normalize_dnsbl_query_meta(meta, listed):
    info = dict(meta or {})
    if listed:
        return info
    code = str(info.get("error_code") or "").strip().upper()
    if code in {"NXDOMAIN", "NO_ANSWER"}:
        info["ok"] = True
        info["error_code"] = ""
        info["error"] = ""
    return info


def _check_dns_blacklists(hostname, resolved_ips, resolver, attempts):
    out = {
        "enabled": _reputation_enabled(),
        "status": "disabled",
        "listed": False,
        "listed_count": 0,
        "ip_checks": [],
        "domain_checks": [],
        "asn_country_exposure": {
            "ips_with_asn_data": 0,
            "asns": [],
            "countries": [],
        },
    }
    if not out["enabled"]:
        return out

    ip_dnsbl_zones = _blacklist_dns_zones_env(
        "REPUTATION_IP_DNSBL_ZONES",
        "zen.spamhaus.org,bl.spamcop.net",
    )
    domain_dnsbl_zones = _blacklist_dns_zones_env(
        "REPUTATION_DOMAIN_DNSBL_ZONES",
        "",
    )

    host = _normalize_host_name(hostname)
    listed_count = 0

    ips = []
    seen_ips = set()
    for value in resolved_ips or []:
        ip_text = str(value or "").strip()
        if not ip_text or ip_text in seen_ips:
            continue
        seen_ips.add(ip_text)
        ips.append(ip_text)

    asn_values = []
    country_values = []
    for ip_text in ips:
        asn_info = _lookup_ip_asn_country(ip_text, resolver, attempts)
        if asn_info.get("asn"):
            asn_values.append(str(asn_info.get("asn")))
        if asn_info.get("country"):
            country_values.append(str(asn_info.get("country")))

        reverse_ip = _reverse_ipv4_for_dnsbl(ip_text)
        zone_checks = []
        for zone in ip_dnsbl_zones:
            qname = f"{reverse_ip}.{zone}" if reverse_ip else ""
            listed_ip = False
            listed_response = ""
            query_meta = {
                "ok": False,
                "error_code": "UNSUPPORTED_IP_VERSION" if not reverse_ip else "SKIPPED",
                "error": "Only IPv4 is currently supported" if not reverse_ip else "",
            }
            if qname:
                listed_response, query_meta = _query_a_single(
                    qname, resolver, attempts
                )
                listed_ip = bool(listed_response)
                query_meta = _normalize_dnsbl_query_meta(query_meta, listed_ip)
            if listed_ip:
                listed_count += 1
            zone_checks.append(
                {
                    "zone": zone,
                    "query_name": qname,
                    "listed": listed_ip,
                    "response": listed_response,
                    "query": query_meta,
                }
            )
        out["ip_checks"].append(
            {
                "ip": ip_text,
                "asn": asn_info.get("asn") or "",
                "asn_name": asn_info.get("asn_name") or "",
                "country": asn_info.get("country") or "",
                "zones": zone_checks,
            }
        )

    for zone in domain_dnsbl_zones:
        qname = f"{host}.{zone}" if host else ""
        listed_domain = False
        listed_response = ""
        query_meta = {"ok": False, "error_code": "EMPTY_HOST", "error": "hostname empty"}
        if qname:
            listed_response, query_meta = _query_a_single(qname, resolver, attempts)
            listed_domain = bool(listed_response)
            query_meta = _normalize_dnsbl_query_meta(query_meta, listed_domain)
        if listed_domain:
            listed_count += 1
        out["domain_checks"].append(
            {
                "zone": zone,
                "query_name": qname,
                "listed": listed_domain,
                "response": listed_response,
                "query": query_meta,
            }
        )

    asn_sorted = sorted({value for value in asn_values if value})
    country_sorted = sorted({value for value in country_values if value})
    out["asn_country_exposure"] = {
        "ips_with_asn_data": len(asn_values),
        "asns": asn_sorted,
        "countries": country_sorted,
    }
    out["listed_count"] = listed_count
    out["listed"] = listed_count > 0
    out["status"] = "listed" if out["listed"] else "clean"
    return out


def _query_soa_via_nameserver(zone, ns_name, resolver, attempts):
    target_zone = str(zone or "").strip().rstrip(".")
    nameserver = _normalize_host_name(ns_name)
    if not target_zone or not nameserver:
        return {
            "nameserver": nameserver,
            "ip": "",
            "reachable": False,
            "authoritative_for_zone": False,
            "lame": True,
            "serial": "",
            "query": {"ok": False, "error_code": "INVALID_INPUT", "error": "zone or nameserver missing"},
        }

    ns_ips, ns_meta = _resolve_records(nameserver, "A", resolver, attempts)
    ns_ip = str(ns_ips[0]).strip() if ns_ips else ""
    if not ns_ip:
        return {
            "nameserver": nameserver,
            "ip": "",
            "reachable": False,
            "authoritative_for_zone": False,
            "lame": True,
            "serial": "",
            "query": ns_meta,
        }

    direct_resolver = dns.resolver.Resolver(configure=False)
    direct_resolver.nameservers = [ns_ip]
    direct_resolver.timeout = resolver.timeout
    direct_resolver.lifetime = resolver.lifetime
    tries = max(1, int(attempts))
    last_exc = None
    serial = ""
    for _ in range(tries):
        try:
            answers = direct_resolver.resolve(target_zone, "SOA")
            if answers:
                try:
                    serial = str(int(answers[0].serial))
                except Exception:
                    serial = str(getattr(answers[0], "serial", "") or "")
            return {
                "nameserver": nameserver,
                "ip": ns_ip,
                "reachable": True,
                "authoritative_for_zone": True,
                "lame": False,
                "serial": serial,
                "query": {
                    "ok": True,
                    "error_code": "",
                    "error": "",
                    "query": {"name": target_zone, "type": "SOA", "nameserver_ip": ns_ip},
                },
            }
        except Exception as exc:
            last_exc = exc
            code = _classify_dns_error(exc)
            if code in {"NXDOMAIN", "NO_ANSWER"}:
                break

    return {
        "nameserver": nameserver,
        "ip": ns_ip,
        "reachable": True,
        "authoritative_for_zone": False,
        "lame": True,
        "serial": "",
        "query": {
            "ok": False,
            "error_code": _classify_dns_error(last_exc) if last_exc else "UNKNOWN",
            "error": str(last_exc) if last_exc else "SOA query failed",
            "query": {"name": target_zone, "type": "SOA", "nameserver_ip": ns_ip},
        },
    }


def _build_authoritative_dns_health(hostname, soa_zone, ns_records, resolver, attempts):
    zone_name = str(soa_zone or hostname or "").strip().rstrip(".")
    ns_list = []
    for value in ns_records or []:
        ns_name = _normalize_host_name(value)
        if ns_name:
            ns_list.append(ns_name)

    health = {
        "zone_checked": zone_name,
        "nameserver_count": len(ns_list),
        "nameservers_reachable": 0,
        "authoritative_answer_count": 0,
        "lame_delegation_detected": False,
        "ns_consistent": True,
        "serials": [],
        "status": "unknown",
        "issues": [],
        "nameserver_checks": [],
    }

    if not ns_list:
        health["status"] = "bad"
        health["issues"].append("no_ns_records")
        return health

    for ns_name in ns_list:
        check = _query_soa_via_nameserver(zone_name, ns_name, resolver, attempts)
        health["nameserver_checks"].append(check)
        if check.get("reachable"):
            health["nameservers_reachable"] += 1
        if check.get("authoritative_for_zone"):
            health["authoritative_answer_count"] += 1

    serial_values = [
        str(item.get("serial") or "").strip()
        for item in health["nameserver_checks"]
        if item.get("authoritative_for_zone") and str(item.get("serial") or "").strip()
    ]
    dedup_serials = sorted({value for value in serial_values if value})
    health["serials"] = dedup_serials
    health["ns_consistent"] = len(dedup_serials) <= 1

    lame = any(item.get("lame") for item in health["nameserver_checks"])
    health["lame_delegation_detected"] = lame

    if health["nameservers_reachable"] == 0:
        health["issues"].append("no_nameserver_reachable")
    if health["authoritative_answer_count"] == 0:
        health["issues"].append("no_authoritative_soa_answers")
    if lame:
        health["issues"].append("lame_delegation_detected")
    if not health["ns_consistent"]:
        health["issues"].append("ns_soa_serial_inconsistency")

    if not health["issues"]:
        health["status"] = "good"
    elif "no_authoritative_soa_answers" in health["issues"] or "lame_delegation_detected" in health["issues"]:
        health["status"] = "bad"
    else:
        health["status"] = "warn"

    return health


def _extract_spf(txt_records):
    for record in txt_records:
        if str(record).lower().startswith("v=spf1"):
            return record
    return ""


def _extract_dmarc(txt_records):
    for record in txt_records:
        if str(record).lower().startswith("v=dmarc1"):
            return record
    return ""


def _parse_dmarc_policy(record):
    if not record:
        return ""
    parts = [p.strip() for p in str(record).split(";") if p.strip()]
    for part in parts:
        if part.lower().startswith("p="):
            return part.split("=", 1)[1].strip()
    return ""


def _extract_spf_tokens(spf_record):
    value = str(spf_record or "").strip()
    if not value:
        return []
    return [token.strip().lower() for token in re.split(r"\s+", value) if token.strip()]


def _extract_ms_verification_tokens(txt_records):
    tokens = []
    seen = set()
    for record in txt_records or []:
        text_value = str(record or "").strip()
        if not text_value:
            continue
        lowered = text_value.lower()
        if not lowered.startswith("ms="):
            continue
        token = text_value.split("=", 1)[1].strip()
        if not token:
            continue
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        tokens.append(token)
    return tokens


def _extract_m365_tenant_hint_from_mx(mx_exchange):
    host = _normalize_host_name(mx_exchange)
    suffix = ".mail.protection.outlook.com"
    if not host.endswith(suffix):
        return ""
    prefix = host[: -len(suffix)].strip(".")
    # Keep only tenant-style single-label prefixes.
    if not prefix or "." in prefix:
        return ""
    if not re.match(r"^[a-z0-9][a-z0-9-]{0,62}$", prefix):
        return ""
    return prefix


def _extract_tenant_id_from_microsoft_url(value):
    text_value = str(value or "").strip()
    if not text_value:
        return ""
    match = re.search(
        r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$)",
        text_value,
    )
    if not match:
        return ""
    return match.group(1).lower()


def _fetch_json_url(url, timeout_seconds=6):
    target = str(url or "").strip()
    meta = {
        "ok": False,
        "url": target,
        "status_code": None,
        "error_code": "",
        "error": "",
    }
    if not target:
        meta["error_code"] = "EMPTY_URL"
        meta["error"] = "empty_url"
        return {}, meta

    request = Request(
        target,
        method="GET",
        headers={
            "User-Agent": "TLSAuditHub/1.0",
            "Accept": "application/json",
        },
    )
    body_text = ""
    status_code = None
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(response.getcode())
            body_text = response.read().decode("utf-8", "ignore")
    except HTTPError as exc:
        status_code = int(exc.code)
        try:
            body_text = exc.read().decode("utf-8", "ignore")
        except Exception:
            body_text = ""
    except URLError as exc:
        meta["error_code"] = "URL_ERROR"
        meta["error"] = str(getattr(exc, "reason", exc) or exc)
        return {}, meta
    except Exception as exc:
        meta["error_code"] = exc.__class__.__name__.upper()
        meta["error"] = str(exc)
        return {}, meta

    meta["status_code"] = status_code
    if not body_text:
        meta["error_code"] = "EMPTY_BODY"
        meta["error"] = "empty_response_body"
        return {}, meta

    try:
        payload = json.loads(body_text)
    except Exception as exc:
        meta["error_code"] = "INVALID_JSON"
        meta["error"] = str(exc)
        return {}, meta

    if 200 <= int(status_code or 0) < 300:
        meta["ok"] = True
    else:
        meta["error_code"] = f"HTTP_{status_code}"
        meta["error"] = str(payload.get("error_description") or payload.get("error") or "http_error")
    return payload, meta


def _fetch_openid_metadata_for_domain(domain):
    checked_domain = str(domain or "").strip().lower()
    url = (
        "https://login.microsoftonline.com/"
        f"{urllib.parse.quote(checked_domain, safe='')}"
        "/v2.0/.well-known/openid-configuration"
    )
    payload, meta = _fetch_json_url(url)
    issuer = str(payload.get("issuer") or "").strip()
    token_endpoint = str(payload.get("token_endpoint") or "").strip()
    authorization_endpoint = str(payload.get("authorization_endpoint") or "").strip()
    tenant_id = (
        _extract_tenant_id_from_microsoft_url(issuer)
        or _extract_tenant_id_from_microsoft_url(token_endpoint)
        or _extract_tenant_id_from_microsoft_url(authorization_endpoint)
    )
    return {
        "domain_checked": checked_domain,
        "tenant_id": tenant_id,
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "cloud_instance_name": str(payload.get("cloud_instance_name") or "").strip(),
        "tenant_region_scope": str(payload.get("tenant_region_scope") or "").strip(),
        "tenant_region_sub_scope": str(payload.get("tenant_region_sub_scope") or "").strip(),
        "query": meta,
    }


def _fetch_user_realm_for_domain(domain):
    checked_domain = str(domain or "").strip().lower()
    probe_login = f"tlsaudithub-probe@{checked_domain}"
    query = urllib.parse.urlencode({"login": probe_login, "xml": "0"})
    url = f"https://login.microsoftonline.com/GetUserRealm.srf?{query}"
    payload, meta = _fetch_json_url(url)
    return {
        "domain_checked": checked_domain,
        "domain_name": str(payload.get("DomainName") or "").strip(),
        "namespace_type": str(payload.get("NameSpaceType") or "").strip(),
        "federation_brand_name": str(payload.get("FederationBrandName") or "").strip(),
        "auth_url": str(payload.get("AuthURL") or "").strip(),
        "federation_metadata_url": str(payload.get("FederationMetadataUrl") or "").strip(),
        "cloud_instance_name": str(payload.get("CloudInstanceName") or "").strip(),
        "query": meta,
    }


def _discover_m365_identity(hostname):
    variants = _candidate_domain_variants(hostname)
    if not variants:
        return {
            "domain_checked": "",
            "tenant_id": "",
            "issuer": "",
            "authorization_endpoint": "",
            "token_endpoint": "",
            "cloud_instance_name": "",
            "tenant_region_scope": "",
            "tenant_region_sub_scope": "",
            "namespace_type": "",
            "federation_brand_name": "",
            "auth_url": "",
            "federation_metadata_url": "",
            "openid_query": {"ok": False, "error_code": "SKIPPED_EMPTY_HOST", "error": "hostname empty"},
            "user_realm_query": {"ok": False, "error_code": "SKIPPED_EMPTY_HOST", "error": "hostname empty"},
        }

    best = None
    best_score = -1
    for domain in variants:
        openid = _fetch_openid_metadata_for_domain(domain)
        user_realm = _fetch_user_realm_for_domain(domain)
        tenant_id = str(openid.get("tenant_id") or "").strip()
        namespace_type = str(user_realm.get("namespace_type") or "").strip()
        score = 0
        if openid.get("query", {}).get("ok"):
            score += 2
        if user_realm.get("query", {}).get("ok"):
            score += 2
        if tenant_id:
            score += 3
        if namespace_type:
            score += 1
        if score > best_score:
            best_score = score
            best = {
                "domain_checked": str(openid.get("domain_checked") or domain),
                "tenant_id": tenant_id,
                "issuer": str(openid.get("issuer") or ""),
                "authorization_endpoint": str(openid.get("authorization_endpoint") or ""),
                "token_endpoint": str(openid.get("token_endpoint") or ""),
                "cloud_instance_name": str(
                    openid.get("cloud_instance_name")
                    or user_realm.get("cloud_instance_name")
                    or ""
                ),
                "tenant_region_scope": str(openid.get("tenant_region_scope") or ""),
                "tenant_region_sub_scope": str(openid.get("tenant_region_sub_scope") or ""),
                "namespace_type": namespace_type,
                "federation_brand_name": str(user_realm.get("federation_brand_name") or ""),
                "auth_url": str(user_realm.get("auth_url") or ""),
                "federation_metadata_url": str(user_realm.get("federation_metadata_url") or ""),
                "openid_query": openid.get("query") or {},
                "user_realm_query": user_realm.get("query") or {},
            }
    return best or {}


def _detect_m365_hosting(
    hostname, spf_record, txt_records, mx_records, resolver, attempts
):
    host = _normalize_host_name(hostname)
    mx_hosts = []
    for record in mx_records or []:
        if isinstance(record, dict):
            mx_hosts.append(_normalize_host_name(record.get("exchange")))
        else:
            mx_hosts.append(_normalize_host_name(record))
    mx_hosts = [value for value in mx_hosts if value]

    signals = []
    score = 0
    tenant_hints = []
    seen_tenants = set()
    outlook_mx_hosts = []
    ms_verification_tokens = _extract_ms_verification_tokens(txt_records)
    tenant_assigned = False
    service_usage = False

    for exchange in mx_hosts:
        if exchange.endswith(".mail.protection.outlook.com"):
            outlook_mx_hosts.append(exchange)
            tenant_hint = _extract_m365_tenant_hint_from_mx(exchange)
            if tenant_hint and tenant_hint not in seen_tenants:
                seen_tenants.add(tenant_hint)
                tenant_hints.append(tenant_hint)

    if outlook_mx_hosts:
        signals.append(
            f"exchange_online_mx={', '.join(outlook_mx_hosts[:4])}"
        )
        service_usage = True
        tenant_assigned = True
        score += 3

    spf_tokens = _extract_spf_tokens(spf_record)
    has_spf_o365 = any(
        token == "include:spf.protection.outlook.com"
        or token == "redirect=spf.protection.outlook.com"
        for token in spf_tokens
    )
    if has_spf_o365:
        signals.append("spf_includes_m365=spf.protection.outlook.com")
        service_usage = True
        score += 2

    if ms_verification_tokens:
        signals.append(
            "ms_verification_txt="
            + ", ".join(f"MS={token}" for token in ms_verification_tokens[:4])
        )
        tenant_assigned = True
        score += 1

    identity = _discover_m365_identity(host)
    identity_tenant_id = str(identity.get("tenant_id") or "").strip()
    identity_namespace_type = str(identity.get("namespace_type") or "").strip()
    identity_domain_checked = str(identity.get("domain_checked") or "").strip()
    if identity_tenant_id:
        signals.append(f"tenant_id={identity_tenant_id}")
        tenant_assigned = True
        score += 2
    if identity_namespace_type:
        signals.append(f"identity_namespace_type={identity_namespace_type}")
        score += 1
    if identity_domain_checked:
        signals.append(f"identity_domain_checked={identity_domain_checked}")

    autodiscover_host = f"autodiscover.{host}" if host else ""
    autodiscover_target = ""
    autodiscover_meta = {
        "ok": False,
        "error_code": "SKIPPED_EMPTY_HOST",
        "error": "hostname empty",
        "attempts": 0,
        "query": {"name": autodiscover_host, "type": "CNAME"},
    }
    if autodiscover_host:
        cname_records, autodiscover_meta = _resolve_records(
            autodiscover_host, "CNAME", resolver, attempts
        )
        if cname_records:
            autodiscover_target = _normalize_host_name(cname_records[0])
            if autodiscover_target.endswith(".outlook.com"):
                signals.append(
                    f"autodiscover_cname={autodiscover_target}"
                )
                service_usage = True
                score += 1

    hosted = bool(service_usage and tenant_assigned)
    if score >= 5:
        confidence = "high"
    elif score >= 3:
        confidence = "medium"
    elif score > 0:
        confidence = "low"
    else:
        confidence = "none"

    return {
        "hosted": hosted,
        "tenant_assigned": tenant_assigned,
        "service_usage": service_usage,
        "confidence": confidence,
        "score": score,
        "signals": signals,
        "tenant_hints": tenant_hints,
        "ms_verification_tokens": ms_verification_tokens,
        "mx_outlook_hosts": outlook_mx_hosts,
        "identity": identity,
        "autodiscover": {
            "name": autodiscover_host,
            "target": autodiscover_target,
            "query": autodiscover_meta,
        },
    }


def _env_bool(name, default):
    raw = os.environ.get(name, "true" if default else "false")
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_host_name(value):
    return str(value or "").strip().lower().rstrip(".")


def _candidate_domain_variants(domain):
    host = _normalize_host_name(domain)
    if not host or "." not in host:
        return [host] if host else []
    labels = host.split(".")
    out = []
    if len(labels) >= 3:
        out.append(".".join(labels[-3:]))
    if len(labels) >= 2:
        out.append(".".join(labels[-2:]))
    out.append(host)
    dedup = []
    seen = set()
    for item in out:
        if not item or item in seen:
            continue
        seen.add(item)
        dedup.append(item)
    return dedup


def _dkim_default_selectors():
    return [
        "selector1",
        "selector2",
        "s1",
        "s2",
        "k1",
        "k2",
        "default",
        "dkim",
        "mail",
        "mx",
        "google",
        "smtp",
        "smtpapi",
        "m1",
        "m2",
        "key1",
        "key2",
    ]


def _sanitize_selector(value):
    selector = str(value or "").strip().lower()
    if not selector:
        return ""
    if not re.match(r"^[a-z0-9][a-z0-9._-]{0,62}$", selector):
        return ""
    return selector


def _dkim_selector_candidates(dkim_cfg=None):
    raw_selectors = ""
    if isinstance(dkim_cfg, dict):
        raw_selectors = str(dkim_cfg.get("selectors_text") or "")
    if not raw_selectors:
        raw_selectors = os.environ.get("DKIM_SELECTORS", "")
    configured = [
        _sanitize_selector(v)
        for v in re.split(r"[\r\n,;]+", str(raw_selectors or ""))
    ]
    extra = [_sanitize_selector(v) for v in _split_csv_env(os.environ.get("DKIM_EXTRA_SELECTORS", ""))]
    include_defaults = _env_bool("DKIM_INCLUDE_DEFAULT_SELECTORS", True)

    out = []
    seen = set()
    for selector in configured + extra + (_dkim_default_selectors() if include_defaults else []):
        if not selector or selector in seen:
            continue
        seen.add(selector)
        out.append(selector)
    return out


def _dkim_candidate_domains(hostname, mx_records):
    out = []
    seen = set()

    def add_domains(source):
        for candidate in _candidate_domain_variants(source):
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            out.append(candidate)

    add_domains(hostname)
    for mx in mx_records or []:
        if isinstance(mx, dict):
            add_domains(mx.get("exchange"))
        else:
            add_domains(mx)
    return out


def _extract_dkim_record(txt_records):
    for record in txt_records or []:
        if str(record or "").strip().lower().startswith("v=dkim1"):
            return str(record).strip()
    return ""


def _parse_tag_pairs(record):
    tags = {}
    for part in [p.strip() for p in str(record or "").split(";") if p.strip()]:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def _dkim_key_size_hint_bits(public_key_b64):
    key = str(public_key_b64 or "").strip()
    if not key:
        return 0
    return int(len(key) * 6)


def _query_single_dkim_selector(idx, selector, domain, dns_cfg, attempts):
    fqdn = f"{selector}._domainkey.{domain}"
    resolver = _build_dns_resolver(dns_cfg)
    txt_records, meta = _resolve_records(fqdn, "TXT", resolver, attempts)
    dkim_record = _extract_dkim_record(txt_records)
    found = bool(dkim_record)
    return {
        "idx": idx,
        "selector": selector,
        "domain": domain,
        "fqdn": fqdn,
        "meta": meta,
        "dkim_record": dkim_record,
        "found": found,
    }


def _query_dkim_records(hostname, mx_records, resolver, attempts, dkim_cfg=None):
    domains = _dkim_candidate_domains(hostname, mx_records)
    selectors = _dkim_selector_candidates(dkim_cfg)
    max_queries = _env_int("DKIM_MAX_QUERIES", 48, minimum=1)
    max_parallel = min(32, _env_int("DKIM_MAX_PARALLEL", 8, minimum=1))
    early_stop_records = _env_int("DKIM_EARLY_STOP_RECORDS", 3, minimum=1)
    full_scan = _env_bool("DKIM_FULL_SCAN", False)
    query_meta = []
    records = []
    query_count = 0
    found_count = 0
    dns_cfg = {
        "nameservers": list(getattr(resolver, "nameservers", []) or []),
        "lifetime": float(getattr(resolver, "lifetime", 8)),
        "timeout": float(getattr(resolver, "timeout", 3)),
        "use_search": bool(getattr(resolver, "use_search_by_default", True)),
    }

    with ThreadPoolExecutor(max_workers=max_parallel) as pool:
        for domain in domains:
            domain_found = 0
            selector_index = 0

            while selector_index < len(selectors) and query_count < max_queries:
                if not full_scan and domain_found >= early_stop_records:
                    break

                remaining_queries = max_queries - query_count
                batch_size = min(
                    max_parallel,
                    remaining_queries,
                    len(selectors) - selector_index,
                )
                if batch_size <= 0:
                    break

                batch = selectors[selector_index : selector_index + batch_size]
                start_index = selector_index
                selector_index += batch_size

                futures = []
                for i, selector in enumerate(batch):
                    futures.append(
                        pool.submit(
                            _query_single_dkim_selector,
                            start_index + i,
                            selector,
                            domain,
                            dns_cfg,
                            attempts,
                        )
                    )

                batch_results = []
                for future in as_completed(futures):
                    try:
                        batch_results.append(future.result())
                    except Exception as exc:
                        batch_results.append(
                            {
                                "idx": -1,
                                "selector": "",
                                "domain": domain,
                                "fqdn": "",
                                "meta": {
                                    "ok": False,
                                    "error_code": exc.__class__.__name__.upper(),
                                },
                                "dkim_record": "",
                                "found": False,
                            }
                        )

                batch_results.sort(key=lambda item: int(item.get("idx", -1)))

                for result in batch_results:
                    query_count += 1
                    selector = result.get("selector") or ""
                    fqdn = result.get("fqdn") or ""
                    meta = result.get("meta") or {}
                    dkim_record = result.get("dkim_record") or ""
                    found = bool(result.get("found"))
                    if found:
                        domain_found += 1
                        found_count += 1
                        tags = _parse_tag_pairs(dkim_record)
                        key_type = str(tags.get("k") or "rsa").lower()
                        key_hint_bits = _dkim_key_size_hint_bits(tags.get("p") or "")
                        weak_key_hint = bool(
                            key_type == "rsa"
                            and key_hint_bits
                            and key_hint_bits < 2048
                        )
                        records.append(
                            {
                                "selector": selector,
                                "domain": domain,
                                "fqdn": fqdn,
                                "record": dkim_record,
                                "key_type": key_type,
                                "service": tags.get("s") or "",
                                "flags": tags.get("t") or "",
                                "public_key_present": bool(tags.get("p")),
                                "public_key_size_hint_bits": key_hint_bits,
                                "weak_key_hint": weak_key_hint,
                            }
                        )
                    if found or len(query_meta) < 24:
                        query_meta.append(
                            {
                                "selector": selector,
                                "domain": domain,
                                "fqdn": fqdn,
                                "ok": bool(meta.get("ok")),
                                "error_code": str(meta.get("error_code") or ""),
                                "found_record": found,
                            }
                        )

    return {
        "domains": domains,
        "selectors": selectors,
        "records": records,
        "query_meta": query_meta,
        "summary": {
            "queries_total": query_count,
            "queries_with_records": found_count,
            "queries_without_records": max(0, query_count - found_count),
            "selector_count": len(selectors),
            "domain_count": len(domains),
            "max_queries": max_queries,
            "max_parallel": max_parallel,
            "early_stop_records": early_stop_records,
            "full_scan": full_scan,
            "truncated": bool(query_count >= max_queries),
        },
    }


def _build_dns_payload(hostname, dns_scope="system", dkim_cfg=None):
    host = str(hostname or "").strip()
    dns_cfg = _dns_config_for_scope(dns_scope)
    resolver = _build_dns_resolver(dns_cfg)
    attempts = dns_cfg["attempts"]
    payload = {
        "hostname": host,
        "whois": {},
        "soa": [],
        "soa_zone": "",
        "a": [],
        "aaaa": [],
        "resolved_ips": [],
        "ns": [],
        "mx": [],
        "txt": [],
        "spf": "",
        "dmarc": {"record": "", "policy": "", "domain": ""},
        "m365": {
            "hosted": False,
            "tenant_assigned": False,
            "service_usage": False,
            "confidence": "none",
            "score": 0,
            "signals": [],
            "tenant_hints": [],
            "ms_verification_tokens": [],
            "mx_outlook_hosts": [],
            "identity": {
                "domain_checked": "",
                "tenant_id": "",
                "issuer": "",
                "authorization_endpoint": "",
                "token_endpoint": "",
                "cloud_instance_name": "",
                "tenant_region_scope": "",
                "tenant_region_sub_scope": "",
                "namespace_type": "",
                "federation_brand_name": "",
                "auth_url": "",
                "federation_metadata_url": "",
                "openid_query": {},
                "user_realm_query": {},
            },
            "autodiscover": {
                "name": "",
                "target": "",
                "query": {},
            },
        },
        "dns_authority": {
            "zone_checked": "",
            "nameserver_count": 0,
            "nameservers_reachable": 0,
            "authoritative_answer_count": 0,
            "lame_delegation_detected": False,
            "ns_consistent": True,
            "serials": [],
            "status": "unknown",
            "issues": [],
            "nameserver_checks": [],
        },
        "reputation": {
            "enabled": False,
            "status": "disabled",
            "listed": False,
            "listed_count": 0,
            "ip_checks": [],
            "domain_checks": [],
            "asn_country_exposure": {
                "ips_with_asn_data": 0,
                "asns": [],
                "countries": [],
            },
        },
        "dkim": {
            "domains": [],
            "selectors": [],
            "records": [],
            "summary": {
                "queries_total": 0,
                "queries_with_records": 0,
                "queries_without_records": 0,
                "selector_count": 0,
                "domain_count": 0,
                "max_queries": _env_int("DKIM_MAX_QUERIES", 48, minimum=1),
                "max_parallel": _env_int("DKIM_MAX_PARALLEL", 8, minimum=1),
                "early_stop_records": _env_int(
                    "DKIM_EARLY_STOP_RECORDS", 3, minimum=1
                ),
                "full_scan": _env_bool("DKIM_FULL_SCAN", False),
                "truncated": False,
            },
        },
        "dns_meta": {
            "config": {
                "scope": dns_cfg.get("scope", "system"),
                "nameservers": dns_cfg["nameservers"],
                "lifetime_seconds": dns_cfg["lifetime"],
                "timeout_seconds": dns_cfg["timeout"],
                "attempts": attempts,
                "use_search": dns_cfg["use_search"],
            },
            "queries": {},
        },
    }

    if not host:
        return payload

    is_ip = _is_ip_address(host)

    if not is_ip:
        soa_records, soa_zone, soa_meta = _resolve_soa_for_host_or_zone(
            host, resolver, attempts
        )
        payload["soa"] = soa_records
        payload["soa_zone"] = soa_zone
        payload["dns_meta"]["queries"]["soa"] = soa_meta

        payload["a"], payload["dns_meta"]["queries"]["a"] = _resolve_records(
            host, "A", resolver, attempts
        )
        payload["aaaa"], payload["dns_meta"]["queries"]["aaaa"] = _resolve_records(
            host, "AAAA", resolver, attempts
        )
        if dns_cfg.get("scope") == "system":
            payload["resolved_ips"], payload["dns_meta"]["queries"]["resolved_ips"] = (
                _resolve_host_ips(host)
            )
        else:
            merged = []
            seen = set()
            for ip in (payload["a"] or []) + (payload["aaaa"] or []):
                value = str(ip)
                if value in seen:
                    continue
                seen.add(value)
                merged.append(value)
            payload["resolved_ips"] = merged
            payload["dns_meta"]["queries"]["resolved_ips"] = {
                "ok": bool(merged),
                "error_code": "" if merged else "NO_IP_RECORDS",
                "error": "" if merged else "No A/AAAA records resolved",
                "source": "resolver_records",
            }
        payload["ns"], payload["dns_meta"]["queries"]["ns"] = _resolve_records(
            host, "NS", resolver, attempts
        )
        payload["dns_authority"] = _build_authoritative_dns_health(
            host,
            payload["soa_zone"],
            payload["ns"],
            resolver,
            attempts,
        )
        payload["mx"], payload["dns_meta"]["queries"]["mx"] = _resolve_records(
            host, "MX", resolver, attempts
        )
        txt_records, payload["dns_meta"]["queries"]["txt"] = _resolve_records(
            host, "TXT", resolver, attempts
        )
        payload["txt"] = txt_records
        payload["spf"] = _extract_spf(txt_records)
        payload["m365"] = _detect_m365_hosting(
            host,
            payload["spf"],
            txt_records,
            payload["mx"],
            resolver,
            attempts,
        )
        payload["reputation"] = _check_dns_blacklists(
            host,
            payload["resolved_ips"],
            resolver,
            attempts,
        )

        dmarc_domain = f"_dmarc.{host}"
        dmarc_txt, payload["dns_meta"]["queries"]["dmarc_txt"] = _resolve_records(
            dmarc_domain, "TXT", resolver, attempts
        )
        dmarc_record = _extract_dmarc(dmarc_txt)
        payload["dmarc"] = {
            "record": dmarc_record,
            "policy": _parse_dmarc_policy(dmarc_record),
            "domain": dmarc_domain,
        }
        dkim = _query_dkim_records(
            host, payload["mx"], resolver, attempts, dkim_cfg=dkim_cfg
        )
        payload["dkim"] = {
            "domains": dkim["domains"],
            "selectors": dkim["selectors"],
            "records": dkim["records"],
            "summary": dkim["summary"],
        }
        payload["dns_meta"]["queries"]["dkim_txt"] = dkim["query_meta"]
    else:
        payload["resolved_ips"] = [host]
        payload["dns_meta"]["queries"]["resolved_ips"] = {
            "ok": True,
            "error_code": "",
            "error": "",
        }
        payload["dns_meta"]["queries"]["dns"] = {
            "ok": False,
            "error_code": "SKIPPED_IP_TARGET",
            "error": "DNS record queries skipped because target is an IP address",
        }

    skip_whois, skip_reason = _should_skip_whois(host, is_ip)
    if skip_whois:
        payload["whois"] = {"skipped": True, "reason": skip_reason}
    else:
        try:
            whois_result = whois.whois(host)
            payload["whois"] = {
                "domain_name": _safe_list(getattr(whois_result, "domain_name", None)),
                "registrar": getattr(whois_result, "registrar", None),
                "creation_date": _safe_list(
                    getattr(whois_result, "creation_date", None)
                ),
                "expiration_date": _safe_list(
                    getattr(whois_result, "expiration_date", None)
                ),
                "updated_date": _safe_list(
                    getattr(whois_result, "updated_date", None)
                ),
                "name_servers": _safe_list(
                    getattr(whois_result, "name_servers", None)
                ),
            }
        except Exception as exc:
            payload["whois"] = {"error": str(exc)}

    return payload

def _parse_no_proxy_patterns(raw_patterns):
    if not raw_patterns:
        return []
    return [
        p.strip().lower()
        for p in re.split(r"[\n,;]+", raw_patterns)
        if p.strip()
    ]


def _should_use_proxy(hostname, proxy_cfg):
    host = str(hostname or "").strip().lower()
    if not host:
        return True

    for pattern in _parse_no_proxy_patterns(
        proxy_cfg.get("no_proxy_patterns", "")
    ):
        if fnmatchcase(host, pattern):
            return False
    return True


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_url_reachability(url, timeout_seconds=5):
    target = str(url or "").strip()
    if not target:
        return {
            "url": target,
            "reachable": False,
            "status_code": None,
            "error": "empty_url",
        }
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        return {
            "url": target,
            "reachable": False,
            "status_code": None,
            "error": f"unsupported_scheme:{parsed.scheme or 'unknown'}",
        }
    request = Request(
        target,
        method="HEAD",
        headers={"User-Agent": "TLSAuditHub/1.0"},
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return {
                "url": target,
                "reachable": True,
                "status_code": int(response.getcode()),
                "error": "",
            }
    except HTTPError as exc:
        return {
            "url": target,
            "reachable": True,
            "status_code": int(exc.code),
            "error": "",
        }
    except Exception as exc:
        return {
            "url": target,
            "reachable": False,
            "status_code": None,
            "error": exc.__class__.__name__,
        }


def _extract_ct_info(leaf_cert):
    info = {
        "has_embedded_scts": False,
        "embedded_scts_count": 0,
    }
    try:
        from cryptography.x509.oid import ExtensionOID

        ext = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        )
        scts = list(ext.value) if ext and ext.value is not None else []
        info["embedded_scts_count"] = len(scts)
        info["has_embedded_scts"] = bool(scts)
    except Exception:
        pass
    return info


def _extract_revocation_urls(leaf_cert):
    out = {"ocsp_urls": [], "crl_urls": []}
    try:
        from cryptography import x509
        from cryptography.x509.oid import AuthorityInformationAccessOID

        aia_ext = leaf_cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        )
        ocsp_urls = []
        for access_desc in aia_ext.value:
            if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                value = getattr(access_desc.access_location, "value", "") or ""
                if value and value not in ocsp_urls:
                    ocsp_urls.append(str(value))
        out["ocsp_urls"] = ocsp_urls
    except Exception:
        pass

    try:
        from cryptography import x509

        crl_ext = leaf_cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        )
        crl_urls = []
        for dp in crl_ext.value:
            full_names = getattr(dp, "full_name", None) or []
            for full_name in full_names:
                value = getattr(full_name, "value", "") or ""
                if value and value not in crl_urls:
                    crl_urls.append(str(value))
        out["crl_urls"] = crl_urls
    except Exception:
        pass
    return out


def _extract_ocsp_stapling_info(deployment):
    payload = {
        "present": False,
        "quality": "missing",
        "response_status": "",
        "cert_status": "",
        "this_update": "",
        "next_update": "",
        "error": "",
    }
    ocsp_blob = getattr(deployment, "ocsp_response", None)
    if not ocsp_blob:
        return payload
    payload["present"] = True
    try:
        from cryptography.x509 import ocsp

        if isinstance(ocsp_blob, str):
            ocsp_blob = ocsp_blob.encode("latin-1", "ignore")
        if not isinstance(ocsp_blob, (bytes, bytearray)):
            raise ValueError("unsupported_ocsp_blob_type")
        parsed = ocsp.load_der_ocsp_response(bytes(ocsp_blob))
        response_status = str(getattr(parsed, "response_status", "") or "")
        cert_status = str(getattr(parsed, "certificate_status", "") or "")
        this_update = getattr(parsed, "this_update", None)
        next_update = getattr(parsed, "next_update", None)
        payload["response_status"] = response_status
        payload["cert_status"] = cert_status
        payload["this_update"] = (
            this_update.isoformat() if hasattr(this_update, "isoformat") else ""
        )
        payload["next_update"] = (
            next_update.isoformat() if hasattr(next_update, "isoformat") else ""
        )
        good_response = "successful" in response_status.lower()
        good_cert = "good" in cert_status.lower()
        if good_response and good_cert:
            payload["quality"] = "good"
        elif "revoked" in cert_status.lower():
            payload["quality"] = "revoked"
        elif cert_status:
            payload["quality"] = "unknown"
        else:
            payload["quality"] = "invalid"
    except Exception as exc:
        payload["quality"] = "invalid"
        payload["error"] = exc.__class__.__name__
    return payload


def _https_url(hostname, port):
    host = str(hostname or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}:{int(port)}/"


def _probe_http_status_code(hostname, port):
    host = str(hostname or "").strip()
    if not host:
        return None

    try:
        url = _https_url(host, port)
    except Exception:
        return None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        opener = build_opener(
            _NoRedirectHandler(),
            HTTPSHandler(context=context),
            HTTPHandler(),
        )
        request = Request(
            url,
            method="GET",
            headers={"User-Agent": "TLSAuditHub/1.0"},
        )
        with opener.open(request, timeout=8) as response:
            return int(response.getcode())
    except HTTPError as exc:
        try:
            return int(exc.code)
        except Exception:
            return None
    except (URLError, TimeoutError, ssl.SSLError, OSError):
        return None
    except Exception:
        return None


def _serialize_http_headers(headers_result, hostname, port):
    hsts = headers_result.strict_transport_security_header
    hsts_payload = None
    if hsts is not None:
        hsts_payload = {
            "max_age": int(hsts.max_age),
            "include_subdomains": bool(hsts.include_subdomains),
            "preload": bool(hsts.preload),
        }

    status_code = None
    for attr in ("http_status_code", "status_code", "http_response_status_code"):
        value = getattr(headers_result, attr, None)
        if isinstance(value, int):
            status_code = value
            break
    if status_code is None:
        status_code = _probe_http_status_code(hostname, port)

    return {
        "http_status_code": status_code,
        "http_path_redirected_to": headers_result.http_path_redirected_to,
        "strict_transport_security": hsts_payload,
    }


def _serialize_certificate_info(cert_result):
    deployments = cert_result.certificate_deployments
    if not deployments:
        return {
            "certificate_chain": [],
            "certificate_transparency": {
                "has_embedded_scts": False,
                "embedded_scts_count": 0,
            },
            "revocation": {
                "ocsp_stapling": {
                    "present": False,
                    "quality": "missing",
                    "response_status": "",
                    "cert_status": "",
                    "this_update": "",
                    "next_update": "",
                    "error": "",
                },
                "basic_status": "unknown",
                "ocsp_urls": [],
                "crl_urls": [],
                "ocsp_reachability": [],
                "crl_reachability": [],
                "reachable_ocsp_count": 0,
                "reachable_crl_count": 0,
            },
        }

    deployment = deployments[0]
    leaf_cert = deployment.received_certificate_chain[0]
    not_before = getattr(
        leaf_cert, "not_valid_before_utc", leaf_cert.not_valid_before
    )
    not_after = getattr(
        leaf_cert, "not_valid_after_utc", leaf_cert.not_valid_after
    )

    san_values = []
    try:
        from cryptography import x509

        san_ext = leaf_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san_values = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        san_values = []

    ct_info = _extract_ct_info(leaf_cert)
    revocation_urls = _extract_revocation_urls(leaf_cert)
    max_revocation_urls = 4
    ocsp_reachability = [
        _http_url_reachability(url, timeout_seconds=5)
        for url in revocation_urls["ocsp_urls"][:max_revocation_urls]
    ]
    crl_reachability = [
        _http_url_reachability(url, timeout_seconds=5)
        for url in revocation_urls["crl_urls"][:max_revocation_urls]
    ]
    ocsp_stapling = _extract_ocsp_stapling_info(deployment)
    basic_status = "unknown"
    cert_status = str(ocsp_stapling.get("cert_status") or "").lower()
    if "good" in cert_status:
        basic_status = "good"
    elif "revoked" in cert_status:
        basic_status = "revoked"
    elif "unknown" in cert_status:
        basic_status = "unknown"

    return {
        "certificate_chain": [
            {
                "subject": leaf_cert.subject.rfc4514_string(),
                "issuer": leaf_cert.issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "subject_alternative_name": san_values,
            }
        ],
        "certificate_transparency": ct_info,
        "revocation": {
            "ocsp_stapling": ocsp_stapling,
            "basic_status": basic_status,
            "ocsp_urls": revocation_urls["ocsp_urls"],
            "crl_urls": revocation_urls["crl_urls"],
            "ocsp_reachability": ocsp_reachability,
            "crl_reachability": crl_reachability,
            "reachable_ocsp_count": sum(
                1 for item in ocsp_reachability if item.get("reachable")
            ),
            "reachable_crl_count": sum(
                1 for item in crl_reachability if item.get("reachable")
            ),
        },
    }


def load_results(db, scan_id):
    rows = db.execute(
        text("SELECT plugin, result FROM scan_results WHERE scan_id=:id"),
        {"id": scan_id},
    ).fetchall()
    return [
        {"plugin": r._mapping["plugin"], "result": r._mapping["result"]}
        for r in rows
    ]
