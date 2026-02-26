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
import socket
import uuid
import json
import re
import ssl
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
)
from urllib.error import HTTPError, URLError

celery = Celery(
    "worker",
    broker="redis://redis:6379/0",
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
        rows = db.execute(
            text("SELECT id FROM targets WHERE enabled = true")
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
        target_row = db.execute(
            text("SELECT hostname, port FROM targets WHERE id=:id"),
            {"id": target_id},
        ).fetchone()
        if not target_row:
            return
        target = target_row._mapping

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
        server_location = ServerNetworkLocation(
            hostname=target["hostname"],
            port=target["port"],
            http_proxy_settings=proxy_settings,
        )
        request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
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
            },
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
                SET finished_at=:end, status='done'
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
    except Exception:
        if scan_id:
            db.execute(
                text("""
                    UPDATE scans
                    SET finished_at=:end, status='failed'
                    WHERE id=:sid
                """),
                {"end": datetime.utcnow(), "sid": scan_id},
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
        row = db.execute(
            text("SELECT hostname FROM targets WHERE id=:id"),
            {"id": target_id},
        ).fetchone()
        if not row:
            return
        hostname = row._mapping["hostname"]
        payload = _build_dns_payload(hostname)
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


def _resolve_records(name, rdtype):
    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=5)
    except Exception:
        return []

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
    return records


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


def _build_dns_payload(hostname):
    host = str(hostname or "").strip()
    payload = {
        "hostname": host,
        "whois": {},
        "soa": [],
        "a": [],
        "aaaa": [],
        "resolved_ips": [],
        "ns": [],
        "mx": [],
        "spf": "",
        "dmarc": {"record": "", "policy": "", "domain": ""},
    }

    if not host:
        return payload

    is_ip = _is_ip_address(host)

    if not is_ip:
        payload["soa"] = _resolve_records(host, "SOA")
        payload["a"] = _resolve_records(host, "A")
        payload["aaaa"] = _resolve_records(host, "AAAA")
        payload["resolved_ips"] = _resolve_host_ips(host)
        payload["ns"] = _resolve_records(host, "NS")
        payload["mx"] = _resolve_records(host, "MX")
        txt_records = _resolve_records(host, "TXT")
        payload["spf"] = _extract_spf(txt_records)

        dmarc_domain = f"_dmarc.{host}"
        dmarc_txt = _resolve_records(dmarc_domain, "TXT")
        dmarc_record = _extract_dmarc(dmarc_txt)
        payload["dmarc"] = {
            "record": dmarc_record,
            "policy": _parse_dmarc_policy(dmarc_record),
            "domain": dmarc_domain,
        }
    else:
        payload["resolved_ips"] = [host]

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


def _resolve_host_ips(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return []

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
    return addresses

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
        return {"certificate_chain": []}

    leaf_cert = deployments[0].received_certificate_chain[0]
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

    return {
        "certificate_chain": [
            {
                "subject": leaf_cert.subject.rfc4514_string(),
                "issuer": leaf_cert.issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "subject_alternative_name": san_values,
            }
        ]
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
