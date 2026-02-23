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
from datetime import datetime
import uuid
import json
import re
from fnmatch import fnmatchcase
from diff import diff_sets, diff_dict
from normalize import normalize_scan

from celery.schedules import crontab

celery = Celery(
    "worker",
    broker="redis://redis:6379/0",
)

celery.conf.beat_schedule = {
    "scan-all-targets-every-night": {
        "task": "worker.run_scheduled_scans",
        "schedule": crontab(hour=2, minute=0),
        "args": (),
    }
}

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
                server_result
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


def _extract_plugin_results(server_result):
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
            ("http_headers", _serialize_http_headers(headers_attempt.result))
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


def _serialize_http_headers(headers_result):
    hsts = headers_result.strict_transport_security_header
    hsts_payload = None
    if hsts is not None:
        hsts_payload = {
            "max_age": int(hsts.max_age),
            "include_subdomains": bool(hsts.include_subdomains),
            "preload": bool(hsts.preload),
        }

    return {
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
