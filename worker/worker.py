from celery import Celery
from sslyze import Scanner, ServerScanRequest
from sqlalchemy import text
from shared.database import SessionLocal
from datetime import datetime
import uuid
from diff import diff_sets, diff_dict
from normalize import normalize_scan

from celery.schedules import crontab

celery.conf.beat_schedule = {
    "scan-all-targets-every-night": {
        "task": "worker.run_scan",
        "schedule": crontab(hour=2, minute=0),
        "args": (),
    }
}

celery = Celery(
    "worker",
    broker="redis://redis:6379/0",
)

@celery.task
def run_scan(target_id):
    db = SessionLocal()

    target = db.execute(
        text("SELECT hostname, port FROM targets WHERE id=:id"),
        {"id": target_id},
    ).fetchone()

    scan_id = str(uuid.uuid4())
    db.execute(
        text("""
            INSERT INTO scans (id, target_id, started_at, status)
            VALUES (:sid, :tid, :start, 'running')
        """),
        {"sid": scan_id, "tid": target_id, "start": datetime.utcnow()},
    )
    db.commit()

    scanner = Scanner()
    request = ServerScanRequest(
        server_location=(target.hostname, target.port),
        scan_commands={"certificate_info", "tlsv1_2_cipher_suites"},
    )
    scanner.queue_scan(request)

    for result in scanner.get_results():
        db.execute(
            text("""
                INSERT INTO scan_results (scan_id, plugin, result)
                VALUES (:sid, :p, :r)
            """),
            {
                "sid": scan_id,
                "p": result.scan_command,
                "r": result.scan_result.as_json(),
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
        old_norm = normalize_scan(load_results(prev_scan.id))
        new_norm = normalize_scan(load_results(scan_id))

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
                    VALUES (:tid, :old, :new, :diff)
                """),
                {
                    "tid": target_id,
                    "old": prev_scan.id,
                    "new": scan_id,
                    "diff": diff,
                },
            )

def load_results(scan_id):
    rows = db.execute(
        text("SELECT plugin, result FROM scan_results WHERE scan_id=:id"),
        {"id": scan_id},
    ).fetchall()
    return [{"plugin": r.plugin, "result": r.result} for r in rows]