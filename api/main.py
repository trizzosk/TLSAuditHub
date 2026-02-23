from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from celery import Celery
from shared.database import SessionLocal
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from auth import verify_password, create_access_token
from deps import get_current_user

app = FastAPI(title="SSLyze Scanner API")
celery_client = Celery("api", broker="redis://redis:6379/0")


class ProxyConfigUpdate(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 8080
    username: str = ""
    password: str = ""
    no_proxy_patterns: str = ""

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_proxy_config_table(db):
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


def read_proxy_config(db):
    ensure_proxy_config_table(db)
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
        "host": data["host"] or "",
        "port": int(data["port"] or 8080),
        "username": data["username"] or "",
        "has_password": bool(data["password"]),
        "no_proxy_patterns": data["no_proxy_patterns"] or "",
    }


@app.on_event("startup")
def init_proxy_config():
    db = SessionLocal()
    try:
        ensure_proxy_config_table(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/targets")
def add_target(hostname: str, port: int = 443, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO targets (hostname, port) VALUES (:h, :p)"
            ),
            {"h": hostname, "p": port},
        )
        db.commit()
        return {"status": "added"}
    finally:
        db.close()


@app.get("/targets")
def list_targets(user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT id, hostname, port, enabled, scan_interval_minutes
                FROM targets
                ORDER BY hostname ASC, port ASC
                """
            )
        ).fetchall()
        return [dict(r._mapping) for r in rows]
    finally:
        db.close()


@app.delete("/targets/{target_id}")
def remove_target(target_id: str, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        target = db.execute(
            text("SELECT id FROM targets WHERE id=:tid"),
            {"tid": target_id},
        ).fetchone()

        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        db.execute(text("DELETE FROM scan_results WHERE scan_id IN (SELECT id FROM scans WHERE target_id=:tid)"), {"tid": target_id})
        db.execute(text("DELETE FROM scan_diffs WHERE target_id=:tid"), {"tid": target_id})
        db.execute(text("DELETE FROM scans WHERE target_id=:tid"), {"tid": target_id})
        db.execute(text("DELETE FROM targets WHERE id=:tid"), {"tid": target_id})
        db.commit()
        return {"status": "deleted", "target_id": target_id}
    finally:
        db.close()


@app.post("/targets/{target_id}/scan")
def run_target_scan(target_id: str, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        target = db.execute(
            text("SELECT id FROM targets WHERE id=:tid"),
            {"tid": target_id},
        ).fetchone()

        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        task = celery_client.send_task("worker.run_scan", args=[target_id])
        return {"status": "queued", "target_id": target_id, "task_id": task.id}
    finally:
        db.close()


@app.post("/auth/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    try:
        user = db.execute(
            text("SELECT * FROM users WHERE username=:u"),
            {"u": form_data.username},
        ).fetchone()

        if not user or not verify_password(
            form_data.password, user.password_hash
        ):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_access_token({"sub": user.username})
        return {"access_token": token, "token_type": "bearer"}
    finally:
        db.close()


@app.get("/dashboard/summary")
def dashboard_summary(user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        counts = db.execute(
            text(
                """
                SELECT
                  (SELECT COUNT(*) FROM targets) AS targets_total,
                  (SELECT COUNT(*) FROM targets WHERE enabled=true) AS targets_enabled,
                  (SELECT COUNT(*) FROM scans) AS scans_total,
                  (SELECT COUNT(*) FROM scans WHERE status='running') AS scans_running,
                  (SELECT COUNT(*) FROM scan_results) AS results_total,
                  (SELECT COUNT(*) FROM scan_diffs) AS diffs_total,
                  (SELECT MAX(finished_at) FROM scans) AS last_scan_finished_at
                """
            )
        ).fetchone()
        return dict(counts._mapping)
    finally:
        db.close()


@app.get("/config/proxy")
def get_proxy_config(user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        return read_proxy_config(db)
    finally:
        db.close()


@app.put("/config/proxy")
def update_proxy_config(
    payload: ProxyConfigUpdate, user=Depends(get_current_user)
):
    db = SessionLocal()
    try:
        ensure_proxy_config_table(db)
        current = db.execute(
            text(
                """
                SELECT password FROM proxy_config
                WHERE id = 1
                """
            )
        ).fetchone()
        current_password = current._mapping["password"] if current else ""
        new_password = (
            payload.password
            if payload.password not in (None, "")
            else current_password
        )

        db.execute(
            text(
                """
                UPDATE proxy_config
                SET enabled=:enabled,
                    host=:host,
                    port=:port,
                    username=:username,
                    password=:password,
                    no_proxy_patterns=:no_proxy_patterns,
                    updated_at=now()
                WHERE id = 1
                """
            ),
            {
                "enabled": payload.enabled,
                "host": payload.host.strip(),
                "port": payload.port,
                "username": payload.username.strip(),
                "password": new_password,
                "no_proxy_patterns": payload.no_proxy_patterns.strip(),
            },
        )
        db.commit()
        return read_proxy_config(db)
    finally:
        db.close()


@app.get("/jobs")
def list_jobs(limit: int = 50, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                  s.id,
                  s.target_id,
                  t.hostname,
                  t.port,
                  s.started_at,
                  s.finished_at,
                  s.status
                FROM scans s
                LEFT JOIN targets t ON t.id = s.target_id
                ORDER BY s.started_at DESC NULLS LAST
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).fetchall()
        return [dict(r._mapping) for r in rows]
    finally:
        db.close()


@app.get("/jobs/{scan_id}/results")
def job_results(scan_id: str, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT plugin, result
                FROM scan_results
                WHERE scan_id=:sid
                ORDER BY plugin ASC
                """
            ),
            {"sid": scan_id},
        ).fetchall()
        return [dict(r._mapping) for r in rows]
    finally:
        db.close()


@app.get("/targets/{target_id}/diffs")
def get_diffs(target_id: str, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.execute(
            text("""
                SELECT created_at, diff
                FROM scan_diffs
                WHERE target_id=:tid
                ORDER BY created_at DESC
            """),
            {"tid": target_id},
        ).fetchall()
        return [dict(r._mapping) for r in rows]
    finally:
        db.close()
