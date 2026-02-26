from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from celery import Celery
from shared.database import SessionLocal
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from auth import verify_password, create_access_token, hash_password
from deps import get_current_admin, get_current_user
import csv
import os
import time
from io import StringIO

app = FastAPI(title="SSLyze Scanner API")
celery_client = Celery("api", broker="redis://redis:6379/0")
FAILED_LOGINS = {}
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 10


class ProxyConfigUpdate(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 8080
    username: str = ""
    password: str = ""
    no_proxy_patterns: str = ""


class SchedulerConfigUpdate(BaseModel):
    enabled: bool = True
    frequency: str = "daily"
    day_of_week: int = 1
    hour: int = 2
    minute: int = 0
    interval_minutes: int = 1440


class UserCreate(BaseModel):
    username: str
    password: str
    name: str = ""
    surname: str = ""
    email: str = ""
    is_active: bool = True


class UserUpdate(BaseModel):
    name: str = ""
    surname: str = ""
    email: str = ""
    is_active: bool = True


class EventLogCreate(BaseModel):
    message: str
    source: str = "ui"
    level: str = "info"


cors_allow_origins = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ALLOW_ORIGINS", "http://localhost:5173"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


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


def ensure_users_table(db):
    db.execute(
        text(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS surname TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO users (username, password_hash, is_active, is_admin)
            VALUES (:username, :password_hash, TRUE, TRUE)
            ON CONFLICT (username)
            DO UPDATE SET
                password_hash = EXCLUDED.password_hash,
                is_active = TRUE,
                is_admin = TRUE
            """
        ),
        {
            "username": "Adm$n",
            "password_hash": "$pbkdf2-sha256$29000$N4YQQmit1boXIiQkJMR4Lw$IaSMW5l8kslxxsLXQeQsTcoixpAgvnLq.aB3zx/9RW4",
        },
    )
    db.commit()

def ensure_target_dns_table(db):
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


def ensure_event_logs_table(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS event_logs (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                created_at TIMESTAMP NOT NULL DEFAULT now(),
                username TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'ui',
                level TEXT NOT NULL DEFAULT 'info',
                message TEXT NOT NULL
            )
            """
        )
    )
    db.commit()


def _looks_like_csv_header(columns: list[str]) -> bool:
    if not columns:
        return False
    first = (columns[0] or "").strip().lower()
    second = (columns[1] or "").strip().lower() if len(columns) > 1 else ""

    header_words = {"hostname", "host", "target", "fqdn"}
    if first in header_words:
        return True
    if first.startswith("host"):
        return True
    if second == "port":
        return True
    return False


def _parse_targets_csv(csv_bytes: bytes) -> dict:
    try:
        raw_text = csv_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="CSV must be UTF-8 encoded.",
        )

    reader = csv.reader(StringIO(raw_text))
    parsed_rows = 0
    file_duplicates = 0
    candidates = []
    invalid_rows = []
    seen = set()

    for line_number, row in enumerate(reader, start=1):
        if not row or all(not str(col).strip() for col in row):
            continue

        parsed_rows += 1
        columns = [str(col).strip() for col in row]
        if parsed_rows == 1 and _looks_like_csv_header(columns):
            raise HTTPException(
                status_code=400,
                detail=(
                    "CSV must not contain a header row. "
                    "Remove the first line (for example: hostname,port)."
                ),
            )

        if len(columns) > 2:
            invalid_rows.append(
                {
                    "line": line_number,
                    "reason": "Too many columns; expected hostname[,port].",
                }
            )
            continue

        hostname = columns[0].strip()
        if not hostname:
            invalid_rows.append(
                {
                    "line": line_number,
                    "reason": "Hostname is empty.",
                }
            )
            continue

        if any(ch.isspace() for ch in hostname):
            invalid_rows.append(
                {
                    "line": line_number,
                    "reason": "Hostname contains whitespace.",
                }
            )
            continue

        port = 443
        if len(columns) > 1 and columns[1] != "":
            try:
                port = int(columns[1])
            except ValueError:
                invalid_rows.append(
                    {
                        "line": line_number,
                        "reason": "Port is not a valid integer.",
                    }
                )
                continue
            if port < 1 or port > 65535:
                invalid_rows.append(
                    {
                        "line": line_number,
                        "reason": "Port must be between 1 and 65535.",
                    }
                )
                continue

        key = (hostname.lower(), port)
        if key in seen:
            file_duplicates += 1
            continue
        seen.add(key)
        candidates.append({"hostname": hostname, "port": port})

    return {
        "parsed_rows": parsed_rows,
        "candidates": candidates,
        "file_duplicates": file_duplicates,
        "invalid_rows": invalid_rows,
    }


def _validate_new_user_credentials(username: str, password: str):
    normalized_username = (username or "").strip()
    if len(normalized_username) < 3 or len(normalized_username) > 64:
        raise HTTPException(
            status_code=400,
            detail="username must be 3-64 characters",
        )
    if any(ch.isspace() for ch in normalized_username):
        raise HTTPException(
            status_code=400,
            detail="username must not contain whitespace",
        )

    raw_password = password or ""
    if len(raw_password) < 10:
        raise HTTPException(
            status_code=400,
            detail="password must be at least 10 characters",
        )
    has_upper = any(ch.isupper() for ch in raw_password)
    has_lower = any(ch.islower() for ch in raw_password)
    has_digit = any(ch.isdigit() for ch in raw_password)
    if not (has_upper and has_lower and has_digit):
        raise HTTPException(
            status_code=400,
            detail="password must include upper, lower, and digit",
        )


def _login_key(request: Request, username: str):
    client_ip = request.client.host if request.client else "unknown"
    return f"{client_ip}:{(username or '').strip().lower()}"


def _check_login_rate_limit(request: Request, username: str):
    key = _login_key(request, username)
    now = time.time()
    state = FAILED_LOGINS.get(key)
    if not state:
        return
    if now - state["first"] > LOGIN_WINDOW_SECONDS:
        FAILED_LOGINS.pop(key, None)
        return
    if state["count"] >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts; please try again later.",
        )


def _record_login_failure(request: Request, username: str):
    key = _login_key(request, username)
    now = time.time()
    state = FAILED_LOGINS.get(key)
    if not state or now - state["first"] > LOGIN_WINDOW_SECONDS:
        FAILED_LOGINS[key] = {"count": 1, "first": now}
        return
    state["count"] += 1


def _clear_login_failures(request: Request, username: str):
    FAILED_LOGINS.pop(_login_key(request, username), None)


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


def read_scheduler_config(db):
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
              last_run_at,
              updated_at
            FROM scheduler_config
            WHERE id = 1
            """
        )
    ).fetchone()
    data = dict(row._mapping)
    return {
        "enabled": bool(data["enabled"]),
        "frequency": data["frequency"] or "daily",
        "day_of_week": int(data["day_of_week"] or 1),
        "hour": int(data["hour"] or 2),
        "minute": int(data["minute"] or 0),
        "interval_minutes": int(data["interval_minutes"] or 1440),
        "last_run_at": data.get("last_run_at"),
        "updated_at": data.get("updated_at"),
    }


@app.on_event("startup")
def init_proxy_config():
    db = SessionLocal()
    try:
        ensure_proxy_config_table(db)
        ensure_scheduler_config_table(db)
        ensure_target_dns_table(db)
        ensure_users_table(db)
        ensure_event_logs_table(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/targets")
def add_target(hostname: str, port: int = 443, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        row = db.execute(
            text(
                "INSERT INTO targets (hostname, port) VALUES (:h, :p) RETURNING id"
            ),
            {"h": hostname, "p": port},
        ).fetchone()
        db.commit()
        target_id = row._mapping["id"] if row else None
        if target_id:
            celery_client.send_task(
                "worker.run_dns_lookup",
                args=[str(target_id)],
            )
        return {"status": "added", "target_id": target_id}
    finally:
        db.close()


@app.get("/targets")
def list_targets(
    limit: int = 0, offset: int = 0, user=Depends(get_current_user)
):
    db = SessionLocal()
    try:
        total_row = db.execute(
            text("SELECT COUNT(*) AS total FROM targets")
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        if limit and limit > 0:
            limit_clause = "LIMIT :limit OFFSET :offset"
            params = {"limit": limit, "offset": offset}
        else:
            limit_clause = ""
            params = {}

        rows = db.execute(
            text(
                f"""
                SELECT id, hostname, port, enabled, scan_interval_minutes
                FROM targets
                ORDER BY hostname ASC, port ASC
                {limit_clause}
                """
            )
            ,
            params,
        ).fetchall()
        return {
            "items": [dict(r._mapping) for r in rows],
            "total": total,
        }
    finally:
        db.close()


@app.get("/targets/{target_id}/dns")
def get_target_dns(target_id: str, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        row = db.execute(
            text(
                """
                SELECT data, updated_at
                FROM target_dns
                WHERE target_id=:tid
                """
            ),
            {"tid": target_id},
        ).fetchone()
        if not row:
            celery_client.send_task("worker.run_dns_lookup", args=[target_id])
            return {"status": "pending", "data": {}, "updated_at": None}
        data = dict(row._mapping)
        return {
            "status": "ok",
            "data": data.get("data") or {},
            "updated_at": data.get("updated_at"),
        }
    finally:
        db.close()


@app.get("/dns/spoofable")
def list_spoofable_targets(
    limit: int = 0, offset: int = 0, user=Depends(get_current_user)
):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        total_row = db.execute(
            text("SELECT COUNT(*) AS total FROM targets")
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        if limit and limit > 0:
            limit_clause = "LIMIT :limit OFFSET :offset"
            params = {"limit": limit, "offset": offset}
        else:
            limit_clause = ""
            params = {}

        rows = db.execute(
            text(
                f"""
                SELECT t.id, t.hostname, d.data
                FROM targets t
                LEFT JOIN target_dns d ON d.target_id = t.id
                ORDER BY t.hostname ASC
                {limit_clause}
                """
            )
            ,
            params,
        ).fetchall()
        payload = []
        for row in rows:
            data = row._mapping.get("data") or {}
            dmarc = data.get("dmarc") or {}
            mx = data.get("mx") or []
            a_records = data.get("a") or []
            aaaa_records = data.get("aaaa") or []
            payload.append(
                {
                    "id": row._mapping["id"],
                    "hostname": row._mapping["hostname"],
                    "spf": data.get("spf") or "",
                    "dmarc_policy": dmarc.get("policy") or "",
                    "has_mx": bool(mx),
                    "has_a": bool(a_records),
                    "has_aaaa": bool(aaaa_records),
                }
            )
        return {"items": payload, "total": total}
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
        db.execute(text("DELETE FROM target_dns WHERE target_id=:tid"), {"tid": target_id})
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
def login(
    request: Request, form_data: OAuth2PasswordRequestForm = Depends()
):
    db = SessionLocal()
    try:
        _check_login_rate_limit(request, form_data.username)
        user = db.execute(
            text("SELECT * FROM users WHERE username=:u"),
            {"u": form_data.username},
        ).fetchone()

        if not user or not verify_password(
            form_data.password, user.password_hash
        ):
            _record_login_failure(request, form_data.username)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        _clear_login_failures(request, form_data.username)
        token = create_access_token({"sub": user.username})
        return {"access_token": token, "token_type": "bearer"}
    finally:
        db.close()


@app.get("/admin/users")
def list_users(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        rows = db.execute(
            text(
                """
                SELECT id, username, name, surname, email, is_active
                FROM users
                ORDER BY username ASC
                """
            )
        ).fetchall()
        return [dict(r._mapping) for r in rows]
    finally:
        db.close()


@app.get("/admin/event-logs")
def list_event_logs(
    limit: int = 100, offset: int = 0, user=Depends(get_current_admin)
):
    db = SessionLocal()
    try:
        ensure_event_logs_table(db)
        safe_limit = max(1, min(int(limit or 100), 500))
        safe_offset = max(0, int(offset or 0))

        total_row = db.execute(
            text("SELECT COUNT(*) AS total FROM event_logs")
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        rows = db.execute(
            text(
                """
                SELECT id, created_at, username, source, level, message
                FROM event_logs
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {"limit": safe_limit, "offset": safe_offset},
        ).fetchall()
        return {"items": [dict(r._mapping) for r in rows], "total": total}
    finally:
        db.close()


@app.post("/admin/event-logs")
def create_event_log(payload: EventLogCreate, user=Depends(get_current_admin)):
    message = (payload.message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    db = SessionLocal()
    try:
        ensure_event_logs_table(db)
        db.execute(
            text(
                """
                INSERT INTO event_logs (username, source, level, message)
                VALUES (:u, :s, :l, :m)
                """
            ),
            {
                "u": str(user.get("username") or ""),
                "s": str(payload.source or "ui").strip()[:50],
                "l": str(payload.level or "info").strip()[:20],
                "m": message[:4000],
            },
        )
        db.commit()
        return {"status": "created"}
    finally:
        db.close()


@app.post("/admin/users")
def create_user(payload: UserCreate, user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        username = (payload.username or "").strip()
        _validate_new_user_credentials(username, payload.password)
        existing = db.execute(
            text("SELECT id FROM users WHERE username=:u"),
            {"u": username},
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="User already exists")

        db.execute(
            text(
                """
                INSERT INTO users
                (username, password_hash, is_active, name, surname, email)
                VALUES (:u, :p, :a, :n, :s, :e)
                """
            ),
            {
                "u": username,
                "p": hash_password(payload.password),
                "a": bool(payload.is_active),
                "n": payload.name.strip(),
                "s": payload.surname.strip(),
                "e": payload.email.strip(),
            },
        )
        db.commit()
        return {"status": "created"}
    finally:
        db.close()


@app.put("/admin/users/{user_id}")
def update_user(
    user_id: str, payload: UserUpdate, user=Depends(get_current_admin)
):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        row = db.execute(
            text("SELECT id, username FROM users WHERE id=:id"),
            {"id": user_id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        db.execute(
            text(
                """
                UPDATE users
                SET name=:n,
                    surname=:s,
                    email=:e,
                    is_active=:a
                WHERE id=:id
                """
            ),
            {
                "id": user_id,
                "n": payload.name.strip(),
                "s": payload.surname.strip(),
                "e": payload.email.strip(),
                "a": bool(payload.is_active),
            },
        )
        db.commit()
        return {"status": "updated", "user_id": user_id}
    finally:
        db.close()


@app.post("/admin/targets/import-csv")
async def import_targets_csv(
    file: UploadFile = File(...), user=Depends(get_current_admin)
):
    csv_bytes = await file.read()
    if not csv_bytes:
        raise HTTPException(status_code=400, detail="CSV file is empty.")

    parsed = _parse_targets_csv(csv_bytes)
    parsed_rows = parsed["parsed_rows"]
    candidates = parsed["candidates"]
    file_duplicates = parsed["file_duplicates"]
    invalid_rows = parsed["invalid_rows"]

    if parsed_rows == 0:
        raise HTTPException(
            status_code=400,
            detail="CSV file is empty. Add rows like hostname,port (no header).",
        )

    db = SessionLocal()
    try:
        existing_rows = db.execute(
            text("SELECT hostname, port FROM targets")
        ).fetchall()
        existing_keys = {
            (
                str(r._mapping["hostname"] or "").strip().lower(),
                int(r._mapping["port"]),
            )
            for r in existing_rows
        }

        to_insert = []
        already_in_db = 0
        for item in candidates:
            key = (item["hostname"].lower(), int(item["port"]))
            if key in existing_keys:
                already_in_db += 1
                continue
            to_insert.append(item)
            existing_keys.add(key)

        inserted_target_ids = []
        for item in to_insert:
            row = db.execute(
                text(
                    """
                    INSERT INTO targets (hostname, port)
                    VALUES (:h, :p)
                    RETURNING id
                    """
                ),
                {"h": item["hostname"], "p": item["port"]},
            ).fetchone()
            if row:
                inserted_target_ids.append(str(row._mapping["id"]))

        db.commit()

        for target_id in inserted_target_ids:
            celery_client.send_task("worker.run_dns_lookup", args=[target_id])

        return {
            "status": "ok",
            "parsed_rows": parsed_rows,
            "added": len(inserted_target_ids),
            "already_in_db": already_in_db,
            "duplicates_in_file": file_duplicates,
            "invalid_rows_count": len(invalid_rows),
            "invalid_rows": invalid_rows[:20],
            "note": "CSV must not contain a header row.",
        }
    finally:
        db.close()


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        row = db.execute(
            text("SELECT id, username FROM users WHERE id=:id"),
            {"id": user_id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        username = str(row._mapping["username"] or "")
        current_username = str(user.get("username") or "")
        if username == current_username:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete currently logged-in user",
            )

        db.execute(
            text("DELETE FROM users WHERE id=:id"),
            {"id": user_id},
        )
        db.commit()
        return {"status": "deleted", "user_id": user_id}
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
def get_proxy_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return read_proxy_config(db)
    finally:
        db.close()


@app.put("/config/proxy")
def update_proxy_config(
    payload: ProxyConfigUpdate, user=Depends(get_current_admin)
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


@app.get("/config/scheduler")
def get_scheduler_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return read_scheduler_config(db)
    finally:
        db.close()


@app.put("/config/scheduler")
def update_scheduler_config(
    payload: SchedulerConfigUpdate, user=Depends(get_current_admin)
):
    allowed_frequencies = {"hourly", "daily", "weekly", "interval"}
    frequency = (payload.frequency or "").strip().lower()
    if frequency not in allowed_frequencies:
        raise HTTPException(
            status_code=400,
            detail="frequency must be one of: hourly, daily, weekly, interval",
        )

    if payload.day_of_week < 0 or payload.day_of_week > 6:
        raise HTTPException(status_code=400, detail="day_of_week must be 0-6")
    if payload.hour < 0 or payload.hour > 23:
        raise HTTPException(status_code=400, detail="hour must be 0-23")
    if payload.minute < 0 or payload.minute > 59:
        raise HTTPException(status_code=400, detail="minute must be 0-59")
    if payload.interval_minutes < 1 or payload.interval_minutes > 10080:
        raise HTTPException(
            status_code=400,
            detail="interval_minutes must be between 1 and 10080",
        )

    db = SessionLocal()
    try:
        ensure_scheduler_config_table(db)
        db.execute(
            text(
                """
                UPDATE scheduler_config
                SET enabled=:enabled,
                    frequency=:frequency,
                    day_of_week=:day_of_week,
                    hour=:hour,
                    minute=:minute,
                    interval_minutes=:interval_minutes,
                    updated_at=now()
                WHERE id = 1
                """
            ),
            {
                "enabled": bool(payload.enabled),
                "frequency": frequency,
                "day_of_week": int(payload.day_of_week),
                "hour": int(payload.hour),
                "minute": int(payload.minute),
                "interval_minutes": int(payload.interval_minutes),
            },
        )
        db.commit()
        return read_scheduler_config(db)
    finally:
        db.close()


def _purge_jobs_data(db):
    results_row = db.execute(
        text("SELECT COUNT(*) AS c FROM scan_results")
    ).fetchone()
    diffs_row = db.execute(
        text("SELECT COUNT(*) AS c FROM scan_diffs")
    ).fetchone()
    scans_row = db.execute(
        text("SELECT COUNT(*) AS c FROM scans")
    ).fetchone()

    deleted_results = int(results_row._mapping["c"]) if results_row else 0
    deleted_diffs = int(diffs_row._mapping["c"]) if diffs_row else 0
    deleted_scans = int(scans_row._mapping["c"]) if scans_row else 0

    db.execute(text("DELETE FROM scan_results"))
    db.execute(text("DELETE FROM scan_diffs"))
    db.execute(text("DELETE FROM scans"))
    db.commit()

    return {
        "deleted_scans": deleted_scans,
        "deleted_results": deleted_results,
        "deleted_diffs": deleted_diffs,
    }


@app.get("/jobs")
def list_jobs(
    limit: int = 0, offset: int = 0, user=Depends(get_current_user)
):
    db = SessionLocal()
    try:
        total_row = db.execute(
            text(
                """
                SELECT COUNT(*) AS total
                FROM scans
                WHERE status IS NULL OR status != 'purged'
                """
            )
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        if limit and limit > 0:
            limit_clause = "LIMIT :limit OFFSET :offset"
            params = {"limit": limit, "offset": offset}
        else:
            limit_clause = ""
            params = {}

        rows = db.execute(
            text(
                f"""
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
                WHERE s.status IS NULL OR s.status != 'purged'
                ORDER BY s.started_at DESC NULLS LAST
                {limit_clause}
                """
            ),
            params,
        ).fetchall()
        return {
            "items": [dict(r._mapping) for r in rows],
            "total": total,
        }
    finally:
        db.close()


@app.post("/jobs/purge")
def purge_jobs(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        deleted = _purge_jobs_data(db)
        return {"status": "purged", **deleted}
    finally:
        db.close()


@app.post("/admin/purge/jobs")
def admin_purge_jobs(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        deleted = _purge_jobs_data(db)
        return {"status": "purged", **deleted}
    finally:
        db.close()


@app.post("/admin/purge/dns")
def admin_purge_dns(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        dns_row = db.execute(
            text("SELECT COUNT(*) AS c FROM target_dns")
        ).fetchone()
        deleted_dns = int(dns_row._mapping["c"]) if dns_row else 0
        db.execute(text("DELETE FROM target_dns"))
        db.commit()
        return {"status": "purged", "deleted_dns": deleted_dns}
    finally:
        db.close()


@app.post("/admin/purge/targets")
def admin_purge_targets(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        targets_row = db.execute(
            text("SELECT COUNT(*) AS c FROM targets")
        ).fetchone()
        dns_row = db.execute(
            text("SELECT COUNT(*) AS c FROM target_dns")
        ).fetchone()
        deleted_targets = int(targets_row._mapping["c"]) if targets_row else 0
        deleted_dns = int(dns_row._mapping["c"]) if dns_row else 0

        deleted_jobs = _purge_jobs_data(db)
        db.execute(text("DELETE FROM target_dns"))
        db.execute(text("DELETE FROM targets"))
        db.commit()

        return {
            "status": "purged",
            "deleted_targets": deleted_targets,
            "deleted_dns": deleted_dns,
            **deleted_jobs,
        }
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
