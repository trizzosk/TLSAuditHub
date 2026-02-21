from fastapi import FastAPI
from sqlalchemy import text
from shared.database import SessionLocal
from fastapi.security import OAuth2PasswordRequestForm
from auth import verify_password, create_access_token, hash_password
from deps import get_current_user

app = FastAPI(title="SSLyze Scanner API")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/targets")
def add_target(hostname: str, port: int = 443, user=Depends(get_current_user)):
    db = SessionLocal()
    db.execute(
        text(
            "INSERT INTO targets (hostname, port) VALUES (:h, :p)"
        ),
        {"h": hostname, "p": port},
    )
    db.commit()
    return {"status": "added"}

@app.get("/targets")
def list_targets(user=Depends(get_current_user)):
    db = SessionLocal()
    rows = db.execute(text("SELECT * FROM targets")).fetchall()
    return [dict(r._mapping) for r in rows]

@app.post("/auth/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
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

@app.get("/targets/{target_id}/diffs")
def get_diffs(target_id: str, user=Depends(get_current_user)):
    db = SessionLocal()
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