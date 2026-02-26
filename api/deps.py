from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import text
from shared.database import SessionLocal
from jose import JWTError

from auth import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)

    db = SessionLocal()
    try:
        user = db.execute(
            text("SELECT * FROM users WHERE username=:u AND is_active=true"),
            {"u": username},
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401)

        return dict(user._mapping)
    finally:
        db.close()


def get_current_admin(user: dict = Depends(get_current_user)):
    if not bool(user.get("is_admin")):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
