from datetime import datetime, timedelta
import os
from jose import jwt, JWTError
from passlib.context import CryptContext


#SECRET_KEY = "CHANGE_ME_TO_RANDOM_64_CHARS"
#ALGORITHM = "HS256"


SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is not set")

ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60)
)

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt"],
    deprecated="auto",
)

if (
    os.environ.get("APP_ENV", "").lower() in {"prod", "production"}
    and SECRET_KEY in {"CHANGE_ME", "changeme", "default", "secret"}
):
    raise RuntimeError(
        "JWT_SECRET_KEY is weak in production; set a strong random secret."
    )

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
