import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://sslyze:sslyze@postgres:5432/sslyze",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
