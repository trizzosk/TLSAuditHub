from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://sslyze:sslyze@postgres:5432/sslyze"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)