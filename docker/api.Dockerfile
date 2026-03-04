FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    psycopg2-binary \
    sqlalchemy \
    celery \
    redis \
    python-jose \
    passlib[bcrypt] \
    python-multipart

COPY api/ /app/
RUN mkdir -p /app/shared
COPY app/database.py /app/shared/database.py

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
