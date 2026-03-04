FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir \
    sslyze \
    celery \
    redis \
    psycopg2-binary \
    sqlalchemy \
    dnspython \
    python-whois

COPY worker/ /app/
RUN mkdir -p /app/shared
COPY app/database.py /app/shared/database.py

CMD ["celery", "-A", "worker", "worker", "--loglevel=info"]
