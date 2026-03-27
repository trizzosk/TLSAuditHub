FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY ui/ /app/

EXPOSE 5173

CMD ["python", "/app/secure_server.py"]
