FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY ui/ /app/

EXPOSE 5173

CMD ["python", "-m", "http.server", "5173", "--bind", "0.0.0.0"]
