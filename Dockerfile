# syntax=docker/dockerfile:1.7

FROM node:20-alpine AS frontend-builder
WORKDIR /app/phishing_shield/PWA_frontend
COPY phishing_shield/PWA_frontend/package*.json ./
RUN npm ci
COPY phishing_shield/PWA_frontend/ ./
RUN npm run build

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

COPY phishing_shield/requirements.txt ./phishing_shield/requirements.txt
RUN pip install --no-cache-dir -r phishing_shield/requirements.txt

COPY phishing_shield/ ./phishing_shield/
COPY --from=frontend-builder /app/phishing_shield/PWA_frontend/dist ./phishing_shield/PWA_frontend/dist

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.main:app --app-dir phishing_shield --host 0.0.0.0 --port ${PORT}"]
