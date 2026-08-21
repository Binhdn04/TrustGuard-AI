# syntax=docker/dockerfile:1

# ---- Stage 1: Build ----
FROM python:3.11.15-slim-bookworm AS builder

WORKDIR /app

COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install \
        --disable-pip-version-check \
        --no-compile \
        --timeout 300 \
        --retries 10 \
        -r requirements.txt

# ---- Shared runtime dependencies ----
FROM python:3.11.15-slim-bookworm AS runtime-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/data \
    && chown appuser:appuser /app/data

# ---- Worker ----
FROM runtime-base AS worker

ENV RUN_DURABLE_WORKER=true

COPY --chown=appuser:appuser src ./src

USER appuser
CMD ["python", "-m", "src.worker"]

# ---- API ----
FROM runtime-base AS backend

ENV RUN_DURABLE_WORKER=false \
    PORT=8000 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers

RUN playwright install --with-deps chromium \
    && chmod -R a+rX /opt/playwright-browsers

COPY --chown=appuser:appuser src ./src
COPY --chown=appuser:appuser migrations ./migrations
COPY --chown=appuser:appuser alembic.ini ./alembic.ini

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f\"http://localhost:{os.environ['PORT']}/health/ready\")" || exit 1

CMD ["sh", "-c", "exec uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
