# syntax=docker/dockerfile:1

# ---- Stage 1: Build ----
FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=cache,id=p068-pip-v2,target=/root/.cache/pip,sharing=locked \
    python -m venv /opt/venv \
    && /opt/venv/bin/pip install \
        --disable-pip-version-check \
        --timeout 300 \
        --retries 10 \
        -r requirements.txt

# ---- Stage 2: Production ----
FROM python:3.11-slim

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT=300000 \
    FLASHRANK_CACHE_DIR=/ms-flashrank

WORKDIR /app

# Copy an application-owned environment that remains readable/executable by
# the non-root runtime user.
COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Security: run as non-root user
RUN useradd -m appuser

# Install the pinned Chromium runtime and OS libraries used by the isolated
# screenshot worker. Browser contexts are always fresh and run as appuser.
RUN /opt/venv/bin/playwright install --with-deps chromium \
    && chmod -R 755 /ms-playwright

# Keep reranking deterministic at runtime and avoid a first-request model download.
RUN mkdir -p /ms-flashrank \
    && /opt/venv/bin/python -c "from flashrank import Ranker; Ranker(model_name='ms-marco-MultiBERT-L-12', cache_dir='/ms-flashrank')" \
    && chmod -R 755 /ms-flashrank

# Copy application code
COPY . .

# Create data directory with correct ownership
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
