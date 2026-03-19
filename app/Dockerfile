# ─── STAGE 1: BUILDER ────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Build args for image metadata
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG GIT_BRANCH=unknown

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy and install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy application source
COPY src/ ./src/

# ─── STAGE 2: RUNTIME ────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: create non-root user
RUN groupadd -r appgroup --gid=1000 && \
    useradd -r -g appgroup --uid=1000 --no-create-home --shell=/sbin/nologin appuser

WORKDIR /app

# Copy only built artifacts — no build tools in runtime image
COPY --from=builder /root/.local /home/appuser/.local
COPY --from=builder /build/src/ ./src/

# Set ownership
RUN chown -R appuser:appgroup /app

# OCI image labels
LABEL org.opencontainers.image.title="Demo App" \
      org.opencontainers.image.description="DevSecOps pipeline demo application" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/thomasasamba-bot/05-devsecops-pipeline" \
      maintainer="thomas-asamba"

# Runtime environment
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH \
    PORT=8080

# Security: drop all capabilities, read-only filesystem enforced by K8s
USER appuser

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
