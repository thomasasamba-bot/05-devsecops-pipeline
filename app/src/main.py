"""
Demo Application — DevSecOps Pipeline
======================================
FastAPI application demonstrating:
  • /healthz  — liveness endpoint (Kubernetes probe)
  • /ready    — readiness endpoint (Kubernetes probe)
  • /metrics  — Prometheus metrics
  • Structured logging
  • Security headers middleware
"""

import os
import time
import logging
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import (
    Counter, Histogram, Gauge,
    generate_latest, CONTENT_TYPE_LATEST
)

# ─── LOGGING ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
)
log = logging.getLogger(__name__)

# ─── PROMETHEUS METRICS ───────────────────────────────────────────────
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
    buckets=[.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5]
)
ACTIVE_REQUESTS = Gauge(
    "http_requests_active",
    "Active HTTP requests"
)
APP_INFO = Gauge(
    "app_info",
    "Application information",
    ["version", "git_commit", "environment"]
)

APP_VERSION   = os.getenv("APP_VERSION",  "1.0.0")
GIT_COMMIT    = os.getenv("GIT_COMMIT",   "unknown")
ENVIRONMENT   = os.getenv("APP_ENV",      "development")
START_TIME    = time.time()

APP_INFO.labels(
    version     = APP_VERSION,
    git_commit  = GIT_COMMIT,
    environment = ENVIRONMENT
).set(1)

# ─── APP FACTORY ──────────────────────────────────────────────────────
app = FastAPI(
    title       = "Demo App",
    description = "DevSecOps pipeline demo",
    version     = APP_VERSION,
    docs_url    = "/docs" if ENVIRONMENT != "production" else None,
    redoc_url   = None,
)

# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    start = time.time()
    ACTIVE_REQUESTS.inc()

    response = await call_next(request)

    duration = time.time() - start
    REQUEST_COUNT.labels(
        method   = request.method,
        endpoint = request.url.path,
        status   = response.status_code
    ).inc()
    REQUEST_LATENCY.labels(
        method   = request.method,
        endpoint = request.url.path
    ).observe(duration)
    ACTIVE_REQUESTS.dec()

    # Security headers
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"]   = "default-src 'self'"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"

    return response

# ─── HEALTH ENDPOINTS ─────────────────────────────────────────────────
@app.get("/healthz", tags=["health"])
async def liveness():
    """Kubernetes liveness probe — is the app alive?"""
    return {
        "status":    "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_s":  round(time.time() - START_TIME, 1)
    }


@app.get("/ready", tags=["health"])
async def readiness():
    """
    Kubernetes readiness probe — is the app ready for traffic?
    Checks: DB connectivity, cache, dependencies.
    """
    checks = {}
    all_ready = True

    # Database check (placeholder)
    try:
        # db.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"
        all_ready = False

    # Cache check (placeholder)
    checks["cache"] = "ok"

    status_code = 200 if all_ready else 503
    return Response(
        content = str({
            "ready":     all_ready,
            "checks":    checks,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }),
        status_code = status_code,
        media_type  = "application/json"
    )


# ─── METRICS ENDPOINT ─────────────────────────────────────────────────
@app.get("/metrics", tags=["observability"])
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content    = generate_latest(),
        media_type = CONTENT_TYPE_LATEST
    )


# ─── APP ENDPOINTS ────────────────────────────────────────────────────
@app.get("/", tags=["app"])
async def root():
    log.info("Root endpoint called")
    return {
        "app":         "demo-app",
        "version":     APP_VERSION,
        "environment": ENVIRONMENT,
        "commit":      GIT_COMMIT,
    }


@app.get("/api/v1/status", tags=["app"])
async def status():
    return {
        "status":    "operational",
        "version":   APP_VERSION,
        "uptime_s":  round(time.time() - START_TIME, 1),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
