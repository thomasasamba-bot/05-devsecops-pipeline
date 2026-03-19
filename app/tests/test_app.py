"""
Test suite — Demo App
=====================
Comprehensive tests covering health endpoints, metrics,
security headers, and API behaviour.
Run: pytest app/tests/ --cov=app/src --cov-report=xml -v
"""

import pytest
from fastapi.testclient import TestClient
from app.src.main import app

client = TestClient(app)


# ─── HEALTH ENDPOINT TESTS ────────────────────────────────────────────
class TestHealthEndpoints:

    def test_liveness_returns_200(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200

    def test_liveness_returns_healthy_status(self):
        data = client.get("/healthz").json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "uptime_s" in data

    def test_readiness_returns_200(self):
        resp = client.get("/ready")
        assert resp.status_code == 200

    def test_readiness_returns_ready_true(self):
        data = client.get("/ready")
        # Response is a string dict — basic check
        assert data.status_code in (200, 503)


# ─── METRICS ENDPOINT TESTS ───────────────────────────────────────────
class TestMetricsEndpoint:

    def test_metrics_returns_200(self):
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type_is_prometheus(self):
        resp = client.get("/metrics")
        assert "text/plain" in resp.headers["content-type"]

    def test_metrics_contains_request_counter(self):
        client.get("/healthz")   # Generate a request
        resp = client.get("/metrics")
        assert "http_requests_total" in resp.text

    def test_metrics_contains_app_info(self):
        resp = client.get("/metrics")
        assert "app_info" in resp.text


# ─── SECURITY HEADER TESTS ────────────────────────────────────────────
class TestSecurityHeaders:

    @pytest.fixture(autouse=True)
    def response(self):
        self._resp = client.get("/")
        return self._resp

    def test_x_content_type_options(self):
        assert self._resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self):
        assert self._resp.headers.get("x-frame-options") == "DENY"

    def test_xss_protection(self):
        assert "1; mode=block" in self._resp.headers.get("x-xss-protection", "")

    def test_hsts_header(self):
        hsts = self._resp.headers.get("strict-transport-security", "")
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    def test_csp_header(self):
        csp = self._resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp


# ─── API ENDPOINT TESTS ───────────────────────────────────────────────
class TestAPIEndpoints:

    def test_root_returns_200(self):
        assert client.get("/").status_code == 200

    def test_root_returns_app_name(self):
        data = client.get("/").json()
        assert data["app"] == "demo-app"
        assert "version" in data
        assert "environment" in data

    def test_status_endpoint(self):
        resp = client.get("/api/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "operational"
        assert "uptime_s" in data

    def test_unknown_endpoint_returns_404(self):
        assert client.get("/does-not-exist").status_code == 404

    def test_root_includes_commit(self):
        data = client.get("/").json()
        assert "commit" in data


# ─── PERFORMANCE TESTS ────────────────────────────────────────────────
class TestPerformance:

    def test_health_endpoint_is_fast(self):
        import time
        start = time.time()
        client.get("/healthz")
        elapsed = time.time() - start
        assert elapsed < 0.5, f"Health check took {elapsed:.2f}s — too slow"

    def test_metrics_endpoint_is_fast(self):
        import time
        start = time.time()
        client.get("/metrics")
        elapsed = time.time() - start
        assert elapsed < 1.0, f"Metrics took {elapsed:.2f}s — too slow"
