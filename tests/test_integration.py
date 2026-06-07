"""Integration tests: concurrency, full flow, multi-component interactions."""

import asyncio
import concurrent.futures
import time
import threading

import pytest
from starlette.testclient import TestClient

from mimicweb.main import build_app


@pytest.fixture
def client(config_file):
    app = build_app(config_file)
    return TestClient(app)


class TestConcurrency:
    def test_concurrent_requests(self, client):
        """Verify server handles concurrent requests without errors."""
        errors = []

        def make_request(path):
            try:
                resp = client.get(path)
                if resp.status_code not in (200, 401, 403, 404, 500):
                    errors.append(f"Unexpected status {resp.status_code} for {path}")
            except Exception as e:
                errors.append(str(e))

        paths = ["/", "/api/users/1", "/api/users/2", "/admin/panel",
                 "/health", "/api/data", "/api/flaky"] * 5

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, p) for p in paths]
            concurrent.futures.wait(futures)

        assert len(errors) == 0, f"Errors during concurrent requests: {errors}"

    def test_concurrent_admin_operations(self, client):
        """Admin operations should not corrupt config under concurrent access."""
        errors = []

        def create_route(i):
            try:
                resp = client.post("/_admin/api/routes", json={
                    "id": f"concurrent_{i}",
                    "path": f"/concurrent/{i}",
                    "method": "GET",
                    "response": {"status": 200, "body": f"route {i}"},
                })
                if resp.status_code not in (201, 409):
                    errors.append(f"Create {i}: status {resp.status_code}")
            except Exception as e:
                errors.append(str(e))

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_route, i) for i in range(10)]
            concurrent.futures.wait(futures)

        assert len(errors) == 0


class TestFullFlow:
    def test_honeypot_full_scenario(self, client):
        """Simulate attacker reconnaissance -> probe -> exploit attempt."""
        # Recon
        resp = client.get("/")
        assert resp.status_code == 200

        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200

        # Auth attempt
        resp = client.post("/api/auth/login", data={
            "username": "admin",
            "password": "admin123",
        })
        assert resp.status_code == 200
        token = resp.json()["token"]

        # Use token
        resp = client.get("/api/data", headers={
            "Authorization": f"Bearer {token}"
        })
        assert resp.status_code == 200

        # Check logs captured everything
        resp = client.get("/_admin/api/logs")
        data = resp.json()
        assert data["total"] >= 4

    def test_scanner_detected_in_logs(self, client):
        """Scanner traffic should be classified as suspicious."""
        client.get("/", headers={"User-Agent": "sqlmap/1.5"})
        client.get("/../../etc/passwd")

        resp = client.get("/_admin/api/logs?suspicious=true")
        data = resp.json()
        suspicious_entries = [e for e in data["entries"] if e["suspicious"]]
        assert len(suspicious_entries) >= 1

    def test_hot_reload_flow(self, client):
        """Routes can be added and immediately serve traffic."""
        # Add route via admin
        resp = client.post("/_admin/api/routes", json={
            "id": "dynamic_honey",
            "path": "/secret/documents",
            "method": "GET",
            "response": {
                "status": 200,
                "body": '{"files": ["budget.xlsx", "passwords.txt"]}',
                "headers": {"Content-Type": "application/json"},
            },
        })
        assert resp.status_code == 201

        # Immediately accessible
        resp = client.get("/secret/documents")
        assert resp.status_code == 200
        assert "passwords.txt" in resp.text

        # Disable it
        client.post("/_admin/api/routes/dynamic_honey/toggle", json={"enabled": False})
        resp = client.get("/secret/documents")
        assert resp.status_code == 404

        # Re-enable
        client.post("/_admin/api/routes/dynamic_honey/toggle", json={"enabled": True})
        resp = client.get("/secret/documents")
        assert resp.status_code == 200


class TestEdgeCases:
    def test_large_body(self, client):
        """Server handles large request bodies without crashing."""
        large_body = "A" * 100000
        resp = client.post("/api/auth/login", content=large_body,
                           headers={"Content-Type": "application/octet-stream"})
        assert resp.status_code == 200

    def test_unicode_in_path(self, client):
        resp = client.get("/api/users/用户123")
        assert resp.status_code == 200

    def test_empty_headers(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_malformed_json_body(self, client):
        resp = client.post("/api/auth/login",
                           content=b"{invalid json",
                           headers={"Content-Type": "application/json"})
        assert resp.status_code == 200

    def test_very_long_path(self, client):
        long_path = "/a" * 500
        resp = client.get(long_path)
        assert resp.status_code in (200, 404)

    def test_special_chars_in_query(self, client):
        resp = client.get("/api/users/1?foo=<script>alert(1)</script>")
        assert resp.status_code == 200
