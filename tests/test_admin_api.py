"""Tests for the admin API."""

import pytest
from starlette.testclient import TestClient

from mimicweb.main import build_app


@pytest.fixture
def client(config_file):
    app = build_app(config_file)
    return TestClient(app)


class TestAdminDashboard:
    def test_dashboard_page(self, client):
        resp = client.get("/_admin")
        assert resp.status_code == 200
        assert "MimicWeb Admin" in resp.text

    def test_get_stats(self, client):
        # Generate some traffic first
        client.get("/")
        resp = client.get("/_admin/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "suspicious_requests" in data
        assert "active_routes" in data
        assert "uptime_seconds" in data


class TestAdminLogs:
    def test_get_logs_empty(self, client):
        resp = client.get("/_admin/api/logs")
        assert resp.status_code == 200
        data = resp.json()
        assert "entries" in data
        assert "total" in data

    def test_logs_after_request(self, client):
        client.get("/")
        resp = client.get("/_admin/api/logs")
        data = resp.json()
        assert data["total"] >= 1

    def test_filter_by_method(self, client):
        client.get("/")
        resp = client.get("/_admin/api/logs?method=GET")
        assert resp.status_code == 200

    def test_filter_suspicious(self, client):
        client.get("/", headers={"User-Agent": "sqlmap"})
        resp = client.get("/_admin/api/logs?suspicious=true")
        data = resp.json()
        assert any(e["suspicious"] for e in data["entries"])

    def test_export_csv(self, client):
        client.get("/")
        resp = client.get("/_admin/api/logs/export")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "timestamp" in resp.text


class TestAdminRoutes:
    def test_list_routes(self, client):
        resp = client.get("/_admin/api/routes")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["routes"]) > 0

    def test_create_route(self, client):
        resp = client.post("/_admin/api/routes", json={
            "id": "new_test_route",
            "path": "/test/new",
            "method": "GET",
            "response": {"status": 200, "body": "new route"},
        })
        assert resp.status_code == 201
        assert resp.json()["route"]["id"] == "new_test_route"

        # Verify it works
        resp = client.get("/test/new")
        assert resp.status_code == 200
        assert "new route" in resp.text

    def test_create_duplicate_route(self, client):
        client.post("/_admin/api/routes", json={
            "id": "dup_route", "path": "/dup", "method": "GET",
            "response": {"status": 200, "body": "x"},
        })
        resp = client.post("/_admin/api/routes", json={
            "id": "dup_route", "path": "/dup2", "method": "GET",
            "response": {"status": 200, "body": "y"},
        })
        assert resp.status_code == 409

    def test_update_route(self, client):
        client.post("/_admin/api/routes", json={
            "id": "update_me", "path": "/update", "method": "GET",
            "response": {"status": 200, "body": "original"},
        })
        resp = client.put("/_admin/api/routes/update_me", json={
            "response": {"status": 200, "body": "updated"},
        })
        assert resp.status_code == 200

        resp = client.get("/update")
        assert "updated" in resp.text

    def test_delete_route(self, client):
        client.post("/_admin/api/routes", json={
            "id": "delete_me", "path": "/deletable", "method": "GET",
            "response": {"status": 200, "body": "bye"},
        })
        resp = client.delete("/_admin/api/routes/delete_me")
        assert resp.status_code == 200

        resp = client.get("/deletable")
        assert resp.status_code == 404

    def test_toggle_route(self, client):
        resp = client.post("/_admin/api/routes/home/toggle", json={"enabled": False})
        assert resp.status_code == 200

        resp = client.get("/")
        assert resp.status_code == 404

        client.post("/_admin/api/routes/home/toggle", json={"enabled": True})
        resp = client.get("/")
        assert resp.status_code == 200

    def test_reload_config(self, client):
        resp = client.post("/_admin/api/reload")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_update_nonexistent(self, client):
        resp = client.put("/_admin/api/routes/nonexistent", json={"path": "/x"})
        assert resp.status_code == 404

    def test_create_missing_fields(self, client):
        resp = client.post("/_admin/api/routes", json={"method": "GET"})
        assert resp.status_code == 400
