"""Tests for the dynamic router."""

import re
import pytest
from starlette.testclient import TestClient

from mimicweb.config import AppConfig
from mimicweb.main import build_app


@pytest.fixture
def client(config_file):
    app = build_app(config_file)
    return TestClient(app)


class TestRouteMatching:
    def test_static_route(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Hello World" in resp.text

    def test_path_params(self, client):
        resp = client.get("/api/users/42")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "42"
        assert "ts" in data

    def test_regex_route(self, client):
        resp = client.get("/admin/settings")
        assert resp.status_code == 403
        data = resp.json()
        assert data["section"] == "settings"

    def test_regex_no_match(self, client):
        resp = client.get("/admin/")
        assert resp.status_code == 404

    def test_disabled_route(self, client):
        resp = client.get("/disabled")
        assert resp.status_code == 404

    def test_method_mismatch(self, client):
        resp = client.post("/")
        assert resp.status_code == 404

    def test_server_header(self, client):
        resp = client.get("/")
        assert resp.headers.get("server") == "TestServer/1.0"


class TestConditionalResponses:
    def test_condition_met(self, client):
        resp = client.get("/api/data", headers={"Authorization": "Bearer abc123"})
        assert resp.status_code == 200
        assert resp.json()["data"] == "secret"

    def test_condition_unmet(self, client):
        resp = client.get("/api/data")
        assert resp.status_code == 401
        assert resp.json()["error"] == "unauthorized"


class TestErrorInjection:
    def test_full_error_rate(self, client):
        resp = client.get("/api/flaky")
        assert resp.status_code == 500
        assert "internal_server_error" in resp.text
