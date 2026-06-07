"""Tests for scanner detection."""

import pytest
from unittest.mock import MagicMock

from starlette.testclient import TestClient
from mimicweb.main import build_app


@pytest.fixture
def client(config_file):
    app = build_app(config_file)
    return TestClient(app)


class TestScannerDetection:
    def test_normal_request(self, client):
        resp = client.get("/", headers={"User-Agent": "Mozilla/5.0"})
        assert resp.status_code == 200

    def test_sqlmap_detected(self, client):
        resp = client.get("/", headers={"User-Agent": "sqlmap/1.5"})
        assert resp.status_code == 200

    def test_path_traversal_detected(self, client):
        resp = client.get("/../../etc/passwd")
        # Should still respond (honeypot) but log as suspicious
        assert resp.status_code in (200, 403, 404)

    def test_nikto_detected(self, client):
        resp = client.get("/", headers={"User-Agent": "Nikto/2.1.6"})
        assert resp.status_code == 200
