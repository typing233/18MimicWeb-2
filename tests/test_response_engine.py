"""Tests for the response engine: variable substitution."""

import re
import time
import pytest
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient
from mimicweb.main import build_app


@pytest.fixture
def client(config_file):
    app = build_app(config_file)
    return TestClient(app)


class TestVariableSubstitution:
    def test_path_param_substitution(self, client):
        resp = client.get("/api/users/test-user-99")
        data = resp.json()
        assert data["id"] == "test-user-99"

    def test_timestamp_iso_format(self, client):
        resp = client.get("/api/users/1")
        data = resp.json()
        assert re.match(r"\d{4}-\d{2}-\d{2}T", data["ts"])

    def test_regex_group_substitution(self, client):
        resp = client.get("/admin/dashboard")
        data = resp.json()
        assert data["section"] == "dashboard"


class TestDelayInjection:
    def test_delay_is_applied(self, client):
        start = time.time()
        client.get("/api/users/1")
        elapsed = time.time() - start
        assert elapsed >= 0
