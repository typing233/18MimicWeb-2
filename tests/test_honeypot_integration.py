"""Integration tests for the honeypot enhancement features."""

import time
import pytest
from starlette.testclient import TestClient

from mimicweb.main import build_app


@pytest.fixture
def client(config_file):
    app = build_app(config_file)
    return TestClient(app)


class TestBehaviorTracking:
    def test_sessions_endpoint_available(self, client):
        resp = client.get("/_admin/api/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert "sessions" in data

    def test_session_created_on_request(self, client):
        client.get("/", headers={"User-Agent": "TestBot"})
        resp = client.get("/_admin/api/sessions")
        data = resp.json()
        assert len(data["sessions"]) > 0

    def test_session_detail(self, client):
        client.get("/page1", headers={"User-Agent": "TestBot"})
        client.get("/page2", headers={"User-Agent": "TestBot"})
        resp = client.get("/_admin/api/sessions")
        sessions = resp.json()["sessions"]
        ip = sessions[0]["client_ip"]
        resp = client.get(f"/_admin/api/sessions/{ip}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["request_count"] >= 2

    def test_risk_score_increases_with_suspicious_behavior(self, client):
        for i in range(8):
            client.get(f"/nonexist_{i}", headers={"User-Agent": ""})
        resp = client.get("/_admin/api/sessions")
        sessions = resp.json()["sessions"]
        assert any(s["risk_score"] > 0 for s in sessions)


class TestAdaptiveResponses:
    def test_normal_requests_serve_configured_routes(self, client):
        resp = client.get("/", headers={"User-Agent": "Mozilla/5.0"})
        assert resp.status_code == 200
        assert "Hello World" in resp.text

    def test_crawler_gets_dynamic_content(self, client):
        for i in range(12):
            client.get(f"/scan/{i}/deep/path", headers={"User-Agent": ""})
        resp = client.get("/another/target", headers={"User-Agent": ""})
        if resp.status_code == 200:
            assert len(resp.text) > 50


class TestAntiCrawlStrategies:
    def test_rapid_enumeration_triggers_strategy(self, client):
        responses = []
        for i in range(20):
            r = client.get(f"/a/b/c/d/e/f/{i}", headers={"User-Agent": ""})
            responses.append(r)
        last_responses = responses[-5:]
        has_anticrawl = any(
            r.status_code in (200, 302) and "Hello World" not in r.text
            for r in last_responses
        )
        assert has_anticrawl

    def test_normal_user_unaffected(self, client):
        resp = client.get("/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        assert resp.status_code == 200
        assert "Hello World" in resp.text


class TestAggregationEndpoints:
    def test_aggregation_by_time(self, client):
        client.get("/page1")
        client.get("/page2")
        resp = client.get("/_admin/api/aggregation?group_by=time&interval=300")
        assert resp.status_code == 200
        data = resp.json()
        assert "buckets" in data
        assert data["group_by"] == "time"

    def test_aggregation_by_source(self, client):
        client.get("/page1")
        resp = client.get("/_admin/api/aggregation?group_by=source")
        assert resp.status_code == 200
        data = resp.json()
        assert data["group_by"] == "source"

    def test_aggregation_by_path(self, client):
        client.get("/page1")
        client.get("/page2")
        resp = client.get("/_admin/api/aggregation?group_by=path")
        assert resp.status_code == 200
        data = resp.json()
        assert data["group_by"] == "path"
        assert len(data["buckets"]) > 0

    def test_aggregation_by_risk(self, client):
        client.get("/page1")
        resp = client.get("/_admin/api/aggregation?group_by=risk")
        assert resp.status_code == 200
        data = resp.json()
        assert data["group_by"] == "risk"

    def test_export_json(self, client):
        client.get("/page1")
        resp = client.get("/_admin/api/aggregation/export?format=json&group_by=time")
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]

    def test_export_csv(self, client):
        client.get("/page1")
        resp = client.get("/_admin/api/aggregation/export?format=csv&group_by=source")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]


class TestHoneypotConfig:
    def test_config_endpoint(self, client):
        resp = client.get("/_admin/api/honeypot/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "enabled" in data
        assert "behavior_analysis" in data
        assert "adaptive_response" in data
        assert "anticrawl" in data
        assert "log_export" in data

    def test_config_has_defaults(self, client):
        resp = client.get("/_admin/api/honeypot/config")
        data = resp.json()
        assert data["behavior_analysis"]["rate_threshold_per_minute"] == 30
        assert data["anticrawl"]["score_threshold"] == 30.0
        assert data["adaptive_response"]["max_link_depth"] == 5


class TestLogExport:
    def test_csv_export_includes_risk_score(self, client):
        client.get("/page1")
        resp = client.get("/_admin/api/logs/export")
        assert resp.status_code == 200
        assert "risk_score" in resp.text
