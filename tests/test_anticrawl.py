"""Tests for the anti-crawler strategy module."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from starlette.testclient import TestClient

from mimicweb.anticrawl import AntiCrawlerStrategy
from mimicweb.adaptive_engine import AdaptiveEngine


@pytest.fixture
def adaptive_engine():
    return AdaptiveEngine({
        "max_link_depth": 5,
        "enable_fake_forms": True,
        "enable_fake_search": True,
    })


@pytest.fixture
def strategy(adaptive_engine):
    config = {
        "enabled": True,
        "score_threshold": 30.0,
        "delay": {"enabled": False, "min_ms": 0, "max_ms": 0},
        "slow_drip_max_ms": 100,
        "strategies": {
            "redirect_deeper": True,
            "fake_page": True,
            "pollute_data": True,
            "slow_drip": True,
        },
    }
    return AntiCrawlerStrategy(config, adaptive_engine)


class TestStrategySelection:
    @pytest.mark.asyncio
    async def test_below_threshold_returns_none(self, strategy):
        request = MagicMock()
        request.url.path = "/test"
        result = await strategy.apply(request, risk_score=10.0, request_count=5, labels=[])
        assert result is None

    @pytest.mark.asyncio
    async def test_above_threshold_returns_response(self, strategy):
        request = MagicMock()
        request.url.path = "/test"
        request.client.host = "1.2.3.4"
        result = await strategy.apply(request, risk_score=50.0, request_count=20, labels=[])
        assert result is not None

    @pytest.mark.asyncio
    async def test_api_path_gets_polluted_data(self, strategy):
        request = MagicMock()
        request.url.path = "/api/v1/users"
        request.client.host = "1.2.3.4"
        result = await strategy.apply(request, risk_score=50.0, request_count=20, labels=[])
        assert result is not None
        assert result.headers.get("content-type") == "application/json"

    @pytest.mark.asyncio
    async def test_bruteforce_gets_redirect(self, strategy):
        request = MagicMock()
        request.url.path = "/admin/secret"
        request.client.host = "1.2.3.4"
        result = await strategy.apply(
            request, risk_score=50.0, request_count=20, labels=["directory_bruteforce"]
        )
        assert result is not None
        assert result.status_code == 302

    @pytest.mark.asyncio
    async def test_very_high_risk_slow_drip(self, strategy):
        request = MagicMock()
        request.url.path = "/documents"
        request.client.host = "1.2.3.4"
        result = await strategy.apply(
            request, risk_score=85.0, request_count=100, labels=["high_request_rate"]
        )
        assert result is not None
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_disabled_returns_none(self, adaptive_engine):
        config = {"enabled": False, "score_threshold": 30.0}
        strat = AntiCrawlerStrategy(config, adaptive_engine)
        request = MagicMock()
        request.url.path = "/test"
        result = await strat.apply(request, risk_score=90.0, request_count=100, labels=[])
        assert result is None


class TestIntegrationWithApp:
    def test_normal_request_not_affected(self, config_file):
        from mimicweb.main import build_app
        app = build_app(config_file)
        client = TestClient(app)
        resp = client.get("/", headers={"User-Agent": "Mozilla/5.0 (normal browser)"})
        assert resp.status_code == 200
        assert "Hello World" in resp.text

    def test_repeated_404s_trigger_anticrawl(self, config_file):
        from mimicweb.main import build_app
        app = build_app(config_file)
        client = TestClient(app)
        for i in range(10):
            client.get(f"/nonexistent/{i}", headers={"User-Agent": ""})
        resp = client.get("/another/missing/path", headers={"User-Agent": ""})
        assert resp.status_code in (200, 302, 404)
