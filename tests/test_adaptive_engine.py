"""Tests for the adaptive engine module."""

import pytest

from mimicweb.adaptive_engine import AdaptiveEngine


@pytest.fixture
def engine():
    config = {
        "max_link_depth": 5,
        "enable_fake_forms": True,
        "enable_fake_search": True,
    }
    return AdaptiveEngine(config)


class TestPageGeneration:
    def test_generates_html(self, engine):
        html = engine.generate_page("/test", risk_score=50.0, request_count=10, labels=[])
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_low_risk_minimal_content(self, engine):
        html = engine.generate_page("/test", risk_score=10.0, request_count=2, labels=[])
        assert "<!DOCTYPE html>" in html
        assert "Data Export Request" not in html

    def test_medium_risk_includes_search(self, engine):
        html = engine.generate_page("/test", risk_score=30.0, request_count=10, labels=[])
        assert "Internal Search" in html
        assert '<form' in html

    def test_high_risk_includes_form(self, engine):
        html = engine.generate_page("/test", risk_score=50.0, request_count=20, labels=[])
        assert "Data Export Request" in html

    def test_very_high_risk_includes_data_table(self, engine):
        html = engine.generate_page("/test", risk_score=70.0, request_count=50, labels=[])
        assert "<table>" in html
        assert "EMP-" in html

    def test_links_increase_with_risk(self, engine):
        low_html = engine.generate_page("/test", risk_score=10.0, request_count=2, labels=[])
        high_html = engine.generate_page("/test", risk_score=90.0, request_count=100, labels=[])
        assert low_html.count("<a href=") < high_html.count("<a href=")

    def test_no_real_data_leaked(self, engine):
        html = engine.generate_page("/test", risk_score=80.0, request_count=50, labels=[])
        assert "@corp.internal" in html
        assert "@gmail.com" not in html
        assert "@company.com" not in html


class TestApiResponse:
    def test_generates_api_response(self, engine):
        data = engine.generate_api_response("/api/users", risk_score=50.0, request_count=10)
        assert "status" in data
        assert "data" in data
        assert isinstance(data["data"], list)
        assert len(data["data"]) > 0

    def test_response_has_pagination(self, engine):
        data = engine.generate_api_response("/api/users", risk_score=50.0, request_count=10)
        assert "pagination" in data
        assert "total" in data["pagination"]

    def test_high_risk_has_links(self, engine):
        data = engine.generate_api_response("/api/users", risk_score=60.0, request_count=30)
        assert "_links" in data

    def test_fake_records_have_correct_fields(self, engine):
        data = engine.generate_api_response("/api/users", risk_score=50.0, request_count=10)
        record = data["data"][0]
        assert "id" in record
        assert "name" in record
        assert "email" in record
        assert "department" in record

    def test_more_results_with_higher_risk(self, engine):
        low = engine.generate_api_response("/api/x", risk_score=10.0, request_count=2)
        high = engine.generate_api_response("/api/x", risk_score=90.0, request_count=100)
        assert len(low["data"]) < len(high["data"])


class TestConfigUpdate:
    def test_disable_forms(self):
        engine = AdaptiveEngine({
            "max_link_depth": 5,
            "enable_fake_forms": False,
            "enable_fake_search": True,
        })
        html = engine.generate_page("/test", risk_score=80.0, request_count=50, labels=[])
        assert "Data Export Request" not in html

    def test_disable_search(self):
        engine = AdaptiveEngine({
            "max_link_depth": 5,
            "enable_fake_forms": True,
            "enable_fake_search": False,
        })
        html = engine.generate_page("/test", risk_score=30.0, request_count=10, labels=[])
        assert "Internal Search" not in html
