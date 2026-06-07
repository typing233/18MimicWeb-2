"""Tests for the behavior analyzer module."""

import time
import pytest

from mimicweb.behavior_analyzer import BehaviorAnalyzer, SessionProfile


@pytest.fixture
def analyzer():
    config = {
        "session_ttl_seconds": 3600,
        "analysis_window_seconds": 300,
        "rate_threshold_per_minute": 30,
        "path_diversity_threshold": 20,
        "depth_threshold": 5,
        "sequential_404_threshold": 5,
    }
    return BehaviorAnalyzer(config)


class TestSessionTracking:
    def test_new_session_created(self, analyzer):
        result = analyzer.record_request("1.2.3.4", "/", "GET", 200, user_agent="Mozilla/5.0")
        assert result["request_count"] == 1
        assert result["risk_score"] == 0.0

    def test_session_accumulates(self, analyzer):
        analyzer.record_request("1.2.3.4", "/page1", "GET", 200)
        result = analyzer.record_request("1.2.3.4", "/page2", "GET", 200)
        assert result["request_count"] == 2

    def test_separate_sessions_per_ip(self, analyzer):
        analyzer.record_request("1.2.3.4", "/", "GET", 200)
        analyzer.record_request("5.6.7.8", "/", "GET", 200)
        assert len(analyzer.sessions) == 2

    def test_get_session(self, analyzer):
        analyzer.record_request("1.2.3.4", "/test", "GET", 200)
        session = analyzer.get_session("1.2.3.4")
        assert session is not None
        assert session.request_count == 1
        assert "/test" in session.paths

    def test_get_nonexistent_session(self, analyzer):
        assert analyzer.get_session("9.9.9.9") is None


class TestRiskScoring:
    def test_missing_user_agent_adds_score(self, analyzer):
        result = analyzer.record_request("1.2.3.4", "/", "GET", 200, user_agent="")
        assert result["risk_score"] > 0
        assert "missing_user_agent" in result["labels"]

    def test_sequential_404_detection(self, analyzer):
        for i in range(6):
            result = analyzer.record_request("1.2.3.4", f"/path{i}", "GET", 404)
        assert "directory_bruteforce" in result["labels"]
        assert result["risk_score"] > 0

    def test_deep_traversal(self, analyzer):
        result = analyzer.record_request(
            "1.2.3.4", "/a/b/c/d/e/f/g", "GET", 200, user_agent="Mozilla/5.0"
        )
        assert "deep_traversal" in result["labels"]

    def test_path_enumeration(self, analyzer):
        for i in range(25):
            result = analyzer.record_request(
                "1.2.3.4", f"/unique_path_{i}", "GET", 200, user_agent="Mozilla/5.0"
            )
        assert "path_enumeration" in result["labels"]

    def test_high_404_ratio(self, analyzer):
        for i in range(8):
            analyzer.record_request("1.2.3.4", f"/found{i}", "GET", 404, user_agent="Mozilla/5.0")
        for i in range(4):
            result = analyzer.record_request("1.2.3.4", f"/ok{i}", "GET", 200, user_agent="Mozilla/5.0")
        assert "high_404_ratio" in result["labels"]

    def test_score_capped_at_100(self, analyzer):
        for i in range(100):
            result = analyzer.record_request(
                "1.2.3.4", f"/a/b/c/d/e/f/{i}", "GET", 404, user_agent=""
            )
        assert result["risk_score"] <= 100.0

    def test_normal_browsing_low_score(self, analyzer):
        result = analyzer.record_request(
            "1.2.3.4", "/", "GET", 200, user_agent="Mozilla/5.0 (Windows NT 10.0)"
        )
        assert result["risk_score"] == 0.0
        assert result["labels"] == []


class TestCleanup:
    def test_cleanup_expired_sessions(self, analyzer):
        analyzer.record_request("1.2.3.4", "/", "GET", 200)
        session = analyzer.get_session("1.2.3.4")
        session.last_seen = time.time() - 7200
        analyzer.cleanup_expired()
        assert analyzer.get_session("1.2.3.4") is None

    def test_cleanup_keeps_active_sessions(self, analyzer):
        analyzer.record_request("1.2.3.4", "/", "GET", 200)
        analyzer.cleanup_expired()
        assert analyzer.get_session("1.2.3.4") is not None
