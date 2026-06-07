"""Tests for the log aggregator module."""

import time
import pytest

from mimicweb.log_aggregator import LogAggregator
from mimicweb.storage.base import LogEntry


def _make_entry(
    ts: float = 0,
    path: str = "/",
    client_ip: str = "1.2.3.4",
    suspicious: bool = False,
    labels: list[str] | None = None,
    response_time_ms: float = 50.0,
    method: str = "GET",
    status_code: int = 200,
) -> LogEntry:
    return LogEntry(
        timestamp=ts or time.time(),
        method=method,
        path=path,
        query="",
        headers={},
        client_ip=client_ip,
        client_port=12345,
        status_code=status_code,
        response_time_ms=response_time_ms,
        route_id="test",
        suspicious=suspicious,
        labels=labels or [],
        risk_score=50.0 if suspicious else 0.0,
    )


@pytest.fixture
def aggregator():
    return LogAggregator()


@pytest.fixture
def sample_entries():
    base_time = 1700000000.0
    return [
        _make_entry(ts=base_time, path="/page1", client_ip="1.1.1.1"),
        _make_entry(ts=base_time + 60, path="/page2", client_ip="1.1.1.1"),
        _make_entry(ts=base_time + 120, path="/page1", client_ip="2.2.2.2", suspicious=True, labels=["scanner"]),
        _make_entry(ts=base_time + 400, path="/api/v1/users", client_ip="3.3.3.3"),
        _make_entry(ts=base_time + 450, path="/api/v1/data", client_ip="3.3.3.3", suspicious=True, labels=["high_rate"]),
    ]


class TestAggregateByTime:
    def test_groups_into_buckets(self, aggregator, sample_entries):
        result = aggregator.aggregate_by_time(sample_entries, interval_seconds=300)
        assert len(result) >= 2

    def test_empty_entries(self, aggregator):
        result = aggregator.aggregate_by_time([], interval_seconds=300)
        assert result == []

    def test_counts_correct(self, aggregator, sample_entries):
        result = aggregator.aggregate_by_time(sample_entries, interval_seconds=300)
        total = sum(b["count"] for b in result)
        assert total == 5

    def test_suspicious_counted(self, aggregator, sample_entries):
        result = aggregator.aggregate_by_time(sample_entries, interval_seconds=300)
        total_suspicious = sum(b["suspicious_count"] for b in result)
        assert total_suspicious == 2


class TestAggregateBySource:
    def test_groups_by_ip(self, aggregator, sample_entries):
        result = aggregator.aggregate_by_source(sample_entries)
        assert len(result) == 3
        ips = [b["key"] for b in result]
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips
        assert "3.3.3.3" in ips

    def test_sorted_by_count(self, aggregator, sample_entries):
        result = aggregator.aggregate_by_source(sample_entries)
        counts = [b["count"] for b in result]
        assert counts == sorted(counts, reverse=True)


class TestAggregateByPath:
    def test_groups_by_path(self, aggregator, sample_entries):
        result = aggregator.aggregate_by_path(sample_entries)
        paths = [b["key"] for b in result]
        assert "/page1" in paths
        assert "/page2" in paths

    def test_path_counts(self, aggregator, sample_entries):
        result = aggregator.aggregate_by_path(sample_entries)
        page1 = next(b for b in result if b["key"] == "/page1")
        assert page1["count"] == 2


class TestAggregateByRisk:
    def test_groups_by_risk_level(self, aggregator, sample_entries):
        risk_scores = {"1.1.1.1": 10.0, "2.2.2.2": 70.0, "3.3.3.3": 45.0}
        result = aggregator.aggregate_by_risk(sample_entries, risk_scores)
        levels = [b["key"] for b in result]
        assert "low" in levels
        assert "high" in levels or "medium" in levels


class TestExport:
    def test_export_json(self, aggregator, sample_entries):
        import json
        output = aggregator.export_json(sample_entries, group_by="time")
        data = json.loads(output)
        assert "group_by" in data
        assert "buckets" in data
        assert data["group_by"] == "time"

    def test_export_csv(self, aggregator, sample_entries):
        output = aggregator.export_csv(sample_entries, group_by="source")
        assert "key" in output
        assert "count" in output
        lines = output.strip().split("\n")
        assert len(lines) >= 2

    def test_export_csv_empty(self, aggregator):
        output = aggregator.export_csv([], group_by="time")
        assert output == ""

    def test_export_json_by_path(self, aggregator, sample_entries):
        import json
        output = aggregator.export_json(sample_entries, group_by="path")
        data = json.loads(output)
        assert data["group_by"] == "path"
        assert len(data["buckets"]) > 0
