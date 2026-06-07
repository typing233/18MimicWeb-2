"""Tests for storage backends."""

import asyncio
import time
import pytest

from mimicweb.storage.base import LogEntry
from mimicweb.storage.local import LocalStorage


def make_entry(suspicious: bool = False, method: str = "GET", path: str = "/test") -> LogEntry:
    return LogEntry(
        timestamp=time.time(),
        method=method,
        path=path,
        query="",
        headers={"user-agent": "test"},
        client_ip="127.0.0.1",
        client_port=12345,
        status_code=200,
        response_time_ms=5.0,
        route_id="test_route",
        suspicious=suspicious,
        labels=["test_label"] if suspicious else [],
        body_preview="",
        instance_id="test-node",
    )


class TestLocalStorage:
    @pytest.fixture
    def storage(self, tmp_path):
        return LocalStorage(log_dir=str(tmp_path))

    @pytest.mark.asyncio
    async def test_store_and_query(self, storage):
        entry = make_entry()
        await storage.store(entry)

        results = await storage.query(limit=10)
        assert len(results) == 1
        assert results[0].method == "GET"
        assert results[0].path == "/test"

    @pytest.mark.asyncio
    async def test_count(self, storage):
        await storage.store(make_entry())
        await storage.store(make_entry(suspicious=True))

        assert await storage.count() == 2
        assert await storage.count(suspicious_only=True) == 1

    @pytest.mark.asyncio
    async def test_filter_by_method(self, storage):
        await storage.store(make_entry(method="GET"))
        await storage.store(make_entry(method="POST"))

        results = await storage.query(method="POST")
        assert len(results) == 1
        assert results[0].method == "POST"

    @pytest.mark.asyncio
    async def test_filter_by_path(self, storage):
        await storage.store(make_entry(path="/api/users"))
        await storage.store(make_entry(path="/api/data"))

        results = await storage.query(path_contains="users")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_filter_suspicious_only(self, storage):
        await storage.store(make_entry(suspicious=False))
        await storage.store(make_entry(suspicious=True))

        results = await storage.query(suspicious_only=True)
        assert len(results) == 1
        assert results[0].suspicious is True

    @pytest.mark.asyncio
    async def test_export_csv(self, storage):
        await storage.store(make_entry())
        csv_data = await storage.export_csv()
        assert "timestamp" in csv_data
        assert "127.0.0.1" in csv_data

    @pytest.mark.asyncio
    async def test_pagination(self, storage):
        for i in range(20):
            await storage.store(make_entry(path=f"/page/{i}"))

        page1 = await storage.query(limit=5, offset=0)
        page2 = await storage.query(limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        assert page1[0].path != page2[0].path

    @pytest.mark.asyncio
    async def test_persistence(self, tmp_path):
        storage1 = LocalStorage(log_dir=str(tmp_path))
        await storage1.store(make_entry(path="/persistent"))

        storage2 = LocalStorage(log_dir=str(tmp_path))
        results = await storage2.query()
        assert len(results) == 1
        assert results[0].path == "/persistent"


class TestLogEntry:
    def test_to_json(self):
        entry = make_entry()
        json_str = entry.to_json()
        assert '"method": "GET"' in json_str

    def test_from_dict(self):
        entry = make_entry()
        import json
        data = json.loads(entry.to_json())
        restored = LogEntry.from_dict(data)
        assert restored.method == entry.method
        assert restored.path == entry.path

    def test_csv_row(self):
        entry = make_entry(suspicious=True)
        row = entry.to_csv_row()
        assert len(row) == len(LogEntry.csv_header())
