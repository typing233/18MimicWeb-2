"""Tests for Redis storage backend using fakeredis."""

import time
import pytest
import fakeredis.aioredis

from mimicweb.storage.base import LogEntry
from mimicweb.storage.redis_backend import RedisStorage


def make_entry(
    suspicious: bool = False,
    method: str = "GET",
    path: str = "/test",
    timestamp: float | None = None,
) -> LogEntry:
    return LogEntry(
        timestamp=timestamp or time.time(),
        method=method,
        path=path,
        query="q=hello",
        headers={"user-agent": "test-agent"},
        client_ip="192.168.1.100",
        client_port=54321,
        status_code=200,
        response_time_ms=12.5,
        route_id="test_route",
        suspicious=suspicious,
        labels=["known_scanner"] if suspicious else [],
        body_preview="request body",
        instance_id="test-node-1",
    )


class FakeRedisStorage(RedisStorage):
    """RedisStorage subclass that uses fakeredis for testing."""

    def __init__(self, prefix: str = "mimicweb:test:"):
        self._url = "redis://fake"
        self._prefix = prefix
        self._client = None

    async def _get_client(self):
        if self._client is None:
            self._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        return self._client


@pytest.fixture
def storage():
    return FakeRedisStorage()


class TestRedisStore:
    @pytest.mark.asyncio
    async def test_store_single_entry(self, storage):
        entry = make_entry()
        await storage.store(entry)
        count = await storage.count()
        assert count == 1

    @pytest.mark.asyncio
    async def test_store_multiple_entries(self, storage):
        for i in range(10):
            await storage.store(make_entry(path=f"/path/{i}"))
        count = await storage.count()
        assert count == 10

    @pytest.mark.asyncio
    async def test_store_suspicious_tracked_separately(self, storage):
        await storage.store(make_entry(suspicious=False))
        await storage.store(make_entry(suspicious=True))
        await storage.store(make_entry(suspicious=True))

        total = await storage.count()
        suspicious = await storage.count(suspicious_only=True)
        assert total == 3
        assert suspicious == 2


class TestRedisQuery:
    @pytest.mark.asyncio
    async def test_query_returns_entries(self, storage):
        await storage.store(make_entry(path="/api/users"))
        await storage.store(make_entry(path="/api/data"))

        results = await storage.query(limit=10)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_limit(self, storage):
        for i in range(20):
            await storage.store(make_entry(path=f"/page/{i}"))

        results = await storage.query(limit=5)
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_query_offset(self, storage):
        for i in range(10):
            await storage.store(make_entry(path=f"/item/{i}"))

        page1 = await storage.query(limit=3, offset=0)
        page2 = await storage.query(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        # Pages should not overlap
        paths1 = {e.path for e in page1}
        paths2 = {e.path for e in page2}
        assert paths1.isdisjoint(paths2)

    @pytest.mark.asyncio
    async def test_query_filter_suspicious(self, storage):
        await storage.store(make_entry(suspicious=False, path="/normal"))
        await storage.store(make_entry(suspicious=True, path="/scan"))

        results = await storage.query(suspicious_only=True)
        assert len(results) == 1
        assert results[0].path == "/scan"
        assert results[0].suspicious is True

    @pytest.mark.asyncio
    async def test_query_filter_method(self, storage):
        await storage.store(make_entry(method="GET"))
        await storage.store(make_entry(method="POST"))
        await storage.store(make_entry(method="GET"))

        results = await storage.query(method="POST")
        assert len(results) == 1
        assert results[0].method == "POST"

    @pytest.mark.asyncio
    async def test_query_filter_path_contains(self, storage):
        await storage.store(make_entry(path="/api/users/123"))
        await storage.store(make_entry(path="/api/data/456"))
        await storage.store(make_entry(path="/health"))

        results = await storage.query(path_contains="/api/")
        assert len(results) == 2
        assert all("/api/" in e.path for e in results)

    @pytest.mark.asyncio
    async def test_query_filter_since(self, storage):
        old_time = time.time() - 3600
        new_time = time.time()

        await storage.store(make_entry(timestamp=old_time, path="/old"))
        await storage.store(make_entry(timestamp=new_time, path="/new"))

        results = await storage.query(since=new_time - 1)
        assert len(results) == 1
        assert results[0].path == "/new"

    @pytest.mark.asyncio
    async def test_query_combined_filters(self, storage):
        await storage.store(make_entry(method="POST", path="/api/login", suspicious=True))
        await storage.store(make_entry(method="GET", path="/api/login", suspicious=True))
        await storage.store(make_entry(method="POST", path="/api/data", suspicious=False))

        results = await storage.query(
            method="POST", path_contains="login", suspicious_only=True
        )
        assert len(results) == 1
        assert results[0].method == "POST"
        assert "login" in results[0].path


class TestRedisCSVExport:
    @pytest.mark.asyncio
    async def test_export_all(self, storage):
        await storage.store(make_entry(path="/one"))
        await storage.store(make_entry(path="/two", suspicious=True))

        csv_data = await storage.export_csv()
        assert "timestamp" in csv_data  # header
        assert "/one" in csv_data
        assert "/two" in csv_data

    @pytest.mark.asyncio
    async def test_export_suspicious_only(self, storage):
        await storage.store(make_entry(path="/normal", suspicious=False))
        await storage.store(make_entry(path="/scan", suspicious=True))

        csv_data = await storage.export_csv(suspicious_only=True)
        assert "/scan" in csv_data
        assert "/normal" not in csv_data

    @pytest.mark.asyncio
    async def test_export_empty(self, storage):
        csv_data = await storage.export_csv()
        assert "timestamp" in csv_data  # header always present
        lines = csv_data.strip().split("\n")
        assert len(lines) == 1  # only header


class TestRedisClose:
    @pytest.mark.asyncio
    async def test_close_cleans_up(self, storage):
        await storage.store(make_entry())
        await storage.close()
        assert storage._client is None

    @pytest.mark.asyncio
    async def test_close_idempotent(self, storage):
        await storage.close()
        await storage.close()  # should not raise


class TestRedisMultiInstance:
    @pytest.mark.asyncio
    async def test_shared_log_visibility(self):
        """Two storage instances sharing the same Redis see each other's logs."""
        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

        storage_a = FakeRedisStorage(prefix="mimicweb:shared:")
        storage_b = FakeRedisStorage(prefix="mimicweb:shared:")
        # Point both to the same fake redis instance
        storage_a._client = fake_redis
        storage_b._client = fake_redis

        # Instance A writes
        entry_a = make_entry(path="/from-node-a")
        entry_a.instance_id = "node-a"
        await storage_a.store(entry_a)

        # Instance B writes
        entry_b = make_entry(path="/from-node-b")
        entry_b.instance_id = "node-b"
        await storage_b.store(entry_b)

        # Instance A can see both
        results_a = await storage_a.query(limit=10)
        assert len(results_a) == 2
        paths = {e.path for e in results_a}
        assert "/from-node-a" in paths
        assert "/from-node-b" in paths

        # Instance B can see both
        results_b = await storage_b.query(limit=10)
        assert len(results_b) == 2

        # Verify instance_id is preserved
        instances = {e.instance_id for e in results_b}
        assert "node-a" in instances
        assert "node-b" in instances

        await fake_redis.aclose()
