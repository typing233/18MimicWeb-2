"""Tests for CompositeStorage (dual-write to Redis + PostgreSQL)."""

import time
from unittest.mock import AsyncMock, patch

import pytest
import fakeredis.aioredis

from mimicweb.storage.base import LogEntry
from mimicweb.storage.composite import CompositeStorage
from mimicweb.storage.redis_backend import RedisStorage
from mimicweb.storage.postgres_backend import PostgresStorage


def make_entry(path: str = "/test", suspicious: bool = False) -> LogEntry:
    return LogEntry(
        timestamp=time.time(),
        method="GET",
        path=path,
        query="",
        headers={"user-agent": "test"},
        client_ip="10.0.0.1",
        client_port=12345,
        status_code=200,
        response_time_ms=10.0,
        route_id="test",
        suspicious=suspicious,
        labels=["scan"] if suspicious else [],
        body_preview="",
        instance_id="composite-test",
    )


class FakeCompositeStorage(CompositeStorage):
    """CompositeStorage with fakeredis and mocked postgres."""

    def __init__(self):
        self._redis = RedisStorage.__new__(RedisStorage)
        self._redis._url = "redis://fake"
        self._redis._prefix = "mimicweb:composite:"
        self._redis._client = None

        self._postgres = AsyncMock(spec=PostgresStorage)
        self._postgres.store = AsyncMock()
        self._postgres.query = AsyncMock(return_value=[])
        self._postgres.count = AsyncMock(return_value=0)
        self._postgres.export_csv = AsyncMock(return_value="timestamp\n")
        self._postgres.close = AsyncMock()

    async def _init_redis(self):
        if self._redis._client is None:
            self._redis._client = fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
async def storage():
    s = FakeCompositeStorage()
    await s._init_redis()
    return s


class TestCompositeStore:
    @pytest.mark.asyncio
    async def test_writes_to_both_backends(self, storage):
        entry = make_entry()
        await storage.store(entry)

        # Redis should have the entry
        redis_count = await storage._redis.count()
        assert redis_count == 1

        # PostgreSQL store should have been called
        storage._postgres.store.assert_called_once_with(entry)

    @pytest.mark.asyncio
    async def test_postgres_failure_does_not_block_redis(self, storage):
        storage._postgres.store.side_effect = Exception("PG connection refused")

        entry = make_entry(path="/resilient")
        await storage.store(entry)  # should not raise

        # Redis still stores successfully
        redis_count = await storage._redis.count()
        assert redis_count == 1

    @pytest.mark.asyncio
    async def test_multiple_stores(self, storage):
        for i in range(5):
            await storage.store(make_entry(path=f"/p/{i}"))

        redis_count = await storage._redis.count()
        assert redis_count == 5
        assert storage._postgres.store.call_count == 5


class TestCompositeQuery:
    @pytest.mark.asyncio
    async def test_query_prefers_postgres(self, storage):
        expected = [make_entry(path="/from-pg")]
        storage._postgres.query.return_value = expected

        results = await storage.query(limit=10)
        assert results == expected
        storage._postgres.query.assert_called_once()

    @pytest.mark.asyncio
    async def test_query_falls_back_to_redis_on_pg_error(self, storage):
        storage._postgres.query.side_effect = Exception("PG down")

        # Put data into Redis
        await storage._redis.store(make_entry(path="/from-redis"))

        results = await storage.query(limit=10)
        assert len(results) == 1
        assert results[0].path == "/from-redis"

    @pytest.mark.asyncio
    async def test_query_passes_filters_to_postgres(self, storage):
        storage._postgres.query.return_value = []

        await storage.query(
            limit=50, offset=10,
            suspicious_only=True,
            method="POST",
            path_contains="/api",
            since=1000.0,
        )
        storage._postgres.query.assert_called_once_with(
            limit=50, offset=10,
            suspicious_only=True,
            method="POST",
            path_contains="/api",
            since=1000.0,
        )


class TestCompositeCount:
    @pytest.mark.asyncio
    async def test_count_from_postgres(self, storage):
        storage._postgres.count.return_value = 42

        count = await storage.count()
        assert count == 42

    @pytest.mark.asyncio
    async def test_count_falls_back_to_redis(self, storage):
        storage._postgres.count.side_effect = Exception("PG error")
        await storage._redis.store(make_entry())
        await storage._redis.store(make_entry())

        count = await storage.count()
        assert count == 2


class TestCompositeExport:
    @pytest.mark.asyncio
    async def test_export_from_postgres(self, storage):
        storage._postgres.export_csv.return_value = "timestamp,method\n1234,GET\n"

        csv = await storage.export_csv()
        assert "1234" in csv

    @pytest.mark.asyncio
    async def test_export_falls_back_to_redis(self, storage):
        storage._postgres.export_csv.side_effect = Exception("PG error")
        await storage._redis.store(make_entry(path="/redis-export"))

        csv = await storage.export_csv()
        assert "/redis-export" in csv


class TestCompositeClose:
    @pytest.mark.asyncio
    async def test_close_both_backends(self, storage):
        await storage.close()
        storage._postgres.close.assert_called_once()
        assert storage._redis._client is None
