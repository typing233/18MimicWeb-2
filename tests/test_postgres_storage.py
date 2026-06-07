"""Tests for PostgreSQL storage backend using mock asyncpg."""

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mimicweb.storage.base import LogEntry
from mimicweb.storage.postgres_backend import PostgresStorage, CREATE_TABLE_SQL


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
        client_ip="10.0.0.1",
        client_port=8080,
        status_code=200,
        response_time_ms=15.0,
        route_id="pg_route",
        suspicious=suspicious,
        labels=["sqli_probe"] if suspicious else [],
        body_preview="test body",
        instance_id="pg-node-1",
    )


def make_pg_row(
    path: str = "/test",
    method: str = "GET",
    suspicious: bool = False,
    timestamp: float | None = None,
) -> dict:
    return {
        "timestamp": timestamp or time.time(),
        "method": method,
        "path": path,
        "query": "q=hello",
        "headers": json.dumps({"user-agent": "test"}),
        "client_ip": "10.0.0.1",
        "client_port": 8080,
        "status_code": 200,
        "response_time_ms": 15.0,
        "route_id": "pg_route",
        "suspicious": suspicious,
        "labels": ["sqli_probe"] if suspicious else [],
        "body_preview": "body",
        "instance_id": "pg-node-1",
    }


class FakeRecord(dict):
    """Mimics asyncpg Record."""
    def __getitem__(self, key):
        return super().__getitem__(key)


def make_record(**kwargs) -> FakeRecord:
    return FakeRecord(**kwargs)


class FakeConnection:
    """Mock asyncpg connection supporting async context manager on pool.acquire()."""
    def __init__(self):
        self.execute = AsyncMock()
        self.fetch = AsyncMock(return_value=[])
        self.fetchrow = AsyncMock(return_value={"cnt": 0})


class FakePool:
    """Mock asyncpg pool with proper acquire() context manager."""
    def __init__(self, conn: FakeConnection):
        self._conn = conn
        self.close = AsyncMock()

    def acquire(self):
        return self

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *args):
        pass


@pytest.fixture
def pg_conn():
    return FakeConnection()


@pytest.fixture
def storage(pg_conn):
    pool = FakePool(pg_conn)
    s = PostgresStorage(dsn="postgresql://test:test@localhost/testdb")
    s._pool = pool
    return s


class TestPostgresStore:
    @pytest.mark.asyncio
    async def test_store_calls_execute(self, storage, pg_conn):
        entry = make_entry()
        await storage.store(entry)

        pg_conn.execute.assert_called_once()
        call_args = pg_conn.execute.call_args
        sql = call_args[0][0]
        assert "INSERT INTO request_logs" in sql
        params = call_args[0][1:]
        assert params[0] == entry.timestamp
        assert params[1] == entry.method
        assert params[2] == entry.path
        assert params[10] == entry.suspicious
        assert params[11] == entry.labels

    @pytest.mark.asyncio
    async def test_store_multiple(self, storage, pg_conn):
        for i in range(5):
            await storage.store(make_entry(path=f"/p/{i}"))
        assert pg_conn.execute.call_count == 5

    @pytest.mark.asyncio
    async def test_store_suspicious_entry(self, storage, pg_conn):
        entry = make_entry(suspicious=True)
        await storage.store(entry)

        call_args = pg_conn.execute.call_args[0]
        assert call_args[11] is True
        assert call_args[12] == ["sqli_probe"]


class TestPostgresQuery:
    @pytest.mark.asyncio
    async def test_query_basic(self, storage, pg_conn):
        pg_conn.fetch.return_value = [make_record(**make_pg_row(path="/api/users"))]

        results = await storage.query(limit=10)
        assert len(results) == 1
        assert results[0].path == "/api/users"
        assert results[0].method == "GET"

    @pytest.mark.asyncio
    async def test_query_with_method_filter(self, storage, pg_conn):
        pg_conn.fetch.return_value = [make_record(**make_pg_row(method="POST", path="/login"))]

        results = await storage.query(method="POST")
        pg_conn.fetch.assert_called_once()
        sql = pg_conn.fetch.call_args[0][0]
        assert "method = $1" in sql
        params = pg_conn.fetch.call_args[0][1:]
        assert "POST" in params

    @pytest.mark.asyncio
    async def test_query_with_suspicious_filter(self, storage, pg_conn):
        pg_conn.fetch.return_value = [make_record(**make_pg_row(suspicious=True))]

        results = await storage.query(suspicious_only=True)
        sql = pg_conn.fetch.call_args[0][0]
        assert "suspicious = TRUE" in sql

    @pytest.mark.asyncio
    async def test_query_with_path_filter(self, storage, pg_conn):
        pg_conn.fetch.return_value = []

        await storage.query(path_contains="/api/")
        sql = pg_conn.fetch.call_args[0][0]
        assert "path LIKE" in sql
        params = pg_conn.fetch.call_args[0][1:]
        assert "%/api/%" in params

    @pytest.mark.asyncio
    async def test_query_with_since_filter(self, storage, pg_conn):
        since_time = time.time() - 3600
        pg_conn.fetch.return_value = []

        await storage.query(since=since_time)
        sql = pg_conn.fetch.call_args[0][0]
        assert "timestamp >=" in sql

    @pytest.mark.asyncio
    async def test_query_combined_filters(self, storage, pg_conn):
        pg_conn.fetch.return_value = []

        await storage.query(method="GET", path_contains="/admin", suspicious_only=True)
        sql = pg_conn.fetch.call_args[0][0]
        assert "suspicious = TRUE" in sql
        assert "method = $1" in sql
        assert "path LIKE $2" in sql

    @pytest.mark.asyncio
    async def test_query_limit_and_offset(self, storage, pg_conn):
        pg_conn.fetch.return_value = []

        await storage.query(limit=50, offset=100)
        sql = pg_conn.fetch.call_args[0][0]
        assert "LIMIT" in sql
        assert "OFFSET" in sql
        params = pg_conn.fetch.call_args[0][1:]
        assert 50 in params
        assert 100 in params

    @pytest.mark.asyncio
    async def test_query_parses_json_headers(self, storage, pg_conn):
        row_data = make_pg_row()
        row_data["headers"] = '{"content-type": "application/json"}'
        pg_conn.fetch.return_value = [make_record(**row_data)]

        results = await storage.query()
        assert results[0].headers == {"content-type": "application/json"}

    @pytest.mark.asyncio
    async def test_query_empty_result(self, storage, pg_conn):
        pg_conn.fetch.return_value = []

        results = await storage.query()
        assert results == []


class TestPostgresCount:
    @pytest.mark.asyncio
    async def test_count_all(self, storage, pg_conn):
        pg_conn.fetchrow.return_value = {"cnt": 42}

        count = await storage.count()
        assert count == 42
        sql = pg_conn.fetchrow.call_args[0][0]
        assert "COUNT(*)" in sql
        assert "WHERE" not in sql

    @pytest.mark.asyncio
    async def test_count_suspicious_only(self, storage, pg_conn):
        pg_conn.fetchrow.return_value = {"cnt": 7}

        count = await storage.count(suspicious_only=True)
        assert count == 7
        sql = pg_conn.fetchrow.call_args[0][0]
        assert "WHERE suspicious = TRUE" in sql


class TestPostgresCSVExport:
    @pytest.mark.asyncio
    async def test_export_csv_all(self, storage, pg_conn):
        pg_conn.fetch.return_value = [
            make_record(**make_pg_row(path="/one")),
            make_record(**make_pg_row(path="/two")),
        ]

        csv_data = await storage.export_csv()
        assert "timestamp" in csv_data
        assert "/one" in csv_data
        assert "/two" in csv_data

    @pytest.mark.asyncio
    async def test_export_csv_suspicious_only(self, storage, pg_conn):
        pg_conn.fetch.return_value = [make_record(**make_pg_row(path="/scan", suspicious=True))]

        csv_data = await storage.export_csv(suspicious_only=True)
        assert "/scan" in csv_data

    @pytest.mark.asyncio
    async def test_export_csv_empty(self, storage, pg_conn):
        pg_conn.fetch.return_value = []

        csv_data = await storage.export_csv()
        assert "timestamp" in csv_data
        lines = csv_data.strip().split("\n")
        assert len(lines) == 1


class TestPostgresClose:
    @pytest.mark.asyncio
    async def test_close_calls_pool_close(self, storage):
        pool = storage._pool
        await storage.close()
        pool.close.assert_called_once()
        assert storage._pool is None

    @pytest.mark.asyncio
    async def test_close_idempotent(self, storage):
        await storage.close()
        await storage.close()


class TestPostgresInitialization:
    @pytest.mark.asyncio
    async def test_get_pool_creates_table(self):
        """Verify that _get_pool executes CREATE TABLE on first call."""
        mock_conn = FakeConnection()
        mock_pool = FakePool(mock_conn)

        async def fake_create_pool(*args, **kwargs):
            return mock_pool

        with patch("asyncpg.create_pool", side_effect=fake_create_pool) as mock_create:
            s = PostgresStorage(dsn="postgresql://test:test@localhost/test")
            pool = await s._get_pool()

            mock_create.assert_called_once_with(
                "postgresql://test:test@localhost/test",
                min_size=2, max_size=10,
            )
            mock_conn.execute.assert_called_once_with(CREATE_TABLE_SQL)
