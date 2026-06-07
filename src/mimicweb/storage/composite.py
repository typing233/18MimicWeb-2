"""Composite storage backend: dual-write to Redis (real-time) + PostgreSQL (audit)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .base import LogEntry
from .redis_backend import RedisStorage
from .postgres_backend import PostgresStorage

logger = logging.getLogger(__name__)


class CompositeStorage:
    """Writes to both Redis and PostgreSQL. Reads from Redis for speed."""

    def __init__(self, redis_url: str, redis_prefix: str, postgres_dsn: str):
        self._redis = RedisStorage(url=redis_url, prefix=redis_prefix)
        self._postgres = PostgresStorage(dsn=postgres_dsn)

    async def store(self, entry: LogEntry) -> None:
        await self._redis.store(entry)
        try:
            await self._postgres.store(entry)
        except Exception as e:
            logger.warning(f"PostgreSQL write failed (audit degraded): {e}")

    async def query(
        self,
        limit: int = 100,
        offset: int = 0,
        suspicious_only: bool = False,
        method: str | None = None,
        path_contains: str | None = None,
        since: float | None = None,
    ) -> list[LogEntry]:
        try:
            return await self._postgres.query(
                limit=limit, offset=offset,
                suspicious_only=suspicious_only,
                method=method, path_contains=path_contains, since=since,
            )
        except Exception as e:
            logger.warning(f"PostgreSQL query failed, falling back to Redis: {e}")
            return await self._redis.query(
                limit=limit, offset=offset,
                suspicious_only=suspicious_only,
                method=method, path_contains=path_contains, since=since,
            )

    async def count(self, suspicious_only: bool = False) -> int:
        try:
            return await self._postgres.count(suspicious_only=suspicious_only)
        except Exception:
            return await self._redis.count(suspicious_only=suspicious_only)

    async def export_csv(self, suspicious_only: bool = False) -> str:
        try:
            return await self._postgres.export_csv(suspicious_only=suspicious_only)
        except Exception:
            return await self._redis.export_csv(suspicious_only=suspicious_only)

    async def close(self) -> None:
        await self._redis.close()
        await self._postgres.close()
