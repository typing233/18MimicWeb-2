"""Redis storage backend for multi-instance request log sharing."""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Any

from .base import LogEntry


class RedisStorage:
    def __init__(self, url: str = "redis://localhost:6379/0", prefix: str = "mimicweb:"):
        self._url = url
        self._prefix = prefix
        self._client: Any = None

    async def _get_client(self) -> Any:
        if self._client is None:
            import redis.asyncio as aioredis
            self._client = aioredis.from_url(self._url, decode_responses=True)
        return self._client

    @property
    def _log_key(self) -> str:
        return f"{self._prefix}logs"

    @property
    def _suspicious_key(self) -> str:
        return f"{self._prefix}suspicious"

    async def store(self, entry: LogEntry) -> None:
        client = await self._get_client()
        data = entry.to_json()
        pipe = client.pipeline()
        pipe.lpush(self._log_key, data)
        pipe.ltrim(self._log_key, 0, 99999)
        if entry.suspicious:
            pipe.lpush(self._suspicious_key, data)
            pipe.ltrim(self._suspicious_key, 0, 99999)
        await pipe.execute()

    async def query(
        self,
        limit: int = 100,
        offset: int = 0,
        suspicious_only: bool = False,
        method: str | None = None,
        path_contains: str | None = None,
        since: float | None = None,
    ) -> list[LogEntry]:
        client = await self._get_client()
        key = self._suspicious_key if suspicious_only else self._log_key

        batch_size = limit * 3
        start = 0
        results: list[LogEntry] = []
        skipped = 0

        while len(results) < limit:
            raw_items = await client.lrange(key, start, start + batch_size - 1)
            if not raw_items:
                break
            start += batch_size

            for raw in raw_items:
                try:
                    entry = LogEntry.from_dict(json.loads(raw))
                except (json.JSONDecodeError, TypeError):
                    continue

                if method and entry.method != method.upper():
                    continue
                if path_contains and path_contains not in entry.path:
                    continue
                if since and entry.timestamp < since:
                    continue

                if skipped < offset:
                    skipped += 1
                    continue

                results.append(entry)
                if len(results) >= limit:
                    break

        return results

    async def count(self, suspicious_only: bool = False) -> int:
        client = await self._get_client()
        key = self._suspicious_key if suspicious_only else self._log_key
        return await client.llen(key)

    async def export_csv(self, suspicious_only: bool = False) -> str:
        entries = await self.query(limit=100000, suspicious_only=suspicious_only)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(LogEntry.csv_header())
        for entry in entries:
            writer.writerow(entry.to_csv_row())
        return output.getvalue()

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None
