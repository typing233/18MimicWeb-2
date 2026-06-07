"""PostgreSQL storage backend for long-term audit data."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .base import LogEntry


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS request_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp DOUBLE PRECISION NOT NULL,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    query TEXT DEFAULT '',
    headers JSONB DEFAULT '{}',
    client_ip VARCHAR(45) NOT NULL,
    client_port INTEGER DEFAULT 0,
    status_code INTEGER NOT NULL,
    response_time_ms DOUBLE PRECISION DEFAULT 0,
    route_id VARCHAR(128),
    suspicious BOOLEAN DEFAULT FALSE,
    labels TEXT[] DEFAULT '{}',
    body_preview TEXT DEFAULT '',
    instance_id VARCHAR(64) DEFAULT '',
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_suspicious ON request_logs(suspicious) WHERE suspicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_logs_path ON request_logs(path);
"""


class PostgresStorage:
    def __init__(self, dsn: str):
        self._dsn = dsn
        self._pool: Any = None

    async def _get_pool(self) -> Any:
        if self._pool is None:
            import asyncpg
            self._pool = await asyncpg.create_pool(self._dsn, min_size=2, max_size=10)
            async with self._pool.acquire() as conn:
                await conn.execute(CREATE_TABLE_SQL)
        return self._pool

    async def store(self, entry: LogEntry) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO request_logs
                   (timestamp, method, path, query, headers, client_ip, client_port,
                    status_code, response_time_ms, route_id, suspicious, labels,
                    body_preview, instance_id)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)""",
                entry.timestamp, entry.method, entry.path, entry.query,
                json.dumps(entry.headers), entry.client_ip, entry.client_port,
                entry.status_code, entry.response_time_ms, entry.route_id,
                entry.suspicious, entry.labels, entry.body_preview, entry.instance_id,
            )

    async def query(
        self,
        limit: int = 100,
        offset: int = 0,
        suspicious_only: bool = False,
        method: str | None = None,
        path_contains: str | None = None,
        since: float | None = None,
    ) -> list[LogEntry]:
        pool = await self._get_pool()
        conditions = []
        params: list[Any] = []
        idx = 1

        if suspicious_only:
            conditions.append("suspicious = TRUE")
        if method:
            conditions.append(f"method = ${idx}")
            params.append(method.upper())
            idx += 1
        if path_contains:
            conditions.append(f"path LIKE ${idx}")
            params.append(f"%{path_contains}%")
            idx += 1
        if since:
            conditions.append(f"timestamp >= ${idx}")
            params.append(since)
            idx += 1

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])

        sql = f"""SELECT timestamp, method, path, query, headers, client_ip,
                         client_port, status_code, response_time_ms, route_id,
                         suspicious, labels, body_preview, instance_id
                  FROM request_logs {where}
                  ORDER BY timestamp DESC
                  LIMIT ${idx} OFFSET ${idx + 1}"""

        async with pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)

        results = []
        for row in rows:
            headers = json.loads(row["headers"]) if isinstance(row["headers"], str) else dict(row["headers"] or {})
            results.append(LogEntry(
                timestamp=row["timestamp"],
                method=row["method"],
                path=row["path"],
                query=row["query"],
                headers=headers,
                client_ip=row["client_ip"],
                client_port=row["client_port"],
                status_code=row["status_code"],
                response_time_ms=row["response_time_ms"],
                route_id=row["route_id"],
                suspicious=row["suspicious"],
                labels=list(row["labels"] or []),
                body_preview=row["body_preview"] or "",
                instance_id=row["instance_id"] or "",
            ))
        return results

    async def count(self, suspicious_only: bool = False) -> int:
        pool = await self._get_pool()
        condition = "WHERE suspicious = TRUE" if suspicious_only else ""
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT COUNT(*) as cnt FROM request_logs {condition}"
            )
            return row["cnt"]

    async def export_csv(self, suspicious_only: bool = False) -> str:
        entries = await self.query(limit=1000000, suspicious_only=suspicious_only)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(LogEntry.csv_header())
        for entry in entries:
            writer.writerow(entry.to_csv_row())
        return output.getvalue()

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None
