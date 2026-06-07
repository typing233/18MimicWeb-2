"""Abstract storage interface and log entry model."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Protocol
import json


@dataclass
class LogEntry:
    timestamp: float
    method: str
    path: str
    query: str
    headers: dict[str, str]
    client_ip: str
    client_port: int
    status_code: int
    response_time_ms: float
    route_id: str | None
    suspicious: bool
    labels: list[str]
    body_preview: str = ""
    instance_id: str = ""
    risk_score: float = 0.0

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    def to_csv_row(self) -> list[str]:
        return [
            str(self.timestamp),
            self.method,
            self.path,
            self.query,
            self.client_ip,
            str(self.status_code),
            f"{self.response_time_ms:.1f}",
            self.route_id or "",
            str(self.suspicious),
            ";".join(self.labels),
            self.body_preview[:200],
            self.instance_id,
            f"{self.risk_score:.1f}",
        ]

    @staticmethod
    def csv_header() -> list[str]:
        return [
            "timestamp", "method", "path", "query", "client_ip",
            "status_code", "response_time_ms", "route_id", "suspicious",
            "labels", "body_preview", "instance_id", "risk_score",
        ]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogEntry:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class StorageBackend(Protocol):
    async def store(self, entry: LogEntry) -> None: ...
    async def query(
        self,
        limit: int = 100,
        offset: int = 0,
        suspicious_only: bool = False,
        method: str | None = None,
        path_contains: str | None = None,
        since: float | None = None,
    ) -> list[LogEntry]: ...
    async def count(self, suspicious_only: bool = False) -> int: ...
    async def export_csv(self, suspicious_only: bool = False) -> str: ...
    async def close(self) -> None: ...
