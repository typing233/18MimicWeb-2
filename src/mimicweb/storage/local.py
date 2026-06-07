"""Local JSON Lines storage backend."""

from __future__ import annotations

import csv
import io
import json
import os
import threading
from pathlib import Path
from typing import Any

from .base import LogEntry, StorageBackend


class LocalStorage:
    def __init__(self, log_dir: str = "./logs"):
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / "requests.jsonl"
        self._lock = threading.Lock()
        self._entries: list[LogEntry] = []
        self._load_existing()

    def _load_existing(self) -> None:
        if not self._log_file.exists():
            return
        with open(self._log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        self._entries.append(LogEntry.from_dict(data))
                    except (json.JSONDecodeError, TypeError):
                        pass

    async def store(self, entry: LogEntry) -> None:
        with self._lock:
            self._entries.append(entry)
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(entry.to_json() + "\n")

    async def query(
        self,
        limit: int = 100,
        offset: int = 0,
        suspicious_only: bool = False,
        method: str | None = None,
        path_contains: str | None = None,
        since: float | None = None,
    ) -> list[LogEntry]:
        with self._lock:
            filtered = self._filter(suspicious_only, method, path_contains, since)
            filtered.sort(key=lambda e: e.timestamp, reverse=True)
            return filtered[offset:offset + limit]

    async def count(self, suspicious_only: bool = False) -> int:
        with self._lock:
            if suspicious_only:
                return sum(1 for e in self._entries if e.suspicious)
            return len(self._entries)

    async def export_csv(self, suspicious_only: bool = False) -> str:
        with self._lock:
            entries = [e for e in self._entries if not suspicious_only or e.suspicious]

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(LogEntry.csv_header())
        for entry in entries:
            writer.writerow(entry.to_csv_row())
        return output.getvalue()

    async def close(self) -> None:
        pass

    def _filter(
        self,
        suspicious_only: bool,
        method: str | None,
        path_contains: str | None,
        since: float | None,
    ) -> list[LogEntry]:
        results = []
        for e in self._entries:
            if suspicious_only and not e.suspicious:
                continue
            if method and e.method != method.upper():
                continue
            if path_contains and path_contains not in e.path:
                continue
            if since and e.timestamp < since:
                continue
            results.append(e)
        return results
