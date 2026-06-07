"""Log aggregation: time/source/path/risk-level grouping with JSON and CSV export."""

from __future__ import annotations

import csv
import io
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any

from .storage.base import LogEntry


@dataclass
class AggregationBucket:
    key: str
    count: int = 0
    suspicious_count: int = 0
    avg_response_ms: float = 0.0
    unique_ips: set[str] = field(default_factory=set)
    labels: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    max_risk_score: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "count": self.count,
            "suspicious_count": self.suspicious_count,
            "avg_response_ms": round(self.avg_response_ms, 2),
            "unique_ips": len(self.unique_ips),
            "labels": dict(self.labels),
            "max_risk_score": self.max_risk_score,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class LogAggregator:
    def __init__(self):
        pass

    def aggregate_by_time(
        self,
        entries: list[LogEntry],
        interval_seconds: int = 300,
    ) -> list[dict[str, Any]]:
        if not entries:
            return []

        buckets: dict[int, AggregationBucket] = {}
        for entry in entries:
            slot = int(entry.timestamp // interval_seconds) * interval_seconds
            if slot not in buckets:
                buckets[slot] = AggregationBucket(
                    key=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(slot)),
                    first_seen=entry.timestamp,
                )
            b = buckets[slot]
            b.count += 1
            if entry.suspicious:
                b.suspicious_count += 1
            b.avg_response_ms = (
                (b.avg_response_ms * (b.count - 1) + entry.response_time_ms) / b.count
            )
            b.unique_ips.add(entry.client_ip)
            for label in entry.labels:
                b.labels[label] += 1
            b.last_seen = entry.timestamp

        return [b.to_dict() for _, b in sorted(buckets.items())]

    def aggregate_by_source(self, entries: list[LogEntry]) -> list[dict[str, Any]]:
        buckets: dict[str, AggregationBucket] = {}
        for entry in entries:
            ip = entry.client_ip
            if ip not in buckets:
                buckets[ip] = AggregationBucket(key=ip, first_seen=entry.timestamp)
            b = buckets[ip]
            b.count += 1
            if entry.suspicious:
                b.suspicious_count += 1
            b.avg_response_ms = (
                (b.avg_response_ms * (b.count - 1) + entry.response_time_ms) / b.count
            )
            b.unique_ips.add(ip)
            for label in entry.labels:
                b.labels[label] += 1
            b.last_seen = entry.timestamp

        result = [b.to_dict() for b in buckets.values()]
        result.sort(key=lambda x: x["count"], reverse=True)
        return result

    def aggregate_by_path(self, entries: list[LogEntry]) -> list[dict[str, Any]]:
        buckets: dict[str, AggregationBucket] = {}
        for entry in entries:
            path = entry.path
            if path not in buckets:
                buckets[path] = AggregationBucket(key=path, first_seen=entry.timestamp)
            b = buckets[path]
            b.count += 1
            if entry.suspicious:
                b.suspicious_count += 1
            b.avg_response_ms = (
                (b.avg_response_ms * (b.count - 1) + entry.response_time_ms) / b.count
            )
            b.unique_ips.add(entry.client_ip)
            for label in entry.labels:
                b.labels[label] += 1
            b.last_seen = entry.timestamp

        result = [b.to_dict() for b in buckets.values()]
        result.sort(key=lambda x: x["count"], reverse=True)
        return result

    def aggregate_by_risk(
        self,
        entries: list[LogEntry],
        risk_scores: dict[str, float] | None = None,
    ) -> list[dict[str, Any]]:
        levels = {
            "low": (0, 30),
            "medium": (30, 60),
            "high": (60, 80),
            "critical": (80, 101),
        }
        buckets: dict[str, AggregationBucket] = {
            level: AggregationBucket(key=level) for level in levels
        }

        for entry in entries:
            score = 0.0
            if risk_scores and entry.client_ip in risk_scores:
                score = risk_scores[entry.client_ip]
            elif entry.suspicious:
                score = 50.0

            level_name = "low"
            for name, (lo, hi) in levels.items():
                if lo <= score < hi:
                    level_name = name
                    break

            b = buckets[level_name]
            b.count += 1
            if entry.suspicious:
                b.suspicious_count += 1
            if b.count == 1:
                b.first_seen = entry.timestamp
            b.avg_response_ms = (
                (b.avg_response_ms * (b.count - 1) + entry.response_time_ms) / b.count
            )
            b.unique_ips.add(entry.client_ip)
            for label in entry.labels:
                b.labels[label] += 1
            b.last_seen = entry.timestamp
            if score > b.max_risk_score:
                b.max_risk_score = score

        return [b.to_dict() for b in buckets.values() if b.count > 0]

    def export_json(
        self,
        entries: list[LogEntry],
        group_by: str = "time",
        interval_seconds: int = 300,
        risk_scores: dict[str, float] | None = None,
    ) -> str:
        data = self._get_aggregation(entries, group_by, interval_seconds, risk_scores)
        return json.dumps({"group_by": group_by, "buckets": data}, ensure_ascii=False, indent=2)

    def export_csv(
        self,
        entries: list[LogEntry],
        group_by: str = "time",
        interval_seconds: int = 300,
        risk_scores: dict[str, float] | None = None,
    ) -> str:
        data = self._get_aggregation(entries, group_by, interval_seconds, risk_scores)
        if not data:
            return ""

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "key", "count", "suspicious_count", "avg_response_ms",
            "unique_ips", "labels", "max_risk_score", "first_seen", "last_seen",
        ])
        writer.writeheader()
        for row in data:
            row_copy = dict(row)
            row_copy["labels"] = json.dumps(row_copy["labels"])
            writer.writerow(row_copy)
        return output.getvalue()

    def _get_aggregation(
        self,
        entries: list[LogEntry],
        group_by: str,
        interval_seconds: int,
        risk_scores: dict[str, float] | None,
    ) -> list[dict[str, Any]]:
        if group_by == "source":
            return self.aggregate_by_source(entries)
        elif group_by == "path":
            return self.aggregate_by_path(entries)
        elif group_by == "risk":
            return self.aggregate_by_risk(entries, risk_scores)
        else:
            return self.aggregate_by_time(entries, interval_seconds)
