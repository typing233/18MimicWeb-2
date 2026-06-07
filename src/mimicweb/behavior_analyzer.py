"""Behavior analyzer: cross-request correlation, session tracking, risk scoring."""

from __future__ import annotations

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SessionProfile:
    first_seen: float = 0.0
    last_seen: float = 0.0
    request_count: int = 0
    paths: list[str] = field(default_factory=list)
    request_timestamps: list[float] = field(default_factory=list)
    max_depth: int = 0
    unique_paths: set[str] = field(default_factory=set)
    methods: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    status_codes: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    risk_score: float = 0.0
    labels: list[str] = field(default_factory=list)
    sequential_404_count: int = 0
    last_status: int = 0


class BehaviorAnalyzer:
    def __init__(self, config: dict[str, Any]):
        self._config = config
        self._sessions: dict[str, SessionProfile] = {}
        self._lock = threading.Lock()

    @property
    def sessions(self) -> dict[str, SessionProfile]:
        with self._lock:
            return dict(self._sessions)

    def update_config(self, config: dict[str, Any]) -> None:
        self._config = config

    def record_request(
        self,
        client_ip: str,
        path: str,
        method: str,
        status_code: int,
        user_agent: str = "",
    ) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            session = self._sessions.get(client_ip)
            if session is None:
                session = SessionProfile(first_seen=now)
                self._sessions[client_ip] = session

            session.last_seen = now
            session.request_count += 1
            session.paths.append(path)
            session.request_timestamps.append(now)
            session.unique_paths.add(path)
            session.methods[method] += 1
            session.status_codes[status_code] = session.status_codes.get(status_code, 0) + 1

            depth = path.count("/")
            if depth > session.max_depth:
                session.max_depth = depth

            if status_code == 404:
                session.sequential_404_count += 1
            elif status_code != 0:
                session.sequential_404_count = 0
            session.last_status = status_code

            self._trim_timestamps(session)
            self._compute_risk(session, user_agent)

            return {
                "risk_score": session.risk_score,
                "labels": list(session.labels),
                "request_count": session.request_count,
            }

    def update_status(self, client_ip: str, status_code: int) -> None:
        """Update the final response status for the current request without incrementing counters."""
        with self._lock:
            session = self._sessions.get(client_ip)
            if session is None:
                return
            old_status = session.last_status
            if old_status == 0:
                session.status_codes[0] = max(0, session.status_codes.get(0, 0) - 1)
            session.status_codes[status_code] = session.status_codes.get(status_code, 0) + 1
            session.last_status = status_code
            if status_code == 404:
                session.sequential_404_count += 1
            elif old_status == 0:
                pass
            else:
                session.sequential_404_count = 0

    def get_session(self, client_ip: str) -> SessionProfile | None:
        with self._lock:
            return self._sessions.get(client_ip)

    def get_risk_score(self, client_ip: str) -> float:
        with self._lock:
            session = self._sessions.get(client_ip)
            return session.risk_score if session else 0.0

    def cleanup_expired(self) -> None:
        ttl = self._config.get("session_ttl_seconds", 3600)
        now = time.time()
        with self._lock:
            expired = [
                ip for ip, s in self._sessions.items()
                if now - s.last_seen > ttl
            ]
            for ip in expired:
                del self._sessions[ip]

    def _trim_timestamps(self, session: SessionProfile) -> None:
        window = self._config.get("analysis_window_seconds", 300)
        cutoff = time.time() - window
        session.request_timestamps = [
            t for t in session.request_timestamps if t > cutoff
        ]

    def _compute_risk(self, session: SessionProfile, user_agent: str) -> None:
        score = 0.0
        labels: list[str] = []

        rate_threshold = self._config.get("rate_threshold_per_minute", 30)
        window = self._config.get("analysis_window_seconds", 300)
        recent_count = len(session.request_timestamps)
        rate_per_minute = (recent_count / max(window, 1)) * 60

        if rate_per_minute > rate_threshold:
            score += min(40.0, (rate_per_minute / rate_threshold) * 20)
            labels.append("high_request_rate")

        path_diversity_threshold = self._config.get("path_diversity_threshold", 20)
        if len(session.unique_paths) > path_diversity_threshold:
            score += 15.0
            labels.append("path_enumeration")

        depth_threshold = self._config.get("depth_threshold", 5)
        if session.max_depth > depth_threshold:
            score += 10.0
            labels.append("deep_traversal")

        sequential_404_threshold = self._config.get("sequential_404_threshold", 5)
        if session.sequential_404_count >= sequential_404_threshold:
            score += 20.0
            labels.append("directory_bruteforce")

        if session.request_count > 10:
            not_found = session.status_codes.get(404, 0)
            ratio = not_found / session.request_count
            if ratio > 0.5:
                score += 15.0
                labels.append("high_404_ratio")

        if not user_agent or user_agent == "-":
            score += 10.0
            labels.append("missing_user_agent")

        if recent_count >= 3:
            intervals = []
            ts = sorted(session.request_timestamps[-20:])
            for i in range(1, len(ts)):
                intervals.append(ts[i] - ts[i - 1])
            if intervals:
                avg = sum(intervals) / len(intervals)
                if avg < 0.5 and len(intervals) >= 3:
                    variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
                    if variance < 0.01:
                        score += 15.0
                        labels.append("robotic_timing")

        session.risk_score = min(100.0, score)
        session.labels = labels
