"""Configuration management with hot-reload support."""

from __future__ import annotations

import os
import asyncio
import threading
import time
from pathlib import Path
from typing import Any, Callable

import yaml


_HONEYPOT_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "behavior_analysis": {
        "session_ttl_seconds": 3600,
        "analysis_window_seconds": 300,
        "rate_threshold_per_minute": 30,
        "path_diversity_threshold": 20,
        "depth_threshold": 5,
        "sequential_404_threshold": 5,
    },
    "adaptive_response": {
        "max_link_depth": 5,
        "enable_fake_forms": True,
        "enable_fake_search": True,
    },
    "anticrawl": {
        "enabled": True,
        "score_threshold": 30.0,
        "delay": {
            "enabled": True,
            "min_ms": 100,
            "max_ms": 2000,
        },
        "slow_drip_max_ms": 5000,
        "strategies": {
            "redirect_deeper": True,
            "fake_page": True,
            "pollute_data": True,
            "slow_drip": True,
        },
    },
    "log_export": {
        "sampling_rate": 1.0,
        "formats": ["json", "csv"],
        "aggregation_intervals": ["1m", "5m", "1h", "1d"],
    },
}

_ENV_OVERRIDES: dict[str, tuple[str, type]] = {
    "MIMICWEB_HONEYPOT_ENABLED": ("enabled", bool),
    "MIMICWEB_RATE_THRESHOLD": ("behavior_analysis.rate_threshold_per_minute", int),
    "MIMICWEB_SESSION_TTL": ("behavior_analysis.session_ttl_seconds", int),
    "MIMICWEB_ANALYSIS_WINDOW": ("behavior_analysis.analysis_window_seconds", int),
    "MIMICWEB_PATH_DIVERSITY_THRESHOLD": ("behavior_analysis.path_diversity_threshold", int),
    "MIMICWEB_DEPTH_THRESHOLD": ("behavior_analysis.depth_threshold", int),
    "MIMICWEB_404_THRESHOLD": ("behavior_analysis.sequential_404_threshold", int),
    "MIMICWEB_MAX_LINK_DEPTH": ("adaptive_response.max_link_depth", int),
    "MIMICWEB_FAKE_FORMS": ("adaptive_response.enable_fake_forms", bool),
    "MIMICWEB_FAKE_SEARCH": ("adaptive_response.enable_fake_search", bool),
    "MIMICWEB_ANTICRAWL_ENABLED": ("anticrawl.enabled", bool),
    "MIMICWEB_ANTICRAWL_THRESHOLD": ("anticrawl.score_threshold", float),
    "MIMICWEB_DELAY_MIN_MS": ("anticrawl.delay.min_ms", int),
    "MIMICWEB_DELAY_MAX_MS": ("anticrawl.delay.max_ms", int),
    "MIMICWEB_SAMPLING_RATE": ("log_export.sampling_rate", float),
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _apply_env_overrides(config: dict[str, Any]) -> dict[str, Any]:
    for env_var, (path, cast) in _ENV_OVERRIDES.items():
        value = os.environ.get(env_var)
        if value is None:
            continue
        if cast == bool:
            parsed: Any = value.lower() in ("1", "true", "yes")
        elif cast == int:
            parsed = int(value)
        elif cast == float:
            parsed = float(value)
        else:
            parsed = value

        keys = path.split(".")
        target = config
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        target[keys[-1]] = parsed
    return config


class RouteConfig:
    __slots__ = (
        "id", "path", "path_type", "method", "enabled", "priority",
        "conditions", "response", "delay", "error_rate",
    )

    def __init__(self, data: dict[str, Any]):
        self.id: str = data["id"]
        self.path: str = data["path"]
        self.path_type: str = data.get("path_type", "path")
        self.method: str = data.get("method", "GET").upper()
        self.enabled: bool = data.get("enabled", True)
        self.priority: int = data.get("priority", 0)
        self.conditions: list[dict] = data.get("conditions", [])
        self.response: dict = data.get("response", {"status": 200, "body": ""})
        self.delay: dict | None = data.get("delay")
        self.error_rate: float = data.get("error_rate", 0.0)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "path": self.path,
            "method": self.method,
            "enabled": self.enabled,
            "response": self.response,
        }
        if self.path_type != "path":
            d["path_type"] = self.path_type
        if self.priority:
            d["priority"] = self.priority
        if self.conditions:
            d["conditions"] = self.conditions
        if self.delay:
            d["delay"] = self.delay
        if self.error_rate:
            d["error_rate"] = self.error_rate
        return d


class AppConfig:
    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path)
        self._data: dict[str, Any] = {}
        self._routes: list[RouteConfig] = []
        self._lock = threading.RLock()
        self._callbacks: list[Callable] = []
        self._start_time = time.time()
        self.load()

    @property
    def start_time(self) -> float:
        return self._start_time

    @property
    def server(self) -> dict[str, Any]:
        return self._data.get("server", {})

    @property
    def storage_config(self) -> dict[str, Any]:
        return self._data.get("storage", {"backend": "local"})

    @property
    def scanner_detection(self) -> dict[str, Any]:
        return self._data.get("scanner_detection", {"enabled": False})

    @property
    def honeypot_config(self) -> dict[str, Any]:
        file_cfg = self._data.get("honeypot", {})
        merged = _deep_merge(_HONEYPOT_DEFAULTS, file_cfg)
        return _apply_env_overrides(merged)

    @property
    def routes(self) -> list[RouteConfig]:
        with self._lock:
            return list(self._routes)

    def load(self) -> None:
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        with self._lock:
            self._data = data or {}
            self._routes = [
                RouteConfig(r) for r in self._data.get("routes", [])
            ]
            self._routes.sort(key=lambda r: r.priority)

    def save(self) -> None:
        with self._lock:
            self._data["routes"] = [r.to_dict() for r in self._routes]
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(self._data, f, default_flow_style=False, allow_unicode=True)

    def reload(self) -> None:
        self.load()
        for cb in self._callbacks:
            cb()

    def on_reload(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def get_route(self, route_id: str) -> RouteConfig | None:
        with self._lock:
            for r in self._routes:
                if r.id == route_id:
                    return r
        return None

    def add_route(self, data: dict[str, Any]) -> RouteConfig:
        route = RouteConfig(data)
        with self._lock:
            self._routes.append(route)
            self._routes.sort(key=lambda r: r.priority)
        self.save()
        self._notify()
        return route

    def update_route(self, route_id: str, data: dict[str, Any]) -> RouteConfig | None:
        with self._lock:
            for i, r in enumerate(self._routes):
                if r.id == route_id:
                    merged = r.to_dict()
                    merged.update(data)
                    merged["id"] = route_id
                    self._routes[i] = RouteConfig(merged)
                    self._routes.sort(key=lambda r: r.priority)
                    self.save()
                    self._notify()
                    return self._routes[i]
        return None

    def delete_route(self, route_id: str) -> bool:
        with self._lock:
            for i, r in enumerate(self._routes):
                if r.id == route_id:
                    self._routes.pop(i)
                    self.save()
                    self._notify()
                    return True
        return False

    def toggle_route(self, route_id: str, enabled: bool) -> bool:
        with self._lock:
            for r in self._routes:
                if r.id == route_id:
                    r.enabled = enabled
                    self.save()
                    self._notify()
                    return True
        return False

    def _notify(self) -> None:
        for cb in self._callbacks:
            cb()
