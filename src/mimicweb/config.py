"""Configuration management with hot-reload support."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any, Callable

import yaml


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
