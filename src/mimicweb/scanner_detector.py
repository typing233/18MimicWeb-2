"""Scanner detection: identify suspicious requests."""

from __future__ import annotations

import re
from typing import Any

from starlette.requests import Request

from .config import AppConfig


class ScannerDetector:
    def __init__(self, config: AppConfig):
        self._config = config
        self._rules: list[dict[str, Any]] = []
        self._compile_rules()
        config.on_reload(self._compile_rules)

    def _compile_rules(self) -> None:
        detection = self._config.scanner_detection
        if not detection.get("enabled"):
            self._rules = []
            return
        rules = []
        for rule in detection.get("rules", []):
            rules.append({
                "pattern": re.compile(rule["pattern"], re.IGNORECASE),
                "field": rule["field"],
                "label": rule["label"],
            })
        self._rules = rules

    def classify(self, request: Request, body: bytes = b"") -> dict[str, Any]:
        if not self._rules:
            return {"suspicious": False, "labels": []}

        labels: list[str] = []
        for rule in self._rules:
            value = self._get_value(rule["field"], request, body)
            if value and rule["pattern"].search(value):
                labels.append(rule["label"])

        return {
            "suspicious": len(labels) > 0,
            "labels": labels,
        }

    def _get_value(self, field: str, request: Request, body: bytes) -> str | None:
        if field == "user_agent":
            return request.headers.get("user-agent", "")
        elif field == "path":
            return request.url.path
        elif field == "body":
            try:
                return body.decode("utf-8", errors="replace")
            except Exception:
                return ""
        elif field == "query":
            return str(request.url.query)
        elif field.startswith("header:"):
            return request.headers.get(field[7:], "")
        return ""
