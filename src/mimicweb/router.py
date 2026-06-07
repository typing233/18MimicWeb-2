"""Dynamic router: regex matching, path params, route dispatch."""

from __future__ import annotations

import re
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

from .config import AppConfig, RouteConfig
from .response_engine import ResponseEngine


_PATH_PARAM_RE = re.compile(r"\{(\w+)(?::(\w+))?\}")


def _path_to_regex(path: str) -> re.Pattern:
    parts = _PATH_PARAM_RE.split(path)
    regex_str = ""
    i = 0
    while i < len(parts):
        if i % 3 == 0:
            regex_str += re.escape(parts[i])
        elif i % 3 == 1:
            name = parts[i]
            kind = parts[i + 1] if i + 1 < len(parts) else None
            if kind == "remaining":
                regex_str += f"(?P<{name}>.+)"
            else:
                regex_str += f"(?P<{name}>[^/]+)"
            i += 1
        i += 1
    return re.compile(f"^{regex_str}$")


class Router:
    def __init__(self, config: AppConfig):
        self._config = config
        self._engine = ResponseEngine(config.start_time)
        self._compiled: list[tuple[RouteConfig, re.Pattern | None]] = []
        self._compile_routes()
        config.on_reload(self._compile_routes)

    def _compile_routes(self) -> None:
        compiled = []
        for route in self._config.routes:
            if route.path_type == "regex":
                pattern = re.compile(route.path)
            else:
                pattern = _path_to_regex(route.path)
            compiled.append((route, pattern))
        self._compiled = compiled

    async def dispatch(self, request: Request) -> Response | None:
        path = request.url.path
        method = request.method.upper()

        for route, pattern in self._compiled:
            if not route.enabled:
                continue
            if route.method != "ANY" and route.method != method:
                continue
            if pattern is None:
                continue

            m = pattern.match(path)
            if not m:
                continue

            path_params = m.groupdict()
            regex_groups = m.groupdict() if route.path_type == "regex" else None

            return await self._engine.build_response(
                route, request, path_params, regex_groups
            )

        return None
