"""Response engine: variable substitution, conditional logic, delay, error injection."""

from __future__ import annotations

import asyncio
import random
import re
import time
import uuid
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

from .config import RouteConfig


_VAR_PATTERN = re.compile(r"\{\{(\w+(?::\w+(?::\w+)?)?)\}\}")


class ResponseEngine:
    def __init__(self, start_time: float):
        self._start_time = start_time

    async def build_response(
        self,
        route: RouteConfig,
        request: Request,
        path_params: dict[str, str],
        regex_groups: dict[str, str] | None = None,
    ) -> Response:
        if route.error_rate > 0 and random.random() < route.error_rate:
            return Response(
                content='{"error": "internal_server_error"}',
                status_code=500,
                headers={"Content-Type": "application/json"},
            )

        response_spec = await self._evaluate_conditions(route, request, path_params)

        if route.delay:
            delay_ms = random.randint(
                route.delay.get("min_ms", 0),
                route.delay.get("max_ms", 0),
            )
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

        body = self._substitute_vars(
            response_spec.get("body", ""),
            request,
            path_params,
            regex_groups or {},
        )
        status = response_spec.get("status", 200)
        headers = dict(response_spec.get("headers", {}))

        return Response(content=body, status_code=status, headers=headers)

    async def _evaluate_conditions(
        self,
        route: RouteConfig,
        request: Request,
        path_params: dict[str, str],
    ) -> dict[str, Any]:
        for cond in route.conditions:
            field_value = self._get_field_value(cond["field"], request, path_params)
            pattern = cond.get("pattern", "")
            matches = bool(re.search(pattern, field_value or "", re.IGNORECASE))
            action = cond.get("action", "proceed")

            if action == "proceed" and matches:
                return route.response
            elif action == "respond" and matches:
                return cond.get("response", route.response)

        return route.response

    def _get_field_value(
        self, field: str, request: Request, path_params: dict[str, str]
    ) -> str | None:
        if field.startswith("header:"):
            header_name = field[7:]
            return request.headers.get(header_name, "")
        elif field.startswith("query:"):
            param_name = field[6:]
            return request.query_params.get(param_name, "")
        elif field.startswith("path:"):
            param_name = field[5:]
            return path_params.get(param_name, "")
        elif field == "method":
            return request.method
        elif field == "body":
            return ""
        elif field == "user_agent":
            return request.headers.get("user-agent", "")
        elif field == "path":
            return request.url.path
        return ""

    def _substitute_vars(
        self,
        template: str,
        request: Request,
        path_params: dict[str, str],
        regex_groups: dict[str, str],
    ) -> str:
        def replacer(match: re.Match) -> str:
            expr = match.group(1)
            parts = expr.split(":")

            if parts[0] == "timestamp_iso":
                from datetime import datetime, timezone
                return datetime.now(timezone.utc).isoformat()
            elif parts[0] == "timestamp_unix":
                return str(int(time.time()))
            elif parts[0] == "random_hex":
                length = int(parts[1]) if len(parts) > 1 else 16
                return uuid.uuid4().hex[:length] + uuid.uuid4().hex[:max(0, length - 32)]
            elif parts[0] == "random_uuid":
                return str(uuid.uuid4())
            elif parts[0] == "random_int":
                lo = int(parts[1]) if len(parts) > 1 else 0
                hi = int(parts[2]) if len(parts) > 2 else 9999
                return str(random.randint(lo, hi))
            elif parts[0] == "uptime_seconds":
                return str(int(time.time() - self._start_time))
            elif parts[0] == "client_ip":
                return request.client.host if request.client else "unknown"
            elif parts[0] == "path" and len(parts) > 1:
                return path_params.get(parts[1], "")
            elif parts[0] == "query" and len(parts) > 1:
                return request.query_params.get(parts[1], "")
            elif parts[0] == "header" and len(parts) > 1:
                return request.headers.get(parts[1], "")
            elif parts[0] == "regex" and len(parts) > 1:
                return regex_groups.get(parts[1], "")
            elif parts[0] == "random_email":
                user = uuid.uuid4().hex[:8]
                return f"{user}@corp.internal"
            elif parts[0] == "random_ip":
                return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            return match.group(0)

        return _VAR_PATTERN.sub(replacer, template)
