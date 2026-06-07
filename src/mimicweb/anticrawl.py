"""Anti-crawler response strategies: delay, redirect to deeper fakes, pollute data."""

from __future__ import annotations

import asyncio
import random
from typing import Any

from starlette.requests import Request
from starlette.responses import Response, JSONResponse, RedirectResponse

from .adaptive_engine import AdaptiveEngine


class AntiCrawlerStrategy:
    def __init__(self, config: dict[str, Any], adaptive_engine: AdaptiveEngine):
        self._config = config
        self._adaptive = adaptive_engine

    def update_config(self, config: dict[str, Any]) -> None:
        self._config = config

    async def apply(
        self,
        request: Request,
        risk_score: float,
        request_count: int,
        labels: list[str],
        original_response: Response | None = None,
    ) -> Response | None:
        if not self._config.get("enabled", True):
            return None

        score_threshold = self._config.get("score_threshold", 30.0)
        if risk_score < score_threshold:
            return None

        await self._apply_delay(risk_score)

        strategy = self._select_strategy(risk_score, request.url.path, labels)

        if strategy == "redirect_deeper":
            return self._redirect_deeper(request, risk_score)
        elif strategy == "fake_page":
            return self._serve_fake_page(request, risk_score, request_count, labels)
        elif strategy == "pollute_data":
            return self._serve_polluted_data(request, risk_score, request_count)
        elif strategy == "slow_drip":
            await self._extra_delay(risk_score)
            return self._serve_fake_page(request, risk_score, request_count, labels)

        return None

    async def _apply_delay(self, risk_score: float) -> None:
        delay_config = self._config.get("delay", {})
        if not delay_config.get("enabled", True):
            return

        base_min = delay_config.get("min_ms", 100)
        base_max = delay_config.get("max_ms", 2000)

        factor = min(2.0, risk_score / 50.0)
        actual_min = int(base_min * factor)
        actual_max = int(base_max * factor)

        if actual_max > actual_min:
            delay_ms = random.randint(actual_min, actual_max)
            await asyncio.sleep(delay_ms / 1000.0)

    async def _extra_delay(self, risk_score: float) -> None:
        extra_max = self._config.get("slow_drip_max_ms", 5000)
        factor = min(1.0, risk_score / 80.0)
        upper = max(501, int(extra_max * factor))
        delay_ms = random.randint(500, upper)
        await asyncio.sleep(delay_ms / 1000.0)

    def _select_strategy(self, risk_score: float, path: str, labels: list[str]) -> str:
        strategies = self._config.get("strategies", {})

        if risk_score > 80 and strategies.get("slow_drip", True):
            return "slow_drip"

        if "directory_bruteforce" in labels and strategies.get("fake_page", True):
            return "fake_page"

        if "/api/" in path and strategies.get("pollute_data", True):
            return "pollute_data"

        if strategies.get("fake_page", True):
            return "fake_page"

        return "fake_page"

    def _redirect_deeper(self, request: Request, risk_score: float) -> Response:
        segments = ["internal", "backup", "archive", "data", "export",
                    "reports", "admin", "config", "users", "secrets"]
        depth = max(2, int(risk_score / 20))
        path_parts = random.sample(segments, min(depth, len(segments)))
        suffix = f"/{random.randint(1, 9999)}"
        new_path = "/" + "/".join(path_parts) + suffix

        return RedirectResponse(url=new_path, status_code=302)

    def _serve_fake_page(
        self,
        request: Request,
        risk_score: float,
        request_count: int,
        labels: list[str],
    ) -> Response:
        html = self._adaptive.generate_page(
            path=request.url.path,
            risk_score=risk_score,
            request_count=request_count,
            labels=labels,
        )
        return Response(
            content=html,
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )

    def _serve_polluted_data(
        self,
        request: Request,
        risk_score: float,
        request_count: int,
    ) -> Response:
        data = self._adaptive.generate_api_response(
            path=request.url.path,
            risk_score=risk_score,
            request_count=request_count,
        )
        import json
        return Response(
            content=json.dumps(data, ensure_ascii=False),
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
