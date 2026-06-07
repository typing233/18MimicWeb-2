"""Admin API: log viewing, route management, hot-reload."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse, Response

from ..config import AppConfig
from ..storage.base import LogEntry


class AdminAPI:
    def __init__(self, config: AppConfig, storage: Any):
        self._config = config
        self._storage = storage
        self._template_dir = Path(__file__).parent / "templates"

    async def dashboard(self, request: Request) -> HTMLResponse:
        html_path = self._template_dir / "index.html"
        content = html_path.read_text(encoding="utf-8")
        return HTMLResponse(content)

    async def get_logs(self, request: Request) -> JSONResponse:
        params = request.query_params
        limit = int(params.get("limit", "100"))
        offset = int(params.get("offset", "0"))
        suspicious_only = params.get("suspicious", "").lower() == "true"
        method = params.get("method") or None
        path_contains = params.get("path") or None
        since = float(params.get("since", "0")) or None

        entries = await self._storage.query(
            limit=limit, offset=offset,
            suspicious_only=suspicious_only,
            method=method, path_contains=path_contains, since=since,
        )
        total = await self._storage.count(suspicious_only=suspicious_only)

        return JSONResponse({
            "entries": [
                {
                    "timestamp": e.timestamp,
                    "method": e.method,
                    "path": e.path,
                    "query": e.query,
                    "client_ip": e.client_ip,
                    "status_code": e.status_code,
                    "response_time_ms": e.response_time_ms,
                    "route_id": e.route_id,
                    "suspicious": e.suspicious,
                    "labels": e.labels,
                    "instance_id": e.instance_id,
                }
                for e in entries
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        })

    async def export_csv(self, request: Request) -> Response:
        suspicious_only = request.query_params.get("suspicious", "").lower() == "true"
        csv_data = await self._storage.export_csv(suspicious_only=suspicious_only)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=mimicweb_logs.csv"},
        )

    async def get_routes(self, request: Request) -> JSONResponse:
        routes = self._config.routes
        return JSONResponse({
            "routes": [r.to_dict() for r in routes],
        })

    async def create_route(self, request: Request) -> JSONResponse:
        data = await request.json()
        if not data.get("id") or not data.get("path"):
            return JSONResponse({"error": "id and path are required"}, status_code=400)
        if self._config.get_route(data["id"]):
            return JSONResponse({"error": "route id already exists"}, status_code=409)
        route = self._config.add_route(data)
        return JSONResponse({"route": route.to_dict()}, status_code=201)

    async def update_route(self, request: Request) -> JSONResponse:
        route_id = request.path_params.get("route_id", "")
        data = await request.json()
        route = self._config.update_route(route_id, data)
        if not route:
            return JSONResponse({"error": "route not found"}, status_code=404)
        return JSONResponse({"route": route.to_dict()})

    async def delete_route(self, request: Request) -> JSONResponse:
        route_id = request.path_params.get("route_id", "")
        if self._config.delete_route(route_id):
            return JSONResponse({"ok": True})
        return JSONResponse({"error": "route not found"}, status_code=404)

    async def toggle_route(self, request: Request) -> JSONResponse:
        route_id = request.path_params.get("route_id", "")
        data = await request.json()
        enabled = data.get("enabled", True)
        if self._config.toggle_route(route_id, enabled):
            return JSONResponse({"ok": True, "enabled": enabled})
        return JSONResponse({"error": "route not found"}, status_code=404)

    async def reload_config(self, request: Request) -> JSONResponse:
        self._config.reload()
        return JSONResponse({"ok": True, "routes_count": len(self._config.routes)})

    async def get_stats(self, request: Request) -> JSONResponse:
        import time
        total = await self._storage.count()
        suspicious = await self._storage.count(suspicious_only=True)
        uptime = int(time.time() - self._config.start_time)
        return JSONResponse({
            "total_requests": total,
            "suspicious_requests": suspicious,
            "active_routes": sum(1 for r in self._config.routes if r.enabled),
            "total_routes": len(self._config.routes),
            "uptime_seconds": uptime,
        })
