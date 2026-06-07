"""Main application entry point."""

from __future__ import annotations

import os
import time
import uuid
import asyncio
import argparse
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.routing import Route, Mount

from .config import AppConfig
from .router import Router
from .scanner_detector import ScannerDetector
from .auth_simulator import AuthSimulator
from .admin import AdminAPI
from .storage.base import LogEntry
from .storage.local import LocalStorage


INSTANCE_ID = os.environ.get("MIMICWEB_INSTANCE_ID", uuid.uuid4().hex[:8])


def create_storage(config: AppConfig) -> Any:
    storage_cfg = config.storage_config
    backend = storage_cfg.get("backend", "local")

    if backend == "redis":
        from .storage.redis_backend import RedisStorage
        redis_cfg = storage_cfg.get("redis", {})
        return RedisStorage(
            url=redis_cfg.get("url", "redis://localhost:6379/0"),
            prefix=redis_cfg.get("prefix", "mimicweb:"),
        )
    elif backend == "postgres":
        from .storage.postgres_backend import PostgresStorage
        pg_cfg = storage_cfg.get("postgres", {})
        return PostgresStorage(dsn=pg_cfg.get("dsn", ""))
    else:
        local_cfg = storage_cfg.get("local", {})
        return LocalStorage(log_dir=local_cfg.get("log_dir", "./logs"))


def build_app(config_path: str = "config/routes.yaml") -> Starlette:
    config = AppConfig(config_path)
    storage = create_storage(config)
    router = Router(config)
    detector = ScannerDetector(config)
    auth_sim = AuthSimulator()
    admin_api = AdminAPI(config, storage)

    server_name = config.server.get("name", "Apache/2.4.52 (Ubuntu)")

    auth_handlers: dict[tuple[str, str], Any] = {}
    for route_def in auth_sim.get_routes():
        key = (route_def["method"], route_def["path"])
        auth_handlers[key] = route_def["handler"]

    async def honeypot_handler(request: Request) -> Response:
        start_time = time.time()
        body = b""
        try:
            body = await request.body()
        except Exception:
            pass

        path = request.url.path
        method = request.method.upper()

        # Skip admin routes
        if path.startswith("/_admin"):
            return Response("Not Found", status_code=404)

        # Check auth simulation routes
        auth_key = (method, path)
        auth_key_any = ("ANY", path)
        handler = auth_handlers.get(auth_key) or auth_handlers.get(auth_key_any)
        if handler:
            response = await handler(request)
            elapsed = (time.time() - start_time) * 1000
            classification = detector.classify(request, body)
            entry = LogEntry(
                timestamp=time.time(),
                method=method,
                path=path,
                query=str(request.url.query),
                headers=dict(request.headers),
                client_ip=request.client.host if request.client else "unknown",
                client_port=request.client.port if request.client else 0,
                status_code=response.status_code,
                response_time_ms=elapsed,
                route_id=f"auth:{path}",
                suspicious=classification["suspicious"],
                labels=classification["labels"],
                body_preview=body[:500].decode("utf-8", errors="replace"),
                instance_id=INSTANCE_ID,
            )
            await storage.store(entry)
            response.headers["Server"] = server_name
            return response

        # Dynamic route dispatch
        response = await router.dispatch(request)
        elapsed = (time.time() - start_time) * 1000

        if response is None:
            response = Response(
                content="<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>",
                status_code=404,
                headers={"Content-Type": "text/html"},
            )
            route_id = None
        else:
            matched_routes = config.routes
            route_id = None
            for r in matched_routes:
                if r.enabled:
                    route_id = r.id
                    break

        classification = detector.classify(request, body)

        # Find actual matched route id
        from .router import _path_to_regex
        import re
        actual_route_id = None
        for r in config.routes:
            if not r.enabled:
                continue
            if r.method != "ANY" and r.method != method:
                continue
            if r.path_type == "regex":
                pat = re.compile(r.path)
            else:
                pat = _path_to_regex(r.path)
            if pat.match(path):
                actual_route_id = r.id
                break

        entry = LogEntry(
            timestamp=time.time(),
            method=method,
            path=path,
            query=str(request.url.query),
            headers=dict(request.headers),
            client_ip=request.client.host if request.client else "unknown",
            client_port=request.client.port if request.client else 0,
            status_code=response.status_code,
            response_time_ms=elapsed,
            route_id=actual_route_id,
            suspicious=classification["suspicious"],
            labels=classification["labels"],
            body_preview=body[:500].decode("utf-8", errors="replace"),
            instance_id=INSTANCE_ID,
        )
        await storage.store(entry)
        response.headers["Server"] = server_name
        return response

    # Admin routes
    admin_routes = [
        Route("/_admin", admin_api.dashboard, methods=["GET"]),
        Route("/_admin/api/logs", admin_api.get_logs, methods=["GET"]),
        Route("/_admin/api/logs/export", admin_api.export_csv, methods=["GET"]),
        Route("/_admin/api/routes", admin_api.get_routes, methods=["GET"]),
        Route("/_admin/api/routes", admin_api.create_route, methods=["POST"]),
        Route("/_admin/api/routes/{route_id}", admin_api.update_route, methods=["PUT"]),
        Route("/_admin/api/routes/{route_id}", admin_api.delete_route, methods=["DELETE"]),
        Route("/_admin/api/routes/{route_id}/toggle", admin_api.toggle_route, methods=["POST"]),
        Route("/_admin/api/reload", admin_api.reload_config, methods=["POST"]),
        Route("/_admin/api/stats", admin_api.get_stats, methods=["GET"]),
        Route("/{path:path}", honeypot_handler, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]),
    ]

    @asynccontextmanager
    async def lifespan(app):
        yield
        await storage.close()

    app = Starlette(routes=admin_routes, lifespan=lifespan)
    return app


def cli():
    parser = argparse.ArgumentParser(description="MimicWeb HTTP Simulation Server")
    parser.add_argument("-c", "--config", default="config/routes.yaml", help="Config file path")
    parser.add_argument("-H", "--host", default=None, help="Host to bind")
    parser.add_argument("-p", "--port", type=int, default=None, help="Port to bind")
    args = parser.parse_args()

    config = AppConfig(args.config)
    host = args.host or config.server.get("host", "0.0.0.0")
    port = args.port or config.server.get("port", 8080)

    app = build_app(args.config)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    cli()
