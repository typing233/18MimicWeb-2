"""Main application entry point."""

from __future__ import annotations

import os
import re
import random
import time
import uuid
import asyncio
import argparse
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.routing import Route

from .config import AppConfig
from .router import Router, _path_to_regex
from .scanner_detector import ScannerDetector
from .auth_simulator import AuthSimulator
from .admin import AdminAPI
from .behavior_analyzer import BehaviorAnalyzer
from .adaptive_engine import AdaptiveEngine
from .anticrawl import AntiCrawlerStrategy
from .log_aggregator import LogAggregator
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
    elif backend == "composite":
        from .storage.composite import CompositeStorage
        redis_cfg = storage_cfg.get("redis", {})
        pg_cfg = storage_cfg.get("postgres", {})
        return CompositeStorage(
            redis_url=redis_cfg.get("url", "redis://localhost:6379/0"),
            redis_prefix=redis_cfg.get("prefix", "mimicweb:"),
            postgres_dsn=pg_cfg.get("dsn", ""),
        )
    else:
        local_cfg = storage_cfg.get("local", {})
        return LocalStorage(log_dir=local_cfg.get("log_dir", "./logs"))


def _match_configured_route(config: AppConfig, path: str, method: str) -> str | None:
    """Return route_id if path matches an explicitly configured route, else None."""
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
            return r.id
    return None


def build_app(config_path: str = "config/routes.yaml") -> Starlette:
    config = AppConfig(config_path)
    storage = create_storage(config)
    router = Router(config)
    detector = ScannerDetector(config)
    auth_sim = AuthSimulator()
    admin_api = AdminAPI(config, storage)

    honeypot_cfg = config.honeypot_config
    behavior_analyzer = BehaviorAnalyzer(honeypot_cfg.get("behavior_analysis", {}))
    adaptive_engine = AdaptiveEngine(honeypot_cfg.get("adaptive_response", {}))
    anticrawl = AntiCrawlerStrategy(honeypot_cfg.get("anticrawl", {}), adaptive_engine)
    log_aggregator = LogAggregator()

    sampling_rate = honeypot_cfg.get("log_export", {}).get("sampling_rate", 1.0)
    export_formats = honeypot_cfg.get("log_export", {}).get("formats", ["json", "csv"])

    server_name = config.server.get("name", "Apache/2.4.52 (Ubuntu)")

    auth_handlers: dict[tuple[str, str], Any] = {}
    for route_def in auth_sim.get_routes():
        key = (route_def["method"], route_def["path"])
        auth_handlers[key] = route_def["handler"]

    def _is_honeypot_target(path: str, method: str) -> bool:
        """Returns True if path does NOT match any explicitly configured route (i.e. it's a honeypot/catch-all target)."""
        for r in config.routes:
            if not r.enabled:
                continue
            if r.method != "ANY" and r.method != method:
                continue
            if r.id == "catch_all":
                continue
            if r.path_type == "regex":
                pat = re.compile(r.path)
            else:
                pat = _path_to_regex(r.path)
            if pat.match(path):
                return False
        return True

    async def _store_with_sampling(entry: LogEntry) -> None:
        if sampling_rate >= 1.0 or random.random() < sampling_rate:
            await storage.store(entry)

    async def honeypot_handler(request: Request) -> Response:
        start_time = time.time()
        body = b""
        try:
            body = await request.body()
        except Exception:
            pass

        path = request.url.path
        method = request.method.upper()

        if path.startswith("/_admin"):
            return Response("Not Found", status_code=404)

        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")

        # Single record_request per incoming request (status_code=0 as placeholder)
        behavior_result = behavior_analyzer.record_request(
            client_ip=client_ip,
            path=path,
            method=method,
            status_code=0,
            user_agent=user_agent,
        )
        risk_score = behavior_result["risk_score"]
        behavior_labels = behavior_result["labels"]
        request_count = behavior_result["request_count"]

        # --- Auth simulation routes ---
        auth_key = (method, path)
        auth_key_any = ("ANY", path)
        handler = auth_handlers.get(auth_key) or auth_handlers.get(auth_key_any)
        if handler:
            response = await handler(request)
            elapsed = (time.time() - start_time) * 1000
            classification = detector.classify(request, body)
            all_labels = list(set(classification["labels"] + behavior_labels))

            behavior_analyzer.update_status(client_ip, response.status_code)

            entry = LogEntry(
                timestamp=time.time(),
                method=method,
                path=path,
                query=str(request.url.query),
                headers=dict(request.headers),
                client_ip=client_ip,
                client_port=request.client.port if request.client else 0,
                status_code=response.status_code,
                response_time_ms=elapsed,
                route_id=f"auth:{path}",
                suspicious=classification["suspicious"] or risk_score >= 30,
                labels=all_labels,
                body_preview=body[:500].decode("utf-8", errors="replace"),
                instance_id=INSTANCE_ID,
                risk_score=risk_score,
            )
            await _store_with_sampling(entry)
            response.headers["Server"] = server_name
            return response

        # --- Anti-crawl: only applies to honeypot targets (not configured business routes) ---
        is_honeypot = _is_honeypot_target(path, method)
        anticrawl_cfg = honeypot_cfg.get("anticrawl", {})
        if (
            is_honeypot
            and honeypot_cfg.get("enabled", True)
            and risk_score >= anticrawl_cfg.get("score_threshold", 30)
        ):
            anticrawl_response = await anticrawl.apply(
                request=request,
                risk_score=risk_score,
                request_count=request_count,
                labels=behavior_labels,
            )
            if anticrawl_response is not None:
                elapsed = (time.time() - start_time) * 1000
                classification = detector.classify(request, body)
                all_labels = list(set(classification["labels"] + behavior_labels))

                behavior_analyzer.update_status(client_ip, anticrawl_response.status_code)

                entry = LogEntry(
                    timestamp=time.time(),
                    method=method,
                    path=path,
                    query=str(request.url.query),
                    headers=dict(request.headers),
                    client_ip=client_ip,
                    client_port=request.client.port if request.client else 0,
                    status_code=anticrawl_response.status_code,
                    response_time_ms=elapsed,
                    route_id="anticrawl",
                    suspicious=True,
                    labels=all_labels,
                    body_preview=body[:500].decode("utf-8", errors="replace"),
                    instance_id=INSTANCE_ID,
                    risk_score=risk_score,
                )
                await _store_with_sampling(entry)
                anticrawl_response.headers["Server"] = server_name
                return anticrawl_response

        # --- Normal route dispatch ---
        response = await router.dispatch(request)
        elapsed = (time.time() - start_time) * 1000

        if response is None:
            response = Response(
                content="<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>",
                status_code=404,
                headers={"Content-Type": "text/html"},
            )

        classification = detector.classify(request, body)
        actual_route_id = _match_configured_route(config, path, method)
        all_labels = list(set(classification["labels"] + behavior_labels))

        behavior_analyzer.update_status(client_ip, response.status_code)

        entry = LogEntry(
            timestamp=time.time(),
            method=method,
            path=path,
            query=str(request.url.query),
            headers=dict(request.headers),
            client_ip=client_ip,
            client_port=request.client.port if request.client else 0,
            status_code=response.status_code,
            response_time_ms=elapsed,
            route_id=actual_route_id,
            suspicious=classification["suspicious"] or risk_score >= 30,
            labels=all_labels,
            body_preview=body[:500].decode("utf-8", errors="replace"),
            instance_id=INSTANCE_ID,
            risk_score=risk_score,
        )
        await _store_with_sampling(entry)
        response.headers["Server"] = server_name
        return response

    # --- Admin endpoints ---

    async def get_sessions(request: Request) -> JSONResponse:
        sessions = behavior_analyzer.sessions
        result = []
        for ip, s in sessions.items():
            result.append({
                "client_ip": ip,
                "request_count": s.request_count,
                "risk_score": s.risk_score,
                "labels": s.labels,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
                "max_depth": s.max_depth,
                "unique_paths": len(s.unique_paths),
            })
        result.sort(key=lambda x: x["risk_score"], reverse=True)
        return JSONResponse({"sessions": result})

    async def get_session_detail(request: Request) -> JSONResponse:
        ip = request.path_params.get("ip", "")
        session = behavior_analyzer.get_session(ip)
        if not session:
            return JSONResponse({"error": "session not found"}, status_code=404)
        return JSONResponse({
            "client_ip": ip,
            "request_count": session.request_count,
            "risk_score": session.risk_score,
            "labels": session.labels,
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
            "max_depth": session.max_depth,
            "unique_paths": len(session.unique_paths),
            "recent_paths": session.paths[-50:],
            "methods": dict(session.methods),
            "status_codes": dict(session.status_codes),
        })

    async def get_aggregation(request: Request) -> JSONResponse:
        params = request.query_params
        group_by = params.get("group_by", "time")
        interval = int(params.get("interval", "300"))
        since = float(params.get("since", "0")) or None
        suspicious_only = params.get("suspicious", "").lower() == "true"

        entries = await storage.query(
            limit=10000,
            suspicious_only=suspicious_only,
            since=since,
        )

        risk_scores = {ip: s.risk_score for ip, s in behavior_analyzer.sessions.items()}
        data = log_aggregator._get_aggregation(entries, group_by, interval, risk_scores)
        return JSONResponse({"group_by": group_by, "buckets": data})

    async def export_aggregation(request: Request) -> Response:
        params = request.query_params
        group_by = params.get("group_by", "time")
        interval = int(params.get("interval", "300"))
        fmt = params.get("format", "json")
        since = float(params.get("since", "0")) or None
        suspicious_only = params.get("suspicious", "").lower() == "true"

        if fmt not in export_formats:
            return JSONResponse(
                {"error": f"format '{fmt}' not enabled, allowed: {export_formats}"},
                status_code=400,
            )

        entries = await storage.query(
            limit=10000,
            suspicious_only=suspicious_only,
            since=since,
        )
        risk_scores = {ip: s.risk_score for ip, s in behavior_analyzer.sessions.items()}

        if fmt == "csv":
            content = log_aggregator.export_csv(entries, group_by, interval, risk_scores)
            return Response(
                content=content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=mimicweb_agg_{group_by}.csv"},
            )
        else:
            content = log_aggregator.export_json(entries, group_by, interval, risk_scores)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=mimicweb_agg_{group_by}.json"},
            )

    async def get_honeypot_config(request: Request) -> JSONResponse:
        return JSONResponse(config.honeypot_config)

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
        Route("/_admin/api/sessions", get_sessions, methods=["GET"]),
        Route("/_admin/api/sessions/{ip}", get_session_detail, methods=["GET"]),
        Route("/_admin/api/aggregation", get_aggregation, methods=["GET"]),
        Route("/_admin/api/aggregation/export", export_aggregation, methods=["GET"]),
        Route("/_admin/api/honeypot/config", get_honeypot_config, methods=["GET"]),
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
