"""Shared test fixtures."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml


SAMPLE_CONFIG = {
    "server": {"host": "127.0.0.1", "port": 8080, "name": "TestServer/1.0"},
    "storage": {"backend": "local", "local": {"log_dir": ""}},
    "honeypot": {
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
            "delay": {"enabled": False, "min_ms": 0, "max_ms": 0},
            "slow_drip_max_ms": 100,
            "strategies": {
                "redirect_deeper": True,
                "fake_page": True,
                "pollute_data": True,
                "slow_drip": True,
            },
        },
    },
    "scanner_detection": {
        "enabled": True,
        "rules": [
            {"pattern": "sqlmap|nikto", "field": "user_agent", "label": "known_scanner"},
            {"pattern": "\\.\\./", "field": "path", "label": "path_traversal"},
        ],
    },
    "routes": [
        {
            "id": "home",
            "path": "/",
            "method": "GET",
            "enabled": True,
            "response": {"status": 200, "body": "Hello World", "headers": {"Content-Type": "text/plain"}},
        },
        {
            "id": "user_api",
            "path": "/api/users/{user_id}",
            "method": "GET",
            "enabled": True,
            "response": {
                "status": 200,
                "body": '{"id": "{{path:user_id}}", "ts": "{{timestamp_iso}}"}',
                "headers": {"Content-Type": "application/json"},
            },
            "delay": {"min_ms": 0, "max_ms": 10},
        },
        {
            "id": "regex_admin",
            "path": "^/admin/(?P<section>\\w+)$",
            "path_type": "regex",
            "method": "GET",
            "enabled": True,
            "response": {
                "status": 403,
                "body": '{"error": "forbidden", "section": "{{regex:section}}"}',
            },
        },
        {
            "id": "conditional",
            "path": "/api/data",
            "method": "GET",
            "enabled": True,
            "conditions": [
                {"field": "header:Authorization", "pattern": "^Bearer .+", "action": "proceed"},
                {"field": "header:Authorization", "pattern": "^$", "action": "respond",
                 "response": {"status": 401, "body": '{"error": "unauthorized"}'}},
            ],
            "response": {"status": 200, "body": '{"data": "secret"}'},
        },
        {
            "id": "error_rate",
            "path": "/api/flaky",
            "method": "GET",
            "enabled": True,
            "response": {"status": 200, "body": "ok"},
            "error_rate": 1.0,
        },
        {
            "id": "disabled",
            "path": "/disabled",
            "method": "GET",
            "enabled": False,
            "response": {"status": 200, "body": "should not serve"},
        },
    ],
}


@pytest.fixture
def config_file(tmp_path):
    config = SAMPLE_CONFIG.copy()
    config["storage"]["local"]["log_dir"] = str(tmp_path / "logs")
    cfg_path = tmp_path / "routes.yaml"
    cfg_path.write_text(yaml.dump(config))
    return str(cfg_path)


@pytest.fixture
def app_config(config_file):
    from mimicweb.config import AppConfig
    return AppConfig(config_file)
