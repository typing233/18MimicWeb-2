"""Adaptive engine: generates dynamic decoy content based on visitor risk profile."""

from __future__ import annotations

import hashlib
import random
import string
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any


_FAKE_NAMES = [
    "Alice Johnson", "Bob Smith", "Carol Williams", "David Brown",
    "Eve Davis", "Frank Miller", "Grace Wilson", "Henry Moore",
    "Irene Taylor", "Jack Anderson", "Karen Thomas", "Larry Jackson",
]

_FAKE_DEPARTMENTS = [
    "Engineering", "Finance", "Legal", "Marketing", "Operations",
    "Human Resources", "Research", "Sales", "Security", "Compliance",
]

_FAKE_FILE_NAMES = [
    "budget_2024.xlsx", "employee_directory.csv", "api_keys.txt",
    "database_backup.sql", "internal_memo.pdf", "salary_report.xlsx",
    "credentials.json", "server_list.txt", "vpn_config.ovpn",
    "passwords_old.txt", "migration_plan.docx", "audit_log.csv",
]

_FAKE_ENDPOINTS = [
    "/api/v2/internal/users", "/api/v2/internal/billing",
    "/api/v2/internal/secrets", "/api/v2/admin/config",
    "/api/v2/admin/database", "/api/v2/admin/logs",
    "/internal/backup", "/internal/debug", "/internal/metrics",
]


class AdaptiveEngine:
    def __init__(self, config: dict[str, Any]):
        self._config = config

    def update_config(self, config: dict[str, Any]) -> None:
        self._config = config

    def generate_page(
        self,
        path: str,
        risk_score: float,
        request_count: int,
        labels: list[str],
    ) -> str:
        link_depth = self._config.get("max_link_depth", 5)
        enable_forms = self._config.get("enable_fake_forms", True)
        enable_search = self._config.get("enable_fake_search", True)

        depth_factor = min(1.0, risk_score / 50.0)
        num_links = int(3 + depth_factor * link_depth * 2)
        links = self._generate_links(path, num_links, risk_score)

        sections = []
        sections.append(self._generate_header(path))
        sections.append(self._generate_nav(links[:5]))
        sections.append(self._generate_content(path, risk_score, request_count))

        if enable_search and risk_score > 20:
            sections.append(self._generate_search_form(path))

        if enable_forms and risk_score > 40:
            sections.append(self._generate_fake_form(path))

        if risk_score > 60:
            sections.append(self._generate_data_table())

        sections.append(self._generate_link_section(links))
        sections.append(self._generate_footer())

        return self._wrap_html(path, "\n".join(sections))

    def generate_api_response(
        self,
        path: str,
        risk_score: float,
        request_count: int,
    ) -> dict[str, Any]:
        num_results = int(3 + (risk_score / 20) * 5)
        results = []
        for _ in range(num_results):
            results.append(self._generate_fake_record())

        response: dict[str, Any] = {
            "status": "success",
            "data": results,
            "pagination": {
                "page": 1,
                "per_page": num_results,
                "total": random.randint(100, 5000),
                "total_pages": random.randint(10, 500),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": str(uuid.uuid4()),
        }

        if risk_score > 50:
            response["_links"] = {
                "next": f"{path}?page=2&per_page={num_results}",
                "self": path,
                "related": random.sample(_FAKE_ENDPOINTS, min(3, len(_FAKE_ENDPOINTS))),
            }

        return response

    def _generate_links(self, base_path: str, count: int, risk_score: float) -> list[str]:
        links = []
        segments = ["documents", "reports", "users", "admin", "internal",
                    "backup", "config", "data", "export", "files", "archive"]
        depth = max(1, int((risk_score / 100) * self._config.get("max_link_depth", 5)))

        for _ in range(count):
            parts = random.sample(segments, min(depth, len(segments)))
            suffix = f"/{random.randint(1, 999)}" if random.random() > 0.5 else ""
            link = "/" + "/".join(parts) + suffix
            links.append(link)

        return links

    def _generate_header(self, path: str) -> str:
        title = path.strip("/").replace("/", " - ").title() or "Portal"
        return f'<header><h1>{title}</h1><p class="subtitle">Internal Corporate Portal</p></header>'

    def _generate_nav(self, links: list[str]) -> str:
        items = []
        nav_labels = ["Dashboard", "Documents", "Users", "Settings", "Reports"]
        for i, link in enumerate(links):
            label = nav_labels[i] if i < len(nav_labels) else f"Section {i}"
            items.append(f'<li><a href="{link}">{label}</a></li>')
        return f'<nav><ul>{"".join(items)}</ul></nav>'

    def _generate_content(self, path: str, risk_score: float, request_count: int) -> str:
        paragraphs = []
        paragraphs.append("<div class=\"content\">")
        paragraphs.append(f"<h2>Welcome to {path.strip('/').split('/')[-1].title() or 'Home'}</h2>")
        paragraphs.append("<p>This section contains confidential internal resources. "
                          "Access is logged and monitored.</p>")

        if risk_score > 30:
            paragraphs.append("<div class=\"alert\">Notice: Your access level grants "
                              "read-only permissions to the following resources.</div>")

        return "\n".join(paragraphs) + "</div>"

    def _generate_search_form(self, path: str) -> str:
        return (
            '<div class="search-section">'
            '<h3>Internal Search</h3>'
            f'<form action="{path}/search" method="GET">'
            '<input type="text" name="q" placeholder="Search documents, users, reports...">'
            '<select name="category">'
            '<option value="all">All Categories</option>'
            '<option value="docs">Documents</option>'
            '<option value="users">User Profiles</option>'
            '<option value="reports">Financial Reports</option>'
            '<option value="configs">System Configs</option>'
            '</select>'
            '<button type="submit">Search</button>'
            '</form></div>'
        )

    def _generate_fake_form(self, path: str) -> str:
        form_id = hashlib.md5(path.encode()).hexdigest()[:8]
        return (
            '<div class="form-section">'
            '<h3>Data Export Request</h3>'
            f'<form action="{path}/export" method="POST" id="form_{form_id}">'
            '<input type="hidden" name="csrf_token" '
            f'value="{uuid.uuid4().hex}">'
            '<label>Export Format:</label>'
            '<select name="format">'
            '<option value="csv">CSV</option>'
            '<option value="json">JSON</option>'
            '<option value="xlsx">Excel</option>'
            '</select><br>'
            '<label>Date Range:</label>'
            '<input type="date" name="start_date"> to '
            '<input type="date" name="end_date"><br>'
            '<label>Include PII:</label>'
            '<input type="checkbox" name="include_pii" value="1"><br>'
            '<button type="submit">Request Export</button>'
            '</form></div>'
        )

    def _generate_data_table(self) -> str:
        rows = []
        for _ in range(random.randint(5, 12)):
            name = random.choice(_FAKE_NAMES)
            dept = random.choice(_FAKE_DEPARTMENTS)
            emp_id = f"EMP-{random.randint(10000, 99999)}"
            email = name.lower().replace(" ", ".") + "@corp.internal"
            rows.append(
                f"<tr><td>{emp_id}</td><td>{name}</td>"
                f"<td>{dept}</td><td>{email}</td></tr>"
            )

        return (
            '<div class="data-section">'
            '<h3>Recent Records</h3>'
            '<table><thead><tr>'
            '<th>ID</th><th>Name</th><th>Department</th><th>Email</th>'
            '</tr></thead><tbody>'
            + "".join(rows) +
            '</tbody></table></div>'
        )

    def _generate_link_section(self, links: list[str]) -> str:
        items = []
        labels = _FAKE_FILE_NAMES + [f"resource_{i}.html" for i in range(20)]
        for i, link in enumerate(links):
            label = labels[i % len(labels)]
            items.append(f'<li><a href="{link}">{label}</a></li>')
        return f'<div class="resources"><h3>Available Resources</h3><ul>{"".join(items)}</ul></div>'

    def _generate_footer(self) -> str:
        year = datetime.now().year
        return (
            f'<footer><p>&copy; {year} Internal Systems. '
            'Unauthorized access is prohibited and monitored.</p>'
            '<p><a href="/admin/panel">Admin Panel</a> | '
            '<a href="/internal/status">System Status</a> | '
            '<a href="/api/v2/docs">API Documentation</a></p>'
            '</footer>'
        )

    def _wrap_html(self, path: str, body: str) -> str:
        title = path.strip("/").replace("/", " / ").title() or "Portal"
        return (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            f'<meta charset="utf-8"><title>{title} - Corp Internal</title>\n'
            '<meta name="robots" content="noindex, nofollow">\n'
            '<style>'
            'body{font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5}'
            'header{background:#2c3e50;color:white;padding:20px;margin:-20px -20px 20px}'
            'nav ul{list-style:none;padding:0;display:flex;gap:15px}'
            'nav a{color:#3498db;text-decoration:none}'
            '.content{background:white;padding:20px;border-radius:4px;margin:15px 0}'
            '.alert{background:#fff3cd;border:1px solid #ffc107;padding:10px;margin:10px 0}'
            'table{width:100%;border-collapse:collapse;margin:10px 0}'
            'th,td{border:1px solid #ddd;padding:8px;text-align:left}'
            'th{background:#f8f9fa}'
            '.search-section,.form-section,.data-section,.resources'
            '{background:white;padding:15px;margin:10px 0;border-radius:4px}'
            'input,select,button{margin:5px;padding:5px 10px}'
            'footer{margin-top:30px;color:#666;font-size:0.9em}'
            '</style>\n</head>\n<body>\n'
            f'{body}\n</body>\n</html>'
        )

    def _generate_fake_record(self) -> dict[str, Any]:
        name = random.choice(_FAKE_NAMES)
        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "email": name.lower().replace(" ", ".") + "@corp.internal",
            "department": random.choice(_FAKE_DEPARTMENTS),
            "employee_id": f"EMP-{random.randint(10000, 99999)}",
            "phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
            "hire_date": (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 2000))).strftime("%Y-%m-%d"),
            "salary_band": random.choice(["L3", "L4", "L5", "L6", "L7"]),
            "active": random.choice([True, True, True, False]),
            "last_login": (datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 10000))).isoformat(),
        }
