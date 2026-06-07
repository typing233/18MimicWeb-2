# MimicWeb - HTTP 仿真服务框架

轻量级 HTTP 仿真服务框架，专为授权安全演练和低风险蜜罐设计。

## 功能特性

### 核心能力
- **YAML 配置驱动**：通过声明式配置定义路由、响应、条件逻辑
- **动态响应引擎**：支持变量替换（时间戳、UUID、随机数据）、条件判断、随机延迟、模拟错误率
- **正则 + 路径参数**：灵活的路由匹配（`/api/users/{user_id}` 或 `^/admin/.*`）
- **OAuth2/JWT 模拟**：完整的授权码流程、Token 签发、UserInfo 端点、OIDC Discovery
- **扫描器检测**：自动识别 sqlmap、nikto、nmap 等工具，区分正常访问与可疑行为
- **热更新**：通过 Admin API 新增/修改/启用/停用路由，无需重启

### 管理后台
- 内置 Web UI（`/_admin`），实时查看 JSON Lines 请求日志
- 支持按方法、路径、可疑标记过滤
- 路由 CRUD + 一键启停
- CSV 导出审计日志

### 多实例部署
- Redis 后端共享请求记录
- PostgreSQL 存储长期审计数据
- Docker Compose 一键启动

## 快速开始

### 本地运行

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
mimicweb -c config/routes.yaml
```

服务启动后：
- 蜜罐服务：`http://localhost:8080`
- 管理后台：`http://localhost:8080/_admin`

### Docker Compose 部署

```bash
# 基础部署（含 Redis 共享日志）
docker compose up -d

# 包含 PostgreSQL 长期审计
docker compose --profile audit up -d
```

## 配置详解

### 路由配置 (`config/routes.yaml`)

```yaml
routes:
  - id: "api_users"
    path: "/api/v1/users/{user_id}"  # 路径参数
    method: "GET"
    enabled: true
    
    # 条件判断：基于请求头决定响应
    conditions:
      - field: "header:Authorization"
        pattern: "^Bearer .+"
        action: "proceed"        # 匹配则返回默认响应
      - field: "header:Authorization"
        pattern: "^$"
        action: "respond"        # 匹配则返回自定义响应
        response:
          status: 401
          body: '{"error": "unauthorized"}'
    
    # 默认响应（支持变量替换）
    response:
      status: 200
      headers:
        Content-Type: "application/json"
      body: |
        {
          "id": "{{path:user_id}}",
          "email": "{{random_email}}",
          "session": "{{random_hex:32}}",
          "timestamp": "{{timestamp_iso}}"
        }
    
    # 随机延迟注入
    delay:
      min_ms: 50
      max_ms: 200
    
    # 模拟 5% 错误率
    error_rate: 0.05

  # 正则路由
  - id: "admin_regex"
    path: "^/admin/(?P<section>\\w+)$"
    path_type: "regex"
    method: "ANY"
    response:
      status: 403
      body: '{"forbidden": "{{regex:section}}"}'
```

### 可用变量

| 变量 | 说明 |
|------|------|
| `{{timestamp_iso}}` | ISO 8601 时间戳 |
| `{{timestamp_unix}}` | Unix 时间戳 |
| `{{random_hex:N}}` | N 位十六进制随机字符串 |
| `{{random_uuid}}` | 随机 UUID |
| `{{random_int:MIN:MAX}}` | 范围内随机整数 |
| `{{random_email}}` | 随机内部邮箱 |
| `{{random_ip}}` | 随机内网 IP |
| `{{uptime_seconds}}` | 服务运行时间 |
| `{{client_ip}}` | 客户端 IP |
| `{{path:name}}` | 路径参数值 |
| `{{query:name}}` | 查询参数值 |
| `{{header:name}}` | 请求头值 |
| `{{regex:group}}` | 正则命名组 |

### 扫描器检测规则

```yaml
scanner_detection:
  enabled: true
  rules:
    - pattern: "sqlmap|nikto|nmap"
      field: "user_agent"       # user_agent | path | body | query | header:X
      label: "known_scanner"
    - pattern: "\\.\\./"
      field: "path"
      label: "path_traversal"
```

### 存储后端配置

```yaml
storage:
  backend: "redis"  # local | redis | postgres
  redis:
    url: "redis://localhost:6379/0"
    prefix: "mimicweb:"
  postgres:
    dsn: "postgresql://user:pass@host:5432/mimicweb"
```

## OAuth2 模拟端点

框架内置完整的 OAuth2/OIDC 模拟：

| 端点 | 说明 |
|------|------|
| `GET /oauth/authorize` | 授权端点（返回 302 + code） |
| `POST /oauth/token` | Token 端点（支持 authorization_code / client_credentials / refresh_token） |
| `GET /oauth/userinfo` | UserInfo（需 Bearer token） |
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/jwks.json` | JWK 集合 |
| `POST /api/auth/login` | 表单登录（返回 JWT） |

## Admin API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/_admin` | GET | Web 管理界面 |
| `/_admin/api/logs` | GET | 查询日志（支持 limit/offset/suspicious/method/path/since） |
| `/_admin/api/logs/export` | GET | CSV 导出 |
| `/_admin/api/routes` | GET | 列出所有路由 |
| `/_admin/api/routes` | POST | 新增路由 |
| `/_admin/api/routes/{id}` | PUT | 修改路由 |
| `/_admin/api/routes/{id}` | DELETE | 删除路由 |
| `/_admin/api/routes/{id}/toggle` | POST | 启用/停用路由 |
| `/_admin/api/reload` | POST | 热重载配置文件 |
| `/_admin/api/stats` | GET | 统计信息 |

## 测试

```bash
# 运行全部测试
pytest tests/ -v

# 含覆盖率报告
pytest tests/ --cov=mimicweb --cov-report=term-missing
```

测试覆盖：
- 路由匹配（静态/正则/路径参数/禁用）
- 条件判断逻辑
- 变量替换引擎
- 错误注入/延迟注入
- OAuth2 完整流程
- JWT 签发与验证
- 扫描器检测
- 存储 CRUD + 持久化
- Admin API 全部端点
- 并发安全性
- 边界场景（大 body、Unicode、畸形 JSON）

## 项目结构

```
├── config/
│   ├── routes.yaml          # 默认配置
│   └── routes-docker.yaml   # Docker 环境配置
├── src/mimicweb/
│   ├── main.py              # 入口，Starlette 应用组装
│   ├── config.py            # YAML 配置管理 + 热更新
│   ├── router.py            # 动态路由匹配
│   ├── response_engine.py   # 响应构建 + 变量替换
│   ├── scanner_detector.py  # 扫描行为检测
│   ├── auth_simulator.py    # OAuth2/JWT 模拟
│   ├── admin/               # 管理后台
│   │   ├── __init__.py      # Admin API
│   │   └── templates/
│   │       └── index.html   # Web UI
│   └── storage/
│       ├── base.py          # 抽象接口 + LogEntry
│       ├── local.py         # JSON Lines 本地存储
│       ├── redis_backend.py # Redis 多实例共享
│       └── postgres_backend.py  # PostgreSQL 审计
├── tests/                   # 68 个测试用例
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## 安全提示

此工具仅用于：
- 授权的渗透测试环境
- 安全培训和 CTF 演练
- 低交互蜜罐部署
- 安全研究

请确保在隔离环境中部署，并遵守所在司法管辖区的法律法规。
