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

### 行为分析与自适应反爬
- **跨请求会话追踪**：按来源 IP 关联多个请求，构建访问行为画像
- **风险评分系统**：基于请求频率、路径遍历深度、404 比率、机器人式定时规律等多维度自动评分（0-100）
- **自适应诱饵页面**：根据风险等级动态调整返回内容——逐步增加假链接深度、注入假搜索表单、生成虚假数据表
- **反爬策略引擎**：可配置的随机延迟、假页面诱导、API 数据污染（仅作用于诱饵路径，不影响已配置的正常路由）
- **日志聚合与导出**：按时间/来源/路径/风险等级汇总，支持 JSON 和 CSV 格式导出

### 管理后台
- 内置 Web UI（`/_admin`），实时查看 JSON Lines 请求日志
- 支持按方法、路径、可疑标记过滤
- 路由 CRUD + 一键启停
- 会话监控和风险评分面板
- 聚合报告导出

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
# 基础多实例部署（2 节点 + Redis 共享日志）
docker compose up -d

# 包含 PostgreSQL 审计的完整部署
docker compose --profile audit up -d
```

**部署模式说明：**

| 模式 | 命令 | 说明 |
|------|------|------|
| 基础 | `docker compose up -d` | 2 个蜜罐实例 (8080/8081) + Redis，日志实时共享 |
| 审计 | `docker compose --profile audit up -d` | 基础 + PostgreSQL + 审计实例 (8082)，双写模式 |

## 行为分析配置

在 `config/routes.yaml` 中的 `honeypot:` 段配置，所有参数都支持环境变量覆盖：

```yaml
honeypot:
  enabled: true

  # 行为分析参数
  behavior_analysis:
    session_ttl_seconds: 3600        # 会话过期时间
    analysis_window_seconds: 300     # 频率计算的时间窗口
    rate_threshold_per_minute: 30    # 触发"高频请求"标签的阈值
    path_diversity_threshold: 20     # 触发"路径枚举"标签的独立路径数
    depth_threshold: 5               # 触发"深度遍历"标签的路径深度
    sequential_404_threshold: 5      # 连续 404 次数触发"目录爆破"

  # 自适应响应内容
  adaptive_response:
    max_link_depth: 5                # 假页面中生成的最大链接层级
    enable_fake_forms: true          # 高风险时是否注入假表单
    enable_fake_search: true         # 中风险时是否注入假搜索入口

  # 反爬策略（仅作用于诱饵路径，不影响已配置路由）
  anticrawl:
    enabled: true
    score_threshold: 30.0            # 风险分达到此值才激活反爬
    delay:
      enabled: true
      min_ms: 100                    # 基础延迟下限
      max_ms: 2000                   # 基础延迟上限（实际值 = 基础 × 风险系数）
    slow_drip_max_ms: 5000           # 极高风险时的额外延迟上限
    strategies:
      redirect_deeper: true          # 诱导跳转到更深假页面
      fake_page: true                # 返回自适应假页面
      pollute_data: true             # /api/ 路径返回假 JSON 数据
      slow_drip: true                # 极高风险时超慢响应

  # 日志采样与导出
  log_export:
    sampling_rate: 1.0               # 1.0=全量记录，0.5=50% 采样
    formats:                         # 允许的导出格式
      - json
      - csv
    aggregation_intervals:           # 聚合时可用的时间粒度
      - "1m"
      - "5m"
      - "1h"
      - "1d"
```

### 环境变量覆盖

所有关键参数支持环境变量覆盖（优先级高于 YAML 文件）：

| 环境变量 | 对应配置 |
|----------|----------|
| `MIMICWEB_HONEYPOT_ENABLED` | `honeypot.enabled` |
| `MIMICWEB_RATE_THRESHOLD` | `behavior_analysis.rate_threshold_per_minute` |
| `MIMICWEB_SESSION_TTL` | `behavior_analysis.session_ttl_seconds` |
| `MIMICWEB_ANALYSIS_WINDOW` | `behavior_analysis.analysis_window_seconds` |
| `MIMICWEB_PATH_DIVERSITY_THRESHOLD` | `behavior_analysis.path_diversity_threshold` |
| `MIMICWEB_DEPTH_THRESHOLD` | `behavior_analysis.depth_threshold` |
| `MIMICWEB_404_THRESHOLD` | `behavior_analysis.sequential_404_threshold` |
| `MIMICWEB_MAX_LINK_DEPTH` | `adaptive_response.max_link_depth` |
| `MIMICWEB_FAKE_FORMS` | `adaptive_response.enable_fake_forms` |
| `MIMICWEB_FAKE_SEARCH` | `adaptive_response.enable_fake_search` |
| `MIMICWEB_ANTICRAWL_ENABLED` | `anticrawl.enabled` |
| `MIMICWEB_ANTICRAWL_THRESHOLD` | `anticrawl.score_threshold` |
| `MIMICWEB_DELAY_MIN_MS` | `anticrawl.delay.min_ms` |
| `MIMICWEB_DELAY_MAX_MS` | `anticrawl.delay.max_ms` |
| `MIMICWEB_SAMPLING_RATE` | `log_export.sampling_rate` |

### 反爬作用范围

反爬策略**仅对诱饵页面**生效。判定标准：

- 请求路径能匹配 `routes:` 中已配置且 `enabled: true` 的路由 → **正常路由**，始终返回配置的响应
- 请求路径不匹配任何已配置路由（或只匹配 `catch_all`） → **诱饵目标**，根据风险分决定是否激活反爬

例如，即使某个 IP 已积累高风险分，访问 `/health` 仍返回正常的 200 状态，不会被反爬策略拦截。

## 会话与风险评分 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/_admin/api/sessions` | GET | 列出所有活跃会话（含风险评分、标签、请求数） |
| `/_admin/api/sessions/{ip}` | GET | 单个 IP 的详细行为画像（最近路径、方法分布、状态码统计） |
| `/_admin/api/honeypot/config` | GET | 查看当前生效的蜜罐配置 |

**风险评分标签说明：**

| 标签 | 含义 | 触发条件 |
|------|------|----------|
| `high_request_rate` | 请求频率过高 | 超过 `rate_threshold_per_minute` |
| `path_enumeration` | 路径枚举行为 | 独立路径数 > `path_diversity_threshold` |
| `deep_traversal` | 深层路径遍历 | 路径深度 > `depth_threshold` |
| `directory_bruteforce` | 目录爆破 | 连续 404 ≥ `sequential_404_threshold` |
| `high_404_ratio` | 404 比率过高 | 超过 10 次请求且 404 占比 > 50% |
| `missing_user_agent` | 缺失 User-Agent | UA 为空或 `-` |
| `robotic_timing` | 机器人式定时 | 请求间隔极规律（方差 < 0.01s） |

## 日志聚合与导出 API

| 端点 | 方法 | 参数 | 说明 |
|------|------|------|------|
| `/_admin/api/aggregation` | GET | `group_by`, `interval`, `since`, `suspicious` | 查询聚合数据 |
| `/_admin/api/aggregation/export` | GET | `format`, `group_by`, `interval`, `since`, `suspicious` | 下载聚合报告 |

**参数说明：**

- `group_by`: `time` | `source` | `path` | `risk`
- `interval`: 时间聚合粒度（秒），默认 300
- `format`: `json` | `csv`（需在 `log_export.formats` 配置中启用）
- `since`: Unix 时间戳，只聚合此时间之后的数据
- `suspicious`: `true` 则只聚合可疑请求

**示例：**

```bash
# 按来源 IP 聚合
curl "http://localhost:8080/_admin/api/aggregation?group_by=source"

# 按风险等级聚合，只看可疑请求
curl "http://localhost:8080/_admin/api/aggregation?group_by=risk&suspicious=true"

# 导出 CSV 报告（按时间，5分钟粒度）
curl -o report.csv "http://localhost:8080/_admin/api/aggregation/export?format=csv&group_by=time&interval=300"

# 导出 JSON 报告（按路径）
curl -o report.json "http://localhost:8080/_admin/api/aggregation/export?format=json&group_by=path"
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
  # 可选值: local | redis | postgres | composite
  backend: "redis"
  
  local:
    log_dir: "./logs"          # JSON Lines 文件存储
  
  redis:
    url: "redis://localhost:6379/0"
    prefix: "mimicweb:"       # 多实例通过相同前缀共享日志
  
  postgres:
    dsn: "postgresql://user:pass@host:5432/mimicweb"
  
  # composite = Redis (实时共享) + PostgreSQL (长期审计) 双写
  # 查询优先走 PostgreSQL，PostgreSQL 不可用时降级到 Redis
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
| `/_admin/api/sessions` | GET | 活跃会话列表（含风险评分） |
| `/_admin/api/sessions/{ip}` | GET | 单 IP 会话详情 |
| `/_admin/api/aggregation` | GET | 日志聚合查询 |
| `/_admin/api/aggregation/export` | GET | 聚合报告导出 |
| `/_admin/api/honeypot/config` | GET | 当前蜜罐配置 |

## 验证功能

### 运行测试

```bash
# 运行全部测试（186 个）
pytest tests/ -v

# 含覆盖率报告
pytest tests/ --cov=mimicweb --cov-report=term-missing
```

### 手动验证反爬效果

```bash
# 启动服务
mimicweb -c config/routes.yaml

# 1. 正常访问 - 应返回配置的正常响应
curl http://localhost:8080/
curl http://localhost:8080/health

# 2. 模拟爬虫行为 - 快速遍历大量路径（无 User-Agent）
for i in $(seq 1 20); do
  curl -s -H "User-Agent: " "http://localhost:8080/scan/deep/$i/path" > /dev/null
done

# 3. 验证正常路由不受影响
curl http://localhost:8080/health  # 仍返回正常 200 + 配置的 JSON

# 4. 查看会话和风险评分
curl http://localhost:8080/_admin/api/sessions | python3 -m json.tool

# 5. 查看聚合报告
curl "http://localhost:8080/_admin/api/aggregation?group_by=risk" | python3 -m json.tool

# 6. 导出 CSV 报告
curl -o report.csv "http://localhost:8080/_admin/api/aggregation/export?format=csv&group_by=source"

# 7. 查看当前配置
curl http://localhost:8080/_admin/api/honeypot/config | python3 -m json.tool
```

### 通过环境变量调参

```bash
# 降低触发阈值便于测试
MIMICWEB_ANTICRAWL_THRESHOLD=10 MIMICWEB_RATE_THRESHOLD=5 mimicweb -c config/routes.yaml

# 关闭反爬（仅做行为记录）
MIMICWEB_ANTICRAWL_ENABLED=false mimicweb -c config/routes.yaml

# 50% 日志采样
MIMICWEB_SAMPLING_RATE=0.5 mimicweb -c config/routes.yaml
```

## 项目结构

```
├── config/
│   ├── routes.yaml              # 默认配置（含 honeypot 段）
│   ├── routes-docker.yaml       # Docker 环境配置
│   └── routes-audit.yaml        # 审计模式配置
├── src/mimicweb/
│   ├── main.py                  # 入口，Starlette 应用组装
│   ├── config.py                # YAML 配置 + 环境变量覆盖 + 热更新
│   ├── router.py                # 动态路由匹配
│   ├── response_engine.py       # 响应构建 + 变量替换
│   ├── scanner_detector.py      # 扫描行为检测（正则规则）
│   ├── behavior_analyzer.py     # 跨请求会话追踪 + 风险评分
│   ├── adaptive_engine.py       # 自适应诱饵内容生成
│   ├── anticrawl.py             # 反爬策略引擎
│   ├── log_aggregator.py        # 日志聚合 + JSON/CSV 导出
│   ├── auth_simulator.py        # OAuth2/JWT 模拟
│   ├── admin/                   # 管理后台
│   │   ├── __init__.py          # Admin API
│   │   └── templates/
│   │       └── index.html       # Web UI
│   └── storage/
│       ├── base.py              # 抽象接口 + LogEntry
│       ├── local.py             # JSON Lines 本地存储
│       ├── redis_backend.py     # Redis 多实例共享
│       ├── composite.py         # 双写存储
│       └── postgres_backend.py  # PostgreSQL 审计
├── tests/                       # 186 个测试用例
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
