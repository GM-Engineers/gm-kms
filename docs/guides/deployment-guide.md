# Deployment Guide / 部署指南

> Document version: 1.3.0 | 文档版本: 1.3.0
> Last updated: 2026-09-05

---

## Language Switch / 语言切换

**[English](#overview) | [中文](#概述)**

---

<!-- English Section -->

## Overview

This guide covers production deployment of gm-kms including prerequisites, configuration, and operational procedures.

## Prerequisites

### Infrastructure Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| Memory | 4 GB | 8+ GB |
| Disk | 50 GB SSD | 100+ GB SSD |
| Redis | 1 GB RAM | 2+ GB RAM |
| PostgreSQL | 2 GB RAM | 4+ GB RAM |

### Software Requirements

- Rust 1.85+ (for building from source; Edition 2024 requires 1.85+)
- Docker 24+
- Docker Compose 2.20+
- Redis 7+
- PostgreSQL 16+

## Building

### Production Build

```bash
# Build optimized release binary
cargo build --release -p kms

# Build Docker image
docker build -t gm-kms:latest .
```

### Multi-stage Build (Recommended)

The included Dockerfile uses multi-stage builds to minimize image size (~150MB).

```bash
docker build -t gm-kms:latest -f Dockerfile .
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REST_PORT` | No | `8080` | REST API listen port |
| `GRPC_PORT` | No | `9090` | gRPC API listen port |
| `DATABASE_URL` | Yes | - | PostgreSQL connection string (e.g., `postgres://kms:kms123@localhost:5432/kms` — ⚠️ use a strong password in production) |
| `REDIS_URL` | Yes | `redis://127.0.0.1:6379` | Redis connection string |
| `KMS_API_KEY` | No | `dev-api-key` | API authentication key. Using `dev-api-key` triggers a security warning; set a strong key for production |
| `RUST_LOG` | No | `info` | Logging level |
| `KMS_BACKEND` | No | `software` | Backend type: `software` or `tpm` |

### Configuration File

Create `kms.toml` in the working directory:

```toml
[server]
rest_port = 8080
grpc_port = 9090

[backend]
backend_type = "software"  # Options: software, tpm

[redis]
url = "redis://127.0.0.1:6379"
enabled = true

[audit]
output_path = "stdout"  # or file path
flush_interval_secs = 5
buffer_size = 100

[rate_limit]
enabled = true
requests_per_second = 100
requests_per_minute = 5000
burst_size = 200

[quota]
enabled = true
max_keys = 1000
max_requests_per_minute = 5000
max_requests_per_day = 1000000
```

### TLS Configuration (Optional)

```toml
[tls]
cert_path = "/path/to/server.crt"
key_path = "/path/to/server.key"
ca_path = "/path/to/ca.crt"
require_client_cert = false  # true for mTLS

[rest_tls]
enabled = true
cert_path = "/path/to/rest-server.crt"
key_path = "/path/to/rest-server.key"
```

## Docker Compose Setup

The project includes `docker-compose.yml` for local development with Redis and PostgreSQL:

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis_data:/data

  postgres:
    image: postgres:16-alpine
    ports:
      - "5432:5432"  # Exposed on localhost:5432
    environment:
      POSTGRES_DB: kms
      POSTGRES_USER: kms
      POSTGRES_PASSWORD: kms123
          # ⚠️ 仅用于开发/测试！生产环境请使用强密码
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  redis_data:
  postgres_data:
```

### Start Services

```bash
docker-compose up -d

# Verify services are healthy
redis-cli ping  # Should return PONG
psql -h localhost -p 5432 -U kms -d kms -c "SELECT 1"  # Should return 1
```

## Kubernetes Deployment

### Helm Chart (Planned)

> **注意**：Helm chart 尚未发布。当前请使用下面的 Kubernetes Manifest 方式部署。

```bash
# Helm chart 发布后可用
# helm install gm-kms ./helm -f values.yaml
```

### Basic Kubernetes Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gm-kms
spec:
  replicas: 3
  selector:
    matchLabels:
      app: gm-kms
  template:
    metadata:
      labels:
        app: gm-kms
    spec:
      containers:
        - name: kms
          image: gm-kms:latest
          ports:
            - containerPort: 8080
            - containerPort: 9090
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: kms-secrets
                  key: database-url
```

## Health Checks

### REST Health Endpoint

```bash
curl http://localhost:8080/v1/health
```

Response:
```json
{
  "status": "ok",
  "version": "0.2.1",
  "components": {
    "keystore": "healthy",
    "audit": "healthy"
  }
}
```

Status values: `ok`, `degraded`, `error`

### Liveness Probe

```bash
curl http://localhost:8080/healthz
```

Returns `200 OK` if the server is alive.

### gRPC Health Check

```bash
grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check
```

## Monitoring

### Metrics Endpoint

Prometheus-compatible metrics available at `/v1/metrics`:

```bash
curl http://localhost:8080/v1/metrics
```

Key metrics:
- `kms_key_operations_total` - Total key operations by type
- `kms_key_create_total` - Key creation count
- `kms_encrypt_total` - Encryption operations
- `kms_decrypt_total` - Decryption operations
- `kms_rate_limit_exceeded_total` - Rate limit hits

### Tracing

OpenTelemetry tracing is supported via gRPC interceptor. Configure an OTLP exporter to collect traces.

## Backup and Recovery

### Database Backup

```bash
# Full backup (use correct database name)
pg_dump -Fc kms > kms_backup_$(date +%Y%m%d).dump

# Restore
pg_restore -d kms kms_backup_20260428.dump
```

### Redis Backup

```bash
# BGSAVE triggers async save
redis-cli BGSAVE

# Or use RDB file directly
cp /var/lib/redis/dump.rdb backup/
```

## Security Configuration

### TLS Configuration

For production, enable TLS:

```toml
[tls]
cert_path = "/path/to/server.crt"
key_path = "/path/to/server.key"
ca_path = "/path/to/ca.crt"
require_client_cert = false  # true for mTLS
```

### API Key Rotation

Rotate API keys regularly:

```bash
# Generate new key
openssl rand -hex 32

# Update via environment
export KMS_API_KEY=new_key_here
```

### Audit Configuration

```toml
[audit]
output_path = "stdout"  # or file path like "/var/log/kms/audit.jsonl"
flush_interval_secs = 5
buffer_size = 100
```

### API Key Configuration

API key is configured via `KMS_API_KEY` environment variable. Using `dev-api-key` triggers a security warning; set a strong key for production.

#### Multi-tenant API keys (recommended for production)

A key declared without a tenant falls back to the tenant the **caller** self-reports, which is
not tenant isolation. Declare keys in the server configuration file to bind them to a tenant;
the server then derives the tenant from the credential and ignores any self-reported value.

```toml
[[api_keys]]
key_id = "acme-admin"                    # identifier used in audit trails
role = "key-admin"                       # read-only | operator | key-admin | security-officer | audit-admin | tenant-admin
tenant = "acme"                          # bound tenant: the authoritative one
secret_env = "KMS_API_KEY_ACME"          # secret lives in the environment, not in the file

[[api_keys]]
key_id = "auditor"
role = "audit-admin"
secret_env = "KMS_API_KEY_AUDIT"         # no tenant -> unbound (caller-reported tenant)
```

Then export the secrets before starting the server:

```bash
export KMS_API_KEY_ACME="$(openssl rand -hex 32)"
export KMS_API_KEY_AUDIT="$(openssl rand -hex 32)"
```

Notes:

- The secret is only read from `secret_env`; it is never stored in the configuration file.
- A missing environment variable or an unknown role makes the **startup fail** rather than
  silently running with a weaker key. `KMS_API_KEY_ROLE` accepts the same role names and
  fails the startup on an unknown one, too.
- An **empty** secret makes the startup fail as well: an empty `x-api-key` header is a valid
  credential, so accepting one would let anybody authenticate.
- Two keys must not share a secret, and two keys must not share a `key_id`; both make the
  **startup fail**. A duplicate secret authenticates as whichever key is checked first, and a
  duplicate key id breaks the revocation, which only revokes the first match.
- Keys without a `tenant` produce a `warn` log line at startup, because they still rely on the
  tenant the caller reports.
- `KMS_API_KEY` keeps working as the primary (unbound) key.

#### Roles and the approval workflow

| Role | May | Approval level |
|------|-----|----------------|
| `read-only` | list and read key metadata | `Single` |
| `operator` | encrypt, decrypt, sign, verify, hash, DH | `Double` |
| `key-admin` | key lifecycle (create, rotate, delete, import, export) | `Triple` |
| `security-officer` | policies, API keys, MFA, **approvals**, audit view | `Manager` |
| `audit-admin` | audit log view and export | `Single` |
| `tenant-admin` | **approvals** only (tenant administration) | `Admin` |

The approval level is what an approver contributes to a request. An operation fixes the level it
requires (`key_export` → `Triple`, `high_value_key_create` → `Manager`, `tenant_admin` →
`Admin`), and an approver whose level is **below** it is refused. Both the identity and the
authority of the approver come from the API key — a client-supplied `approver_id` or
`approver_role` in the request body is ignored (and logged as a warning).

`tenant-admin` is the only role that reaches the `Admin` level, so it is the only role that can
approve a `tenant_admin` request. It holds the approval permission and nothing else, so the
three-officer separation (system admin / security admin / audit admin) stays intact.

### Attribute-Based Access Control (PBAC)

PBAC is an **additional** layer on top of the role-based check. The role check (the API key's
permission bits) always runs first and PBAC can only restrict further — it can never grant
access.

Two states matter:

- **No policy configured** — the policy store is empty, so attribute-based control is *inactive*
  and the role check is the only gate. This is the out-of-the-box state. The server logs a `warn`
  on every startup saying so.
- **At least one enabled policy configured** — the engine denies every request that no policy
  covers, so an allow-list policy means exactly that: only what the policies cover is permitted.

A `Deny` policy always wins over an `Allow` policy for the same request.

> **Policies are persisted in PostgreSQL.** They are written to a `policies` table when installed
> and loaded back at startup, so a policy survives a restart along with the attribute-based
> restrictions it carries. The table is created automatically on the first start.
>
> The server **refuses to start** if the policy store cannot be read. An unreadable store and an
> empty store look the same from the API's point of view, and treating the first as the second
> would silently drop every attribute-based restriction while the deployment believes they are
> in force. If the startup fails with a policy-store error, fix the database — the KMS will not
> come up degraded on this path.
>
> Without a PostgreSQL connection there is no store to read, and the engine stays in memory only.
> That is the degraded development mode, and the startup log says so.
>
> A **disabled** policy (`"enabled": false`) does not count: it matches nothing, so it does not
> switch the engine into the default-deny mode either. Only enabled policies count.

```bash
# Install a policy: from then on the default-deny applies.
curl -X POST http://127.0.0.1:8080/v1/policies \
  -H "x-api-key: $KMS_API_KEY_SECURITY_OFFICER" \
  -H 'content-type: application/json' \
  -d '{
        "name": "operators-may-not-export",
        "effect": "deny",
        "condition": {"operator": "eq", "attribute": "action", "value": "export_key"},
        "resources": ["*"],
        "subjects": ["*"]
      }'
```

```bash
# Withdraw a policy again. A persisted policy that turns out to be wrong
# would otherwise outlive every restart.
curl -X DELETE http://127.0.0.1:8080/v1/policies/$POLICY_ID \
  -H "x-api-key: $KMS_API_KEY_SECURITY_OFFICER"
```

### Scoping a policy to one tenant

A policy may carry an optional `tenant` field. Omit it (or send an empty string) and the
policy applies to **every** tenant — exactly how a policy behaved before the tenant dimension
existed, so existing policies keep working unchanged. Set it and the policy applies to that
tenant only:

```bash
# tenant-a may not export; tenant-b is unaffected.
curl -X POST http://127.0.0.1:8080/v1/policies \
  -H "x-api-key: $KMS_API_KEY_SECURITY_OFFICER" \
  -H 'content-type: application/json' \
  -d '{
        "name": "tenant-a-may-not-export",
        "effect": "deny",
        "condition": {"operator": "eq", "attribute": "action", "value": "export_key"},
        "resources": ["*"],
        "subjects": ["*"],
        "tenant": "tenant-a"
      }'
```

`tenant` accepts a glob pattern, so `"tenant-*"` covers a family of tenants.

The tenant a policy is matched against is the **effective** tenant of the request: the tenant the
API key is bound to when it is bound to one (the bound tenant wins and the self-reported value is
ignored), otherwise the tenant the request carries. A request that carries no tenant at all matches
**no** tenant-scoped policy — a caller that does not know which tenant it is in must not reach a
tenant-scoped rule.

> Because both protocol channels resolve the effective tenant before the decision and hand the
> same string to the shared evaluation entry point, switching between REST and gRPC cannot change
> the outcome. A tenant-scoped deny refuses on both channels.

> The `tenant` column is added to the `policies` table automatically. Rows written before this
> column existed load as policies that are **not** tenant-scoped, so an upgrade never silently
> widens or narrows an already-installed policy.

The policy management endpoints require the `security-officer` role (`MANAGE_POLICY`). Installing
and removing a policy are both recorded in the audit trail as a `policy_changed` event.

Both protocol channels evaluate the same policies with the same action names, so switching
between REST and gRPC cannot change the decision. The action names are:

```
create_key  get_key  list_keys  delete_key  rotate_key  import_key  export_key
encrypt     decrypt  sign       verify      hmac       hmac_verify hash
dh_derive   envelope_encrypt  envelope_decrypt  envelope_rewrap
sm9_sign    sm9_verify  sm9_encrypt  sm9_decrypt  query_audit_events
```

The `action` attribute of a policy condition is matched against these names (see the example
above).

## Troubleshooting

### Common Issues

1. **Connection refused to Redis**
   - Check Redis is running: `redis-cli ping`
   - Verify REDIS_URL format

2. **Database migration failed**
   - Check DATABASE_URL is correct
   - Ensure PostgreSQL is accessible

3. **API returns 401 Unauthorized**
   - Verify KMS_API_KEY is set
   - Check X-API-Key header format

### Log Levels

Increase verbosity for debugging:

```bash
RUST_LOG=debug cargo run --release
```

## Performance Tuning

### Redis Configuration

```conf
maxmemory 2gb
maxmemory-policy allkeys-lru
```

### PostgreSQL Configuration

```conf
max_connections = 50
shared_buffers = 256MB
effective_cache_size = 1GB
```

## Upgrade Procedure

1. **Backup data**
2. **Drain connections**: Stop sending traffic
3. **Deploy new version**: `docker-compose up -d`
4. **Verify health**: Check `/v1/health` endpoint
5. **Resume traffic**

## Support

For issues, please open an issue on the project repository with:
- Version (`cargo show kms-api`)
- Configuration (sanitized)
- Logs from the failure period

---

<!-- 中文 Section -->

## 概述

本指南涵盖 gm-kms 的生产部署，包括前提条件、配置和操作程序。

## 前提条件

### 基础设施要求

| 组件 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 2 核 | 4+ 核 |
| 内存 | 4 GB | 8+ GB |
| 磁盘 | 50 GB SSD | 100+ GB SSD |
| Redis | 1 GB RAM | 2+ GB RAM |
| PostgreSQL | 2 GB RAM | 4+ GB RAM |

### 软件要求

- Rust 1.85+ (用于从源码编译；Edition 2024 要求 1.85+)
- Docker 24+
- Docker Compose 2.20+
- Redis 7+
- PostgreSQL 16+

## 编译构建

### 生产构建

```bash
# 编译优化后的发布版本
cargo build --release -p kms

# 构建 Docker 镜像
docker build -t gm-kms:latest .
```

### 多阶段构建（推荐）

Dockerfile 使用多阶段构建，镜像大小约 150MB。

```bash
docker build -t gm-kms:latest -f Dockerfile .
```

## 配置

### 环境变量

| 变量名 | 必需 | 默认值 | 说明 |
|--------|------|--------|------|
| `REST_PORT` | 否 | `8080` | REST API 监听端口 |
| `GRPC_PORT` | 否 | `9090` | gRPC API 监听端口 |
| `DATABASE_URL` | 是 | - | PostgreSQL 连接字符串（如 `postgres://kms:kms123@localhost:5432/kms` — ⚠️ 生产环境请使用强密码） |
| `REDIS_URL` | 是 | `redis://127.0.0.1:6379` | Redis 连接字符串 |
| `KMS_API_KEY` | 否 | `dev-api-key` | API 认证密钥。使用 `dev-api-key` 会触发安全警告；生产环境必须设置强密钥 |
| `RUST_LOG` | 否 | `info` | 日志级别 |
| `KMS_BACKEND` | 否 | `software` | 后端类型：`software` 或 `tpm` |

### 配置文件

在工作目录创建 `kms.toml`：

```toml
[server]
rest_port = 8080
grpc_port = 9090

[backend]
backend_type = "software"  # 选项: software, tpm

[redis]
url = "redis://127.0.0.1:6379"
enabled = true

[audit]
output_path = "stdout"  # 或文件路径
flush_interval_secs = 5
buffer_size = 100

[rate_limit]
enabled = true
requests_per_second = 100
requests_per_minute = 5000
burst_size = 200

[quota]
enabled = true
max_keys = 1000
max_requests_per_minute = 5000
max_requests_per_day = 1000000
```

### TLS 配置（可选）

```toml
[tls]
cert_path = "/path/to/server.crt"
key_path = "/path/to/server.key"
ca_path = "/path/to/ca.crt"
require_client_cert = false  # 设为 true 启用 mTLS

[rest_tls]
enabled = true
cert_path = "/path/to/rest-server.crt"
key_path = "/path/to/rest-server.key"
```

## Docker Compose 部署

项目包含 `docker-compose.yml`，用于本地开发环境的 Redis 和 PostgreSQL：

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis_data:/data

  postgres:
    image: postgres:16-alpine
    ports:
      - "5432:5432"  # 暴露在 localhost:5432
    environment:
      POSTGRES_DB: kms
      POSTGRES_USER: kms
      POSTGRES_PASSWORD: kms123
          # ⚠️ 仅用于开发/测试！生产环境请使用强密码
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  redis_data:
  postgres_data:
```

### 启动服务

```bash
docker-compose up -d

# 验证服务健康状态
redis-cli ping  # 应返回 PONG
psql -h localhost -p 5432 -U kms -d kms -c "SELECT 1"  # 应返回 1
```

## Kubernetes 部署

### Helm Chart（计划中）

> **注意**：Helm chart 尚未发布。当前请使用下面的 Kubernetes Manifest 方式部署。

```bash
# Helm chart 发布后可用
# helm install gm-kms ./helm -f values.yaml
```

### 基本 Kubernetes 清单

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gm-kms
spec:
  replicas: 3
  selector:
    matchLabels:
      app: gm-kms
  template:
    metadata:
      labels:
        app: gm-kms
    spec:
      containers:
        - name: kms
          image: gm-kms:latest
          ports:
            - containerPort: 8080
            - containerPort: 9090
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: kms-secrets
                  key: database-url
```

## 健康检查

### REST 健康端点

```bash
curl http://localhost:8080/v1/health
```

响应示例：
```json
{
  "status": "ok",
  "version": "0.2.1",
  "components": {
    "keystore": "healthy",
    "audit": "healthy"
  }
}
```

状态值：`ok`、`degraded`、`error`

### 存活探针

```bash
curl http://localhost:8080/healthz
```

返回 `200 OK` 表示服务器存活。

### gRPC 健康检查

```bash
grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check
```

## 监控

### 指标端点

Prometheus 兼容指标可通过 `/v1/metrics` 访问：

```bash
curl http://localhost:8080/v1/metrics
```

关键指标：
- `kms_key_operations_total` - 按类型统计的密钥操作总数
- `kms_key_create_total` - 密钥创建数量
- `kms_encrypt_total` - 加密操作数
- `kms_decrypt_total` - 解密操作数
- `kms_rate_limit_exceeded_total` - 限流触发次数

### 链路追踪

通过 gRPC 拦截器支持 OpenTelemetry 追踪。配置 OTLP 导出器收集追踪数据。

## 备份与恢复

### 数据库备份

```bash
# 完全备份（使用正确的数据库名）
pg_dump -Fc kms > kms_backup_$(date +%Y%m%d).dump

# 恢复
pg_restore -d kms kms_backup_20260428.dump
```

### Redis 备份

```bash
# BGSAVE 触发异步保存
redis-cli BGSAVE

# 或直接复制 RDB 文件
cp /var/lib/redis/dump.rdb backup/
```

## 安全配置

### TLS 配置

生产环境建议启用 TLS：

```toml
[tls]
cert_path = "/path/to/server.crt"
key_path = "/path/to/server.key"
ca_path = "/path/to/ca.crt"
require_client_cert = false  # 设为 true 启用 mTLS
```

### API 密钥轮换

定期轮换 API 密钥：

```bash
# 生成新密钥
openssl rand -hex 32

# 通过环境变量更新
export KMS_API_KEY=new_key_here
```

### 审计配置

```toml
[audit]
output_path = "stdout"  # 或文件路径如 "/var/log/kms/audit.jsonl"
flush_interval_secs = 5
buffer_size = 100
```

### API 密钥配置

API 密钥通过 `KMS_API_KEY` 环境变量配置。使用 `dev-api-key` 会触发安全警告；生产环境必须设置强密钥。

## 故障排除

### 常见问题

1. **Redis 连接被拒绝**
   - 检查 Redis 是否运行：`redis-cli ping`
   - 验证 REDIS_URL 格式

2. **数据库迁移失败**
   - 检查 DATABASE_URL 是否正确
   - 确保 PostgreSQL 可访问

3. **API 返回 401 Unauthorized**
   - 验证 KMS_API_KEY 已设置
   - 检查 X-API-Key 头格式

### 日志级别

增加调试详细程度：

```bash
RUST_LOG=debug cargo run --release
```

## 性能调优

### Redis 配置

```conf
maxmemory 2gb
maxmemory-policy allkeys-lru
```

### PostgreSQL 配置

```conf
max_connections = 50
shared_buffers = 256MB
effective_cache_size = 1GB
```

## 升级流程

1. **备份数据**
2. **排空连接**：停止发送流量
3. **部署新版本**：`docker-compose up -d`
4. **验证健康状态**：检查 `/v1/health` 端点
5. **恢复流量**

## 技术支持

如遇问题，请在项目仓库提交 Issue，并提供：
- 版本信息（`cargo show kms-api`）
- 配置（脱敏后）
- 故障时段日志