# N3: DB / Redis TLS Production Defaults / 数据库与缓存 TLS 生产默认值

> 创建 Created: 2026-09-23
> 状态 Status: ✅ 已实现（PR-4.4 / P1-4）
> 更新 Updated: 2026-09-23

## 需求 / Requirement

**English**: KMS database (PostgreSQL) and cache (Redis) connections MUST default to TLS with server-certificate verification (`verify-ca`) in production. Operators MUST NOT be able to silently downgrade to `no-verify` (unauthenticated TLS) or `disabled` (plaintext) in production without an explicit opt-in via `KMS_ALLOW_INSECURE=1` or `KMS_DEV_MODE=1`. `verify-ca` mode MUST require a CA cert path; a config that omits the CA cert must be rejected at startup, not at first connection.

**中文**：KMS 数据库（PostgreSQL）与缓存（Redis）连接在生产环境必须默认启用 TLS 并验证服务端证书（`verify-ca`）。运维若要在生产中降级到 `no-verify`（不验证证书的 TLS）或 `disabled`（明文），必须显式设置 `KMS_ALLOW_INSECURE=1` 或 `KMS_DEV_MODE=1`；不允许静默降级。`verify-ca` 模式必须要求配置 CA 证书路径；缺失 CA 证书的配置应在启动期拒绝，不应等到首次连接时才发现。

## 安全需求 / Security Requirements

### N3.1 默认值 / Defaults

- **NR3.1.1**: 未设置 `KMS_DB_TLS_MODE` 时，生产模式下默认 `verify_ca`（验证服务端证书），而非 `disabled`（明文）。这与 PR-4.1 的 KMS API listener TLS 默认值一致
- **NR3.1.2**: `verify_ca` 必须要求 `KMS_DB_TLS_CA_CERT` 环境变量（或同等配置）非空；缺失则在 startup 期间报错而非等到首次 connect
- **NR3.1.3**: `verify_ca` mode 同时支持 `mutual_tls` 路径（client cert + client key），与现状保持一致

### N3.2 生产禁用明文 / Production Plaintext Disabled

- **NR3.2.1**: 非 `KMS_DEV_MODE=1` 且非 `KMS_ALLOW_INSECURE=1` 时，`KMS_DB_TLS_MODE=disabled` 必须 fail-fast，stderr 输出明确指引
- **NR3.2.2**: 非 `KMS_DEV_MODE=1` 且非 `KMS_ALLOW_INSECURE=1` 时，`KMS_DB_TLS_MODE=no_verify` 必须 fail-fast；`no_verify` 在生产属于禁止配置（攻击者可伪造中间人证书）
- **NR3.2.3**: `KMS_DEV_MODE=1`（测试 / 嵌入式集成）下 `disabled` 仍可接受；`KMS_ALLOW_INSECURE=1` 下 `disabled` 与 `no_verify` 均接受并输出 `tracing::warn!`

### N3.3 环境变量识别 / Env Var Recognition

- **NR3.3.1**: `KMS_DB_TLS_MODE` 接受字面 `verify_ca` / `no_verify` / `disabled`（大小写不敏感）；其他值 reject 为"unknown"，默认 `verify_ca`
- **NR3.3.2**: `KMS_ALLOW_INSECURE=1` 接受字面值 `"1"`，与 PR-4.1 的 `production_safety::is_insecure_opted_in` 复用同一 helper（DRY）

## 验收标准 / Acceptance Criteria

- [x] `KMS_DB_TLS_MODE` 未设 + 非 dev mode + 非 insecure opt-in → `verify_ca`
- [x] `KMS_DB_TLS_MODE=verify_ca` + CA 路径缺失 → startup fail-fast
- [x] `KMS_DB_TLS_MODE=verify_ca` + CA 路径非空 → `VerifyCa` with cert
- [x] `KMS_DB_TLS_MODE=disabled` + 非 dev mode + 非 insecure → fail-fast
- [x] `KMS_DB_TLS_MODE=disabled` + `KMS_DEV_MODE=1` → `Disabled`
- [x] `KMS_DB_TLS_MODE=disabled` + `KMS_ALLOW_INSECURE=1` → `Disabled` + warn
- [x] `KMS_DB_TLS_MODE=no_verify` + 非 dev mode + 非 insecure → fail-fast
- [x] `KMS_DB_TLS_MODE=no_verify` + `KMS_ALLOW_INSECURE=1` → `NoVerify` + warn
- [x] `KMS_DB_TLS_MODE=foo` (unknown) → `VerifyCa` (现有行为)

## 测试覆盖 / Test Coverage

`crates/kms-core/src/tls_config.rs` 新增 11 个 PR-4.4 单元测试：
- `pr44_db_tls_default_unset_production`: 默认 `verify_ca`
- `pr44_db_tls_disabled_in_dev_mode_ok`: dev mode 下 `disabled` 接受
- `pr44_db_tls_disabled_in_prod_no_opt_in_rejected`: prod 拒绝 `disabled`
- `pr44_db_tls_disabled_in_prod_with_allow_insecure_ok`: `KMS_ALLOW_INSECURE=1` 放行
- `pr44_db_tls_no_verify_in_prod_rejected`: prod 拒绝 `no_verify`
- `pr44_db_tls_no_verify_with_allow_insecure_ok`: insecure opt-in 放行
- `pr44_db_tls_no_verify_in_dev_mode_ok`: dev mode 下 `no_verify` 接受
- `pr44_db_tls_verify_ca_default`: `verify_ca` 字面值
- `pr44_db_tls_unknown_value_defaults_to_verify_ca`: 未知值默认
- `pr44_db_tls_case_insensitive`: 大小写不敏感
- `pr44_db_tls_empty_path_set`: 空字符串视为 unset

## 实现说明 / Implementation Notes

### 关键代码位置

- [`crates/kms-core/src/tls_config.rs`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-core/src/tls_config.rs) — `BackendTlsConfig::from_env` 重构 + 11 个新单元测试
- [`crates/kms-core/src/production_safety.rs`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-core/src/production_safety.rs)（PR-4.1 已建）— 复用 `is_insecure_opted_in()`

### 设计决策

1. **为什么 `verify_ca` 模式下必须有 CA 路径**：PostgreSQL / Redis TLS 不验证服务端证书等于没加密（攻击者可伪造证书）。仅 TLS 不够，必须 verify-ca
2. **为什么复用 `is_insecure_opted_in`**：避免 KMS env var 命名漂移；PR-4.1 已建立的约定应统一
3. **为什么 dev mode 下 `no_verify` 仍接受**：嵌入式测试场景需要本地 Postgres/Redis；dev mode 本身就是契约上的"测试/嵌入式集成"标记

### 已知限制

- `mutual_tls` mode 的 client cert 路径存在性不在 startup 校验；PostgreSQL 连接握手时才会报错。属于"运行时快速失败"而非 startup 校验
- `KMS_DB_TLS_CA_CERT` 路径值存在性（文件是否存在）不在 startup 校验；属于运行时

## 关联 PR / Related PRs

- 触发：`gm与gm-kms源码级改进建议.md §6 / §7 P1-4`
- 实现：`PR-4.4`（本需求）
- 关联：`PR-4.1`（P1-3 KMS API listener TLS fail-fast — 同样 `KMS_ALLOW_INSECURE` opt-in 机制）
- 关联：`PR-1.1 ~ PR-1.4`（P0 AES-GCM / KEK / tenant fail-fast）

## 关联需求 / Related Requirements

- `N1-security.md`：租户隔离 / API 安全 / 输入验证
- `N2-tls-failfast.md`：KMS API listener TLS fail-fast