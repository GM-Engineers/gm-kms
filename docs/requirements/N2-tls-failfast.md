# N2: TLS Startup Fail-Fast / 启动 TLS 失败即停

> 创建 Created: 2026-09-23
> 状态 Status: ✅ 已实现（PR-4.1 / P1-3）
> 更新 Updated: 2026-09-23

## 需求 / Requirement

**English**: The KMS server MUST refuse to start its gRPC and REST API listeners in plaintext unless the operator explicitly opts in via `KMS_ALLOW_INSECURE=1` (production-safety opt-in) or `KMS_DEV_MODE=1` (test / embedded-integration opt-in). This mirrors the KEK fail-fast contract at `kms-keystore/src/postgres.rs:92-95`.

**中文**：除非运维人员通过 `KMS_ALLOW_INSECURE=1`（生产安全白名单）或 `KMS_DEV_MODE=1`（测试 / 嵌入式集成白名单）明确放行，KMS 服务必须拒绝以明文启动 gRPC 与 REST API 监听器。该契约与 KEK 启动期 fail-fast（`kms-keystore/src/postgres.rs:92-95`）对称。

## 安全需求 / Security Requirements

### N2.1 gRPC 启动期 TLS 强制 / gRPC Startup TLS Enforcement

- **NR2.1.1**: 未配置任何 TLS 证书（既无 `[tls]` 配置块，也无 `TLS_CERT_PATH` / `TLS_KEY_PATH` / `TLS_CA_PATH` 环境变量）时，gRPC 启动必须 `bail!` 失败并打印明确指引
- **NR2.1.2**: gRPC 明文启动的唯一放行路径是 `KMS_ALLOW_INSECURE=1` 或 `KMS_DEV_MODE=1`
- **NR2.1.3**: gRPC 明文启动必须输出 `tracing::warn!` 日志，明文提示"API keys will transit in plaintext"

### N2.2 REST 启动期 TLS 强制 / REST Startup TLS Enforcement

- **NR2.2.1**: `rest_tls_config = None`（无 `[rest_tls]` 配置块）时，REST 必须 `bail!` 失败
- **NR2.2.2**: `rest_tls.enabled = false`（运维在配置文件中显式禁用）时，REST 也必须 `bail!` 失败
- **NR2.2.3**: 两条分支的失败消息必须互不相同，运维可据此判断究竟属于哪一种误配置
- **NR2.2.4**: REST 明文启动必须输出 `tracing::warn!` 日志

### N2.3 白名单互斥 / Opt-in Flag Semantics

- **NR2.3.1**: `KMS_ALLOW_INSECURE` 与 `KMS_DEV_MODE` 仅识别字面值 `"1"`，其他值（`"true"` / `"yes"` / `"on"`）一律视为未设置
- **NR2.3.2**: 两个 env-var 互相独立：单独设置任一即足以放行；二者同时设置亦可
- **NR2.3.3**: helper 必须可独立单元测试（不依赖网络 / 密钥库 / 真实启动流程）

## 验收标准 / Acceptance Criteria

- [x] gRPC 无 TLS 配置 → 启动 fail，stderr 含 "gRPC requires TLS in production"
- [x] gRPC + `KMS_ALLOW_INSECURE=1` → 启动通过，输出明文 warn
- [x] gRPC + `KMS_DEV_MODE=1` → 启动通过
- [x] REST `rest_tls_config = None` → 启动 fail，stderr 含 "no [rest_tls] config block"
- [x] REST `rest_tls.enabled = false` → 启动 fail，stderr 含 "rest_tls.enabled=false"
- [x] `KMS_ALLOW_INSECURE=true`（非字面 "1"）→ 视为未放行，fail-fast 仍生效
- [x] 两条 REST 错误消息互不相同
- [x] 既有用例（设置 `KMS_DEV_MODE=1` 的测试 fixture）继续通过

## 测试覆盖 / Test Coverage

- `crates/kms-core/src/production_safety.rs` 单元测试（5 个）：
  - `pr41_is_allow_insecure_default_false`
  - `pr41_is_allow_insecure_set_to_one`
  - `pr41_is_allow_insecure_other_value_is_false`
  - `pr41_is_dev_mode_set_to_one`
  - `pr41_is_insecure_opted_in_either_flag_suffices`
- `src/cmd/server.rs::pr41_failfast_tests`（7 个）：
  - `pr41_grpc_failfast_no_opt_in`
  - `pr41_grpc_failfast_allow_insecure_opt_in`
  - `pr41_grpc_failfast_dev_mode_opt_in`
  - `pr41_rest_failfast_no_opt_in_config_present`
  - `pr41_rest_failfast_no_opt_in_config_absent`
  - `pr41_rest_failfast_allow_insecure_overrides_both`
  - `pr41_messages_distinct_per_arm`

合计 12 个新增单元测试，全部使用 `Mutex<()>` 串行化 `std::env::*` 调用，避免并行测试互相污染。

## 实现说明 / Implementation Notes

### 关键代码位置

- `crates/kms-core/src/production_safety.rs` 新模块（PR-4.1 新增）：三个 env-var 读取 helper + 5 个单元测试
- `src/cmd/server.rs::grpc_tls_failfast_message()`：`pub(crate)` helper，返回 `Option<&'static str>`；调用方在 gRPC startup 中 `if let Some(msg) = ... { anyhow::bail!(msg); }`
- `src/cmd/server.rs::rest_tls_failfast_message(bool)`：REST-side 对应；`bool` 参数区分 `rest_tls_config = None` 与 `rest_tls.enabled = false` 两种失败模式
- `src/cmd/server.rs::run`：gRPC + REST 启动路径均调用上述 helper

### 设计决策 / Design Decisions

- **为什么不直接 inline 启动路径**：原 `cmd::server::run` 函数依赖 KEK / Postgres / Redis / TLS 配置 / API key 等大量外部状态，端到端集成测试成本极高。拆出 helper 后，单测覆盖全部 4 分支仅需 7 个测试用例（见上）。
- **为什么不用 `bool` 包装环境变量读 helper**：现有 `kms-core::tls_config::TlsConfig::from_env` 模式将 `"1"` 严格化，但 PR-4.1 选择显式 `as_deref() == Ok("1")` 而非新建一个 `EnvBool` 类型，保持 helper 一行就能写完。
- **为什么不用 deny-by-default 的 Option**：考虑过 `mode: Insecure | Secure`，但现有 `KMS_DEV_MODE=1` 已广泛存在于测试 fixture，破坏向后兼容的风险高于收益。helper `is_insecure_opted_in()` 显式返回 bool，调用方一目了然。

### 已知限制 / Known Limitations

- `cmd::server::run` 启动路径的真正集成测试仍缺失（需要 mock 网络监听 + 真实 Postgres / Redis 才能端到端跑通，超出 PR-4.1 范围）
- operator 误将 `KMS_DEV_MODE=1` 写入生产 systemd unit 的风险未在 PR-4.1 内缓解（属于部署规范 / runbook 范畴）
- PR-4.1 只覆盖 KMS 自身 API listener；DB / Redis TLS 默认值是独立的 P1-4，将在后续 PR-4.2 处理

## 关联 PR / Related PRs

- 触发：`gm与gm-kms源码级改进建议.md §6 / §7 P1-3`
- 实现：`PR-4.1`（本需求）
- 关联：`PR-1.1 ~ PR-1.4`（Batch 1 — P0-1 / P0-2 / P0-3 / P0-5 已经修复了同等级别的 KEK / AES-GCM / SM4-GCM / AAD fail-fast）
- 后续：`PR-4.2`（P1-4 DB / Redis TLS 默认 VerifyCa）、`PR-4.3`（P1-5 SM9 密钥生成 material 检查）
