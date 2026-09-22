# Changelog

All notable changes to gm-kms will be documented in this file.

## [0.3.0] — Unreleased

### 重塑定位（Breaking change in messaging, not code）

本版本将项目定位从"生产 KMS"调整为"Rust 国密 KMS 参考实现"，面向学习、内部演示、生态集成和小规模辅助场景。**不替代**商业云 KMS，**未通过**密评或等保认证。

- README.md / README.en.md 全面重写：顶部定位声明、"本项目是什么 / 不是什么"、适用 / 不适用场景矩阵、合规自评估表
- 新增 LEARN.md：按依赖关系组织的代码导读，10 个推荐起点
- 删除 deploy/kubernetes/kms-hpa-pdb.yaml、deploy/kubernetes/kms-monitoring.yaml（暗示生产的资产）
- deploy/kubernetes/ 内容迁移到 examples/k8s-demo/，README 重写为 demo 定位
- operators/kms-operator/ 和 providers/terraform/ README 顶部加 experimental / not maintained 警告
- 测试统计表数字修正：877 实测 vs 959 历史声称

### Added

- **TLCP (GB/T 38636-2020) REST 入口**：新增 `src/cmd/tlcp_listener.rs`，镜像 `gm_listener.rs` 模式，使用 `gm_tlcp::TlcpAcceptor` 替代 `gm_tls::TlsAcceptor`
- 新增 `[rest_tls].backend = "tlcp"` 配置项（向后兼容，`gm` / `rustls` 仍可用）
- 新增集成测试 `crates/kms-api/tests/tlcp_integration.rs`：TLCP 握手 + REST 端到端、双证书缺失失败、握手失败处理
- 新增文档：
  - `docs/guides/tlcp-deployment.md`：TLCP 模式部署指南
  - `docs/wiki/tlcp.md`：TLCP vs TLS 1.3 概念差异
  - `LEARN.md`：代码导读

### Changed

- `src/cmd/config.rs::RestTlsConfig`：新增 TLCP 双证书路径字段（`tlcp_sign_cert_path`、`tlcp_enc_cert_path`、`tlcp_sign_key_path`、`tlcp_enc_key_path`）
- `src/cmd/server.rs`：REST 服务启动按 `backend` 字段 dispatch 到对应 listener
- `kms.toml.example`：`[rest_tls]` 区块增加 TLCP 配置示例
- 顶层 `Cargo.toml`：新增 `gm-tlcp = "0.6"` 依赖；`[patch.crates-io]` 加入 gm-tlcp（与其他三个 gm-* crate 同一 git rev）

### Fixed

- README 测试统计表数字与实测一致（877 passed，含 18 个 ignored）
- README 合规自评估表改为如实标注（已实现 ≠ 已认证）
- **`crates/kms-core/src/algorithms_impl.rs::Aes256GcmDecryptor::decrypt`**：修复 12-byte nonce 越界 panic。
  旧实现 `if len >= 12 { [4..16] }` 对 len ∈ [12, 16) 的密文会 panic；外部导入 / 跨实现密文可触发进程崩溃（DoS）。改用穷举 `match` 接受 12（RFC 5116 §5.2 固定 N_MIN = N_MAX = 12 octets）与 16（自产 counter）两种格式，其他长度返回 `DecryptionFailed`。
  新增 4 个回归测试覆盖 12-byte 外密文解密、16-byte 截断为 12-byte 解密、长度 8 与 15 负测试。
  （对应 P0-1）
- **`crates/kms-api/src/service/crypto_service.rs`**：P0-2 修复跨租户访问走完密码路径并泄露密钥枚举 oracle。
  旧实现在 `keystore.sign` / `decrypt` / `encrypt` / `verify` 走完后才校验 `tenant_id`，造成：远程 HSM/TPM 签名额度被未授权请求消耗；响应时间可区分「不存在」与「被其他租户拥有」；错误码 `KeyNotFound` (404) 与 `Forbidden` (403) 可区分。
  改用 `fetch_owned_key_meta` 前置校验：密钥元数据 + 租户一致，未通过则统一返回 `KeyNotFound`。移除原后置 `get_key_metadata` 调用，改用前置获取的 `meta` 给批量指标复用。
  `crates/kms-api/src/service/key_service.rs` 一致性：`rotate_key` / `delete_key` / `get_key` / `export_key` 的跨租户返回从 `Forbidden` 改为 `KeyNotFound`，与「不存在」不可区分。
  新增 11 个测试：CryptoService 5 个跨租户 + 1 个非存在 + 1 个响应等价字节比较 + 1 个 keystore 不被调用；KeyService 3 个跨租户 + 1 个非存在。
  （对应 P0-2）

### Known Limitations（本项目固有，不在本版本修复范围）

- gRPC over TLCP 未实现（TLCP 协议无 ALPN，gRPC 需要 h2）
- TLCP 证书链验证未集成（仅信任对端字节，等 gm-tlcp 上游 `TlcpCertPair` 接 `cert_verify`）
- SM9 主密钥默认存内存，无 HSM/TPM 强制（`kms-hsm` 仍为 stub）
- 无 bug bounty / 商业支持 / SLA

## [0.2.1] — Unreleased

### Dependencies — upstream `gm` workspace 0.3.0

- **`gm-tls` 0.1.0 → 0.2.0** (BREAKING upstream): `pub mod tlcp` removed from `gm-tls`. TLCP (GB/T 38636-2020) is now a separate `gm-tlcp` crate. gm-kms does **not** depend on `gm-tlcp` and only uses `TlsConfig` / `TlsAcceptor` / `GmTlsStream` / `grpc::GmTlsIncoming` / `TlsError` from `gm-tls`, all preserved unchanged. No source code changes required.
- **`gm-crypto` 0.1.0 → 0.2.0** (additive): 3 new APIs (`Sm4Cipher::encrypt_cbc_raw` / `decrypt_cbc_raw`, `x509::extract_sm2_pubkey_from_der`) used only by the new `gm-tlcp` crate. No breaking changes to the `Sm2KeyPair` / `Sm2Signer` / `Sm2Verifier` / `Sm2Encryptor` / `Sm2Decryptor` / `Sm3Hasher` / `Sm3Hmac` / `Sm4Cipher` APIs that gm-kms consumes.
- **`[patch.crates-io]`**: bumped from `rev = c0148032` to `rev = 37e1b21` (tag `gm-tls-v0.2.0`). Added `gm-sm9-rs` to the patch list to ensure all three crates (gm-ca, gm-crypto, gm-sm9-rs) resolve to the same git source, eliminating the dual-source type mismatch (E0308 on `Sm2KeyPair`) that previously surfaced in `cargo check --workspace --all-targets`. All direct `gm-crypto = "0.1.0"` deps bumped to `"0.2"` for the same reason.

### Fixed

- **`src/cmd/server.rs`**: pre-existing rustfmt drift in the `gm-tls` REST error message (`anyhow::bail!("TLS 1.3 + SM (gm-tls) ...")`) that had `cargo fmt --all -- --check` failing on CI since commit 8c06d24.
- **`CONTRIBUTING.md`**: clarified the dependency story — replaced the stale claim that gm-kms uses "versioned crates.io dependencies" with an accurate description of the crates.io + `[patch.crates-io]` hybrid strategy.

## [0.2.0] — 2026-08-27

### ⚠️ Breaking Changes

- **`kms-api::quota`**: `Result<_, ()>` → `Result<_, QuotaError>`. `TenantQuotaTracker::increment_key_count` / `decrement_key_count` / `get_usage` now return `Result<T, QuotaError>` instead of `Result<T, ()>`. Callers using `Match Err(())` (or `.unwrap_err()`) need to update to the new error type.
  - New type: `pub enum QuotaError { Exceeded(QuotaExceeded), Storage(String) }` with `Display` + `Error` impls.
  - This was triggered by `clippy::result_unit_err`; the `()` error carried no information and was unreachable to handle.
- **`kms-api::ratelimit`**: `TenantRateLimiter::get_usage` returns `Result<u64, RateLimitBackendError>` (new tuple struct) instead of `Result<u64, ()>`. Same reasoning as above.
  - The pre-existing `pub struct RateLimitError` (the HTTP-response body) is unchanged; the new type is named `RateLimitBackendError` to avoid collision.

### Security

- **h2 0.4.13 → 0.4.16** (RUSTSEC-2026-0258): fixes unbounded empty DATA frames DoS. Propagated via `tonic` → `tonic-prost`; `tonic` 0.14.5 accepts `h2 0.4.*`, no API break.

### Changed

- **`kms-api::metrics`**: `*count % 100 == 0` → `count.is_multiple_of(100)` (clippy::manual_is_multiple_of).
- **`kms-core::shamir`**: `original_len % block_size == 0` → `original_len.is_multiple_of(block_size)` (split PKCS#7 padding); `shares.len() % num_blocks != 0` → `!shares.len().is_multiple_of(num_blocks)` (reconstruction alignment check).
- **`src/cmd/config.rs`**: 11 nested `if let Ok(...) { if let Ok(...) { ... } }` collapsed to let-chains (`if let Ok(...) && let Ok(...) { ... }`) per clippy::collapsible_if. Env vars affected: `REST_PORT`, `GRPC_PORT`, `TLS_CERT_PATH`, `REST_TLS_CERT_PATH`, `TSA_TIMEOUT`, `TSA_INTERVAL`, `RATE_LIMIT_RPS`, `POSTGRES_PORT`, `BACKUP_RETENTION_COUNT`, `BACKUP_RETENTION_DAYS`, `BACKUP_KDF_ITERATIONS`.

### CI / Dev Tooling

- **`.github/dependabot.yml`**: tightened per SemVer discipline.
  - `open-pull-requests-limit`: 10 → 5 (cargo) / 3 (github-actions).
  - Added `cooldown`: patch 1 d / minor 4 d / major 14 d — wait for upstream fixes before opening PRs.
  - `rebase-strategy: disabled` — no silent force-push on already-opened PRs.
  - 4 new RustCrypto ecosystem groups (`rustcrypto-block-modes`, `rustcrypto-formats`, `rustcrypto-elliptic-curves`, `rustcrypto-hash`) to merge transitive upgrades into 1 PR per ecosystem instead of single-crate PRs.
  - 9 ignored dependencies (require explicit SemVer-major-style adaptation):
    `redis >= 1.x`, `tokio >= 2.x`, `x25519-dalek >= 3.x`, `curve25519-dalek >= 5.x`,
    `totp-rs >= 6.x`, `sqlx >= 0.9`, `toml >= 1.x`, `config >= 0.15`, `rdkafka >= 0.37`, `getrandom >= 0.3`.
  - Motivation: patch upgrades that pull transitive `cipher 0.4 → 0.5` (BlockEncrypt → BlockCipherEncrypt rename) are *real* breaking changes, not "low A-tier lockfile-only".

### Fixed

- **文档修正**：明确 TLCP (GB/T 38636-2020) 当前为参考实现，位于独立 `gm-tlcp` crate 中维护。gm-kms REST/gRPC 入口当前走 TLS 1.3 + SM ciphers（通过 `gm-tls` 实现）。同步更新 README.md / CONTRIBUTING.md / kms.toml.example / `src/cmd/gm_listener.rs` 中“gm-kms 部署 TLCP”的不实描述。“gm” backend 配置实际为 TLS 1.3 + SM ciphers，未接入 TLCP 协议。

## [0.1.0] — 2026-08-27

### Added

- **SM2/SM3/SM4/SM9** cryptographic algorithms via the `gm` workspace
- **[planned, 未实际部署]** TLCP (Transport Layer Cryptographic Protocol) with dual-certificate ECDHE handshake and SM4-CBC suite — 参考实现见 `gm-tlcp` crate（独立维护中）。
- **gRPC + REST dual API** with full feature parity (envelope encrypt/decrypt/rewrap, import/export, hash, DH derive, audit query)
- **PBAC** (Policy-Based Access Control) engine integrated across all handlers
- **SM9 key rotation** via `Sm9RotationAdapter` bridging `gm-sm9-rs` to gm-kms
- **SM9 key exchange** protocol (GM/T 0044.3-2016 §7) with mutual key confirmation
- **MFA** (TOTP) with PostgreSQL persistence and AES-256-GCM envelope encryption for secrets
- **WORM audit log** with hash-chained integrity, TSA timestamping, and Kafka streaming
- **Shamir secret sharing** with multi-block VSS commitments
- **DEK/KEK version binding** and rewrap-after-rotation
- **TLS/mTLS** support for REST, gRPC, Redis, and PostgreSQL connections
- **Rate limiting** and **tenant quota tracking** via Redis
- **KAT self-test** at startup (GB/T 37092-2018 §7.10)
- **Health check** endpoint with periodic background monitoring
- **SM2-KEX session management** with Redis shared sessions
- **TPM stub** backend (`RealTpmKeystore`) for future HSM integration

### Security

- gRPC API key authentication with mandatory auth interceptor
- Key export requires approval flow
- Tenant isolation enforcement in all services
- TOTP secrets encrypted with KEK (AES-256-GCM envelope), never stored in plaintext
- API key protection against enumeration timing attacks
- Audit log chain integrity verification
- Constant-time cryptographic primitives (conditional_select + delinearization)
- Memory protection (mlock available, core dump disabled)
- Old key material zeroized on rotation/deletion
- TLS production default enforced (disabled only in dev mode)

### Changed

- rand 0.8 → 0.10 migration across all crates
- `software.rs` split into module directory (mod.rs + tests.rs)
- Keystore backend `Default` impl removed for explicit initialization
- `ark-bn254` dead dependency removed
- `glob_match` trailing wildcard boundary bug fixed
- `repository.list()` tenant_id from `Option<&str>` to mandatory `&str`

### Documentation

- **Architecture document** (`ARCHITECTURE.md`) added — crate dependency graph, data flow diagrams, security design principles
- **PBAC coverage** extended to all 59 handlers (21 gRPC + 38 REST)
- **kms-audit** custom error types (`AuditError`/`AuditResult`) replace `anyhow` across all modules
- **Multiple audit false positives** confirmed and documented:
  - GmSSL FFI Drop: all FFI structs are plain value types, `SM9_SIGN_CTX` Drop already implemented
  - `from_raw_parts` ordering: `.to_vec()` before `free()` — correct and safe
  - `verify_chain` startup: method present but not called at startup (not a P1 issue)

## [0.1.0] — 2026-06-29

### Added

- **SM9 主密钥持久化 (F-1)**: PG 存储，AES-256-GCM 加密
- **SoftwareKeystore PG+Redis 持久化 (F-2)**: 双重后端
- **备份服务 (F-3)**: create_key best-effort 备份
- **delete_key 双人控制 (F-4)**: 新增 approval_id 字段
- **SM9 KAT 自检 (F-5)**: 签/验签 + 加解密往返测试
- **备份码哈希 (H-1)**: SHA-256 哈希化存储和对比
- **MFA-API Key 联动锁定 (H-2)**: Arc+Mutex + lock_key_by_id

### Changed

- **parking_lot 锁迁移**: 28 文件，+726/-328，全局替换 std::sync 锁
- **生产 unwrap() 清零**: 全部替换为 .expect()
- **kms-audit anyhow 迁移**: AuditError/AuditResult 全覆盖
- **ARCHITECTURE.md 依赖图修复**: 修正空箱和错误箭头，新增依赖验证表
- **README.md 测试统计修正**: kms-core 277→278，总计 957→958
- **sm2-kex-requirement.md 状态更新**: "已实现（部分）" → "已实现"
- **PBAC handler 计数修正**: 修正为 21 gRPC RPC + 38 REST handler（共 59）
