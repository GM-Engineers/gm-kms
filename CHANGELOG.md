# Changelog

All notable changes to gm-kms will be documented in this file.

## [0.3.0] — Unreleased

### Added

- **Opt-in background preload via `PostgresKeystore::spawn_load_keys()`** (PR-4.19 / PR-4.17 follow-up): new method returns a `tokio::task::JoinHandle<Result<usize>>` so callers can decouple startup blocking from DB preload. Pre-PR-4.19 callers used `await pg_keystore.load_keys()` which blocked the gRPC/HTTP listener by 5–10 seconds for 10k keys (O(N) DB queries + KEK decrypt × N). Post-PR-4.19 the server's `create_software_keystore` and `create_software_keystore_inner` helpers fire the preload in a background task and return immediately; PR-4.17's lazy-load covers any keys not yet cached when the first request lands. Internal refactor: extracted `decrypt_material_static(kek, key_id, encrypted)` from `decrypt_material` so the spawned task can decrypt without a `&self` borrow; added shared `load_one_into_cache` helper used by both sync (`load_keys`) and async (`spawn_load_keys`) paths. `PostgresKeyRepository` now derives `Clone` so the spawned task can take its own handle to the `sqlx::PgPool` (Arc-backed; zero-cost clone). Four new tests: 3 unit tests verifying the helper's type shape and early-return error path; 1 `#[ignore]` live-DB integration test verifying that sync and background preload agree on key count. Bumps the workspace to 0.2.7 (patch; new API, no breakage).

- **`PostgresKeystore` cache-miss lazy load** (PR-4.17 /
  PR-4.15 follow-up): `verify_tenant` now falls back to a
  DB round-trip via the new `load_entry_from_db` helper
  when the bounded in-memory cache misses. Before PR-4.17,
  keys beyond `with_in_memory_cap(n)` were silently
  unreachable (only the first `n` keys loaded at startup
  worked). After PR-4.17 the cap controls **memory
  usage**, not **key access** — keys beyond the cap are
  pulled in on first use and cached via
  `BoundedKeyCache::insert_with_eviction` (which honours
  the FIFO cap automatically). Tenant isolation
  (PR-1.2 conflation) is preserved: lazy-load + wrong
  tenant still returns `Error::KeyNotFound`. KEK-rotation
  failures during lazy load are surfaced as
  `Error::Internal` with a loud comment pointing operators
  at the rotation. Four new tests: 3 live-DB `#[ignore]`
  integration tests (`pr417_lazy_load_*`) cover
  cap-beyond / unknown-id / wrong-tenant scenarios; 1 unit
  smoke test (`pr417_helper_is_inherent_method`) verifies
  the helper is reachable via inherent impl (no public
  API change). Bumps the workspace to 0.2.6 (patch; no
  API change).

- **PostgreSQL keystore in-memory cap + FIFO eviction**
  (PR-4.15 / P2-10): pre-PR-4.15, `PostgresKeystore.keys`
  was an unbounded `RwLock<HashMap<Uuid, KeyEntry>>` with no
  cap and no eviction policy. Production deployments with
  thousands of keys would consume hundreds of MB of RAM for
  material that was rarely (if ever) accessed again. PR-4.15
  introduces:
  - New `kms-keystore::bounded_cache::BoundedKeyCache`
    type: FIFO eviction via `VecDeque<Uuid>`, optional
    `capacity: Option<usize>`. Default `None` reproduces
    pre-PR-4.15 behavior byte-for-byte.
  - `PostgresKeystore::with_in_memory_cap(n)` builder
    opting the keystore into the cap. The cap is enforced
    on every `insert_with_eviction` call (which now
    replaces all 11 `keys.write().insert(...)` sites).
  - Six new mutating helpers (`mutate`,
    `mutate_and_insert`, `remove`, `try_read`, etc.) replace
    the old `keys.read()` / `keys.write()` lock ceremony
    with a more ergonomic async-free API.
  - 8 new unit tests in `pr415_*` covering unbounded,
    cap-respecting, bulk-eviction, and re-insertion
    edge cases.
  - Bumps workspace version to 0.2.5 (patch; default
    behavior unchanged).
  True lazy load (replacing eager `load_keys()`) is
  deferred to a follow-up PR; this PR caps the eager
  load to `take(cap)` entries.

- **SM2 private scalar range validation** (PR-4.14 / P2-9): new
  `kms_core::sm2_scalar` module with `sm2_scalar_in_range()`
  helper that checks a candidate 32-byte SM2 private key is
  in `[1, n-1]` per GB/T 32918.1-2016 §5.1.4. Pre-PR-4.14
  the software keystore's `generate_sm2_key()` generated raw
  32 random bytes without range validation, exposing a
  (theoretical) attack surface against upstream scalar
  generation. PR-4.14 routes SM2 key generation through the
  canonical `Sm2KeyPair::generate()` path (which already
  enforces `[1, n-1]` via rustcrypto `SecretKey::random`)
  and adds a defense-in-depth `sm2_scalar_in_range` re-check.
  New `KmsError::InvalidSm2Scalar(String)` variant surfaces
  any future upstream regression as a typed error. The
  `SM2_CURVE_ORDER_N` constant is exported and locked by a
  unit test that compares against the GB/T 32918.1-2016
  reference value. Nine new unit tests in
  `pr414_sm2_scalar_tests` cover the boundary conditions
  (accept 1, accept n-1, reject 0, reject n, reject n+1,
  reject wrong lengths, reject MSB-overflow). Bumps
  workspace version to 0.2.4 (patch; new public surface is
  additive).

- **WORM audit HMAC signing-key path isolation** (PR-4.11 / P2-6):
  the WORM-backed signed-audit logger (`kms-audit::worm_logger`)
  now allows operators to store the HMAC signing key at a path
  separate from the WORM log. Pre-PR-4.11, the key was a sibling
  file (`<worm_path>.signing_key`); a compromised process could
  replace both the log AND the key, defeating WORM's integrity
  guarantee. PR-4.11 adds:
  - `WormSignedAuditConfig::with_signing_key_path(PathBuf)`
    builder;
  - `WormSignedAuditConfig::load_or_create_with_key_path(
    worm_path, key_path, seq)` factory;
  - `WormSignedAuditConfig::effective_signing_key_path()`
    accessor (single source of truth);
  - the `signing_key_path: Option<PathBuf>` field on the config
    struct (`None` preserves pre-PR-4.11 sibling-path behavior).
  Six unit tests in `pr411_signing_key_isolation_tests` cover
  default-behavior preservation, custom-path override, 0600
  enforcement, and existing-key loading. KEK integration
  (`KekSource` wrapping the HMAC key) is deferred to PR-4.12
  to keep this PR within kms-audit crate only.

- **KEK source layering** (PR-4.7 / P1-7 阶段 1/3): new
  `kms_core::kek_source` module with `KekSource` enum (Env / File
  / Missing). Operators can now load the master KEK from either
  `KMS_KEK` (env var, hex) or `KMS_KEK_FILE` (path to a file with
  mode 0600 on Unix; the mode bit is enforced and any other mode
  is rejected with a clear error). File beats env when both are
  set (file is more secure). Replaces the inline hex-parsing in
  `kms-keystore::postgres` and `kms-api::mfa`, removing duplication.
  HSM / TPM provider integration is scoped for PR-4.8;
  KEK rotation (kek_label persistence + multi-active-KEK) is scoped
  for PR-4.9. Added 17 unit tests in `pr47_kek_source_tests`.

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
- **`crates/kms-keystore/src/software/mod.rs` + `crates/kms-keystore/src/postgres.rs`**：P0-3 修复 keystore trait 层 `_tenant_id` 参数被忽略的纵深防御漏洞。
  旧实现所有 sensitive 方法（`encrypt` / `decrypt` / `sign` / `verify` / `rotate_key` / `delete_key` / `export_key_material` / `get_key_material` / `get_key_material_version`）的 `_tenant_id` 参数均被下划线开头直接忽略——若新增调用方（REST/gRPC handler、CLI、运维脚本、内部 task）绕过 PR-1.2 上层校验直接调用 keystore，将导致跨租户越权访问。
  新增私有 `verify_tenant(key_id, tenant_id) -> Result<()>` helper：调 `get_key_metadata` 取元数据并比对 `tenant_id`，不匹配返回 `Error::KeyNotFound(key_id)`（与 PR-1.2 上层一致：missing 与 wrong-tenant 不可区分）。每个 sensitive 方法首行调用 `verify_tenant`；参数 `_tenant_id` → `tenant_id`（已实际使用，不再是 placeholder）。`generate_key` / `import_key_material` / `destroy_key*` 不需要校验（前者创建者即租户；后者 trait 当前无 tenant 参数）。
  新增 12 个测试：9 个跨租户返回 `KeyNotFound`（sign / decrypt / encrypt / verify / export_key_material / get_key_material / get_key_material_version / rotate_key / delete_key）+ 3 个正向不破坏（Ed25519 / SM2 sign/verify、AES encrypt/decrypt）。
  （对应 P0-3）

- **AAD 绑定到 `(key_id, tenant_id, version)`（P0-5 / PR-1.4）**：AES-GCM / SM4-GCM 用户数据加密以及 Postgres KEK 信封、KeyService 导出信封都绑定稳定上下文后，AGC 标签检查必须失败—记帐 AAD blob 。 
  旧实现 `seal_in_place_separate_tag` 传入 `Aad::empty()`：对于攻击者可以互换持久化存储行的场景，同一租户的合法 `decrypt(key_b)` 调用可能被递给 key-a 的密文。 
  新增 `crates/kms-core/src/aad.rs`：`Purpose` 枚举区分 `UserData` / `KekWrap` / `ExportWrap`； 42 字节 v2 AAD 格式 = magic(2) + aad_version(2) + purpose(2) + key_id(16) + SHA-256(tenant)[..16] + version(4)。三个公开构造器：`user_data_aad`、`kek_wrap_aad`、`export_wrap_aad`，以及 9 个 aad.rs 单元测试。 
  wire 格式向后兼容：`Ciphertext::format_version ∈ {0, 1}` 走 empty-AAD 分支；`format_version == 2` 走绑定-AAD 分支；未知 format_version 返回 `Error::InvalidCiphertext`。  五个调用点改动：
  - `crates/kms-keystore/src/software/mod.rs`：`encrypt`（AES / SM4 两个分支） 使用 `user_data_aad(*key_id, &entry.meta.tenant_id, entry.meta.version)`，输出 `format_version = 2`；`decrypt` 两 个分支按 `format_version` 分流。
  - `crates/kms-keystore/src/postgres.rs`：四个调用点（load_keys、generate_key、rotate_key 的 encrypted_dek、import_key_material）传 `key_id: &Uuid` 给 `encrypt_material` / `decrypt_material`，信封 AAD  为 `kek_wrap_aad(*key_id)`；`crypto_encrypt` / `crypto_decrypt` 加 `tenant_id: &str` 参数以使用 `user_data_aad`。SM2 分支不变（SM2 是公钥加密，无 AEAD-AAD）。
  - `crates/kms-api/src/service/key_service.rs`：导出信封使用 `export_wrap_aad(*key_id, tenant_id)` 替代 `Aad::empty()`。
  - `crates/kms-core/src/lib.rs`：增加 `pub mod aad` 及再导出。
  新增 8 个回归测试：AES/SM4 往返 、AES/SM4 跨 key 复制拒绝、跨 version 伪造拒绝、`format_version ∈ {0, 1}` 向后兼容、未知 format_version 拒绝、跨租户 AAD 发散验证。  跨租户 AES-GCM “零 AAD” 场景（与 PR-1.2 / PR-1.3 形成纵深防御：即使上层漏检，标签不匹配也拒绝）。
  （对应 P0-5）

### Security

- **SM9 key generation no longer reports success on empty material**（PR-4.5 / P1-5）。PR-4.5 之前 `SoftwareKeystore::generate_key(Sm9Signing | Sm9Encryption)` 静默返回 `Ok(KeyMeta)` 且 `material: Vec::new()`；后续所有 SM9 加解密调用都会在运行时失败，但 API 表面上报“创建成功”。PR-4.5 改为 `Err(Error::NotImplemented)`，与 RSA-4096 分支对称；rotate 路径仍保留原有的 `Error::KeyOperationNotAllowed` + Sm9RotationAdapter 提示。
- 新增 4 个 `pr45_sm9_generate_tests` 单元测试（SM9 signing / encryption 返回 NotImplemented，RSA-4096 不变，SM2 仍正常）；并删除依赖该错误行为的旧 `test_sm9_direct_keystore_rotation_errors` 测试（该路径已无法从公开 API 到达）。
- 新增双语需求文档 `docs/requirements/N4-sm9-generate-not-implemented.md` 登记在 requirements 索引。

### Security (PR-4.4 / P1-4)

- **DB / Redis TLS production-safety fail-fast**（PR-4.4 / P1-4）。`BackendTlsConfig::from_env` 由 `Self` 改为 `anyhow::Result<Self>`，三重生产安全门：
  - `KMS_DB_TLS_MODE=no_verify` 在生产环境 fail-fast（不加 `KMS_DEV_MODE=1` / `KMS_ALLOW_INSECURE=1`）—— MITM 攻击者可伪造证书
  - `KMS_DB_TLS_MODE=disabled` 在生产环境 fail-fast——明文数据库流量
  - `verify_ca` 模式要求 `KMS_DB_TLS_CA_CERT` 非空；否则启动期拒绝（不等首连接才失败）
  - 复用 PR-4.1 的 `kms_core::production_safety::is_insecure_opted_in()` helper
- `src/cmd/server.rs` 与 `crates/kms-keystore/src/{repository,rate_limiter}.rs` 的 4 个 caller 同步升级为 `unwrap_or_else(|e| std::process::exit(1))` 以保证 fail-fast 契约。
- 新增 14 个 `pr44_db_tls_defaults_tests` 单元测试覆盖所有分支（默认 / disabled / no_verify / 大小写 / 空路径 / opt-in）。
- 新增双语需求文档 `docs/requirements/N3-db-redis-tls-defaults.md` 登记在 requirements 索引。
- 现有 296 个 kms-core + 94 个 kms-keystore 单元测试继续通过。

### Security (PR-4.1 / P1-3)

- **`src/cmd/server.rs`：gRPC / REST 生产启动 TLS fail-fast**（PR-4.1 / P1-3）。仿照 KEK fail-fast 模式（`kms-keystore/src/postgres.rs:92-95`），默认启动需 TLS；仅 `KMS_ALLOW_INSECURE=1`（或测试 `KMS_DEV_MODE=1`）明确放行才使用明文。REST 两个分支（`rest_tls_config = None` 与 `rest_tls.enabled = false`）独立报错。
- 新增 `kms_core::production_safety` 模块：`is_allow_insecure()`、`is_dev_mode()`、`is_insecure_opted_in()` 三个 helper；值严格为字符串 `"1"`，避免 `"true"`/`"yes"` 误选。
- `cmd/server.rs` 拆出 `pub(crate) fn grpc_tls_failfast_message` 与 `pub(crate) fn rest_tls_failfast_message` 两个可测试 helper，避免 `cmd::server::run` 启动逻辑集成测试成本。
- 新增 12 个 PR-4.1 单元测试（`kms-core/production_safety.rs` 5 个 + `cmd/server.rs::pr41_failfast_tests` 7 个），覆盖所有 helper 分支与 REST 两条互斥错误消息。
- 新增 `discuss/40-pr-4-1-spec.md` 完整 SPEC。

### Known Limitations（本项目固有，不在本版本修复范围）

- gRPC over TLCP 未实现（TLCP 协议无 ALPN，gRPC 需要 h2）
- TLCP 证书链验证未集成（仅信任对端字节，等 gm-tlcp 上游 `TlcpCertPair` 接 `cert_verify`）
- SM9 主密钥默认存内存，无 HSM/TPM 强制（`kms-hsm` 仍为 stub）
- 无 bug bounty / 商业支持 / SLA

## [0.2.1] — 2026-09-05

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

Initial public release.

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

## [Pre-0.1.0 development] — 2026-06-29

Pre-release development snapshots folded into 0.1.0. Listed here for
audit-trail purposes only; these items are NOT part of any published
release and predate the v0.1.0 tag (18b32a3, 2026-08-27).

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
