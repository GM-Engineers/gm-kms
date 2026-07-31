# Changelog

All notable changes to gm-kms will be documented in this file.

## [0.1.0] — Unreleased

### Added

- **SM2/SM3/SM4/SM9** cryptographic algorithms via the `gm` workspace
- **TLCP** (Transport Layer Cryptographic Protocol) with dual-certificate ECDHE handshake and SM4-CBC suite
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
