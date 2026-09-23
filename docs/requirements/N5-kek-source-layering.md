# SPEC: PR-4.7 — gm-kms KEK 来源分层 (P1-7 阶段 1/3)

- **目标编号**：PR-4.7（Batch 4 — gm-kms 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §6 / §7 P1-7`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L121)：KEK 来源仅环境变量（gm-kms）
- **范围**：`crates/kms-core/src/kek_source.rs`（新）+ `crates/kms-keystore/src/postgres.rs` 重构 + `crates/kms-api/src/mfa.rs` 重构
- **影响面**：env-var-only 接口保留（向后兼容）；新增 `KMS_KEK_FILE` env 路径；DEV 模式随机 KEK 保留

---

## 1. 问题陈述

[`gm-kms/crates/kms-keystore/src/postgres.rs:83-112`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-keystore/src/postgres.rs#L83)：

```rust
fn load_or_generate_kek() -> Result<[u8; 32]> {
    if let Ok(kek_hex) = std::env::var("KMS_KEK") { /* hex decode */ }
    if std::env::var("KMS_DEV_MODE").as_deref() == Ok("1") { /* random + warn */ }
    std::process::exit(1);  // 生产硬退
}
```

`kms-api/src/mfa.rs:128-153` 重复实现：仅 env var 路径，无 DEV 随机 fallback。

后果：
- **进程环境暴露**：KEK 明文出现在 `/proc/<pid>/environ`，违背 zeroize 原则
- **运维摩擦**：把 32-byte 十六进制粘进 unit / systemd / docker-compose 易出错（多空格、换行、大小写）
- **与 kms-hsm 脱钩**：仓库已有 `kms-hsm/src/tpm.rs` + `real.rs` 但 KEK 没有走这条链路
- **代码重复**：postgres.rs 与 mfa.rs 各实现一份 env-var 解析

### 1.1 改进建议依据（master plan §6 / §7 P1-7）

> KEK 来源分层：env → 文件（0600）→ HSM provider 接口（对接 `kms-hsm`/TPM），并支持 KEK 轮换（旧 KEK 保留解密历史密文）。

PR-4.7 实现 **阶段 1/3**（env + 文件）。阶段 2（HSM）和阶段 3（KEK 轮换 + kek_label 持久化）后续 PR。

---

## 2. Fix 策略

### 2.1 新模块：`kms-core/src/kek_source.rs`

```rust
//! Key Encryption Key (KEK) source abstraction
//!
//! PR-4.7 / P1-7 (阶段 1/3): 支持从环境变量或文件加载 KEK。
//! 后续 PR (阶段 2/3) 引入 HSM provider 与 KEK 轮换。

use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KekSource {
    /// KMS_KEK env var (hex, 64 chars)
    Env,
    /// KMS_KEK_FILE env var (path to file containing 64 hex chars, 0600 perms)
    File(PathBuf),
    /// Neither env nor file set; caller decides (DEV-mode random or fail-hard)
    Missing,
}

#[derive(Debug, thiserror::Error)]
pub enum KekSourceError {
    #[error("KMS_KEK_FILE path {0:?} is not 0600 (got {1:o}); \
             refusing to read KEK from a world/group-readable file")]
    InsecureFileMode(PathBuf, u32),
    #[error("KMS_KEK_FILE path {0:?} not found")]
    FileNotFound(PathBuf),
    #[error("KMS_KEK must be 32 bytes (64 hex characters), got {0} bytes")]
    InvalidLength(usize),
    #[error("KMS_KEK hex decode failed: {0}")]
    InvalidHex(String),
}

impl KekSource {
    /// Detect from env: prefer File over Env when both set.
    pub fn from_env() -> Self {
        if let Ok(p) = std::env::var("KMS_KEK_FILE") {
            if !p.trim().is_empty() {
                return KekSource::File(PathBuf::from(p));
            }
        }
        if let Ok(v) = std::env::var("KMS_KEK") {
            if !v.trim().is_empty() {
                return KekSource::Env;
            }
        }
        KekSource::Missing
    }

    /// Resolve to 32-byte KEK (zeroized).
    pub fn load(&self) -> Result<Zeroizing<[u8; 32]>, KekSourceError> {
        match self {
            KekSource::Env => load_from_env_var("KMS_KEK"),
            KekSource::File(p) => load_from_file(p),
            KekSource::Missing => Err(KekSourceError::InvalidHex(
                "no KEK configured (set KMS_KEK or KMS_KEK_FILE)".to_string(),
            )),
        }
    }
}
```

### 2.2 重构 `postgres.rs::load_or_generate_kek`

```rust
fn load_or_generate_kek() -> Result<[u8; 32]> {
    let source = KekSource::from_env();
    match source.load() {
        Ok(kek) => Ok(*kek),  // Zeroizing -> [u8; 32] copy (already in Zeroizing ctx)
        Err(_) if std::env::var("KMS_DEV_MODE").as_deref() == Ok("1") => {
            tracing::warn!("KMS_KEK/KMS_KEK_FILE not set and KMS_DEV_MODE=1: \
                            generating a random KEK. DO NOT use this configuration in production.");
            let mut kek = [0u8; 32];
            use rand::Rng;
            rand::rng().fill_bytes(&mut kek);
            Ok(kek)
        }
        Err(e) => {
            eprintln!("ERROR: KEK source failed to load: {e}. Exiting.");
            std::process::exit(1);
        }
    }
}
```

### 2.3 重构 `mfa.rs::load_kek`

复用 `KekSource::File + Env`，去掉重复实现：

```rust
fn load_kek() -> Option<Zeroizing<[u8; 32]>> {
    match KekSource::from_env().load() {
        Ok(kek) => Some(kek),
        Err(e) => {
            tracing::error!("MFA KEK load failed: {e}");
            None
        }
    }
}
```

> 注：mfa.rs 当前的"未设置时降级到明文"语义保留：返回 `None` 后调用方写明文 + 警告。PR-4.7 不引入 fail-fast（mfa.rs 与 postgres.rs 的安全策略不同）。

### 2.4 文件模式校验

仅 Unix：

```rust
#[cfg(unix)]
fn assert_file_mode_0600(path: &Path) -> Result<(), KekSourceError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|_| KekSourceError::FileNotFound(path.to_path_buf()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(KekSourceError::InsecureFileMode(path.to_path_buf(), mode));
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_file_mode_0600(_path: &Path) -> Result<(), KekSourceError> {
    Ok(())  // Windows: 跳过权限检查（不在生产平台范围）
}
```

### 2.5 优先级 & 冲突

当 `KMS_KEK_FILE` 和 `KMS_KEK` **同时**设置：
- File 优先（更安全 — 文件权限受 OS 保护，env 受进程边界暴露）
- 在 startup 时 `tracing::warn!` 提示冲突，引导运维修正

### 2.6 版本

`kms-core`：patch bump（新增 pub API）。
`kms-keystore` / `kms-api`：patch bump（内部重构）。

---

## 3. Tests（`crates/kms-core/src/kek_source.rs::pr47_kek_source_tests`）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr47_kek_source_from_env_with_env_var` | 仅设 KMS_KEK → returns Env |
| T2 | `pr47_kek_source_from_env_with_file` | 仅设 KMS_KEK_FILE → returns File(path) |
| T3 | `pr47_kek_source_from_env_with_both_prefers_file` | 同时设 → File 优先 + warn |
| T4 | `pr47_kek_source_from_env_with_empty_file` | KMS_KEK_FILE="" → falls through to KMS_KEK |
| T5 | `pr47_kek_source_from_env_missing` | 两者未设 → returns Missing |
| T6 | `pr47_kek_source_env_load_valid_64_hex` | load() 返回 32 bytes |
| T7 | `pr47_kek_source_env_load_invalid_hex` | 非 hex → InvalidHex |
| T8 | `pr47_kek_source_env_load_wrong_length` | 短/长 → InvalidLength |
| T9 | `pr47_kek_source_file_load_valid_0600` | temp file 0600 → Ok |
| T10 | `pr47_kek_source_file_load_rejects_0644` | mode 0644 → InsecureFileMode |
| T11 | `pr47_kek_source_file_load_rejects_0666` | mode 0666 → InsecureFileMode |
| T12 | `pr47_kek_source_file_load_missing_path` | 不存在 → FileNotFound |
| T13 | `pr47_kek_source_file_load_empty_file` | 0 bytes → InvalidLength |
| T14 | `pr47_kek_source_load_returns_zeroizing` | 返回类型是 Zeroizing<[u8;32]> |
| T15 | `pr47_kek_source_env_var_name_override` | 未来扩展性：env var 名参数化（仅占位测试） |

注：env var 测试使用 `std::env::set_var/remove_var` + `Mutex<()>` 串行化（沿用 PR-4.1 模式）。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p kms-core --all-targets pr47_
cargo +1.88 test -p kms-keystore --all-targets
cargo +1.88 test -p kms-api --all-targets
```

CI 全套含 Security Audit / Build Docker / OWASP ZAP / Container Scan。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 现有部署仅设 KMS_KEK，未设 KMS_KEK_FILE | PR-4.7 保留 KMS_KEK env var 路径；T1 回归测试 |
| File 权限位检测在 macOS dev 环境（umask 影响） | 测试用 `OpenOptions::new().mode(0o600).create(true).open()` |
| Windows 平台无 mode bits | `#[cfg(unix)]` 守门，Windows 上跳过权限检查 |
| mfa.rs 行为变更 | 仅复用 `KekSource::load` 替代内联 hex 解析；外部行为不变（None on failure） |
| `std::env::set_var` 在多线程测试中 race | Mutex<()> 串行化所有 env-var 操作（PR-4.1 模式） |

---

## 6. Out of Scope（不在本 PR 范围）

- **阶段 2**：HSM / TPM provider（kms-hsm::SimulatedTpmKeystore / RealTpmKeystore 作为 KekSource 实现）
- **阶段 3**：KEK 轮换（需要在 ciphertext 中持久化 kek_label；需要 schema 迁移）
- 任何对 DEK (per-key material) 加密格式的变更
- 对 KMS_ALLOW_INSECURE / KMS_DEV_MODE 行为本身的修改

---

## 7. 后续 PR 候选

- **PR-4.8**：gm-kms KEK HSM provider 阶段 2/3（kms-hsm::SimulatedTpmKeystore / RealTpmKeystore 作为 KekSource 实现）
- **PR-4.9**：gm-kms KEK 轮换（kek_label 在 ciphertext 中持久化；schema 迁移；多 active KEK）
- **PR-4.10**：gm-ca URI SAN 透传 (P1-8 ★SPIRE 刚需)
- **PR-4.11**：gm-ca 小时级 TTL (P1-9 ★SPIRE 刚需)