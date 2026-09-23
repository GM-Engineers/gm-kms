# SPEC: PR-4.11 — gm-kms WORM audit HMAC 密钥路径独立化 (P2-6)

- **目标编号**：PR-4.11（Batch 4 — gm-kms 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-6`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L150)：审计 HMAC 签名密钥与日志同目录
- **范围**：`crates/kms-audit/src/worm_logger.rs` 的 `WormSignedAuditConfig` 增加可配置的 signing-key 路径
- **影响面**：纯增量（默认行为兼容）；操作员可通过 `with_signing_key_path()` 将密钥独立部署

---

## 1. 问题陈述

[`gm-kms/crates/kms-audit/src/worm_logger.rs:25-27`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-audit/src/worm_logger.rs#L25)：

```rust
fn signing_key_path(worm_path: &Path) -> PathBuf {
    worm_path.with_extension("signing_key")
}
```

后果：
- **密钥与日志同目录**：默认部署下，审计 HMAC 密钥文件 `<worm_path>.signing_key` 与 WORM 日志在同一目录
- **攻击面叠加**：进程被攻陷 → 攻击者可同时写 WORM 日志 + 替换/重签密钥 → 哈希链校验通过 → **审计完整性失效**
- WORM 只防 append-only 防删除，不防密钥文件被替换
- 现实部署中，audit dir 通常是 NFS / 共享存储，密钥与日志必须分盘

### 1.1 改进建议依据（master plan §四 P2-6）

> `gm-kms/crates/kms-audit/src/worm_logger.rs:25-27` | 审计 HMAC 签名密钥与日志同目录（`with_extension("signing_key")`），建议密钥独立路径/权限或接入 KEK 管理，并文档说明 WORM 的信任边界

PR-4.11 解决**独立路径 / 权限**部分（KEK 接入留作后续 PR）。

---

## 2. Fix 策略

### 2.1 配置层：`with_signing_key_path(PathBuf)`

```rust
pub struct WormSignedAuditConfig {
    pub signed: SignedAuditConfig,
    pub worm_path: PathBuf,
    pub rotation_age_secs: u64,
    /// PR-4.11 / P2-6: signing-key path is now configurable.
    /// `None` preserves pre-4.11 behavior (sibling file at
    /// `<worm_path>.signing_key`); `Some(p)` stores the key at `p`,
    /// which SHOULD be on a separate filesystem from `worm_path`.
    signing_key_path: Option<PathBuf>,
}

impl WormSignedAuditConfig {
    pub fn with_signing_key_path(mut self, p: PathBuf) -> Self {
        self.signing_key_path = Some(p);
        self
    }
}
```

### 2.2 解析层：effective path helper

```rust
fn effective_signing_key_path(&self) -> PathBuf {
    self.signing_key_path
        .clone()
        .unwrap_or_else(|| self.worm_path.with_extension("signing_key"))
}
```

### 2.3 文件权限保持 0o600（已有）

`load_or_generate_key` 在 Unix 下写文件时调用 `set_permissions(0o600)`。PR-4.11 不变更该行为 — 即使密钥部署到独立路径，权限仍然 0600。

### 2.4 WORM 信任边界文档

新增 docstring 段落说明：
- WORM 防 append-only 防删除（OS-level file system layer）
- WORM 不防密钥替换（密钥文件不在 WORM 约束内）
- 推荐部署：日志 dir 与密钥 dir 分盘分账户；密钥 dir 0600 + ACL 限制为 KMS process UID
- PR-4.11 让操作员通过 `with_signing_key_path()` 实现该分离

### 2.5 向后兼容

- 默认行为（无 `with_signing_key_path` 调用）：签名密钥仍在 `<worm_path>.signing_key`（与 PR-4.11 前完全一致）
- 现有测试 + 配置示例不需要任何修改
- `WormSignedAuditConfig` 字段是 **private** (`signing_key_path: Option<PathBuf>`)，外部 caller 通过 `with_signing_key_path` 访问 —— 不破坏现有 struct literal 构造

### 2.6 KEK 集成（out of scope）

PR-4.11 **不**实现 KMS_KEK / KMS_KEK_FILE 接入（PR-4.7 的 `KekSource` 在 `kms-core`，`kms-audit` 是另一个 crate，跨 crate dep 涉及重构）。留作后续 PR：
- PR-4.12：kms-audit 接受 `Option<KekSource>` 让 HMAC 密钥由 KMS 主 KEK 派生/包裹

---

## 3. Tests（`crates/kms-audit/src/worm_logger.rs::pr411_signing_key_isolation_tests`）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr411_default_signing_key_path_is_sibling` | 不调 `with_signing_key_path`；`effective_signing_key_path()` = `<worm_path>.signing_key` |
| T2 | `pr411_with_signing_key_path_overrides` | 调 `with_signing_key_path("/var/lib/kms/keys/audit.hmac")`；`effective_signing_key_path()` = 该路径 |
| T3 | `pr411_separate_key_path_creates_file` | 真实 tmp dir 测试：WORM dir = `/tmp/a/audit`；key path = `/tmp/b/keys/hmac`；`load_or_create` 后 key 在 `/tmp/b/keys/hmac` 而非 `/tmp/a/audit.signing_key` |
| T4 | `pr411_signing_key_file_is_0o600_on_unix` | 真实创建后检查 `mode & 0o777 == 0o600` |
| T5 | `pr411_existing_key_at_custom_path_is_loaded` | 预写一个 32-byte key 到自定义路径；`load_or_create` 加载它而非生成新 key |
| T6 | `pr411_load_or_create_failure_when_path_dir_unwritable` | key path 指向只读目录 → Err(AuditError::Io) |

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy -p kms-audit --all-targets -- -D warnings
cargo +1.88 test -p kms-audit --all-targets pr411_
cargo +1.88 test -p kms-audit --all-targets    # 全量回归
cargo +1.88 test -p kms-core -p kms-keystore --all-targets    # 邻接 crate 回归
```

CI 含 Security Audit / Build Docker / OWASP ZAP / Container Security Scan。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 操作员部署疏忽（仍用 sibling path） | DEFAULT 行为兼容；同时 docstring 强烈推荐独立路径 |
| 现有 `with_extension("signing_key")` 行为变更 | 不变更默认；新 opt-in |
| KEK 集成跨 crate 重构 | 单独 PR（PR-4.12） |

---

## 6. Out of Scope

- KMS_KEK / KMS_KEK_FILE 接入（PR-4.12 计划）
- WORM 密钥轮换 / KMS-side key wrapping（更深入议题）
- 任何对 worm_logger 现有签名逻辑的修改

---

## 7. 后续 PR 候选

- **PR-4.12**：kms-audit 接受 `KekSource` 派生/包裹 HMAC 密钥（跨 crate 集成）
- **PR-4.13**：gm-tls CRL grace period + session cache persistence
- **PR-4.14**：gm-crypto SM2 private key [1, n-1] 范围校验 (P2-9)
