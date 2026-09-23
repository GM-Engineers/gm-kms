# N4: SM9 Key Generation Must Fail-Loud (P1-5)

> 创建 Created: 2026-09-23
> 状态 Status: ✅ 已实现（PR-4.5 / P1-5）
> 更新 Updated: 2026-09-23

## 需求 / Requirement

**English**: `SoftwareKeystore::generate_key(&KeySpec::Sm9Signing | Sm9Encryption, ...)` MUST return `Err(Error::NotImplemented)` instead of silently storing empty material. Pre-PR-4.5 the function returned `Ok(KeyMeta)` with `material: Vec::new()`, after which every subsequent SM9 operation (sign / encrypt / decrypt) would fail at runtime despite the API reporting successful key generation.

**中文**：`SoftwareKeystore::generate_key(&KeySpec::Sm9Signing | Sm9Encryption, ...)` 必须返回 `Err(Error::NotImplemented)`，而不是静默存入空 material。PR-4.5 之前函数返回 `Ok(KeyMeta)` 而 `material: Vec::new()`，导致后续任何 SM9 操作（签名 / 加密 / 解密）在运行时都会失败，尽管 API 表面上报"创建成功"。

## 安全需求 / Security Requirements

### N4.1 显式错误 / Explicit Error

- **NR4.1.1**: SM9 generate_key 路径必须返回 `Error::NotImplemented`，与 RSA 分支一致（line 700-704 of `software/mod.rs`）
- **NR4.1.2**: 错误消息必须包含 `SM9` 和显式说明，让调用方明确知道这是"未实现"而不是"运行时失败"
- **NR4.1.3**: 不能修改 RSA 分支的语义（保留作正面参照样例）

### N4.2 调用方一致 / Caller Consistency

- **NR4.2.1**: rotate 路径已经正确（line 1253-1262 返回 Error::KeyOperationNotAllowed，引用 Sm9RotationAdapter）；PR-4.5 不改变 rotate 路径
- **NR4.2.2**: 不破坏既有 `Sm9RotationAdapter` 路径（`kms-core/src/sm9_key_rotation.rs` 仍使用 rotate API）
- **NR4.2.3**: 其他 KeySpec（Aes256Gcm / Sm2 / Sm4 / EcdsaP256 / EcdsaP384 / Ed25519 / Ed448 / Rsa4096）的行为不变

## 验收标准 / Acceptance Criteria

- [x] `generate_key(Sm9Signing)` → `Err(Error::NotImplemented)`，错误消息包含 "SM9"
- [x] `generate_key(Sm9Encryption)` → `Err(Error::NotImplemented)`，错误消息包含 "SM9"
- [x] `generate_key(Rsa4096)` → 仍返回 `Err(Error::NotImplemented)`（回归保护）
- [x] `generate_key(Sm2)` → 仍返回 `Ok(KeyMeta)` 且 material 非空（回归保护）
- [x] rotate 路径行为不变（独立测试覆盖）

## 测试覆盖 / Test Coverage

`crates/kms-keystore/src/software/mod.rs::pr45_sm9_generate_tests` 新增 5 个单元测试：
- `pr45_sm9_signing_generate_returns_not_implemented`
- `pr45_sm9_encryption_generate_returns_not_implemented`
- `pr45_sm9_signing_error_message_mentions_sm9`
- `pr45_sm9_encryption_error_message_mentions_sm9`
- `pr45_rsa4096_generate_still_not_implemented`（回归保护）
- `pr45_sm2_generate_still_works`（回归保护）

## 实现说明 / Implementation Notes

### 关键代码位置

- [`crates/kms-keystore/src/software/mod.rs`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-keystore/src/software/mod.rs) — `generate_key()` 内 `KeySpec::Sm9Signing | KeySpec::Sm9Encryption` 分支从 `Vec::new()` 改为 `Err(Error::NotImplemented(...))`

### 设计决策

1. **为什么用 `NotImplemented` 而非 `KeyOperationNotAllowed`**：rotate 路径用 `KeyOperationNotAllowed` 是因为 SM9 旋转应该走 `Sm9RotationAdapter`。generate 路径**没有替代路径**（没有 rotate adapter 的对应物），所以用更基础的 `NotImplemented`，与 RSA 分支对称
2. **为什么不实际实现 SM9 主密钥派生**：gm-kms 仓库已有 `kms-core/src/sm9_master_key.rs`，但实际用户密钥派生需要 KMS-SM9 master key 管理（HSM / KMS 集成），这是单独议题。PR-4.5 只确保 API 不撒谎

### 已知限制

- `Error::NotImplemented` 不能区分"未实现"与"已实现但被禁用"——目前尚无 SM9 主密钥管理基础设施；待后续 PR 引入

## 关联 PR / Related PRs

- 触发：`gm与gm-kms源码级改进建议.md §6 / §7 P1-5`
- 实现：`PR-4.5`（本需求）

## 关联需求 / Related Requirements

- `N1-security.md`：租户隔离 / API 安全 / 输入验证
- `N2-tls-failfast.md`：KMS API listener TLS fail-fast
- `N3-db-redis-tls-defaults.md`：DB/Redis TLS production defaults
- `docs/requirements/sm2-kex-requirement.md`：SM2 密钥交换需求（提供完整 implemenation 范例）