# F1: Key Lifecycle Management / 密钥生命周期管理

> 创建 Created: 2026-04-28
> 状态 Status: ✅ 已实现 Implemented

## 需求 / Requirement

KMS 必须提供完整的密钥生命周期管理，包括生成、轮换、过期和销毁。

The KMS must provide complete key lifecycle management including generation, rotation, expiration, and destruction.

## 功能需求 / Functional Requirements

### F1.1 密钥生成 / Key Generation
- **FR1.1.1**: 系统必须按指定算法（AES-256-GCM、SM4、SM2、Ed25519 等）生成密码学密钥
- **FR1.1.2**: 生成的密钥必须以租户隔离方式安全存储
- **FR1.1.3**: 密钥元数据必须包含：唯一 ID、创建时间戳、算法、状态、版本

### F1.2 密钥轮换 / Key Rotation
- **FR1.2.1**: 系统必须支持密钥轮换（创建新版本）
- **FR1.2.2**: 废弃密钥必须保留用于解密历史密文
- **FR1.2.3**: 密钥轮换不得删除旧密钥材料（直到显式销毁）

### F1.3 密钥删除 / Key Deletion
- **FR1.3.1**: 系统必须支持软删除（标记为 PendingDeletion）
- **FR1.3.2**: 软删除的密钥在宽限期内可恢复
- **FR1.3.3**: 系统必须支持硬删除（永久销毁）
- **FR1.3.4**: 硬删除的密钥不可恢复

### F1.4 密钥状态机 / Key Status State Machine
```
Active → PendingDeletion → Obsolete → Destroyed
              ↓
         (recoverable)
```

## 验收标准 / Acceptance Criteria

- [x] ✅ 所有支持算法的密钥可正常生成 / Keys can be generated for all supported algorithms
- [x] ✅ 密钥轮换创建新版本（不删除旧密钥）/ Key rotation creates new version without deleting old key
- [x] ✅ 废弃密钥可解密历史密文（向后兼容）/ Obsolete keys can decrypt historical ciphertexts (backward compatibility)
- [x] ✅ 软删除保留密钥（可恢复）/ Soft delete preserves key for recovery
- [x] ✅ 硬删除永久移除密钥材料 / Hard delete permanently removes key material

## 测试覆盖 / Test Coverage

- `test_key_lifecycle_complete` - 集成测试：创建/加密/解密/轮换/删除
- `test_key_not_found` - 错误处理测试

## 实现说明 / Implementation Notes

- 密钥轮换实现于 `SoftwareKeystore::rotate_key()`
- 密钥状态机定义于 `crates/kms-core/src/key.rs`
- 废弃密钥向后兼容性通过 `KeyStatus::can_decrypt()` 保障（包含 Obsolete）
- Phase 2 (F-4)：`delete_key` 需审批（`approval_id` 字段）

