# Software Keystore / 软件密钥存储

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 软件实现的密钥存储 / Software-implemented key storage |
| **实现位置 Implementation** | `crates/kms-keystore/src/software/mod.rs` |
| **安全性 Security** | 依赖进程内存安全和操作系统隔离 / Depends on OS process isolation and memory protection |
| **性能 Performance** | 高（无硬件延迟）High (no hardware latency) |
| **密钥存储 Key Storage** | 内存 HashMap（进程生命周期）/ In-memory HashMap (process lifetime) |
| **持久化 Persistence** | 可选 PostgreSQL + Redis（Phase 1 F-2）/ Optional PostgreSQL + Redis (Phase 1 F-2) |
| **备份 Backup** | `KeyBackupService` 接入 `create_key`（Phase 2 F-3）Integrated at `create_key` (Phase 2 F-3) |

## 概述 / Overview

gm-kms 的 `SoftwareKeystore` 是纯内存实现的密钥存储后端（Rust HashMap），密钥材料以加密形式保存在进程内存中，通过 AES-256-GCM 信封加密保护。Phase 1 (F-2) 将其扩展为支持 PostgreSQL 持久化和 Redis 缓存，Phase 2 (F-3) 接入备份服务。

gm-kms's `SoftwareKeystore` is a pure in-memory key storage backend (Rust HashMap). Key material is stored encrypted in process memory, protected by AES-256-GCM envelope encryption. Phase 1 (F-2) extended it with PostgreSQL persistence and Redis caching; Phase 2 (F-3) integrated the backup service.

## 核心结构 / Core Structure

```rust
// crates/kms-keystore/src/software/mod.rs
pub struct SoftwareKeystore {
    keys: RwLock<HashMap<Uuid, KeyEntry>>,                    // 内存密钥存储 In-memory key storage
    sm2_kex_sessions: RwLock<HashMap<Uuid, Sm2KexSessionEntry>>, // SM2-KEX 会话 SM2-KEX sessions
    revoked_sessions: RwLock<HashMap<Uuid, RevokedSessionEntry>>, // 已撤销会话防重放 Revoked sessions (anti-replay)
}
```

> 注意：`SoftwareKeystore` **不**直接持久化到文件系统。所有持久化通过 PostgreSQL（`PostgresKeystore`）或备份服务实现。
> Note: `SoftwareKeystore` does **NOT** persist directly to the filesystem. All persistence goes through PostgreSQL (`PostgresKeystore`) or the backup service.

## 密钥生命周期 / Key Lifecycle

```rust
use kms_keystore::SoftwareKeystore;

let ks = SoftwareKeystore::new();

// 创建密钥（触发 backup_key 最佳努力调用）
// Create key (triggers best-effort backup_key call)
let key_id = ks.create_key(algorithm, &key_meta).await?;

// 使用密钥（加密/解密/签名/验签）
// Use key (encrypt/decrypt/sign/verify)
let ciphertext = ks.encrypt(key_id, plaintext, aad).await?;

// 轮换密钥（保留旧版本用于历史密文解密）
// Rotate key (old version retained for historical ciphertext)
let new_version = ks.rotate_key(key_id, key_material).await?;

// 软删除（可恢复，PendingDeletion 状态）
// Soft delete (recoverable, PendingDeletion status)
ks.delete_key(key_id, approval_id).await?;  // F-4: delete_key requires approval

// 彻底销毁（不可恢复，Obsolete → Destroyed）
// Hard destroy (irrecoverable, Obsolete → Destroyed)
ks.destroy_key(key_id).await?;  // 必须先 soft delete / Must soft delete first
```

## 密钥状态机 / Key Status State Machine

```
Active ──(soft delete)──▶ PendingDeletion ──(recover)──▶ Active
                              │
                              └──(hard delete)──▶ Obsolete ──▶ Destroyed
```

- `Active`：正常可用 / Normal operation
- `PendingDeletion`：软删除状态，可恢复，**仍可解密** / Soft-deleted, recoverable, **still decrypts**
- `Obsolete`：已废弃但保留用于历史密文解密，**仍可解密** / Retained for historical ciphertext, **still decrypts**
- `Destroyed`：彻底销毁，不可恢复 / Permanently destroyed, irrecoverable

## 双后端架构 / Dual-Backend Architecture

gm-kms 支持两种 Keystore 后端：

| 后端 Backend | 持久化 Persistence | 适用场景 Use Case |
|-------------|-------------------|------------------|
| **SoftwareKeystore** | 无（内存）None (in-memory) | 开发测试 Development/testing |
| **PostgresKeystore** | PostgreSQL + Redis 缓存 | 生产环境 Production |

运行时根据数据库可用性自动切换：

```rust
// crates/kms-api/src/cmd/server.rs
let keystore: Arc<dyn KeystoreBackend> = if pool.is_some() {
    // 生产：PostgreSQL 持久化 + Redis 缓存
    Arc::new(PostgresKeystore::new(pool.clone(), redis.clone()))
} else {
    // 开发：无持久化回退
    Arc::new(SoftwareKeystore::new())
};
```

## SM2-KEX 会话管理 / SM2-KEX Session Management

```rust
use kms_keystore::{SoftwareKeystore, Sm2KexResult};

// 创建 SM2-KEX 会话（发起方）
// Create SM2-KEX session (initiator)
let session_id = ks.create_sm2_kex_session(tenant_id, key_id, initiator_id).await?;

// 处理对方消息
// Process peer message
let response = ks.accept_sm2_kex_session(&session_id, peer_message).await?;

// 获取协商结果
// Get key exchange result
let result: Sm2KexResult = ks.get_sm2_kex_result(&session_id).await?;

// 移除会话（完成后清理）
// Remove session (cleanup after completion)
ks.remove_sm2_kex_session(&session_id).await?;
```

## 备份接入 / Backup Integration

Phase 2 (F-3) 在 `create_key` handler 中接入 `KeyBackupService`：

```rust
// 在 kms-api gRPC/REST handlers 中 / In kms-api handlers
if let Some(bs) = &state.backup_service {
    // best-effort 备份，不阻断密钥创建
    // Best-effort backup; creation proceeds even if backup fails
    if let Err(e) = bs.backup_key(&key_meta, &key_material, Some(key_name)).await {
        tracing::warn!("Key backup failed for {}: {}", key_meta.id, e);
    }
}
```

## 与 HSM 对比 / Comparison with HSM

| 对比项 Criterion | SoftwareKeystore | HSM |
|----------------|-----------------|-----|
| **安全性 Security** | 中等（依赖 OS 安全）Medium (depends on OS) | 高（物理隔离，防篡改）High (physical isolation, tamper-resistant) |
| **性能 Performance** | 高（无硬件延迟）High (no hardware latency) | 中等（有限吞吐量）Medium (limited throughput) |
| **成本 Cost** | 低 Low | 高（数万至数百万元）High (¥10k-¥1M+) |
| **合规 Compliance** | 有限（通常需 L1/L2）Limited (L1/L2 usually required) | 强（符合 FIPS 140-2 L2+/L3）Strong (FIPS 140-2 L2+/L3) |
| **密钥生命周期 Key Lifecycle** | 灵活 Flexible | 受 HSM 限制 Limited by HSM |
| **适用场景 Use Case** | 通用应用 General applications | 金融、政府、高安全 Financial, government, high-security |

## 安全威胁与缓解 / Security Threats and Mitigations

| 威胁 Threat | 描述 Description | 缓解措施 Mitigation |
|-----------|-----------------|-------------------|
| **内存 Dump** | 进程内存被导出（core dump、调试器）/ Process memory dump | mlock 禁止换页 MLOCK to prevent paging; `memory_protection` 模块 |
| **冷启动攻击 Cold boot** | 断电后 DRAM 数据残留 / DRAM remnants after power loss | 内存加密、主密钥快速擦除 / Memory encryption, fast key erasure |
| **侧信道攻击 Side channel** | 密钥操作时序/功耗分析 / Timing/power analysis | 恒定时间实现（`conditional_select` + delinearization）|
| **交换文件泄露 Swap leak** | 密钥数据被换页到磁盘 / Key data paged to disk | MLOCK + RAMFS |
| **特权用户读取 Privilege escalation** | 特权用户读取进程内存 / Privileged user reads process memory | 独立 enclave（Intel SGX，待实现）；最小权限用户运行 |

## 软件密钥存储最佳实践 / Best Practices

1. **主密钥（KEK）保护**：使用 `memory_protection` 模块的 mlock + 核心转储禁用
2. **最小化密钥暴露**：密钥仅在需要时解密，敏感操作后立即 Zeroizing 清零
3. **进程隔离**：以最小权限用户运行密钥管理进程
4. **审计日志**：记录所有密钥访问操作（`KeyMaterialAccessed` 事件）
5. **定期轮换**：对存储密钥定期更新加密包装（`rotate_key`）
6. **生产环境使用 PostgresKeystore**：纯内存模式仅适用于开发测试
