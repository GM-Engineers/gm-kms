# Key Backup / 密钥备份

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 密钥管理 / 灾难恢复 Key Management / Disaster Recovery |
| **实现位置 Implementation** | `crates/kms-core/src/backup.rs` |
| **S3 归档 S3 Archive** | `crates/kms-audit/src/s3_archive.rs` |
| **加密算法 Encryption** | SM4-GCM（主密钥加密）SM4-GCM (master key encryption) |
| **完整性校验 Integrity** | SM3 哈希 SM3 hash |
| **文件签名 File Signature** | SM3-HMAC |
| **接入场景 Integration** | `create_key` 时 best-effort 调用 best-effort call at `create_key` |

## 概述 / Overview

密钥备份服务（`KeyBackupService`）提供密钥材料的加密备份与恢复，支持本地文件存储和 S3 归档。Phase 2 (F-3) 将其接入 `create_key` 流程，在密钥创建时自动执行备份。

The `KeyBackupService` provides encrypted key material backup and restore with local file storage and S3 archival. Phase 2 (F-3) integrated it into the `create_key` flow for automatic backup on key creation.

## 备份架构 / Backup Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         KMS                                  │
│  ┌─────────────┐    ┌────────────────┐    ┌─────────────┐ │
│  │   Key       │───▶│  BackupService │───▶│  Storage     │ │
│  │   Material  │    │  (SM4-GCM 加密) │    │  (File/S3)   │ │
│  └─────────────┘    └───────┬────────┘    └─────────────┘ │
│                             │                              │
│                    ┌────────▼────────┐                      │
│                    │  Master Key     │                      │
│                    │  (主备份密钥)   │                      │
│                    └────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

## 核心类型 / Core Types

### KeyBackup — 备份条目结构 / Backup Entry Structure

```rust
pub struct KeyBackup {
    pub version: u32,                    // 备份格式版本 Backup format version
    pub key_meta: KeyMeta,               // 密钥元数据 Key metadata
    pub encrypted_material: Vec<u8>,     // SM4-GCM 密文（含 16 字节 tag）SM4-GCM ciphertext (includes 16-byte tag)
    pub nonce: Vec<u8>,                  // 12 字节 Nonce / IV  (NOT `iv`)
    pub material_hash: String,           // 原始材料 SM3 哈希（完整性校验）Original material SM3 hash (integrity check)
    pub backed_up_at: DateTime<Utc>,     // 备份时间戳 Backup timestamp
    pub description: Option<String>,      // 备份描述（可选）Optional backup description
}
```

> ⚠️ 注意：`iv` 字段已更名为 `nonce`（对应 SM4-GCM 标准术语）。/ Note: `iv` field renamed to `nonce` (standard SM4-GCM terminology).

### SignedBackup — 文件签名封装 / File Signature Envelope

```rust
pub struct SignedBackup {
    pub data: String,        // JSON 序列化的 KeyBackup / JSON-serialized KeyBackup
    pub signature: String,    // SM3-HMAC(hmac_key, data)，十六进制 / SM3-HMAC(hmac_key, data) in hex
}
```

### BackupConfig — 配置结构 / Configuration Structure

```rust
pub struct BackupConfig {
    pub enabled: bool,              // 启用备份 / Enable backup
    pub backup_path: String,        // 备份存储路径 / Backup storage path
    pub retention_count: u32,        // 每密钥最大保留数 / Max backups per key (default: 3)
    pub retention_days: u32,         // 保留天数 / Retention days (default: 365, NOT 2555)
    pub kdf_iterations: u32,         // 主密钥加密 KDF 迭代次数 / KDF iterations (default: 100_000)
}
```

## 实现机制 / Implementation

### 创建备份服务 / Creating Backup Service

```rust
use kms_core::backup::{KeyBackupService, BackupConfig, MasterKey};

// 方式一：使用已有主密钥 / Option 1: with existing master key
let master_key = MasterKey::generate()?;  // NOT MasterKey::new(material)
let config = BackupConfig {
    enabled: true,
    backup_path: "/var/kms/backup".to_string(),
    retention_count: 3,
    retention_days: 365,          // 1 年，不是 2555 天 / 1 year, NOT 2555 days
    kdf_iterations: 100_000,
};
let backup_service = KeyBackupService::new(config, master_key);

// 方式二：随机生成主密钥 / Option 2: with randomly generated master key
let backup_service = KeyBackupService::with_random_master_key(config)?;
```

### 备份密钥 / Backing Up a Key

```rust
// 备份密钥（SM4-GCM 加密 + SM3-HMAC 签名）
// Backup a key: SM4-GCM encryption + SM3-HMAC signing
let backup = backup_service.backup_key(
    &key_meta,               // 密钥元数据（内含 key_id）/ Key metadata (contains key_id)
    &key_material,           // 原始密钥材料 / Raw key material as byte slice
    Some("primary-backup".to_string()),  // 描述（可选）/ Optional description
)?;

// 返回 KeyBackup 元数据（签名文件自动写入磁盘）
// Returns KeyBackup metadata; signed backup file is written to disk automatically
println!("Backed up key {} at {}", backup.key_meta.id, backup.backed_up_at);
```

### 从备份恢复 / Restoring from Backup

```rust
// 从 KeyBackup 元数据恢复（验证 SM3 哈希完整性）
// Restore from KeyBackup metadata (verifies SM3 hash integrity)
let recovered_material = backup_service.restore_key(&backup)?;

// 从备份文件直接恢复（验证 HMAC 签名 + SM3 完整性）
// Restore directly from backup file (verifies HMAC signature + SM3 integrity)
let (backup_meta, recovered) = backup_service.restore_from_file(path)?;
assert_eq!(recovered, original_key_material);
```

### 列出与清理 / Listing and Cleanup

```rust
// 列出某密钥所有备份时间戳
// List all backup timestamps for a given key
let timestamps = backup_service.list_backups(&key_meta.id);
println!("Found {} backups for key {}", timestamps.len(), key_meta.id);

// 清理超过 retention_days 的旧备份
// Clean up backups older than retention_days
let cleaned = backup_service.cleanup_old_backups()?;
println!("Cleaned {} old backups", cleaned);
```

### S3 归档 / S3 Archive

```rust
use kms_audit::s3_archive::S3ArchiveClient;

// 配置 S3 归档客户端
// Configure S3 archive client
let s3_client = S3ArchiveClient::new(
    "s3://kms-backups".to_string(),
    "backup-key-id".to_string(),
);

// 归档备份文件（含签名验证）
// Archive backup file (with signature verification)
s3_client.archive(&backup).await?;

// 验证归档完整性
// Verify archive integrity
assert!(s3_client.verify(&backup).await?);
```

## gm-kms 中的集成 / Integration in gm-kms

Phase 2 在 `create_key` handler 中接入备份服务：

```rust
// crates/kms-api/src/grpc.rs 或 rest.rs
if let Some(bs) = &self.state.backup_service {
    // best-effort 备份，不阻断密钥创建
    // Best-effort backup; does not block key creation on failure
    if let Err(e) = bs.backup_key(&key_meta, &key_material, None).await {
        tracing::warn!("Key backup failed for {}: {}", key_meta.id, e);
    }
}
```

## 备份与导入/导出的区别 / Backup vs Import/Export

| 特性 Feature | 备份/恢复 Backup/Restore | 导入/导出 Import/Export |
|-------------|------------------------|----------------------|
| **格式 Format** | 内部加密格式 Internal encrypted format | 多格式（PKCS#8、JWK、raw）Multi-format |
| **方向 Direction** | KMS → 备份存储 KMS → backup storage | 外部 ↔ KMS External ↔ KMS |
| **加密 Encryption** | SM4-GCM 主密钥加密 SM4-GCM master key | 传输加密 Transport encryption |
| **用途 Purpose** | 灾难恢复 Disaster recovery | 迁移、互操作 Migration、interoperability |
| **触发 Trigger** | 自动（创建时）Automatic (at creation) | 手动 Manual |

## 合规对应 / Compliance Mapping

| 合规标准 Standard | 要求 Requirement | 实现 Implementation |
|-------------------|------------------|--------------------|
| 等保三级 GB/T 22239-2019 | 密钥备份 Key backup | ✅ `KeyBackupService` |
| JR/T 017-2020 | 加密备份 Encrypted backup | ✅ SM4-GCM + SM3-HMAC |
| PCI-DSS v4.0 | 密钥恢复程序 Key recovery procedure | ✅ 完整恢复流程 Complete restore flow |

## 参考资料 / References

- [NIST SP 800-57 Part 1 Rev.5](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) — Key Management
- GM/T 0044-2016 — SM9 IBE Algorithm (backup key hierarchy)
