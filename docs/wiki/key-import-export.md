# Key Import/Export（密钥导入导出） / Key Import and Export

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 密钥管理 / Key Management |
| **实现位置** | `kms-core/key_io.rs` |
| **目的 Purpose** | 密钥迁移与备份 / Key migration and backup |


## 概述

密钥导入导出功能允许将密钥材料导入 KMS 或从 KMS 导出，支持多种格式以实现互操作性。

## 支持的格式 / Supported Formats

| 格式 Format | 说明 Description | 用途 Use Case |
|-----------|----------------|-------------|
| `Pkcs8` | PKCS#8 格式（默认）/ PKCS#8 format (default) | 通用私钥 / Generic private keys |
| `Jwk` | JSON Web Key | JSON 格式密钥 / JSON format keys |
| `Raw` | 原始二进制 / Raw binary | 同系统迁移 / Same-system migration |


## 导入流程

```
外部密钥
    ↓
传输加密（TLS + 临时传输密钥）
    ↓
格式验证
    ↓
密钥材料验证（算法、大小）
    ↓
存储加密（使用 KEK 加密）
    ↓
KMS 存储
```

## 实现机制

### 导入请求

```rust
use kms_core::key_io::{ImportKeyRequest, KeyFormat};

let request = ImportKeyRequest {
    name: "imported-key".to_string(),     // 密钥名称
    spec: "sm2".to_string(),              // 密钥规格
    format: KeyFormat::Pkcs8,            // 密钥格式
    wrapped_key: encrypted_key,            // Base64 编码的加密密钥材料
    encrypted_transport_key: enc_transport_key, // 加密后的传输密钥
    source_fingerprint: "sha256:...".to_string(), // 来源指纹
    tenant_id: "tenant-123".to_string(), // 租户 ID
};
```

### 导出请求

导出功能需要考虑安全限制，详见代码中的 `ExportKeyRequest` 定义。

## 传输密钥

导入导出使用临时传输密钥保护密钥材料：

```rust
// 传输密钥流程
// 1. 客户端请求传输密钥公钥
let transport_pubkey = client.get_transport_public_key().await?;

// 2. 用传输公钥加密密钥材料
let encrypted = sm2_encrypt(&key_material, &transport_pubkey)?;

// 3. 发送加密后的数据到 KMS
let response = client.import_key(encrypted).await?;

// 4. KMS 用传输私钥解密
```

## 安全考虑 / Security Considerations

| 考虑 Consideration | 实现 Implementation |
|-----------------|-------------------|
| 传输加密 / Transport Encryption | TLS + SM2 加密层 / TLS + SM2 encryption layer |
| 访问控制 / Access Control | API 层鉴权 / API-level authentication |
| 审计追溯 / Audit Trail | 所有导入导出记录审计 / All import/export operations audited |
| 密钥分离 / Key Separation | 不同用途使用不同密钥 / Different keys for different purposes |
| 内存安全 / Memory Safety | zeroize 清零 / Zeroize on drop |


## 与备份的区别 / Differences from Backup

| 特性 Feature | 导入/导出 Import/Export | 备份/恢复 Backup/Restore |
|-------------|------------------------|------------------------|
| 对象 / Object | 密钥材料 / Key material | 密钥材料 |
| 方向 / Direction | 外部 ↔ KMS / External ↔ KMS | KMS → 备份存储 / KMS → backup storage |
| 格式 / Format | 多格式支持 / Multi-format | KMS 内部格式 / Internal format |
| 加密 / Encryption | 传输加密 / Transport encryption | 备份密钥加密 / Master key encryption |
| 用途 / Purpose | 迁移、互操作 / Migration, interoperability | 灾难恢复 / Disaster recovery |


## 参考资料

- [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208) - PKCS#8
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) - JSON Web Key
