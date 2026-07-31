# Envelope Encryption / 信封加密

> 上次更新：2026-06-29

## 基本信息

| 字段 | 值 |
|------|------|
| **全称** | Envelope Encryption |
| **类型** | 加密架构模式 |
| **核心思想** | 用密钥加密密钥（KEK 加密 DEK）的两层加密 / Two-layer encryption: DEK encrypted by KEK |
| **典型应用** | AWS KMS、Google Cloud KMS、Azure Key Vault |
| **实现位置** | `crates/kms-core/src/envelope.rs` + `crates/kms-api/src/service/envelope_service.rs` |

## 概述

信封加密是一种两级加密架构：
1. **DEK（Data Encryption Key）**：直接用于加密数据的密钥
2. **KEK（Key Encryption Key）**：用于加密 DEK 的上层密钥

```
 plaintext ──▶ DEK 加密 ──▶ ciphertext
                    ▲
                    │
               DEK 被 KEK 加密
                    ▲
                    │
                  KEK（主密钥）
```

由于 DEK 不需要离开存储介质，只需将加密后的 DEK 与 ciphertext 一起存储，大大降低了密钥泄露风险。

## 工作流程

### 加密过程

```
1. 生成 DEK（数据加密密钥，GM/SM3 HMAC_DRBG）
2. 使用 DEK 加密数据 → 得到 ciphertext + tag
3. 使用 KEK 加密 DEK → 得到 wrapped DEK + dek_nonce
4. 存储：（wrapped DEK + dek_nonce + ciphertext + data_nonce + tag）
```

### 解密过程

```
1. 获取 wrapped DEK
2. 使用 KEK 解密 DEK → 得到明文 DEK
3. 使用 DEK 解密 ciphertext → 得到 plaintext
4. 销毁明文 DEK（内存中 zeroize）
```

## 在 KMS 中的应用

| 场景 Scenario | 说明 Description |
|------|------|
| **文件加密** / File Encryption | 每个文件使用唯一 DEK，DEK 由 KMS 管理 / Each file uses unique DEK managed by KMS |
| **数据库字段加密** / DB Field Encryption | 列级加密，DEK 存储在 KMS / Column-level encryption with DEK stored in KMS |
| **消息加密** / Message Encryption | 端到端加密，DEK 包装在消息头中 / End-to-end encryption with DEK wrapped in message header |
| **多租户隔离** / Multi-tenant Isolation | 每个租户使用不同 KEK / Each tenant uses different KEK |

### Rust 实现示例

```rust
use kms_core::envelope::{Envelope, EnvelopeConfig, generate_dek, generate_nonce};

// 构建信封加密结果
// Envelope 结构体包含：wrapped_dek, dek_nonce, ciphertext, data_nonce, tag, kek_version
let envelope = Envelope::new(
    wrapped_dek,   // Vec<u8>: KEK 加密后的 DEK
    dek_nonce,     // Vec<u8>: DEK 加密用的 nonce
    ciphertext,    // Vec<u8>: DEK 加密后的密文
    data_nonce,    // Vec<u8>: 数据加密用的 nonce
    tag,           // Vec<u8>: AEAD 完整性校验码
    kek_version,   // u32: KEK 版本号
);

// 所有字段均为 base64 编码的 String（Envelope 内部自动编码）

// 通过 envelope service 进行加密（REST API /v1/keys/{id}/envelope-encrypt）
// 服务内部：
//   1. generate_dek(32) 生成 32 字节 DEK（SM3 HMAC_DRBG）
//   2. 用 DEK + AES-256-GCM 加密 plaintext
//   3. 用 KEK + AES-256-GCM 加密 DEK
//   4. 返回 Envelope 结构
```

### REST API 调用

```bash
# 信封加密
curl -X POST http://localhost:8080/v1/keys/{key_id}/envelope-encrypt \
  -H "X-API-Key: $KMS_API_KEY" \
  -d '{"plaintext": "base64-encoded-data"}'

# 信封解密
curl -X POST http://localhost:8080/v1/keys/{key_id}/envelope-decrypt \
  -H "X-API-Key: $KMS_API_KEY" \
  -d '{
    "wrapped_dek": "...",
    "dek_nonce": "...",
    "ciphertext": "...",
    "data_nonce": "...",
    "tag": "..."
  }'
```

## 优势

| 优势 | 说明 |
|------|------|
| **密钥泄露风险低** | DEK 可随时重新生成，无需重新加密所有数据 |
| **性能优化** | DEK 使用高效的对称加密（AES-256-GCM） |
| **密钥轮换** | 轮换 KEK 即可，无需重新加密数据（只需重新加密 DEK） |
| **分区隔离** | 不同数据分区使用不同 DEK，泄露影响范围小 |
| **审计追溯** | KEK 操作在 KMS 留下审计日志，DEK 操作在应用层 |

## 与简单加密的对比

| 特性 | Envelope Encryption | 简单加密（KEK 直接加密数据） |
|------|---------------------|------------------------------|
| **加密粒度** | 每条数据独立 DEK | 所有数据共用 KEK |
| **密钥轮换** | 只需重新加密 DEK | 需要重新加密所有数据 |
| **泄露影响** | 单条数据泄露 | 全部数据泄露 |
| **实现复杂度** | 高 | 低 |
| **适用场景** | 大规模数据、多租户 | 少量数据、低延迟 |

## 安全注意事项

1. **DEK 随机性**：DEK 使用 GM/SM3 HMAC_DRBG 生成（符合 GM/T 0103-2012, GM/T 0105-2012），非 ring SystemRandom
2. **KEK 保护**：KEK 必须存储在 HSM 或其他高安全存储中
3. **内存安全**：DEK 使用后通过 zeroize 清零内存
4. **完整性验证**：AEAD tag 确保密文完整性

## 参考实现

- AWS KMS [信封加密](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping)
- Google Cloud KMS [信封加密](https://cloud.google.com/kms/docs/envelope-encryption)
- [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116) - AEAD 接口定义
