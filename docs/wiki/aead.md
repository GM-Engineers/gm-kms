# AEAD（关联数据的认证加密） / Authenticated Encryption with Associated Data

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Authenticated Encryption with Associated Data |
| **类型 Type** | 密码学原语 / Cryptographic Primitive |
| **核心特性** | 同时提供加密（Confidentiality）和认证（Authentication）/ Provides both encryption and authentication simultaneously |
| **标准 Standard** | NIST SP 800-38D（GCM）、RFC 5116 |


## 概述

AEAD 是一种同时提供加密和认证的密码学操作模式。它确保：
1. **机密性**：只有授权方能读取明文
2. **完整性**：消息未被篡改
3. **认证性**：确认消息来自声称的发送方

AEAD 可以将任意的关联数据（Associated Data，AD）包含在认证范围内，但不需要加密。例如，可以将消息头部作为 AD 一起认证，这样即使攻击者重放旧消息，也能被检测到。

## 算法变体 / Algorithm Variants

| 模式 Mode | 说明 Description | 标准 Standard |
|-----------|----------------|--------------|
| **AES-256-GCM** | AES 分组密码 + 伽罗瓦计数器模式，最常用 / AES block cipher + Galois counter mode, most common | NIST SP 800-38D |
| **ChaCha20-Poly1305** | 流密码 ChaCha20 + Poly1305 MAC，移动端性能优异 / Stream cipher ChaCha20 + Poly1305 MAC, excellent mobile performance | RFC 7539 |
| **AES-CCM** | AES 计数器模式 + CMAC，新设备兼容性好 / AES CTR mode + CMAC, good legacy compatibility | NIST SP 800-38C |
| **AES-GCM-SIV** | 基于 SIV 的变体，抗误用性更强 / SIV-based variant, stronger misuse resistance | RFC 8452 |


## 工作原理（AES-GCM 为例）

```
加密过程：
┌──────────┐     ┌────────────┐     ┌─────────────┐
│  Plaintext │ ──▶ │  AES-CTR   │ ──▶ │ 密文        │
└──────────┘     └────────────┘     └─────────────┘
                     │
              ┌──────┴──────┐
              │  GHASH      │
              │ (MAC 计算)  │
              └──────┬──────┘
                     │
               ┌─────▼─────┐
               │  Auth Tag │ (128位认证标签)
               └───────────┘
```

1. 使用计数器模式（CTR）生成密钥流
2. 与明文异或得到密文
3. 使用 GHASH 函数计算认证标签
4. 返回密文 + 认证标签

## 在 KMS 中的应用 / KMS Applications

在 KMS 架构中，AEAD 是最常用的数据加密接口。gm-kms 使用 AES-256-GCM 作为默认 AEAD 模式：

| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **数据加密密钥（DEK）** / DEK | 使用 KEK 通过 AEAD 加密 DEK，实现 Envelope Encryption / Encrypt DEK with KEK via AEAD to implement Envelope Encryption |
| **数据库字段加密** / DB Column | 加密敏感业务数据（身份证号、银行卡号）/ Encrypt sensitive business data (ID numbers, bank cards) |
| **文件加密** / File Encryption | 大文件分块加密，每块使用不同 nonce / Chunked encryption with unique nonce per chunk |
| **通信加密** / TLS | TLS 记录层使用 AEAD 加密应用数据 / AEAD encrypts application data in TLS record layer |


## 与非 AEAD 模式的对比 / Comparison with Non-AEAD Modes

| 特性 Feature | AEAD（GCM/ChaCha20-Poly1305） | 仅加密（GCM/CTR）/ Encryption Only | 仅认证（HMAC）/ MAC Only |
|-------------|------------------------------|--------------------|----------------|
| 机密性 / Confidentiality | ✅ | ✅ | ❌ |
| 完整性 / Integrity | ✅ | ❌ | ✅ |
| 认证性 / Authentication | ✅ | ❌ | ✅ |
| 防重放 / Anti-replay | ✅（通过 nonce）/ via nonce | ❌ | ❌ |
| 实现复杂度 / Complexity | 中等 / Medium | 低 / Low | 中等 / Medium |


## 安全注意事项 / Security Notes

1. **Nonce 不可重复** / No Nonce Reuse：同一个 nonce 使用两次会泄露密钥 / Using the same nonce twice leaks the key
2. **Tag 长度** / Tag Length：128位（GCM）提供足够安全性，不要截断 / 128-bit (GCM) provides sufficient security, do not truncate
3. **AD 保护** / AD Protection：关联数据完整性保护，但不加密 / AD is integrity-protected but not encrypted
4. **密钥分离** / Key Separation：不同用途使用不同密钥 / Use different keys for different purposes


## 参考标准

- [NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) - GCM 推荐
- [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116) - AEAD 接口定义
- [RFC 7539](https://datatracker.ietf.org/doc/html/rfc7539) - ChaCha20-Poly1305