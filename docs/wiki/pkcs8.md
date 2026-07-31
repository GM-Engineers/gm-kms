# PKCS#8（私钥信息语法标准） / Private-Key Information Syntax Standard

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Private-Key Information Syntax Standard |
| **类型 Type** | 密钥格式标准 / Key format standard |
| **标准 Standard** | RFC 5208（PKCS#8 v1.2）、RFC 5958 |
| **用途 Purpose** | 私钥的存储和传输 / Private key storage and transmission |


## 概述

PKCS#8 定义了私钥信息的语法格式，用于存储和传输私钥材料。它支持多种算法类型的私钥，如 RSA、ECC（SM2、P-256）、EdDSA 等。

PKCS#8 文件通常以 `-----BEGIN PRIVATE KEY-----` 或 `-----BEGIN ENCRYPTED PRIVATE KEY-----` 标记。

## 格式结构

### 明文私钥（Unencrypted）

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD...
-----END PRIVATE KEY-----
```

 ASN.1 结构：
```asn1
PrivateKeyInfo ::= SEQUENCE {
    version Version,
    privateKeyAlgorithm AlgorithmIdentifier,
    privateKey PrivateKey,
    attributes [0] Attributes OPTIONAL
}
```

### 加密私钥（Encrypted）

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIA6eh...
-----END ENCRYPTED PRIVATE KEY-----
```

 使用 PBKDF2 加密（PKCS#5 v2），可通过口令保护私钥。

## 在 KMS 中的应用

| 场景 | 说明 |
|------|------|
| **密钥导入** | 外部生成的私钥导入 KMS |
| **密钥导出** | 从 KMS 导出私钥（通常加密） |
| **密钥迁移** | 跨 KMS 系统迁移密钥 |
| **格式转换** | PEM ↔ DER 格式转换 |

```go
// PKCS#8 解析示例
func ParsePKCS8PrivateKey(data []byte) (crypto.PrivateKey, error) {
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, errors.New("invalid PEM")
    }

    var privKey pkcs8.PrivateKey
    if err := UnmarshalASN1(block.Bytes, &privKey); err != nil {
        // 可能已加密，需要先解密
        return nil, err
    }
    return privKey, nil
}
```

## 相关的 PKCS 标准 / Related PKCS Standards

| 标准 Standard | 说明 Description |
|-------------|----------------|
| **PKCS#1** | RSA 加密标准（RFC 3447）/ RSA encryption standard |
| **PKCS#3** | Diffie-Hellman 密钥协议 / Diffie-Hellman key agreement |
| **PKCS#5** | 基于口令的加密（PBKDF2）/ Password-based encryption |
| **PKCS#7** | 加密消息语法 / Cryptographic Message Syntax |
| **PKCS#8** | 私钥语法（本文）/ Private key syntax (this article) |
| **PKCS#12** | 个人信息交换（可含证书+私钥）/ Personal Information Exchange (can include cert+key) |


## 与 JWK 的对比 / JWK Comparison

| 特性 Feature | PKCS#8 | JWK |
|-----------|--------|-----|
| **格式** / Format | ASN.1 DER / PEM | JSON |
| **适用场景** / Use Case | 传统系统、HSM 导入导出 / Legacy systems, HSM import/export | Web、REST API |
| **密钥类型** / Key Types | RSA、ECC、ElGamal | RSA、ECC、Oct（对称）/ RSA, ECC, Symmetric |
| **元数据** / Metadata | 有限 / Limited | 丰富的 key_ops、use 等 / Rich key_ops, use, etc. |
| **可读性** / Human-readable | 二进制/Base64 | 人类可读 JSON / Human-readable JSON |


## 安全注意事项 / Security Considerations

1. **私钥保护** / Private Key Protection：导出时务必加密，设置强口令 / Always encrypt on export; use strong password
2. **传输安全** / Transport Security：网络传输使用 TLS 或其他加密通道 / Use TLS or other encryption channel for network transport
3. **验证签名** / Verify on Import：导入后验证私钥格式和算法参数 / Verify key format and algorithm parameters after import
4. **备份管理** / Backup Management：PKCS#8 私钥备份需安全存储 / PKCS#8 private key backups must be stored securely


## 参考标准

- [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208) - PKCS#8 v1.2
- [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958) - PKCS#8 更新
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) - JWK（JSON Web Key）