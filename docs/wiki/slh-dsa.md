# SLH-DSA（无状态哈希数字签名） / Stateless Hash-based Digital Signature Algorithm

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Stateless Hash-based Digital Signature Algorithm |
| **原名** | SPHINCS+ |
| **类型 Type** | 无状态哈希数字签名算法 / Stateless hash-based digital signature algorithm |
| **标准 Standard** | NIST FIPS 205 |
| **安全基础** | 底层哈希函数的安全性（安全性最保守）/ Security based on underlying hash function (most conservative) |


## 概述

SLH-DSA 是一种基于哈希的无状态数字签名算法（原名 SPHINCS+），是 NIST 后量子密码标准化项目选定的算法之一。与 ML-DSA 不同，SLH-DSA 完全基于哈希函数的安全性，不依赖任何数论假设。

```
SLH-DSA 特点：
- 无状态：签名时不需要维护状态（vs 有状态的 XMSS）
- 纯哈希：仅依赖哈希函数（如 SHA-256）
- 大签名：签名较大（~30-50KB）
- 超高安全：最保守的后量子安全假设
```

## 安全性等级

| 级别 | 参数 | 公钥大小 | 签名大小 | 哈希函数 |
|------|------|----------|----------|----------|
| **SLH-DSA-SHA2-128s** | 128-bit security, small | 32 bytes | 7856 bytes | SHA-256 |
| **SLH-DSA-SHA2-128f** | 128-bit security, fast | 32 bytes | 17078 bytes | SHA-256 |
| **SLH-DSA-SHAKE-128s** | 128-bit security | 32 bytes | 7980 bytes | SHAKE-256 |
| **SLH-DSA-SHA2-192s** | 192-bit security | 48 bytes | 16224 bytes | SHA-256 |
| **SLH-DSA-SHA2-256s** | 256-bit security | 64 bytes | 29792 bytes | SHA-256 |

> `s` = small（签名较小）, `f` = fast（签名较快）

## 算法原理（简化）

```
SLH-DSA 使用 Merkle 树 + Lamport 一次性签名：

1. 密钥生成
   - 生成底层的 LAMPK 个一次性签名密钥对
   - 构键 Merkle 树（上层认证路径）
   - 公钥 = Merkle 树根哈希 + HORST TreeAuth

2. 签名过程
   - 将消息哈希映射到 HORST 索引
   - 使用对应的一 次性签名密钥签名
   - 附加 Merkle 认证路径
   - 无状态：不需要知道之前签过什么

3. 验签
   - 解析签名结构
   - 验证 HORST 一次性签名
   - 验证 Merkle 认证路径
```

## 与 ML-DSA 的对比 / ML-DSA Comparison

| 特性 Feature | ML-DSA | SLH-DSA |
|-------------|--------|---------|
| **安全假设** / Security Assumption | 数论（格）/ Lattice | 哈希函数 / Hash function |
| **签名大小** / Sig Size | ~3KB | ~30KB |
| **密钥大小** / Key Size | ~2KB | ~32-64 bytes |
| **签名速度** / Signing Speed | 快 / Fast | 慢 / Slow |
| **状态** / State | 无 / Stateless | 无 / Stateless |
| **适用场景** / Use Case | 通用签名 / General signing | 超高安全、长有效期 / Ultra-high security, long validity |


## 选择建议 / Selection Guide

| 场景 Scenario | 推荐算法 Recommended Algorithm |
|--------------|------------------------------|
| **通用应用** / General Apps | ML-DSA（性能好）/ ML-DSA (good performance) |
| **长期签名（如证书）** / Long-term Signing | SLH-DSA（更保守）/ SLH-DSA (more conservative) |
| **极端量子威胁** / Extreme Quantum Threat | SLH-DSA（无数论假设）/ SLH-DSA (no number-theory assumption) |
| **受限环境** / Constrained Env | ML-DSA（签名小）/ ML-DSA (smaller signatures) |


## 在 KMS 中的应用

```go
// SLH-DSA 签名接口
type SLHDSASigner interface {
    // 生成签名密钥（无状态）
    GenerateKey() (*SigningKey, error)

    // 签名
    Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)

    // 验签
    Verify(pubKey []byte, message, signature []byte) (bool, error)
}

// 使用场景：长期签名文档
func SignLongTermDocument(signer SLHDSASigner, keyID string, doc []byte) ([]byte, error) {
    msgHash := sha256.Sum256(doc)

    // SLH-DSA 签名
    signature, err := signer.Sign(context.Background(), keyID, msgHash[:])
    if err != nil {
        return nil, err
    }

    // SLH-DSA 签名约 30KB
    return signature, nil
}
```

## 安全注意事项 / Security Considerations

1. **签名大小** / Signature Size：SLH-DSA 签名约 30KB，网络传输需注意 / SLH-DSA sigs are ~30KB; consider network impact
2. **签名速度** / Signing Speed：比 ML-DSA 慢 10-100 倍，考虑性能影响 / 10-100x slower than ML-DSA; consider performance impact
3. **密钥保护** / Key Protection：私钥仍需高安全存储 / Private keys still need high-security storage
4. **无状态保证** / Stateless Guarantee：确保签名过程不维护状态 / Ensure signing process maintains no state


## 参考标准

- [NIST FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) - SLH-DSA 标准
- [SPHINCS+](https://sphincs.org/) - 算法参考实现