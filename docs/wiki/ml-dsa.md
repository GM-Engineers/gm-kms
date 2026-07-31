# ML-DSA（模块格数字签名算法） / Module-Lattice Digital Signature Algorithm

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Module-Lattice-based Digital Signature Algorithm |
| **原名** | CRYSTALS-Dilithium |
| **类型 Type** | 后量子数字签名算法 / Post-quantum digital signature algorithm |
| **标准 Standard** | NIST FIPS 204 |
| **安全基础** | 模格上的错误学习问题（MLWE）和 SelfTargetMSIS / MLWE and SelfTargetMSIS on module lattices |


## 概述

ML-DSA 是一种基于模格的数字签名算法（，原名 CRYSTALS-Dilithium），是 NIST 后量子密码标准化项目选定的签名算法之一。它具有较好的性能和紧凑的签名大小，适用于各种应用场景。

```
ML-DSA 性能：
- 密钥生成：~50μs
- 签名：~100μs
- 验签：~50μs
- 公钥大小：1312-1952 bytes
- 签名大小：2420-4595 bytes
```

## 安全性等级 / Security Levels

| 级别 Level | 参数 Params | 公钥大小 Public Key | 签名大小 Signature | 安全强度 Security |
|-----------|------------|-------------------|------------------|-----------------|
| **ML-DSA-44** | k=4, η=2, d=13 | 1312 bytes | 2420 bytes | ≈ AES-128 |
| **ML-DSA-65** | k=6, η=4, d=13 | 1952 bytes | 3307 bytes | ≈ AES-192 |
| **ML-DSA-87** | k=8, η=2, d=13 | 2590 bytes | 4595 bytes | ≈ AES-256 |


## 算法原理（简化）

```
ML-DSA 基于 Module-LWE 和 Module-SIS 问题：

1. 密钥生成 (KeyGen)
   - 采样随机矩阵 A（公开）
   - 生成私钥 s₁, s₂（短噪声向量）
   - 计算 t = A·s₁ + s₂
   - 私钥：(A, s₁, s₂)，公钥：(A, t)

2. 签名 (Sign)
   - 计算 y（随机短向量）
   - 计算 w = A^T·y（高熵部分）
   - 计算 c = Hash(w || m)（承诺）
   - 计算 z = y + c·s₁（使用短噪声）
   - 输出签名 (z, c)

3. 验签 (Verify)
   - 计算 w' = A^T·z - c·t
   - 验证 c == Hash(w' || m)
   - 确保 z 是短向量
```

## 在 KMS 中的应用

### 签名操作

```go
// ML-DSA 签名接口
type MLDSASigner interface {
    // 生成签名密钥对
    GenerateKey() (*SigningKey, error)

    // 签名
    Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)

    // 验签
    Verify(pubKey []byte, message, signature []byte) (bool, error)
}

// 使用示例
func SignDocument(signer MLDSASigner, keyID string, doc []byte) ([]byte, error) {
    // 1. 计算消息哈希
    msgHash := sha256.Sum256(doc)

    // 2. 调用 KMS 签名
    signature, err := signer.Sign(context.Background(), keyID, msgHash[:])
    if err != nil {
        return nil, err
    }

    return signature, nil
}
```

### Hybrid Signature 模式

```go
// 混合签名（经典 + 后量子）
type HybridSigner struct {
    classicSign SignatureAlgorithm   // ECDSA
    quantumSign SignatureAlgorithm   // ML-DSA
}

func (h *HybridSigner) Sign(ctx context.Context, keyID string, msg []byte) ([]byte, error) {
    // 1. 经典签名
    classicSig, err := h.classicSign.Sign(ctx, keyID+"-classic", msg)
    if err != nil {
        return nil, err
    }

    // 2. 后量子签名
    quantumSig, err := h.quantumSign.Sign(ctx, keyID+"-quantum", msg)
    if err != nil {
        return nil, err
    }

    // 3. 组合签名
    return append(classicSig, quantumSig...), nil
}
```

## 与经典签名的对比 / Classical Signature Comparison

| 特性 Feature | ECDSA P-256 | ML-DSA-65 |
|-------------|-------------|-----------|
| **性能** / Performance | 极快 / Very fast | 中等 / Medium |
| **密钥大小** / Key Size | 32 bytes | 1952 bytes |
| **签名大小** / Sig Size | 64 bytes | 3307 bytes |
| **量子安全** / Quantum-safe | ❌ | ✅ |
| **标准化** / Standardization | FIPS 186-4 | NIST FIPS 204 |
| **适用范围** / Use Case | 通用 / General | 通用（推荐迁移）/ General (recommended for migration) |


## 安全注意事项 / Security Considerations

1. **签名长度** / Signature Size：ML-DSA 签名较大（约 3KB），考虑存储和传输 / ML-DSA signatures are large (~3KB), consider storage and transport
2. **密钥保护** / Key Protection：私钥仍需 HSM/TPM 保护 / Private keys still need HSM/TPM protection
3. **实现安全** / Implementation Security：需防止侧信道攻击（功率分析、时序）/ Must prevent side-channel attacks (power analysis, timing)
4. **版本管理** / Version Management：签名密钥版本需清晰追踪 / Signature key versions must be clearly tracked


## 参考标准

- [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) - ML-DSA 标准
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/) - 算法参考实现