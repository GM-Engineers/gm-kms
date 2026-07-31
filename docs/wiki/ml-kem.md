# ML-KEM（模块格密钥封装机制） / Module-Lattice Key Encapsulation Mechanism

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Module-Lattice-based Key Encapsulation Mechanism |
| **原名** | CRYSTALS-Kyber |
| **类型 Type** | 后量子密钥封装/协商算法 / Post-quantum key encapsulation/key agreement |
| **标准 Standard** | NIST FIPS 203 |
| **安全基础** | 模格上的错误学习问题（MLWE）/ Module-LWE (Learning With Errors) |


## 概述

ML-KEM 是一种基于模格的密钥封装机制（KEM），是 NIST 后量子密码标准化项目选定的标准算法之一（原名 CRYSTALS-Kyber）。它能够抵抗量子计算机的攻击，同时保持良好的性能。

```
ML-KEM 性能：
- 密钥生成：~10μs
- 封装（Encaps）：~15μs
- 解封装（Decaps）：~15μs
- 公钥大小：800-1564 bytes（取决于安全性等级）
- 密文大小：768-1564 bytes
```

## 安全性等级 / Security Levels

| 级别 Level | 参数 Params | 公钥大小 Public Key | 密文大小 Ciphertext | 安全强度 Security |
|-----------|------------|-------------------|-------------------|-----------------|
| **ML-KEM-512** | k=2, η=2 | 800 bytes | 768 bytes | ≈ AES-128 |
| **ML-KEM-768** | k=3, η=2 | 1184 bytes | 1088 bytes | ≈ AES-192 |
| **ML-KEM-1024** | k=4, η=2 | 1564 bytes | 1564 bytes | ≈ AES-256 |


## 算法原理（简化）

```
ML-KEM 基于 Module-LWE（模格错误学习）问题：

1. 密钥生成 (KeyGen)
   - 采样随机矩阵 A (公开)
   - 生成私钥 s（噪声向量）
   - 计算公钥 t = A·s + e（其中 e 是小噪声）

2. 封装 (Encaps)
   - 随机生成消息 m
   - 计算 u = A^T·m + e₁
   - 计算 v = t^T·m + e₂ + m·⌈q/2⌋
   - 返回 (u, v) 作为密文

3. 解封装 (Decaps)
   - 使用私钥 s 计算 m' = v - s^T·u
   - 解码得到消息（共享密钥）

数学问题：已知 A, t = A·s + e，难以求出 s（即使量子计算机也难以解决）
```

## 在 KMS 中的应用

### Hybrid KEM 模式

```go
// 混合密钥封装（经典 + 后量子）
type HybridKEM struct {
    classic  KEMInterface   // RSA/ECDH
    quantum  KEMInterface   // ML-KEM
}

func (h *HybridKEM) GenerateSharedSecret(pubKey []byte) ([]byte, error) {
    // 1. 经典 KEM
    classicSecret, err := h.classic.GenerateSharedSecret(pubKey)
    if err != nil {
        return nil, err
    }

    // 2. 后量子 KEM
    quantumSecret, err := h.quantum.GenerateSharedSecret(pubKey)
    if err != nil {
        return nil, err
    }

    // 3. 组合两者（KDF）
    combined := append(classicSecret, quantumSecret...)
    return h.kdf.Derive(combined, 32), nil
}
```

### 迁移策略

| 阶段 | 时间 | 策略 |
|------|------|------|
| **Phase 1** | 2024-2026 | 经典算法为主，ML-KEM 可选 |
| **Phase 2** | 2026-2028 | ML-KEM 主流，经典作为后备 |
| **Phase 3** | 2028+ | 纯 ML-KEM（如果无遗留需求） |

## 与经典 KEM 的对比 / Classical KEM Comparison

| 特性 Feature | ECDH (P-256) | ML-KEM-768 |
|-------------|--------------|------------|
| **性能** / Performance | 极快 / Very fast | 快 / Fast |
| **密钥大小** / Key Size | 32 bytes | 1184 bytes |
| **密文大小** / Ciphertext Size | 32 bytes | 1088 bytes |
| **量子安全** / Quantum-safe | ❌ | ✅ |
| **标准化** / Standardization | 成熟 / Mature | NIST FIPS 203 |
| **适用范围** / Use Case | 通用 / General | 通用（推荐迁移）/ General (recommended for migration) |


## 实现注意事项 / Implementation Notes

1. **随机数质量** / Random Quality：ML-KEM 对随机数质量敏感，使用加密安全 RNG / ML-KEM is sensitive to RNG quality; use CSPRNG
2. **抗侧信道** / Side-channel Resistance：实现需考虑时序、功耗等侧信道攻击 / Consider timing and power analysis attacks
3. **兼容性** / Compatibility：支持与经典算法的混合模式 / Support hybrid mode with classical algorithms
4. **版本管理** / Version Management：ML-KEM 密钥与经典密钥分开版本管理 / Keep ML-KEM and classical keys in separate versions


## 参考标准

- [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) - ML-KEM 标准
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/) - 算法参考实现
- [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) - Hybrid KEM