# SM3 密码杂凑算法 / SM3 Cryptographic Hash Algorithm

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | SM3 密码杂凑算法 / SM3 Cryptographic Hash Algorithm |
| **类型 Type** | 密码哈希函数（杂凑函数）/ Cryptographic hash function |
| **GM/T 标准** | GM/T 0004-2012 |
| **发布机构** | 国家密码管理局（OSCCA）/ OSCCA |
| **发布日期** | 2010 年 12 月 17 日 / Dec 17, 2010 |
| **算法公开性** | 公开（软件实现可用）/ Public (software implementations available) |


## 算法概述

SM3 是一种密码杂凑算法（密码哈希函数），用于数字签名、消息认证码生成、随机数生成等场景，是中国商用密码体系中的核心哈希算法。

### 关键参数 / Key Parameters

| 参数 Parameter | 值 Value |
|--------------|----------|
| **输出长度** | 256 位（32 字节）/ 256-bit (32 bytes) |
| **分组长度** | 512 位（64 字节）/ 512-bit (64 bytes) |
| **算法结构** | Merkle-Damgård + Davies-Meyer / Merkle-Damgård + Davies-Meyer |
| **安全强度** | 与 SHA-256 相当 / Comparable to SHA-256 |


## 算法设计特点 / Design Features

1. **安全性相当 SHA-256** / Comparable Security：经过充分的 cryptanalysis 检验 / Thoroughly cryptanalyzed
2. **计算效率** / Efficiency：与 SHA-256 相当，适合硬件和软件实现 / Comparable to SHA-256, suitable for HW and SW
3. **不可逆性** / One-wayness：从哈希值无法逆向推导原始输入 / Cannot derive input from hash output
4. **抗碰撞性** / Collision Resistance：计算上找不到两个不同输入产生相同输出 / Computationally infeasible to find collisions


## 应用场景 / Use Cases


| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **数字签名/验签** / Signing | 与 SM2 配合，生成待签名消息的哈希值 / Used with SM2 to hash messages for signing |
| **消息认证码** / HMAC | HMAC-SM3，用于数据完整性保护 / HMAC-SM3 for data integrity |
| **随机数生成** / RNG | 作为伪随机数生成器的输入种子 / Input seed for PRNG |
| **密钥派生** / Key Derivation | 从主密钥派生子密钥 / Derive sub-keys from master key |
| **区块链** / Blockchain | 中国国产区块链项目常采用 SM3 / Used in Chinese domestic blockchain |


## 与 SHA-256 对比 / SHA-256 Comparison

| 对比项 Comparison | SM3 | SHA-256 |
|-----------------|-----|---------|
| 输出长度 / Output | 256 位 | 256 位 |
| 分组长度 / Block Size | 512 位 | 512 位 |
| 设计机构 / Designer | OSCCA（中国）/ OSCCA | NIST（美国）/ NIST |
| 算法结构 / Structure | Merkle-Damgård + Davies-Meyer | Merkle-Damgård + Davies-Meyer |
| 性能 / Performance | 相当 / Comparable | 相当 |
| 安全强度 / Security | 同级 / Equivalent | 同级 |


## 软件支持 / Software Support

- **GmSSL**：开源国密算法库 / Open-source GM cryptographic library
- **BouncyCastle**：Java 生态 / Java ecosystem
- **Hutool**：Java 工具库 / Java utility library
- **OpenSSL**：通过 GmSSL 扩展支持 / Via GmSSL extension


## 参考资料

- GM/T 0004-2012《SM3 密码杂凑算法》
- 国家密码管理局：[oscca.gov.cn](https://www.oscca.gov.cn)
