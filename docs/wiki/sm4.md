# SM4 分组密码算法 / SM4 Block Cipher Algorithm

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | SM4 分组密码算法（原名 SMS4）/ SM4 Block Cipher Algorithm (formerly SMS4) |
| **类型 Type** | 对称加密（分组密码）/ Symmetric encryption (block cipher) |
| **GM/T 标准** | GM/T 0002-2012 |
| **发布机构** | 国家密码管理局（OSCCA）/ OSCCA |
| **发布日期** | 2012 年 3 月 / March 2012 |
| **算法公开性** | 公开（软件实现可用）/ Public (software implementations available) |


## 算法概述

SM4 是一种分组对称加密算法，用于保护电子数据的机密性和完整性，是中国商用密码体系中替代 DES/AES 等国际算法的核心对称密码算法。

### 关键参数 / Key Parameters

| 参数 Parameter | 值 Value |
|--------------|----------|
| **分组长度** | 128 位（16 字节）/ 128-bit (16 bytes) |
| **密钥长度** | 128 位（16 字节）/ 128-bit (16 bytes) |
| **迭代轮数** | 32 轮 / 32 rounds |
| **数据处理单位** | 字节（8 位）和字（32 位）/ Byte (8-bit) and word (32-bit) |
| **算法结构** | 非平衡 Feistel 结构 / Unbalanced Feistel structure |

### 工作模式 / Block Cipher Modes

SM4 支持多种分组密码工作模式：

| 模式 Mode | 说明 Description | 适用场景 Use Case |
|---------|----------------|-----------------|
| **ECB** | 电子密码本模式（简单，但有规律泄露风险）/ Electronic codebook (simple, pattern leakage risk) | 数据块相互独立、低价值数据 / Independent blocks, low-value data |
| **CBC** | 密码块链接模式（引入 IV，常用）/ Cipher block chaining (IV, common) | 文件加密、数据库加密 / File encryption, database encryption |
| **CFB** | 密码反馈模式 / Cipher feedback | 流式数据加密 / Stream data encryption |
| **OFB** | 输出反馈模式 / Output feedback | 流式数据加密 / Stream data encryption |
| **GCM** | 伽罗瓦计数器模式（AEAD）/ Galois counter mode | TLS/SSL、高安全场景 / TLS/SSL, high security |


## 应用场景 / Use Cases

| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **无线局域网** / Wireless LAN | 最初设计用于无线 LAN 产品（像 WAPI 协议）/ Originally designed for wireless LAN (WAPI protocol) |
| **数据加密** / Data Encryption | 文件、数据库、磁盘加密 / File, database, disk encryption |
| **TLS/SSL** | HTTPS 中的数据机密性保护 / Data confidentiality in HTTPS |
| **数字信封** / Digital Envelope | 结合 SM2，用于混合加密体制 / Combined with SM2 for hybrid encryption |
| **金融支付** / Financial Payment | 银联卡等金融场景的加密要求 / Encryption for financial scenarios (e.g., UnionPay) |


## 与 AES 对比 / AES Comparison

| 对比项 Comparison | SM4 | AES |
|-----------------|-----|-----|
| 分组长度 / Block Size | 128 位 | 128 位 |
| 密钥长度 / Key Size | 128 位 | 128/192/256 位 |
| 迭代轮数 / Rounds | 32 轮 / 32 | 10/12/14 轮 / 10/12/14 |
| 算法结构 / Structure | 非平衡 Feistel / Unbalanced Feistel | 代数结构（置换组合网络）/ Algebraic structure |
| 标准机构 / Standard Body | OSCCA（中国）/ OSCCA | NIST（美国）/ NIST |
| 安全等级 / Security Level | 高 / High | 高（经过更广泛分析）/ High (more extensively analyzed) |


## 软件支持 / Software Support

- **GmSSL**：开源国密算法库 / Open-source GM cryptographic library
- **BouncyCastle**：Java 生态（`SM4Engine`）/ Java ecosystem
- **Hutool**：Java 工具库 / Java utility library
- **OpenSSL**：通过 GmSSL 扩展支持 / Via GmSSL extension

## 数字信封流程（SM2 + SM4 混合使用） / Digital Envelope (SM2 + SM4 Hybrid)


```
发送方：
1. 使用 SM4 生成随机对称密钥（会话密钥）
2. 用 SM4 会话密钥加密明文数据
3. 用 SM2 公钥加密 SM4 会话密钥
4. 将两者组合发送

接收方：
1. 用 SM2 私钥解密出会话密钥
2. 用会话密钥通过 SM4 解密数据
```

## 参考资料

- GM/T 0002-2012《SM4 分组密码算法》
- 国家密码管理局：[oscca.gov.cn](https://www.oscca.gov.cn)
