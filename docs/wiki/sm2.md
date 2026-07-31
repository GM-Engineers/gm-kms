# SM2 椭圆曲线公钥密码算法 / SM2 Elliptic Curve Public Key Cryptography

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | SM2 椭圆曲线公钥密码算法 / SM2 Elliptic Curve Public Key Cryptography |
| **类型 Type** | 非对称加密（公钥密码体系）/ Asymmetric cryptography |
| **GM/T 标准** | GM/T 0003-2012 |
| **发布机构** | 国家密码管理局（OSCCA）/ OSCCA |
| **发布日期** | 2010 年 12 月 17 日 / Dec 17, 2010 |
| **算法公开性** | 公开（软件实现可用）/ Public (software implementations available) |


## 算法概述

SM2 是一种基于椭圆曲线密码学（ECC）的公钥密码算法，设计用于替代国际通用的 RSA、ECC 等算法。

### 关键参数 / Key Parameters

| 参数 Parameter | 值 Value |
|--------------|----------|
| **曲线类型** | SM2p256v1（国家规定的椭圆曲线参数）/ SM2p256v1 (state-specified ECC params) |
| **密钥长度** | 256 位 / 256-bit |
| **安全强度** | 相当于 RSA 2048 位 / Equivalent to RSA 2048-bit |
| **签名长度** | 64 字节（512 位）/ 64 bytes |

### 算法模式 / Algorithm Modes

SM2 标准包含三个具体模式：

| 模式 Mode | 用途 Use | 说明 Description |
|---------|--------|----------------|
| **SM2-1** | 数字签名 / Digital Signature | 签名和验签 / Signing and verification |
| **SM2-2** | 密钥交换 / Key Exchange | 双方协商共享密钥 / Two parties negotiate shared key |
| **SM2-3** | 公钥加密 / Public Key Encryption | 用公钥加密数据 / Encrypt data with public key |


## 应用场景

- **数字签名**：替代 RSA/ECDSA，用于软件签名、文档签名
- **密钥交换**：双方协商会话密钥，支持前向安全
- **公钥加密**：适用于加密长度较短的数据（如会话密钥、消息报文）
- **SSL/TLS 证书**：SM2 证书可应用于国内密码体系

## 与国际算法对比 / International Algorithm Comparison

| 对比项 Comparison | SM2 | RSA | ECC（国际）/ Intl |
|-----------------|-----|-----|-------------|
| 密钥长度 / Key Size | 256 位 | 2048~4096 位 | 256~384 位 |
| 安全强度 / Security | 高 / High | 高 / High | 高 / High |
| 签名速度 / Signing Speed | 快 / Fast | 慢 / Slow | 快 / Fast |
| 运算效率 / Efficiency | 优（相同安全级别下密钥更短）/ Excellent | 较差 / Worse | 优 / Excellent |
| 标准机构 / Standard Body | OSCCA | RSA Labs | NIST |


## 技术特点 / Technical Features

1. **高安全强度** / High Security：相同密钥长度下安全性优于 RSA / Better security than RSA at same key length
2. **高效运算** / Efficient Computation：适合资源受限场景（嵌入式设备、移动终端）/ Suitable for embedded and mobile devices
3. **防篡改特性** / Tamper Detection：SM2 公钥加密的密文在解密过程中可检测篡改 / SM2 encryption detects tampering during decryption
4. **合规性** / Compliance：国家密码管理局强制或推荐在特定领域使用 / Mandatory or recommended by OSCCA in specific domains

## 软件支持 / Software Support

- **GmSSL**：开源国密算法库，支持 SM2 / Open-source GM cryptographic library
- **BouncyCastle**：Java 生态广泛使用，支持 SM2 / Widely used in Java ecosystem
- **Hutool**：Java 工具库，支持 SM2/SM3/SM4 / Java utility library
- **OpenSSL 1.0.2+**：通过 GmSSL 扩展或特定分支支持 / Via GmSSL extension or specific branches


## 参考资料

- GM/T 0003-2012《SM2 椭圆曲线公钥密码算法》
- 国家密码管理局：[oscca.gov.cn](https://www.oscca.gov.cn)
