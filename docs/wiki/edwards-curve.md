# Edwards 曲线 / Edwards Curves (Ed25519 / Ed448)

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **曲线类型** | Edwards 曲线（扭曲线）/ Twisted Edwards curve |
| **标准 Standard** | RFC 8032 |
| **发布机构** | IETF / IRTF |
| **算法公开性** | 公开 / Public |


## 曲线参数 / Curve Parameters

### Ed25519

| 参数 Parameter | 值 Value |
|--------------|----------|
| **全称** | Edwards25519 |
| **密钥长度** | 256 位（32 字节）/ 256-bit (32 bytes) |
| **签名长度** | 512 位（64 字节）/ 512-bit (64 bytes) |
| **安全强度** | ~128 位 / ~128-bit |
| **哈希函数** | SHA-512 |
| **基域** | 255 位素数 / 255-bit prime |
| **曲线方程** | x² + y² = 1 + d·x²·y² (mod p) |

### Ed448 (Edwards448)

| 参数 Parameter | 值 Value |
|--------------|----------|
| **全称** | Edwards448 |
| **密钥长度** | 448 位（57 字节）/ 448-bit (57 bytes) |
| **签名长度** | 912 位（114 字节）/ 912-bit (114 bytes) |
| **安全强度** | ~192 位 / ~192-bit |
| **哈希函数** | SHAKE-256 |
| **基域** | 448 位素数 / 448-bit prime |
| **曲线方程** | x² + y² = 1 + d·x²·y² (mod p) |


## 算法概述

Edwards 曲线是由 Harold Edwards 在 2007 年设计的椭圆曲线变体。相比 Weierstrass 形式（如 NIST P-256），扭曲线具有更好的数学特性：

1. **加法公式完备**：不存在"无穷远点"特殊情况，处理更一致
2. **常数时间运算**：天然抗时序攻击（timing attack）
3. **签名快速稳定**：不依赖大数乘法，性能稳定
4. **抗碰撞**：对侧信道攻击抵抗力更强

## 与 NIST ECC 对比 / NIST ECC Comparison

| 对比项 Comparison | Ed25519 | Ed448 | NIST P-256 | NIST P-384 |
|-----------------|---------|-------|------------|------------|
| 密钥长度 / Key Size | 256 位 | 448 位 | 256 位 | 384 位 |
| 签名长度 / Sig Size | 512 位 | 912 位 | 512 位 | 768 位 |
| 安全强度 / Security | 128 bit | 192 bit | 128 bit | 192 bit |
| 运算特性 / Constant-time | 恒定时间 / Constant-time | 恒定时间 / Constant-time | 不一定 / Not guaranteed | 不一定 / Not guaranteed |
| 设计者 / Designer | Bernstein 等 | Bernstein 等 | NSA (Certicom) | NSA (Certicom) |
| 标准机构 / Standard | IETF (RFC 8032) | IETF (RFC 8032) | NIST | NIST |


## 应用场景 / Use Cases

| 场景 Scenario | 推荐算法 Recommended Algorithm |
|--------------|------------------------------|
| SSH 密钥 / SSH Keys | Ed25519（首选，现代 SSH 默认）/ Ed25519 (preferred, modern SSH default) |
| 代码签名 / Code Signing | Ed25519（Swift、Go 等采用）/ Ed25519 (used by Swift, Go, etc.) |
| Bitcoin 改进提议 / BIPs | Ed25519（部分 altcoin 采用）/ Ed25519 (used by some altcoins) |
| TLS 证书 / TLS Certs | Ed25519 / Ed448（RFC 8422） |
| TLS 密钥交换 / TLS KEX | X25519（Curve25519，ECDH） |
| 区块链/DeFi | Ed25519（Solana、Near 等）/ Ed25519 (Solana, Near, etc.) |
| WireGuard VPN | Curve25519（X25519） |


## 技术特点

1. **高性能签名**：签名速度是 RSA 的 10x 以上
2. **小密钥**：32 字节公钥，64 字节签名
3. **安全可靠**：经过多年 cryptanalysis 检验
4. **多语言支持**：主流语言均有实现

## 软件支持 / Software Support

| 语言 Language | 库 Library | 备注 Notes |
|-------------|----------|----------|
| C | libsodium、NaCl | 推荐 / Recommended |
| Go | crypto/ed25519 | 标准库 / Standard library |
| Rust | ring、ed25519-dalek | |
| Python | PyNaCl、ed25519 | |
| JavaScript | tweetnacl-js | 纯 JS 实现 / Pure JS implementation |
| Java | BouncyCastle / Tink | |


## X25519（密钥交换） / X25519 Key Exchange

Edwards 曲线配套的 ECDH 协议：

| 曲线 Curve | 用途 Use | RFC |
|-----------|--------|-----|
| Curve25519 | X25519 ECDH | RFC 7748 |
| Ed25519 | 签名 / Signing | RFC 8032 |
| Ed448 | 签名（192-bit 安全）/ Signing (192-bit security) | RFC 8032 |


## 可信来源

- **IETF** — RFC 8032（EdDSA 签名协议）
- **IRTF** — CFRG（Crypto Forum Research Group）推荐
- **IETF** — RFC 7748（Curve25519 和 Curve448）
- **IETF** — RFC 8422（TLS EdDSA 证书）
