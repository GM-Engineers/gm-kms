# FIPS 140-2/140-3（密码模块安全标准） / FIPS 140-2/140-3 Cryptographic Module Standard

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Federal Information Processing Standard 140-2/140-3 |
| **中文** | 联邦信息处理标准 / Federal Information Processing Standard |
| **类型 Type** | 密码模块安全认证标准 / Cryptographic module security certification standard |
| **发布机构** | NIST（美国国家标准与技术研究院）/ NIST |
| **适用范围** | 密码模块（硬件、软件、固件）/ Cryptographic modules (HW, SW, firmware) |


## FIPS 140-2 概述

FIPS 140-2 是密码模块的安全认证标准，定义了密码模块必须满足的安全要求。认证等级从 1 到 4 逐级提高。

```
安全等级概览：

Level 1    最低安全要求
Level 2    角色分离、防篡改证据
Level 3    物理防拆、基于输入的密钥擦除
Level 4    最高安全、环境中所有物理攻击防护
```

## 安全等级详情 / Security Level Details

| 等级 Level | 核心要求 Core Requirements | 典型应用 Typical Application |
|-----------|--------------------------|---------------------------|
| **Level 1** | 基本安全要求，CSP 以加密形式存储 / Basic requirements, CSP stored encrypted | 软件密码库（OpenSSL）/ Software crypto library |
| **Level 2** | 角色分离、操作日志、防篡改证据 / Role separation, logs, tamper evidence | 商业应用 HSM / Commercial HSM |
| **Level 3** | 物理防篡改、基于输入的密钥擦除 / Physical tamper resistance, key erasure on input | 金融、政府 HSM / Finance, government HSM |
| **Level 4** | 物理安全最高，环境攻击防护 / Highest physical security, environmental attack protection | 军事、高安全场景 / Military, high-security |


### Level 1 要求

- 使用批准的加密算法（FIPS 140-2 Approved algorithms）
- 固件/软件完整性验证（可选）
- CSP（关键安全参数）以加密形式存储

### Level 2 要求（Level 1 +）

- 角色分离：操作员角色和管理员角色分离
- 鉴权机制：基于角色的鉴权
- 操作日志：审计日志记录
- 防篡改证据：可见的篡改指示（如密封标签）

### Level 3 要求（Level 2 +）

- 物理防拆：检测物理攻击并响应（擦除 CSP）
- 基于输入的密钥擦除：专用清除输入引脚
- 增强的鉴权：基于身份的鉴权
- 安全覆盖：有效载荷接口的访问控制

### Level 4 要求（Level 3 +）

- 环境攻击防护：温度、电压、EM、光等攻击检测
- 主动防护：检测到攻击后立即擦除
- 高可用：容错设计

## FIPS 140-3 概述

FIPS 140-3 于 2019 年发布，替代 FIPS 140-2（虽然 140-2 仍被接受）。主要变化：

| 变化 | 说明 |
|------|------|
| **对齐 ISO/IEC** | 与 ISO/IEC 19790:2012 对齐 |
| **可测试性** | 更强调可测试的安全功能 |
| **密钥生命周期** | 更明确的密钥生命周期要求 |
| **固件更新** | 更新的固件/软件更新要求 |

## 在 HSM 选型中的应用

```
HSM 选型等级对照：

场景                          推荐等级
────────────────────────────────────────
软件加密库                    Level 1
普通企业应用                  Level 2
金融支付、CA                  Level 3
政府、军事、极高安全           Level 4
```

### 认证 HSM 产品

| 厂商 | 产品 | 认证等级 |
|------|------|----------|
| **Thales Luna** | HSM 7 / PCIe | Level 3 |
| **Utimaco** | CryptoServer | Level 3 |
| **AWS CloudHSM** | CloudHSM | Level 3 |
| **Azure Dedicated HSM** | Luna HSM | Level 3 |
| **Yubico** | YubiHSM 2 | Level 3 |
| **Marvell** | HSM（硬件） | Level 3 |

## KMS 中的 FIPS 模式

```go
// FIPS 模式配置
type FIPSConfig struct {
    Level       int  // 1-4
    ApprovedOnly bool  // 仅使用 FIPS 批准的算法
}

func (c *FIPSConfig) ValidateAlgorithm(alg string) error {
    if c.ApprovedOnly {
        approved := map[string]bool{
            "AES-256-GCM": true,
            "SHA-256":     true,
            "HMAC-SHA256": true,
            "ECDSA-P256":  true,
            "RSA-4096":    true,
            // SM2 在某些模式下不被视为 FIPS 批准
            "SM2": false,
            "SM3": false,
            "SM4": false,
        }
        if !approved[alg] {
            return fmt.Errorf("algorithm %s not FIPS approved", alg)
        }
    }
    return nil
}
```

## FIPS 与其他标准的关系 / Relationship with Other Standards

| 标准 Standard | 关系 Relationship |
|-------------|----------------|
| **CC（通用准则）** / CC | FIPS 140-2 可作为 CC 评估的一部分 / Can be part of CC evaluation |
| **PCI-DSS** | 要求使用 FIPS 140-2+ 认证的 HSM / Requires FIPS 140-2+ certified HSM |
| **等保三级** / Level 3 | 可参考 FIPS 140-2 L3 作为技术标准 / Can reference FIPS 140-2 L3 as technical standard |
| **ISO 27001** | 密码控制可参考 FIPS 要求 / Cryptographic controls can reference FIPS requirements |


## 安全注意事项 / Security Considerations

1. **认证过期** / Certification Expiry：HSM 认证有有效期，需定期重新认证 / HSM certification has validity period; recertification needed periodically
2. **配置正确** / Correct Configuration：购买后正确配置 FIPS 模式 / Configure FIPS mode correctly after purchase
3. **算法限制** / Algorithm Restrictions：FIPS 模式可能限制某些算法的使用 / FIPS mode may restrict certain algorithms
4. **固件更新** / Firmware Updates：更新固件后可能需要重新认证 / Recertification may be needed after firmware updates


## 参考标准

- [NIST FIPS 140-2](https://doi.org/10.6028/NIST.FIPS.140-2) - 原文
- [NIST FIPS 140-3](https://doi.org/10.6028/NIST.FIPS.140-3) - 原文
- [CMVP（验证模块）](https://csrc.nist.gov/projects/cryptographic-module-validation-program) - 认证数据库