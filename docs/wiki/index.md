# 词条索引 / Wiki Entry Index

> 上次更新：2026-06-29

## 算法与密码学 / Algorithms & Cryptography

### 非对称加密 / Asymmetric Encryption
| 词条 | 说明 |
|------|------|
| [sm2.md](./sm2.md) | SM2 椭圆曲线公钥密码算法（GM/T 0003-2012） ✅ |
| [sm2-kex.md](./sm2-kex.md) | SM2 密钥交换协议 ✅ |
| [rsa-4096.md](./rsa-4096.md) | RSA-4096 非对称加密 ✅ |
| [ecc-p256-p384.md](./ecc-p256-p384.md) | ECC P-256/P-384 椭圆曲线 ✅ |
| [edwards-curve.md](./edwards-curve.md) | Edwards 曲线（Ed25519 等） ✅ |

### 对称加密 / Symmetric Encryption
| 词条 | 说明 |
|------|------|
| [sm4.md](./sm4.md) | SM4 分组密码算法 ✅ |
| [aead.md](./aead.md) | AEAD 认证加密模式 ✅ |
| [sm2.md#sm2-3](./sm2.md) | SM2-3 公钥加密模式 ✅ |

### 哈希与 MAC / Hash & MAC
| 词条 | 说明 |
|------|------|
| [sm3.md](./sm3.md) | SM3 密码哈希算法 ✅ |
| [hmac.md](./hmac.md) | HMAC 消息认证码 ✅ |
| [hkdf.md](./hkdf.md) | HKDF 密钥派生函数 ✅ |
| [pbkdf2.md](./pbkdf2.md) | PBKDF2 密码派生函数 ✅ |

### 密钥管理 / Key Management
| 词条 | 说明 |
|------|------|
| [kek.md](./kek.md) | Key Encryption Key，密钥加密密钥 ✅ |
| [dek.md](./dek.md) | Data Encryption Key，数据加密密钥 ✅ |
| [envelope-encryption.md](./envelope-encryption.md) | 包络加密（DEK/KEK 两层架构） ✅ |
| [key-import-export.md](./key-import-export.md) | 密钥导入导出（PKCS#8、JWK、raw） ✅ |
| [key-backup.md](./key-backup.md) | 密钥备份与恢复 ✅ |

### 高级算法 / Advanced Algorithms
| 词条 | 说明 |
|------|------|
| [ml-kem.md](./ml-kem.md) | ML-KEM（CRYSTALS-Kyber）后量子密钥封装 ✅ |
| [ml-dsa.md](./ml-dsa.md) | ML-DSA（CRYSTALS-Dilithium）后量子签名 ✅ |
| [slh-dsa.md](./slh-dsa.md) | SLH-DSA（SPHINCS+）无状态哈希签名 ✅ |
| [sss.md](./sss.md) | Shamir 秘密分享方案 ✅ |
| [forward-secrecy.md](./forward-secrecy.md) | 前向保密 ✅ |
| [csprng.md](./csprng.md) | 密码学安全随机数生成器 ✅ |

## 安全模块与硬件 / Security Modules & Hardware

### 硬件安全模块 / HSM
| 词条 | 说明 |
|------|------|
| [hsm.md](./hsm.md) | Hardware Security Module，硬件安全模块 ✅ |
| [tpm2.md](./tpm2.md) | TPM 2.0 可信平台模块 ✅ |
| [software-keystore.md](./software-keystore.md) | 软件密钥存储 ✅ |

### 密钥存储架构 / Key Storage Architecture
| 词条 | 说明 |
|------|------|
| [vault.md](./vault.md) | Vault 密钥存储架构 ✅ |

## 访问控制 / Access Control

### 权限模型 / Permission Models
| 词条 | 说明 |
|------|------|
| [pbac.md](./pbac.md) | Policy-Based Access Control，基于策略的访问控制 ✅ |
| [rbac.md](./rbac.md) | Role-Based Access Control，基于角色的访问控制 ✅ |
| [abac.md](./abac.md) | Attribute-Based Access Control，基于属性的访问控制 ✅ |

### 身份与认证 / Identity & Authentication
| 词条 | 说明 |
|------|------|
| [mfa.md](./mfa.md) | 多因素认证 ✅ |
| [totp.md](./totp.md) | TOTP 基于时间的一次性密码（RFC 6238） ✅ |
| [break-glass.md](./break-glass.md) | Break Glass 紧急访问机制 ✅ |

### 审批与监管 / Approval & Governance
| 词条 | 说明 |
|------|------|
| [approval-workflow.md](./approval-workflow.md) | 多级审批工作流 ✅ |
| [dual-custody.md](./dual-custody.md) | 双人保管（双人授权） ✅ |

## 存储与高可用 / Storage & High Availability

| 词条 | 说明 |
|------|------|
| [worm-storage.md](./worm-storage.md) | WORM 存储（一次写入，多次读取） ✅ |
| [hashchain.md](./hashchain.md) | 哈希链完整性保护 ✅ |
| [quota.md](./quota.md) | 租户配额管理 ✅ |
| [rate-limiting.md](./rate-limiting.md) | 速率限制 ✅ |

## 合规与标准 / Compliance & Standards

### 国际标准 / International Standards
| 词条 | 说明 |
|------|------|
| [fips-140.md](./fips-140.md) | FIPS 140-2/140-3 密码模块安全标准 ✅ |
| [pci-dss.md](./pci-dss.md) | PCI-DSS 支付卡行业数据安全标准 ✅ |
| [iso-27001.md](./iso-27001.md) | ISO 27001 信息安全管理 ✅ |
| [soc2.md](./soc2.md) | SOC 2 服务组织控制报告 ✅ |
| [tss.md](./tss.md) | TCG 软件栈（TSS） ✅ |

### 国内标准 / Domestic Standards
| 词条 | 说明 |
|------|------|
| [djcp.md](djcp.md) | 网络安全等级保护制度 ✅ |
| [gmt-standards.md](./gmt-standards.md) | GM/T 国密标准体系 ✅ |
| [gmt-index.md](./gmt-index.md) | GM/T 标准索引 ✅ |

## 密钥格式与互操作 / Key Formats & Interoperability

| 词条 | 说明 |
|------|------|
| [jwk.md](./jwk.md) | JSON Web Key 格式 ✅ |
| [pkcs8.md](./pkcs8.md) | PKCS#8 私钥格式 ✅ |
| [pam.md](./pam.md) | PAM 策略代理模式 ✅ |

## 安全与审计 / Security & Audit

| 词条 | 说明 |
|------|------|
| [anomaly.md](./anomaly.md) | 异常行为检测 ✅ |
| [hashchain.md](./hashchain.md) | 哈希链审计 ✅ |

---

✅ 全部 52 篇词条已双语化 / All 52 entries are now bilingual
