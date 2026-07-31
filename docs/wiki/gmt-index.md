# Wiki 词条总索引 / Wiki Entry Index

> 上次更新：2026-06-29
> 共计 52 篇词条 / Total: 52 entries


---

## 一、算法/协议类

### 国密算法
| 词条 | 说明 | GM/T |
|------|------|------|
| [sm2.md](./sm2.md) | SM2 椭圆曲线公钥密码算法 | GM/T 0003-2012 |
| [sm3.md](./sm3.md) | SM3 密码杂凑算法 | GM/T 0004-2012 |
| [sm4.md](./sm4.md) | SM4 分组密码算法 | GM/T 0002-2012 |
| [sm9.md](./sm9.md) | SM9 标识密码算法 | GM/T 0044-2016 |

### 国际算法
| 词条 | 说明 | 标准 |
|------|------|------|
| [rsa-4096.md](./rsa-4096.md) | RSA-4096 非对称加密算法 | RFC 8017 |
| [ecc-p256-p384.md](./ecc-p256-p384.md) | ECC P-256 / P-384 椭圆曲线密码 | FIPS 186-4 |
| [edwards-curve.md](./edwards-curve.md) | Edwards 曲线 (Ed25519 / Ed448) | RFC 8032 |

### 密码学原语
| 词条 | 说明 | 标准 |
|------|------|------|
| [aead.md](./aead.md) | 关联数据的认证加密 | NIST SP 800-38D |
| [hkdf.md](./hkdf.md) | 基于 HMAC 的密钥派生函数 | RFC 5869 |
| [hmac.md](./hmac.md) | 基于散列函数的消息认证码 | RFC 2104 |
| [pbkdf2.md](./pbkdf2.md) | 基于口令的密钥派生函数 2 | RFC 8018 |
| [csprng.md](./csprng.md) | 密码学安全随机数生成器 | NIST SP 800-90A |

### 密钥格式
| 词条 | 说明 | 标准 |
|------|------|------|
| [pkcs8.md](./pkcs8.md) | 私钥信息语法标准 | RFC 5208 |
| [jwk.md](./jwk.md) | JSON Web Key | RFC 7517 |

### 加密架构
| 词条 | 说明 |
|------|------|
| [envelope-encryption.md](./envelope-encryption.md) | 信封加密（KEK 加密 DEK） |
| [sm2-kex.md](./sm2-kex.md) | SM2 密钥交换协议 | GM/T 0003.3-2012 |

---

## 二、密钥层次类

| 词条 | 说明 |
|------|------|
| [kek.md](./kek.md) | 密钥加密密钥（Key Encryption Key） |
| [dek.md](./dek.md) | 数据加密密钥（Data Encryption Key） |
| [key-backup.md](./key-backup.md) | 密钥备份与恢复 |
| [key-import-export.md](./key-import-export.md) | 密钥导入导出 |

---

## 三、存储/组件类

| 词条 | 说明 |
|------|------|
| [software-keystore.md](./software-keystore.md) | 软件 Keystore 实现方式 |
| [hsm.md](./hsm.md) | 硬件安全模块 |
| [tpm2.md](./tpm2.md) | 可信平台模块 2.0 |
| [vault.md](./vault.md) | HashiCorp Vault 企业级密钥管理 |
| [worm-storage.md](./worm-storage.md) | 一次写入多次读取存储 |
| [hashchain.md](./hashchain.md) | 哈希链（审计防篡改） |

---

## 四、访问控制类

| 词条 | 说明 |
|------|------|
| [rbac.md](./rbac.md) | 基于角色的访问控制 |
| [abac.md](./abac.md) | 基于属性的访问控制 |
| [pbac.md](./pbac.md) | 基于策略的访问控制 |
| [mfa.md](./mfa.md) | 多因素认证 |
| [totp.md](./totp.md) | 基于时间的一次性密码 |
| [break-glass.md](./break-glass.md) | 紧急访问机制 |
| [dual-custody.md](./dual-custody.md) | 双人授权 |
| [pam.md](./pam.md) | 特权访问管理 |
| [rate-limiting.md](./rate-limiting.md) | 速率限制 |
| [quota.md](./quota.md) | 租户配额控制 |
| [anomaly.md](./anomaly.md) | 异常访问检测 |
| [approval-workflow.md](./approval-workflow.md) | 审批工作流 |

---

## 五、后量子/高级安全类

| 词条 | 说明 | 标准 |
|------|------|------|
| [ml-kem.md](./ml-kem.md) | 模块格密钥封装机制（原 Kyber） | NIST FIPS 203 |
| [ml-dsa.md](./ml-dsa.md) | 模块格数字签名算法（原 Dilithium） | NIST FIPS 204 |
| [slh-dsa.md](./slh-dsa.md) | 无状态哈希数字签名（原 SPHINCS+） | NIST FIPS 205 |
| [forward-secrecy.md](./forward-secrecy.md) | 正向安全/完美前向保密 | TLS 1.3 |
| [sss.md](./sss.md) | Shamir 秘密分享 | 原始论文 1979 |
| [tss.md](./tss.md) | 阈值签名方案 | 分布式密码学 |

---

## 六、合规/标准类

### 中国标准
| 词条 | 说明 | 标准号 |
|------|------|--------|
| [djcp.md](djcp.md) | 信息安全等级保护 2.0 | GB/T 22239-2019 |
| [gmt-standards.md](./gmt-standards.md) | 密码行业标准（GM/T） | GM/T 系列 |

### 国际标准
| 词条 | 说明 | 标准号 |
|------|------|--------|
| [fips-140.md](./fips-140.md) | 密码模块安全标准 | NIST FIPS 140-2/140-3 |
| [pci-dss.md](./pci-dss.md) | 支付卡行业数据安全标准 | PCI-DSS v4.0 |
| [soc2.md](./soc2.md) | 服务组织控制报告 2 | AICPA SOC 2 |
| [iso-27001.md](./iso-27001.md) | 信息安全管理体系 | ISO/IEC 27001:2022 |

---

## 词汇统计

| 分类 | 篇数 |
|------|------|
| 算法/协议类 | 16 |
| 密钥层次类 | 4 |
| 存储/组件类 | 6 |
| 访问控制类 | 12 |
| 后量子/高级安全类 | 6 |
| 合规/标准类 | 6 |
| **合计** | **51** |

---

## 可信机构

| 机构 | 缩写 | 职责 | 官网 |
|------|------|------|------|
| 国家密码管理局 | OSCCA | 制定和管理国密算法标准、密码行业标准 | oscca.gov.cn |
| NIST | NIST | 美国国家标准与技术研究院，发布 FIPS 标准 | nist.gov |
| IETF | IETF | 互联网工程任务组，发布 RFC 标准 | ietf.org |
| PCI SSC | PCI SSC | 支付卡行业安全标准委员会 | pcisecuritystandards.org |
| AICPA | AICPA | 美国注册会计师协会，SOC 2 标准 | aicpa.org |
| ISO | ISO | 国际标准化组织 | iso.org |

---

## 头脑风暴文档索引

