# gm-kms 文档索引

> 更新日期：2026-06-23

---

## 文档目录

### [需求文档](requirements/README.md)
功能需求与验收标准。

| 文档 | 说明 |
|------|------|
| F1-key-lifecycle.md | 密钥生命周期管理 |
| F2-encryption.md | 加解密操作 |
| F3-signature.md | 数字签名服务 |
| F4-pbac.md | 策略访问控制 |
| F5-audit.md | 审计日志 |
| N1-security.md | 安全控制与租户隔离 |

### [合规性文档](compliance/)
合规性检查与标准对照。

| 文档 | 说明 |
|------|------|
| checklist.md | GM/T 标准合规性检查清单 |
| regulations-index.md | 商用密码法规标准索引 |
| sm9-curve-design.md | SM9 国密曲线切换设计 |
| self-assessment.md | 自评估报告 |

### [部署指南](guides/)
生产环境部署与运维指南。

| 文档 | 说明 |
|------|------|
| deployment-guide.md | 完整部署指南 |

### [技术词条](wiki/)
密码学与安全技术百科。

- [词条总索引](wiki/gmt-index.md) - 50 篇技术词条

#### 国密算法
| 词条 | 说明 | 标准 |
|------|------|------|
| sm2.md | SM2 椭圆曲线公钥密码 | GM/T 0003-2012 |
| sm3.md | SM3 密码杂凑算法 | GM/T 0004-2012 |
| sm4.md | SM4 分组密码算法 | GM/T 0002-2012 |
| sm9.md | SM9 标识密码算法 | GM/T 0044-2016 |

#### 国际算法
| 词条 | 说明 | 标准 |
|------|------|------|
| rsa-4096.md | RSA-4096 非对称加密 | RFC 8017 |
| ecc-p256-p384.md | ECC P-256/P-384 | FIPS 186-4 |
| edwards-curve.md | Ed25519/Ed448 | RFC 8032 |

#### 访问控制与治理
| 词条 | 说明 |
|------|------|
| rbac.md | 基于角色的访问控制 |
| abac.md | 基于属性的访问控制 |
| pbac.md | 基于策略的访问控制 |
| mfa.md | 多因素认证 |
| totp.md | 基于时间的一次性密码 |
| rate-limiting.md | 速率限制 |
| quota.md | 租户配额控制 |
| anomaly.md | 异常访问检测 |
| approval-workflow.md | 审批工作流 |

#### 合规标准
| 词条 | 说明 | 标准号 |
|------|------|--------|
| 等保.md | 信息安全等级保护 2.0 | GB/T 22239-2019 |
| gmt-standards.md | 密码行业标准 GM/T | GM/T 系列 |
| fips-140.md | 密码模块安全标准 | NIST FIPS 140-2/140-3 |
| pci-dss.md | 支付卡行业数据安全标准 | PCI-DSS v4.0 |
| soc2.md | 服务组织控制报告 2 | AICPA SOC 2 |
| iso-27001.md | 信息安全管理体系 | ISO/IEC 27001:2022 |

#### 密钥管理
| 词条 | 说明 |
|------|------|
| kek.md | 密钥加密密钥 |
| dek.md | 数据加密密钥 |
| envelope-encryption.md | 信封加密 |
| key-backup.md | 密钥备份与恢复 |
| key-import-export.md | 密钥导入导出 |
| software-keystore.md | 软件 Keystore |
| hsm.md | 硬件安全模块 |
| tpm2.md | 可信平台模块 2.0 |

#### 审计与安全
| 词条 | 说明 |
|------|------|
| hashchain.md | 哈希链审计防篡改 |
| worm-storage.md | WORM 存储 |

#### 后量子密码
| 词条 | 说明 | 标准 |
|------|------|------|
| ml-kem.md | 模块格密钥封装 (Kyber) | NIST FIPS 203 |
| ml-dsa.md | 模块格数字签名 (Dilithium) | NIST FIPS 204 |
| slh-dsa.md | 无状态哈希签名 (SPHINCS+) | NIST FIPS 205 |

---

## 快速链接

- [项目 README](../README.md) - 项目概述与快速开始
- [合规性检查清单](compliance/checklist.md) - 对照监管要求逐项检查
- [部署指南](guides/deployment-guide.md) - 生产环境部署步骤
- [SM9 曲线设计](compliance/sm9-curve-design.md) - GM/T 0044-2016 参数迁移计划

---

## 文档更新记录

| 日期 | 更新内容 |
|------|----------|
| 2026-04-29 | Wiki 梳理：新增 10 篇词条，修复含 Go 代码的词条 |
| 2026-04-29 | 修复 gmt-index.md 统计数字，创建项目 README |
| 2026-04-29 | 更新 sm9-curve-design.md 状态标注 |
| 2026-04-29 | 移除 gmt-standards.md 中 Go 代码示例 |

## 文档更新记录（续）

| 日期 | 更新内容 |
|------|----------|
| 2026-06-29 | 批量 wiki + requirements 双语化 + 内容修正（见各文件）|
