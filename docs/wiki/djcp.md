# 等保 2.0（信息安全等级保护 2.0） / Cybersecurity Level Protection 2.0

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | 信息安全等级保护 2.0 / Cybersecurity Level Protection 2.0 |
| **标准号** | GB/T 22239-2019 |
| **类型 Type** | 中国网络安全等级保护制度 / Chinese cybersecurity level protection system |
| **级别** | 五个等级（一级~五级）/ Five levels (1-5) |
| **等级** | 等保二级（建议）、等保三级（重要）/ Level 2 (recommended), Level 3 (important) |


## 概述

等保 2.0（GB/T 22239-2019）是中国网络安全等级保护制度的第二代标准，于 2019 年 12 月正式实施，替代了原有的等保 1.0 标准。它是《网络安全法》规定的法定要求，所有网络运营者都必须按照等级保护制度的要求开展网络安全等级保护工作。

> ⚠️ 注意："等保 3.0" 不是官方术语，正确表述为"等保三级（等保2.0三级）"。

## 等级划分 / Level Classification

| 等级 Level | 名称 Name | 适用场景 Scenario | 保护对象 Protected |
|-----------|----------|------------------|------------------|
| **第一级** | 自主保护级 / Self-protection | 较小、单一系统 / Small, single systems | 公民、法人 / Citizens, organizations |
| **第二级** | 指导保护级 / Guided protection | 业务系统，破坏后影响公民权益 / Business systems affecting citizens | 公民、法人 / Citizens, organizations |
| **第三级** | 监督保护级 / Supervised protection | 重要系统，破坏后影响社会秩序 / Important systems affecting social order | 社会秩序、公共利益 / Social order, public interest |
| **第四级** | 强制保护级 / Mandatory protection | 核心系统，破坏后影响国家安全 / Core systems affecting national security | 国家安全 / National security |
| **第五级** | 专控保护级 / Dedicated protection | 极端重要系统 / Extremely important systems | 国家安全 / National security |


## KMS 相关要求（等保三级） / KMS Requirements (Level 3)

| 控制项 Control | 要求 Requirement | KMS 实现 Implementation |
|--------------|----------------|---------------------|
| **身份鉴别** / Identity Authentication | 重要用户双因素认证 / Multi-factor auth for privileged users | MFA（TOTP/WebAuthn） |
| **访问控制** / Access Control | 基于策略的访问控制 / Policy-based access control | PBAC 引擎 / PBAC engine |
| **安全审计** / Security Audit | 日志保留 3 年，不可篡改 / 3-year log retention, tamper-proof | WORM + HashChain |
| **密钥管理** / Key Management | 密钥生命周期管理，HSM 保护 / Full key lifecycle, HSM protection | HSM/TPM 集成 / HSM/TPM integration |
| **数据加密** / Data Encryption | 敏感数据加密传输和存储 / Sensitive data encrypted in transit and at rest | AEAD 加密 / AEAD encryption |
| **备份恢复** / Backup/Recovery | 关键数据备份，异地容灾 / Critical data backup, DR | 多副本备份 / Multi-replica backup |


## 技术要求分类 / Technical Requirement Categories

| 类别 Category | 说明 Description |
|-------------|----------------|
| **安全物理环境** / Physical Security | 机房安全、物理访问控制 / Data center security, physical access control |
| **安全通信网络** / Network Security | 网络架构、传输加密 / Network architecture, transport encryption |
| **安全区域边界** / Perimeter Security | 边界防护、入侵检测 / Perimeter protection, intrusion detection |
| **安全计算环境** / Computing Environment | 主机安全、应用安全 / Host security, application security |
| **安全管理中心** / Security Management | 安全管理、审计中心 / Security management, audit center |


## 密码应用要求 / Cryptographic Requirements

等保 2.0 对密码应用有明确要求（对应 GM/T 0054-2018）：

| 要求项 Requirement | 说明 Description |
|--------------|----------------|
| **密码算法** / Cryptographic Algorithms | 必须使用国密算法（SM2/SM3/SM4）/ Must use GM algorithms |
| **密码产品** / Cryptographic Products | 必须使用经认证的密码产品 / Must use certified products |
| **密钥管理** / Key Management | 密钥全生命周期管理 / Full key lifecycle management |
| **合规性** / Compliance | 满足密评要求 / Meet cryptographic assessment requirements |

### 等保二级/三级密码要求 / Level 2/3 Cryptographic Requirements

| 级别 Level | 密码使用要求 Requirement |
|-----------|---------------------|
| **等保二级** / Level 2 | 建议使用，满足密评可加分 / Recommended;加分 for passing assessment |
| **等保三级** / Level 3 | 必须使用，密评必须通过 / Required; must pass assessment |


## 测评流程

```
等保测评流程：
1. 定级备案
   系统定级 ──▶ 专家评审 ──▶ 公安备案

2. 差距分析
   资产梳理 ──▶ 对标分析 ──▶ 整改方案

3. 整改建设
   安全加固 ──▶ 密码建设 ──▶ 制度建设

4. 测评验收
   机构测评 ──▶ 整改验证 ──▶ 报告出具

5. 持续监测
   定期检查 ──▶ 应急响应 ──▶ 持续改进
```

## KMS 在等保合规中的角色 / KMS Role in Level Protection Compliance

| 合规点 Compliance Point | KMS 支持 KMS Support |
|-----------------------|----------------|
| **访问控制** / Access Control | PBAC + RBAC + MFA |
| **审计日志** / Audit Logs | WORM + HashChain + 3 年保留 / 3-year retention |
| **密钥管理** / Key Management | HSM + 全生命周期管理 / Full lifecycle management |
| **数据保护** / Data Protection | 国密算法 + 信封加密 / GM algorithms + envelope encryption |
| **高可用** / High Availability | 多副本 + 故障转移 / Multi-replica + failover |
| **备份恢复** / Backup/Recovery | 异地备份 + 密钥恢复 / Remote backup + key recovery |


## 参考标准

- [GB/T 22239-2019](https://openstd.standsam.org/) - 信息安全技术 网络安全等级保护基本要求
- [GM/T 0054-2018](http://www.oscca.gov.cn/) - 信息系统密码应用基本要求
- [等保 2.0 解读](https://www.digitalchina.com/) - 等保 2.0 技术白皮书