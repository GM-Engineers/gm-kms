# SOC 2（服务组织控制报告） / Service Organization Control 2

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Service Organization Control 2 |
| **中文** | 服务组织控制报告 2 / Service Organization Control Report 2 |
| **类型 Type** | 审计报告框架 / Audit reporting framework |
| **发布机构** | AICPA（美国注册会计师协会）/ AICPA |
| **适用范围** | 提供服务的企业（云服务商、SaaS 等）/ Service organizations (cloud providers, SaaS, etc.) |


## 概述

SOC 2 是一种审计报告框架，用于评估服务组织在安全性、可用性、处理完整性、保密性和隐私方面的控制措施。它是云服务和 SaaS 供应商证明其安全性的主要方式。

## 五项信任服务准则（TSC） / Trust Service Criteria

| 准则 Criteria | 说明 Description | KMS 相关 KMS Related |
|-------------|----------------|------------------|
| **安全性** / Security | 系统和数据受保护 / Systems and data protected | 访问控制、加密 / Access control, encryption |
| **可用性** / Availability | 系统可用承诺 / System availability commitment | 高可用、故障转移 / HA, failover |
| **处理完整性** / Processing Integrity | 系统处理准确完整 / Accurate and complete processing | 数据校验、日志 / Data validation, logging |
| **保密性** / Confidentiality | 保密数据受保护 / Confidential data protected | 加密、访问控制 / Encryption, access control |
| **隐私性** / Privacy | 个人数据隐私保护 / Personal data privacy protection | 数据分类、合规 / Data classification, compliance |


## SOC 2 报告类型

| 类型 | 说明 | 有效期 |
|------|------|--------|
| **SOC 2 Type I** | 审计时点控制有效性 | 1 年 |
| **SOC 2 Type II** | 审计期间（通常 6-12 月）控制有效性 | 1 年 |

### Type I vs Type II

```
Type I：
  审计师验证 ──▶ 系统在特定时点的控制措施
  证明："截止 X 日期，控制措施已到位"
  关注：控制设计

Type II：
  审计师验证 ──▶ 过去一段时间（6-12月）的控制有效性
  证明："过去 Y 月，控制持续有效运行"
  关注：控制运行（更严格）
```

## 在 KMS 中的应用

### 安全性对应

| SOC 2 安全性要求 | KMS 实现 |
|-----------------|----------|
| **访问管理** | PBAC + MFA + 强密码策略 |
| **数据保护** | AES-256 加密、WORM 存储 |
| **密钥管理** | HSM 保护、密钥轮换、完整审计 |
| **事故响应** | 安全事件响应计划 |
| **监控** | 实时安全监控 |

### KMS SOC 2 审计范围

```go
// SOC 2 审计证据收集
type SOC2AuditEvidence struct {
    // 访问控制
    accessControlEvidence []AccessLog
    mfaEnforcementProof   MFAConfig

    // 加密
    encryptionEvidence    EncryptionConfig
    keyManagementEvidence []KeyOperation

    // 审计日志
    auditLogEvidence      AuditLogs
    logIntegrityProof     HashChainVerification

    // 可用性
    availabilityEvidence  UptimeReport
    backupEvidence        BackupRecords
}

// SOC 2 审计检查点
checkpoints := []string{
    "access-control-implemented",
    "mfa-for-privileged-access",
    "encryption-at-rest",
    "encryption-in-transit",
    "key-rotation-policy",
    "audit-log-retention",
    "incident-response-plan",
}
```

## 与其他框架的对比

| 框架 | 适用范围 | 焦点 |
|------|----------|------|
| **SOC 2** | 服务组织 | 安全、可用、隐私 |
| **ISO 27001** | 任何组织 | 信息安全管理体系 |
| **PCI-DSS** | 支付卡数据 | 支付安全 |
| **等保** | 中国网络安全 | 等级保护 |

## 常见 SOC 2 审计发现 / Common SOC 2 Audit Findings

| 发现 Finding | 问题 Issue | 修复 Remediation |
|-----------|---------|------------|
| **访问审查不足** / Insufficient Access Review | 未定期审查用户权限 / User permissions not periodically reviewed | 季度权限审查 / Quarterly permission review |
| **日志保留不足** / Insufficient Log Retention | 日志保留期短 / Log retention too short | 延长到 1 年以上 / Extend to >1 year |
| **密钥管理弱** / Weak Key Management | 无 HSM，密钥弱 / No HSM, weak keys | 部署 HSM，强制轮换 / Deploy HSM, enforce rotation |
| **事故响应缺失** / Missing Incident Response | 无正式 IRP / No formal IRP | 建立 IRP，定期演练 / Establish IRP, regular drills |
| **变更管理弱** / Weak Change Management | 变更无审批 / Changes not approved | 实施变更管理流程 / Implement change management process |


## 参考标准

- [AICPA SOC 2 指南](https://www.aicpa.org/soc2) - 官方资源
- [TSP（信任服务标准）](https://www.aicpa.org/TSP) - 信任服务标准
- [SOC 2 报告模板](https://www.aicpa.org/soc2toolkit) - 工具和模板