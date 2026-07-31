# PAM（特权访问管理） / Privileged Access Management

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Privileged Access Management |
| **类型 Type** | 安全控制和合规框架 / Security control and compliance framework |
| **核心目标** | 管理、监控、控制特权账号和访问 / Manage, monitor, and control privileged accounts and access |
| **相关概念** | 特权访问管理、特权身份管理（PIM）/ PIM (Privileged Identity Management) |


## 概述

PAM 是一套完整的安全控制和合规框架，用于管理组织中的特权账号（具有高级权限的账号），包括超级管理员、系统管理员、服务账号等。PAM 的核心原则是最小权限和职责分离。

```
PAM 架构：

┌─────────────────────────────────────────────────────────┐
│                     PAM 控制平面                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│  │  身份认证   │  │   策略引擎  │  │   审计日志  │        │
│  │  (MFA/SSO) │  │ (最小权限)  │  │ (会话录制)  │        │
│  └────────────┘  └────────────┘  └────────────┘        │
└─────────────────────────────────────────────────────────┘
           │                │                │
           ▼                ▼                ▼
┌─────────────────────────────────────────────────────────┐
│                   特权访问目标                            │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐       │
│  │ 数据库  │  │   OS   │  │   KMS  │  │  网络   │       │
│  └────────┘  └────────┘  └────────┘  └────────┘       │
└─────────────────────────────────────────────────────────┘
```

## PAM 核心组件

| 组件 | 说明 |
|------|------|
| **特权账号发现** | 自动发现所有特权账号（含遗忘的） |
| **密码保管库** | 集中存储特权凭证（密码保险箱） |
| **会话管理** | 监控和录制特权会话 |
| **审计日志** | 记录所有特权操作 |
| **即时授权** | Just-in-Time 提升权限 |
| **访问请求** | 审批工作流 |

## PAM vs IAM（身份识别管理） / IAM Comparison

| 维度 Dimension | PAM | IAM |
|---------------|-----|-----|
| **范围** / Scope | 特权账号（admin、root）/ Privileged accounts | 所有用户（员工、外包）/ All users (employees, contractors) |
| **权限级别** / Privilege Level | 高（sudo、admin） | 中低（普通用户）/ Medium-low (regular users) |
| **控制重点** / Control Focus | 防止滥用、完整审计 / Prevent abuse, full audit | 便捷访问、单点登录 / Convenient access, SSO |
| **会话时长** / Session Duration | 短（按需）/ Short (on-demand) | 长（工作日/周）/ Long (workday/week) |
| **风险级别** / Risk Level | 高 / High | 中 / Medium |


## 在 KMS 中的 PAM 集成

### 特权账号场景

| 场景 | PAM 作用 | KMS 配合 |
|------|----------|----------|
| **KMS 管理员** | 管理 KMS 的高权限账号 | 提供 KMS Admin 角色 |
| **HSM 操作员** | 管理 HSM 的物理/逻辑访问 | HSM 与 KMS 联动 |
| **审计员** | 访问审计日志的特权 | KMS 日志写 WORM |
| **密钥操作员** | 日常密钥操作的特权 | KMS PBAC 策略控制 |

### 密码保险箱集成

```go
// PAM 密码保险箱与 KMS 集成
type PrivilegedCredentialManager struct {
    vault       *PasswordVault    // PAM 保管库
    kmsClient   *KMSClient        // KMS 客户端
    auditLogger *AuditLogger       // 审计日志
}

// 申请数据库管理员密码（通过 PAM）
func (p *PrivilegedCredentialManager) GetDatabasePassword(ctx context.Context, req *CredentialRequest) (*Credential, error) {
    // 1. 验证用户身份和权限
    if err := p.validateAccess(ctx, req); err != nil {
        return nil, err
    }

    // 2. 检查 PAM 审批工作流
    approval, err := p.vault.RequestApproval(ctx, req)
    if err != nil {
        return nil, err
    }

    // 3. 从 PAM 保险箱获取密码
    cred, err := p.vault.GetCredential(req.ResourceID)
    if err != nil {
        return nil, err
    }

    // 4. 记录审计日志
    p.auditLogger.Log(ctx, "PRIV_CRED_GET", cred)

    // 5. 设置密码有效期（自动轮换）
    cred.Lease = 1 * time.Hour
    go p.autoRotate(cred)

    return cred, nil
}
```

## 即时授权（JIT）模式

```
传统模式 vs JIT 模式：

传统模式：
  用户申请管理员权限 ──▶ 审批 ──▶ 获得长期权限（数天~数月）
  问题：权限长期有效，泄露风险大

JIT 模式：
  用户申请权限 ──▶ 审批 ──▶ 获得临时权限（15分钟~2小时）
  问题：需要时请求，用完即失效
```

```yaml
# JIT 授权策略
jit_policies:
  - name: "database-admin-jit"
    trigger: "role=db-admin AND department=ops"
    approval: "single"  # 或 "dual"
    duration: "30m"
    max_per_day: 3

  - name: "kms-admin-jit"
    trigger: "role=key-operator AND emergency=true"
    approval: "dual"
    duration: "2h"
    max_per_day: 1
```

## PAM 与 KMS 的闭环

```
┌─────────────────────────────────────────────────────┐
│                   PAM 闭环                           │
│                                                      │
│   1. 特权账号生命周期管理                             │
│      账号创建 ──▶ KMS 加密存储凭证                   │
│                                                      │
│   2. 即时授权                                        │
│      申请 ──▶ 审批 ──▶ KMS 临时凭证 ──▶ 执行操作    │
│                                                      │
│   3. 会话监控                                        │
│      操作中 ──▶ 实时监控 ──▶ 异常检测               │
│                                                      │
│   4. 审计与合规                                      │
│      操作完成 ──▶ 审计日志 ──▶ 合规报告            │
│                                                      │
│   5. 凭证轮换                                        │
│      TTL 过期 ──▶ PAM 自动轮换 ──▶ 新凭证存储 KMS   │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## 合规对应 / Compliance Mapping

| 合规标准 Standard | PAM 要求 Requirement |
|-------------------|---------------------|
| **等保三级** / Level 3 | 特权账号管理、MFA、会话监控 / Privileged account management, MFA, session monitoring |
| **PCI-DSS** | 特权访问控制、密码轮换、会话审计 / Privileged access control, password rotation, session audit |
| **SOC 2** | 最小权限、访问监控、审计日志 / Least privilege, access monitoring, audit logs |
| **ISO 27001** | 特权访问管理、职责分离 / Privileged access management, separation of duties |


## 主流 PAM 产品

| 产品 | 厂商 | 特点 |
|------|------|------|
| **CyberArk** | CyberArk | 密码保险箱、会话管理 |
| **BeyondTrust** | BeyondTrust | 特权访问管理 |
| **Thycotic** | Thycotic (Delinea) | 密码管理、即时代理 |
| **HashiCorp Vault** | HashiCorp | 动态凭证、KMS |
| **Teleport** | Teleport | 开源、JIT 访问 |
| **云 PAM** | AWS SSM、Azure PIM | 云原生特权管理 |

## 实施步骤 / Implementation Steps

1. **特权账号发现** / Privileged Account Discovery：扫描所有系统和应用，找到特权账号 / Scan all systems and apps to find privileged accounts
2. **集中保管** / Centralized Storage：将所有特权凭证存入密码保险箱 / Store all privileged credentials in password vault
3. **策略制定** / Policy Definition：定义最小权限策略和审批流程 / Define least-privilege policies and approval workflows
4. **JIT 部署** / JIT Deployment：实施即时授权，减少长期权限 / Deploy just-in-time auth, reduce standing privileges
5. **会话监控** / Session Monitoring：部署会话录制和异常检测 / Deploy session recording and anomaly detection
6. **持续审计** / Continuous Audit：定期审查特权账号使用情况 / Regularly review privileged account usage


## 参考标准

- [NIST SP 800-53](https://doi.org/10.6028/NIST.SP.800-53r5) - AC-2 账户管理
- [PAM 最佳实践](https://csrc.nist.gov/projects/pam) - NIST PAM 指南
- [CIS Controls](https://www.cisecurity.org/) - 特权访问控制措施