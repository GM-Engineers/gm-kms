# Break Glass（紧急访问） / Break Glass Emergency Access

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Break Glass |
| **类型 Type** | 紧急访问机制 / Emergency Access Mechanism |
| **目的 Purpose** | 在紧急情况下绕过正常流程获取特权访问 / Bypass normal process to gain privileged access in emergencies |
| **特点** | 事后审计、时限控制、多人授权 / Post-audit, time-limited, multi-party authorization |


## 概述

Break Glass（打破玻璃）是一种紧急访问机制，允许用户在紧急情况下（如系统故障、业务中断）绕过正常审批流程获取必要的特权访问。

```
正常流程 vs Break Glass 流程：

正常流程：                    Break Glass 流程：
用户申请 ──▶ 审批 ──▶ 执行    紧急情况 ──▶ 立即执行 ──▶ 事后审计
         (正常审批)                (跳过审批，触发告警)

Break Glass 特点：
- 立即可用（无需等待审批）
- 触发告警（通知安全团队）
- 时限控制（自动回收权限）
- 完整审计（记录所有操作）
```

## 触发条件 / Trigger Conditions

| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **系统故障** / System Failure | 数据库无法访问，需要紧急恢复 / Database unreachable, emergency recovery needed |
| **业务中断** / Business Interruption | 密钥不可用导致业务停顿 / Key unavailability causing business downtime |
| **安全事件** / Security Incident | 响应正在发生的安全事件 / Responding to active security incidents |
| **人员紧急** / Personnel Emergency | 关键人员不可用，需临时替代 / Key personnel unavailable, need temporary replacement |


## 在 KMS 中的实现

```go
// Break Glass 配置
type BreakGlassConfig struct {
    Enabled        bool      // 是否启用
    MaxDuration    int64     // 最大持续时间（秒）
    RequireMFA     bool      // 是否需要 MFA
    RequireDual    bool      // 是否需要第二人授权
    NotifyRoles    []string  // 通知角色列表
    AutoRevoke     bool      // 是否自动撤销
    Cooldown       int64     // 冷却时间（秒）
}

// Break Glass 会话
type BreakGlassSession struct {
    ID           string
    UserID       string
    StartTime    time.Time
    EndTime      time.Time
    Reason       string
    ApprovedBy   []string   // 批准人（如需）
    Actions      []string   // 允许的操作
    AutoRevoked  bool
}
```

### Break Glass 操作流程

```
1. 触发 Break Glass
   用户 ──▶ KMS API: /v1/breakglass
   参数：reason, duration, mfa_token

2. 身份验证（必须 MFA）
   KMS ──▶ 验证 MFA（WebAuthn/TOTP）

3. 紧急授权
   KMS ──▶ 生成临时 Token（TTL = duration）
   KMS ──▶ 记录 BreakGlassSession
   KMS ──▶ 触发告警（Slack/邮件）

4. 执行紧急操作
   用户 ──▶ KMS API: 使用临时 Token 执行操作

5. 会话结束
   - TTL 过期自动撤销
   - 或用户主动 close
   - 或安全团队强制 revoke

6. 事后审计
   安全团队 ──▶ 审计 Break Glass 期间所有操作
   安全团队 ──▶ 评估是否需要额外补救
```

## 与正常权限的对比 / Comparison with Normal Access

| 特性 Feature | 正常流程 Normal Process | Break Glass |
|-------------|------------------------|-------------|
| **审批时间** / Approval Time | 可延迟（数小时~数天）/ Can be delayed (hours~days) | 即时 / Immediate |
| **审批流程** / Approval Flow | 完整审批链 / Full approval chain | 可能跳过 / May be skipped |
| **告警** / Alerting | 无特殊 / No special | 实时告警 / Real-time alert |
| **会话期限** / Session Duration | 较长（数小时~数天）/ Long (hours~days) | 短（建议 ≤ 4h）/ Short (≤ 4h recommended) |
| **审计深度** / Audit Depth | 标准日志 / Standard logs | 增强日志（屏幕录制）/ Enhanced (screen recording) |
| **权限范围** / Permission Scope | 正常授权范围 / Normal scope | 可扩大（需评估风险）/ Expandable (risk assessment needed) |


## 安全控制措施 / Security Controls

| 控制 Control | 说明 Description |
|-------------|----------------|
| **MFA 必须** / MFA Required | Break Glass 必须通过 MFA 验证 / Break Glass must pass MFA verification |
| **时限控制** / Time Limit | 权限自动过期（建议 ≤ 4 小时）/ Auto-expire privileges (≤ 4h recommended) |
| **双人授权** / Dual Authorization | 敏感操作需第二人批准 / Sensitive ops require second approver |
| **范围限制** / Scope Limit | 仅允许必要操作（最小权限）/ Only necessary operations (least privilege) |
| **实时告警** / Real-time Alert | 触发时立即通知安全团队 / Notify security team immediately on trigger |
| **完整审计** / Full Audit | 记录所有操作，包含屏幕操作 / Log all operations including screen |
| **冷却期** / Cooldown | 每次 Break Glass 后需间隔才能再次使用 / Require interval before next Break Glass |
| **定期审查** / Periodic Review | 事后安全团队审查合理性 / Post-event security team review |


## 通知与告警

```yaml
# Break Glass 告警配置
alerts:
  - type: "slack"
    channel: "#security-alerts"
    template: |
      🚨 Break Glass 触发
      用户: {{user_id}}
      原因: {{reason}}
      持续时间: {{duration}}
      审批人: {{approved_by}}
      状态: {{status}}

  - type: "email"
    to: ["security-team@company.com"]
    template: |
      Break Glass 事件报告

  - type: "ticket"
    system: "jira"
    project: "SEC"
    summary: "Break Glass: {{user_id}}"
```

## 合规对应 / Compliance Mapping

| 合规标准 Standard | Break Glass 要求 Requirement |
|-------------------|------------------------------|
| **等保三级** / Level 3 | 重要操作双人授权，Break Glass 作为例外机制 / Key ops require dual auth; Break Glass as exception |
| **PCI-DSS** | 紧急访问必须有记录和审计 / Emergency access must be logged and audited |
| **SOC 2** | 紧急访问需要管理批准（事后）/ Emergency access requires management approval (post-event) |


## 安全注意事项 / Security Considerations

1. **防止滥用** / Prevent Abuse：Break Glass 应作为最后手段，频繁使用需审查 / Should be last resort; frequent use requires review
2. **权限最小化** / Least Privilege：紧急权限应限制在最小必要范围 / Emergency privileges limited to minimum necessary
3. **时间限制** / Time Limit：权限应尽可能短，避免长时间暴露 / Keep privileges as short as possible
4. **完整审计** / Full Audit：记录所有操作，便于事后审查 / Log all operations for post-event review
5. **自动回收** / Auto-revoke：确保权限在到期后真正失效 / Ensure privileges truly expire after TTL


## 参考标准

- [NIST SP 800-53](https://doi.org/10.6028/NIST.SP.800-53r5) - 紧急访问控制
- [CISA Emergency Access](https://www.cisa.gov/) - 关键基础设施应急访问指南