# Dual Custody（双人授权） / Dual Custody / Dual Control

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Dual Custody / Dual Control |
| **中文** | 双人授权、双重保管 / Dual authorization, dual control |
| **类型 Type** | 安全控制机制 / Security Control Mechanism |
| **目的 Purpose** | 防止单点风险，关键操作需两人同时参与 / Prevent single point of risk; key ops require two participants |


## 概述

Dual Custody（双重保管）是一种安全控制机制，要求关键操作必须由两个或以上授权人同时参与才能执行。这防止了单个人员的恶意行为或疏忽导致的安全问题。

```
Dual Custody 执行流程：

操作请求 ──▶ 第一个人审批 ──▶ 第二个人审批 ──▶ 执行
                                    ↑
                              两人必须都同意
                              任何一人拒绝则终止
```

## 适用场景 / Applicable Scenarios

| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **密钥删除** / Key Deletion | 删除高敏感密钥需两人批准 / High-sensitivity key deletion requires two approvers |
| **密钥导出** / Key Export | 导出密钥材料需两人授权 / Key material export requires two authorizers |
| **策略修改** / Policy Change | 修改安全策略需多人批准 / Security policy changes require multi-party approval |
| **HSM 解封** / HSM Unseal | 解封 HSM 需两人操作 / HSM unseal requires two operators |
| **紧急访问** / Emergency Access | Break Glass 可能需要第二人批准 / Break Glass may require second approver |
| **审计日志删除** / Audit Log Deletion | WORM 存储的日志删除需双人授权 / WORM-stored log deletion requires dual auth |


## 在 KMS 中的实现

### M-of-N 模式

```go
// M-of-N 双人授权
type DualCustodyConfig struct {
    M int // 至少 M 人
    N int // 总共 N 人可选
}

type ApprovalRequest struct {
    ID        string
    Action    string
    Resource  string
    Requester string
    Reasons   string
    Approvals []Approval
    Status    string
}

type Approval struct {
    ApproverID   string
    ApproverRole string
    Timestamp    time.Time
    Signature    []byte // 签名证明
}

// 执行双人授权检查
func (d *DualCustodyConfig) Check(ctx *Context) error {
    requiredApprovers := d.GetRequiredApprovers(ctx.Action)

    approvals := ctx.GetApprovals()
    if len(approvals) < requiredApprovers {
        return fmt.Errorf("need %d approvals, got %d", requiredApprovers, len(approvals))
    }

    // 验证所有批准人身份
    for _, approval := range approvals {
        if !d.IsValidApprover(ctx.Action, approval.ApproverID) {
            return fmt.Errorf("invalid approver: %s", approval.ApproverID)
        }
    }

    return nil
}
```

### 操作流程

```
1. 创建授权请求
   操作员A ──▶ /v1/approvals/create
   参数：action=key_delete, key_id=xxx, reason="安全合规"

2. 系统生成审批请求
   系统 ──▶ 通知相关审批人（B、C、D）

3. 第一人审批
   操作员B ──▶ /v1/approvals/{id}/approve
   签名：使用私钥签名审批意图

4. 第二人审批（可选）
   操作员C ──▶ /v1/approvals/{id}/approve

5. 达到 M-of-N 要求
   系统 ──▶ 执行实际操作
   系统 ──▶ 记录完整审批链

6. 拒绝处理
   任何审批人拒绝 ──▶ 终止操作
   系统 ──▶ 记录拒绝原因
```

## 审批人选择策略 / Approver Selection Strategies

| 策略 Strategy | 说明 Description | 示例 Example |
|-------------|----------------|------------|
| **固定角色** / Fixed Role | 特定角色（如 security-officer）必须参与 / Specific roles (e.g., security-officer) must participate | 合规操作 / Compliance ops |
| **部门分离** / Dept Separation | 审批人不能与申请人同部门 / Approvers cannot be from same dept as requester | 财务相关 / Finance-related |
| **地理分离** / Geo Separation | 审批人不能在同一物理位置 / Approvers cannot be at same physical location | 高敏感操作 / High-sensitivity ops |
| **职能分离** / Role Separation | 操作员不能审批自己的操作 / Operators cannot approve their own actions | 审计要求 / Audit requirements |


```yaml
# 审批规则配置
dual_custody_rules:
  - action: "key_delete"
    m: 2
    n: 3
    required_roles: ["security-officer", "audit-officer"]
    exclude_requester: true

  - action: "key_export"
    m: 2
    n: 2
    required_roles: ["security-officer"]
    require_different_departments: true

  - action: "policy_modify"
    m: 3
    n: 5
    required_roles: ["security-officer", "compliance-officer", "it-director"]
```

## 与 Break Glass 的关系

```
Break Glass 中的 Dual Custody：

场景：严重故障，需要立即删除密钥

正常流程：用户A申请 ──▶ 用户B审批 ──▶ 执行

Break Glass 场景：
  用户A 触发 Break Glass（MFA 验证）
  用户A 立即执行（无需等待）
  系统通知用户B（B 可以否决）

这仍是 Dual Custody：
  - 操作前：MFA 认证（A 的身份）
  - 操作后：B 有机会否决或审查
```

## 合规要求 / Compliance Requirements

| 合规标准 Standard | Dual Custody 要求 Requirement |
|-------------------|------------------------------|
| **等保三级** / Level 3 | 重要操作需双人授权（关键密钥操作）/ Key ops require dual authorization |
| **PCI-DSS** | 超级用户访问需双重控制 / Superuser access requires dual control |
| **SOC 2** | 敏感操作需要多个审批点 / Sensitive ops require multiple approval points |
| **银行合规** / Banking Reg | 密钥操作需双人完成（行业规范）/ Key ops must be dual-performed (industry norm) |


## 实现注意事项 / Implementation Notes

1. **审批人身份验证** / Approver Verification：每次审批都需要强身份验证（MFA）/ Strong auth (MFA) required for each approval
2. **操作原子性** / Atomicity：如果执行失败，整个操作回滚 / Rollback entire operation on failure
3. **审批超时** / Approval Timeout：审批请求应有超时限制 / Approval requests should have timeout limits
4. **拒绝追溯** / Rejection Trace：拒绝操作需要记录原因 / Rejected operations must record reasons
5. **完整性保护** / Integrity Protection：审批链不可被篡改（签名保护）/ Approval chain must be tamper-proof (signature-protected)


## 参考标准

- [NIST SP 800-53](https://doi.org/10.6028/NIST.SP.800-53r5) - AC-3 多重控制
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/) - 密钥管理要求
- [ISO 27001](https://www.iso.org/standard/27001) - 访问控制措施