# ABAC（基于属性的访问控制） / Attribute-Based Access Control

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Attribute-Based Access Control |
| **类型 Type** | 访问控制模型 / Access Control Model |
| **核心思想** | 基于用户、资源、环境的属性进行决策 / Decisions based on user, resource, and environmental attributes |
| **标准 Standard** | NIST SP 800-162 |

## 概述

ABAC 是一种基于属性（而非角色）的访问控制模型。它通过评估用户属性、资源属性和环境属性，做出访问决策。

```
ABAC 决策模型：

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ 用户属性     │     │ 资源属性     │     │ 环境属性     │
│ (Department,│  +  │ (Owner,     │  +  │ (Time,      │
│  Clearance) │     │  Sensitivity)│     │  Location)  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────▼──────┐
                    │  PDP         │
                    │ (Policy     │
                    │  Decision   │
                    │  Point)     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   允许/拒绝   │
                    └─────────────┘
```

## 属性类型 / Attribute Types

| 类别 Category | 属性示例 Example | 说明 Description |
|--------------|----------------|----------------|
| **用户属性** / User | 部门、职级、clearance、角色 / dept, clearance, role | 主体特征 / Subject attributes |
| **资源属性** / Resource | 所有者、分类、敏感等级、创建时间 / owner, classification, sensitivity, created_at | 客体特征 / Object attributes |
| **操作属性** / Action | read、write、delete、approve | 动作类型 / Action types |
| **环境属性** / Environment | 时间、位置、设备类型、网络区域 / time, location, device_type, network_zone | 上下文 / Context |


## 策略示例 / Policy Examples

```yaml
# ABAC 策略示例
policies:
  - name: "金融部门敏感文件访问"
    condition:
      and:
        - user.department: "finance"
        - user.clearance: ">= secret"
        - resource.classification: ">= confidential"
        - environment.location: "in [CN, HK]"
        - not:
            environment.time: "weekend"

  - name: "紧急 Break Glass 访问"
    condition:
      or:
        - user.break_glass: true
        - user.emergency_auth: true
    max_duration: 24h

  - name: "开发环境密钥访问"
    condition:
      and:
        - user.role: "developer"
        - environment.env_type: "dev"
        - resource.tag: "env=dev"
```

## 在 KMS 中的应用 / KMS Applications

| 场景 Scenario | ABAC 策略 ABAC Policy |
|--------------|----------------------|
| **时间限制访问** / Time-restricted | 密钥操作仅在工作时间内允许 / Key ops allowed only during work hours |
| **位置限制** / Location-restricted | 敏感密钥仅在特定 IP 段访问 / Sensitive keys accessible only from specific IP ranges |
| **最小权限** / Least Privilege | 根据用户职级决定可访问的密钥分类 / Key classification accessible based on user clearance |
| **数据主权** / Data Sovereignty | 密钥操作记录必须在数据本地 / Key operation logs must stay in local jurisdiction |
| **动态授权** / Dynamic Auth | 临时提升权限（Just-in-Time）/ Temporary privilege elevation |


```go
// ABAC 评估引擎
type ABACEngine struct {
    policies []Policy
}

func (e *ABACEngine) Evaluate(ctx *AccessContext) (Decision, error) {
    for _, policy := range e.policies {
        if policy.Match(ctx) {
            return policy.Decide(ctx), nil
        }
    }
    // 默认拒绝
    return Deny, nil
}

type AccessContext struct {
    Subject  SubjectAttributes   // 用户属性
    Resource ResourceAttributes   // 资源属性
    Action   string               // 操作
    Env      EnvironmentAttributes // 环境属性
}

type Policy struct {
    Name      string
    Effect    string // "allow" or "deny"
    Condition *Condition
    Obligations []string // 执行时的附加操作（日志、通知）
}
```

## 与 RBAC 的对比 / RBAC Comparison

| 特性 Feature | RBAC | ABAC |
|-------------|------|------|
| **决策依据** / Decision Basis | 角色 / Role | 多维度属性 / Multi-dimensional attributes |
| **粒度** / Granularity | 粗粒度 / Coarse-grained | 细粒度 / Fine-grained |
| **灵活性** / Flexibility | 固定角色 / Fixed roles | 动态策略 / Dynamic policies |
| **管理成本** / Management Cost | 低 / Low | 中 / Medium |
| **性能开销** / Performance | 低 / Low | 中 / Medium |
| **适用场景** / Use Case | 角色稳定 / Stable roles | 复杂、动态策略 / Complex/dynamic |
| **动态性** / Dynamic | 静态分配 / Static assignment | 可动态调整 / Dynamically adjustable |


## NIST ABAC 组件 / NIST Components

| 组件 Component | 说明 Description |
|--------------|----------------|
| **PDP** | Policy Decision Point，决策点 / Evaluates access requests against policies |
| **PEP** | Policy Enforcement Point，执行点 / Enforces access decisions |
| **PIP** | Policy Information Point，属性源 / Provides attribute information |
| **PAP** | Policy Administration Point，策略管理 / Manages policies |


## 实现考虑 / Implementation Considerations

1. **属性来源** / Attribute Sources：用户属性（LDAP）、资源属性（元数据）、环境属性（上下文）/ User attrs (LDAP), resource attrs (metadata), env attrs (context)
2. **策略冲突** / Policy Conflicts：Deny 优先、First-match、Most-specific / Deny-override, first-match, most-specific
3. **性能优化** / Performance：属性缓存、决策结果缓存 / Attribute caching, decision result caching
4. **审计追溯** / Audit Trail：记录每次决策的属性和策略 / Log attributes and policies for each decision


## 参考标准

- [NIST SP 800-162](https://doi.org/10.6028/NIST.SP.800-162) - ABAC 指南
- [NIST ABAC 概念](https://csrc.nist.gov/projects/abac) - ABAC 资源