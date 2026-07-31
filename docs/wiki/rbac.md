# RBAC（基于角色的访问控制） / Role-Based Access Control

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Role-Based Access Control |
| **类型 Type** | 访问控制模型 / Access Control Model |
| **标准 Standard** | NIST SP 800-53、FIPS 85 |
| **核心概念** | 用户 → 角色 → 权限 / User → Role → Permission |


## 概述

RBAC 是一种将权限分配给角色、再将角色分配给用户的访问控制模型。它简化了权限管理，避免了为每个用户单独配置权限的复杂性。

```
RBAC 模型：

用户 ──属于──▶ 角色 ──拥有──▶ 权限
  │                      │
  │                      ▼
  │                 可执行操作
  │                 可访问资源
  └──关联会话──▶ 激活权限
```

## 核心概念

| 概念 | 说明 |
|------|------|
| **用户（User）** | 系统中的实体（人、服务、机器） |
| **角色（Role）** | 一组权限的命名集合（如 admin、viewer） |
| **权限（Permission）** | 对资源的操作许可（如 read、write、delete） |
| **会话（Session）** | 用户激活角色的临时上下文 |
| **角色层级（Role Hierarchy）** | 角色之间的继承关系 |

## 角色层级示例

```yaml
# 角色层级定义
role_hierarchy:
  - name: "super_admin"
    inherits: ["admin", "operator", "viewer"]
  - name: "admin"
    inherits: ["operator", "viewer"]
  - name: "operator"
    inherits: ["viewer"]

# 权限分配
permissions:
  admin:
    - key:read
    - key:write
    - key:delete
    - audit:read
  operator:
    - key:read
    - key:write
    - audit:read
  viewer:
    - key:read
```

## NIST RBAC 模型

| 模型 | 说明 |
|------|------|
| **Core RBAC** | 基本角色分配，无层级 |
| **Hierarchical RBAC** | 支持角色层级继承 |
| **Constrained RBAC** | 增加职责分离约束（如双人授权） |
| **Generalized RBAC** | 完全灵活的层级和约束 |

## 在 KMS 中的应用

| 场景 | KMS 角色定义 |
|------|-------------|
| **密钥管理员** | CreateKey、DeleteKey、RotateKey |
| **密钥操作员** | Encrypt、Decrypt、Sign |
| **审计员** | ReadAuditLogs、ExportAudit |
| **租户管理员** | ManageUsers、SetQuota |
| **超级管理员** | 全部操作 |

```go
// RBAC 在 KMS 中的实现
type RBACEngine struct {
    roles     map[string]*Role
    userRoles map[string][]string
}

type Role struct {
    Name        string
    Permissions []Permission
    Parent      string // 继承关系
}

// 权限检查
func (r *RBACEngine) CheckPermission(userID, resource, action string) bool {
    roles := r.userRoles[userID]
    for _, roleName := range roles {
        role := r.roles[roleName]
        for _, perm := range role.Permissions {
            if perm.Resource == resource && perm.Action == action {
                return true
            }
        }
        // 检查继承
        if role.Parent != "" {
            parentRole := r.roles[role.Parent]
            // ...
        }
    }
    return false
}
```

## 与其他访问控制模型的对比 / Other Model Comparison

| 特性 Feature | RBAC | ABAC | PBAC |
|-------------|------|------|------|
| **控制粒度** / Granularity | 粗粒度（角色）/ Coarse-grained (role) | 细粒度（属性）/ Fine-grained (attribute) | 细粒度（策略）/ Fine-grained (policy) |
| **灵活性** / Flexibility | 中等 / Medium | 高 / High | 最高 / Highest |
| **管理复杂度** / Mgmt Complexity | 低 / Low | 中 / Medium | 中 / Medium |
| **性能** / Performance | 高 / High | 中 / Medium | 中 / Medium |
| **适用场景** / Use Case | 企业内部 / Enterprise | 复杂策略 / Complex policies | 动态策略 / Dynamic policies |
| **标准化** / Standardization | NIST 定义 / NIST-defined | NGAC、XACML | 自定义 / Custom |


## 安全注意事项 / Security Considerations

1. **最小权限原则** / Least Privilege：角色权限应按需分配 / Assign role permissions on need-to-know basis
2. **职责分离** / Separation of Duties：关键操作需要互斥角色（如审批和执行）/ Key ops require mutually exclusive roles
3. **定期审查** / Periodic Review：清理无用角色和过期权限 / Remove unused roles and expired permissions
4. **角色爆炸** / Role Explosion：避免创建过多细粒度角色 / Avoid creating too many fine-grained roles


## 参考标准

- [NIST SP 800-53](https://doi.org/10.6028/NIST.SP.800-53r5) - 访问控制类别
- [NIST RBAC 规范](https://csrc.nist.gov/publications/detail/sp/800-53/rev-4/final) - RBAC 参考
- [FIPS 85](https://csrc.nist.gov/publications/detail/fips/85/final) - RBAC 建议