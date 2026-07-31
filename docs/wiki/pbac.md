# PBAC（基于策略的访问控制） / Policy-Based Access Control

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Policy-Based Access Control |
| **类型 Type** | 访问控制模型 / Access Control Model |
| **核心思想** | 统一的策略描述语言，支持 RBAC + ABAC 混合 / Unified policy language supporting RBAC + ABAC |
| **特点** | 声明式策略、属性丰富、决策引擎 / Declarative policies, rich attributes, decision engine |
| **实现位置** | `kms-core/src/policy.rs`（类型定义）、`kms-policy` crate（引擎）/ Type definitions, engine |


## 概述

PBAC 是一种以策略为核心的访问控制模型，它提供统一的策略描述语言，可以同时支持 RBAC 和 ABAC 的特性。PBAC 强调策略的声明式描述，而非实现细节。

## 策略结构

```rust
use kms_core::policy::{Policy, PolicyEffect, Condition};

// 创建策略
let policy = Policy::new(
    "key-access-policy",               // 策略名称
    PolicyEffect::Allow,               // 允许/拒绝
    Condition::Eq("subject.role".into(), "admin".into()),  // 条件
);

// 策略自动生成 UUID、时间戳，默认启用
// 可指定 resources/subjects 范围
policy.resources = vec!["key:prod-*".to_string()];
policy.subjects = vec!["user:admin-*".to_string()];
```

## 条件操作符

以下为 `kms-core/src/policy.rs` → `Condition` 枚举中**已实现**的操作符：

### 比较操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| `Eq` | 精确匹配（字符串） | `Condition::Eq("role", "admin")` |
| `Neq` | 不等于（字符串） | `Condition::Neq("role", "guest")` |
| `Gt` | 大于（整数） | `Condition::Gt("clearance", 3)` |
| `Gte` | 大于等于（整数） | `Condition::Gte("level", 5)` |
| `Lt` | 小于（整数） | `Condition::Lt("attempts", 3)` |
| `Lte` | 小于等于（整数） | `Condition::Lte("risk_score", 50)` |

### 字符串操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| `Contains` | 包含子串 | `Condition::Contains("email", "@company.com")` |
| `StartsWith` | 前缀匹配 | `Condition::StartsWith("dept", "eng-")` |
| `EndsWith` | 后缀匹配 | `Condition::EndsWith("resource", ".conf")` |
| `Matches` | 正则匹配 | `Condition::Matches("ip", r"^192\.168\..*")` |

### 集合操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| `In` | 值在列表中 | `Condition::In("action", vec!["encrypt".into(), "decrypt".into()])` |
| `NotIn` | 值不在列表中 | `Condition::NotIn("env", vec!["test".into()])` |

### 范围操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| `Between` | 值在区间内（字符串比较） | `Condition::Between("hour", "09", "18")` |
| `Outside` | 值在区间外（字符串比较） | `Condition::Outside("hour", "09", "18")` |

### 存在性操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| `Exists` | 属性存在 | `Condition::Exists("mfa_verified")` |
| `NotExists` | 属性不存在 | `Condition::NotExists("suspended")` |

### 逻辑组合操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| `And` | 所有条件满足 | `Condition::And(vec![cond1, cond2])` |
| `Or` | 任一条件满足 | `Condition::Or(vec![cond1, cond2])` |
| `Not` | 条件取反 | `Condition::Not(Box::new(cond))` |

## 策略评估

```rust
use kms_core::policy::{Policy, PolicyEffect, Condition, PolicyContext};

// 构建上下文
let ctx = PolicyContext::new()
    .with_attr("subject.id", "user:alice")
    .with_attr("subject.role", "admin")
    .with_attr("resource.id", "key:prod-sm4-001");

// 检查策略是否匹配
if policy.matches(&ctx) {
    match policy.effect {
        PolicyEffect::Allow => { /* 执行操作 */ }
        PolicyEffect::Deny => { /* 拒绝并记录 */ }
    }
}
```

## 与 RBAC/ABAC 的关系

```
           ┌──────────────────────┐
           │        PBAC         │
           │  (统一策略引擎)       │
           └──────────┬───────────┘
                      │
        ┌─────────────┼─────────────┐
        │            │            │
        ▼            ▼            ▼
   ┌────────┐   ┌────────┐   ┌────────┐
   │  RBAC  │   │  ABAC  │   │  ABAC  │
   │(角色层)│   │(属性层)│   │(环境层)│
   └────────┘   └────────┘   └────────┘

PBAC 可以表达：
- RBAC: Eq("role", "admin")           (Eq 操作符)
- ABAC: Gte("clearance", 5)           (Gte 操作符)
- 环境: Between("hour", "09", "18")    (Between 操作符)
```

## 优势 / Advantages

| 优势 Advantage | 说明 Description |
|--------------|----------------|
| **统一模型** / Unified Model | 一个引擎支持 RBAC + ABAC / One engine supports RBAC + ABAC |
| **声明式** / Declarative | 策略与实现分离 / Policies separated from implementation |
| **可审计** / Auditable | 所有策略版本化、可追溯 / All policies versioned and traceable |
| **可扩展** / Extensible | 易于添加新属性和新条件操作符 / Easy to add new attributes and operators |
| **外部化** / Externalized | 策略可独立存储和管理 / Policies stored and managed independently |


## 参考标准

- [NIST SP 800-162](https://doi.org/10.6028/NIST.SP.800-162) - ABAC/PBAC 指南
- [Open Policy Agent](https://www.openpolicyagent.com/) - CNCF 策略引擎
