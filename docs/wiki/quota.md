# Quota（租户配额） / Tenant Quota

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 资源管理 / Resource Management |
| **实现位置** | `kms-api/quota.rs` |
| **存储 Storage** | Redis |


## 概述

配额控制用于管理每个租户的密钥资源使用量，防止资源耗尽和成本超支。

## 配额类型 / Quota Types

| 类型 Type | 说明 Description | 默认值 Default |
|---------|----------------|----------------|
| `max_keys` | 每租户最大密钥数 / Max keys per tenant | 1,000 |
| `max_requests_per_minute` | 每分钟最大请求数 / Max requests per minute | 5,000 |
| `max_requests_per_day` | 每天最大请求数 / Max requests per day | 1,000,000 |


## 实现机制

```rust
use kms_api::quota::{QuotaConfig, DEFAULT_QUOTA};

// 配额配置
let config = QuotaConfig {
    max_keys: 10000,
    max_requests_per_minute: 5000,
    max_requests_per_day: 1_000_000,
};

// 检查密钥数量
if current_key_count >= config.max_keys {
    return Err(QuotaExceeded.into());
}
```

## 配额检查流程

```
创建密钥请求
       ↓
  检查租户配额
       ↓
┌──────┴──────┐
↓              ↓
配额内         超配额
  ↓           ↓
允许创建    QuotaExceeded (402)
```

## Redis 存储结构

```
quota:{tenant_id}:keys          → 当前密钥数量
quota:{tenant_id}:requests:min  → 本分钟请求计数
quota:{tenant_id}:requests:day  → 今日请求计数
```

## 配置示例

```toml
[quota]
enabled = true
max_keys_per_tenant = 10000

# 租户级覆盖
[[quota.overrides]]
tenant_id = "enterprise-tenant"
max_keys = 100000
max_requests_per_day = 10_000_000
```

## 速率限制 vs 配额 / Rate Limiting vs Quota

| 维度 Dimension | 速率限制 Rate Limiting | 配额 Quota |
|---------------|------------------------|-----------|
| 目的 / Purpose | 防滥用 / Abuse prevention | 资源管理 / Resource management |
| 粒度 / Granularity | 请求频率 / Request frequency | 资源数量 / Resource quantity |
| 超限响应 / Over-limit Response | 429 Too Many Requests | 402 Payment Required |
| 重置周期 / Reset Period | 分钟级 / Minute-level | 天/永久 / Day/permanent |


## 参考资料

- [RFC 6585](https://datatracker.ietf.org/doc/html/rfc6585) - Additional HTTP Status Codes
