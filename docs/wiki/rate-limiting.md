# Rate Limiting（速率限制） / Rate Limiting

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 访问控制/防滥用 / Access control / Anti-abuse |
| **实现位置** | `kms-api/ratelimit.rs` |
| **算法 Algorithm** | 滑动窗口计数器 / Sliding window counter |


## 概述

速率限制用于防止 API 滥用和 DDoS 攻击。gm-kms 实现分布式滑动窗口限流，支持按租户、API Key 等维度进行限制。

## 实现机制

### 滑动窗口算法

使用 Redis 实现滑动窗口限流：

```
时间窗口（1秒）
├─────────────────────────────────────────────────────┤
│  T-60s  │  T-59s  │  ...  │  T-2s  │  T-1s  │ Now │
├─────────────────────────────────────────────────────┤
│    10   │    15   │  ...  │    8   │    5   │  2  │  ← 请求计数
└─────────────────────────────────────────────────────┘
        └──────────────────┬──────────────────┘
                     滑动窗口求和
                   = 窗口内总请求
```

### Redis 分布式存储

速率限制状态存储在 Redis，支持多实例共享：

```rust
use kms_api::ratelimit::{TenantRateLimiter, RateLimitConfig};

let limiter = TenantRateLimiter::new(
    redis_connection_manager,
    RateLimitConfig {
        requests_per_second: 100,
        requests_per_minute: 5000,
        burst_size: 200,
        fail_mode: RateLimitFailMode::FailClosed,
    },
);

// 检查请求是否允许
match limiter.check("tenant-123").await {
    Ok(remaining) => { /* 允许 */ }
    Err((retry_after_secs, _)) => { /* 拒绝 */ }
}
```

## 限流维度 / Rate Limit Dimensions

| 维度 Dimension | 说明 Description | 配置项 Config |
|---------------|----------------|--------------|
| 租户级 / Tenant-level | 每租户全局限流 / Global rate limit per tenant | `rate_limiting.requests_per_minute` |
| API Key 级 / API Key-level | 每个 API Key 限流 / Rate limit per API Key | `max_requests_per_minute` |
| 操作级 / Operation-level | 特定操作限流 / Rate limit specific ops | 敏感操作单独限制 / Separate limits for sensitive ops |


## 配置示例

```toml
[rate_limiting]
enabled = true
requests_per_minute = 1000  # 默认值

# 按租户覆盖
[[rate_limiting.overrides]]
tenant_id = "premium-tenant"
requests_per_minute = 10000
```

## 在 API 层集成

API 请求经过限流检查：

```
请求 → 认证 → 限流检查 → 配额检查 → 业务处理
                  ↓
           RateLimitExceeded (429)
```

## 响应头 / Response Headers

超过限制时返回：

| 头 Header | 说明 Description |
|---------|----------------|
| `X-RateLimit-Limit` | 窗口内最大请求数 / Max requests in window |
| `X-RateLimit-Remaining` | 剩余可用请求数 / Remaining requests |
| `X-RateLimit-Reset` | 窗口重置时间戳 / Window reset timestamp |

## 与配额的差异 / Quota Difference

| 特性 Feature | 速率限制 Rate Limiting | 配额 Quota |
|-------------|------------------------|-----------|
| 维度 / Dimension | 短时间请求频率 / Short-term frequency | 长期资源使用 / Long-term usage |
| 时间窗口 / Time Window | 秒~分钟 / Seconds~minutes | 天~月 / Days~months |
| 超出处理 / On Exceed | 延迟或拒绝 / Delay or reject | 拒绝创建新资源 / Reject new resource creation |
| 用途 / Purpose | 防滥用、防 DDoS / Abuse/DDoS prevention | 资源管理、成本控制 / Resource management, cost control |


## 参考资料

- [IETF RateLimit Header](https://datatracker.ietf.org/doc/html/rfc6585#section-4)
- [Redis sliding window](https://redis.io/commands/zadd/)
