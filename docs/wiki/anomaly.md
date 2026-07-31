# Anomaly Detection（异常检测） / Anomaly Detection

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 安全监控 / Security Monitoring |
| **实现位置** | `kms-api/anomaly.rs` |
| **目的 Purpose** | 检测异常访问模式 / Detect anomalous access patterns |


## 概述

异常检测模块用于识别可疑的密钥访问模式，帮助发现潜在的安全威胁，如凭证泄露、内部威胁或攻击行为。

## 检测类型 / Detection Types

| 类型 Type | 说明 Description | 严重级别 Severity |
|----------|----------------|-------------------|
| `OffHoursAccess` | 工作时间外访问 / Access outside work hours | Medium |
| `HighFrequency` | 短时间高频访问 / High-frequency access in short period | High |
| `AuthFailure` | 认证失败过多 / Excessive authentication failures | High |
| `UnusualPattern` | 异常访问模式 / Anomalous access pattern | Medium |
| `RateLimitExceeded` | 速率限制超出 / Rate limit exceeded | Low |


## 严重级别 / Severity Levels

| 级别 Level | 值 Value | 响应 Response |
|-----------|---------|--------------|
| Low | 0 | 记录日志 / Log only |
| Medium | 1 | 记录 + 告警 / Log + alert |
| High | 2 | 记录 + 告警 + 通知管理员 / Log + alert + notify admin |
| Critical | 3 | 记录 + 告警 + 锁定账户 / Log + alert + lock account |


## 实现机制

```rust
use kms_api::anomaly::{AnomalyDetector, AnomalyAlert, AnomalyType, Severity};

// 创建检测器
let detector = AnomalyDetector::new();

// 检测访问
if let Some(alert) = detector.check_access(&context).await {
    match alert.severity {
        Severity::Critical | Severity::High => {
            // 锁定账户并通知
            lock_account(&alert.actor_id).await?;
            notify_security_team(&alert).await?;
        }
        _ => {
            // 仅记录
            tracing::warn!("Anomaly detected: {:?}", alert);
        }
    }
}
```

## 异常事件结构

```rust
pub struct AnomalyAlert {
    pub alert_id: Uuid,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub actor_id: String,
    pub tenant_id: String,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub detected_at: DateTime<Utc>,
}
```

## 检测规则

### 工作时间外访问

```rust
// 定义工作时间（当地时间）
let work_hours = (9, 18); // 9:00 - 18:00

// 检测
if !is_within_work_hours(now, work_hours) {
    return Some(AnomalyAlert::new(
        AnomalyType::OffHoursAccess,
        Severity::Medium,
        actor_id,
    ));
}
```

### 高频访问

```rust
// 阈值：每分钟超过 100 次请求
const FREQUENCY_THRESHOLD: u64 = 100;

if request_count > FREQUENCY_THRESHOLD {
    return Some(AnomalyAlert::new(
        AnomalyType::HighFrequency,
        Severity::High,
        actor_id,
    ));
}
```

## 与 SIEM 集成

异常事件可发送到 SIEM 系统：

```rust
// 输出到 Kafka 或 Splunk
async fn send_to_siem(alert: &AnomalyAlert) -> Result<()> {
    let event = serde_json::to_string(alert)?;
    kafka_producer.send("security-alerts", event.as_bytes()).await?;
    Ok(())
}
```

## 合规对应 / Compliance Mapping

| 合规标准 Standard | 要求 Requirement | 实现 Implementation |
|-------------------|----------------|-------------------|
| 等保三级 / Level 3 | 异常行为检测 / Anomaly behavior detection | ✅ AnomalyDetector |
| SOC 2 | 安全事件监控 / Security event monitoring | ✅ 异常告警 / Anomaly alerts |


## 参考资料

- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - SI-4 Incident Reporting
