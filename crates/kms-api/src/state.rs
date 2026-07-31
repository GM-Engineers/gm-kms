//! Sub-states for KmsState decomposition
//!
//! KmsState contains diverse fields that can be grouped by concern:
//! - **SecurityState**: MFA and approval management
//! - **ObservabilityState**: Metrics and audit logging
//! - **RateLimitingState**: Rate limiting and quota tracking
//!
//! This decomposition improves single-responsibility and makes testing easier.

use crate::{ApprovalManager, KmsMetrics, MfaManager, TenantQuotaTracker, TenantRateLimiter};
use std::sync::Arc;
use parking_lot::RwLock;

/// Security-related state (MFA, approval workflows)
#[derive(Clone)]
pub struct SecurityState {
    pub mfa_manager: Arc<MfaManager>,
    pub approval_manager: Arc<RwLock<ApprovalManager>>,
}

impl SecurityState {
    pub fn new() -> Self {
        let metrics = Arc::new(KmsMetrics::new());
        Self {
            mfa_manager: Arc::new(MfaManager::new_in_memory().with_metrics((*metrics).clone())),
            approval_manager: Arc::new(RwLock::new(ApprovalManager::new(Arc::clone(&metrics)))),
        }
    }

    pub fn with_managers(mfa: MfaManager, approval: ApprovalManager) -> Self {
        Self {
            mfa_manager: Arc::new(mfa),
            approval_manager: Arc::new(RwLock::new(approval)),
        }
    }
}

impl Default for SecurityState {
    fn default() -> Self {
        Self::new()
    }
}

/// Observability-related state (metrics, audit logging)
#[derive(Clone)]
pub struct ObservabilityState {
    pub metrics: Arc<KmsMetrics>,
    pub audit_logger: Arc<dyn kms_audit::AuditLog>,
}

impl ObservabilityState {
    pub fn new(metrics: KmsMetrics, audit_logger: Arc<dyn kms_audit::AuditLog>) -> Self {
        Self {
            metrics: Arc::new(metrics),
            audit_logger,
        }
    }
}

/// Rate limiting and quota state
#[derive(Clone)]
pub struct RateLimitingState {
    pub rate_limiter: Option<Arc<TenantRateLimiter>>,
    pub quota_tracker: Option<Arc<TenantQuotaTracker>>,
}

impl RateLimitingState {
    pub fn new() -> Self {
        Self {
            rate_limiter: None,
            quota_tracker: None,
        }
    }

    pub fn with_rate_limiter(limiter: TenantRateLimiter) -> Self {
        Self {
            rate_limiter: Some(Arc::new(limiter)),
            quota_tracker: None,
        }
    }

    pub fn with_quota_tracker(tracker: TenantQuotaTracker) -> Self {
        Self {
            rate_limiter: None,
            quota_tracker: Some(Arc::new(tracker)),
        }
    }

    pub fn with_both(rate_limiter: TenantRateLimiter, quota_tracker: TenantQuotaTracker) -> Self {
        Self {
            rate_limiter: Some(Arc::new(rate_limiter)),
            quota_tracker: Some(Arc::new(quota_tracker)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rate_limiter.is_none() && self.quota_tracker.is_none()
    }
}

impl Default for RateLimitingState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_state_default() {
        let state = SecurityState::default();
        // MfaManager created (in-memory mode by default)
        assert!(state.approval_manager.try_read().is_some());
    }

    #[test]
    fn test_rate_limiting_state_empty() {
        let state = RateLimitingState::default();
        assert!(state.is_empty());
    }

    // Note: with_rate_limiter test removed - requires Redis connection
    // which is complex to set up in unit tests. RateLimitingState is
    // primarily used with real Redis connections in production.

    #[test]
    fn test_observability_state() {
        let metrics = crate::KmsMetrics::new();
        let logger = Arc::new(kms_audit::AuditLogger::with_stdout());
        let state = ObservabilityState::new(metrics, logger);
        // Just verify it was created without panic
        let _ = state.metrics.clone();
    }
}
