//! KMS Approval Workflow Module
//!
//! This module provides approval workflow functionality for sensitive KMS operations.
//! Implements multi-level approvals, timeout handling, and audit trail.
//!
//! ## Features
//!
//! - Multi-level approval chains
//! - Configurable approval thresholds
//! - Timeout-based automatic rejection
//! - Approval request status tracking
//! - Integration with audit logging

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod approver;
pub mod error;
pub mod workflow;

pub use approver::{Approver, ApproverConfig, Role};
pub use error::{ApprovalError, Result};
pub use workflow::{
    ApprovalLevel, ApprovalRequest, ApprovalStatus, BreakGlassRequest, BreakGlassStatus,
    OperationType,
};

/// Approval request with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestEntity {
    /// Unique request ID
    pub id: Uuid,

    /// Operation being requested
    pub operation: OperationType,

    /// Target resource (e.g., key ID)
    pub resource_id: String,

    /// Resource type (e.g., "key", "policy")
    pub resource_type: String,

    /// Tenant ID
    pub tenant_id: String,

    /// Requestor user ID
    pub requestor_id: String,

    /// Request justification
    pub justification: Option<String>,

    /// Current status
    pub status: ApprovalStatus,

    /// Required approval level
    pub required_level: ApprovalLevel,

    /// Current approval level reached
    pub current_level: ApprovalLevel,

    /// Approvals received
    pub approvals: Vec<ApprovalRecord>,

    /// Rejection records
    pub rejections: Vec<RejectionRecord>,

    /// When the request was created
    pub created_at: DateTime<Utc>,

    /// When the request expires
    pub expires_at: DateTime<Utc>,

    /// When the request was completed (approved or rejected)
    pub completed_at: Option<DateTime<Utc>>,

    /// Additional metadata
    pub metadata: serde_json::Value,
}

/// Record of an approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Approver ID
    pub approver_id: String,

    /// Approval level
    pub level: ApprovalLevel,

    /// When approved
    pub approved_at: DateTime<Utc>,

    /// Optional comment
    pub comment: Option<String>,
}

/// Record of a rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionRecord {
    /// Rejector ID
    pub rejector_id: String,

    /// Rejection level
    pub level: ApprovalLevel,

    /// When rejected
    pub rejected_at: DateTime<Utc>,

    /// Rejection reason
    pub reason: String,
}

/// Approval workflow engine
#[derive(Debug, Clone)]
pub struct ApprovalEngine {
    #[allow(dead_code)]
    config: ApprovalEngineConfig,
    pending_requests: std::collections::HashMap<Uuid, ApprovalRequestEntity>,
    /// Break glass emergency requests (separate from normal approval flow)
    break_glass_requests: std::collections::HashMap<Uuid, BreakGlassRequest>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ApprovalEngineConfig {
    /// Default timeout for approval requests (in hours)
    default_timeout_hours: u32,

    /// Enable automatic escalation
    auto_escalation: bool,

    /// Escalation delay (in hours)
    escalation_delay_hours: u32,
}

impl Default for ApprovalEngineConfig {
    fn default() -> Self {
        Self {
            default_timeout_hours: 24,
            auto_escalation: true,
            escalation_delay_hours: 4,
        }
    }
}

impl ApprovalEngine {
    /// Create a new approval engine
    pub fn new() -> Self {
        Self {
            config: ApprovalEngineConfig::default(),
            pending_requests: std::collections::HashMap::new(),
            break_glass_requests: std::collections::HashMap::new(),
        }
    }

    /// Create a new approval request
    #[allow(clippy::too_many_arguments)]
    pub fn create_request(
        &mut self,
        operation: OperationType,
        resource_id: &str,
        resource_type: &str,
        tenant_id: &str,
        requestor_id: &str,
        justification: Option<String>,
        required_level: ApprovalLevel,
    ) -> Result<ApprovalRequestEntity> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        // Calculate expiration based on required level
        let timeout_hours = match required_level {
            ApprovalLevel::None => 0,
            ApprovalLevel::Single => 12,
            ApprovalLevel::Double => 24,
            ApprovalLevel::Triple => 48,
            ApprovalLevel::Manager => 8,
            ApprovalLevel::Admin => 4,
        };

        let expires_at = now + chrono::Duration::hours(timeout_hours as i64);

        let request = ApprovalRequestEntity {
            id,
            operation,
            resource_id: resource_id.to_string(),
            resource_type: resource_type.to_string(),
            tenant_id: tenant_id.to_string(),
            requestor_id: requestor_id.to_string(),
            justification,
            status: ApprovalStatus::Pending,
            required_level,
            current_level: ApprovalLevel::None,
            approvals: Vec::new(),
            rejections: Vec::new(),
            created_at: now,
            expires_at,
            completed_at: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        };

        self.pending_requests.insert(id, request.clone());

        tracing::info!(
            approval_request_id = %id,
            operation = ?operation,
            resource_id = resource_id,
            required_level = ?required_level,
            "Approval request created"
        );

        Ok(request)
    }

    /// Approve a request
    pub fn approve(
        &mut self,
        request_id: Uuid,
        approver_id: &str,
        approver_role: Role,
        comment: Option<String>,
    ) -> Result<ApprovalRequestEntity> {
        // Determine approval level for this approver first (before mutable borrow)
        let approval_level = self.determine_approval_level(approver_role);

        let request = self
            .pending_requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::RequestNotFound)?;

        // Prevent self-approval
        if request.requestor_id == approver_id {
            return Err(ApprovalError::SelfApproval);
        }

        // Check if already completed
        if request.status.isTerminal() {
            return Err(ApprovalError::RequestAlreadyCompleted);
        }

        // Check if expired
        if Utc::now() > request.expires_at {
            request.status = ApprovalStatus::Expired;
            request.completed_at = Some(Utc::now());
            return Err(ApprovalError::RequestExpired);
        }

        // Check if approver already voted
        if request
            .approvals
            .iter()
            .any(|a| a.approver_id == approver_id)
        {
            return Err(ApprovalError::AlreadyVoted);
        }

        if request
            .rejections
            .iter()
            .any(|r| r.rejector_id == approver_id)
        {
            return Err(ApprovalError::AlreadyVoted);
        }

        // Record approval
        let record = ApprovalRecord {
            approver_id: approver_id.to_string(),
            level: approval_level,
            approved_at: Utc::now(),
            comment,
        };

        request.approvals.push(record);
        request.current_level = approval_level;

        tracing::info!(
            approval_request_id = %request_id,
            approver_id = approver_id,
            approval_level = ?approval_level,
            "Request approved by approver"
        );

        // Check if required level reached
        if Self::check_approval_complete(request) {
            request.status = ApprovalStatus::Approved;
            request.completed_at = Some(Utc::now());

            tracing::info!(
                approval_request_id = %request_id,
                "Approval request fully approved"
            );
        }

        Ok(request.clone())
    }

    /// Reject a request
    pub fn reject(
        &mut self,
        request_id: Uuid,
        rejector_id: &str,
        rejector_role: Role,
        reason: String,
    ) -> Result<ApprovalRequestEntity> {
        // Determine level for this rejector first (before mutable borrow)
        let rejection_level = self.determine_approval_level(rejector_role);

        let request = self
            .pending_requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::RequestNotFound)?;

        // Prevent self-rejection (a requestor cannot reject their own request by themselves)
        // Note: This prevents the requestor from being the only rejector
        if request.requestor_id == rejector_id {
            return Err(ApprovalError::SelfApproval);
        }

        // Check if already completed
        if request.status.isTerminal() {
            return Err(ApprovalError::RequestAlreadyCompleted);
        }

        // Check if expired
        if Utc::now() > request.expires_at {
            request.status = ApprovalStatus::Expired;
            request.completed_at = Some(Utc::now());
            return Err(ApprovalError::RequestExpired);
        }

        // Check if already voted
        if request
            .approvals
            .iter()
            .any(|a| a.approver_id == rejector_id)
        {
            return Err(ApprovalError::AlreadyVoted);
        }

        if request
            .rejections
            .iter()
            .any(|r| r.rejector_id == rejector_id)
        {
            return Err(ApprovalError::AlreadyVoted);
        }

        // Record rejection
        let record = RejectionRecord {
            rejector_id: rejector_id.to_string(),
            level: rejection_level,
            rejected_at: Utc::now(),
            reason: reason.clone(),
        };

        request.rejections.push(record);

        tracing::warn!(
            approval_request_id = %request_id,
            rejector_id = rejector_id,
            reason = reason,
            "Approval request rejected"
        );

        // Any rejection terminates the request
        request.status = ApprovalStatus::Rejected;
        request.completed_at = Some(Utc::now());

        Ok(request.clone())
    }

    /// Cancel a request (by requestor)
    pub fn cancel(
        &mut self,
        request_id: Uuid,
        requestor_id: &str,
    ) -> Result<ApprovalRequestEntity> {
        let request = self
            .pending_requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::RequestNotFound)?;

        // Only requestor can cancel
        if request.requestor_id != requestor_id {
            return Err(ApprovalError::NotAuthorized);
        }

        // Check if already completed
        if request.status.isTerminal() {
            return Err(ApprovalError::RequestAlreadyCompleted);
        }

        request.status = ApprovalStatus::Cancelled;
        request.completed_at = Some(Utc::now());

        tracing::info!(
            approval_request_id = %request_id,
            requestor_id = requestor_id,
            "Approval request cancelled by requestor"
        );

        Ok(request.clone())
    }

    /// Get a pending request
    pub fn get_request(&self, request_id: Uuid) -> Result<ApprovalRequestEntity> {
        self.pending_requests
            .get(&request_id)
            .cloned()
            .ok_or(ApprovalError::RequestNotFound)
    }

    /// Check if an approval request exists, is for the specified operation, and is fully approved.
    ///
    /// This is the primary gate for sensitive operations like key export.
    pub fn is_approved(&self, request_id: Uuid, operation: OperationType) -> bool {
        match self.get_request(request_id) {
            Ok(req) => {
                req.operation == operation
                    && req.status == ApprovalStatus::Approved
                    && Self::check_approval_complete(&req)
            }
            Err(_) => false,
        }
    }

    /// List pending requests for a tenant
    pub fn list_pending(&self, tenant_id: &str) -> Vec<ApprovalRequestEntity> {
        self.pending_requests
            .values()
            .filter(|r| r.tenant_id == tenant_id && r.status == ApprovalStatus::Pending)
            .cloned()
            .collect()
    }

    /// List all requests for a tenant
    pub fn list_all(&self, tenant_id: &str) -> Vec<ApprovalRequestEntity> {
        self.pending_requests
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    // =========================================================================
    // Break Glass Emergency Access
    // =========================================================================

    /// Maximum break glass access duration in minutes
    const MAX_BREAK_GLASS_DURATION_MINS: u32 = 60;

    /// Create a new break glass emergency request
    ///
    /// Break glass allows emergency access when normal approval is too slow.
    /// Requires:
    /// - Emergency justification (why normal process cannot be used)
    /// - Dual custody (two approvers must confirm)
    /// - Short duration (max 60 minutes, auto-revoked)
    #[allow(clippy::too_many_arguments)]
    pub fn create_break_glass_request(
        &mut self,
        operation: OperationType,
        resource_id: &str,
        resource_type: &str,
        tenant_id: &str,
        requestor_id: &str,
        emergency_reason: String,
        first_approver_id: &str,
        second_approver_id: &str,
        duration_minutes: u32,
    ) -> Result<BreakGlassRequest> {
        // Validate dual custody - must be two different approvers
        if first_approver_id == second_approver_id {
            return Err(ApprovalError::InvalidConfig(
                "Dual custody requires two different approvers".to_string(),
            ));
        }

        // Validate duration
        let duration = duration_minutes.min(Self::MAX_BREAK_GLASS_DURATION_MINS);

        let now = Utc::now();
        let id = Uuid::new_v4();
        let expires_at = now + chrono::Duration::minutes(duration as i64);

        let request = BreakGlassRequest {
            id,
            operation,
            resource_id: resource_id.to_string(),
            resource_type: resource_type.to_string(),
            tenant_id: tenant_id.to_string(),
            requestor_id: requestor_id.to_string(),
            emergency_reason,
            first_approver_id: first_approver_id.to_string(),
            second_approver_id: second_approver_id.to_string(),
            duration_minutes: duration,
            status: BreakGlassStatus::PendingDualApproval,
            created_at: now,
            expires_at,
        };

        self.break_glass_requests.insert(id, request.clone());

        tracing::warn!(
            break_glass_id = %id,
            operation = ?operation,
            resource_id = resource_id,
            requestor_id = requestor_id,
            duration_mins = duration,
            "BREAK GLASS: Emergency access requested - requires dual approval"
        );

        Ok(request)
    }

    /// Confirm break glass by first approver
    pub fn confirm_break_glass_first(
        &mut self,
        request_id: Uuid,
        approver_id: &str,
    ) -> Result<BreakGlassRequest> {
        let request = self
            .break_glass_requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::RequestNotFound)?;

        if request.status != BreakGlassStatus::PendingDualApproval {
            return Err(ApprovalError::RequestAlreadyCompleted);
        }

        if request.first_approver_id != approver_id {
            return Err(ApprovalError::NotAuthorized);
        }

        if Utc::now() > request.expires_at {
            request.status = BreakGlassStatus::Expired;
            return Err(ApprovalError::RequestExpired);
        }

        tracing::info!(
            break_glass_id = %request_id,
            approver_id = approver_id,
            "BREAK GLASS: First approver confirmed"
        );

        Ok(request.clone())
    }

    /// Confirm break glass by second approver (activates access)
    pub fn confirm_break_glass_second(
        &mut self,
        request_id: Uuid,
        approver_id: &str,
    ) -> Result<BreakGlassRequest> {
        let request = self
            .break_glass_requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::RequestNotFound)?;

        if request.status != BreakGlassStatus::PendingDualApproval {
            return Err(ApprovalError::RequestAlreadyCompleted);
        }

        if request.second_approver_id != approver_id {
            return Err(ApprovalError::NotAuthorized);
        }

        if Utc::now() > request.expires_at {
            request.status = BreakGlassStatus::Expired;
            return Err(ApprovalError::RequestExpired);
        }

        // Activate the break glass access
        request.status = BreakGlassStatus::Activated;

        tracing::warn!(
            break_glass_id = %request_id,
            approver_id = approver_id,
            expires_at = ?request.expires_at,
            "BREAK GLASS: Emergency access ACTIVATED - auto-expires in {} minutes",
            request.duration_minutes
        );

        Ok(request.clone())
    }

    /// Cancel break glass request (by requestor)
    pub fn cancel_break_glass(
        &mut self,
        request_id: Uuid,
        requestor_id: &str,
    ) -> Result<BreakGlassRequest> {
        let request = self
            .break_glass_requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::RequestNotFound)?;

        if request.requestor_id != requestor_id {
            return Err(ApprovalError::NotAuthorized);
        }

        if request.status == BreakGlassStatus::Activated
            || request.status == BreakGlassStatus::Expired
        {
            return Err(ApprovalError::RequestAlreadyCompleted);
        }

        request.status = BreakGlassStatus::Cancelled;

        tracing::info!(
            break_glass_id = %request_id,
            requestor_id = requestor_id,
            "BREAK GLASS: Cancelled by requestor"
        );

        Ok(request.clone())
    }

    /// Check and expire break glass requests (called periodically)
    pub fn cleanup_expired_break_glass(&mut self) -> usize {
        let now = Utc::now();
        let mut cleaned = 0;

        for request in self.break_glass_requests.values_mut() {
            if request.status == BreakGlassStatus::Activated && now > request.expires_at {
                request.status = BreakGlassStatus::Expired;
                cleaned += 1;

                tracing::warn!(
                    break_glass_id = %request.id,
                    "BREAK GLASS: Emergency access auto-expired"
                );
            }
        }

        cleaned
    }

    /// Get break glass request
    pub fn get_break_glass(&self, request_id: Uuid) -> Result<BreakGlassRequest> {
        self.break_glass_requests
            .get(&request_id)
            .cloned()
            .ok_or(ApprovalError::RequestNotFound)
    }

    /// Check if break glass access is currently active for a resource
    pub fn is_break_glass_active(&self, resource_id: &str) -> bool {
        let now = Utc::now();
        self.break_glass_requests.values().any(|r| {
            r.resource_id == resource_id
                && r.status == BreakGlassStatus::Activated
                && now <= r.expires_at
        })
    }

    /// List active break glass requests for a tenant
    pub fn list_active_break_glass(&self, _tenant_id: &str) -> Vec<BreakGlassRequest> {
        let now = Utc::now();
        self.break_glass_requests
            .values()
            .filter(|r| r.status == BreakGlassStatus::Activated && now <= r.expires_at)
            .cloned()
            .collect()
    }

    /// Clean up expired requests
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let mut cleaned = 0;

        for request in self.pending_requests.values_mut() {
            if request.status == ApprovalStatus::Pending && now > request.expires_at {
                request.status = ApprovalStatus::Expired;
                request.completed_at = Some(now);
                cleaned += 1;

                tracing::info!(
                    approval_request_id = %request.id,
                    "Expired approval request cleaned up"
                );
            }
        }

        cleaned
    }

    fn determine_approval_level(&self, role: Role) -> ApprovalLevel {
        match role {
            Role::User => ApprovalLevel::Single,
            Role::Operator => ApprovalLevel::Double,
            Role::Manager => ApprovalLevel::Triple,
            Role::Admin => ApprovalLevel::Admin,
            Role::SecurityOfficer => ApprovalLevel::Manager,
        }
    }

    fn check_approval_complete(request: &ApprovalRequestEntity) -> bool {
        // For now, single approval is enough for most operations
        // Double and triple require multiple different approvers
        match request.required_level {
            ApprovalLevel::None => true,
            ApprovalLevel::Single => !request.approvals.is_empty(),
            ApprovalLevel::Double => request.approvals.len() >= 2,
            ApprovalLevel::Triple => request.approvals.len() >= 3,
            ApprovalLevel::Manager => {
                // Need at least one manager-level approval
                request
                    .approvals
                    .iter()
                    .any(|a| a.level == ApprovalLevel::Manager)
            }
            ApprovalLevel::Admin => {
                // Need admin approval
                request
                    .approvals
                    .iter()
                    .any(|a| a.level == ApprovalLevel::Admin)
            }
        }
    }
}

impl Default for ApprovalEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_approval_request() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                Some("Cleaning up old keys".to_string()),
                ApprovalLevel::Single,
            )
            .unwrap();

        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(request.resource_id, "key-123");
        assert!(request.expires_at > request.created_at);
    }

    #[test]
    fn test_approve_request() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Single,
            )
            .unwrap();

        let approved = engine
            .approve(request.id, "approver-1", Role::Manager, None)
            .unwrap();

        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert!(approved.completed_at.is_some());
        assert_eq!(approved.approvals.len(), 1);
    }

    #[test]
    fn test_reject_request() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Single,
            )
            .unwrap();

        let rejected = engine
            .reject(
                request.id,
                "approver-1",
                Role::Manager,
                "Not authorized to delete this key".to_string(),
            )
            .unwrap();

        assert_eq!(rejected.status, ApprovalStatus::Rejected);
        assert!(rejected.completed_at.is_some());
        assert_eq!(rejected.rejections.len(), 1);
    }

    #[test]
    fn test_double_approval_required() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyExport,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Double,
            )
            .unwrap();

        // First approval - still pending
        let partial = engine
            .approve(request.id, "approver-1", Role::Operator, None)
            .unwrap();

        assert_eq!(partial.status, ApprovalStatus::Pending);
        assert_eq!(partial.approvals.len(), 1);

        // Second approval - complete
        let approved = engine
            .approve(request.id, "approver-2", Role::Manager, None)
            .unwrap();

        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.approvals.len(), 2);
    }

    #[test]
    fn test_cancel_by_requestor() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Single,
            )
            .unwrap();

        let cancelled = engine.cancel(request.id, "user-1").unwrap();

        assert_eq!(cancelled.status, ApprovalStatus::Cancelled);
    }

    #[test]
    fn test_cancel_by_non_requestor_fails() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Single,
            )
            .unwrap();

        let result = engine.cancel(request.id, "other-user");

        assert!(result.is_err());
    }

    #[test]
    fn test_self_approval_prevented() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Single,
            )
            .unwrap();

        // Try to approve own request - should fail
        let result = engine.approve(request.id, "user-1", Role::Manager, None);
        assert!(matches!(result, Err(ApprovalError::SelfApproval)));
    }

    #[test]
    fn test_self_rejection_prevented() {
        let mut engine = ApprovalEngine::new();

        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Single,
            )
            .unwrap();

        // Try to reject own request - should fail
        let result = engine.reject(
            request.id,
            "user-1",
            Role::Manager,
            "Just testing".to_string(),
        );
        assert!(matches!(result, Err(ApprovalError::SelfApproval)));
    }

    #[test]
    fn test_list_pending() {
        let mut engine = ApprovalEngine::new();

        // Create two requests
        let _ = engine.create_request(
            OperationType::KeyDelete,
            "key-1",
            "key",
            "tenant-1",
            "user-1",
            None,
            ApprovalLevel::Single,
        );

        let _ = engine.create_request(
            OperationType::KeyDelete,
            "key-2",
            "key",
            "tenant-1",
            "user-1",
            None,
            ApprovalLevel::Single,
        );

        let pending = engine.list_pending("tenant-1");

        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut engine = ApprovalEngine::new();

        // Create a request
        let request = engine
            .create_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                None,
                ApprovalLevel::Single,
            )
            .unwrap();

        // Manually set it as expired
        {
            let req = engine.pending_requests.get_mut(&request.id).unwrap();
            req.expires_at = Utc::now() - chrono::Duration::hours(1);
        }

        let cleaned = engine.cleanup_expired();

        assert_eq!(cleaned, 1);

        let req = engine.get_request(request.id).unwrap();
        assert_eq!(req.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_break_glass_dual_approval() {
        let mut engine = ApprovalEngine::new();

        // Create break glass request
        let bg_request = engine
            .create_break_glass_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                "Production system down - emergency access needed".to_string(),
                "approver-1",
                "approver-2",
                30,
            )
            .unwrap();

        assert_eq!(bg_request.status, BreakGlassStatus::PendingDualApproval);
        assert_eq!(bg_request.duration_minutes, 30);

        // First approver confirms
        let confirmed = engine
            .confirm_break_glass_first(bg_request.id, "approver-1")
            .unwrap();
        assert_eq!(confirmed.status, BreakGlassStatus::PendingDualApproval);

        // Second approver confirms - activates access
        let activated = engine
            .confirm_break_glass_second(bg_request.id, "approver-2")
            .unwrap();
        assert_eq!(activated.status, BreakGlassStatus::Activated);
    }

    #[test]
    fn test_break_glass_same_approver_rejected() {
        let mut engine = ApprovalEngine::new();

        // Try to create with same approver - should fail
        let result = engine.create_break_glass_request(
            OperationType::KeyDelete,
            "key-123",
            "key",
            "tenant-1",
            "user-1",
            "Emergency".to_string(),
            "approver-1",
            "approver-1", // Same - should fail
            30,
        );

        assert!(matches!(result, Err(ApprovalError::InvalidConfig(_))));
    }

    #[test]
    fn test_break_glass_auto_expire() {
        let mut engine = ApprovalEngine::new();

        let bg_request = engine
            .create_break_glass_request(
                OperationType::KeyDelete,
                "key-123",
                "key",
                "tenant-1",
                "user-1",
                "Emergency".to_string(),
                "approver-1",
                "approver-2",
                1, // 1 minute
            )
            .unwrap();

        // Manually expire the request
        {
            let req = engine.break_glass_requests.get_mut(&bg_request.id).unwrap();
            req.expires_at = Utc::now() - chrono::Duration::minutes(1);
        }

        // Try to confirm - should fail with expired
        let result = engine.confirm_break_glass_second(bg_request.id, "approver-2");
        assert!(matches!(result, Err(ApprovalError::RequestExpired)));
    }
}
