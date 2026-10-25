//! Approval API Layer - Simplified
//!
//! Approval types for API integration

use crate::KmsMetrics;
use kms_approval::{ApprovalEngine, ApprovalError, ApprovalLevel, OperationType, Role};
use serde::Serialize;
use std::sync::Arc;

/// Approval Manager for handling approval workflow operations
#[derive(Clone)]
pub struct ApprovalManager {
    engine: ApprovalEngine,
    metrics: Arc<KmsMetrics>,
}

impl ApprovalManager {
    pub fn new(metrics: Arc<KmsMetrics>) -> Self {
        Self {
            engine: ApprovalEngine::new(),
            metrics,
        }
    }

    /// Create an approval request
    #[allow(clippy::too_many_arguments)]
    pub fn create_request(
        &mut self,
        operation: OperationType,
        resource_id: &str,
        resource_type: &str,
        tenant_id: &str,
        requestor_id: &str,
        justification: Option<String>,
        required_level: Option<ApprovalLevel>,
    ) -> Option<ApprovalRequestResponse> {
        let level = required_level.unwrap_or_else(|| operation.default_required_level());

        let request = self
            .engine
            .create_request(
                operation,
                resource_id,
                resource_type,
                tenant_id,
                requestor_id,
                justification,
                level,
            )
            .ok()?;

        Some(request.into())
    }

    /// Check if an approval request is fully approved for the given operation and
    /// resource, and has not expired. This is the security gate for sensitive
    /// operations (key export/delete/rotate).
    pub fn is_approved(
        &self,
        request_id: uuid::Uuid,
        operation: OperationType,
        resource_id: &str,
    ) -> bool {
        self.engine.is_approved(request_id, operation, resource_id)
    }

    /// Restore a persisted approval request into the engine.
    ///
    /// Mirrors [`ApprovalEngine::restore_request`]: the request keeps its own
    /// `expires_at` and its own votes, so a request that was already expired
    /// when it was persisted stays expired and is rejected by
    /// [`Self::is_approved`]. This is the hook a persistence layer needs to
    /// re-hydrate requests across a restart without extending their lifetime.
    pub fn restore_request(
        &mut self,
        request: kms_approval::ApprovalRequestEntity,
    ) -> Result<(), ApprovalError> {
        self.engine.restore_request(request)
    }

    /// Approve a request.
    ///
    /// Returns the engine error so the caller can distinguish a self-approval,
    /// a duplicate vote, an insufficient authority level and a missing request
    /// (audit follow-up B7-a) instead of collapsing them all into "not found".
    pub fn approve(
        &mut self,
        request_id: uuid::Uuid,
        approver_id: &str,
        approver_role: Role,
        comment: Option<String>,
    ) -> Result<ApprovalRequestResponse, ApprovalError> {
        let created_at = self
            .engine
            .get_request(request_id)
            .ok()
            .map(|r| r.created_at);
        let request = self
            .engine
            .approve(request_id, approver_id, approver_role, comment)?;
        if let Some(created) = created_at {
            let duration = (chrono::Utc::now() - created).num_seconds().max(0) as u64;
            self.metrics.record_approval_chain_duration(duration);
        }
        Ok(request.into())
    }

    /// Reject a request.
    ///
    /// Returns the engine error so the caller can distinguish a self-rejection,
    /// a duplicate vote, an expired request and a missing request
    /// (audit follow-up B7-g) instead of collapsing them all into "not found".
    pub fn reject(
        &mut self,
        request_id: uuid::Uuid,
        rejector_id: &str,
        rejector_role: Role,
        reason: String,
    ) -> Result<ApprovalRequestResponse, ApprovalError> {
        let created_at = self
            .engine
            .get_request(request_id)
            .ok()
            .map(|r| r.created_at);
        let request = self
            .engine
            .reject(request_id, rejector_id, rejector_role, reason)?;
        if let Some(created) = created_at {
            let duration = (chrono::Utc::now() - created).num_seconds().max(0) as u64;
            self.metrics.record_approval_chain_duration(duration);
        }
        Ok(request.into())
    }

    /// Cancel a request
    pub fn cancel(
        &mut self,
        request_id: uuid::Uuid,
        requestor_id: &str,
    ) -> Option<ApprovalRequestResponse> {
        let request = self.engine.cancel(request_id, requestor_id).ok()?;
        Some(request.into())
    }

    /// Get a request
    pub fn get_request(&self, request_id: uuid::Uuid) -> Option<ApprovalRequestResponse> {
        let request = self.engine.get_request(request_id).ok()?;
        Some(request.into())
    }

    /// List pending requests for a tenant
    pub fn list_pending(&self, tenant_id: &str) -> Vec<ApprovalRequestResponse> {
        self.engine
            .list_pending(tenant_id)
            .into_iter()
            .map(|r| r.into())
            .collect()
    }
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new(Arc::new(KmsMetrics::new()))
    }
}

/// Approval request API response
#[derive(Debug, Serialize)]
pub struct ApprovalRequestResponse {
    pub id: String,
    pub operation: String,
    pub resource_id: String,
    pub resource_type: String,
    pub tenant_id: String,
    pub requestor_id: String,
    pub justification: Option<String>,
    pub status: String,
    pub required_level: String,
    pub current_level: String,
    pub approvals_count: usize,
    pub rejections_count: usize,
    pub created_at: String,
    pub expires_at: String,
    pub completed_at: Option<String>,
}

impl From<kms_approval::ApprovalRequestEntity> for ApprovalRequestResponse {
    fn from(entity: kms_approval::ApprovalRequestEntity) -> Self {
        Self {
            id: entity.id.to_string(),
            operation: operation_to_string(entity.operation),
            resource_id: entity.resource_id,
            resource_type: entity.resource_type,
            tenant_id: entity.tenant_id,
            requestor_id: entity.requestor_id,
            justification: entity.justification,
            status: status_to_string(entity.status),
            required_level: level_to_string(entity.required_level),
            current_level: level_to_string(entity.current_level),
            approvals_count: entity.approvals.len(),
            rejections_count: entity.rejections.len(),
            created_at: entity.created_at.to_rfc3339(),
            expires_at: entity.expires_at.to_rfc3339(),
            completed_at: entity.completed_at.map(|t| t.to_rfc3339()),
        }
    }
}

fn operation_to_string(op: OperationType) -> String {
    match op {
        OperationType::KeyDelete => "key_delete".to_string(),
        OperationType::KeyExport => "key_export".to_string(),
        OperationType::KeyRotate => "key_rotate".to_string(),
        OperationType::PolicyChange => "policy_change".to_string(),
        OperationType::HighValueKeyCreate => "high_value_key_create".to_string(),
        OperationType::AuditAccess => "audit_access".to_string(),
        OperationType::MfaChange => "mfa_change".to_string(),
        OperationType::TenantAdmin => "tenant_admin".to_string(),
    }
}

fn status_to_string(status: kms_approval::ApprovalStatus) -> String {
    match status {
        kms_approval::ApprovalStatus::Pending => "pending".to_string(),
        kms_approval::ApprovalStatus::Approved => "approved".to_string(),
        kms_approval::ApprovalStatus::Rejected => "rejected".to_string(),
        kms_approval::ApprovalStatus::Cancelled => "cancelled".to_string(),
        kms_approval::ApprovalStatus::Expired => "expired".to_string(),
        kms_approval::ApprovalStatus::EmergencyActivated => "emergency_activated".to_string(),
        kms_approval::ApprovalStatus::EmergencyExpired => "emergency_expired".to_string(),
    }
}

fn level_to_string(level: ApprovalLevel) -> String {
    match level {
        ApprovalLevel::None => "none".to_string(),
        ApprovalLevel::Single => "single".to_string(),
        ApprovalLevel::Double => "double".to_string(),
        ApprovalLevel::Triple => "triple".to_string(),
        ApprovalLevel::Manager => "manager".to_string(),
        ApprovalLevel::Admin => "admin".to_string(),
    }
}

// The request DTOs that used to live here (`CreateApprovalRequest`,
// `ApproveRequest`, `RejectRequest`, `CancelRequest`) and their `to_role()`
// helpers were removed in audit follow-up B7-g: they took the approver's
// identity and authority from the request body, which is exactly the forgery
// the approval workflow must not allow. The server derives both from the
// authenticated API key (see `rest::role_from_permission`).
