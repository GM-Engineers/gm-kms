//! Approval API Layer - Simplified
//!
//! Approval types for API integration

use crate::KmsMetrics;
use kms_approval::{ApprovalEngine, ApprovalLevel, OperationType, Role};
use serde::{Deserialize, Serialize};
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

    /// Check if an approval request is fully approved for the given operation type.
    /// This is the security gate for sensitive operations (key export, etc.).
    pub fn is_approved(&self, request_id: uuid::Uuid, operation: OperationType) -> bool {
        self.engine.is_approved(request_id, operation)
    }

    /// Approve a request
    pub fn approve(
        &mut self,
        request_id: uuid::Uuid,
        approver_id: &str,
        approver_role: Role,
        comment: Option<String>,
    ) -> Option<ApprovalRequestResponse> {
        let created_at = self
            .engine
            .get_request(request_id)
            .ok()
            .map(|r| r.created_at);
        let request = self
            .engine
            .approve(request_id, approver_id, approver_role, comment)
            .ok()?;
        if let Some(created) = created_at {
            let duration = (chrono::Utc::now() - created).num_seconds().max(0) as u64;
            self.metrics.record_approval_chain_duration(duration);
        }
        Some(request.into())
    }

    /// Reject a request
    pub fn reject(
        &mut self,
        request_id: uuid::Uuid,
        rejector_id: &str,
        rejector_role: Role,
        reason: String,
    ) -> Option<ApprovalRequestResponse> {
        let created_at = self
            .engine
            .get_request(request_id)
            .ok()
            .map(|r| r.created_at);
        let request = self
            .engine
            .reject(request_id, rejector_id, rejector_role, reason)
            .ok()?;
        if let Some(created) = created_at {
            let duration = (chrono::Utc::now() - created).num_seconds().max(0) as u64;
            self.metrics.record_approval_chain_duration(duration);
        }
        Some(request.into())
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

/// Create approval request
#[derive(Debug, Deserialize)]
pub struct CreateApprovalRequest {
    pub operation: String,
    pub resource_id: String,
    pub resource_type: String,
    pub tenant_id: String,
    pub requestor_id: String,
    pub justification: Option<String>,
    pub required_level: Option<String>,
}

impl CreateApprovalRequest {
    pub fn to_operation(&self) -> Option<OperationType> {
        match self.operation.to_lowercase().as_str() {
            "key_delete" | "keydelete" => Some(OperationType::KeyDelete),
            "key_export" | "keyexport" => Some(OperationType::KeyExport),
            "key_rotate" | "keyrotate" => Some(OperationType::KeyRotate),
            "policy_change" | "policychange" => Some(OperationType::PolicyChange),
            "high_value_key_create" | "highvaluekeycreate" => {
                Some(OperationType::HighValueKeyCreate)
            }
            "audit_access" | "auditaccess" => Some(OperationType::AuditAccess),
            "mfa_change" | "mfachange" => Some(OperationType::MfaChange),
            "tenant_admin" | "tenantadmin" => Some(OperationType::TenantAdmin),
            _ => None,
        }
    }

    pub fn to_level(&self) -> Option<ApprovalLevel> {
        self.required_level
            .as_ref()
            .and_then(|l| match l.to_lowercase().as_str() {
                "none" => Some(ApprovalLevel::None),
                "single" => Some(ApprovalLevel::Single),
                "double" => Some(ApprovalLevel::Double),
                "triple" => Some(ApprovalLevel::Triple),
                "manager" => Some(ApprovalLevel::Manager),
                "admin" => Some(ApprovalLevel::Admin),
                _ => None,
            })
    }
}

/// Approve request
#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub approver_id: String,
    pub approver_role: String,
    pub comment: Option<String>,
}

impl ApproveRequest {
    pub fn to_role(&self) -> kms_approval::Role {
        match self.approver_role.to_lowercase().as_str() {
            "user" => kms_approval::Role::User,
            "operator" => kms_approval::Role::Operator,
            "manager" => kms_approval::Role::Manager,
            "admin" => kms_approval::Role::Admin,
            "security_officer" | "securityofficer" => kms_approval::Role::SecurityOfficer,
            _ => kms_approval::Role::User,
        }
    }
}

/// Reject request
#[derive(Debug, Deserialize)]
pub struct RejectRequest {
    pub rejector_id: String,
    pub rejector_role: String,
    pub reason: String,
}

impl RejectRequest {
    pub fn to_role(&self) -> kms_approval::Role {
        match self.rejector_role.to_lowercase().as_str() {
            "user" => kms_approval::Role::User,
            "operator" => kms_approval::Role::Operator,
            "manager" => kms_approval::Role::Manager,
            "admin" => kms_approval::Role::Admin,
            "security_officer" | "securityofficer" => kms_approval::Role::SecurityOfficer,
            _ => kms_approval::Role::User,
        }
    }
}

/// Cancel request
#[derive(Debug, Deserialize)]
pub struct CancelRequest {
    pub requestor_id: String,
}
