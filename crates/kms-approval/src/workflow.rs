//! Approval Workflow Types
//!
//! Core types for approval workflow system

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Operation types that require approval
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    /// Delete a key
    KeyDelete,
    /// Export key material
    KeyExport,
    /// Rotate a key
    KeyRotate,
    /// Change key policy
    PolicyChange,
    /// Create key with high-value spec
    HighValueKeyCreate,
    /// Access audit logs
    AuditAccess,
    /// Modify MFA settings
    MfaChange,
    /// Tenant administration
    TenantAdmin,
}

impl OperationType {
    /// Get the default approval level required for this operation
    pub fn default_required_level(&self) -> ApprovalLevel {
        match self {
            // High risk - requires manager approval
            OperationType::KeyDelete => ApprovalLevel::Double,
            OperationType::KeyExport => ApprovalLevel::Triple,
            OperationType::HighValueKeyCreate => ApprovalLevel::Manager,

            // Medium risk - requires dual approval
            OperationType::KeyRotate => ApprovalLevel::Double,
            OperationType::PolicyChange => ApprovalLevel::Double,

            // Standard risk - single approval sufficient
            OperationType::AuditAccess => ApprovalLevel::Single,
            OperationType::MfaChange => ApprovalLevel::Single,
            OperationType::TenantAdmin => ApprovalLevel::Admin,
        }
    }

    /// Check if this operation is high-value/sensitive
    pub fn is_sensitive(&self) -> bool {
        matches!(
            self,
            OperationType::KeyDelete | OperationType::KeyExport | OperationType::TenantAdmin
        )
    }
}

/// Approval status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting approval
    Pending,
    /// Fully approved
    Approved,
    /// Rejected by an approver
    Rejected,
    /// Cancelled by requestor
    Cancelled,
    /// Timed out
    Expired,
    /// Emergency break glass activated (JIT access)
    EmergencyActivated,
    /// Emergency access expired (auto-revoked)
    EmergencyExpired,
}

impl ApprovalStatus {
    /// Check if this is a terminal state
    #[allow(non_snake_case)]
    pub fn isTerminal(&self) -> bool {
        matches!(
            self,
            Self::Approved | Self::Rejected | Self::Cancelled | Self::Expired
        )
    }
}

/// Approval level required/reached
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLevel {
    #[default]
    /// No approval needed
    None = 0,
    /// Single approval required
    Single = 1,
    /// Dual approval required
    Double = 2,
    /// Triple approval required
    Triple = 3,
    /// Manager-level approval required
    Manager = 4,
    /// Admin-level approval required
    Admin = 5,
}

/// Simple approval request for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Operation being requested
    pub operation: OperationType,

    /// Target resource ID
    pub resource_id: String,

    /// Resource type
    pub resource_type: String,

    /// Request justification
    pub justification: Option<String>,

    /// Required approval level (auto-calculated if not specified)
    pub required_level: Option<ApprovalLevel>,

    /// User ID of the requestor (for self-approval prevention)
    pub requestor_id: String,
}

impl ApprovalRequest {
    /// Get the effective required level
    pub fn get_required_level(&self) -> ApprovalLevel {
        self.required_level
            .unwrap_or_else(|| self.operation.default_required_level())
    }

    /// Check if an approver is the same as the requestor (self-approval prevention)
    pub fn is_self_approval(&self, approver_id: &str) -> bool {
        self.requestor_id == approver_id
    }
}

/// Break Glass emergency access request
///
/// For emergency situations where normal approval is too slow.
/// Requires dual custody (second approver must confirm) and auto-expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakGlassRequest {
    /// Unique request ID
    pub id: Uuid,
    /// Original operation being requested
    pub operation: OperationType,
    /// Target resource ID
    pub resource_id: String,
    /// Resource type
    pub resource_type: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Requestor user ID
    pub requestor_id: String,
    /// Emergency justification (required - why normal process cannot be used)
    pub emergency_reason: String,
    /// First approver (emergency authorizer)
    pub first_approver_id: String,
    /// Second approver (dual custody confirmation)
    pub second_approver_id: String,
    /// Access duration in minutes (max 60)
    pub duration_minutes: u32,
    /// Status
    pub status: BreakGlassStatus,
    /// When created
    pub created_at: chrono::DateTime<Utc>,
    /// When expires
    pub expires_at: chrono::DateTime<Utc>,
}

/// Break glass request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakGlassStatus {
    /// Awaiting second approver confirmation
    PendingDualApproval,
    /// Activated (access granted)
    Activated,
    /// Expired (auto-revoked)
    Expired,
    /// Cancelled by requestor
    Cancelled,
}
