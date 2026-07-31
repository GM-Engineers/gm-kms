//! Approver Management
//!
//! Types and traits for managing approvers and their roles

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Approver role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Regular user - can only approve low-risk operations
    User,
    /// Operator - can approve medium-risk operations
    Operator,
    /// Manager - can approve most operations
    Manager,
    /// Administrator - can approve all operations
    Admin,
    /// Security Officer - special role for security-critical operations
    SecurityOfficer,
}

impl Role {
    /// Get the approval level this role can provide
    pub fn approval_level(&self) -> super::ApprovalLevel {
        match self {
            Role::User => super::ApprovalLevel::Single,
            Role::Operator => super::ApprovalLevel::Double,
            Role::Manager => super::ApprovalLevel::Triple,
            Role::Admin => super::ApprovalLevel::Admin,
            Role::SecurityOfficer => super::ApprovalLevel::Manager,
        }
    }

    /// Check if this role can approve a specific operation
    pub fn can_approve_operation(&self, operation: super::OperationType) -> bool {
        let required_level = operation.default_required_level();
        self.approval_level() >= required_level
    }
}

/// Approver entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approver {
    /// Approver ID
    pub id: String,

    /// Approver name
    pub name: String,

    /// Approver email
    pub email: String,

    /// Role
    pub role: Role,

    /// Tenant ID (for multi-tenant)
    pub tenant_id: String,

    /// Whether approver is active
    pub active: bool,
}

impl Approver {
    /// Create a new approver
    pub fn new(id: &str, name: &str, email: &str, role: Role, tenant_id: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            email: email.to_string(),
            role,
            tenant_id: tenant_id.to_string(),
            active: true,
        }
    }
}

/// Approver configuration
#[derive(Debug, Clone)]
pub struct ApproverConfig {
    /// Map of approver ID to approver
    approvers: HashMap<String, Approver>,

    /// Map of tenant ID to approver IDs
    tenant_approvers: HashMap<String, Vec<String>>,
}

impl ApproverConfig {
    /// Create a new approver config
    pub fn new() -> Self {
        Self {
            approvers: HashMap::new(),
            tenant_approvers: HashMap::new(),
        }
    }

    /// Add an approver
    pub fn add_approver(&mut self, approver: Approver) {
        self.approvers.insert(approver.id.clone(), approver.clone());

        self.tenant_approvers
            .entry(approver.tenant_id.clone())
            .or_default()
            .push(approver.id);
    }

    /// Get an approver by ID
    pub fn get(&self, id: &str) -> Option<&Approver> {
        self.approvers.get(id)
    }

    /// Get all approvers for a tenant
    pub fn list_for_tenant(&self, tenant_id: &str) -> Vec<&Approver> {
        self.tenant_approvers
            .get(tenant_id)
            .map(|ids| ids.iter().filter_map(|id| self.approvers.get(id)).collect())
            .unwrap_or_default()
    }

    /// Check if a user can approve a specific operation
    pub fn can_approve(&self, approver_id: &str, operation: super::OperationType) -> bool {
        self.approvers
            .get(approver_id)
            .map(|a| a.active && a.role.can_approve_operation(operation))
            .unwrap_or(false)
    }
}

impl Default for ApproverConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_approval_level() {
        assert_eq!(
            Role::User.approval_level(),
            super::super::ApprovalLevel::Single
        );
        assert_eq!(
            Role::Operator.approval_level(),
            super::super::ApprovalLevel::Double
        );
        assert_eq!(
            Role::Manager.approval_level(),
            super::super::ApprovalLevel::Triple
        );
        assert_eq!(
            Role::Admin.approval_level(),
            super::super::ApprovalLevel::Admin
        );
    }

    #[test]
    fn test_approver_can_approve() {
        let mut config = ApproverConfig::new();

        config.add_approver(Approver::new(
            "user-1",
            "Test User",
            "user@test.com",
            Role::User,
            "tenant-1",
        ));

        assert!(config.can_approve("user-1", super::super::OperationType::AuditAccess));

        assert!(!config.can_approve("user-1", super::super::OperationType::KeyDelete));

        let manager = Approver::new(
            "mgr-1",
            "Test Manager",
            "mgr@test.com",
            Role::Manager,
            "tenant-1",
        );
        config.add_approver(manager);

        assert!(config.can_approve("mgr-1", super::super::OperationType::KeyDelete));
    }

    #[test]
    fn test_list_approvers_for_tenant() {
        let mut config = ApproverConfig::new();

        config.add_approver(Approver::new(
            "user-1",
            "User One",
            "u1@test.com",
            Role::User,
            "tenant-1",
        ));

        config.add_approver(Approver::new(
            "mgr-1",
            "Manager One",
            "m1@test.com",
            Role::Manager,
            "tenant-1",
        ));

        config.add_approver(Approver::new(
            "user-2",
            "User Two",
            "u2@test.com",
            Role::User,
            "tenant-2",
        ));

        let tenant1_approvers = config.list_for_tenant("tenant-1");
        assert_eq!(tenant1_approvers.len(), 2);

        let tenant2_approvers = config.list_for_tenant("tenant-2");
        assert_eq!(tenant2_approvers.len(), 1);
    }
}
