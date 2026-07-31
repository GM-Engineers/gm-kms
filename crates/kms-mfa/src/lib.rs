//! KMS MFA (Multi-Factor Authentication) Module
//!
//! This module provides MFA functionality for securing KMS key operations.
//! Supports TOTP (Time-based One-Time Password) as defined in RFC 6238.
//!
//! ## Features
//!
//! - TOTP generation and validation
//! - Secret key management
//! - MFA enforcement per-key or per-tenant
//! - Backup codes for account recovery

use serde::{Deserialize, Serialize};

pub mod backup_codes;
pub mod error;
pub mod totp;

pub use backup_codes::BackupCodeGenerator;
pub use error::MfaError;
pub use totp::{TotpCode, TotpConfig, TotpGenerator};

/// MFA type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MfaType {
    #[default]
    /// Time-based One-Time Password (RFC 6238)
    Totp,
    /// Hardware token (YubiKey, etc.)
    Hardware,
    /// SMS-based code (not recommended for production)
    Sms,
}

/// MFA status for a user or key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStatus {
    /// Whether MFA is enabled
    pub enabled: bool,
    /// Type of MFA enabled
    pub mfa_type: MfaType,
    /// Number of backup codes remaining
    pub backup_codes_remaining: usize,
    /// When MFA was last verified
    pub last_verified_at: Option<i64>,
}

impl Default for MfaStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            mfa_type: MfaType::Totp,
            backup_codes_remaining: 0,
            last_verified_at: None,
        }
    }
}

/// MFA requirement level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MfaLevel {
    /// No MFA required
    None,
    #[default]
    /// MFA required for sensitive operations only
    OptIn,
    /// MFA required for all key operations
    Required,
}

/// Operation types that can require MFA
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedOperation {
    /// Decrypt operation
    Decrypt,
    /// Sign operation
    Sign,
    /// Key deletion
    Delete,
    /// Key rotation
    Rotate,
    /// Export key material
    Export,
    /// Administrative operations
    Admin,
}

impl ProtectedOperation {
    /// Check if this operation is considered high-value/sensitive
    pub fn is_sensitive(&self) -> bool {
        matches!(
            self,
            Self::Delete | Self::Export | Self::Admin | Self::Rotate
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_type_default() {
        assert_eq!(MfaType::default(), MfaType::Totp);
    }

    #[test]
    fn test_mfa_level_default() {
        assert_eq!(MfaLevel::default(), MfaLevel::OptIn);
    }

    #[test]
    fn test_protected_operation_sensitivity() {
        assert!(ProtectedOperation::Delete.is_sensitive());
        assert!(ProtectedOperation::Export.is_sensitive());
        assert!(ProtectedOperation::Admin.is_sensitive());
        assert!(!ProtectedOperation::Decrypt.is_sensitive());
    }
}
