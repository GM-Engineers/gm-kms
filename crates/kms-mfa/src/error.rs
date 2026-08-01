//! MFA Error Types

use thiserror::Error;

/// MFA-related errors
#[derive(Error, Debug)]
pub enum MfaError {
    #[error("MFA not enabled")]
    NotEnabled,

    #[error("invalid TOTP code")]
    InvalidCode,

    #[error("TOTP code expired")]
    CodeExpired,

    #[error("TOTP code window exceeded")]
    WindowExceeded,

    #[error("invalid secret")]
    InvalidSecret,

    #[error("backup code already used")]
    BackupCodeUsed,

    #[error("no backup codes remaining")]
    NoBackupCodes,

    #[error("too many failed backup code attempts, locked for {0} seconds")]
    BackupCodeLocked(u64),

    #[error("MFA required but not verified")]
    VerificationRequired,

    #[error("operation not permitted without MFA: {0}")]
    OperationNotPermitted(String),

    #[error("invalid MFA configuration: {0}")]
    InvalidConfig(String),

    #[error("secret generation failed: {0}")]
    SecretGenerationFailed(String),
}

pub type Result<T> = std::result::Result<T, MfaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_error_display_not_enabled() {
        let e = MfaError::NotEnabled;
        assert_eq!(e.to_string(), "MFA not enabled");
    }

    #[test]
    fn test_mfa_error_display_invalid_code() {
        let e = MfaError::InvalidCode;
        assert_eq!(e.to_string(), "invalid TOTP code");
    }

    #[test]
    fn test_mfa_error_display_code_expired() {
        let e = MfaError::CodeExpired;
        assert_eq!(e.to_string(), "TOTP code expired");
    }

    #[test]
    fn test_mfa_error_display_window_exceeded() {
        let e = MfaError::WindowExceeded;
        assert_eq!(e.to_string(), "TOTP code window exceeded");
    }

    #[test]
    fn test_mfa_error_display_invalid_secret() {
        let e = MfaError::InvalidSecret;
        assert_eq!(e.to_string(), "invalid secret");
    }

    #[test]
    fn test_mfa_error_display_backup_code_used() {
        let e = MfaError::BackupCodeUsed;
        assert_eq!(e.to_string(), "backup code already used");
    }

    #[test]
    fn test_mfa_error_display_no_backup_codes() {
        let e = MfaError::NoBackupCodes;
        assert_eq!(e.to_string(), "no backup codes remaining");
    }

    #[test]
    fn test_mfa_error_display_backup_code_locked() {
        let e = MfaError::BackupCodeLocked(300);
        assert_eq!(
            e.to_string(),
            "too many failed backup code attempts, locked for 300 seconds"
        );
    }

    #[test]
    fn test_mfa_error_display_verification_required() {
        let e = MfaError::VerificationRequired;
        assert_eq!(e.to_string(), "MFA required but not verified");
    }

    #[test]
    fn test_mfa_error_display_operation_not_permitted() {
        let e = MfaError::OperationNotPermitted("delete key".to_string());
        assert_eq!(
            e.to_string(),
            "operation not permitted without MFA: delete key"
        );
    }

    #[test]
    fn test_mfa_error_display_invalid_config() {
        let e = MfaError::InvalidConfig("bad window".to_string());
        assert_eq!(e.to_string(), "invalid MFA configuration: bad window");
    }

    #[test]
    fn test_mfa_error_display_secret_generation_failed() {
        let e = MfaError::SecretGenerationFailed("RNG error".to_string());
        assert_eq!(e.to_string(), "secret generation failed: RNG error");
    }

    #[test]
    fn test_mfa_result_type_alias() {
        fn ok_func() -> Result<i32> {
            Ok(42)
        }
        fn err_func() -> Result<i32> {
            Err(MfaError::NotEnabled)
        }
        assert_eq!(ok_func().unwrap(), 42);
        assert!(err_func().is_err());
    }

    #[test]
    fn test_mfa_error_debug() {
        let e = MfaError::BackupCodeLocked(60);
        let debug = format!("{:?}", e);
        assert!(debug.contains("BackupCodeLocked"));
        assert!(debug.contains("60"));
    }
}
