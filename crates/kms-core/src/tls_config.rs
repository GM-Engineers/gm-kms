//! TLS configuration for database and cache connections.
//!
//! In production deployments, connections to PostgreSQL and Redis should be
//! encrypted with TLS to prevent eavesdropping on key material and metadata.
//! This module provides a unified configuration structure for both backends.

use serde::{Deserialize, Serialize};

/// TLS mode for database/cache connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// No TLS (development only; not recommended for production)
    #[default]
    Disabled,
    /// TLS with hostname verification (recommended for production)
    VerifyCa,
    /// TLS without hostname verification (useful for self-signed certs)
    NoVerify,
}

/// TLS configuration for backend connections (PostgreSQL, Redis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendTlsConfig {
    /// Whether to use TLS for the connection.
    pub mode: TlsMode,

    /// Path to CA certificate file (PEM format).
    /// Required when mode is VerifyCa.
    pub ca_cert_path: Option<String>,

    /// Path to client certificate file (PEM format) for mutual TLS.
    pub client_cert_path: Option<String>,

    /// Path to client private key file (PEM format) for mutual TLS.
    pub client_key_path: Option<String>,
}

impl BackendTlsConfig {
    /// Create a disabled TLS config (no TLS, for development).
    pub fn disabled() -> Self {
        Self {
            mode: TlsMode::Disabled,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        }
    }

    /// Create a TLS config with CA verification.
    pub fn verify_ca(ca_cert_path: String) -> Self {
        Self {
            mode: TlsMode::VerifyCa,
            ca_cert_path: Some(ca_cert_path),
            client_cert_path: None,
            client_key_path: None,
        }
    }

    /// Create a TLS config with mutual TLS (mTLS).
    pub fn mutual_tls(
        ca_cert_path: String,
        client_cert_path: String,
        client_key_path: String,
    ) -> Self {
        Self {
            mode: TlsMode::VerifyCa,
            ca_cert_path: Some(ca_cert_path),
            client_cert_path: Some(client_cert_path),
            client_key_path: Some(client_key_path),
        }
    }

    /// Whether TLS is enabled.
    pub fn is_tls_enabled(&self) -> bool {
        self.mode != TlsMode::Disabled
    }

    /// Whether mutual TLS is configured (client cert + key present).
    pub fn is_mutual_tls(&self) -> bool {
        self.client_cert_path.is_some() && self.client_key_path.is_some()
    }

    /// Load from environment variables with production-safety check.
    ///
    /// In non-dev mode, refuses `Disabled` TLS and falls back to `VerifyCa` with a warning.
    pub fn from_env() -> Self {
        let is_dev = std::env::var("KMS_DEV_MODE").as_deref() == Ok("1");
        let mode_str = std::env::var("KMS_DB_TLS_MODE")
            .unwrap_or_default()
            .to_lowercase();

        let mode = match mode_str.as_str() {
            "verify_ca" => TlsMode::VerifyCa,
            "no_verify" => TlsMode::NoVerify,
            "disabled" | "" if is_dev => {
                tracing::warn!("KMS_DEV_MODE=1: TLS disabled for database connection");
                TlsMode::Disabled
            }
            "disabled" | "" => {
                tracing::warn!(
                    "KMS_DB_TLS_MODE not set or 'disabled' in non-dev mode — \
                     defaulting to VerifyCa for production safety"
                );
                TlsMode::VerifyCa
            }
            _ => {
                tracing::warn!(
                    mode = %mode_str,
                    "Unknown KMS_DB_TLS_MODE — defaulting to VerifyCa"
                );
                TlsMode::VerifyCa
            }
        };

        Self {
            mode,
            ca_cert_path: std::env::var("KMS_DB_TLS_CA_CERT").ok(),
            client_cert_path: std::env::var("KMS_DB_TLS_CLIENT_CERT").ok(),
            client_key_path: std::env::var("KMS_DB_TLS_CLIENT_KEY").ok(),
        }
    }

    /// Build a PostgreSQL connection string with TLS parameters.
    ///
    /// Adds `sslmode` and `sslrootcert`/`sslcert`/`sslkey` query parameters
    /// to the given database URL.
    pub fn build_postgres_url(&self, base_url: &str) -> String {
        if !self.is_tls_enabled() {
            return base_url.to_string();
        }

        let sslmode = match self.mode {
            TlsMode::Disabled => "disable",
            TlsMode::VerifyCa => "verify-ca",
            TlsMode::NoVerify => "require",
        };

        let separator = if base_url.contains('?') { "&" } else { "?" };
        let mut url = format!("{}{}sslmode={}", base_url, separator, sslmode);

        if let Some(ca) = &self.ca_cert_path {
            url.push_str(&format!("&sslrootcert={}", ca));
        }
        if let Some(cert) = &self.client_cert_path {
            url.push_str(&format!("&sslcert={}", cert));
        }
        if let Some(key) = &self.client_key_path {
            url.push_str(&format!("&sslkey={}", key));
        }

        url
    }
}

impl std::fmt::Display for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMode::Disabled => write!(f, "disabled"),
            TlsMode::VerifyCa => write!(f, "verify_ca"),
            TlsMode::NoVerify => write!(f, "no_verify"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_config() {
        let config = BackendTlsConfig::disabled();
        assert!(!config.is_tls_enabled());
        assert!(!config.is_mutual_tls());
    }

    #[test]
    fn test_verify_ca_config() {
        let config = BackendTlsConfig::verify_ca("/path/to/ca.pem".to_string());
        assert!(config.is_tls_enabled());
        assert!(!config.is_mutual_tls());
        assert_eq!(config.ca_cert_path, Some("/path/to/ca.pem".to_string()));
    }

    #[test]
    fn test_mutual_tls_config() {
        let config = BackendTlsConfig::mutual_tls(
            "/path/to/ca.pem".to_string(),
            "/path/to/client.pem".to_string(),
            "/path/to/client.key".to_string(),
        );
        assert!(config.is_tls_enabled());
        assert!(config.is_mutual_tls());
    }

    #[test]
    fn test_build_postgres_url_disabled() {
        let config = BackendTlsConfig::disabled();
        let url = config.build_postgres_url("postgres://localhost/kms");
        assert_eq!(url, "postgres://localhost/kms");
    }

    #[test]
    fn test_build_postgres_url_verify_ca() {
        let config = BackendTlsConfig::verify_ca("/etc/ssl/ca.pem".to_string());
        let url = config.build_postgres_url("postgres://localhost/kms");
        assert!(url.contains("sslmode=verify-ca"));
        assert!(url.contains("sslrootcert=/etc/ssl/ca.pem"));
    }

    #[test]
    fn test_build_postgres_url_mutual_tls() {
        let config = BackendTlsConfig::mutual_tls(
            "/etc/ssl/ca.pem".to_string(),
            "/etc/ssl/client.pem".to_string(),
            "/etc/ssl/client.key".to_string(),
        );
        let url = config.build_postgres_url("postgres://localhost/kms");
        assert!(url.contains("sslmode=verify-ca"));
        assert!(url.contains("sslrootcert=/etc/ssl/ca.pem"));
        assert!(url.contains("sslcert=/etc/ssl/client.pem"));
        assert!(url.contains("sslkey=/etc/ssl/client.key"));
    }

    #[test]
    fn test_build_postgres_url_with_existing_params() {
        let config = BackendTlsConfig::verify_ca("/etc/ssl/ca.pem".to_string());
        let url = config.build_postgres_url("postgres://localhost/kms?user=admin");
        assert!(url.contains("&sslmode=verify-ca"));
    }

    #[test]
    fn test_tls_mode_display() {
        assert_eq!(format!("{}", TlsMode::Disabled), "disabled");
        assert_eq!(format!("{}", TlsMode::VerifyCa), "verify_ca");
        assert_eq!(format!("{}", TlsMode::NoVerify), "no_verify");
    }
}
