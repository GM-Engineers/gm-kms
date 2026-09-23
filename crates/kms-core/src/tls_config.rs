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

    /// Load from environment variables with production-safety check
    /// (PR-4.4 / P1-4).
    ///
    /// Pre-PR-4.4 behavior: `verify_ca` was the default for unknown
    /// values, but `no_verify` was accepted unconditionally in
    /// production (silent security downgrade) and `disabled` was
    /// silently demoted to `verify_ca` if not in dev mode (which
    /// works only if a CA cert path is set, otherwise fails at first
    /// connect rather than at startup).
    ///
    /// PR-4.4 fixes all three:
    ///
    /// 1. `verify_ca` is the production-safe default (same as pre-PR-4.4
    ///    for unknown values; PR-4.4 extends this to ALL non-opted-in
    ///    cases including empty / unset).
    /// 2. `no_verify` requires `KMS_DEV_MODE=1` or
    ///    `KMS_ALLOW_INSECURE=1` (otherwise fail-fast). Without
    ///    verification, TLS gives encryption but no authentication —
    ///    a MITM attacker can present any cert.
    /// 3. `disabled` similarly requires one of the opt-in flags.
    /// 4. `verify_ca` REQUIRES a non-empty CA cert path; missing
    ///    cert path produces an error rather than silently
    ///    constructing a `VerifyCa` config that will fail at first
    ///    connection.
    ///
    /// # Returns
    /// - `Ok(Self)` — production-safe config.
    /// - `Err(anyhow::Error)` — fail-fast condition tripped; the
    ///   caller MUST bubble this up to fail the KMS startup. We use
    ///   `anyhow::Error` rather than defining a dedicated error
    ///   type because this is a startup-time invariant violation,
    ///   not a runtime per-operation error.
    pub fn from_env() -> anyhow::Result<Self> {
        use crate::production_safety;

        let mode_str = std::env::var("KMS_DB_TLS_MODE")
            .unwrap_or_default()
            .to_lowercase();

        // Pre-resolve the candidate TlsMode (does not yet consider
        // dev-mode / opt-in semantics; just maps the env-var value
        // to the enum).
        let candidate_mode = match mode_str.as_str() {
            "" => TlsMode::VerifyCa, // PR-4.4: explicit default (was: dev-mode demote)
            "verify_ca" => TlsMode::VerifyCa,
            "no_verify" => TlsMode::NoVerify,
            "disabled" => TlsMode::Disabled,
            unknown => {
                tracing::warn!(
                    mode = %unknown,
                    "Unknown KMS_DB_TLS_MODE — defaulting to verify_ca"
                );
                TlsMode::VerifyCa
            }
        };

        // PR-4.4 production-safety gate. Only `KMS_DEV_MODE=1`
        // (test / embedded-integration) or `KMS_ALLOW_INSECURE=1`
        // (explicit production opt-in) can accept `Disabled` or
        // `NoVerify`. Anything else fail-fasts.
        let opted_in = production_safety::is_insecure_opted_in();
        let resolved_mode = match candidate_mode {
            TlsMode::VerifyCa => TlsMode::VerifyCa,
            TlsMode::NoVerify if !opted_in => {
                anyhow::bail!(
                    "KMS_DB_TLS_MODE=no_verify rejected in production; \
                     set KMS_ALLOW_INSECURE=1 (or KMS_DEV_MODE=1) to opt in. \
                     no_verify enables an MITM-attackable connection."
                );
            }
            TlsMode::Disabled if !opted_in => {
                anyhow::bail!(
                    "KMS_DB_TLS_MODE=disabled rejected in production; \
                     set KMS_ALLOW_INSECURE=1 (or KMS_DEV_MODE=1) to opt in. \
                     Disabled means plaintext database traffic."
                );
            }
            TlsMode::NoVerify => {
                tracing::warn!(
                    "KMS_DB_TLS_MODE=no_verify with KMS_ALLOW_INSECURE / KMS_DEV_MODE opt-in: \
                     database TLS will encrypt but NOT authenticate the server \
                     (MITM-attackable)"
                );
                TlsMode::NoVerify
            }
            TlsMode::Disabled => {
                tracing::warn!(
                    "KMS_DB_TLS_MODE=disabled with KMS_ALLOW_INSECURE / KMS_DEV_MODE opt-in: \
                     database traffic will be plaintext"
                );
                TlsMode::Disabled
            }
        };

        // VerifyCa MUST have a CA cert path. Without it, the
        // connection would fail at first handshake; better to
        // fail-fast at startup.
        let ca_cert_path = std::env::var("KMS_DB_TLS_CA_CERT").ok();
        if matches!(resolved_mode, TlsMode::VerifyCa)
            && ca_cert_path.as_deref().is_none_or(str::is_empty)
        {
            anyhow::bail!(
                "KMS_DB_TLS_MODE=verify_ca requires KMS_DB_TLS_CA_CERT to be set \
                 to a non-empty CA certificate path"
            );
        }

        // Build the config. If VerifyCa is in effect, we already
        // validated ca_cert_path is non-empty; unwrap is safe.
        let config = if matches!(resolved_mode, TlsMode::VerifyCa) {
            Self::verify_ca(ca_cert_path.unwrap_or_default())
        } else {
            Self {
                mode: resolved_mode,
                ca_cert_path: std::env::var("KMS_DB_TLS_CA_CERT").ok(),
                client_cert_path: std::env::var("KMS_DB_TLS_CLIENT_CERT").ok(),
                client_key_path: std::env::var("KMS_DB_TLS_CLIENT_KEY").ok(),
            }
        };

        Ok(config)
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
        let mut url = format!("{base_url}{separator}sslmode={sslmode}");

        if let Some(ca) = &self.ca_cert_path {
            url.push_str(&format!("&sslrootcert={ca}"));
        }
        if let Some(cert) = &self.client_cert_path {
            url.push_str(&format!("&sslcert={cert}"));
        }
        if let Some(key) = &self.client_key_path {
            url.push_str(&format!("&sslkey={key}"));
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

// ============================================================================
// PR-4.4 (P1-4) unit tests: production-safety fail-fast for DB/Redis TLS
// ============================================================================
//
// These tests lock in the production-safety gate added in PR-4.4:
// `no_verify` and `disabled` modes are rejected unless one of the
// production opt-in flags (`KMS_DEV_MODE=1` or `KMS_ALLOW_INSECURE=1`)
// is set. `verify_ca` requires a non-empty CA cert path. The
// pre-PR-4.4 silent demotion to `verify_ca` for unset / disabled
// in non-dev mode is removed (it was misleading operators who
// thought they had `disabled` but actually had an empty
// `verify_ca` config).

#[cfg(test)]
mod pr44_db_tls_defaults_tests {
    use super::*;
    use std::sync::Mutex;

    // Same env-var serialization pattern as PR-4.1 / PR-4.2:
    // `from_env` reads three env vars (KMS_DB_TLS_MODE +
    // KMS_DB_TLS_CA_CERT + KMS_DEV_MODE / KMS_ALLOW_INSECURE);
    // serial mutation under a Mutex prevents parallel tests
    // trampling each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();
        // SAFETY: `ENV_LOCK` serializes access. We restore the
        // previous values before returning.
        unsafe {
            for (k, v) in vars {
                match v {
                    Some(s) => std::env::set_var(k, s),
                    None => std::env::remove_var(k),
                }
            }
            let result = f();
            for (k, prev_v) in prev {
                match prev_v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
            result
        }
    }

    fn unset_production_env() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("KMS_DB_TLS_MODE", None),
            ("KMS_DB_TLS_CA_CERT", None),
            ("KMS_DB_TLS_CLIENT_CERT", None),
            ("KMS_DB_TLS_CLIENT_KEY", None),
            ("KMS_DEV_MODE", None),
            ("KMS_ALLOW_INSECURE", None),
        ]
    }

    #[test]
    fn pr44_db_tls_default_unset_production() {
        // Unset all relevant env vars; expect VerifyCa default
        // (which then fails because CA cert is also missing — the
        // exact behavior PR-4.4 enforces).
        with_env(&unset_production_env(), || {
            let result = BackendTlsConfig::from_env();
            assert!(
                result.is_err(),
                "verify_ca default without CA cert must fail-fast"
            );
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("KMS_DB_TLS_CA_CERT"),
                "error must mention missing CA cert; got: {}",
                err
            );
        });
    }

    #[test]
    fn pr44_db_tls_verify_ca_default_with_cert() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[1] = ("KMS_DB_TLS_CA_CERT", Some("/etc/ssl/ca.pem"));
                v
            },
            || {
                let config = BackendTlsConfig::from_env().expect("verify_ca with cert should work");
                assert_eq!(config.mode, TlsMode::VerifyCa);
                assert_eq!(config.ca_cert_path.as_deref(), Some("/etc/ssl/ca.pem"));
            },
        );
    }

    #[test]
    fn pr44_db_tls_disabled_in_dev_mode_ok() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("disabled"));
                v[4] = ("KMS_DEV_MODE", Some("1"));
                v
            },
            || {
                let config = BackendTlsConfig::from_env().expect("dev mode allows disabled");
                assert_eq!(config.mode, TlsMode::Disabled);
            },
        );
    }

    #[test]
    fn pr44_db_tls_disabled_in_prod_no_opt_in_rejected() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("disabled"));
                v
            },
            || {
                let err = BackendTlsConfig::from_env()
                    .expect_err("disabled in production must fail-fast");
                assert!(err.to_string().contains("rejected in production"));
            },
        );
    }

    #[test]
    fn pr44_db_tls_disabled_in_prod_with_allow_insecure_ok() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("disabled"));
                v[5] = ("KMS_ALLOW_INSECURE", Some("1"));
                v
            },
            || {
                let config =
                    BackendTlsConfig::from_env().expect("KMS_ALLOW_INSECURE=1 opts in to disabled");
                assert_eq!(config.mode, TlsMode::Disabled);
            },
        );
    }

    #[test]
    fn pr44_db_tls_no_verify_in_prod_rejected() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("no_verify"));
                v[1] = ("KMS_DB_TLS_CA_CERT", Some("/etc/ssl/ca.pem"));
                v
            },
            || {
                let err = BackendTlsConfig::from_env()
                    .expect_err("no_verify in production must fail-fast (MITM risk)");
                assert!(err.to_string().contains("no_verify rejected"));
            },
        );
    }

    #[test]
    fn pr44_db_tls_no_verify_with_allow_insecure_ok() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("no_verify"));
                v[1] = ("KMS_DB_TLS_CA_CERT", Some("/etc/ssl/ca.pem"));
                v[5] = ("KMS_ALLOW_INSECURE", Some("1"));
                v
            },
            || {
                let config = BackendTlsConfig::from_env()
                    .expect("KMS_ALLOW_INSECURE=1 opts in to no_verify");
                assert_eq!(config.mode, TlsMode::NoVerify);
            },
        );
    }

    #[test]
    fn pr44_db_tls_no_verify_in_dev_mode_ok() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("no_verify"));
                v[1] = ("KMS_DB_TLS_CA_CERT", Some("/etc/ssl/ca.pem"));
                v[4] = ("KMS_DEV_MODE", Some("1"));
                v
            },
            || {
                let config = BackendTlsConfig::from_env().expect("dev mode allows no_verify");
                assert_eq!(config.mode, TlsMode::NoVerify);
            },
        );
    }

    #[test]
    fn pr44_db_tls_verify_ca_explicit_with_cert() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("verify_ca"));
                v[1] = ("KMS_DB_TLS_CA_CERT", Some("/etc/ssl/ca.pem"));
                v
            },
            || {
                let config = BackendTlsConfig::from_env().expect("explicit verify_ca with cert");
                assert_eq!(config.mode, TlsMode::VerifyCa);
            },
        );
    }

    #[test]
    fn pr44_db_tls_verify_ca_explicit_no_cert_rejected() {
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("verify_ca"));
                v
            },
            || {
                let err = BackendTlsConfig::from_env()
                    .expect_err("verify_ca without CA cert must fail-fast");
                assert!(err.to_string().contains("KMS_DB_TLS_CA_CERT"));
            },
        );
    }

    #[test]
    fn pr44_db_tls_unknown_value_defaults_to_verify_ca() {
        // Unknown value: same as before PR-4.4 — defaults to
        // verify_ca (with the same CA-cert fail-fast behavior).
        with_env(
            &{
                let mut v = unset_production_env();
                v[0] = ("KMS_DB_TLS_MODE", Some("garbage"));
                v[1] = ("KMS_DB_TLS_CA_CERT", Some("/etc/ssl/ca.pem"));
                v
            },
            || {
                let config = BackendTlsConfig::from_env()
                    .expect("unknown value defaults to verify_ca (with cert)");
                assert_eq!(config.mode, TlsMode::VerifyCa);
            },
        );
    }

    #[test]
    fn pr44_db_tls_case_insensitive() {
        // Verify_ca / VERIFY_CA / VerifyCa all accepted.
        for val in &["verify_ca", "VERIFY_CA", "VerifyCa"] {
            with_env(
                &{
                    let mut v = unset_production_env();
                    v[0] = ("KMS_DB_TLS_MODE", Some(*val));
                    v[1] = ("KMS_DB_TLS_CA_CERT", Some("/etc/ssl/ca.pem"));
                    v
                },
                || {
                    let config = BackendTlsConfig::from_env()
                        .unwrap_or_else(|e| panic!("value {:?} must work: {}", val, e));
                    assert_eq!(config.mode, TlsMode::VerifyCa);
                },
            );
        }
    }

    #[test]
    fn pr44_db_tls_empty_path_set() {
        // Empty string is treated the same as unset for the
        // opt-in flags (matches PR-4.1 production_safety behavior).
        with_env(
            &{
                let mut v = unset_production_env();
                v[5] = ("KMS_ALLOW_INSECURE", Some(""));
                v[0] = ("KMS_DB_TLS_MODE", Some("disabled"));
                v
            },
            || {
                let err = BackendTlsConfig::from_env()
                    .expect_err("empty KMS_ALLOW_INSECURE must NOT opt in");
                assert!(err.to_string().contains("rejected in production"));
            },
        );
    }

    #[test]
    fn pr44_db_tls_verify_ca_empty_ca_cert_rejected() {
        // KMS_DB_TLS_CA_CERT="" must be treated like unset —
        // verify_ca still requires a non-empty path.
        with_env(
            &{
                let mut v = unset_production_env();
                v[1] = ("KMS_DB_TLS_CA_CERT", Some(""));
                v
            },
            || {
                let err =
                    BackendTlsConfig::from_env().expect_err("empty CA cert path must fail-fast");
                assert!(err.to_string().contains("KMS_DB_TLS_CA_CERT"));
            },
        );
    }
}
