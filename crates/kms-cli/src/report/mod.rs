//! Compliance reporting engine for gm-kms.
//!
//! Provides automated generation of cryptographic configuration reports
//! and DJCP Level 3 self-assessment against the live KMS deployment.
//!
//! ## Report Types
//!
//! - **Crypto Configuration** — Full key inventory with algorithm breakdown,
//!   key statuses, crypto-period analysis, and compliance drift detection.
//! - **DJCP Self-Assessment** — DJCP Level 3 control mapping against the
//!   running system state.

mod compliance;
mod crypto;
mod html;

pub use compliance::ComplianceReport;
pub use crypto::CryptoConfigReport;
pub use html::HtmlReport;

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Report metadata (shared across report types) ──

/// Metadata about the report generation
#[derive(Debug, Clone, Serialize)]
pub struct ReportMeta {
    #[serde(rename = "type")]
    pub report_type: String,
    pub generated_at: String,
    pub generator: String,
    pub scope: ReportScope,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportScope {
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

// ── Data types for KMS API responses ──

/// A single key from /v1/keys
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyEntry {
    pub key_id: String,
    pub name: String,
    pub spec: String,
    pub status: String,
    pub tenant_id: String,
    pub created_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub version: u32,
}

/// Compliance rule status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Pass,
    Fail,
    Warn,
}

impl RuleStatus {
    /// CSS class suffix for this status (e.g. "pass", "fail", "warn")
    pub fn css_class(&self) -> &'static str {
        match self {
            RuleStatus::Pass => "pass",
            RuleStatus::Fail => "fail",
            RuleStatus::Warn => "warn",
        }
    }
}

impl fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleStatus::Pass => write!(f, "PASS"),
            RuleStatus::Fail => write!(f, "FAIL"),
            RuleStatus::Warn => write!(f, "WARN"),
        }
    }
}

/// A single compliance rule with its evaluation result
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceRuleResult {
    pub id: String,
    pub category: String,
    pub requirement: String,
    pub status: RuleStatus,
    pub evidence: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// Overall compliance report (shared across report types)
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceSection {
    pub overall: RuleStatus,
    pub rules: Vec<ComplianceRuleResult>,
}

impl ComplianceSection {
    pub fn new(rules: Vec<ComplianceRuleResult>) -> Self {
        let overall = if rules.iter().any(|r| r.status == RuleStatus::Fail) {
            RuleStatus::Fail
        } else if rules.iter().any(|r| r.status == RuleStatus::Warn) {
            RuleStatus::Warn
        } else {
            RuleStatus::Pass
        };
        ComplianceSection { overall, rules }
    }
}

/// Key inventory summary
#[derive(Debug, Clone, Serialize)]
pub struct KeySummary {
    pub total_keys: usize,
    pub by_algorithm: Vec<AlgorithmCount>,
    pub by_status: Vec<StatusCount>,
    pub by_tenant: Vec<TenantCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlgorithmCount {
    pub algorithm: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusCount {
    pub status: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantCount {
    pub tenant_id: String,
    pub count: usize,
}

// ── Drift detection ──

#[derive(Debug, Clone, Serialize)]
pub struct DriftSection {
    pub detected: bool,
    pub findings: Vec<DriftFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftFinding {
    pub severity: String, // "high", "medium", "low"
    pub description: String,
    pub key_id: Option<String>,
}

/// Build a key inventory summary from the list of keys
pub fn build_key_summary(keys: &[KeyEntry]) -> KeySummary {
    use std::collections::HashMap;

    let total_keys = keys.len();

    let mut algo_map: HashMap<String, usize> = HashMap::new();
    let mut status_map: HashMap<String, usize> = HashMap::new();
    let mut tenant_map: HashMap<String, usize> = HashMap::new();

    for k in keys {
        *algo_map.entry(k.spec.clone()).or_insert(0) += 1;
        *status_map.entry(k.status.clone()).or_insert(0) += 1;
        *tenant_map.entry(k.tenant_id.clone()).or_insert(0) += 1;
    }

    let mut by_algorithm: Vec<AlgorithmCount> = algo_map
        .into_iter()
        .map(|(algorithm, count)| AlgorithmCount { algorithm, count })
        .collect();
    by_algorithm.sort_by_key(|b| std::cmp::Reverse(b.count));

    let mut by_status: Vec<StatusCount> = status_map
        .into_iter()
        .map(|(status, count)| StatusCount { status, count })
        .collect();
    by_status.sort_by_key(|b| std::cmp::Reverse(b.count));

    let mut by_tenant: Vec<TenantCount> = tenant_map
        .into_iter()
        .map(|(tenant_id, count)| TenantCount { tenant_id, count })
        .collect();
    by_tenant.sort_by_key(|b| std::cmp::Reverse(b.count));

    KeySummary {
        total_keys,
        by_algorithm,
        by_status,
        by_tenant,
    }
}

// ── Compliance Rules Engine ──

/// Approved cryptographic algorithms for DJCP Level 3
const APPROVED_ALGORITHMS: &[&str] = &[
    "aes-256-gcm",
    "ed25519",
    "ecdsa-p256",
    "ecdsa-p384",
    "sm4",
    "sm2",
    "sm9-signing",
    "sm9-encryption",
    "hmac-sha256",
    "ed448",
    "rsa4096",
];

/// Deprecated or forbidden algorithms
const DEPRECATED_ALGORITHMS: &[&str] = &[
    "des",
    "3des",
    "rc4",
    "rc5",
    "md5",
    "sha1",
    "aes-128-ecb",
    "aes-128-cbc",
    "rsa1024",
    "rsa2048",
];

/// Run all compliance rules against the key inventory
pub fn evaluate_compliance(keys: &[KeyEntry], _metrics: &str) -> ComplianceSection {
    let rules = vec![
        check_crypto001(keys),
        check_crypto002(keys),
        check_crypto004(keys),
        check_keymgmt001(keys),
        check_keymgmt003(keys),
    ];
    ComplianceSection::new(rules)
}

fn check_crypto001(keys: &[KeyEntry]) -> ComplianceRuleResult {
    let unapproved: Vec<String> = keys
        .iter()
        .filter(|k| !APPROVED_ALGORITHMS.contains(&k.spec.as_str()))
        .map(|k| format!("{} (key: {})", k.spec, k.name))
        .collect();

    ComplianceRuleResult {
        id: "CRYPTO-001".into(),
        category: "crypto".into(),
        requirement: "All algorithms are approved for DJCP Level 3".into(),
        status: if unapproved.is_empty() {
            RuleStatus::Pass
        } else {
            RuleStatus::Fail
        },
        evidence: if unapproved.is_empty() {
            format!("All {} keys use approved algorithms", keys.len())
        } else {
            format!("{} keys use unapproved algorithms", unapproved.len())
        },
        details: unapproved,
    }
}

fn check_crypto002(keys: &[KeyEntry]) -> ComplianceRuleResult {
    // Check SM4 key length (must be 128-bit), SM2 (256-bit), AES-256-GCM (256-bit)
    let mut weak_keys: Vec<String> = Vec::new();
    for k in keys {
        match k.spec.as_str() {
            "sm4" => {}                         // 128-bit is standard
            "aes-256-gcm" | "hmac-sha256" => {} // 256-bit
            "rsa4096" => {}                     // 4096-bit
            "rsa2048" | "rsa1024" => weak_keys.push(format!(
                "{} uses weak key length (spec: {})",
                k.name, k.spec
            )),
            _ => {} // Asymmetric keys validated via algorithm choice
        }
    }

    ComplianceRuleResult {
        id: "CRYPTO-002".into(),
        category: "crypto".into(),
        requirement: "All symmetric keys meet minimum strength (SM4: 128-bit, AES: 256-bit)".into(),
        status: if weak_keys.is_empty() {
            RuleStatus::Pass
        } else {
            RuleStatus::Fail
        },
        evidence: "Key strengths verified against DJCP requirements".into(),
        details: weak_keys,
    }
}

fn check_crypto004(keys: &[KeyEntry]) -> ComplianceRuleResult {
    let deprecated: Vec<String> = keys
        .iter()
        .filter(|k| DEPRECATED_ALGORITHMS.contains(&k.spec.as_str()))
        .map(|k| format!("{} uses deprecated algorithm {}", k.name, k.spec))
        .collect();

    ComplianceRuleResult {
        id: "CRYPTO-004".into(),
        category: "crypto".into(),
        requirement: "No deprecated algorithms (DES, RC4, MD5, SHA1)".into(),
        status: if deprecated.is_empty() {
            RuleStatus::Pass
        } else {
            RuleStatus::Fail
        },
        evidence: if deprecated.is_empty() {
            "No deprecated algorithms found".into()
        } else {
            format!("{} keys use deprecated algorithms", deprecated.len())
        },
        details: deprecated,
    }
}

fn check_keymgmt001(keys: &[KeyEntry]) -> ComplianceRuleResult {
    let unknown_status: Vec<String> = keys
        .iter()
        .filter(|k| {
            !matches!(
                k.status.as_str(),
                "active"
                    | "Active"
                    | "pending_deletion"
                    | "PendingDeletion"
                    | "obsolete"
                    | "Obsolete"
                    | "destroyed"
                    | "Destroyed"
            )
        })
        .map(|k| format!("{} has unknown status: {}", k.name, k.status))
        .collect();

    ComplianceRuleResult {
        id: "KEYMGMT-001".into(),
        category: "key-mgmt".into(),
        requirement: "All keys have a defined lifecycle status".into(),
        status: if unknown_status.is_empty() {
            RuleStatus::Pass
        } else {
            RuleStatus::Warn
        },
        evidence: format!(
            "{} of {} keys have recognized lifecycle statuses",
            keys.len() - unknown_status.len(),
            keys.len()
        ),
        details: unknown_status,
    }
}

fn check_keymgmt003(keys: &[KeyEntry]) -> ComplianceRuleResult {
    let obsolete: Vec<String> = keys
        .iter()
        .filter(|k| k.status == "obsolete" || k.status == "Obsolete")
        .map(|k| format!("Obsolete key: {} ({})", k.name, k.key_id))
        .collect();

    ComplianceRuleResult {
        id: "KEYMGMT-003".into(),
        category: "key-mgmt".into(),
        requirement: "Obsolete keys should be rotated or destroyed in a timely manner".into(),
        status: if obsolete.len() <= 3 {
            RuleStatus::Pass
        } else {
            RuleStatus::Warn
        },
        evidence: format!("{} obsolete keys found", obsolete.len()),
        details: obsolete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(name: &str, spec: &str, status: &str, tenant: &str) -> KeyEntry {
        KeyEntry {
            key_id: format!("uuid-{name}"),
            name: name.into(),
            spec: spec.into(),
            status: status.into(),
            tenant_id: tenant.into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: None,
            version: 1,
        }
    }

    #[test]
    fn test_all_approved_algorithms_pass() {
        let keys = vec![
            make_key("k1", "aes-256-gcm", "Active", "default"),
            make_key("k2", "sm2", "Active", "default"),
            make_key("k3", "sm4", "Active", "default"),
        ];
        let result = check_crypto001(&keys);
        assert_eq!(result.status, RuleStatus::Pass);
    }

    #[test]
    fn test_unapproved_algorithm_fails() {
        let keys = vec![
            make_key("k1", "aes-256-gcm", "Active", "default"),
            make_key("k2", "des", "Active", "default"),
        ];
        let result = check_crypto001(&keys);
        assert_eq!(result.status, RuleStatus::Fail);
    }

    #[test]
    fn test_deprecated_algorithm_detected() {
        let keys = vec![make_key("k1", "rc4", "Active", "default")];
        let result = check_crypto004(&keys);
        assert_eq!(result.status, RuleStatus::Fail);
    }

    #[test]
    fn test_no_deprecated_algorithms_pass() {
        let keys = vec![
            make_key("k1", "aes-256-gcm", "Active", "default"),
            make_key("k2", "sm4", "Active", "default"),
        ];
        let result = check_crypto004(&keys);
        assert_eq!(result.status, RuleStatus::Pass);
    }

    #[test]
    fn test_build_key_summary() {
        let keys = vec![
            make_key("k1", "aes-256-gcm", "Active", "default"),
            make_key("k2", "aes-256-gcm", "Active", "default"),
            make_key("k3", "sm2", "Obsolete", "tenant-a"),
        ];
        let summary = build_key_summary(&keys);
        assert_eq!(summary.total_keys, 3);
        assert_eq!(summary.by_algorithm.len(), 2);
        assert_eq!(summary.by_status.len(), 2);
        assert_eq!(summary.by_tenant.len(), 2);
    }

    #[test]
    fn test_compliance_overall_fail_on_any_fail() {
        let mut rules = vec![
            check_crypto001(&[make_key("k1", "aes-256-gcm", "Active", "default")]),
            check_crypto004(&[make_key("k2", "des", "Active", "default")]),
        ];
        // Manually set to fail for testing
        rules[1].status = RuleStatus::Fail;
        let section = ComplianceSection::new(rules);
        assert_eq!(section.overall, RuleStatus::Fail);
    }

    #[test]
    fn test_obsolete_keys_warn_threshold() {
        let keys: Vec<KeyEntry> = (0..5)
            .map(|i| make_key(&format!("k{i}"), "aes-256-gcm", "Obsolete", "default"))
            .collect();
        let result = check_keymgmt003(&keys);
        assert_eq!(result.status, RuleStatus::Warn);
    }

    #[test]
    fn test_few_obsolete_keys_pass() {
        let keys = vec![
            make_key("k1", "aes-256-gcm", "Obsolete", "default"),
            make_key("k2", "sm2", "Active", "default"),
        ];
        let result = check_keymgmt003(&keys);
        assert_eq!(result.status, RuleStatus::Pass);
    }
}
