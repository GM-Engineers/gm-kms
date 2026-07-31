//! Crypto configuration report generator.
//!
//! Produces a complete cryptographic configuration report
//! in JSON, HTML, or both formats.

use super::*;
use serde::Serialize;

/// Full crypto configuration report
#[derive(Debug, Clone, Serialize)]
pub struct CryptoConfigReport {
    pub report: ReportMeta,
    pub summary: KeySummary,
    pub compliance: ComplianceSection,
    pub keys: Vec<KeyEntry>,
    pub drift: DriftSection,
}

impl CryptoConfigReport {
    /// Generate a crypto configuration report from API data
    pub fn generate(
        server: &str,
        tenant_id: Option<&str>,
        keys: Vec<KeyEntry>,
        metrics: &str,
    ) -> Self {
        let filtered_keys: Vec<KeyEntry> = if let Some(tid) = tenant_id {
            keys.into_iter().filter(|k| k.tenant_id == tid).collect()
        } else {
            keys
        };

        let summary = build_key_summary(&filtered_keys);
        let compliance = evaluate_compliance(&filtered_keys, metrics);
        let drift = evaluate_drift(&filtered_keys);

        CryptoConfigReport {
            report: ReportMeta {
                report_type: "crypto-configuration".into(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                generator: format!("kms-cli v{}", env!("CARGO_PKG_VERSION")),
                scope: ReportScope {
                    server: server.into(),
                    tenant_id: tenant_id.map(String::from),
                },
            },
            summary,
            compliance,
            keys: filtered_keys,
            drift,
        }
    }

    /// Serialize to JSON string
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render to HTML string
    #[allow(dead_code)]
    pub fn to_html(&self) -> String {
        html::render_crypto_report(self)
    }
}

impl HtmlReport for CryptoConfigReport {
    fn to_html(&self) -> String {
        html::render_crypto_report(self)
    }
}

/// Evaluate drift by checking for unexpected algorithms and anomalies
fn evaluate_drift(keys: &[KeyEntry]) -> DriftSection {
    let mut findings = Vec::new();

    // Check for unapproved algorithms
    let unexpected: Vec<_> = keys
        .iter()
        .filter(|k| !APPROVED_ALGORITHMS.contains(&k.spec.as_str()))
        .collect();

    if !unexpected.is_empty() {
        findings.push(DriftFinding {
            severity: "high".into(),
            description: format!(
                "{} key(s) use algorithms not in the approved list",
                unexpected.len()
            ),
            key_id: None,
        });
        for k in unexpected {
            findings.push(DriftFinding {
                severity: "high".into(),
                description: format!("Key '{}' uses unapproved algorithm: {}", k.name, k.spec),
                key_id: Some(k.key_id.clone()),
            });
        }
    }

    // Check for keys without expiration
    let no_expiry: Vec<_> = keys
        .iter()
        .filter(|k| k.expires_at.is_none() && k.status != "destroyed" && k.status != "Destroyed")
        .collect();

    if no_expiry.len() > 10 {
        findings.push(DriftFinding {
            severity: "medium".into(),
            description: format!(
                "{} active keys have no expiration date set",
                no_expiry.len()
            ),
            key_id: None,
        });
    }

    DriftSection {
        detected: !findings.is_empty(),
        findings,
    }
}
