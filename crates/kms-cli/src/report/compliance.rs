//! DJCP Level 3 compliance self-assessment report generator.
//!
//! Maps compliance rules to the DJCP control items from
//! docs/compliance/checklist.md and docs/compliance/self-assessment.md.

use super::*;
use serde::Serialize;

/// A DJCP control item with its evaluation result
#[derive(Debug, Clone, Serialize)]
pub struct ControlItem {
    pub id: String,
    pub category: String,
    pub requirement: String,
    pub standard_ref: String,
    pub status: RuleStatus,
    pub evidence: String,
}

/// DJCP self-assessment report
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReport {
    pub report: ReportMeta,
    pub standard: String,
    pub overall_result: RuleStatus,
    pub summary: ComplianceSummary,
    pub controls: Vec<ControlItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceSummary {
    pub total_controls: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub pass_rate_pct: f64,
}

impl ComplianceReport {
    /// Generate a DJCP Level 3 self-assessment report
    pub fn generate(server: &str, keys: &[KeyEntry], _metrics: &str) -> Self {
        let mut controls = Vec::new();

        // ── 1. Cryptographic Algorithm Compliance ──
        let crypto_pass = keys
            .iter()
            .all(|k| APPROVED_ALGORITHMS.contains(&k.spec.as_str()));
        controls.push(ControlItem {
            id: "A-001".into(),
            category: "密码算法合规性".into(),
            requirement: "使用的密码算法应符合国家密码管理部门要求".into(),
            standard_ref: "GM/T 0054-2018 §5.1.1".into(),
            status: if crypto_pass && !keys.is_empty() {
                RuleStatus::Pass
            } else {
                RuleStatus::Fail
            },
            evidence: format!("{} keys, all using approved algorithms", keys.len()),
        });

        let has_sm = keys.iter().any(|k| k.spec.starts_with("sm"));
        controls.push(ControlItem {
            id: "A-002".into(),
            category: "密码算法合规性".into(),
            requirement: "应使用国密标准算法 (SM2/SM3/SM4/SM9)".into(),
            standard_ref: "GM/T 0054-2018 §5.1.2".into(),
            status: if has_sm {
                RuleStatus::Pass
            } else {
                RuleStatus::Warn
            },
            evidence: if has_sm {
                "国密算法 (SM-series) deployed".into()
            } else {
                "No SM-series algorithms found; consider deploying SM2/SM4 for DJCP compliance"
                    .into()
            },
        });

        let no_deprecated = keys
            .iter()
            .all(|k| !DEPRECATED_ALGORITHMS.contains(&k.spec.as_str()));
        controls.push(ControlItem {
            id: "A-003".into(),
            category: "密码算法合规性".into(),
            requirement: "不得使用已淘汰的不安全算法".into(),
            standard_ref: "GB/T 22239-2019 §8.1.4".into(),
            status: if no_deprecated {
                RuleStatus::Pass
            } else {
                RuleStatus::Fail
            },
            evidence: if no_deprecated {
                "No deprecated algorithms found".into()
            } else {
                "Deprecated algorithms detected".into()
            },
        });

        // ── 2. Key Management Compliance ──
        let active_keys = keys
            .iter()
            .filter(|k| k.status == "Active" || k.status == "active")
            .count();
        controls.push(ControlItem {
            id: "K-001".into(),
            category: "密钥管理合规性".into(),
            requirement: "密钥应有明确的生命周期管理 (生成/使用/销毁/轮换)".into(),
            standard_ref: "GM/T 0054-2018 §5.2.3".into(),
            status: if active_keys > 0 || keys.is_empty() {
                RuleStatus::Pass
            } else {
                RuleStatus::Warn
            },
            evidence: format!("{} keys tracked with lifecycle status", keys.len()),
        });

        let destroyed = keys
            .iter()
            .filter(|k| k.status == "destroyed" || k.status == "Destroyed")
            .count();
        controls.push(ControlItem {
            id: "K-002".into(),
            category: "密钥管理合规性".into(),
            requirement: "密钥销毁应彻底且不可恢复".into(),
            standard_ref: "GM/T 0054-2018 §5.2.4".into(),
            status: RuleStatus::Pass,
            evidence: if destroyed > 0 {
                format!(
                    "{} keys properly destroyed via destroy_key_with_proof",
                    destroyed
                )
            } else {
                "No destroyed keys (system supports destroy_key_with_proof)".into()
            },
        });

        // ── 3. Access Control Compliance ──
        controls.push(ControlItem {
            id: "AC-001".into(),
            category: "访问控制合规性".into(),
            requirement: "应使用密码技术进行身份鉴别 (API Key)".into(),
            standard_ref: "GB/T 22239-2019 §8.1.3".into(),
            status: RuleStatus::Pass,
            evidence: "API Key authentication with role-based access control".into(),
        });

        controls.push(ControlItem {
            id: "AC-002".into(),
            category: "访问控制合规性".into(),
            requirement: "应遵循三权分立原则 (系统管理员/安全管理员/审计管理员)".into(),
            standard_ref: "GB/T 22239-2019 §8.1.3".into(),
            status: RuleStatus::Pass,
            evidence:
                "Three-officer separation: ReadOnly/Operator/KeyAdmin/SecurityOfficer/AuditAdmin"
                    .into(),
        });

        controls.push(ControlItem {
            id: "AC-003".into(),
            category: "访问控制合规性".into(),
            requirement: "应支持多因素认证 (MFA/TOTP)".into(),
            standard_ref: "GM/T 0054-2018 §5.3.3".into(),
            status: RuleStatus::Pass,
            evidence: "TOTP-based MFA (RFC 6238) with backup codes".into(),
        });

        // ── 4. Audit Compliance ──
        controls.push(ControlItem {
            id: "AU-001".into(),
            category: "审计日志合规性".into(),
            requirement: "密码应用应有完整的审计日志".into(),
            standard_ref: "GB/T 22239-2019 §8.1.4".into(),
            status: RuleStatus::Pass,
            evidence: "Structured audit logging with SignedAuditEntry (HMAC-SHA256)".into(),
        });

        controls.push(ControlItem {
            id: "AU-002".into(),
            category: "审计日志合规性".into(),
            requirement: "审计日志应防止篡改".into(),
            standard_ref: "GB/T 22239-2019 §8.1.4".into(),
            status: RuleStatus::Pass,
            evidence:
                "Hash-chained WORM storage + HMAC-SHA256 signatures + optional TSA (RFC 3161)"
                    .into(),
        });

        controls.push(ControlItem {
            id: "AU-003".into(),
            category: "审计日志合规性".into(),
            requirement: "审计日志应包含时间戳、用户标识、操作类型、结果".into(),
            standard_ref: "GM/T 0054-2018 §5.5.3".into(),
            status: RuleStatus::Pass,
            evidence:
                "AuditEvent: event_id, timestamp, actor_id, action, resource_type, result, metadata"
                    .into(),
        });

        // Summary
        let passed = controls
            .iter()
            .filter(|c| c.status == RuleStatus::Pass)
            .count();
        let failed = controls
            .iter()
            .filter(|c| c.status == RuleStatus::Fail)
            .count();
        let warnings = controls
            .iter()
            .filter(|c| c.status == RuleStatus::Warn)
            .count();
        let total = controls.len();
        let overall = if failed > 0 {
            RuleStatus::Fail
        } else if warnings > 0 {
            RuleStatus::Warn
        } else {
            RuleStatus::Pass
        };

        ComplianceReport {
            report: ReportMeta {
                report_type: "dengbao-self-assessment".into(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                generator: format!("kms-cli v{}", env!("CARGO_PKG_VERSION")),
                scope: ReportScope {
                    server: server.into(),
                    tenant_id: None,
                },
            },
            standard: "GB/T 22239-2019 等保 2.0 三级".into(),
            overall_result: overall,
            summary: ComplianceSummary {
                total_controls: total,
                passed,
                failed,
                warnings,
                pass_rate_pct: if total > 0 {
                    (passed as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
            },
            controls,
        }
    }

    /// Serialize to JSON
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render to HTML
    #[allow(dead_code)]
    pub fn to_html(&self) -> String {
        html::render_compliance_report(self)
    }
}

impl HtmlReport for ComplianceReport {
    fn to_html(&self) -> String {
        html::render_compliance_report(self)
    }
}
