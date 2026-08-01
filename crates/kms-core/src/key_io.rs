//! Key Import/Export - 安全导入导出机制
//!
//! 安全原则：导入容易导出难 - 导出的风险远高于导入

use serde::{Deserialize, Serialize};

/// 密钥格式枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyFormat {
    #[default]
    /// PKCS#8 PEM格式
    Pkcs8,
    /// JWK (JSON Web Key) 格式
    Jwk,
    /// 原始二进制格式
    Raw,
}

/// 密钥导入请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportKeyRequest {
    /// 密钥名称
    pub name: String,
    /// 密钥规格 (如 "aes-256-gcm", "sm2", "ed25519")
    pub spec: String,
    /// 密钥格式
    #[serde(default)]
    pub format: KeyFormat,
    /// Base64编码的密钥材料（已用传输密钥包装）
    pub wrapped_key: String,
    /// Base64编码的加密后的传输密钥（用KMS公钥加密）
    pub encrypted_transport_key: String,
    /// 来源指纹（用于完整性校验）
    pub source_fingerprint: String,
    /// 租户ID
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
}

fn default_tenant_id() -> String {
    "default".to_string()
}

/// 密钥导入响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportKeyResponse {
    /// 导入的密钥ID
    pub id: String,
    /// 密钥规格
    pub spec: String,
    /// 是否为导入的密钥
    pub imported: bool,
    /// 来源指纹
    pub source_fingerprint: String,
}

/// 密钥导出请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportKeyRequest {
    /// 要导出的密钥ID
    pub key_id: String,
    /// 目标系统标识（用于审计）
    pub target_system: String,
    /// Base64编码的目标系统公钥（用于加密传输密钥）
    pub target_public_key: String,
    /// 导出目的
    pub purpose: String,
    /// 传输密钥ID（可选）
    pub transport_key_id: Option<String>,
}

/// 密钥导出响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportKeyResponse {
    /// Base64编码的包装后密钥
    pub wrapped_key: String,
    /// Base64编码的加密传输密钥
    pub encrypted_transport_key: String,
    /// 密钥指纹
    pub key_fingerprint: String,
    /// 导出ID
    pub export_id: String,
    /// 导出过期时间
    pub expires_at: String,
}

/// 传输密钥信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportKeyInfo {
    /// 传输密钥ID
    pub id: String,
    /// 密钥创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// 密钥过期时间
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// 密钥是否已使用
    pub used: bool,
}

/// 导出策略配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportPolicy {
    /// 是否允许导出
    pub allow_export: bool,
    /// 是否需要审批
    pub require_approval: bool,
    /// 最小审批人数
    pub min_approvers: usize,
    /// 是否需要MFA验证
    pub mfa_required: bool,
    /// 是否需要传输加密
    pub transport_encryption_required: bool,
}

impl Default for ExportPolicy {
    fn default() -> Self {
        Self {
            allow_export: false,
            require_approval: false,
            min_approvers: 0,
            mfa_required: false,
            transport_encryption_required: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_format_default() {
        let format = KeyFormat::default();
        assert_eq!(format, KeyFormat::Pkcs8);
    }

    #[test]
    fn test_export_policy_default() {
        let policy = ExportPolicy::default();
        assert!(!policy.allow_export);
        assert!(policy.transport_encryption_required);
    }

    #[test]
    fn test_import_request_serialization() {
        let req = ImportKeyRequest {
            name: "test-key".to_string(),
            spec: "aes-256-gcm".to_string(),
            format: KeyFormat::Pkcs8,
            wrapped_key: "YWJjZA==".to_string(),
            encrypted_transport_key: "ZGVmZ2g=".to_string(),
            source_fingerprint: "abc123".to_string(),
            tenant_id: "default".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ImportKeyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.name, deserialized.name);
        assert_eq!(req.spec, deserialized.spec);
    }

    // --- KeyFormat ---

    #[test]
    fn test_key_format_variants_serde() {
        for (fmt, expected) in [
            (KeyFormat::Pkcs8, "\"pkcs8\""),
            (KeyFormat::Jwk, "\"jwk\""),
            (KeyFormat::Raw, "\"raw\""),
        ] {
            let json = serde_json::to_string(&fmt).unwrap();
            assert_eq!(json, expected);
            let de: KeyFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(de, fmt);
        }
    }

    #[test]
    fn test_key_format_serde_default_value() {
        // When format field is missing, serde default should kick in
        let json = r"{}";
        #[derive(Deserialize)]
        struct WithDefault {
            #[serde(default)]
            format: KeyFormat,
        }
        let de: WithDefault = serde_json::from_str(json).unwrap();
        assert_eq!(de.format, KeyFormat::Pkcs8);
    }

    // --- ImportKeyRequest ---

    #[test]
    fn test_import_request_default_tenant_id() {
        let json = r#"{"name":"k","spec":"aes","wrapped_key":"","encrypted_transport_key":"","source_fingerprint":""}"#;
        let de: ImportKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(de.tenant_id, "default");
        assert_eq!(de.format, KeyFormat::Pkcs8);
    }

    #[test]
    fn test_import_request_all_formats() {
        for fmt in [KeyFormat::Pkcs8, KeyFormat::Jwk, KeyFormat::Raw] {
            let req = ImportKeyRequest {
                name: "k".into(),
                spec: "aes".into(),
                format: fmt,
                wrapped_key: "".into(),
                encrypted_transport_key: "".into(),
                source_fingerprint: "".into(),
                tenant_id: "t".into(),
            };
            let json = serde_json::to_string(&req).unwrap();
            let de: ImportKeyRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(de.format, fmt);
        }
    }

    // --- ImportKeyResponse ---

    #[test]
    fn test_import_key_response_serde() {
        let resp = ImportKeyResponse {
            id: "key-123".to_string(),
            spec: "sm2".to_string(),
            imported: true,
            source_fingerprint: "sha256:abc".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let de: ImportKeyResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, "key-123");
        assert!(de.imported);
        assert_eq!(de.source_fingerprint, "sha256:abc");
    }

    // --- ExportKeyRequest ---

    #[test]
    fn test_export_key_request_serde() {
        let req = ExportKeyRequest {
            key_id: "k-1".to_string(),
            target_system: "external-app".to_string(),
            target_public_key: "base64key".to_string(),
            purpose: "migration".to_string(),
            transport_key_id: Some("tk-1".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let de: ExportKeyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(de.key_id, "k-1");
        assert_eq!(de.target_system, "external-app");
        assert_eq!(de.transport_key_id, Some("tk-1".to_string()));
    }

    #[test]
    fn test_export_key_request_optional_transport_key() {
        let json =
            r#"{"key_id":"k","target_system":"app","target_public_key":"","purpose":"test"}"#;
        let de: ExportKeyRequest = serde_json::from_str(json).unwrap();
        assert!(de.transport_key_id.is_none());
    }

    // --- ExportKeyResponse ---

    #[test]
    fn test_export_key_response_serde() {
        let resp = ExportKeyResponse {
            wrapped_key: "wrapped".to_string(),
            encrypted_transport_key: "etk".to_string(),
            key_fingerprint: "fp".to_string(),
            export_id: "exp-1".to_string(),
            expires_at: "2026-12-31T23:59:59Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let de: ExportKeyResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(de.export_id, "exp-1");
        assert_eq!(de.expires_at, "2026-12-31T23:59:59Z");
    }

    // --- TransportKeyInfo ---

    #[test]
    fn test_transport_key_info_serde() {
        let info = TransportKeyInfo {
            id: "tk-1".to_string(),
            created_at: chrono::DateTime::from_timestamp(1700000000, 0).unwrap(),
            expires_at: chrono::DateTime::from_timestamp(1700003600, 0).unwrap(),
            used: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let de: TransportKeyInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, "tk-1");
        assert!(!de.used);
        assert!(de.expires_at > de.created_at);
    }

    // --- ExportPolicy ---

    #[test]
    fn test_export_policy_all_fields() {
        let policy = ExportPolicy {
            allow_export: true,
            require_approval: true,
            min_approvers: 3,
            mfa_required: true,
            transport_encryption_required: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let de: ExportPolicy = serde_json::from_str(&json).unwrap();
        assert!(de.allow_export);
        assert!(de.require_approval);
        assert_eq!(de.min_approvers, 3);
        assert!(de.mfa_required);
    }

    #[test]
    fn test_export_policy_secure_default() {
        // Default policy should be restrictive
        let policy = ExportPolicy::default();
        assert!(!policy.allow_export, "export should be denied by default");
        assert!(
            policy.transport_encryption_required,
            "transport encryption should be required by default"
        );
        assert_eq!(policy.min_approvers, 0);
    }
}
