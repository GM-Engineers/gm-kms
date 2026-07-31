//! Common types for KMS

use serde::{Deserialize, Serialize};

/// Backend type for keystore
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackendType {
    /// Software-based keystore
    Software,
    /// Hardware Security Module
    Hsm,
    /// TPM 2.0
    Tpm,
    /// Cloud KMS (AWS/GCP/Azure)
    Cloud,
    /// Cached layer over another backend
    Cached,
    /// PostgreSQL-backed keystore
    Database,
}

impl BackendType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendType::Software => "software",
            BackendType::Hsm => "hsm",
            BackendType::Tpm => "tpm",
            BackendType::Cloud => "cloud",
            BackendType::Cached => "cached",
            BackendType::Database => "database",
        }
    }
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Health status for a backend
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Audit metadata for events
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditMetadata {
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

/// Pagination parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            limit: Some(100),
            offset: Some(0),
        }
    }
}

/// Paginated result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paginated<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BackendType ---

    #[test]
    fn test_backend_type_as_str() {
        assert_eq!(BackendType::Software.as_str(), "software");
        assert_eq!(BackendType::Hsm.as_str(), "hsm");
        assert_eq!(BackendType::Tpm.as_str(), "tpm");
        assert_eq!(BackendType::Cloud.as_str(), "cloud");
        assert_eq!(BackendType::Cached.as_str(), "cached");
        assert_eq!(BackendType::Database.as_str(), "database");
    }

    #[test]
    fn test_backend_type_display() {
        assert_eq!(format!("{}", BackendType::Software), "software");
        assert_eq!(format!("{}", BackendType::Hsm), "hsm");
        assert_eq!(format!("{}", BackendType::Tpm), "tpm");
        assert_eq!(format!("{}", BackendType::Cloud), "cloud");
        assert_eq!(format!("{}", BackendType::Cached), "cached");
        assert_eq!(format!("{}", BackendType::Database), "database");
    }

    #[test]
    fn test_backend_type_serde() {
        let bt = BackendType::Tpm;
        let json = serde_json::to_string(&bt).unwrap();
        assert_eq!(json, "\"TPM\"");
        let de: BackendType = serde_json::from_str(&json).unwrap();
        assert_eq!(de, bt);
    }

    #[test]
    fn test_backend_type_all_variants_serde() {
        for bt in [
            BackendType::Software,
            BackendType::Hsm,
            BackendType::Tpm,
            BackendType::Cloud,
            BackendType::Cached,
            BackendType::Database,
        ] {
            let json = serde_json::to_string(&bt).unwrap();
            let de: BackendType = serde_json::from_str(&json).unwrap();
            assert_eq!(de, bt);
        }
    }

    #[test]
    fn test_backend_type_eq() {
        assert_eq!(BackendType::Software, BackendType::Software);
        assert_ne!(BackendType::Software, BackendType::Hsm);
    }

    // --- HealthStatus ---

    #[test]
    fn test_health_status_serde() {
        let h = HealthStatus::Healthy;
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, "\"HEALTHY\"");
        let de: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(de, h);
    }

    #[test]
    fn test_health_status_variants_serde() {
        for h in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
            HealthStatus::Unknown,
        ] {
            let json = serde_json::to_string(&h).unwrap();
            let de: HealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(de, h);
        }
    }

    #[test]
    fn test_health_status_eq() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
    }

    // --- AuditMetadata ---

    #[test]
    fn test_audit_metadata_default() {
        let am = AuditMetadata::default();
        assert!(am.request_id.is_none());
        assert!(am.client_ip.is_none());
        assert!(am.user_agent.is_none());
        assert!(am.duration_ms.is_none());
    }

    #[test]
    fn test_audit_metadata_serde() {
        let am = AuditMetadata {
            request_id: Some("req-123".to_string()),
            client_ip: Some("10.0.0.1".to_string()),
            user_agent: Some("kms-cli/1.0".to_string()),
            duration_ms: Some(42),
        };
        let json = serde_json::to_string(&am).unwrap();
        let de: AuditMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(de.request_id, Some("req-123".to_string()));
        assert_eq!(de.client_ip, Some("10.0.0.1".to_string()));
        assert_eq!(de.user_agent, Some("kms-cli/1.0".to_string()));
        assert_eq!(de.duration_ms, Some(42));
    }

    #[test]
    fn test_audit_metadata_partial_serde() {
        let json = r"{}";
        let de: AuditMetadata = serde_json::from_str(json).unwrap();
        assert!(de.request_id.is_none());
        assert!(de.duration_ms.is_none());
    }

    // --- Pagination ---

    #[test]
    fn test_pagination_default() {
        let p = Pagination::default();
        assert_eq!(p.limit, Some(100));
        assert_eq!(p.offset, Some(0));
    }

    #[test]
    fn test_pagination_custom() {
        let p = Pagination {
            limit: Some(50),
            offset: Some(10),
        };
        assert_eq!(p.limit, Some(50));
        assert_eq!(p.offset, Some(10));
    }

    // --- Paginated ---

    #[test]
    fn test_paginated_serde() {
        let p = Paginated {
            items: vec!["a".to_string(), "b".to_string()],
            total: 100,
            limit: 10,
            offset: 0,
        };
        let json = serde_json::to_string(&p).unwrap();
        let de: Paginated<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(de.items, vec!["a", "b"]);
        assert_eq!(de.total, 100);
        assert_eq!(de.limit, 10);
        assert_eq!(de.offset, 0);
    }

    #[test]
    fn test_paginated_empty() {
        let p: Paginated<i32> = Paginated {
            items: vec![],
            total: 0,
            limit: 10,
            offset: 0,
        };
        let json = serde_json::to_string(&p).unwrap();
        let de: Paginated<i32> = serde_json::from_str(&json).unwrap();
        assert!(de.items.is_empty());
    }
}
