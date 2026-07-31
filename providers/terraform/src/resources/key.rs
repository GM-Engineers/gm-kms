//! KMS Key Resource
//!
//! Terraform resource for managing KMS keys

use super::{get_provider_state, ProviderState};
use serde::{Deserialize, Serialize};

/// KMS Key resource
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KmsKeyResource {
    /// Unique identifier (UUID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Key name
    pub name: String,

    /// Key specification (aes-256-gcm, ed25519, sm4, sm2, etc.)
    #[serde(default = "default_spec")]
    pub spec: String,

    /// Tenant ID
    #[serde(default)]
    pub tenant_id: String,

    /// Key status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,

    /// Creation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,

    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

fn default_spec() -> String {
    "aes-256-gcm".to_string()
}

impl KmsKeyResource {
    /// Create a new key
    pub async fn create(
        name: &str,
        spec: &str,
        tenant_id: &str,
    ) -> Result<KmsKeyResource, String> {
        let state = get_provider_state().await;

        let response = state
            .client
            .create_key(name, spec, tenant_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(KmsKeyResource {
            id: Some(response.id),
            name: response.name,
            spec: response.spec,
            tenant_id: response.tenant_id,
            status: Some(response.status),
            version: Some(response.version),
            created_at: Some(response.created_at),
            metadata: Some(response.metadata),
        })
    }

    /// Read a key by ID
    pub async fn read(key_id: &str) -> Result<KmsKeyResource, String> {
        let state = get_provider_state().await;

        let response = state
            .client
            .get_key(key_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(KmsKeyResource {
            id: Some(response.id),
            name: response.name,
            spec: response.spec,
            tenant_id: response.tenant_id,
            status: Some(response.status),
            version: Some(response.version),
            created_at: Some(response.created_at),
            metadata: Some(response.metadata),
        })
    }

    /// Delete a key by ID
    pub async fn delete(key_id: &str) -> Result<(), String> {
        let state = get_provider_state().await;

        state
            .client
            .delete_key(key_id)
            .await
            .map_err(|e| e.to_string())
    }

    /// Rotate a key
    pub async fn rotate(key_id: &str) -> Result<KmsKeyResource, String> {
        let state = get_provider_state().await;

        let response = state
            .client
            .rotate_key(key_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(KmsKeyResource {
            id: Some(response.id),
            name: response.name,
            spec: response.spec,
            tenant_id: response.tenant_id,
            status: Some(response.status),
            version: Some(response.version),
            created_at: Some(response.created_at),
            metadata: Some(response.metadata),
        })
    }
}
