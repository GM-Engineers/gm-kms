//! KMS Sign Resource
//!
//! Terraform resource for signing data using KMS keys

use base64::{engine::general_purpose::STANDARD, Engine};
use super::get_provider_state;
use serde::{Deserialize, Serialize};

/// KMS Sign resource
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KmsSignResource {
    /// Key ID
    pub key_id: String,

    /// Data to sign (base64 encoded)
    pub data: String,

    /// Tenant ID
    #[serde(default)]
    pub tenant_id: String,

    /// Signature (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl KmsSignResource {
    /// Sign data
    pub async fn sign(
        key_id: &str,
        data: &str,
        tenant_id: &str,
    ) -> Result<KmsSignResource, String> {
        let state = get_provider_state().await;

        // Decode base64 data
        let data_bytes = STANDARD
            .decode(data)
            .map_err(|e| format!("Invalid base64 data: {e}"))?;

        let response = state
            .client
            .sign(key_id, &data_bytes, tenant_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(KmsSignResource {
            key_id: response.key_id,
            data: data.to_string(),
            tenant_id: tenant_id.to_string(),
            signature: Some(response.signature),
        })
    }
}
