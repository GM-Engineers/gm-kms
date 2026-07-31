//! KMS Verify Resource
//!
//! Terraform resource for verifying signatures using KMS keys

use base64::{engine::general_purpose::STANDARD, Engine};
use super::get_provider_state;
use serde::{Deserialize, Serialize};

/// KMS Verify resource
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KmsVerifyResource {
    /// Key ID
    pub key_id: String,

    /// Data that was signed (base64 encoded)
    pub data: String,

    /// Signature to verify (base64 encoded)
    pub signature: String,

    /// Tenant ID
    #[serde(default)]
    pub tenant_id: String,

    /// Whether signature is valid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
}

impl KmsVerifyResource {
    /// Verify signature
    pub async fn verify(
        key_id: &str,
        data: &str,
        signature: &str,
        tenant_id: &str,
    ) -> Result<KmsVerifyResource, String> {
        let state = get_provider_state().await;

        // Decode base64 data
        let data_bytes = STANDARD
            .decode(data)
            .map_err(|e| format!("Invalid base64 data: {}", e))?;

        let response = state
            .client
            .verify(key_id, &data_bytes, signature, tenant_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(KmsVerifyResource {
            key_id: key_id.to_string(),
            data: data.to_string(),
            signature: signature.to_string(),
            tenant_id: tenant_id.to_string(),
            valid: Some(response.valid),
        })
    }
}
