//! KMS Encrypt Resource
//!
//! Terraform resource for encrypting data using KMS keys

use super::get_provider_state;
use serde::{Deserialize, Serialize};

/// KMS Encrypt resource
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KmsEncryptResource {
    /// Key ID
    pub key_id: String,

    /// Plaintext (base64 encoded in Terraform)
    pub plaintext: String,

    /// Tenant ID
    #[serde(default)]
    pub tenant_id: String,

    /// Ciphertext (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,

    /// Nonce (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Tag (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl KmsEncryptResource {
    /// Encrypt plaintext
    pub async fn encrypt(
        key_id: &str,
        plaintext: &str,
        tenant_id: &str,
    ) -> Result<KmsEncryptResource, String> {
        let state = get_provider_state().await;

        // Decode base64 plaintext
        let plaintext_bytes = STANDARD
            .decode(plaintext)
            .map_err(|e| format!("Invalid base64 plaintext: {e}"))?;

        let response = state
            .client
            .encrypt(key_id, &plaintext_bytes, tenant_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(KmsEncryptResource {
            key_id: response.key_id,
            plaintext: plaintext.to_string(),
            tenant_id: tenant_id.to_string(),
            ciphertext: Some(response.ciphertext),
            nonce: Some(response.nonce),
            tag: Some(response.tag),
        })
    }
}
