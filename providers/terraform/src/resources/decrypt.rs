//! KMS Decrypt Resource
//!
//! Terraform resource for decrypting data using KMS keys

use base64::{engine::general_purpose::STANDARD, Engine};
use super::get_provider_state;
use serde::{Deserialize, Serialize};

/// KMS Decrypt resource
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KmsDecryptResource {
    /// Key ID
    pub key_id: String,

    /// Ciphertext (base64 encoded)
    pub ciphertext: String,

    /// Nonce (base64 encoded)
    pub nonce: String,

    /// Tag (base64 encoded)
    pub tag: String,

    /// Tenant ID
    #[serde(default)]
    pub tenant_id: String,

    /// Decrypted plaintext (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
}

impl KmsDecryptResource {
    /// Decrypt ciphertext
    pub async fn decrypt(
        key_id: &str,
        ciphertext: &str,
        nonce: &str,
        tag: &str,
        tenant_id: &str,
    ) -> Result<KmsDecryptResource, String> {
        let state = get_provider_state().await;

        let response = state
            .client
            .decrypt(key_id, ciphertext, nonce, tag, tenant_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(KmsDecryptResource {
            key_id: key_id.to_string(),
            ciphertext: ciphertext.to_string(),
            nonce: nonce.to_string(),
            tag: tag.to_string(),
            tenant_id: tenant_id.to_string(),
            plaintext: Some(response.plaintext),
        })
    }
}
