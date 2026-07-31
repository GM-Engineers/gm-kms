//! Terraform Resources
//!
//! Implementation of KMS Terraform resources

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod key;
pub mod encrypt;
pub mod decrypt;
pub mod sign;
pub mod verify;

pub use key::KmsKeyResource;
pub use encrypt::KmsEncryptResource;
pub use decrypt::KmsDecryptResource;
pub use sign::KmsSignResource;
pub use verify::KmsVerifyResource;

/// Provider state shared across resources
#[derive(Debug, Clone)]
pub struct ProviderState {
    pub client: crate::KmsClient,
    pub default_tenant_id: String,
}

impl ProviderState {
    pub fn new(server_url: &str, default_tenant_id: &str) -> Self {
        Self {
            client: crate::KmsClient::new(server_url),
            default_tenant_id: default_tenant_id.to_string(),
        }
    }
}

/// Global provider state
pub static PROVIDER_STATE: once_cell::sync::Lazy<Arc<RwLock<Option<ProviderState>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Set provider state
pub async fn set_provider_state(state: ProviderState) {
    let mut provider = PROVIDER_STATE.write().await;
    *provider = Some(state);
}

/// Get provider state
pub async fn get_provider_state() -> ProviderState {
    let provider = PROVIDER_STATE.read().await;
    provider
        .clone()
        .expect("Provider not configured. Set 'server_url' in provider configuration.")
}
