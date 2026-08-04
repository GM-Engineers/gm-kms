//! Fault injection wrapper for KeystoreBackend.
//!
//! Wraps any [`KeystoreBackend`] implementation with a [`FaultInjector`]
//! to test fail-secure behavior when keystore operations fail, are delayed,
//! or return corrupted data.
//!
//! Gated behind `#[cfg(any(test, feature = "chaos-testing"))]`.

use crate::chaos::{FaultError, FaultInjector};
use async_trait::async_trait;
use kms_core::{
    BackendType, Result,
    dh::{DhAlgorithm, SharedSecret},
    key::{Ciphertext, KeyMeta, KeySpec, Signature},
};
use kms_keystore::{HealthStatus, KeyFilter, KeystoreBackend};
use std::sync::Arc;
use uuid::Uuid;

/// A keystore backend wrapped with fault injection capability.
///
/// Intercepts all [`KeystoreBackend`] calls and optionally injects faults
/// before delegating to the inner backend.
#[derive(Clone)]
pub struct FaultWrappedKeystore {
    inner: Arc<dyn KeystoreBackend>,
    injector: Arc<FaultInjector>,
}

impl FaultWrappedKeystore {
    /// Create a new fault-wrapped keystore.
    pub fn new(inner: Arc<dyn KeystoreBackend>, injector: Arc<FaultInjector>) -> Self {
        Self { inner, injector }
    }

    /// Check and apply any configured fault.
    async fn maybe_fault(&self, operation: &str) -> Result<()> {
        match self.injector.apply_fault::<()>().await {
            Err(FaultError::InjectedFailure) => Err(kms_core::Error::Internal(format!(
                "fault injected: {operation} failed"
            ))),
            Err(FaultError::DataCorrupted) => Err(kms_core::Error::Internal(format!(
                "fault injected: {operation} returned corrupted data"
            ))),
            Err(FaultError::ConnectionLost) => Err(kms_core::Error::Internal(format!(
                "fault injected: {operation} connection lost"
            ))),
            Err(FaultError::Timeout) => Err(kms_core::Error::Internal(format!(
                "fault injected: {operation} timed out"
            ))),
            _ => Ok(()),
        }
    }
}

#[async_trait]
impl KeystoreBackend for FaultWrappedKeystore {
    fn backend_type(&self) -> BackendType {
        self.inner.backend_type()
    }

    async fn generate_key(&self, spec: &KeySpec, name: &str, tenant_id: &str) -> Result<KeyMeta> {
        self.maybe_fault("generate_key").await?;
        self.inner.generate_key(spec, name, tenant_id).await
    }

    async fn get_key_metadata(&self, key_id: &Uuid) -> Result<KeyMeta> {
        self.maybe_fault("get_key_metadata").await?;
        self.inner.get_key_metadata(key_id).await
    }

    async fn encrypt(
        &self,
        key_id: &Uuid,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        tenant_id: &str,
    ) -> Result<Ciphertext> {
        self.maybe_fault("encrypt").await?;
        self.inner.encrypt(key_id, plaintext, aad, tenant_id).await
    }

    async fn decrypt(
        &self,
        key_id: &Uuid,
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
        tenant_id: &str,
    ) -> Result<Vec<u8>> {
        self.maybe_fault("decrypt").await?;
        self.inner.decrypt(key_id, ciphertext, aad, tenant_id).await
    }

    async fn sign(&self, key_id: &Uuid, data: &[u8], tenant_id: &str) -> Result<Signature> {
        self.maybe_fault("sign").await?;
        self.inner.sign(key_id, data, tenant_id).await
    }

    async fn verify(
        &self,
        key_id: &Uuid,
        data: &[u8],
        signature: &Signature,
        tenant_id: &str,
    ) -> Result<bool> {
        self.maybe_fault("verify").await?;
        self.inner.verify(key_id, data, signature, tenant_id).await
    }

    async fn rotate_key(&self, key_id: &Uuid, tenant_id: &str) -> Result<KeyMeta> {
        self.maybe_fault("rotate_key").await?;
        self.inner.rotate_key(key_id, tenant_id).await
    }

    async fn delete_key(&self, key_id: &Uuid, tenant_id: &str) -> Result<()> {
        self.maybe_fault("delete_key").await?;
        self.inner.delete_key(key_id, tenant_id).await
    }

    async fn destroy_key(&self, key_id: &Uuid) -> Result<()> {
        self.maybe_fault("destroy_key").await?;
        self.inner.destroy_key(key_id).await
    }

    async fn destroy_key_with_proof(&self, key_id: &Uuid) -> Result<kms_core::DestructionProof> {
        self.maybe_fault("destroy_key_with_proof").await?;
        self.inner.destroy_key_with_proof(key_id).await
    }

    async fn list_keys(&self, filter: &KeyFilter) -> Result<Vec<KeyMeta>> {
        self.maybe_fault("list_keys").await?;
        self.inner.list_keys(filter).await
    }

    async fn health(&self) -> Result<HealthStatus> {
        self.inner.health().await
    }

    async fn import_key_material(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        material: Vec<u8>,
    ) -> Result<KeyMeta> {
        self.maybe_fault("import_key_material").await?;
        self.inner
            .import_key_material(spec, name, tenant_id, material)
            .await
    }

    async fn export_key_material(&self, key_id: &Uuid, tenant_id: &str) -> Result<Vec<u8>> {
        self.maybe_fault("export_key_material").await?;
        self.inner.export_key_material(key_id, tenant_id).await
    }

    async fn get_key_material(&self, key_id: &Uuid, tenant_id: &str) -> Result<Vec<u8>> {
        self.maybe_fault("get_key_material").await?;
        self.inner.get_key_material(key_id, tenant_id).await
    }

    async fn derive_shared_secret(
        &self,
        key_id: &Uuid,
        peer_public_key: &[u8],
        algorithm: DhAlgorithm,
    ) -> Result<SharedSecret> {
        self.maybe_fault("derive_shared_secret").await?;
        self.inner
            .derive_shared_secret(key_id, peer_public_key, algorithm)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaos::FaultConfig;
    use kms_core::key::KeySpec;
    use kms_keystore::SoftwareKeystore;

    fn make_fault_keystore(probability: f32) -> (FaultWrappedKeystore, Arc<FaultInjector>) {
        let software = Arc::new(SoftwareKeystore::new());
        let injector = Arc::new(FaultInjector::new());
        injector.configure(FaultConfig::fail(probability));
        let wrapper = FaultWrappedKeystore::new(software, injector.clone());
        (wrapper, injector)
    }

    #[tokio::test]
    async fn test_fault_wrapper_no_fault_passes_through() {
        let (wrapper, _) = make_fault_keystore(0.0);
        // With 0% probability, should always return NotFaulted from maybe_fault
        assert!(wrapper.maybe_fault("test").await.is_ok());
    }

    #[tokio::test]
    async fn test_fault_wrapper_fail_encrypt() {
        let (wrapper, _) = make_fault_keystore(1.0);
        let result = wrapper
            .encrypt(&Uuid::new_v4(), b"hello", None, "default")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("fault injected"));
    }

    #[tokio::test]
    async fn test_fault_wrapper_fail_decrypt() {
        let (wrapper, _) = make_fault_keystore(1.0);
        let ciphertext = Ciphertext {
            key_id: Uuid::new_v4(),
            version: 1,
            format_version: 1,
            nonce: vec![4, 5, 6],
            ciphertext: vec![1, 2, 3],
            tag: vec![7, 8, 9],
        };
        let result = wrapper
            .decrypt(&Uuid::new_v4(), &ciphertext, None, "default")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fault_wrapper_fail_sign() {
        let (wrapper, _) = make_fault_keystore(1.0);
        let result = wrapper.sign(&Uuid::new_v4(), b"data", "default").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fault_wrapper_delay_does_not_error() {
        let software = Arc::new(SoftwareKeystore::new());
        let injector = Arc::new(FaultInjector::new());
        // Delay of 1ms should not cause an error (delay returns NotFaulted)
        injector.configure(FaultConfig::delay(1, 1.0));
        let wrapper = FaultWrappedKeystore::new(software, injector);

        // Even with delay fault mode, maybe_fault returns Ok for Delay
        // (the sleep happens but no error is returned from apply_fault)
        let result = wrapper.maybe_fault("test").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fault_wrapper_probability_zero() {
        let (wrapper, _) = make_fault_keystore(0.0);
        // Multiple checks — none should fault
        for _ in 0..50 {
            assert!(wrapper.maybe_fault("test").await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_fault_wrapper_decorates_error_not_panics() {
        let (wrapper, _) = make_fault_keystore(1.0);
        // Fault should return an Err, not panic
        let result = wrapper.maybe_fault("test_op").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fault_wrapper_generate_key_fails() {
        let (wrapper, _) = make_fault_keystore(1.0);
        let spec = KeySpec::Aes256Gcm;
        let result = wrapper.generate_key(&spec, "test-key", "default").await;
        assert!(result.is_err());
    }
}
