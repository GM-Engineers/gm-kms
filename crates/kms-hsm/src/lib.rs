//! kms-hsm - TPM 2.0 / HSM backend support for KMS
//!
//! This crate provides TPM 2.0 backend implementations for the
//! [`KeystoreBackend`] trait, with both software-simulated and real
//! hardware backends.
//!
//! ## Feature flags
//!
//! - **default**: Software-simulated TPM (for development and testing)
//! - **`tpm2-tss`**: Real TPM 2.0 hardware via `tpm2-tss` stack (Linux only)
//!
//! ## Architecture
//!
//! ```text
//! KeystoreBackend (kms-keystore)
//!     │
//!     ├── SoftwareKeystore  (kms-keystore, in-memory)
//!     │
//!     └── HsmBackend (kms-hsm, this crate)
//!             │
//!             ├── SimulatedTpmKeystore  (default, software simulation)
//!             └── RealTpmKeystore      (feature = "tpm2-tss", hardware)
//! ```
//!
//! Both HSM backends implement [`KeystoreBackend`] so they plug directly
//! into the KMS server without code changes.

pub mod tpm;

use thiserror::Error;

#[cfg(any(feature = "tpm2-tss", test))]
pub mod real;

use async_trait::async_trait;
use kms_core::Result;
use kms_core::key::KeyMeta;
use kms_core::key::KeySpec;
use uuid::Uuid;

// Re-exports
pub use tpm::SimulatedTpmKeystore;

/// Backward-compatible alias.
pub type TpmKeystore = SimulatedTpmKeystore;

#[cfg(feature = "tpm2-tss")]
pub use real::RealTpmKeystore;

// ============================================================================
// HsmBackend trait
// ============================================================================

/// The type of HSM backing this keystore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmType {
    /// Software-simulated TPM (development / testing only).
    /// Not suitable for production compliance.
    Simulated,
    /// Real TPM 2.0 hardware via tpm2-tss stack.
    /// Satisfies 等保 2.0 三级 P-009 and K-011 requirements.
    Tpm2Tss,
}

impl std::fmt::Display for HsmType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmType::Simulated => write!(f, "simulated"),
            HsmType::Tpm2Tss => write!(f, "tpm2-tss"),
        }
    }
}

/// PCR binding: list of (pcr_index, pcr_value) pairs.
pub type PcrBinding = Vec<(usize, Vec<u8>)>;

/// Hardware Security Module backend trait.
///
/// Extends [`KeystoreBackend`] with TPM/HSM-specific operations that go
/// beyond basic key storage and cryptographic operations:
///
/// - **PCR management**: Extend and read Platform Configuration Registers
/// - **Key sealing**: Bind keys to PCR values so they can only be used
///   when the platform is in a known-good state
/// - **HSM identity**: Identify the type and capabilities of the HSM
///
/// # Implementors
///
/// | Backend | Feature | Use case |
/// |---------|---------|----------|
/// | `SimulatedTpmKeystore` | default | Development, CI testing |
/// | `RealTpmKeystore` | `tpm2-tss` | Production 等保 2.0 三级 |
#[async_trait]
pub trait HsmBackend: kms_keystore::KeystoreBackend {
    /// Return the HSM type (simulated or real hardware).
    fn hsm_type(&self) -> HsmType;

    /// Extend a PCR with a new measurement (TPM2_PCR_Extend).
    ///
    /// The new PCR value is computed as:
    /// `PCR_new = Hash(PCR_old || measurement)`
    fn extend_pcr(&self, pcr_index: usize, data: &[u8]) -> Result<()>;

    /// Read the current value of a PCR.
    fn read_pcr(&self, pcr_index: usize) -> Result<Vec<u8>>;

    /// Check whether a key has PCR binding (was sealed to specific PCR values).
    fn key_has_pcr_binding(&self, key_id: &Uuid) -> Result<bool>;

    /// Get the PCR binding for a key, if any.
    fn get_key_pcr_binding(&self, key_id: &Uuid) -> Result<Option<PcrBinding>>;

    /// Generate a key sealed to specific PCR indices.
    ///
    /// The key can only be used when current PCR values match the values
    /// at the time of key creation. This implements TPM-style measured-boot
    /// key protection.
    async fn generate_key_with_pcr_binding(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        pcr_indices: &[usize],
    ) -> Result<KeyMeta>;
}

// ============================================================================
// Factory
// ============================================================================

/// Create the appropriate TPM keystore backend based on the selected type.
///
/// Error type returned when creating an HSM backend keystore fails.
#[derive(Debug, Error)]
pub enum HsmError {
    /// The `tpm2-tss` backend was requested but the `tpm2-tss` feature was not
    /// enabled at compile time.
    #[error(
        "tpm2-tss backend requested but feature is not enabled. \
         Rebuild with: cargo build --features kms-hsm/tpm2-tss"
    )]
    TpmFeatureDisabled,
}

/// # Arguments
/// * `hsm_type` - "simulated" or "tpm2-tss"
///
/// # Errors
/// Returns [`HsmError::TpmFeatureDisabled`] if "tpm2-tss" is requested but the
/// `tpm2-tss` feature is not enabled at compile time.
pub fn create_tpm_keystore(
    hsm_type: &str,
) -> std::result::Result<std::sync::Arc<dyn kms_keystore::KeystoreBackend + Send + Sync>, HsmError> {
    match hsm_type {
        "tpm2-tss" => {
            #[cfg(feature = "tpm2-tss")]
            {
                tracing::info!("Creating RealTpmKeystore (tpm2-tss hardware backend)");
                Ok(std::sync::Arc::new(RealTpmKeystore::new()))
            }
            #[cfg(not(feature = "tpm2-tss"))]
            {
                Err(HsmError::TpmFeatureDisabled)
            }
        }
        _ => {
            tracing::info!("Creating SimulatedTpmKeystore (software simulation)");
            Ok(std::sync::Arc::new(SimulatedTpmKeystore::new()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test HsmType Display
    #[test]
    fn test_hsm_type_display() {
        assert_eq!(HsmType::Simulated.to_string(), "simulated");
        assert_eq!(HsmType::Tpm2Tss.to_string(), "tpm2-tss");
    }

    /// Test HsmType equality
    #[test]
    fn test_hsm_type_eq() {
        assert_eq!(HsmType::Simulated, HsmType::Simulated);
        assert_ne!(HsmType::Simulated, HsmType::Tpm2Tss);
    }

    /// Test create_tpm_keystore with "simulated"
    #[test]
    fn test_create_tpm_keystore_simulated() {
        let keystore = create_tpm_keystore("simulated").unwrap();
        assert_eq!(keystore.backend_type(), kms_core::BackendType::Tpm);
    }

    /// Test create_tpm_keystore with unknown type defaults to simulated
    #[test]
    fn test_create_tpm_keystore_unknown_defaults() {
        let keystore = create_tpm_keystore("unknown").unwrap();
        assert_eq!(keystore.backend_type(), kms_core::BackendType::Tpm);
    }

    /// Test create_tpm_keystore with "tpm2-tss" returns an error without feature
    #[test]
    fn test_create_tpm_keystore_tpm2_tss_without_feature() {
        // This should return an error (not panic) when tpm2-tss feature is not enabled
        let result = create_tpm_keystore("tpm2-tss");
        assert!(result.is_err());
    }

    /// Test SimulatedTpmKeystore implements HsmBackend
    #[tokio::test]
    async fn test_simulated_tpm_hsm_backend() {
        let tpm = SimulatedTpmKeystore::new();
        assert_eq!(tpm.hsm_type(), HsmType::Simulated);
    }

    /// Test TpmKeystore alias is SimulatedTpmKeystore
    #[test]
    fn test_tpm_keystore_alias() {
        let keystore = TpmKeystore::new();
        assert_eq!(keystore.hsm_type(), HsmType::Simulated);
    }
}
