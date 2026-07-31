//! kms-core - Core domain types for KMS
//!
//! This crate contains core types with no I/O dependencies.

pub mod algorithms;
pub mod algorithms_impl;
pub mod backup;
pub mod csprng;
pub mod dh;
pub mod envelope;
pub mod error;
pub mod event;
pub mod hybrid_kem;
pub mod key;
pub mod key_io;
pub mod memory_protection;
pub mod policy;
pub mod sanitize;
pub mod secret_rotation;
pub mod self_test;
pub mod shamir;
pub mod sm9_key_rotation;
pub mod sm9_master_key;
pub mod tls_config;
pub mod types;
pub mod webhook;

#[cfg(test)]
mod proptests;

pub use algorithms::{
    AlgorithmInfo, AlgorithmRegistry, DecryptResult, Decryptor, EncryptResult, Encryptor,
    SignResult, Signer, SymmetricCrypto, Verifier, VerifyResult, get_algorithm_info,
    is_encryption_supported, is_signing_supported, validate_key_size,
};
pub use algorithms_impl::{
    Aes256GcmCrypto, Aes256GcmDecryptor, Aes256GcmEncryptor, AlgorithmFactory, Sm4GcmCrypto,
    Sm4GcmDecryptor, Sm4GcmEncryptor,
};
pub use backup::{BackupConfig, KeyBackup, KeyBackupService, MasterKey};
pub use csprng::{
    CsprngDiagnostics, CsprngError, GmRng, generate_dek, generate_nonce, random_bytes,
};
pub use dh::{DhAlgorithm, DhDeriveRequest, DhDeriveResponse, DhKeyPair, SharedSecret};
pub use envelope::{DekInfo, Envelope, EnvelopeConfig};
pub use error::{Error, Result};
pub use event::{Event, EventType};
pub use hybrid_kem::{
    HybridKemCiphertext, HybridKemKeyPair, HybridKemKeyStatus, HybridKemSecret, HybridKemVariant,
    KemDecapsResult, KemEncapsResult, PqReadiness, PqReadinessStatus,
};
pub use key::{
    Ciphertext, DestructionProof, Key, KeyMeta, KeyPurpose, KeySpec, KeyStatus, Signature,
};
pub use key_io::{
    ExportKeyRequest, ExportKeyResponse, ExportPolicy, ImportKeyRequest, ImportKeyResponse,
    KeyFormat, TransportKeyInfo,
};
pub use memory_protection::{
    LockedMemory, SecureBox, disable_core_dump, init_memory_protection, is_mlock_supported, mlock,
    munlock,
};
pub use policy::{Condition, Policy, PolicyEffect};
pub use secret_rotation::{
    RotationConfig, RotationState, SecretRotation, SecretRotationManager, SecretType, SecretVersion,
};
pub use self_test::{
    Aes256GcmSelfTest, AlgorithmSelfTest, AlgorithmTestResult, SelfTestResults, SelfTester,
    Sm3SelfTest, Sm4SelfTest,
};
pub use shamir::{
    Commitment, ReconstructionResult, ShamirSecretSharing, Share, ShareVerification, Shares,
    SharesMetadata,
};
pub use sm9_master_key::{EnvVarKekStore, MemoryKekStore, Sm9MasterKeyStore};
pub use tls_config::{BackendTlsConfig, TlsMode};
pub use types::{AuditMetadata, BackendType, HealthStatus};
pub use uuid::Uuid;
pub use webhook::{
    DeliveryStatus, EventFilter, WebhookClient, WebhookConfig, WebhookDelivery, WebhookManager,
};
