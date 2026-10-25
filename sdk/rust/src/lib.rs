//! A Rust SDK for the **gm-kms** 国密 key management service.
//!
//! The SDK speaks the same REST/JSON channel as the Go, Python and
//! JavaScript SDKs: no `protoc`, no gRPC bindings, no code generation. A
//! server-side change that breaks the wire format is caught by the drift
//! guard in `tests/contract.rs` rather than by a customer.
//!
//! # Getting started
//!
//! ```no_run
//! # async fn run() -> gm_kms_sdk::Result<()> {
//! use gm_kms_sdk::{Client, CreateKeyRequest, EncryptRequest, KeySpec};
//!
//! let kms = Client::builder("https://kms.example.com")
//!     .api_key("secret")
//!     .tenant("acme")
//!     .build()?;
//!
//! // Create a key and use it.
//! let key = kms
//!     .create_key(&CreateKeyRequest {
//!         name: "orders".to_string(),
//!         spec: KeySpec::Sm4,
//!         tenant_id: None,
//!     })
//!     .await?;
//!
//! let plaintext = "订单 42".as_bytes();
//! let sealed = kms
//!     .encrypt(
//!         &key.id,
//!         &EncryptRequest {
//!             plaintext: plaintext.to_vec(),
//!             aad: None,
//!         },
//!         None,
//!     )
//!     .await?;
//!
//! // The ciphertext carries its own nonce, tag and version: hand them back
//! // unchanged and the server rebuilds the exact AAD it authenticated.
//! let opened = kms.decrypt(&key.id, &sealed.to_decrypt_request(), None).await?;
//! assert_eq!(opened, plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! # Errors
//!
//! Every call returns [`Result`]. A refusal by the server comes back as
//! [`KmsError::Api`], which carries the HTTP status code and the server's
//! message. The distinction that matters most in practice:
//!
//! - **403** — the request was well-formed but the caller is not authorized
//!   (the approval gate, the PBAC policy). An expired approval, or one
//!   bound to another key, is a 403.
//! - **400** — the request itself was malformed (a missing or invalid
//!   `approval_id`, an unknown key specification).
//!
//! # Approvals
//!
//! A key export needs an approved `KeyExport` request. One API key is one
//! vote, so a multi-party quorum needs several *distinct* keys:
//!
//! ```no_run
//! # async fn run(kms: &gm_kms_sdk::Client, key_id: uuid::Uuid) -> gm_kms_sdk::Result<()> {
//! use gm_kms_sdk::{ApprovalOperation, CreateApprovalRequest};
//!
//! let approval = kms
//!     .create_approval(&CreateApprovalRequest {
//!         operation: ApprovalOperation::KeyExport,
//!         resource_id: key_id.to_string(),
//!         justification: Some("quarterly migration".to_string()),
//!         tenant_id: None,
//!     })
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Module layout
//!
//! - [`client`] — the [`Client`] and its [`ClientBuilder`].
//! - [`models`] — the request and response types.
//! - [`error`] — the [`KmsError`] type.

#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod models;

pub use client::{Client, ClientBuilder};
pub use error::{KmsError, Result};
pub use models::{
    Approval, ApprovalLevel, ApprovalOperation, ApprovalStatus, ApproveRequest, ComponentHealth,
    CreateApprovalRequest, CreateKeyRequest, CreatePolicyRequest, DecryptRequest, DecryptResult,
    DerivedSecret, DhDeriveRequest, EncryptRequest, EncryptedData, EnvelopeDecryptRequest,
    EnvelopeEncryptRequest, EnvelopeEncrypted, EnvelopeRewrapRequest, EnvelopeRewrapped,
    ExportKeyRequest, ExportKeyResult, HashAlgorithm, HashRequest, HashResult, Health, HmacRequest,
    HmacVerifyRequest, ImportKeyRequest, ImportKeyResult, Key, KeySpec, MacTag, Policy,
    PolicyEffect, RejectRequest, SignRequest, Signature, Sm9Ciphertext, Sm9DecryptRequest,
    Sm9EncryptRequest, Sm9SignRequest, Sm9Signature, Sm9VerifyRequest, VerifyRequest, VerifyResult,
};
