//! The drift guard: the SDK's wire types against the server's own DTOs.
//!
//! The SDK is a second implementation of the REST contract. A change on
//! either side that breaks the other must fail here, not in a customer's
//! application. Two properties are checked for every endpoint:
//!
//! 1. **The SDK understands the server.** The server's DTO is serialized
//!    (or, for a request, written out as the JSON the server accepts), and
//!    the SDK's DTO must deserialize it — with the same field names, all the
//!    way down, and with the same values.
//! 2. **The server understands the SDK.** The SDK's request is serialized and
//!    deserialized by the server's own request DTO; it must not be rejected.
//!
//! The end-to-end companion lives in `tests/e2e.rs`: it runs the SDK against
//! a real server, so a request body that deserializes but means the wrong
//! thing is caught there.

use std::fmt::Debug;

use gm_kms_sdk::{
    Approval, ApprovalLevel, ApprovalOperation, ApprovalStatus, ApproveRequest,
    CreateApprovalRequest, CreateKeyRequest, CreatePolicyRequest, DecryptRequest, DecryptResult,
    DerivedSecret, DhDeriveRequest, EncryptRequest, EncryptedData, EnvelopeDecryptRequest,
    EnvelopeEncryptRequest, EnvelopeEncrypted, EnvelopeRewrapRequest, EnvelopeRewrapped,
    ExportKeyRequest, ExportKeyResult, HashAlgorithm, HashRequest, HashResult, Health, HmacRequest,
    HmacVerifyRequest, ImportKeyRequest, ImportKeyResult, Key, KeySpec, MacTag, Policy,
    RejectRequest, SignRequest, Signature, Sm9Ciphertext, Sm9DecryptRequest, Sm9EncryptRequest,
    Sm9SignRequest, Sm9Signature, Sm9VerifyRequest, VerifyRequest, VerifyResult,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

/// Assert that two JSON documents have exactly the same field names, all the
/// way down.
///
/// The values may differ: the SDK normalizes some of them (a key
/// specification comes back as `"Sm4"` and is re-serialized as `"sm4"`).
/// The *shape* is what must not drift.
fn assert_same_fields(left: &Value, right: &Value, path: &str) {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let mut left_keys: Vec<&str> = left.keys().map(String::as_str).collect();
            let mut right_keys: Vec<&str> = right.keys().map(String::as_str).collect();
            left_keys.sort_unstable();
            right_keys.sort_unstable();
            assert_eq!(
                left_keys, right_keys,
                "the SDK and the server disagree about the field names at {path}"
            );
            for (name, left_value) in left {
                assert_same_fields(left_value, &right[name], &format!("{path}.{name}"));
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            assert_eq!(
                left.len(),
                right.len(),
                "the SDK and the server disagree about the array length at {path}"
            );
            for (index, (left_value, right_value)) in left.iter().zip(right).enumerate() {
                assert_same_fields(left_value, right_value, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

/// Assert that the SDK understands the server's answer, and that its own
/// serialization has the same field names.
fn assert_response<Server, Sdk>(label: &str, server: &Server, sdk: &Sdk)
where
    Server: Serialize + Debug,
    Sdk: DeserializeOwned + Serialize + PartialEq + Debug,
{
    let server_json = serde_json::to_value(server).expect("serialize the server DTO");
    let sdk_value: Sdk = serde_json::from_value(server_json.clone()).unwrap_or_else(|error| {
        panic!("the SDK must accept the server's {label}: {error}\nserver JSON: {server_json}")
    });
    assert_eq!(
        &sdk_value, sdk,
        "the SDK's {label} does not match the value it reads from the server"
    );
    let sdk_json = serde_json::to_value(&sdk_value).expect("serialize the SDK DTO");
    assert_same_fields(&server_json, &sdk_json, label);

    // The SDK's own value must survive a round trip through the wire.
    let round_trip: Sdk =
        serde_json::from_value(sdk_json.clone()).expect("re-read the SDK's own answer");
    assert_eq!(
        round_trip, sdk_value,
        "the SDK's {label} does not survive a round trip"
    );
}

/// Assert that the server understands what the SDK sends.
fn assert_request<Server, Sdk>(label: &str, sdk: &Sdk)
where
    Server: DeserializeOwned + Debug,
    Sdk: Serialize + Debug,
{
    let sdk_json = serde_json::to_value(sdk).expect("serialize the SDK request");
    serde_json::from_value::<Server>(sdk_json.clone()).unwrap_or_else(|error| {
        panic!("the server must accept the SDK's {label}: {error}\nSDK JSON: {sdk_json}")
    });
}

/// Deserialize the same JSON into the server's DTO and into the SDK's DTO.
fn assert_both_accept<Server, Sdk>(label: &str, json: Value) -> (Server, Sdk)
where
    Server: DeserializeOwned + Debug,
    Sdk: DeserializeOwned + Debug,
{
    let server: Server = serde_json::from_value(json.clone()).unwrap_or_else(|error| {
        panic!("the server must accept the {label}: {error}\nJSON: {json}")
    });
    let sdk: Sdk = serde_json::from_value(json.clone())
        .unwrap_or_else(|error| panic!("the SDK must accept the {label}: {error}\nJSON: {json}"));
    (server, sdk)
}

const KEY_ID: &str = "6f1c2f6e-9a3d-4a1e-9d2b-0f5a7c9e1d33";
const PLAINTEXT: &str = "b3BsaW4gY29udGVudA=="; // "oplin content"
const CIPHERTEXT: &str = "Y2lwaGVydGV4dA==";
const NONCE: &str = "bm9uY2U=";
const TAG: &str = "dGFn";

// ═══════════════════════════════════════════════════════════════════════════
// Keys
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn key_request_is_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::CreateKeyRequest, CreateKeyRequest>(
        "create-key request",
        json!({ "name": "orders", "spec": "sm4", "tenant_id": "acme" }),
    );

    assert_eq!(server.name, sdk.name);
    assert_eq!(server.spec, sdk.spec.as_str());
    assert_eq!(
        server.tenant_id,
        sdk.tenant_id.expect("the tenant must be kept")
    );

    assert_request::<kms_api::rest::CreateKeyRequest, _>(
        "create-key request",
        &CreateKeyRequest {
            name: "orders".to_string(),
            spec: KeySpec::Sm4,
            tenant_id: Some("acme".to_string()),
        },
    );
}

#[test]
fn key_response_is_understood_by_the_sdk() {
    let server = kms_api::rest::KeyResponse {
        id: Uuid::parse_str(KEY_ID).expect("uuid"),
        tenant_id: "acme".to_string(),
        name: "orders".to_string(),
        spec: "Sm4".to_string(),
        status: "Active".to_string(),
        version: 3,
        created_at: "2026-10-25T08:00:00Z".to_string(),
    };

    let sdk: Key = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.id, server.id);
    assert_eq!(sdk.tenant_id, server.tenant_id);
    assert_eq!(sdk.name, server.name);
    assert_eq!(sdk.spec, KeySpec::Sm4);
    assert_eq!(sdk.status, server.status);
    assert_eq!(sdk.version, server.version);
    assert_eq!(sdk.created_at, server.created_at);

    assert_response("key response", &server, &sdk);
}

/// The server answers with the Debug spelling of its internal enum; the SDK
/// must understand both that and its own canonical spelling.
#[test]
fn key_spec_accepts_every_spelling_the_server_uses() {
    for (server_spelling, expected) in [
        ("Aes256Gcm", KeySpec::Aes256Gcm),
        ("aes-256-gcm", KeySpec::Aes256Gcm),
        ("aes256gcm", KeySpec::Aes256Gcm),
        ("Sm4", KeySpec::Sm4),
        ("sm4", KeySpec::Sm4),
        ("Sm3Hmac", KeySpec::Sm3Hmac),
        ("sm3-hmac", KeySpec::Sm3Hmac),
        ("Rsa4096", KeySpec::Rsa4096),
        ("rsa-4096", KeySpec::Rsa4096),
    ] {
        assert_eq!(
            KeySpec::parse(server_spelling),
            expected,
            "the SDK must understand the spelling {server_spelling}"
        );
    }

    // An unknown specification is kept, not rejected: a newer server may know
    // algorithms this SDK does not.
    assert_eq!(KeySpec::parse("sm9-signing"), KeySpec::Sm9Signing);
    assert_eq!(
        KeySpec::parse("future-algorithm"),
        KeySpec::Other("future-algorithm".to_string())
    );
    // ...and it survives a round trip unchanged.
    let unknown = KeySpec::parse("future-algorithm");
    let json = serde_json::to_string(&unknown).unwrap();
    assert_eq!(json, "\"future-algorithm\"");
}

// ═══════════════════════════════════════════════════════════════════════════
// Cryptographic operations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn encrypt_request_is_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::EncryptRequest, EncryptRequest>(
        "encrypt request",
        json!({ "plaintext": PLAINTEXT, "aad": null }),
    );

    assert_eq!(server.plaintext, PLAINTEXT);
    assert_eq!(server.aad, None);
    assert_eq!(sdk.plaintext, b"oplin content");
    assert_eq!(sdk.aad, None);

    assert_request::<kms_api::rest::EncryptRequest, _>(
        "encrypt request",
        &EncryptRequest {
            plaintext: b"oplin content".to_vec(),
            aad: None,
        },
    );
}

#[test]
fn encrypt_response_is_understood_by_the_sdk() {
    let server = kms_api::rest::EncryptResponse {
        ciphertext: CIPHERTEXT.to_string(),
        nonce: NONCE.to_string(),
        tag: TAG.to_string(),
        format_version: 2,
        version: 1,
    };

    let sdk: EncryptedData =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.ciphertext, b"ciphertext");
    assert_eq!(sdk.nonce, b"nonce");
    assert_eq!(sdk.tag, b"tag");
    assert_eq!(sdk.format_version, server.format_version);
    assert_eq!(sdk.version, server.version);

    assert_response("encrypt response", &server, &sdk);
}

#[test]
fn decrypt_request_is_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::DecryptRequest, DecryptRequest>(
        "decrypt request",
        json!({
            "ciphertext": CIPHERTEXT,
            "nonce": NONCE,
            "tag": TAG,
            "aad": null,
            "format_version": 2,
            "version": 1,
        }),
    );

    assert_eq!(server.ciphertext, CIPHERTEXT);
    assert_eq!(server.format_version, 2);
    assert_eq!(server.version, 1);
    assert_eq!(sdk.ciphertext, b"ciphertext");
    assert_eq!(sdk.format_version, 2);
    assert_eq!(sdk.version, 1);

    assert_request::<kms_api::rest::DecryptRequest, _>(
        "decrypt request",
        &DecryptRequest {
            ciphertext: b"ciphertext".to_vec(),
            nonce: b"nonce".to_vec(),
            tag: b"tag".to_vec(),
            aad: None,
            format_version: 2,
            version: 1,
        },
    );
}

#[test]
fn decrypt_response_is_understood_by_the_sdk() {
    let server = kms_api::rest::DecryptResponse {
        plaintext: PLAINTEXT.to_string(),
    };

    let sdk: DecryptResult =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.plaintext, b"oplin content");

    assert_response("decrypt response", &server, &sdk);
}

#[test]
fn sign_and_verify_requests_are_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::SignRequest, SignRequest>(
        "sign request",
        json!({ "data": PLAINTEXT }),
    );
    assert_eq!(server.data, PLAINTEXT);
    assert_eq!(sdk.data, b"oplin content");

    assert_request::<kms_api::rest::SignRequest, _>(
        "sign request",
        &SignRequest {
            data: b"oplin content".to_vec(),
        },
    );

    let (server, sdk) = assert_both_accept::<kms_api::rest::VerifyRequest, VerifyRequest>(
        "verify request",
        json!({ "data": PLAINTEXT, "signature": CIPHERTEXT }),
    );
    assert_eq!(server.signature, CIPHERTEXT);
    assert_eq!(sdk.signature, b"ciphertext");

    assert_request::<kms_api::rest::VerifyRequest, _>(
        "verify request",
        &VerifyRequest {
            data: b"oplin content".to_vec(),
            signature: b"ciphertext".to_vec(),
        },
    );
}

#[test]
fn sign_and_verify_responses_are_understood_by_the_sdk() {
    let server = kms_api::rest::SignResponse {
        signature: CIPHERTEXT.to_string(),
        version: 2,
    };
    let sdk: Signature = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.signature, b"ciphertext");
    assert_eq!(sdk.version, 2);
    assert_response("sign response", &server, &sdk);

    let server = kms_api::rest::VerifyResponse { valid: true };
    let sdk: VerifyResult = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert!(sdk.valid);
    assert_response("verify response", &server, &sdk);
}

#[test]
fn hmac_requests_are_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::HmacRequest, HmacRequest>(
        "hmac request",
        json!({ "data": PLAINTEXT, "aad": null }),
    );
    assert_eq!(server.data, PLAINTEXT);
    assert_eq!(sdk.data, b"oplin content");

    assert_request::<kms_api::rest::HmacRequest, _>(
        "hmac request",
        &HmacRequest {
            data: b"oplin content".to_vec(),
            aad: None,
        },
    );

    let (server, sdk) = assert_both_accept::<kms_api::rest::HmacVerifyRequest, HmacVerifyRequest>(
        "hmac-verify request",
        json!({ "data": PLAINTEXT, "mac": TAG, "aad": null }),
    );
    assert_eq!(server.mac, TAG);
    assert_eq!(sdk.mac, b"tag");

    assert_request::<kms_api::rest::HmacVerifyRequest, _>(
        "hmac-verify request",
        &HmacVerifyRequest {
            data: b"oplin content".to_vec(),
            mac: b"tag".to_vec(),
            aad: None,
        },
    );
}

#[test]
fn hmac_response_is_understood_by_the_sdk() {
    let server = kms_api::rest::HmacResponse {
        mac: TAG.to_string(),
        version: 1,
    };
    let sdk: MacTag = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.mac, b"tag");
    assert_eq!(sdk.version, 1);
    assert_response("hmac response", &server, &sdk);
}

#[test]
fn hash_request_and_response_are_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::HashRequest, HashRequest>(
        "hash request",
        json!({ "data": PLAINTEXT, "algorithm": "sm3" }),
    );
    assert_eq!(server.algorithm, "sm3");
    assert_eq!(sdk.algorithm, HashAlgorithm::Sm3);

    assert_request::<kms_api::rest::HashRequest, _>(
        "hash request",
        &HashRequest {
            data: b"oplin content".to_vec(),
            algorithm: HashAlgorithm::Sm3,
        },
    );

    let server = kms_api::rest::HashResponse {
        hash: "66c2f1".to_string(),
        algorithm: "sm3".to_string(),
    };
    let sdk: HashResult = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.hash, "66c2f1");
    assert_eq!(sdk.algorithm, "sm3");
    assert_response("hash response", &server, &sdk);
}

// ═══════════════════════════════════════════════════════════════════════════
// Envelope encryption
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn envelope_requests_are_understood_by_both_sides() {
    let (server, sdk) =
        assert_both_accept::<kms_api::rest::EnvelopeEncryptRequest, EnvelopeEncryptRequest>(
            "envelope-encrypt request",
            json!({
                "plaintext": PLAINTEXT,
                "kek_id": KEY_ID,
                "dek_length": 32,
                "tenant_id": "acme",
            }),
        );
    assert_eq!(server.kek_id, KEY_ID);
    assert_eq!(server.dek_length, Some(32));
    assert_eq!(sdk.kek_id, Uuid::parse_str(KEY_ID).unwrap());
    assert_eq!(sdk.dek_length, Some(32));

    assert_request::<kms_api::rest::EnvelopeEncryptRequest, _>(
        "envelope-encrypt request",
        &EnvelopeEncryptRequest {
            plaintext: b"oplin content".to_vec(),
            kek_id: Uuid::parse_str(KEY_ID).unwrap(),
            dek_length: Some(32),
            tenant_id: Some("acme".to_string()),
        },
    );

    let (server, sdk) =
        assert_both_accept::<kms_api::rest::EnvelopeDecryptRequest, EnvelopeDecryptRequest>(
            "envelope-decrypt request",
            json!({
                "wrapped_dek": CIPHERTEXT,
                "dek_nonce": NONCE,
                "ciphertext": CIPHERTEXT,
                "data_nonce": NONCE,
                "tag": TAG,
                "kek_id": KEY_ID,
                "kek_version": 2,
                "tenant_id": "acme",
            }),
        );
    assert_eq!(server.kek_version, 2);
    assert_eq!(sdk.kek_version, 2);
    assert_eq!(sdk.kek_id, Uuid::parse_str(KEY_ID).unwrap());

    assert_request::<kms_api::rest::EnvelopeDecryptRequest, _>(
        "envelope-decrypt request",
        &EnvelopeDecryptRequest {
            wrapped_dek: b"ciphertext".to_vec(),
            dek_nonce: b"nonce".to_vec(),
            ciphertext: b"ciphertext".to_vec(),
            data_nonce: b"nonce".to_vec(),
            tag: b"tag".to_vec(),
            kek_id: Uuid::parse_str(KEY_ID).unwrap(),
            kek_version: 2,
            tenant_id: Some("acme".to_string()),
        },
    );

    let (server, sdk) =
        assert_both_accept::<kms_api::rest::EnvelopeRewrapRequest, EnvelopeRewrapRequest>(
            "envelope-rewrap request",
            json!({
                "wrapped_dek": CIPHERTEXT,
                "dek_nonce": NONCE,
                "kek_id": KEY_ID,
                "old_kek_version": 1,
                "tenant_id": "acme",
            }),
        );
    assert_eq!(server.old_kek_version, 1);
    assert_eq!(sdk.old_kek_version, 1);

    assert_request::<kms_api::rest::EnvelopeRewrapRequest, _>(
        "envelope-rewrap request",
        &EnvelopeRewrapRequest {
            wrapped_dek: b"ciphertext".to_vec(),
            dek_nonce: b"nonce".to_vec(),
            kek_id: Uuid::parse_str(KEY_ID).unwrap(),
            old_kek_version: 1,
            tenant_id: Some("acme".to_string()),
        },
    );
}

#[test]
fn envelope_responses_are_understood_by_the_sdk() {
    let server = kms_api::rest::EnvelopeEncryptResponse {
        wrapped_dek: CIPHERTEXT.to_string(),
        dek_nonce: NONCE.to_string(),
        ciphertext: CIPHERTEXT.to_string(),
        data_nonce: NONCE.to_string(),
        tag: TAG.to_string(),
        kek_version: 3,
    };
    let sdk: EnvelopeEncrypted =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.wrapped_dek, b"ciphertext");
    assert_eq!(sdk.kek_version, 3);
    assert_response("envelope-encrypt response", &server, &sdk);

    let server = kms_api::rest::EnvelopeDecryptResponse {
        plaintext: PLAINTEXT.to_string(),
    };
    let sdk: DecryptResult =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.plaintext, b"oplin content");
    assert_response("envelope-decrypt response", &server, &sdk);

    let server = kms_api::rest::EnvelopeRewrapResponse {
        wrapped_dek: CIPHERTEXT.to_string(),
        dek_nonce: NONCE.to_string(),
        kek_version: 4,
        old_kek_version: 3,
    };
    let sdk: EnvelopeRewrapped =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.kek_version, 4);
    assert_eq!(sdk.old_kek_version, 3);
    assert_response("envelope-rewrap response", &server, &sdk);
}

// ═══════════════════════════════════════════════════════════════════════════
// Import and export
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn import_request_is_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::ImportKeyRequest, ImportKeyRequest>(
        "import request",
        json!({
            "name": "imported",
            "spec": "rsa-4096",
            "format": "pkcs8",
            "wrapped_key": CIPHERTEXT,
            "encrypted_transport_key": CIPHERTEXT,
            "source_fingerprint": "ab12",
            "tenant_id": "acme",
        }),
    );
    assert_eq!(server.spec, "rsa-4096");
    assert_eq!(server.format, "pkcs8");
    assert_eq!(sdk.spec, KeySpec::Rsa4096);
    assert_eq!(sdk.format, "pkcs8");

    assert_request::<kms_api::rest::ImportKeyRequest, _>(
        "import request",
        &ImportKeyRequest {
            name: "imported".to_string(),
            spec: KeySpec::Rsa4096,
            format: "pkcs8".to_string(),
            wrapped_key: b"ciphertext".to_vec(),
            encrypted_transport_key: b"ciphertext".to_vec(),
            source_fingerprint: "ab12".to_string(),
            tenant_id: Some("acme".to_string()),
        },
    );
}

#[test]
fn import_response_is_understood_by_the_sdk() {
    let server = kms_api::rest::ImportKeyResponse {
        id: KEY_ID.to_string(),
        spec: "Rsa4096".to_string(),
        imported: true,
        source_fingerprint: "ab12".to_string(),
    };
    let sdk: ImportKeyResult =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.id, KEY_ID);
    assert_eq!(sdk.spec, "Rsa4096");
    assert!(sdk.imported);
    assert_response("import response", &server, &sdk);
}

#[test]
fn export_request_is_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::ExportKeyRequest, ExportKeyRequest>(
        "export request",
        json!({
            "target_system": "migration",
            "target_public_key": CIPHERTEXT,
            "purpose": "migration",
            "approval_id": "8a1f",
            "protection_scheme": "rsa-oaep",
            "version": 2,
        }),
    );
    assert_eq!(server.approval_id.as_deref(), Some("8a1f"));
    assert_eq!(server.protection_scheme.as_deref(), Some("rsa-oaep"));
    assert_eq!(server.version, Some(2));
    assert_eq!(sdk.approval_id.as_deref(), Some("8a1f"));
    assert_eq!(sdk.protection_scheme.as_deref(), Some("rsa-oaep"));
    assert_eq!(sdk.version, Some(2));

    // The key id and the tenant travel beside the body, not in it.
    assert_eq!(sdk.key_id, Uuid::nil());

    assert_request::<kms_api::rest::ExportKeyRequest, _>(
        "export request",
        &ExportKeyRequest {
            key_id: Uuid::parse_str(KEY_ID).unwrap(),
            target_system: "migration".to_string(),
            target_public_key: CIPHERTEXT.to_string(),
            purpose: "migration".to_string(),
            approval_id: Some("8a1f".to_string()),
            protection_scheme: Some("rsa-oaep".to_string()),
            version: Some(2),
            tenant_id: Some("acme".to_string()),
        },
    );
}

#[test]
fn export_response_is_understood_by_the_sdk() {
    let server = kms_api::rest::ExportKeyResponse {
        wrapped_key: CIPHERTEXT.to_string(),
        encrypted_transport_key: CIPHERTEXT.to_string(),
        key_fingerprint: "ab12".to_string(),
    };
    let sdk: ExportKeyResult =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.wrapped_key, b"ciphertext");
    assert_eq!(sdk.key_fingerprint, "ab12");
    assert_response("export response", &server, &sdk);
}

// ═══════════════════════════════════════════════════════════════════════════
// Approvals
// ═══════════════════════════════════════════════════════════════════════════

/// The server's approval request DTO is private (`rest::CreateApprovalReq`),
/// so the shape is written out here instead of being taken from the server.
#[test]
fn approval_request_is_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<ServerApprovalRequest, CreateApprovalRequest>(
        "approval request",
        json!({
            "operation": "key_export",
            "resource_id": KEY_ID,
            "resource_type": "key",
            "tenant_id": "acme",
            "requestor_id": "ignored",
            "justification": "quarterly migration",
        }),
    );

    assert_eq!(server.operation, "key_export");
    assert_eq!(server.resource_id, KEY_ID);
    assert_eq!(server.tenant_id, "acme");
    // The identity fields are still accepted (for wire compatibility) but the
    // server derives the requestor from the API key (audit follow-up B7-a).
    assert_eq!(server.resource_type, "key");
    assert_eq!(server.requestor_id, "ignored");
    assert_eq!(server.justification.as_deref(), Some("quarterly migration"));
    assert_eq!(sdk.operation, ApprovalOperation::KeyExport);
    assert_eq!(sdk.resource_id, KEY_ID);
    assert_eq!(sdk.justification.as_deref(), Some("quarterly migration"));
    assert_eq!(sdk.tenant_id.as_deref(), Some("acme"));
}

#[test]
fn approval_response_is_understood_by_the_sdk() {
    let server = kms_api::approval::ApprovalRequestResponse {
        id: "8a1f".to_string(),
        operation: "key_export".to_string(),
        resource_id: KEY_ID.to_string(),
        resource_type: "key".to_string(),
        tenant_id: "acme".to_string(),
        requestor_id: "admin".to_string(),
        justification: Some("quarterly migration".to_string()),
        status: "approved".to_string(),
        required_level: "triple".to_string(),
        current_level: "triple".to_string(),
        approvals_count: 3,
        rejections_count: 0,
        created_at: "2026-10-25T08:00:00Z".to_string(),
        expires_at: "2026-10-26T08:00:00Z".to_string(),
        completed_at: Some("2026-10-25T08:05:00Z".to_string()),
    };

    let sdk: Approval = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.id, "8a1f");
    assert_eq!(sdk.operation, "key_export");
    assert_eq!(sdk.status, ApprovalStatus::Approved);
    assert_eq!(sdk.required_level, ApprovalLevel::Triple);
    assert_eq!(sdk.current_level, ApprovalLevel::Triple);
    assert_eq!(sdk.approvals_count, 3);
    assert_eq!(sdk.completed_at.as_deref(), Some("2026-10-25T08:05:00Z"));

    assert_response("approval response", &server, &sdk);
}

/// The approve and reject bodies carry nothing but the comment and the reason:
/// the identity comes from the API key.
#[test]
fn approval_decisions_carry_only_the_comment_and_the_reason() {
    let approve = ApproveRequest {
        comment: Some("looks good".to_string()),
    };
    let json = serde_json::to_value(&approve).unwrap();
    assert_eq!(json, json!({ "comment": "looks good" }));
    // The server ignores unknown fields, and its own DTO defaults them.
    let server: ServerApproveRequest = serde_json::from_value(json).unwrap();
    assert_eq!(server.comment.as_deref(), Some("looks good"));
    // The SDK sends no approver identity at all: the server would ignore it
    // anyway (audit follow-up B7-a), so the SDK does not offer the field.
    assert_eq!(server.approver_id, "");
    assert_eq!(server.approver_role, "");

    let reject = RejectRequest {
        reason: "not needed".to_string(),
    };
    let json = serde_json::to_value(&reject).unwrap();
    assert_eq!(json, json!({ "reason": "not needed" }));
    let server: ServerRejectRequest = serde_json::from_value(json).unwrap();
    assert_eq!(server.reason, "not needed");
    assert_eq!(server.rejector_id, "");
    assert_eq!(server.rejector_role, "");
}

// ═══════════════════════════════════════════════════════════════════════════
// Policies and health
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn policy_request_and_response_are_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::CreatePolicyRequest, CreatePolicyRequest>(
        "policy request",
        json!({
            "name": "allow-all",
            "effect": "allow",
            "condition": { "operator": "always" },
            "resources": ["*"],
            "subjects": ["*"],
            "enabled": true,
        }),
    );
    assert_eq!(server.effect, "allow");
    assert_eq!(server.resources, vec!["*".to_string()]);
    assert_eq!(sdk.effect, gm_kms_sdk::PolicyEffect::Allow);
    assert_eq!(sdk.resources, vec!["*".to_string()]);

    assert_request::<kms_api::rest::CreatePolicyRequest, _>(
        "policy request",
        &CreatePolicyRequest {
            name: "allow-all".to_string(),
            effect: gm_kms_sdk::PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            tenant: None,
            enabled: true,
        },
    );

    let server = kms_api::rest::PolicyResponse {
        id: "p1".to_string(),
        name: "allow-all".to_string(),
        effect: "Allow".to_string(),
        condition: json!({ "operator": "always" }),
        resources: vec!["*".to_string()],
        subjects: vec!["*".to_string()],
        tenant: None,
        enabled: true,
    };
    let sdk: Policy = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.id, "p1");
    assert_eq!(sdk.effect, "Allow");
    assert_response("policy response", &server, &sdk);
}

#[test]
fn health_response_is_understood_by_the_sdk() {
    let server = kms_api::rest::HealthResponse {
        status: "ok".to_string(),
        version: "0.3.0".to_string(),
        components: kms_api::rest::ComponentHealth {
            keystore: "healthy".to_string(),
            audit: "healthy".to_string(),
        },
    };
    let sdk: Health = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.status, "ok");
    assert_eq!(sdk.version, "0.3.0");
    assert_eq!(sdk.components.keystore, "healthy");
    assert_response("health response", &server, &sdk);
}

// ═══════════════════════════════════════════════════════════════════════════
// SM9 and key derivation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sm9_requests_are_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::Sm9SignRequest, Sm9SignRequest>(
        "sm9-sign request",
        json!({ "identity": "alice@example.com", "data": PLAINTEXT }),
    );
    assert_eq!(server.identity, "alice@example.com");
    assert_eq!(sdk.data, b"oplin content");

    assert_request::<kms_api::rest::Sm9SignRequest, _>(
        "sm9-sign request",
        &Sm9SignRequest {
            identity: "alice@example.com".to_string(),
            data: b"oplin content".to_vec(),
        },
    );

    let (server, sdk) = assert_both_accept::<kms_api::rest::Sm9VerifyRequest, Sm9VerifyRequest>(
        "sm9-verify request",
        json!({
            "identity": "alice@example.com",
            "data": PLAINTEXT,
            "w": CIPHERTEXT,
            "h": "66c2f1",
            "s": CIPHERTEXT,
        }),
    );
    assert_eq!(server.h, "66c2f1");
    assert_eq!(sdk.h, "66c2f1");
    assert_eq!(sdk.w, b"ciphertext");

    let (server, sdk) = assert_both_accept::<kms_api::rest::Sm9EncryptRequest, Sm9EncryptRequest>(
        "sm9-encrypt request",
        json!({ "identity": "bob@example.com", "plaintext": PLAINTEXT }),
    );
    assert_eq!(server.plaintext, PLAINTEXT);
    assert_eq!(sdk.plaintext, b"oplin content");

    let (server, sdk) = assert_both_accept::<kms_api::rest::Sm9DecryptRequest, Sm9DecryptRequest>(
        "sm9-decrypt request",
        json!({
            "identity": "bob@example.com",
            "c1": CIPHERTEXT,
            "c2": CIPHERTEXT,
            "c3": "66c2f1",
        }),
    );
    assert_eq!(server.c3, "66c2f1");
    assert_eq!(sdk.c3, "66c2f1");
}

#[test]
fn sm9_responses_are_understood_by_the_sdk() {
    let server = kms_api::rest::Sm9SignResponse {
        w: CIPHERTEXT.to_string(),
        h: "66c2f1".to_string(),
        s: CIPHERTEXT.to_string(),
    };
    let sdk: Sm9Signature = serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.w, b"ciphertext");
    assert_eq!(sdk.h, "66c2f1");
    assert_response("sm9-sign response", &server, &sdk);

    let server = kms_api::rest::Sm9EncryptResponse {
        c1: CIPHERTEXT.to_string(),
        c2: CIPHERTEXT.to_string(),
        c3: "66c2f1".to_string(),
    };
    let sdk: Sm9Ciphertext =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.c1, b"ciphertext");
    assert_eq!(sdk.c3, "66c2f1");
    assert_response("sm9-encrypt response", &server, &sdk);
}

#[test]
fn dh_derive_request_and_response_are_understood_by_both_sides() {
    let (server, sdk) = assert_both_accept::<kms_api::rest::DhDeriveRequest, DhDeriveRequest>(
        "dh-derive request",
        json!({
            "key_id": KEY_ID,
            "algorithm": "ECDH-P256",
            "peer_public_key": CIPHERTEXT,
            "tenant_id": "acme",
        }),
    );
    assert_eq!(server.algorithm, "ECDH-P256");
    assert_eq!(sdk.key_id, Uuid::parse_str(KEY_ID).unwrap());
    assert_eq!(sdk.peer_public_key, b"ciphertext");

    assert_request::<kms_api::rest::DhDeriveRequest, _>(
        "dh-derive request",
        &DhDeriveRequest {
            key_id: Uuid::parse_str(KEY_ID).unwrap(),
            algorithm: "ECDH-P256".to_string(),
            peer_public_key: b"ciphertext".to_vec(),
            tenant_id: Some("acme".to_string()),
        },
    );

    let server = kms_api::rest::DhDeriveResponse {
        shared_secret: CIPHERTEXT.to_string(),
        kdf: "HKDF-SHA256".to_string(),
    };
    let sdk: DerivedSecret =
        serde_json::from_value(serde_json::to_value(&server).unwrap()).unwrap();
    assert_eq!(sdk.shared_secret, b"ciphertext");
    assert_eq!(sdk.kdf, "HKDF-SHA256");
    assert_response("dh-derive response", &server, &sdk);
}

// ═══════════════════════════════════════════════════════════════════════════
// The server's private approval DTOs, mirrored
// ═══════════════════════════════════════════════════════════════════════════

/// The mirror of the server's private `rest::CreateApprovalReq`.
#[derive(Debug, serde::Deserialize)]
struct ServerApprovalRequest {
    operation: String,
    resource_id: String,
    #[serde(default)]
    resource_type: String,
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    requestor_id: String,
    justification: Option<String>,
}

/// The mirror of the server's private `rest::ApproveReq`.
#[derive(Debug, serde::Deserialize)]
struct ServerApproveRequest {
    #[serde(default)]
    approver_id: String,
    #[serde(default)]
    approver_role: String,
    comment: Option<String>,
}

/// The mirror of the server's private `rest::RejectReq`.
#[derive(Debug, serde::Deserialize)]
struct ServerRejectRequest {
    #[serde(default)]
    rejector_id: String,
    #[serde(default)]
    rejector_role: String,
    reason: String,
}
