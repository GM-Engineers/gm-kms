# GM-KMS Rust SDK

Rust SDK for GM-KMS (国密 Key Management Service).

The SDK speaks the same REST/JSON channel as the Go, Python and JavaScript
SDKs: no `protoc`, no gRPC bindings, no code generation. `reqwest` with
`rustls-tls` keeps it free of a system OpenSSL dependency.

## Installation

The SDK is a member of the `gm-kms` workspace, so a workspace that already
depends on `gm-kms` picks it up automatically:

```toml
[dependencies]
gm-kms-sdk = { path = "../gm-kms/sdk/rust" }
```

## Quick start

```rust
use gm_kms_sdk::{Client, CreateKeyRequest, EncryptRequest, KeySpec};

let kms = Client::builder("https://kms.example.com")
    .api_key("your-api-key")
    .tenant("tenant-1")
    .build()?;

// Create a key.
let key = kms
    .create_key(&CreateKeyRequest {
        name: "orders".to_string(),
        spec: KeySpec::Sm4,
        tenant_id: None,
    })
    .await?;

// Encrypt and decrypt.
let plaintext = "订单 42".as_bytes();
let sealed = kms
    .encrypt(
        &key.id,
        &EncryptRequest {
            plaintext: plaintext.to_vec(),
            aad: None,
        },
        None,
    )
    .await?;

let opened = kms.decrypt(&key.id, &sealed.to_decrypt_request(), None).await?;
assert_eq!(opened, plaintext);
```

## Design

### The wire types are public

Every request body is a public type that mirrors the server's REST DTO
(`crates/kms-api/src/rest.rs`) field for field, and every response body is a
public type that mirrors the server's answer. The SDK does not hide the wire
format behind a façade, so a caller can always see exactly what goes out.

Binary payloads cross the wire as base64 strings, exactly as the server encodes
them. The SDK hides *that*: the request and response types carry raw `Vec<u8>`
and do the encoding themselves.

### The key specification is typed

The server accepts several spellings of the same algorithm (`"aes-256-gcm"`,
`"aes256gcm"`, …) and answers with the `Debug` spelling of its own enum
(`"Aes256Gcm"`). `KeySpec::parse` accepts all of them, and `KeySpec::as_str`
returns the canonical spelling the SDK sends.

A specification this SDK version does not know about is kept verbatim in
`KeySpec::Other` instead of failing: a newer server may know algorithms this
SDK does not, and an SDK that refused to represent them would break the moment
it was used against that server.

### Errors: 400 and 403 are not the same

Every call returns `Result<T, KmsError>`. A refusal by the server comes back
as `KmsError::Api`, which carries the HTTP status code and the server's
message:

| Status | Meaning |
| ------ | ------- |
| **400** | The request itself was malformed: a missing or invalid `approval_id`, an unknown key specification. |
| **403** | The request was well-formed but the caller is not authorized: an expired approval, one bound to another key, a PBAC denial. |

`KmsError` offers `status()`, `message()`, `is_forbidden()`, `is_not_found()`,
`is_unauthorized()` and `is_rate_limited()`.

### Approvals

A key export needs an approved `KeyExport` request. The approver's identity and
authority come from the authenticated API key, so **one key is one vote**: a
multi-party quorum needs several *distinct* keys, not one key replayed.

```rust
use gm_kms_sdk::{ApprovalOperation, CreateApprovalRequest};

let approval = kms
    .create_approval(&CreateApprovalRequest {
        operation: ApprovalOperation::KeyExport,
        resource_id: key_id.to_string(),
        justification: Some("quarterly migration".to_string()),
        tenant_id: None,
    })
    .await?;
```

## The drift guards

The SDK is a second implementation of the REST contract, so a change on either
side that breaks the other must fail the build rather than a customer's
application. Two test suites guard that:

- `tests/contract.rs` — the **shape** guard. Every request body is fed to the
  server's own DTO (which must accept it) and every server answer is fed to
  the SDK's DTO (which must accept it), with the field names compared all the
  way down.
- `tests/e2e.rs` — the **meaning** guard. A real `kms-api` server is booted on
  a loopback port and the SDK walks the whole life of a key through it:
  create → encrypt → decrypt → hmac → hmac/verify → approve → export. The
  refusals that matter are checked through the SDK as well: an export without
  an approval (400), an export unlocked by an expired approval (403), and an
  unknown key (404).

```bash
cargo test -p gm-kms-sdk
```

## License

MIT OR Apache-2.0