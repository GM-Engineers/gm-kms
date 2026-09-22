//! AAD (Additional Authenticated Data) binding for ciphertexts.
//!
//! GCM AEAD requires that the sender and receiver agree on the AAD bytes
//! for every authentication tag. Binding AAD to a stable, unforgeable
//! identifier of the ciphertext's *semantic context* (which key, which
//! tenant, which version, which purpose) means that any tamper with the
//! database row — swapping a ciphertext from one key/tenant/version to
//! another — causes the GCM tag check to fail.
//!
//! # Wire format (format_version = 2)
//!
//! All multi-byte integers are big-endian. Total = 42 bytes.
//!
//! | Offset | Length | Field                       |
//! |--------|--------|-----------------------------|
//! | 0      | 2      | magic = `0x6D 0xB5`         |
//! | 2      | 2      | aad_version = `0x02 0x00`   |
//! | 4      | 2      | purpose tag (`u16 BE`)      |
//! | 6      | 16     | key_id (UUID, big-endian)   |
//! | 22     | 16     | tenant hash (`SHA-256[..16]` of UTF-8 tenant name) |
//! | 38     | 4      | key version (`u32 BE`)      |
//!
//! # Compatibility with `format_version` ∈ {0, 1}
//!
//! Ciphertexts created before PR-1.4 carry an empty AAD. The decrypt path
//! branches on `Ciphertext::format_version`: legacy ciphertexts continue
//! to decrypt with empty AAD; new ciphertexts (`format_version == 2`)
//! must decrypt with the v2 AAD reconstructed from the same (key, tenant,
//! version) triple, or the tag check fails.

use ring::digest::{Context, SHA256};
use uuid::Uuid;

/// Magic marker prefix used to distinguish v2 AAD from random bytes.
pub const AAD_MAGIC: [u8; 2] = [0x6D, 0xB5];

/// AAD wire format version. Bump together with `AAD_MAGIC` if the layout
/// changes in a backward-incompatible way.
pub const AAD_VERSION: u16 = 2;

/// Total length, in bytes, of a v2 AAD blob.
pub const AAD_V2_LEN: usize = 42;

/// What role a ciphertext plays in the system.
///
/// Different purposes get different AAD tags so an attacker cannot lift a
/// valid `UserData` ciphertext and replay it as a `KekWrap` envelope (or
/// vice versa) — even if both happen to use the same AES-256-GCM key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Purpose {
    /// A regular user-data ciphertext produced by `CryptoService.encrypt`.
    UserData = 0x0001,
    /// A KEK-wrapped copy of a stored key material (Postgres backend).
    KekWrap = 0x0002,
    /// A transport-key-wrapped export envelope (`KeyService.export_key`).
    ExportWrap = 0x0003,
}

impl Purpose {
    fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

/// Compute the SHA-256(tenant_name)[..16] used inside the AAD blob.
///
/// Truncating to 16 bytes (128 bits) keeps the AAD length fixed
/// regardless of tenant name length and avoids putting high-cardinality
/// string bytes verbatim into the AAD. The collision probability for a
/// multi-tenant system is bounded by the birthday bound at 2^64 tenants,
/// which is far above any realistic deployment.
fn tenant_hash(tenant_id: &str) -> [u8; 16] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(tenant_id.as_bytes());
    let digest = ctx.finish();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_ref()[..16]);
    out
}

/// Construct the v2 AAD blob for a user-data ciphertext produced by the
/// keystore (CryptoService.encrypt/decrypt).
pub fn user_data_aad(key_id: Uuid, tenant_id: &str, version: u32) -> Vec<u8> {
    build_v2(Purpose::UserData, key_id, &tenant_hash(tenant_id), version)
}

/// Construct the v2 AAD blob for a KEK-wrapped stored material envelope
/// (Postgres backend `encrypt_material` / `decrypt_material`).
pub fn kek_wrap_aad(key_id: Uuid) -> Vec<u8> {
    // The KEK envelope has only one key in scope (the wrapped material's
    // own key_id) and no tenant context — Postgres is a single-process
    // backend. A fixed zero tenant hash keeps the AAD length uniform.
    let zero = [0u8; 16];
    build_v2(Purpose::KekWrap, key_id, &zero, 0)
}

/// Construct the v2 AAD blob for a transport-key-wrapped export envelope
/// (`KeyService.export_key`).
pub fn export_wrap_aad(key_id: Uuid, tenant_id: &str) -> Vec<u8> {
    build_v2(Purpose::ExportWrap, key_id, &tenant_hash(tenant_id), 0)
}

fn build_v2(purpose: Purpose, key_id: Uuid, tenant_hash: &[u8; 16], version: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AAD_V2_LEN);
    buf.extend_from_slice(&AAD_MAGIC);
    buf.extend_from_slice(&AAD_VERSION.to_be_bytes());
    buf.extend_from_slice(&purpose.to_be_bytes());
    buf.extend_from_slice(key_id.as_bytes());
    buf.extend_from_slice(tenant_hash);
    buf.extend_from_slice(&version.to_be_bytes());
    debug_assert_eq!(buf.len(), AAD_V2_LEN);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_v2_length_is_42() {
        let aad = user_data_aad(Uuid::nil(), "tenant-a", 1);
        assert_eq!(aad.len(), AAD_V2_LEN);
    }

    #[test]
    fn aad_v2_starts_with_magic_and_version() {
        let aad = user_data_aad(Uuid::nil(), "tenant-a", 1);
        assert_eq!(&aad[..2], &AAD_MAGIC);
        assert_eq!(u16::from_be_bytes([aad[2], aad[3]]), AAD_VERSION);
    }

    #[test]
    fn aad_is_deterministic() {
        let id = Uuid::new_v4();
        let a = user_data_aad(id, "tenant-a", 7);
        let b = user_data_aad(id, "tenant-a", 7);
        assert_eq!(a, b);
    }

    #[test]
    fn aad_differs_on_key_id() {
        let a = user_data_aad(Uuid::new_v4(), "tenant-a", 1);
        let b = user_data_aad(Uuid::new_v4(), "tenant-a", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_differs_on_tenant() {
        let id = Uuid::new_v4();
        let a = user_data_aad(id, "tenant-a", 1);
        let b = user_data_aad(id, "tenant-b", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_differs_on_version() {
        let id = Uuid::new_v4();
        let a = user_data_aad(id, "tenant-a", 1);
        let b = user_data_aad(id, "tenant-a", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn aad_differs_on_purpose() {
        let id = Uuid::new_v4();
        let ud = user_data_aad(id, "t", 1);
        let ke = kek_wrap_aad(id);
        let ex = export_wrap_aad(id, "t");
        assert_ne!(ud, ke);
        assert_ne!(ud, ex);
        assert_ne!(ke, ex);
    }

    #[test]
    fn tenant_hash_is_first_16_bytes_of_sha256() {
        // SHA-256("tenant-a") = f7bc83...
        let h = tenant_hash("tenant-a");
        let mut ctx = Context::new(&SHA256);
        ctx.update(b"tenant-a");
        let full = ctx.finish();
        assert_eq!(&h[..], &full.as_ref()[..16]);
    }

    #[test]
    fn tenant_hash_is_collision_resistant_at_128_bits() {
        // Sanity: tenant names that differ in the first byte differ in
        // the truncated hash with overwhelming probability.
        let a = tenant_hash("alpha");
        let b = tenant_hash("beta");
        assert_ne!(a, b);
    }
}
