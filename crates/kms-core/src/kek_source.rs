//! Key Encryption Key (KEK) source abstraction
//!
//! PR-4.7 / P1-7 (阶段 1/3): supports loading the KEK from
//! either an environment variable or a 0600-mode file. Later
//! phases (PR-4.8 HSM/TPM provider, PR-4.9 KEK rotation) will
//! extend this enum without breaking the public API surface.
//!
//! ## Security model
//!
//! - **Env-var mode (`KMS_KEK`)**: KEK lives in the process
//!   environment. Visible in `/proc/<pid>/environ` and to any
//!   process with read access to that procfs entry. Suitable
//!   for development and CI; discouraged in production.
//! - **File mode (`KMS_KEK_FILE`)**: KEK lives in a 0600-mode
//!   file. Operators can mount it from a secret manager
//!   (Vault Agent, k8s `Secret` mounted as `subPath`, AWS
//!   Secrets Manager CSI driver, etc.). PR-4.7 enforces
//!   `0o600` on Unix; non-Unix platforms skip the check.
//! - **Missing**: neither env nor file is configured. Caller
//!   decides whether to fall back to a random DEV-mode KEK
//!   (`KMS_DEV_MODE=1`) or fail hard.

use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[cfg(test)]
use std::sync::Mutex;

/// KEK source selector (resolved from process environment).
///
/// `from_env` is the canonical factory; the variants are exposed
/// publicly so that tests can construct sources explicitly
/// without touching process env state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KekSource {
    /// `KMS_KEK` env var (hex-encoded 32 bytes).
    Env,
    /// `KMS_KEK_FILE` env var (path to a 0600 file containing
    /// 64 hex characters).
    File(PathBuf),
    /// Neither `KMS_KEK` nor `KMS_KEK_FILE` is set. The
    /// caller decides whether to fall back to a DEV-mode
    /// random KEK or fail hard.
    Missing,
}

/// Errors that can occur when resolving a `KekSource` to bytes.
#[derive(Debug, thiserror::Error)]
pub enum KekSourceError {
    #[error(
        "KMS_KEK_FILE path {path:?} has insecure mode {mode:o} (expected exactly 0600); \
         refusing to read KEK from a world/group-readable file. \
         Fix with `chmod 600 {path:?}` or mount via a secrets manager."
    )]
    InsecureFileMode { path: PathBuf, mode: u32 },

    #[error("KMS_KEK_FILE path {0:?} could not be read (not found or no permission)")]
    FileNotFound(PathBuf),

    #[error("KMS_KEK must decode to 32 bytes (64 hex characters); got {0} bytes")]
    InvalidLength(usize),

    #[error("KMS_KEK hex decode failed: {0}")]
    InvalidHex(String),

    #[error("KMS_KEK hex value contained non-ASCII whitespace; check for stray newlines")]
    ContainedWhitespace,

    #[error("no KEK configured (set KMS_KEK or KMS_KEK_FILE)")]
    NotConfigured,
}

/// Serialization point for tests that mutate the process env.
///
/// `std::env::set_var` / `remove_var` are unsafe in multi-threaded
/// programs because the environment is shared process state. All
/// tests in `pr47_kek_source_tests` acquire this mutex before
/// reading or writing env state (see PR-4.1 / `production_safety`
/// tests for the same pattern).
#[cfg(test)]
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

impl KekSource {
    /// Build from `KMS_KEK_FILE` (preferred) or `KMS_KEK`
    /// (fallback). Returns `Missing` if neither is set.
    ///
    /// File beats env when both are set — the file is more
    /// secure (mode bits are enforced) and operators usually
    /// want the more explicit channel to win.
    pub fn from_env() -> Self {
        if let Ok(p) = std::env::var("KMS_KEK_FILE")
            && !p.trim().is_empty()
        {
            return KekSource::File(PathBuf::from(p));
        }
        if let Ok(v) = std::env::var("KMS_KEK")
            && !v.trim().is_empty()
        {
            return KekSource::Env;
        }
        KekSource::Missing
    }

    /// Resolve to a 32-byte KEK wrapped in `Zeroizing` (the
    /// `Drop` impl scrubs memory).
    pub fn load(&self) -> Result<Zeroizing<[u8; 32]>, KekSourceError> {
        match self {
            KekSource::Env => load_hex_from_env("KMS_KEK"),
            KekSource::File(p) => load_hex_from_file(p),
            KekSource::Missing => Err(KekSourceError::NotConfigured),
        }
    }
}

fn load_hex_from_env(var_name: &str) -> Result<Zeroizing<[u8; 32]>, KekSourceError> {
    let raw = std::env::var(var_name).map_err(|_| KekSourceError::NotConfigured)?;
    decode_hex_kek(&raw)
}

fn load_hex_from_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, KekSourceError> {
    assert_file_mode_0600(path)?;
    let raw = std::fs::read_to_string(path)
        .map_err(|_| KekSourceError::FileNotFound(path.to_path_buf()))?;
    decode_hex_kek(&raw)
}

fn decode_hex_kek(raw: &str) -> Result<Zeroizing<[u8; 32]>, KekSourceError> {
    // Reject stray whitespace that often comes from copy-paste
    // of multi-line secrets (newlines, tabs, NULs). This catches
    // the very common ops error of pasting the secret with a
    // trailing newline that ends up as an extra byte.
    if raw.chars().any(|c| c.is_whitespace()) {
        return Err(KekSourceError::ContainedWhitespace);
    }
    let bytes = hex::decode(raw).map_err(|e| KekSourceError::InvalidHex(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| KekSourceError::InvalidLength(v.len()))?;
    Ok(Zeroizing::new(arr))
}

#[cfg(unix)]
fn assert_file_mode_0600(path: &Path) -> Result<(), KekSourceError> {
    use std::os::unix::fs::PermissionsExt;
    let meta =
        std::fs::metadata(path).map_err(|_| KekSourceError::FileNotFound(path.to_path_buf()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(KekSourceError::InsecureFileMode {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_file_mode_0600(_path: &Path) -> Result<(), KekSourceError> {
    // Windows: no Unix mode bits. The expected production
    // platform is Linux (per ARCHITECTURE.md); Windows
    // deployment is out of scope for PR-4.7.
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod pr47_kek_source_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    /// 32 bytes = 64 hex characters; deterministic so tests
    /// can compare values. The bytes represented are
    /// `[0x00, 0x01, 0x02, ..., 0x1f]` so `sample_kek_bytes()`
    /// and `sample_kek_hex()` are consistent with each other.
    fn sample_kek_hex() -> String {
        let bytes = sample_kek_bytes();
        hex::encode(bytes)
    }

    fn sample_kek_bytes() -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = i as u8;
        }
        out
    }

    /// RAII guard that clears KMS_KEK and KMS_KEK_FILE on drop.
    struct EnvGuard {
        kek: Option<String>,
        kek_file: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let kek = std::env::var("KMS_KEK").ok();
            let kek_file = std::env::var("KMS_KEK_FILE").ok();
            unsafe {
                std::env::remove_var("KMS_KEK");
                std::env::remove_var("KMS_KEK_FILE");
            }
            Self {
                kek,
                kek_file,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.kek {
                    Some(v) => std::env::set_var("KMS_KEK", v),
                    None => std::env::remove_var("KMS_KEK"),
                }
                match &self.kek_file {
                    Some(v) => std::env::set_var("KMS_KEK_FILE", v),
                    None => std::env::remove_var("KMS_KEK_FILE"),
                }
            }
        }
    }

    /// Helper: set KMS_KEK in tests (avoids `unsafe { ... }` boilerplate).
    fn set_kek(v: &str) {
        unsafe {
            std::env::set_var("KMS_KEK", v);
        }
    }
    fn set_kek_file(v: &str) {
        unsafe {
            std::env::set_var("KMS_KEK_FILE", v);
        }
    }

    #[test]
    fn pr47_from_env_with_kek_env_var() {
        let _g = EnvGuard::new();
        set_kek(&sample_kek_hex());
        assert_eq!(KekSource::from_env(), KekSource::Env);
    }

    #[test]
    fn pr47_from_env_with_kek_file() {
        let _g = EnvGuard::new();
        set_kek_file("/tmp/kek");
        assert_eq!(
            KekSource::from_env(),
            KekSource::File(PathBuf::from("/tmp/kek"))
        );
    }

    #[test]
    fn pr47_from_env_with_both_prefers_file() {
        let _g = EnvGuard::new();
        set_kek(&sample_kek_hex());
        set_kek_file("/tmp/kek");
        assert_eq!(
            KekSource::from_env(),
            KekSource::File(PathBuf::from("/tmp/kek"))
        );
    }

    #[test]
    fn pr47_from_env_with_empty_file_falls_through_to_kek() {
        let _g = EnvGuard::new();
        set_kek_file("   ");
        set_kek(&sample_kek_hex());
        assert_eq!(KekSource::from_env(), KekSource::Env);
    }

    #[test]
    fn pr47_from_env_missing_returns_missing() {
        let _g = EnvGuard::new();
        assert_eq!(KekSource::from_env(), KekSource::Missing);
    }

    #[test]
    fn pr47_env_load_valid_64_hex() {
        let _g = EnvGuard::new();
        set_kek(&sample_kek_hex());
        let source = KekSource::from_env();
        let kek = source.load().expect("valid 64-hex should load");
        assert_eq!(*kek, sample_kek_bytes());
    }

    #[test]
    fn pr47_env_load_invalid_hex() {
        let _g = EnvGuard::new();
        // 64 chars but not all valid hex (contains 'z')
        set_kek("z123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let source = KekSource::from_env();
        match source.load() {
            Err(KekSourceError::InvalidHex(_)) => {}
            other => panic!("expected InvalidHex, got {other:?}"),
        }
    }

    #[test]
    fn pr47_env_load_wrong_length() {
        let _g = EnvGuard::new();
        // 32 chars = 16 bytes (too short)
        let short_hex: String = sample_kek_hex().chars().take(32).collect();
        set_kek(&short_hex);
        let source = KekSource::from_env();
        match source.load() {
            Err(KekSourceError::InvalidLength(16)) => {}
            other => panic!("expected InvalidLength(16), got {other:?}"),
        }
    }

    #[test]
    fn pr47_env_load_contained_whitespace() {
        let _g = EnvGuard::new();
        // 64 hex chars + trailing newline (very common copy-paste bug)
        let mut s = sample_kek_hex();
        s.push('\n');
        set_kek(&s);
        let source = KekSource::from_env();
        match source.load() {
            Err(KekSourceError::ContainedWhitespace) => {}
            Err(KekSourceError::InvalidLength(_)) => {} // also acceptable: trailing \n makes it 33 bytes
            other => panic!("expected whitespace or length error, got {other:?}"),
        }
    }

    #[test]
    fn pr47_file_load_valid_0600() {
        let _g = EnvGuard::new();
        // Write a temp file with mode 0600.
        let dir = std::env::temp_dir().join(format!("kms-pr47-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kek");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        #[cfg(unix)]
        let mut f = opts.open(&path).expect("create 0600 file");
        #[cfg(not(unix))]
        let mut f = opts.open(&path).expect("create file");
        f.write_all(sample_kek_hex().as_bytes()).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let source = KekSource::File(path.clone());
        let kek = source.load().expect("0600 file load should succeed");
        assert_eq!(*kek, sample_kek_bytes());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn pr47_file_load_rejects_0644() {
        let _g = EnvGuard::new();
        let dir = std::env::temp_dir().join(format!("kms-pr47-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kek");
        std::fs::write(&path, sample_kek_hex()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let source = KekSource::File(path.clone());
        match source.load() {
            Err(KekSourceError::InsecureFileMode { mode, .. }) => {
                assert_eq!(mode, 0o644);
            }
            other => panic!("expected InsecureFileMode(0o644), got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn pr47_file_load_rejects_0666() {
        let _g = EnvGuard::new();
        let dir = std::env::temp_dir().join(format!("kms-pr47-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kek");
        std::fs::write(&path, sample_kek_hex()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let source = KekSource::File(path.clone());
        match source.load() {
            Err(KekSourceError::InsecureFileMode { mode, .. }) => {
                assert_eq!(mode, 0o666);
            }
            other => panic!("expected InsecureFileMode(0o666), got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pr47_file_load_missing_path() {
        let _g = EnvGuard::new();
        let bogus = PathBuf::from("/this/path/definitely/does/not/exist/kek");
        let source = KekSource::File(bogus.clone());
        match source.load() {
            Err(KekSourceError::FileNotFound(p)) => assert_eq!(p, bogus),
            other => panic!("expected FileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn pr47_file_load_empty_file() {
        let _g = EnvGuard::new();
        let dir = std::env::temp_dir().join(format!("kms-pr47-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kek");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let source = KekSource::File(path.clone());
        match source.load() {
            Err(KekSourceError::InvalidLength(0)) => {}
            other => panic!("expected InvalidLength(0), got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pr47_load_missing_returns_not_configured() {
        let _g = EnvGuard::new();
        let source = KekSource::Missing;
        match source.load() {
            Err(KekSourceError::NotConfigured) => {}
            other => panic!("expected NotConfigured, got {other:?}"),
        }
    }

    #[test]
    fn pr47_load_returns_zeroizing_wrapped_array() {
        let _g = EnvGuard::new();
        set_kek(&sample_kek_hex());
        let kek = KekSource::from_env().load().expect("load");
        // Zeroizing<T> derefs to T; verify the wrapped array is 32 bytes.
        let view: &[u8] = &*kek;
        assert_eq!(view.len(), 32);
    }

    #[test]
    fn pr47_error_messages_mention_offending_path() {
        let _g = EnvGuard::new();
        let path = PathBuf::from("/example/kek");
        let err = KekSourceError::InsecureFileMode {
            path: path.clone(),
            mode: 0o644,
        };
        let msg = err.to_string();
        assert!(msg.contains("/example/kek"));
        assert!(msg.contains("644"));
    }
}
