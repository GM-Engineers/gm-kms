//! PR-4.1 (P1-3): Production-safety opt-in helpers for the
//! `KMS_ALLOW_INSECURE` / `KMS_DEV_MODE` environment flags.
//!
//! Background: the KMS server historically only emitted a
//! `tracing::warn!` when started without TLS for its gRPC / REST
//! listeners (see `gm-kms/src/cmd/server.rs` lines 1035-1037 +
//! 1154-1159 pre-PR-4.1). API keys + signed payload bytes
//! transited in the clear, which is unacceptable for production
//! deployments. Per the master audit
//! `gm与gm-kms源码级改进建议.md §6 / §7 P1-3`, the KEK
//! `postgres.rs:92-95` fail-fast pattern should be mirrored at the
//! API-listener layer:
//!
//! > "KEK 缺失时会 fail-fast（postgres.rs:92-95），但 KMS 自身 API
//! > 无 TLS 仅警告。API key 明文过网在政企场景不可接受。建议：
//! > 仿照 KEK 逻辑：`KMS_ALLOW_INSECURE=1` 显式放行明文，否则生产
//! > 启动失败；gRPC 与 REST 统一处理。"
//!
//! Two opt-in flags are recognized:
//!
//! - `KMS_DEV_MODE=1`: the canonical pre-existing test/embedded
//!   integration flag (used by the test harness, the embedded
//!   in-memory DB / cache fallbacks, etc.). When set, plaintext
//!   listeners are allowed and the production fail-fast check
//!   short-circuits.
//! - `KMS_ALLOW_INSECURE=1`: the parallel flag added in PR-4.1
//!   specifically for the API-listener TLS check. Equivalent
//!   in effect to `KMS_DEV_MODE` for the fail-fast check but
//!   semantically distinct: `KMS_DEV_MODE` indicates "I am
//!   running tests / a dev fixture"; `KMS_ALLOW_INSECURE`
//!   indicates "I am running production with explicit plaintext
//!   opt-in (rare, but supported for tightly-controlled network
//!   segments behind a TLS-terminating reverse proxy)".

/// Returns `true` iff `KMS_ALLOW_INSECURE=1` is set in the
/// process environment.
pub fn is_allow_insecure() -> bool {
    std::env::var("KMS_ALLOW_INSECURE").as_deref() == Ok("1")
}

/// Returns `true` iff `KMS_DEV_MODE=1` is set in the process
/// environment.
pub fn is_dev_mode() -> bool {
    std::env::var("KMS_DEV_MODE").as_deref() == Ok("1")
}

/// Returns `true` iff either opt-in flag is set.
///
/// Used by the gRPC / REST startup fail-fast check to short-circuit
/// the "API requires TLS in production" bail-out for test
/// fixtures and operators who have explicitly opted in.
pub fn is_insecure_opted_in() -> bool {
    is_dev_mode() || is_allow_insecure()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // PR-4.1's helper functions read three env vars
    // (`KMS_ALLOW_INSECURE`, `KMS_DEV_MODE`). Tests must run with
    // those env vars under a Mutex because they share process
    // state. The Mutex serializes the parallel test runner so we
    // don't trample each other's env state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Snapshot previous values.
        let prev: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();
        // SAFETY: the `ENV_LOCK` mutex serializes env mutations across
        // the test runner; we always restore the previous values
        // before returning, so any test that doesn't read the vars
        // we're mutating sees no change.
        unsafe {
            for (k, v) in vars {
                std::env::set_var(k, v);
            }
            let result = f();
            // Restore.
            for (k, prev_v) in prev {
                match prev_v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
            result
        }
    }

    #[test]
    fn pr41_is_allow_insecure_default_false() {
        with_env(&[("KMS_ALLOW_INSECURE", ""), ("KMS_DEV_MODE", "")], || {
            assert!(!is_allow_insecure());
            assert!(!is_dev_mode());
            assert!(!is_insecure_opted_in());
        });
    }

    #[test]
    fn pr41_is_allow_insecure_set_to_one() {
        with_env(&[("KMS_ALLOW_INSECURE", "1"), ("KMS_DEV_MODE", "")], || {
            assert!(is_allow_insecure());
            assert!(!is_dev_mode());
            assert!(is_insecure_opted_in());
        });
    }

    #[test]
    fn pr41_is_allow_insecure_other_value_is_false() {
        // PR-4.1 treats only the literal value "1" as the opt-in;
        // anything else (including "true", "yes", "on") is a no-op.
        // This prevents accidental opt-in via misconfigured env
        // (e.g. someone setting `KMS_ALLOW_INSECURE=true` thinking
        // it's a boolean).
        with_env(
            &[("KMS_ALLOW_INSECURE", "true"), ("KMS_DEV_MODE", "")],
            || {
                assert!(!is_allow_insecure());
            },
        );
    }

    #[test]
    fn pr41_is_dev_mode_set_to_one() {
        with_env(&[("KMS_ALLOW_INSECURE", ""), ("KMS_DEV_MODE", "1")], || {
            assert!(!is_allow_insecure());
            assert!(is_dev_mode());
            assert!(is_insecure_opted_in());
        });
    }

    #[test]
    fn pr41_is_insecure_opted_in_either_flag_suffices() {
        with_env(
            &[("KMS_ALLOW_INSECURE", "1"), ("KMS_DEV_MODE", "1")],
            || {
                assert!(is_insecure_opted_in());
            },
        );
    }
}
