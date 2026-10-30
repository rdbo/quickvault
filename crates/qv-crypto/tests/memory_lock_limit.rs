// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs in its own process: it lowers `RLIMIT_MEMLOCK` to 0 so that a real
//! `mlock` fails, and checks that the failure is reported as reduced
//! protection rather than hidden.

// 0012 §1: Swap/hibernation leaks
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn memory_lock_failure_under_real_limit_is_reported() {
    use qv_crypto::{SecretBytes, memory_protection};
    use rustix::process::{Resource, Rlimit, setrlimit};

    let small = SecretBytes::zeroed(32);
    assert!(small.is_locked(), "baseline lock should succeed");
    assert!(!memory_protection().is_reduced());

    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();

    // Larger than a page, so it needs at least one page not yet locked.
    let big = SecretBytes::zeroed(4 * 65536);
    if big.is_locked() {
        eprintln!(
            "SKIPPED: mlock succeeded with RLIMIT_MEMLOCK=0 (process has CAP_IPC_LOCK); \
             the real-limit failure path was not exercised"
        );
        return;
    }
    assert!(memory_protection().is_reduced());
    assert!(memory_protection().lock_failures >= 1);
    // The earlier buffer keeps its lock and its data stays usable.
    assert!(small.is_locked());
    assert_eq!(big.expose_secret().len(), 4 * 65536);
}
