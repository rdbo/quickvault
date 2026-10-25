// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs in its own process: hardening changes process-wide state.

use qv_crypto::{Hardening, harden_process};

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn process_hardening_applies_and_is_idempotent() {
    use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};

    let first = harden_process();
    let second = harden_process();
    assert_eq!(first, second);
    assert_eq!(first.core_dumps, Hardening::Applied);
    assert_eq!(first.debugger_attach, Hardening::Applied);
    assert!(!first.is_reduced());

    let core = getrlimit(Resource::Core);
    assert_eq!(core.current, Some(0));
    assert_eq!(core.maximum, Some(0));
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn process_hardening_reports_unsupported() {
    let h = harden_process();
    assert_eq!(h.core_dumps, Hardening::Unsupported);
    assert_eq!(h.debugger_attach, Hardening::Unsupported);
    assert!(h.is_reduced());
}
