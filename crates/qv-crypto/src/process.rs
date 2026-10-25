// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process hardening before secrets are read (spec 0008 §1.1).
//!
//! On Linux and Android this sets the core-dump size limit to zero and marks
//! the process non-dumpable (`PR_SET_DUMPABLE = 0`), which also stops
//! same-user debuggers from attaching with `ptrace`. Other platforms report
//! [`Hardening::Unsupported`].
//!
//! This is best effort. A privileged debugger, `fs.suid_dumpable = 2`, or a
//! piped `core_pattern` handler can still capture process memory.
//! [`Hardening::Applied`] means the calls succeeded, not that every system
//! configuration is covered.

/// Outcome of one hardening measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hardening {
    /// The OS accepted the setting.
    Applied,
    /// Not available on this platform.
    Unsupported,
    /// The OS rejected the setting.
    Failed,
}

/// What [`harden_process`] achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessHardening {
    /// Core dumps disabled (`RLIMIT_CORE = 0`).
    pub core_dumps: Hardening,
    /// Debugger attach blocked (process non-dumpable).
    pub debugger_attach: Hardening,
}

impl ProcessHardening {
    /// Whether any measure is not [`Hardening::Applied`]. Callers must show
    /// this to the user as reduced protection.
    pub fn is_reduced(&self) -> bool {
        self.core_dumps != Hardening::Applied || self.debugger_attach != Hardening::Applied
    }
}

/// Disables core dumps and debugger attach where supported.
///
/// Call before reading any secret. Idempotent; never panics.
pub fn harden_process() -> ProcessHardening {
    imp::harden()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::{Hardening, ProcessHardening};
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

    fn outcome<E>(r: Result<(), E>) -> Hardening {
        match r {
            Ok(()) => Hardening::Applied,
            Err(_) => Hardening::Failed,
        }
    }

    pub(super) fn harden() -> ProcessHardening {
        let no_core = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        ProcessHardening {
            core_dumps: outcome(setrlimit(Resource::Core, no_core)),
            debugger_attach: outcome(set_dumpable_behavior(DumpableBehavior::NotDumpable)),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod imp {
    use super::{Hardening, ProcessHardening};

    pub(super) fn harden() -> ProcessHardening {
        ProcessHardening {
            core_dumps: Hardening::Unsupported,
            debugger_attach: Hardening::Unsupported,
        }
    }
}
