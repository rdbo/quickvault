// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct LAN pairing (spec 0013 §1–4, §8–10; plan 0037).
//!
//! - `transport`: TCP frames with time limits and prompt cancellation, and
//!   the record channel under the pairing keys.
//! - `steps`: the pure pairing computations (hello, accept, transcript),
//!   shared by the drivers and the interoperability vectors.
//! - [`PairingWindow`] (the approving device A): a TCP listener for one
//!   unlocked vault; one session at a time, 16 failed attempts, second-hello
//!   detection (§8.3), the time limit and cancellation.
//! - [`join_new_device`] and [`join_link`] (the joining device B): candidate
//!   endpoints tried one at a time until one authenticates (§3.3).
//! - `exchange`: the exchange (§7) between two holders of the vault, and the
//!   new-device form (§4.7, §10). Each side stages the peer's state and
//!   verifies it completely before merging and committing.
//! - `session`: the pure session-handshake computations (§5).
//! - [`ReceiveWindow`] (the responder) and [`sync`] (the initiator): sync
//!   rounds between linked devices (§5, §7, §8).
//! - `window`: the listener and acceptor shared by both windows.
//!
//! **Trust.** Endpoints are hints (§3.1). Nothing is sent before the hello
//! MAC verifies, and nothing is decapsulated before the accept MAC verifies.
//! After the pairing keys exist, a local failure sends one error record; a
//! frame-level failure only closes. Every secret lives in a `qv_crypto`
//! protected container and is dropped (zeroized) on abort. Discovery (DNS-SD)
//! is deferred (owner decision 2026-11-03); windows run with discovery off.

mod approver;
mod endpoint;
mod exchange;
mod initiator;
mod joiner;
mod qr;
mod receiver;
pub(crate) mod session;
pub(crate) mod steps;
mod transport;
mod window;

use std::net::SocketAddr;
use std::time::Duration;

use qv_protocol::registry::ErrorCode;
use qv_store::StoreError;

pub use approver::{Approved, ApproverContext, ApproverVault, Confirm, PairingWindow, Sealer};
pub use endpoint::{EndpointPolicy, ListenScope, parse_endpoint};
pub use exchange::{Accepted, ExchangeVault, Role, RoundReport, grant_plaintext};
pub use initiator::sync;
pub use joiner::{
    JoinCode, JoinedLink, JoinedNewDevice, JoinerContext, JoinerUi, JoinerVault, join_link,
    join_new_device,
};
pub use qr::{LanQrInfo, LanQrKind, inspect_lan_qr};
pub use qv_crypto::lan::Sas;
pub use qv_protocol::lan::JoinMode;
pub use qv_protocol::lan::Outcome;
pub use receiver::{
    RECEIVE_WINDOW_DEFAULT, RECEIVE_WINDOW_MAX, ReceiveWindow, ResponderVault, WindowEnd,
};

/// Why a LAN pairing failed. Carries no data (0008 §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LanError {
    /// No candidate authenticated: a wrong code, an unreachable device, a
    /// removed link or a closed window. Looks like a closed port.
    NoPeer,
    /// An authenticated peer stopped responding within the time limit.
    Timeout,
    /// Cancelled here: a user cancel, a lock or a closed window.
    Cancelled,
    /// The peer cancelled: its user rejected the code or cancelled.
    PeerCancelled,
    /// A second valid pairing hello arrived: the code may have been observed
    /// (0013 §4.3).
    CodeObserved,
    /// 16 failed attempts closed the window (0013 §8.3).
    TooManyAttempts,
    /// The window's time limit passed (0013 §8.2).
    WindowExpired,
    /// Another vault or generation, or a failed link-mode proof.
    VaultMismatch,
    /// An unknown profile or a required feature this build lacks.
    Unsupported,
    /// A 0004 budget would be exceeded.
    Limit,
    /// Manifest, object or reference verification failed.
    Integrity,
    /// The vault is busy (locked for writing).
    Busy,
    /// The peer can no longer serve the state it named.
    StateChanged,
    /// The vault has no unique verified keyslot record (0013 §10 step 2).
    Keyslot,
    /// An unexpected message or field.
    Protocol,
    /// A local socket operation failed.
    Io,
    /// A local vault operation failed.
    Store(StoreError),
}

impl core::fmt::Display for LanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NoPeer => "no device answered with this code",
            Self::Timeout => "the other device stopped responding",
            Self::Cancelled => "cancelled",
            Self::PeerCancelled => "cancelled on the other device",
            Self::CodeObserved => "a second device used the code; it may have been observed",
            Self::TooManyAttempts => "unexpected connection attempts",
            Self::WindowExpired => "the pairing window expired",
            Self::VaultMismatch => "the devices hold different vaults or key generations",
            Self::Unsupported => "unsupported protocol version or feature",
            Self::Limit => "a size limit would be exceeded",
            Self::Integrity => "received data failed verification",
            Self::Busy => "the vault is busy",
            Self::StateChanged => "the other device's vault changed; try again",
            Self::Keyslot => "resolve the vault's password conflict on the approving device first",
            Self::Protocol => "protocol error",
            Self::Io => "network error",
            Self::Store(e) => return core::fmt::Display::fmt(e, f),
        })
    }
}

impl std::error::Error for LanError {}

impl LanError {
    /// The error a received error record reports (0013 §11).
    pub(crate) fn from_peer(code: ErrorCode) -> Self {
        match code {
            ErrorCode::VaultMismatch => Self::VaultMismatch,
            ErrorCode::Unsupported => Self::Unsupported,
            ErrorCode::Limit => Self::Limit,
            ErrorCode::Integrity => Self::Integrity,
            ErrorCode::Cancelled => Self::PeerCancelled,
            ErrorCode::Busy => Self::Busy,
            ErrorCode::StateChanged => Self::StateChanged,
            ErrorCode::Keyslot => Self::Keyslot,
            ErrorCode::Protocol => Self::Protocol,
        }
    }

    /// The code to send for a local failure after the pairing keys exist,
    /// or `None` to close without sending (the peer's own error, transport
    /// failures).
    pub(crate) fn wire_code(self) -> Option<ErrorCode> {
        Some(match self {
            Self::VaultMismatch => ErrorCode::VaultMismatch,
            Self::Unsupported => ErrorCode::Unsupported,
            Self::Limit => ErrorCode::Limit,
            Self::Integrity => ErrorCode::Integrity,
            Self::Cancelled | Self::CodeObserved | Self::TooManyAttempts | Self::WindowExpired => {
                ErrorCode::Cancelled
            }
            Self::Busy | Self::Store(_) => ErrorCode::Busy,
            Self::StateChanged => ErrorCode::StateChanged,
            Self::Keyslot => ErrorCode::Keyslot,
            Self::Protocol => ErrorCode::Protocol,
            Self::NoPeer | Self::Timeout | Self::PeerCancelled | Self::Io => return None,
        })
    }

    /// A staging or verification failure on received data: integrity,
    /// unsupported and budget failures keep their wire codes; an ID out of
    /// order or unrequested is a protocol error.
    pub fn from_staging(e: StoreError) -> Self {
        match e {
            StoreError::Integrity => Self::Integrity,
            StoreError::Unsupported => Self::Unsupported,
            StoreError::LimitExceeded => Self::Limit,
            StoreError::NotFound | StoreError::InvalidEdit => Self::Protocol,
            StoreError::Io => Self::Io,
            other => Self::Store(other),
        }
    }
}

/// Time limits (0013 §1.3, plan 0037 decision 4). [`Default`] is the spec's
/// values; frontends use it, and tests may only shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanTimeouts {
    /// Each cleartext handshake message and the reveal: 10 s.
    pub message: Duration,
    /// Idle time during an exchange: 60 s.
    pub idle: Duration,
    /// A read that waits on the other user's confirmation: 10 min (also
    /// capped by the window's remaining time).
    pub confirm: Duration,
    /// Opening a connection: 10 s.
    pub connect: Duration,
    /// Reading a probe hello from an extra connection (§8.3): 2 s.
    pub probe: Duration,
}

impl Default for LanTimeouts {
    fn default() -> Self {
        Self {
            message: Duration::from_secs(10),
            idle: Duration::from_secs(60),
            confirm: Duration::from_secs(600),
            connect: Duration::from_secs(10),
            probe: Duration::from_secs(2),
        }
    }
}

impl LanTimeouts {
    /// Every limit is positive and at most the spec's value.
    pub fn validate(&self) -> Result<(), LanError> {
        let max = Self::default();
        let ok = |v: Duration, m: Duration| !v.is_zero() && v <= m;
        if ok(self.message, max.message)
            && ok(self.idle, max.idle)
            && ok(self.confirm, max.confirm)
            && ok(self.connect, max.connect)
            && ok(self.probe, max.probe)
        {
            Ok(())
        } else {
            Err(LanError::Protocol)
        }
    }
}

/// The longest pairing window (0013 §8.2).
pub const PAIRING_WINDOW_MAX: Duration = Duration::from_secs(600);

/// Most candidate endpoints tried per action (0013 §3.3).
const MAX_CANDIDATES: usize = 16;

/// The endpoints to try, in order: deduplicated, at most 16, and filtered by
/// `policy` (0013 §1.4, §3.3).
pub(crate) fn candidates(endpoints: &[SocketAddr], policy: EndpointPolicy) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in endpoints {
        if policy.accepts(a) && !out.contains(a) && out.len() < MAX_CANDIDATES {
            out.push(*a);
        }
    }
    out
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;
