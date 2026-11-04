// SPDX-License-Identifier: AGPL-3.0-or-later

//! The listening side shared by pairing and receive windows (0013 §8; plan
//! 0037 decision 6, plan 0038).
//!
//! The window's protocol runs on the caller's thread. One scoped acceptor
//! thread polls a non-blocking listener and hands the worker one connection
//! at a time:
//! - while the worker checks a hello, other connections close at once,
//!   unanswered;
//! - once a hello was accepted (`Used`), each extra connection goes to the
//!   window's `used` handler. Pairing reads one probe frame (§8.3); a
//!   receive window closes it unanswered.
//!
//! The acceptor stops when the worker finishes or the window closes:
//! 16 failed attempts, the time limit, a cancel or lock, or an observed code.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::LanError;

/// Failed attempts that close a window (0013 §8.3).
pub(crate) const MAX_FAILURES: u32 = 16;
/// Acceptor poll interval.
pub(crate) const POLL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Waiting for a connection.
    Idle,
    /// Checking a hello.
    Checking,
    /// A valid hello was accepted; a session runs.
    Used,
}

/// State shared by the acceptor and the worker.
pub(crate) struct Shared {
    /// The phase and, for pairing, the accepted hello's bytes.
    pub(crate) phase: Mutex<(Phase, Zeroizing<Vec<u8>>)>,
    pub(crate) failures: AtomicU32,
    /// A second valid pairing hello arrived (0013 §4.3).
    pub(crate) observed: AtomicBool,
    pub(crate) finished: AtomicBool,
}

impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            phase: Mutex::new((Phase::Idle, Zeroizing::new(Vec::new()))),
            failures: AtomicU32::new(0),
            observed: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        }
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner).0
    }
    pub(crate) fn set(&self, p: Phase, hello: Option<&[u8]>) {
        let mut g = self.phase.lock().unwrap_or_else(PoisonError::into_inner);
        g.0 = p;
        if let Some(h) = hello {
            g.1 = Zeroizing::new(h.to_vec());
        }
    }
    pub(crate) fn fail(&self) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }
}

/// Why the window must close now, if it must.
pub(crate) fn closing(
    shared: &Shared,
    expires: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Option<LanError> {
    if shared.observed.load(Ordering::SeqCst) {
        Some(LanError::CodeObserved)
    } else if cancelled() {
        Some(LanError::Cancelled)
    } else if shared.failures.load(Ordering::SeqCst) >= MAX_FAILURES {
        Some(LanError::TooManyAttempts)
    } else if Instant::now() >= expires {
        Some(LanError::WindowExpired)
    } else {
        None
    }
}

/// The acceptor loop: hands idle-phase connections to the worker, closes
/// the ones that arrive while a hello is checked, and passes the ones that
/// arrive while the window is used to `used`.
pub(crate) fn acceptor(
    listener: &TcpListener,
    shared: &Shared,
    tx: &SyncSender<TcpStream>,
    expires: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
    used: &dyn Fn(TcpStream),
) {
    while !shared.finished.load(Ordering::SeqCst) && closing(shared, expires, cancelled).is_none() {
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(_) => {
                std::thread::sleep(POLL);
                continue;
            }
        };
        match shared.phase() {
            Phase::Idle => {
                shared.set(Phase::Checking, None);
                if tx.try_send(stream).is_err() {
                    shared.set(Phase::Idle, None);
                }
            }
            Phase::Checking => drop(stream),
            Phase::Used => used(stream),
        }
    }
}
