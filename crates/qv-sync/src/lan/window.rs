// SPDX-License-Identifier: AGPL-3.0-or-later

//! The listening side of a sync window (0013 §8; plans 0037 decision 6,
//! 0038, 0042).
//!
//! The acceptor owns its listener. While a hello is checked, extra sockets
//! close unanswered. Admission returns only after the acceptor has exited and
//! dropped that listener; no monitor survives into the authenticated session.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

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
}

/// State shared by the acceptor and the worker.
pub(crate) struct Shared {
    phase: Mutex<Phase>,
    pub(crate) failures: AtomicU32,
    pub(crate) finished: AtomicBool,
}

impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            phase: Mutex::new(Phase::Idle),
            failures: AtomicU32::new(0),
            finished: AtomicBool::new(false),
        }
    }
    pub(crate) fn phase(&self) -> Phase {
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }
    pub(crate) fn set(&self, phase: Phase) {
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner) = phase;
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
    if cancelled() {
        Some(LanError::Cancelled)
    } else if shared.failures.load(Ordering::SeqCst) >= MAX_FAILURES {
        Some(LanError::TooManyAttempts)
    } else if Instant::now() >= expires {
        Some(LanError::WindowExpired)
    } else {
        None
    }
}

/// Admission-only acceptor. Ownership guarantees listener closure when this
/// function exits, including cancellation, expiry and accepted-hello handoff.
pub(crate) fn acceptor(
    listener: TcpListener,
    shared: &Shared,
    tx: &SyncSender<TcpStream>,
    expires: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
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
                shared.set(Phase::Checking);
                if tx.try_send(stream).is_err() {
                    shared.set(Phase::Idle);
                }
            }
            Phase::Checking => drop(stream),
        }
    }
}
