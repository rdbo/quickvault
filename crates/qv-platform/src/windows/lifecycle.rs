// SPDX-License-Identifier: AGPL-3.0-or-later

//! WTS session and power notifications as lock events (0008 §1.4).
use crate::{Lifecycle, LockCallback, LockEvent, PlatformError, Watch};
use qv_win::session::{SessionEvent, SessionWatcher, session_locked};
use std::sync::{Arc, OnceLock};

/// Lock/sleep monitoring through a hidden notification window.
#[derive(Default)]
pub struct WtsLifecycle;

struct Running(#[allow(dead_code)] SessionWatcher); // held until dropped
impl Watch for Running {}

/// The lock event for a session notification.
pub(crate) fn event(e: SessionEvent) -> LockEvent {
    match e {
        SessionEvent::Locked | SessionEvent::Disconnected => LockEvent::ScreenLocked,
        SessionEvent::Suspend => LockEvent::PreparingForSleep,
        SessionEvent::Logoff | SessionEvent::EndSession | SessionEvent::Lost => {
            LockEvent::ProtectionLost
        }
    }
}

impl WtsLifecycle {
    /// Whether a notification window can be registered in this session
    /// (probed once per process).
    pub fn is_available(&self) -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| SessionWatcher::start(Arc::new(|_| {})).is_ok())
    }
}

impl Lifecycle for WtsLifecycle {
    fn watch(&self, callback: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
        let cb = callback.clone();
        let watcher = SessionWatcher::start(Arc::new(move |e| cb(event(e))))
            .map_err(|_| PlatformError::Unavailable)?;
        // Installation precedes the initial state check, so a lock between
        // the two is not missed.
        if let Ok(Some(true)) = session_locked() {
            callback(LockEvent::ScreenLocked);
        }
        Ok(Box::new(Running(watcher)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_events_map_to_lock_events() {
        assert_eq!(event(SessionEvent::Locked), LockEvent::ScreenLocked);
        assert_eq!(event(SessionEvent::Disconnected), LockEvent::ScreenLocked);
        assert_eq!(event(SessionEvent::Suspend), LockEvent::PreparingForSleep);
        for e in [
            SessionEvent::Logoff,
            SessionEvent::EndSession,
            SessionEvent::Lost,
        ] {
            assert_eq!(event(e), LockEvent::ProtectionLost);
        }
    }
}
