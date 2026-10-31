// SPDX-License-Identifier: AGPL-3.0-or-later

// Fixture setup intentionally fails loudly; no real desktop is locked.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::testutil::{Env, PASSWORD, err, kdf, pw};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Fake {
    callback: Mutex<Option<LockCallback>>,
    active: Arc<AtomicUsize>,
    initially_locked: AtomicBool,
    unavailable: AtomicBool,
}
impl Default for Fake {
    fn default() -> Self {
        Self {
            callback: Mutex::new(None),
            active: Arc::new(AtomicUsize::new(0)),
            initially_locked: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
        }
    }
}
struct Guard(Arc<AtomicUsize>);
impl Watch for Guard {}
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Lifecycle for Fake {
    fn watch(&self, callback: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(PlatformError::Unavailable);
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        *self.callback.lock().unwrap() = Some(callback.clone());
        if self.initially_locked.load(Ordering::SeqCst) {
            callback(LockEvent::ScreenLocked);
        }
        Ok(Box::new(Guard(self.active.clone())))
    }
}
impl PlatformServices for Fake {
    fn status(&self) -> ProtectionStatus {
        ProtectionStatus {
            storage: Evidence::Unknown,
            swap: Evidence::Unknown,
            hibernation: Evidence::Unknown,
            lifecycle: !self.unavailable.load(Ordering::SeqCst),
            clipboard: false,
            quick_unlock: false,
        }
    }
    fn lifecycle(&self) -> &dyn Lifecycle {
        self
    }
    fn clipboard(&self) -> &dyn Clipboard {
        &Unavailable
    }
    fn secure_input(&self) -> &dyn SecureInput {
        &Unavailable
    }
    fn keystore(&self) -> &dyn Keystore {
        &Unavailable
    }
}
impl Fake {
    fn event(&self, event: LockEvent) {
        let callback = self.callback.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(event);
        }
    }
}
// 0012 §1: Swap/hibernation leaks
#[test]
fn platform_requires_acknowledgement_before_persistent_use() {
    let env = Env::new();
    let services = Arc::new(Fake::default());
    let core = env
        .core_with(Some(env.snapshot_policy()))
        .with_platform(services, false);
    assert!(core.platform_status().unwrap().is_reduced());
    assert_eq!(
        err(core.resume_rotation(&env.path, Some(&pw(PASSWORD)), None, None)),
        CoreError::NotAllowed
    );
    let target = env.dir.path().join("not-created.qvault");
    assert_eq!(
        err(core.create(&target, &pw(PASSWORD), "test")),
        CoreError::NotAllowed
    );
    assert!(!target.exists());
    assert_eq!(
        err(core.unlock(&env.path, &pw(PASSWORD), None)),
        CoreError::NotAllowed
    );
}
// 0012 §1: Ambiguous trust boundary
#[test]
fn platform_screen_lock_sleep_and_disconnect_invalidate_sessions_and_drop_watchers() {
    for event in [
        LockEvent::ScreenLocked,
        LockEvent::PreparingForSleep,
        LockEvent::BackgroundExpired,
        LockEvent::ProtectionLost,
    ] {
        let env = Env::new();
        let services = Arc::new(Fake::default());
        let core = env.core().with_platform(services.clone(), true);
        let s = {
            let _k = kdf();
            core.unlock(&env.path, &pw(PASSWORD), None).unwrap()
        };
        let handle = s.root().unwrap();
        assert_eq!(services.active.load(Ordering::SeqCst), 1);
        services.event(event);
        assert!(s.is_locked());
        assert_eq!(err(s.list(handle)), CoreError::SessionLocked);
        drop(s);
        assert_eq!(services.active.load(Ordering::SeqCst), 0);
        // A late OS event cannot retain/repopulate a dead session.
        services.event(event);
    }
}
// 0012 §1: Ambiguous trust boundary
#[test]
fn platform_initial_lock_and_session_drop_are_fail_closed() {
    let env = Env::new();
    let services = Arc::new(Fake::default());
    services.initially_locked.store(true, Ordering::SeqCst);
    let core = env.core().with_platform(services.clone(), true);
    {
        let _k = kdf();
        assert_eq!(
            err(core.unlock(&env.path, &pw(PASSWORD), None)),
            CoreError::Cancelled
        );
    }
    assert_eq!(services.active.load(Ordering::SeqCst), 0);
    services.initially_locked.store(false, Ordering::SeqCst);
    let s = {
        let _k = kdf();
        core.unlock(&env.path, &pw(PASSWORD), None).unwrap()
    };
    drop(s);
    assert_eq!(services.active.load(Ordering::SeqCst), 0);
    services.event(LockEvent::ScreenLocked);
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn platform_lock_cancels_a_session_bound_clipboard_without_holding_session_mutex() {
    struct WaitingClipboard(std::sync::mpsc::Sender<()>);
    impl Clipboard for WaitingClipboard {
        fn hold(
            &self,
            value: crate::SecretBytes,
            _: std::time::Duration,
            cancel: Cancellation,
            _: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
        ) -> Result<(), PlatformError> {
            self.0.send(()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !cancel() && std::time::Instant::now() < deadline {
                std::thread::yield_now();
            }
            drop(value);
            assert!(cancel());
            Err(PlatformError::Cancelled)
        }
    }
    let env = Env::new();
    let services = Arc::new(Fake::default());
    let core = env.core().with_platform(services.clone(), true);
    let s = Arc::new({
        let _k = kdf();
        core.unlock(&env.path, &pw(PASSWORD), None).unwrap()
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = {
        let s = s.clone();
        std::thread::spawn(move || {
            s.hold_clipboard(
                &WaitingClipboard(tx),
                crate::SecretBytes::zeroed(16),
                std::time::Duration::from_secs(20),
                None,
                &mut |_| Ok(()),
            )
        })
    };
    rx.recv_timeout(std::time::Duration::from_secs(3)).unwrap();
    services.event(LockEvent::ScreenLocked);
    assert_eq!(worker.join().unwrap(), Err(CoreError::Cancelled));
    assert!(s.is_locked());
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn platform_reduced_acknowledgement_does_not_bypass_required_lock_monitoring() {
    let env = Env::new();
    let services = Arc::new(Fake::default());
    services.unavailable.store(true, Ordering::SeqCst);
    let core = env.core().with_platform(services.clone(), true);
    let _k = kdf();
    assert_eq!(
        err(core.unlock(&env.path, &pw(PASSWORD), None)),
        CoreError::NotAllowed
    );
    assert!(!core.platform_status().unwrap().lifecycle);
    assert_eq!(services.active.load(Ordering::SeqCst), 0);
}
