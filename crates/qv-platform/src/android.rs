// SPDX-License-Identifier: AGPL-3.0-or-later

//! Android lifecycle metadata supplied by minimal native packaging glue.
//! No secret is passed over the native lifecycle channel.
use crate::{
    Cancellation, Clipboard, Evidence, Keystore, Lifecycle, LockCallback, LockEvent, PlatformError,
    PlatformServices, ProtectionStatus, SecureInput, Unavailable, Watch,
};
use qv_crypto::SecretBytes;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// Identifies the clip this app placed (for example its OS timestamp).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClipToken(pub i64);
/// Minimal native clipboard operations; the hold policy stays in Rust.
pub trait AndroidClipboardBackend: Send + Sync {
    /// Place UTF-8 text marked sensitive where supported; return its token.
    fn set(&self, text: &str) -> Result<ClipToken, PlatformError>;
    /// Whether the current clip is still ours; `None` when the OS hides it
    /// (for example while another app has focus).
    fn owned(&self, token: ClipToken) -> Option<bool>;
    /// Clear the primary clip.
    fn clear(&self) -> Result<(), PlatformError>;
}

/// Current OS observations, without any vault or UI input data.
#[derive(Clone, Copy, Debug, Default)]
pub struct AndroidState {
    /// Native watcher remains connected.
    pub monitoring: bool,
    /// Activity is in the foreground.
    pub foreground: bool,
    /// Display is interactive and keyguard is not locked.
    pub screen_unlocked: bool,
    /// FLAG_SECURE was observed on this window before enabling inputs.
    pub secure_window: bool,
}
#[derive(Default)]
struct State {
    observed: AndroidState,
    next: u64,
    callbacks: BTreeMap<u64, LockCallback>,
    /// Live background deferrals (foreground-started clipboard holds and
    /// document picks).
    holding: usize,
    /// Background expiry observed during a deferral (plan 0031 decision 1).
    deferred: bool,
}
/// Android services. Quick unlock is unavailable; the clipboard needs a backend.
#[derive(Clone, Default)]
pub struct AndroidPlatform {
    state: Arc<Mutex<State>>,
    backend: Option<Arc<dyn AndroidClipboardBackend>>,
    keystore: Option<Arc<dyn Keystore>>,
}
struct Guard {
    state: Weak<Mutex<State>>,
    id: u64,
}
impl Watch for Guard {}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .callbacks
                .remove(&self.id);
        }
    }
}
fn lock_event(observed: AndroidState) -> Option<LockEvent> {
    if !observed.monitoring || !observed.secure_window {
        Some(LockEvent::ProtectionLost)
    } else if !observed.screen_unlocked {
        Some(LockEvent::ScreenLocked)
    } else if !observed.foreground {
        Some(LockEvent::BackgroundExpired)
    } else {
        None
    }
}
impl AndroidPlatform {
    /// Inject a validated hardware wrapping adapter; no default backend exists.
    pub fn with_keystore(mut self, backend: Arc<dyn Keystore>) -> Self {
        self.keystore = Some(backend);
        self
    }
    /// Enable copying through a native clipboard backend.
    pub fn with_clipboard(mut self, backend: Arc<dyn AndroidClipboardBackend>) -> Self {
        self.backend = Some(backend);
        self
    }
    /// Apply observations from native OS polling/events, never from webview IPC.
    /// Background expiry is immediate, except that a clipboard hold started in
    /// the foreground defers it until the hold ends (at most its timeout), so
    /// the copied value can be pasted. Screen lock and lost protection never wait.
    pub fn update(&self, observed: AndroidState) {
        let (callbacks, event) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let previous = state.observed;
            state.observed = observed;
            let mut event = lock_event(observed);
            if event == Some(LockEvent::BackgroundExpired) && state.holding > 0 {
                state.deferred = true;
                event = None;
            }
            let changed = previous.monitoring != observed.monitoring
                || previous.foreground != observed.foreground
                || previous.screen_unlocked != observed.screen_unlocked
                || previous.secure_window != observed.secure_window;
            (
                if changed {
                    state.callbacks.values().cloned().collect::<Vec<_>>()
                } else {
                    Vec::new()
                },
                event,
            )
        };
        if let Some(event) = event {
            for callback in callbacks {
                callback(event);
            }
        }
    }
}
/// Defers background expiry while it lives; see [`AndroidPlatform::defer_background`].
pub struct BackgroundDeferral(Weak<Mutex<State>>);
impl Drop for BackgroundDeferral {
    fn drop(&mut self) {
        if let Some(state) = self.0.upgrade() {
            release(&state);
        }
    }
}
impl AndroidPlatform {
    /// Defer background expiry, and only that, while the guard lives: for an
    /// app-initiated OS interaction started in the foreground (a clipboard
    /// hold, or the system document picker, which always backgrounds the
    /// activity). `None` unless currently foreground with protection. A
    /// deferred expiry fires when the last guard drops while still in the
    /// background. Screen lock and lost protection never wait. Dropping the
    /// guard can run lock callbacks, so never drop it while holding a lock
    /// those callbacks take.
    pub fn defer_background(&self) -> Option<BackgroundDeferral> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if lock_event(state.observed).is_some() {
            return None;
        }
        state.holding += 1;
        Some(BackgroundDeferral(Arc::downgrade(&self.state)))
    }
}
fn release(state: &Mutex<State>) {
    let (callbacks, event) = {
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        state.holding = state.holding.saturating_sub(1);
        if state.holding > 0 || !state.deferred {
            return;
        }
        state.deferred = false;
        match lock_event(state.observed) {
            Some(event) => (state.callbacks.values().cloned().collect::<Vec<_>>(), event),
            None => return,
        }
    };
    for callback in callbacks {
        callback(event);
    }
}
impl Clipboard for AndroidPlatform {
    fn hold(
        &self,
        value: SecretBytes,
        timeout: Duration,
        cancel: Cancellation,
        progress: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        let backend = self.backend.as_ref().ok_or(PlatformError::Unavailable)?;
        let text =
            std::str::from_utf8(value.expose_secret()).map_err(|_| PlatformError::InvalidInput)?;
        let _holding = self.defer_background();
        let token = backend.set(text)?;
        drop(value);
        // Clear only a clip that is verifiably still ours; an unverifiable
        // one is left for the OS (0008 §3: clear only if still owned).
        let finish = |result: Result<(), PlatformError>| {
            if backend.owned(token) == Some(true) {
                let _ = backend.clear();
            }
            result
        };
        let start = Instant::now();
        loop {
            if cancel() {
                return finish(Err(PlatformError::Cancelled));
            }
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                return finish(Ok(()));
            }
            if let Err(e) = progress(left.as_secs() + u64::from(left.subsec_nanos() > 0)) {
                return finish(Err(e));
            }
            if backend.owned(token) == Some(false) {
                // Replaced by another copy: no longer ours to clear.
                return Ok(());
            }
            std::thread::sleep(left.min(Duration::from_millis(250)));
        }
    }
}
impl Lifecycle for AndroidPlatform {
    fn watch(&self, callback: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
        let (id, observed) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if !state.observed.monitoring || !state.observed.secure_window {
                return Err(PlatformError::Unavailable);
            }
            if state.callbacks.len() >= 8 {
                return Err(PlatformError::LimitExceeded);
            }
            state.next = state
                .next
                .checked_add(1)
                .ok_or(PlatformError::LimitExceeded)?;
            let id = state.next;
            state.callbacks.insert(id, callback.clone());
            (id, state.observed)
        };
        if !observed.screen_unlocked {
            callback(LockEvent::ScreenLocked)
        } else if !observed.foreground {
            callback(LockEvent::BackgroundExpired)
        }
        Ok(Box::new(Guard {
            state: Arc::downgrade(&self.state),
            id,
        }))
    }
}
impl PlatformServices for AndroidPlatform {
    fn status(&self) -> ProtectionStatus {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        ProtectionStatus {
            storage: Evidence::Unknown,
            swap: Evidence::Unknown,
            hibernation: Evidence::Unknown,
            lifecycle: state.observed.monitoring && state.observed.secure_window,
            clipboard: self.backend.is_some(),
            quick_unlock: self.keystore.as_ref().is_some_and(|k| k.available()),
        }
    }
    fn lifecycle(&self) -> &dyn Lifecycle {
        self
    }
    fn clipboard(&self) -> &dyn Clipboard {
        if self.backend.is_some() {
            self
        } else {
            &Unavailable
        }
    }
    fn secure_input(&self) -> &dyn SecureInput {
        &Unavailable
    }
    fn keystore(&self) -> &dyn Keystore {
        self.keystore.as_deref().unwrap_or(&Unavailable)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn android_lifecycle_initial_state_failure_and_late_foreground_never_unlock() {
        let os = AndroidPlatform::default();
        assert!(os.watch(Arc::new(|_| {})).is_err());
        os.update(AndroidState {
            monitoring: true,
            foreground: true,
            screen_unlocked: true,
            secure_window: true,
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let capture = events.clone();
        let guard = os
            .watch(Arc::new(move |event| capture.lock().unwrap().push(event)))
            .unwrap();
        os.update(AndroidState {
            monitoring: true,
            foreground: false,
            screen_unlocked: true,
            secure_window: true,
        });
        os.update(AndroidState {
            monitoring: true,
            foreground: true,
            screen_unlocked: true,
            secure_window: true,
        });
        os.update(AndroidState::default());
        assert_eq!(
            *events.lock().unwrap(),
            [LockEvent::BackgroundExpired, LockEvent::ProtectionLost]
        );
        drop(guard);
        assert!(os.state.lock().unwrap().callbacks.is_empty());
        assert!(!os.status().lifecycle);
        assert!(!os.keystore().available());
        assert!(!os.status().clipboard);
    }
    #[derive(Default)]
    struct Native {
        clip: Mutex<Option<(String, i64)>>,
        next: std::sync::atomic::AtomicI64,
        hidden: std::sync::atomic::AtomicBool,
        cleared: std::sync::atomic::AtomicUsize,
    }
    impl AndroidClipboardBackend for Native {
        fn set(&self, text: &str) -> Result<ClipToken, PlatformError> {
            let t = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            *self.clip.lock().unwrap() = Some((text.to_owned(), t));
            Ok(ClipToken(t))
        }
        fn owned(&self, token: ClipToken) -> Option<bool> {
            if self.hidden.load(std::sync::atomic::Ordering::SeqCst) {
                return None;
            }
            Some(
                self.clip
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|c| c.1 == token.0),
            )
        }
        fn clear(&self) -> Result<(), PlatformError> {
            self.cleared
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.clip.lock().unwrap() = None;
            Ok(())
        }
    }
    fn visible() -> AndroidState {
        AndroidState {
            monitoring: true,
            foreground: true,
            screen_unlocked: true,
            secure_window: true,
        }
    }
    fn protected(text: &str) -> SecretBytes {
        let mut v = SecretBytes::zeroed(text.len());
        v.expose_secret_mut().copy_from_slice(text.as_bytes());
        v
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn android_clipboard_hold_defers_only_background_expiry_and_clears_only_owned() {
        use std::sync::atomic::Ordering::SeqCst;
        let native = Arc::new(Native::default());
        let os = AndroidPlatform::default().with_clipboard(native.clone());
        os.update(visible());
        assert!(os.status().clipboard);
        let events = Arc::new(Mutex::new(Vec::new()));
        let capture = events.clone();
        let _guard = os
            .watch(Arc::new(move |e| capture.lock().unwrap().push(e)))
            .unwrap();
        // Expiry clears our clip; the value never reaches progress.
        let mut seen = Vec::new();
        os.clipboard()
            .hold(
                protected("abc"),
                Duration::from_millis(30),
                Arc::new(|| false),
                &mut |s| {
                    seen.push(s);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(native.cleared.load(SeqCst), 1);
        assert!(native.clip.lock().unwrap().is_none());
        // Backgrounding during a foreground hold defers expiry until the hold ends.
        let os2 = os.clone();
        let hold = std::thread::spawn(move || {
            os2.clipboard().hold(
                protected("abc"),
                Duration::from_millis(400),
                Arc::new(|| false),
                &mut |_| Ok(()),
            )
        });
        std::thread::sleep(Duration::from_millis(60));
        // While another app has focus the clip is unverifiable: left alone.
        native.hidden.store(true, SeqCst);
        os.update(AndroidState {
            foreground: false,
            ..visible()
        });
        assert!(events.lock().unwrap().is_empty());
        hold.join().unwrap().unwrap();
        assert_eq!(*events.lock().unwrap(), [LockEvent::BackgroundExpired]);
        assert_eq!(native.cleared.load(SeqCst), 1);
        assert!(native.clip.lock().unwrap().is_some());
        // Screen lock during a hold locks at once; cancel clears an owned clip.
        native.hidden.store(false, SeqCst);
        events.lock().unwrap().clear();
        os.update(visible());
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = cancel.clone();
        let os3 = os.clone();
        let hold = std::thread::spawn(move || {
            os3.clipboard().hold(
                protected("xyz"),
                Duration::from_secs(5),
                Arc::new(move || flag.load(SeqCst)),
                &mut |_| Ok(()),
            )
        });
        std::thread::sleep(Duration::from_millis(60));
        os.update(AndroidState {
            screen_unlocked: false,
            ..visible()
        });
        assert_eq!(*events.lock().unwrap(), [LockEvent::ScreenLocked]);
        cancel.store(true, SeqCst);
        assert_eq!(hold.join().unwrap(), Err(PlatformError::Cancelled));
        assert_eq!(native.cleared.load(SeqCst), 2);
        // A replaced clip ends the hold without clearing someone else's.
        os.update(visible());
        let os4 = os.clone();
        let n2 = native.clone();
        let hold = std::thread::spawn(move || {
            os4.clipboard().hold(
                protected("mine"),
                Duration::from_secs(5),
                Arc::new(|| false),
                &mut |_| Ok(()),
            )
        });
        std::thread::sleep(Duration::from_millis(60));
        n2.set("other").unwrap();
        hold.join().unwrap().unwrap();
        assert_eq!(native.cleared.load(SeqCst), 2);
        assert_eq!(native.clip.lock().unwrap().as_ref().unwrap().0, "other");
        assert!(
            os.clipboard()
                .hold(
                    SecretBytes::zeroed(0),
                    Duration::ZERO,
                    Arc::new(|| false),
                    &mut |_| Ok(())
                )
                .is_ok()
        );
    }
    #[test]
    fn android_document_pick_deferral_is_foreground_only_and_fires_on_release() {
        let os = AndroidPlatform::default();
        os.update(visible());
        let events = Arc::new(Mutex::new(Vec::new()));
        let capture = events.clone();
        let _guard = os
            .watch(Arc::new(move |e| capture.lock().unwrap().push(e)))
            .unwrap();
        // The picker backgrounds the activity; the vault stays open until the
        // deferral is released, and returning to the foreground first means
        // no lock at all.
        let pick = os.defer_background().unwrap();
        os.update(AndroidState {
            foreground: false,
            ..visible()
        });
        os.update(visible());
        drop(pick);
        assert!(events.lock().unwrap().is_empty());
        // Released while still in the background: the deferred expiry fires.
        let pick = os.defer_background().unwrap();
        os.update(AndroidState {
            foreground: false,
            ..visible()
        });
        assert!(events.lock().unwrap().is_empty());
        assert!(os.defer_background().is_none());
        drop(pick);
        assert_eq!(*events.lock().unwrap(), [LockEvent::BackgroundExpired]);
        // Screen lock never waits for a deferral.
        events.lock().unwrap().clear();
        os.update(visible());
        let _pick = os.defer_background().unwrap();
        os.update(AndroidState {
            screen_unlocked: false,
            ..visible()
        });
        assert_eq!(*events.lock().unwrap(), [LockEvent::ScreenLocked]);
    }
}
