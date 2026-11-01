// SPDX-License-Identifier: AGPL-3.0-or-later

//! Android lifecycle metadata supplied by minimal native packaging glue.
//! No secret is passed over the native lifecycle channel.
use crate::{
    Clipboard, Evidence, Keystore, Lifecycle, LockCallback, LockEvent, PlatformError,
    PlatformServices, ProtectionStatus, SecureInput, Unavailable, Watch,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

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
}
/// Android services. Clipboard/quick unlock are unavailable in this foundation.
#[derive(Clone, Default)]
pub struct AndroidPlatform {
    state: Arc<Mutex<State>>,
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
impl AndroidPlatform {
    /// Apply observations from native OS polling/events, never from webview IPC.
    /// Immediate background locking is stricter than a background grace period.
    pub fn update(&self, observed: AndroidState) {
        let (callbacks, event) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let previous = state.observed;
            state.observed = observed;
            let event = if !observed.monitoring || !observed.secure_window {
                Some(LockEvent::ProtectionLost)
            } else if !observed.screen_unlocked {
                Some(LockEvent::ScreenLocked)
            } else if !observed.foreground {
                Some(LockEvent::BackgroundExpired)
            } else {
                None
            };
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
    }
}
