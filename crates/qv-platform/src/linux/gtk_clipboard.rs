// SPDX-License-Identifier: AGPL-3.0-or-later

//! The desktop app's clipboard on Wayland (plan 0055). GTK owns the selection
//! through the app window's seat, which every Wayland compositor accepts;
//! whether an XWayland selection reaches Wayland clients is compositor policy.
//! X11 displays keep [`X11Clipboard`]; processes without GTK (the CLI) use
//! [`SessionClipboard`].
//!
//! GTK copies the text into its own memory for each request and writes it to
//! the requester's pipe. That framework copy is best-effort (0008 §4.4), like
//! x11rb's send buffer; the value itself stays in [`SecretBytes`].
use crate::clipboard::{SessionClipboard, X11Clipboard, validate};
use crate::{Cancellation, Clipboard, PlatformError};
use gtk::prelude::*;
use gtk::{gdk, glib};
use qv_crypto::SecretBytes;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant};

/// Target info: text targets answer the value, the hint answers a marker.
const TEXT: u32 = 0;
const HINT: u32 = 1;
const TARGETS: [(&str, u32); 6] = [
    ("UTF8_STRING", TEXT),
    ("text/plain;charset=utf-8", TEXT),
    ("STRING", TEXT),
    ("TEXT", TEXT),
    ("text/plain", TEXT),
    ("x-kde-passwordManagerHint", HINT),
];
/// How long the worker waits for the GTK thread to answer.
const GTK_ANSWER: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(100);

/// A Wayland session, for status reporting before GTK is initialized.
pub(crate) fn wayland_session() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

#[derive(Default)]
struct Shared {
    value: Option<SecretBytes>,
    /// A text target was answered (0008 §3: the GTK delivery rule).
    delivered: bool,
    /// GTK gave up ownership to someone else.
    lost: bool,
    /// We are clearing our own selection; the release is not a loss.
    releasing: bool,
    /// The worker stopped waiting; a late start must not take ownership.
    abandoned: bool,
}
type State = Arc<Mutex<Shared>>;
fn lock(state: &State) -> MutexGuard<'_, Shared> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Owned by the provider closure, which GTK frees exactly when it gives up
/// ownership: on a successor's copy, or on our own clear.
struct Release(State);
impl Drop for Release {
    fn drop(&mut self) {
        let mut shared = lock(&self.0);
        if !shared.releasing {
            shared.lost = true;
        }
    }
}

enum Start {
    Owned,
    UseX11,
    Unavailable,
}

/// The result once a successor took ownership.
fn replaced(delivered: bool) -> Result<(), PlatformError> {
    if delivered {
        Ok(())
    } else {
        Err(PlatformError::ClipboardReplaced)
    }
}

/// The bytes one request receives: the hint marker never carries the value.
fn answer(info: u32, value: &[u8]) -> &[u8] {
    if info == HINT { b"secret" } else { value }
}

/// On the GTK thread: take ownership on a Wayland display.
fn start(state: State) -> Start {
    if lock(&state).abandoned {
        return Start::Unavailable;
    }
    let Some(display) = gdk::Display::default() else {
        return Start::Unavailable;
    };
    if display.type_().name() != "GdkWaylandDisplay" {
        return Start::UseX11;
    }
    let targets: Vec<gtk::TargetEntry> = TARGETS
        .iter()
        .map(|(name, info)| gtk::TargetEntry::new(name, gtk::TargetFlags::empty(), *info))
        .collect();
    let release = Release(state);
    let provider = move |_: &gtk::Clipboard, data: &gtk::SelectionData, info: u32| {
        let mut shared = lock(&release.0);
        let Some(value) = shared.value.as_ref() else {
            return;
        };
        let bytes = answer(info, value.expose_secret());
        if info == HINT {
            data.set(&data.target(), 8, bytes);
        } else if let Ok(text) = std::str::from_utf8(bytes)
            && data.set_text(text)
        {
            shared.delivered = true;
        }
    };
    if gtk::Clipboard::get(&gdk::SELECTION_CLIPBOARD).set_with_data(&targets, provider) {
        Start::Owned
    } else {
        Start::Unavailable
    }
}

/// From the worker: give up our selection if, and only if, we still own it.
/// A Wayland round trip reads any pending loss first, and the idle callback
/// runs after GDK has dispatched it (idle is below event priority).
fn finish(state: &State) -> Result<(), PlatformError> {
    if lock(state).lost {
        return Ok(());
    }
    let (tx, rx) = mpsc::channel();
    let state = state.clone();
    glib::MainContext::default().invoke(move || {
        if let Some(display) = gdk::Display::default() {
            display.sync();
        }
        glib::idle_add_once(move || {
            let ours = {
                let mut shared = lock(&state);
                shared.releasing = !shared.lost;
                shared.releasing
            };
            // No lock is held here: clearing frees the provider, whose
            // `Release` takes it.
            if ours {
                gtk::Clipboard::get(&gdk::SELECTION_CLIPBOARD).clear();
            }
            let _ = tx.send(());
        });
    });
    rx.recv_timeout(GTK_ANSWER)
        .map_err(|_| PlatformError::Unavailable)
}

/// Clipboard for the desktop app: GTK on a Wayland display, X11 on an X11
/// one, and [`SessionClipboard`] when GTK is not running in this process.
#[derive(Debug, Default)]
pub struct GtkClipboard;
impl Clipboard for GtkClipboard {
    fn hold(
        &self,
        value: SecretBytes,
        timeout: Duration,
        cancel: Cancellation,
        progress: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        validate(&value, timeout, &cancel)?;
        if !gtk::is_initialized() {
            return SessionClipboard.hold(value, timeout, cancel, progress);
        }
        let state: State = Arc::new(Mutex::new(Shared {
            value: Some(value),
            ..Shared::default()
        }));
        let (tx, rx) = mpsc::channel();
        {
            let state = state.clone();
            glib::MainContext::default().invoke(move || {
                let _ = tx.send(start(state));
            });
        }
        match rx.recv_timeout(GTK_ANSWER) {
            Ok(Start::Owned) => {}
            Ok(Start::UseX11) => {
                let value = lock(&state).value.take();
                return match value {
                    Some(value) => X11Clipboard.hold(value, timeout, cancel, progress),
                    None => Err(PlatformError::Unavailable),
                };
            }
            Ok(Start::Unavailable) | Err(_) => {
                let mut shared = lock(&state);
                shared.abandoned = true;
                shared.value = None;
                return Err(PlatformError::Unavailable);
            }
        }
        let end = Instant::now() + timeout;
        let mut last = None;
        let result = loop {
            if cancel() {
                break Err(PlatformError::Cancelled);
            }
            let now = Instant::now();
            if now >= end {
                break Ok(());
            }
            {
                let shared = lock(&state);
                if shared.lost {
                    break replaced(shared.delivered);
                }
            }
            let left = end.saturating_duration_since(now).as_secs() + 1;
            if last != Some(left) {
                if let Err(error) = progress(left) {
                    break Err(error);
                }
                last = Some(left);
            }
            std::thread::sleep(POLL.min(end.saturating_duration_since(now)));
        };
        let cleanup = finish(&state);
        lock(&state).value = None;
        if cancel() {
            return Err(PlatformError::Cancelled);
        }
        result.and(cleanup)
    }
}

#[cfg(test)]
mod tests {
    // Tests intentionally fail loudly on fixture errors.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::clipboard::MAX_VALUE;

    fn never() -> Cancellation {
        Arc::new(|| false)
    }

    #[test]
    fn gtk_clipboard_rejects_bad_requests_before_any_backend() {
        let ok = Duration::from_secs(20);
        assert_eq!(
            validate(&SecretBytes::zeroed(MAX_VALUE + 1), ok, &never()),
            Err(PlatformError::LimitExceeded)
        );
        let mut invalid = [0xff, 0xfe];
        assert_eq!(
            validate(&SecretBytes::take_from(&mut invalid), ok, &never()),
            Err(PlatformError::InvalidInput)
        );
        for timeout in [Duration::from_millis(999), Duration::from_secs(301)] {
            assert_eq!(
                validate(&SecretBytes::zeroed(4), timeout, &never()),
                Err(PlatformError::InvalidInput)
            );
        }
        assert_eq!(
            validate(
                &SecretBytes::zeroed(4),
                ok,
                &(Arc::new(|| true) as Cancellation)
            ),
            Err(PlatformError::Cancelled)
        );
        assert_eq!(
            validate(&SecretBytes::zeroed(MAX_VALUE), ok, &never()),
            Ok(())
        );
    }

    #[test]
    fn gtk_clipboard_reports_replacement_only_before_delivery() {
        assert_eq!(replaced(false), Err(PlatformError::ClipboardReplaced));
        assert_eq!(replaced(true), Ok(()));
    }

    #[test]
    fn gtk_clipboard_hint_target_never_carries_the_value() {
        let value = b"hunter2";
        assert_eq!(answer(HINT, value), b"secret");
        assert_eq!(answer(TEXT, value), value);
        assert_eq!(TARGETS.iter().filter(|(_, info)| *info == HINT).count(), 1);
        assert!(
            TARGETS
                .iter()
                .any(|(name, info)| *name == "UTF8_STRING" && *info == TEXT)
        );
    }

    #[test]
    fn gtk_clipboard_release_marks_loss_unless_we_cleared() {
        let state: State = Arc::default();
        drop(Release(state.clone()));
        assert!(lock(&state).lost);

        let state: State = Arc::default();
        lock(&state).releasing = true;
        drop(Release(state.clone()));
        assert!(!lock(&state).lost);
    }

    #[test]
    fn gtk_clipboard_without_gtk_uses_the_session_clipboard_checks() {
        // No GTK in this process: the session clipboard runs, and the
        // shared checks still reject an invalid request first.
        assert!(!gtk::is_initialized());
        let mut invalid = [0xff];
        assert_eq!(
            GtkClipboard.hold(
                SecretBytes::take_from(&mut invalid),
                Duration::from_secs(20),
                never(),
                &mut |_| Ok(())
            ),
            Err(PlatformError::InvalidInput)
        );
    }
}
