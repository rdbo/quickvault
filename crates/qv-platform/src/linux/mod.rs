// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux adapters. System-bus/logind absence is explicit reduced protection.
#[cfg(feature = "gtk")]
mod gtk_clipboard;
mod instance;
mod logind;
mod persistence;
pub mod portal;
use crate::clipboard::SessionClipboard;
use crate::{
    Clipboard, Keystore, Lifecycle, PlatformServices, ProtectionStatus, SecureInput, Unavailable,
};
#[cfg(feature = "gtk")]
pub use gtk_clipboard::GtkClipboard;
pub use instance::InstanceLock;
pub use logind::Logind;
pub use persistence::detect_persistence;

/// GTK on a Wayland display when GTK runs in this process, else the session
/// clipboard: Wayland data-control, then X11 (plan 0055).
#[cfg(feature = "gtk")]
const CLIPBOARD: &dyn Clipboard = &GtkClipboard;
#[cfg(not(feature = "gtk"))]
const CLIPBOARD: &dyn Clipboard = &SessionClipboard;

/// Linux OS services; no native-input requirement and no quick-unlock backend.
#[derive(Default)]
pub struct LinuxPlatform {
    logind: Logind,
}
impl PlatformServices for LinuxPlatform {
    fn status(&self) -> ProtectionStatus {
        let mut status = detect_persistence();
        status.lifecycle = self.logind.is_available();
        // A bounded local connection probe never reads/owns the clipboard.
        // With GTK (the desktop app), a Wayland session has a native one.
        #[cfg(feature = "gtk")]
        let native = gtk_clipboard::wayland_session();
        #[cfg(not(feature = "gtk"))]
        let native = false;
        status.clipboard = native || SessionClipboard.is_available();
        status
    }
    fn lifecycle(&self) -> &dyn Lifecycle {
        &self.logind
    }
    fn clipboard(&self) -> &dyn Clipboard {
        CLIPBOARD
    }
    fn secure_input(&self) -> &dyn SecureInput {
        &Unavailable
    }
    fn keystore(&self) -> &dyn Keystore {
        &Unavailable
    }
}
