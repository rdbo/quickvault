// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux adapters. System-bus/logind absence is explicit reduced protection.
mod instance;
mod logind;
mod persistence;
use crate::clipboard::X11Clipboard;
use crate::{
    Clipboard, Keystore, Lifecycle, PlatformServices, ProtectionStatus, SecureInput, Unavailable,
};
pub use instance::InstanceLock;
pub use logind::Logind;
pub use persistence::detect_persistence;

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
        status.clipboard = X11Clipboard.is_available();
        status
    }
    fn lifecycle(&self) -> &dyn Lifecycle {
        &self.logind
    }
    fn clipboard(&self) -> &dyn Clipboard {
        &X11Clipboard
    }
    fn secure_input(&self) -> &dyn SecureInput {
        &Unavailable
    }
    fn keystore(&self) -> &dyn Keystore {
        &Unavailable
    }
}
