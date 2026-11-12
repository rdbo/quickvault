// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows adapters (spec 0009 §5.1; plan 0052): WTS session and sleep
//! notifications, a clipboard with history/cloud exclusion, the
//! single-instance lock and native file dialogs. Storage, swap and
//! hibernation protection cannot be established without administrator
//! queries, so they are reported as unknown and the reduced-protection
//! acknowledgement applies. There is no quick-unlock backend.
mod clipboard;
mod instance;
mod lifecycle;

use crate::{
    Clipboard, Evidence, Keystore, Lifecycle, PlatformError, PlatformServices, ProtectionStatus,
    SecureInput, Unavailable,
};
pub use clipboard::WinClipboard;
pub use instance::InstanceLock;
pub use lifecycle::WtsLifecycle;
pub use qv_win::dialog::Choose as Pick;

/// Windows OS services; quick unlock is unavailable (no validated backend).
#[derive(Default)]
pub struct WindowsPlatform {
    lifecycle: WtsLifecycle,
}

impl PlatformServices for WindowsPlatform {
    fn status(&self) -> ProtectionStatus {
        ProtectionStatus {
            storage: Evidence::Unknown,
            swap: Evidence::Unknown,
            hibernation: Evidence::Unknown,
            lifecycle: self.lifecycle.is_available(),
            clipboard: true,
            quick_unlock: false,
        }
    }
    fn lifecycle(&self) -> &dyn Lifecycle {
        &self.lifecycle
    }
    fn clipboard(&self) -> &dyn Clipboard {
        &WinClipboard
    }
    fn secure_input(&self) -> &dyn SecureInput {
        &Unavailable
    }
    fn keystore(&self) -> &dyn Keystore {
        &Unavailable
    }
}

/// Shows the native open, save or folder dialog. `Ok(None)` if the user
/// cancelled. The path is untrusted: open it through [`crate::files`].
pub fn pick(title: &str, kind: &Pick) -> Result<Option<std::path::PathBuf>, PlatformError> {
    qv_win::dialog::choose(title, kind).map_err(|_| PlatformError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_status_is_reduced_without_quick_unlock() {
        let p = WindowsPlatform::default();
        let s = p.status();
        assert!(s.is_reduced());
        assert!(!s.quick_unlock);
        assert!(!p.keystore().available());
        assert_eq!(s.storage, Evidence::Unknown);
    }
}
