// SPDX-License-Identifier: AGPL-3.0-or-later

//! OS service injection and explicit reduced-protection policy (0008 §1.3).
//! Frontends continue through core; no vault key reaches an OS event callback.
use crate::{Core, CoreError, Session};
pub use qv_platform::{
    Cancellation, Clipboard, Evidence, InputPurpose, Keystore, Lifecycle, LockCallback, LockEvent,
    PlatformError, PlatformServices, ProtectionStatus, SecureInput, Unavailable, Watch,
};
#[cfg(target_os = "linux")]
pub use qv_platform::{
    clipboard::X11Clipboard,
    linux::{InstanceLock, LinuxPlatform},
};
use std::sync::Arc;

pub(crate) struct PlatformPolicy {
    services: Arc<dyn PlatformServices>,
    acknowledged: bool,
}
pub(crate) fn error(error: PlatformError) -> CoreError {
    match error {
        PlatformError::Cancelled => CoreError::Cancelled,
        PlatformError::LimitExceeded => CoreError::LimitExceeded,
        PlatformError::InvalidInput => CoreError::InvalidInput,
        PlatformError::Unavailable | PlatformError::Busy => CoreError::NotAllowed,
        PlatformError::Io => qv_store::StoreError::Io.into(),
    }
}
impl Core {
    /// Inject OS services. `acknowledge_reduced` is explicit frontend consent
    /// for this core instance, not a claim that OS persistence is protected.
    /// Production app flows must configure this before persistent secret use.
    pub fn with_platform(
        mut self,
        services: Arc<dyn PlatformServices>,
        acknowledge_reduced: bool,
    ) -> Self {
        self.platform = Some(PlatformPolicy {
            services,
            acknowledged: acknowledge_reduced,
        });
        self
    }
    /// Current OS protection status for frontend security settings.
    pub fn platform_status(&self) -> Option<ProtectionStatus> {
        self.platform.as_ref().map(|p| p.services.status())
    }
    pub(crate) fn platform_gate(&self) -> Result<(), CoreError> {
        if self
            .platform
            .as_ref()
            .is_some_and(|p| p.services.status().is_reduced() && !p.acknowledged)
        {
            return Err(CoreError::NotAllowed);
        }
        Ok(())
    }
    pub(crate) fn bind_platform(&self, mut session: Session) -> Result<Session, CoreError> {
        if let Some(policy) = &self.platform {
            // Consent covers uncertain OS persistence, not disabling required
            // lock/sleep handling for a configured platform session.
            session
                .attach_platform(policy.services.as_ref())
                .map_err(error)?;
            if session.is_locked() {
                return Err(CoreError::Cancelled);
            }
        }
        Ok(session)
    }
}
#[cfg(test)]
#[path = "platform_tests.rs"]
mod tests;
