// SPDX-License-Identifier: AGPL-3.0-or-later

//! OS service injection and explicit reduced-protection policy (0008 §1.3).
//! Frontends continue through core; no vault key reaches an OS event callback.
use crate::{Core, CoreError, Session};
pub use qv_platform::android::{
    AndroidClipboardBackend, AndroidPlatform, AndroidState, BackgroundDeferral, ClipToken,
};
pub use qv_platform::autofill;
pub use qv_platform::quick_unlock::{AndroidKeystore, AndroidKeystoreBackend};
pub use qv_platform::{
    Cancellation, Clipboard, Evidence, InputPurpose, Keystore, Lifecycle, LockCallback, LockEvent,
    PlatformError, PlatformServices, ProtectionStatus, QuickBinding, QuickPolicy, SecureInput,
    Unavailable, Watch,
};
#[cfg(target_os = "linux")]
pub use qv_platform::{
    clipboard::X11Clipboard,
    files,
    linux::{InstanceLock, LinuxPlatform, portal},
};
use std::sync::Arc;

pub(crate) struct PlatformPolicy {
    pub(crate) services: Arc<dyn PlatformServices>,
    acknowledged: bool,
    lifecycle_required: bool,
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
            lifecycle_required: true,
        });
        self
    }
    /// Configure Linux OS services with optional lock/sleep notifications.
    /// Manual and application inactivity locking remain the frontend's duty.
    /// Missing monitoring requires explicit reduced-protection acknowledgement;
    /// observed lock/loss events still invalidate the bound session.
    #[cfg(target_os = "linux")]
    pub fn with_linux_platform(
        self,
        services: Arc<dyn PlatformServices>,
        acknowledge_reduced: bool,
    ) -> Self {
        let mut core = self.with_platform(services, acknowledge_reduced);
        if let Some(policy) = &mut core.platform {
            policy.lifecycle_required = false;
        }
        core
    }
    /// Current OS protection status for frontend security settings.
    pub fn platform_status(&self) -> Option<ProtectionStatus> {
        self.platform.as_ref().map(|p| p.services.status())
    }
    pub(crate) fn quick_services(&self) -> Result<&Arc<dyn PlatformServices>, CoreError> {
        let services = &self
            .platform
            .as_ref()
            .ok_or(CoreError::NotAllowed)?
            .services;
        if !services.keystore().available() {
            return Err(CoreError::NotAllowed);
        }
        Ok(services)
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
            session.services = Some(policy.services.clone());
            if let Err(failure) = session.attach_platform(policy.services.as_ref()) {
                if policy.lifecycle_required {
                    return Err(error(failure));
                }
                // Monitoring may become unavailable after the initial gate.
                if !policy.acknowledged {
                    return Err(CoreError::NotAllowed);
                }
            }
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
