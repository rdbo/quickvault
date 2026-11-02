// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native OS services injected into core. OS protection is reported explicitly.
//! No backend here stores keys or implements Linux quick unlock. Framework input
//! and its best-effort cleanup remain the application's responsibility (0008).

/// Android lifecycle/protection adapter, also testable without a device.
pub mod android;

use qv_crypto::SecretBytes;
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
pub mod clipboard;
/// No-follow explicit user file input/output (Linux).
#[cfg(target_os = "linux")]
pub mod files;
#[cfg(target_os = "linux")]
pub mod linux;

/// Cancellation is sampled between bounded units of OS work; contains no secrets.
pub type Cancellation = Arc<dyn Fn() -> bool + Send + Sync>;
/// Redacted OS-service failures, without paths, OS messages or secret payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformError {
    /// Backend is absent or its security contract cannot be established.
    Unavailable,
    /// The operation was cancelled.
    Cancelled,
    /// Invalid request (for example non-text clipboard content).
    InvalidInput,
    /// A request exceeds its public budget.
    LimitExceeded,
    /// Another instance holds the lock.
    Busy,
    /// An OS operation failed.
    Io,
}
/// Whether a protection prerequisite has been established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// The particular prerequisite is established (not a general security claim).
    Verified,
    /// Configuration exposes a known gap.
    KnownGap,
    /// The adapter cannot establish this prerequisite.
    Unknown,
}
/// OS persistence and service availability, for frontend security settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectionStatus {
    /// Storage keys unavailable to a locked-device thief.
    pub storage: Evidence,
    /// Swap protection/key custody.
    pub swap: Evidence,
    /// Hibernation protection/key custody.
    pub hibernation: Evidence,
    /// Lock/sleep monitoring is available.
    pub lifecycle: bool,
    /// A supported clipboard backend is available.
    pub clipboard: bool,
    /// A validated authenticated wrapping backend exists.
    pub quick_unlock: bool,
}
impl ProtectionStatus {
    /// Whether explicit reduced-protection acknowledgement is required.
    pub fn is_reduced(self) -> bool {
        self.storage != Evidence::Verified
            || self.swap != Evidence::Verified
            || self.hibernation != Evidence::Verified
            || !self.lifecycle
    }
}
/// A reason to cancel operations, clear owned clipboard and lock the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockEvent {
    /// Screen lock requested or observed.
    ScreenLocked,
    /// Suspend/hibernate is starting.
    PreparingForSleep,
    /// The mobile background grace period expired.
    BackgroundExpired,
    /// Monitoring disconnected, service ownership changed or data was invalid.
    ProtectionLost,
}
/// No-secret callback; implementations must never invoke it while holding their own locks.
pub type LockCallback = Arc<dyn Fn(LockEvent) + Send + Sync>;
/// Owned subscription. Drop must cancel the reader and release OS resources.
pub trait Watch: Send + Sync {}
/// Lifecycle monitor. Installation precedes the initial lock-state check.
pub trait Lifecycle: Send + Sync {
    /// Subscribe; failure must not be advertised as working protection.
    fn watch(&self, callback: LockCallback) -> Result<Box<dyn Watch>, PlatformError>;
}
/// Purpose for a bounded secret-input request; no dynamic prompt can carry data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPurpose {
    /// A master password.
    MasterPassword,
    /// A recovery phrase.
    RecoveryPhrase,
    /// A protected record field.
    ProtectedField,
}
/// Optional native input service; ordinary Dioxus input does not require one.
pub trait SecureInput: Send + Sync {
    /// Return protected bytes, respecting a caller bound and cancellation.
    fn read_secret(
        &self,
        purpose: InputPurpose,
        max_bytes: usize,
        cancel: Cancellation,
    ) -> Result<SecretBytes, PlatformError>;
}
/// Authenticated platform wrapping service. Unsupported backends must fail closed.
pub trait Keystore: Send + Sync {
    /// Whether the backend meets 0002 §5; Linux returns false.
    fn available(&self) -> bool;
    /// Produce an authenticated device-local envelope; never an exportable fallback key.
    fn wrap(&self, secret: &SecretBytes) -> Result<SecretBytes, PlatformError>;
    /// Require OS authentication and return protected bytes.
    fn unwrap(&self, envelope: &SecretBytes) -> Result<SecretBytes, PlatformError>;
}
/// Foreground clipboard ownership; no readback or clipboard-manager handover.
pub trait Clipboard: Send + Sync {
    /// Consume protected text, retain ownership until expiry/cancel/replacement,
    /// and report seconds remaining without ever passing a value to progress.
    fn hold(
        &self,
        value: SecretBytes,
        timeout: Duration,
        cancel: Cancellation,
        progress: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError>;
}
/// OS boundary accepted by core, with no dependency back to core/frontends.
pub trait PlatformServices: Send + Sync {
    /// Current protection and backend status.
    fn status(&self) -> ProtectionStatus;
    /// Lock/sleep notifications.
    fn lifecycle(&self) -> &dyn Lifecycle;
    /// Clipboard ownership.
    fn clipboard(&self) -> &dyn Clipboard;
    /// Optional native input; framework input stays at the app boundary.
    fn secure_input(&self) -> &dyn SecureInput;
    /// Authenticated wrapping, or an explicitly unavailable backend.
    fn keystore(&self) -> &dyn Keystore;
}
/// A fail-closed input/keystore/clipboard adapter for unsupported mechanisms.
#[derive(Debug, Default)]
pub struct Unavailable;
impl SecureInput for Unavailable {
    fn read_secret(
        &self,
        _: InputPurpose,
        _: usize,
        _: Cancellation,
    ) -> Result<SecretBytes, PlatformError> {
        Err(PlatformError::Unavailable)
    }
}
impl Keystore for Unavailable {
    fn available(&self) -> bool {
        false
    }
    fn wrap(&self, _: &SecretBytes) -> Result<SecretBytes, PlatformError> {
        Err(PlatformError::Unavailable)
    }
    fn unwrap(&self, _: &SecretBytes) -> Result<SecretBytes, PlatformError> {
        Err(PlatformError::Unavailable)
    }
}
impl Clipboard for Unavailable {
    fn hold(
        &self,
        _: SecretBytes,
        _: Duration,
        _: Cancellation,
        _: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unavailable)
    }
}
impl Lifecycle for Unavailable {
    fn watch(&self, _: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
        Err(PlatformError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_keystore_never_offers_or_wraps_a_fallback_key() {
        let secret = SecretBytes::zeroed(32);
        assert!(!Unavailable.available());
        assert!(matches!(
            Unavailable.wrap(&secret),
            Err(PlatformError::Unavailable)
        ));
        assert!(matches!(
            Unavailable.unwrap(&secret),
            Err(PlatformError::Unavailable)
        ));
        assert!(matches!(
            Unavailable.read_secret(InputPurpose::MasterPassword, 1024, Arc::new(|| false)),
            Err(PlatformError::Unavailable)
        ));
    }
}
