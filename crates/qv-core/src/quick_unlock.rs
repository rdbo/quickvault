// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bound Android quick unlock through existing authenticated store/session opens.
use crate::platform::{QuickBinding, QuickPolicy};
use crate::views::record;
use crate::{CancelToken, Core, CoreError, Session};
use qv_crypto::{MasterPassword, SecretBytes};
use qv_model::{RandomId, RecordKind};
use qv_store::{AnchorStatus, StoreError};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};

/// Which step refused the last quick unlock (plan 0063). No secret: it only
/// says why fingerprint unlock had to be turned off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuickFailure {
    /// The phone's key store refused or lost its key.
    Keystore,
    /// The released key did not open the vault.
    Open,
    /// The vault's rollback record (anchor) is missing, damaged or behind.
    Anchor,
    /// The vault, its key generation or its password keyslot changed since
    /// enrollment.
    Binding,
    /// The device's protection checks refused the session.
    Platform,
    /// No live enrollment: nothing to unlock with.
    NotEnrolled,
    /// The vault file's header names another vault or key generation.
    OtherVault,
    /// The vault file's header could not be read when checked.
    Unreadable,
    /// Reading the vault failed for a passing reason after the key was
    /// released: an I/O error, full storage or a busy vault file. The
    /// enrollment is kept (plan 0063 review finding 4).
    Storage,
}

/// Errors that say nothing about the released key: the enrollment stays.
fn transient(e: &CoreError) -> bool {
    matches!(
        e,
        CoreError::Store(StoreError::Io | StoreError::StorageCapacity | StoreError::Locked)
    )
}
fn binding(ctx: &crate::session::Ctx<'_>) -> Result<QuickBinding, CoreError> {
    let header = ctx.open.vault.header();
    let id = ctx.open.vault.manifest().keyslot_id();
    let version = record(&ctx.open.index, id, RecordKind::PasswordKeyslot)?.single_head()?;
    Ok(QuickBinding {
        vault: header.vault_id.0,
        generation: header.key_generation.0,
        password_version: version.to_bytes(),
    })
}
impl Session {
    /// Enroll after master-password reauthentication. No phrase reaches the UI.
    pub fn enroll_quick(
        &self,
        password: &MasterPassword,
        policy: QuickPolicy,
        cancel: Option<&CancelToken>,
    ) -> Result<(), CoreError> {
        let services = self.services.as_ref().ok_or(CoreError::NotAllowed)?;
        let token = cancel.cloned();
        let locking = self.locking.clone();
        let cancelled: qv_platform::Cancellation = Arc::new(move || {
            locking.load(Ordering::SeqCst) || token.as_ref().is_some_and(CancelToken::is_cancelled)
        });
        let (expected, bytes) = self.read(|ctx| {
            if ctx.open.read_only {
                return Err(CoreError::NotAllowed);
            }
            let phrase = ctx.open.vault.recovery_phrase(password)?;
            let bytes = SecretBytes::try_init(phrase.expose_secret().len(), |b| {
                b.copy_from_slice(phrase.expose_secret().as_bytes());
                Ok::<(), CoreError>(())
            })?;
            Ok((binding(ctx)?, bytes))
        })?;
        // Native deferral guards can run lifecycle callbacks when dropped.
        // Hold no session mutex across OS prompting or guard destruction.
        services
            .keystore()
            .enroll(expected, policy, &bytes, cancelled.clone())
            .map_err(crate::platform::error)?;
        let checked = self.read(|ctx| {
            if cancelled() || binding(ctx)? != expected {
                return Err(CoreError::Cancelled);
            }
            Ok(())
        });
        if checked.is_err() {
            let _ = services.keystore().invalidate(&expected.vault);
        }
        checked
    }
    /// True while this session's vault has a live enrollment for its key
    /// generation, as [`Core::quick_ready_for`] judges a closed vault. Each
    /// vault has its own (0002 §5.1, plan 0074).
    pub fn quick_enrolled(&self) -> bool {
        let Some(services) = self.services.as_ref() else {
            return false;
        };
        self.read(|ctx| binding(ctx)).is_ok_and(|b| {
            services
                .keystore()
                .binding(&b.vault)
                .is_some_and(|live| live.generation == b.generation)
        })
    }
    /// This vault's enrollment policy, while it has a live enrollment.
    pub fn quick_policy(&self) -> Option<QuickPolicy> {
        let services = self.services.as_ref()?;
        let vault = self
            .read(|ctx| Ok(ctx.open.vault.header().vault_id.0))
            .ok()?;
        services.keystore().policy(&vault)
    }
    /// Remove the in-process policy, envelope and native hardware handle.
    pub fn disable_quick(&self) -> Result<(), CoreError> {
        self.invalidate_quick()
    }
    /// Ends only this vault's enrollment (0002 §5.4, plan 0074).
    pub(crate) fn invalidate_quick(&self) -> Result<(), CoreError> {
        if let Some(services) = &self.services {
            let vault = self.read(|ctx| Ok(ctx.open.vault.header().vault_id.0))?;
            services
                .keystore()
                .invalidate(&vault)
                .map_err(crate::platform::error)?;
        }
        Ok(())
    }
}
impl Core {
    /// True while the vault at `path` has a live enrollment for its key
    /// generation, judged from its unverified public header (vault ID and
    /// key generation). Opening still verifies everything; this only
    /// decides what to offer.
    pub fn quick_ready_for(&self, path: &Path) -> bool {
        let Ok(services) = self.quick_services() else {
            return false;
        };
        header_ids(path).is_some_and(|(vault, generation)| {
            services
                .keystore()
                .binding(&vault)
                .is_some_and(|b| b.generation == generation)
        })
    }
    /// False when the last quick-unlock attempt found its vault without an
    /// enrollment or ended it; an attempt refused before naming a vault (a
    /// platform check, an unreadable header) ended nothing.
    pub fn quick_kept(&self) -> bool {
        let last = *self
            .quick_vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        last.is_none_or(|vault| {
            self.quick_services()
                .is_ok_and(|s| s.keystore().binding(&vault).is_some())
        })
    }
    /// Ends the enrollment of the vault at `path` when it is removed from
    /// this device's list (plan 0074), unless one of `others` (the files
    /// still listed) is the same vault, such as a copy.
    pub fn forget_quick<P: AsRef<Path>>(&self, path: &Path, others: &[P]) -> Result<(), CoreError> {
        let (Ok(services), Some((vault, _))) = (self.quick_services(), header_ids(path)) else {
            return Ok(());
        };
        if others
            .iter()
            .any(|p| header_ids(p.as_ref()).is_some_and(|(v, _)| v == vault))
        {
            return Ok(());
        }
        services
            .keystore()
            .invalidate(&vault)
            .map_err(crate::platform::error)
    }
    /// Why the last quick unlock failed, if it did.
    pub fn quick_failure(&self) -> Option<QuickFailure> {
        *self
            .quick_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn note_quick(&self, failure: Option<QuickFailure>) {
        *self
            .quick_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = failure;
    }
    /// Explicit hardware-authenticated open; never falls back to recovery/password.
    pub fn unlock_quick(
        &self,
        path: &Path,
        cancel: Option<&CancelToken>,
    ) -> Result<Session, CoreError> {
        *self
            .quick_vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        // Steps before the prompt record why they refused too (plan 0063).
        let early = |failure: QuickFailure, e: CoreError| {
            self.note_quick(Some(failure));
            e
        };
        self.platform_gate()
            .map_err(|e| early(QuickFailure::Platform, e))?;
        let services = self
            .quick_services()
            .map_err(|e| early(QuickFailure::Platform, e))?;
        // The header names the vault whose enrollment applies (plan 0074).
        let (vault, generation) = header_ids(path)
            .ok_or_else(|| early(QuickFailure::Unreadable, CoreError::NotAllowed))?;
        *self
            .quick_vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(vault);
        let expected = services
            .keystore()
            .binding(&vault)
            .ok_or_else(|| early(QuickFailure::NotEnrolled, CoreError::NotAllowed))?;
        // Another key generation (an older copy of the vault): refuse before
        // prompting, keeping the enrollment.
        if generation != expected.generation {
            return Err(early(QuickFailure::OtherVault, CoreError::NotAllowed));
        }
        let token = cancel.cloned();
        let cancelled: qv_platform::Cancellation =
            Arc::new(move || token.as_ref().is_some_and(CancelToken::is_cancelled));
        // The keystore counts attempts and destroys its own state on
        // lockouts and lost keys; a dismissal keeps the enrollment.
        self.note_quick(None);
        let phrase = match services
            .keystore()
            .unlock_bound(expected, cancelled.clone())
        {
            Ok(phrase) => phrase,
            Err(e) => {
                let e = crate::platform::error(e);
                if !matches!(e, CoreError::Cancelled) {
                    self.note_quick(Some(QuickFailure::Keystore));
                }
                return Err(e);
            }
        };
        let mut step = QuickFailure::Open;
        let result = (|| {
            let (vault, status, index) = self.open(path, cancel, |f, b| {
                f.unlock_with_phrase_into(phrase.expose_secret(), &self.anchors, b)
            })?;
            step = QuickFailure::Anchor;
            match status {
                AnchorStatus::Missing => return Err(StoreError::NoAnchor.into()),
                AnchorStatus::Damaged => return Err(StoreError::DamagedAnchor.into()),
                AnchorStatus::Mismatch => return Err(StoreError::Rollback.into()),
                _ => {}
            }
            step = QuickFailure::Open;
            let session = Session::open_built(
                vault,
                index,
                self.time.clone(),
                status,
                self.snapshots.clone(),
                false,
            )?;
            step = QuickFailure::Binding;
            if cancelled() {
                return Err(CoreError::Cancelled);
            }
            if session.read(|ctx| binding(ctx))? != expected {
                return Err(CoreError::NotAllowed);
            }
            step = QuickFailure::Platform;
            let session = self.bind_platform(session)?;
            session.run_automatic_snapshot(cancel);
            Ok(session)
        })();
        match result {
            // A store failure after cancellation is the cancellation.
            Err(CoreError::Store(StoreError::Io)) if cancelled() => Err(CoreError::Cancelled),
            Err(CoreError::Cancelled) => Err(CoreError::Cancelled),
            // A passing storage failure says nothing about the key.
            Err(e) if transient(&e) => {
                self.note_quick(Some(QuickFailure::Storage));
                Err(e)
            }
            // The phrase did not open this vault as bound: the state is stale.
            Err(e) => {
                self.note_quick(Some(step));
                let _ = services.keystore().invalidate(&expected.vault);
                Err(e)
            }
            Ok(session) => Ok(session),
        }
    }
}
/// The vault ID and key generation in the file's unverified public header.
fn header_ids(path: &Path) -> Option<([u8; 16], u32)> {
    let f = qv_store::VaultFile::open(path).ok()?;
    let h = f.header();
    Some((h.vault_id.0, h.key_generation.0))
}

/// Synthetic backend reuse for the large-vault lifecycle fixture. It copies
/// protected data and provides no evidence about real biometric hardware.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn synthetic_services() -> Arc<dyn qv_platform::PlatformServices> {
    tests::services()
}

// The synthetic platform has no lifecycle monitor, which only Linux's
// optional-monitoring policy (`with_linux_platform`) accepts.
#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::testutil::{Env, PASSWORD, kdf, pw};
    use qv_platform::PlatformServices;
    use qv_platform::quick_unlock::{AndroidKeystore, AndroidKeystoreBackend};
    use qv_platform::{
        Clipboard, Evidence, Keystore, Lifecycle, PlatformError, ProtectionStatus, SecureInput,
        Unavailable,
    };
    use std::sync::atomic::Ordering;
    struct Native;
    impl AndroidKeystoreBackend for Native {
        fn validated(&self) -> bool {
            true
        }
        fn seal(
            &self,
            _: QuickBinding,
            _: QuickPolicy,
            s: &SecretBytes,
            _: qv_platform::Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            copy(s)
        }
        fn open(
            &self,
            _: QuickBinding,
            _: QuickPolicy,
            s: &SecretBytes,
            _: qv_platform::Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            copy(s)
        }
        fn delete(&self, _: &SecretBytes) -> Result<(), PlatformError> {
            Ok(())
        }
    }
    fn copy(s: &SecretBytes) -> Result<SecretBytes, PlatformError> {
        SecretBytes::try_init(s.len(), |b| {
            b.copy_from_slice(s.expose_secret());
            Ok(())
        })
    }
    struct Platform(AndroidKeystore);
    impl PlatformServices for Platform {
        fn status(&self) -> ProtectionStatus {
            ProtectionStatus {
                storage: Evidence::Verified,
                swap: Evidence::Verified,
                hibernation: Evidence::Verified,
                lifecycle: false,
                clipboard: false,
                quick_unlock: true,
            }
        }
        fn lifecycle(&self) -> &dyn Lifecycle {
            &Unavailable
        }
        fn clipboard(&self) -> &dyn Clipboard {
            &Unavailable
        }
        fn secure_input(&self) -> &dyn SecureInput {
            &Unavailable
        }
        fn keystore(&self) -> &dyn Keystore {
            &self.0
        }
    }
    #[cfg(target_os = "linux")]
    pub(super) fn services() -> Arc<dyn PlatformServices> {
        Arc::new(Platform(AndroidKeystore::new(Arc::new(Native))))
    }
    // 0012 §1: Hardware assumptions
    #[test]
    fn quick_core_reauth_round_trip_and_password_change_invalidates_handle() {
        let env = Env::new();
        let _k = kdf();
        let services = Arc::new(Platform(AndroidKeystore::new(Arc::new(Native))));
        let core = env.core().with_linux_platform(services, true);
        let s = core.unlock(&env.path, &pw(PASSWORD), None).unwrap();
        assert!(
            s.enroll_quick(&pw("wrong"), QuickPolicy::Class3, None)
                .is_err()
        );
        // An open vault's file is held: its session answers for it.
        assert!(!s.quick_enrolled());
        s.enroll_quick(&pw(PASSWORD), QuickPolicy::Class3, None)
            .unwrap();
        assert!(s.quick_enrolled());
        s.lock();
        assert!(core.quick_ready_for(&env.path));
        let quick = core.unlock_quick(&env.path, None).unwrap();
        assert!(quick.verify(None).unwrap().ok());
        quick
            .change_password(&pw("new master password for quick test"), None)
            .unwrap();
        assert!(!quick.quick_enrolled());
        quick.lock();
        assert!(!core.quick_ready_for(&env.path));
        assert!(core.unlock_quick(&env.path, None).is_err());
        let new = pw("new master password for quick test");
        let session = core.unlock(&env.path, &new, None).unwrap();
        session
            .enroll_quick(&new, QuickPolicy::Class3, None)
            .unwrap();
        session.lock();
        // A password-slot change received outside this injected service must
        // still fail the authenticated binding check, even with unchanged VK.
        let outside = env.core().unlock(&env.path, &new, None).unwrap();
        outside.change_password(&new, None).unwrap();
        outside.lock();
        assert!(core.quick_ready_for(&env.path));
        assert!(core.unlock_quick(&env.path, None).is_err());
        assert_eq!(core.quick_failure(), Some(QuickFailure::Binding));
        assert!(!core.quick_ready_for(&env.path));
        let session = core.unlock(&env.path, &new, None).unwrap();
        session
            .enroll_quick(&new, QuickPolicy::Class3, None)
            .unwrap();
        session.lock();
        for item in std::fs::read_dir(&env.anchors).unwrap() {
            std::fs::remove_file(item.unwrap().path()).unwrap();
        }
        assert!(core.unlock_quick(&env.path, None).is_err());
        assert_eq!(core.quick_failure(), Some(QuickFailure::Anchor));
        assert!(!core.quick_ready_for(&env.path));
    }

    /// Opens like `Native`, or reports a dismissal when `cancel` is set.
    struct Dismissable(std::sync::atomic::AtomicBool);
    impl AndroidKeystoreBackend for Dismissable {
        fn validated(&self) -> bool {
            true
        }
        fn seal(
            &self,
            b: QuickBinding,
            p: QuickPolicy,
            s: &SecretBytes,
            c: qv_platform::Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            Native.seal(b, p, s, c)
        }
        fn open(
            &self,
            b: QuickBinding,
            p: QuickPolicy,
            s: &SecretBytes,
            c: qv_platform::Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            if self.0.load(Ordering::SeqCst) {
                return Err(PlatformError::Cancelled);
            }
            Native.open(b, p, s, c)
        }
        fn delete(&self, _: &SecretBytes) -> Result<(), PlatformError> {
            Ok(())
        }
    }
    // 0012 §1: Hardware assumptions
    #[test]
    fn dismissal_keeps_the_enrollment_and_each_vault_has_its_own() {
        let env = Env::new();
        let _k = kdf();
        let backend = Arc::new(Dismissable(std::sync::atomic::AtomicBool::new(true)));
        let services = Arc::new(Platform(AndroidKeystore::new(backend.clone())));
        let core = env.core().with_linux_platform(services, true);
        let s = core.unlock(&env.path, &pw(PASSWORD), None).unwrap();
        assert!(!s.quick_enrolled());
        s.enroll_quick(&pw(PASSWORD), QuickPolicy::Class3, None)
            .unwrap();
        assert!(s.quick_enrolled());
        s.lock();
        assert!(!s.quick_enrolled(), "a locked session names no vault");
        assert!(core.quick_ready_for(&env.path));
        for _ in 0..4 {
            assert!(matches!(
                core.unlock_quick(&env.path, None),
                Err(CoreError::Cancelled)
            ));
        }
        assert!(core.quick_ready_for(&env.path));
        // Another vault has no enrollment of its own yet: refused before any
        // prompt, keeping the first vault's.
        let other = env.dir.path().join("other.qvault");
        let open = core.create(&other, &pw(PASSWORD), "Other").unwrap().session;
        assert!(core.quick_ready_for(&env.path));
        assert!(!open.quick_enrolled());
        assert_eq!(open.quick_policy(), None);
        open.lock();
        assert!(!core.quick_ready_for(&other));
        let missing = env.dir.path().join("missing.qvault");
        assert!(!core.quick_ready_for(&missing));
        assert!(matches!(
            core.unlock_quick(&other, None),
            Err(CoreError::NotAllowed)
        ));
        assert_eq!(core.quick_failure(), Some(QuickFailure::NotEnrolled));
        assert!(!core.quick_kept());
        // An unreadable file names no vault and ends nothing.
        assert!(core.unlock_quick(&missing, None).is_err());
        assert_eq!(core.quick_failure(), Some(QuickFailure::Unreadable));
        assert!(core.quick_kept());
        assert!(core.quick_ready_for(&env.path));
        // Each vault gets its own enrollment; the first keeps its (plan 0074).
        let open = core.unlock(&other, &pw(PASSWORD), None).unwrap();
        open.enroll_quick(&pw(PASSWORD), QuickPolicy::DeviceCredential, None)
            .unwrap();
        assert!(open.quick_enrolled());
        assert_eq!(open.quick_policy(), Some(QuickPolicy::DeviceCredential));
        open.lock();
        assert!(core.quick_ready_for(&other) && core.quick_ready_for(&env.path));
        backend.0.store(false, Ordering::SeqCst);
        for path in [&env.path, &other] {
            let s = core.unlock_quick(path, None).unwrap();
            assert!(s.verify(None).unwrap().ok());
            s.lock();
        }
        // Turning one off, or forgetting it, leaves the other.
        let s = core.unlock_quick(&other, None).unwrap();
        s.disable_quick().unwrap();
        s.lock();
        assert!(!core.quick_ready_for(&other) && core.quick_ready_for(&env.path));
        let none: [&Path; 0] = [];
        core.forget_quick(&missing, &none).unwrap();
        assert!(core.quick_ready_for(&env.path));
        // A listed copy of the same vault keeps it; removing the last ends it.
        let copy = env.dir.path().join("copy.qvault");
        std::fs::copy(&env.path, &copy).unwrap();
        core.forget_quick(&env.path, &[&copy, &other]).unwrap();
        assert!(core.quick_ready_for(&env.path));
        core.forget_quick(&env.path, &[&other]).unwrap();
        assert!(!core.quick_ready_for(&env.path) && !core.quick_ready_for(&copy));
    }

    /// What [`Scripted`] does when the key is released.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Release {
        /// Return the sealed phrase.
        Phrase,
        /// Return bytes that are no phrase of this vault.
        Wrong,
        /// Hold the vault file open elsewhere, then return the phrase.
        Busy,
        /// Cancel the caller's token, then return the phrase.
        Cancel,
    }

    /// A synthetic backend whose release step is chosen by the test.
    struct Scripted {
        release: std::sync::Mutex<Release>,
        path: std::path::PathBuf,
        held: std::sync::Mutex<Option<qv_store::VaultFile>>,
        token: CancelToken,
    }
    impl Scripted {
        fn set(&self, r: Release) {
            *self.release.lock().unwrap() = r;
        }
    }
    impl AndroidKeystoreBackend for Scripted {
        fn validated(&self) -> bool {
            true
        }
        fn seal(
            &self,
            b: QuickBinding,
            p: QuickPolicy,
            s: &SecretBytes,
            c: qv_platform::Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            Native.seal(b, p, s, c)
        }
        fn open(
            &self,
            b: QuickBinding,
            p: QuickPolicy,
            s: &SecretBytes,
            c: qv_platform::Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            match *self.release.lock().unwrap() {
                Release::Phrase => {}
                Release::Wrong => {
                    return SecretBytes::try_init(23, |b| {
                        b.copy_from_slice(b"not this vault's phrase");
                        Ok(())
                    });
                }
                Release::Busy => {
                    *self.held.lock().unwrap() =
                        Some(qv_store::VaultFile::open(&self.path).unwrap());
                }
                Release::Cancel => self.token.cancel(),
            }
            Native.open(b, p, s, c)
        }
        fn delete(&self, _: &SecretBytes) -> Result<(), PlatformError> {
            Ok(())
        }
    }

    /// Plan 0063 review finding 4: each refusing step is named, and only
    /// failures that say the key is stale end the enrollment.
    // 0012 §1: Hardware assumptions
    #[test]
    fn quick_failure_names_the_refusing_step() {
        let env = Env::new();
        let _k = kdf();
        let backend = Arc::new(Scripted {
            release: std::sync::Mutex::new(Release::Phrase),
            path: env.path.clone(),
            held: std::sync::Mutex::new(None),
            token: CancelToken::new(),
        });
        let services = Arc::new(Platform(AndroidKeystore::new(backend.clone())));
        let core = env.core().with_linux_platform(services, true);

        // Nothing enrolled yet.
        assert!(matches!(
            core.unlock_quick(&env.path, None),
            Err(CoreError::NotAllowed)
        ));
        assert_eq!(core.quick_failure(), Some(QuickFailure::NotEnrolled));
        let enroll = || {
            let s = core.unlock(&env.path, &pw(PASSWORD), None).unwrap();
            s.enroll_quick(&pw(PASSWORD), QuickPolicy::Class3, None)
                .unwrap();
            s.lock();
        };
        enroll();

        // A busy vault file is a passing storage failure: kept.
        backend.set(Release::Busy);
        assert!(matches!(
            core.unlock_quick(&env.path, None),
            Err(CoreError::Store(StoreError::Locked))
        ));
        assert_eq!(core.quick_failure(), Some(QuickFailure::Storage));
        drop(backend.held.lock().unwrap().take());
        assert!(core.quick_ready_for(&env.path));
        assert!(core.quick_kept());

        // A cancellation after the release is neither a failure nor stale.
        backend.set(Release::Cancel);
        assert!(matches!(
            core.unlock_quick(&env.path, Some(&backend.token)),
            Err(CoreError::Cancelled)
        ));
        assert_eq!(core.quick_failure(), None);
        assert!(core.quick_ready_for(&env.path));

        // The released key does not open the vault: stale, ended.
        backend.set(Release::Wrong);
        assert!(core.unlock_quick(&env.path, None).is_err());
        assert_eq!(core.quick_failure(), Some(QuickFailure::Open));
        assert!(!core.quick_ready_for(&env.path));
        assert!(!core.quick_kept());

        // Enrolled again, it works and clears the reason.
        backend.set(Release::Phrase);
        enroll();
        assert!(
            core.unlock_quick(&env.path, None)
                .unwrap()
                .verify(None)
                .unwrap()
                .ok()
        );
        assert_eq!(core.quick_failure(), None);
    }

    #[test]
    fn quick_transient_errors_are_storage_only() {
        for e in [
            StoreError::Io,
            StoreError::StorageCapacity,
            StoreError::Locked,
        ] {
            assert!(transient(&CoreError::Store(e)));
        }
        for e in [
            CoreError::Store(StoreError::WrongPhrase),
            CoreError::Store(StoreError::Integrity),
            CoreError::Store(StoreError::Rollback),
            CoreError::NotAllowed,
            CoreError::Cancelled,
        ] {
            assert!(!transient(&e));
        }
    }
}
