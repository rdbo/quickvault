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
            let _ = services.keystore().invalidate();
        }
        checked
    }
    /// Remove the in-process policy, envelope and native hardware handle.
    pub fn disable_quick(&self) -> Result<(), CoreError> {
        self.invalidate_quick()
    }
    pub(crate) fn invalidate_quick(&self) -> Result<(), CoreError> {
        if let Some(services) = &self.services {
            services
                .keystore()
                .invalidate()
                .map_err(crate::platform::error)?;
        }
        Ok(())
    }
}
impl Core {
    /// True only while a validated backend retains a live trusted binding.
    pub fn quick_ready(&self) -> bool {
        self.quick_services()
            .is_ok_and(|s| s.keystore().binding().is_some())
    }
    /// True while the live binding names the vault at `path`, judged from
    /// its unverified public header (vault ID and key generation). Opening
    /// still verifies everything; this only decides what to offer.
    pub fn quick_ready_for(&self, path: &Path) -> bool {
        let Some(binding) = self
            .quick_services()
            .ok()
            .and_then(|s| s.keystore().binding())
        else {
            return false;
        };
        same_vault(path, binding)
    }
    /// Explicit hardware-authenticated open; never falls back to recovery/password.
    pub fn unlock_quick(
        &self,
        path: &Path,
        cancel: Option<&CancelToken>,
    ) -> Result<Session, CoreError> {
        self.platform_gate()?;
        let services = self.quick_services()?;
        let expected = services.keystore().binding().ok_or(CoreError::NotAllowed)?;
        // Another vault: refuse before prompting, keeping the enrollment.
        if !same_vault(path, expected) {
            return Err(CoreError::NotAllowed);
        }
        let token = cancel.cloned();
        let cancelled: qv_platform::Cancellation =
            Arc::new(move || token.as_ref().is_some_and(CancelToken::is_cancelled));
        // The keystore counts attempts and destroys its own state on
        // lockouts and lost keys; a dismissal keeps the enrollment.
        let phrase = services
            .keystore()
            .unlock_bound(expected, cancelled.clone())
            .map_err(crate::platform::error)?;
        let result = (|| {
            let (vault, status) = self.open(path, cancel, |f| {
                f.unlock_with_phrase(phrase.expose_secret(), &self.anchors)
            })?;
            match status {
                AnchorStatus::Missing => return Err(StoreError::NoAnchor.into()),
                AnchorStatus::Mismatch => return Err(StoreError::Rollback.into()),
                _ => {}
            }
            let session = Session::open(
                vault,
                self.time.clone(),
                status,
                self.snapshots.clone(),
                false,
                cancel,
            )?;
            if session.read(|ctx| binding(ctx))? != expected || cancelled() {
                return Err(CoreError::NotAllowed);
            }
            let session = self.bind_platform(session)?;
            session.run_automatic_snapshot(cancel);
            Ok(session)
        })();
        // The phrase did not open this vault as bound: the state is stale.
        if result
            .as_ref()
            .is_err_and(|e| !matches!(e, CoreError::Cancelled))
        {
            let _ = services.keystore().invalidate();
        }
        result
    }
}
fn same_vault(path: &Path, binding: QuickBinding) -> bool {
    qv_store::VaultFile::open(path).is_ok_and(|f| {
        let h = f.header();
        h.vault_id.0 == binding.vault && h.key_generation.0 == binding.generation
    })
}

#[cfg(test)]
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
        assert!(!core.quick_ready());
        s.enroll_quick(&pw(PASSWORD), QuickPolicy::Class3, None)
            .unwrap();
        assert!(core.quick_ready());
        s.lock();
        let quick = core.unlock_quick(&env.path, None).unwrap();
        assert!(quick.verify(None).unwrap().ok());
        quick
            .change_password(&pw("new master password for quick test"), None)
            .unwrap();
        assert!(!core.quick_ready());
        quick.lock();
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
        assert!(core.quick_ready());
        assert!(core.unlock_quick(&env.path, None).is_err());
        assert!(!core.quick_ready());
        let session = core.unlock(&env.path, &new, None).unwrap();
        session
            .enroll_quick(&new, QuickPolicy::Class3, None)
            .unwrap();
        session.lock();
        for item in std::fs::read_dir(&env.anchors).unwrap() {
            std::fs::remove_file(item.unwrap().path()).unwrap();
        }
        assert!(core.unlock_quick(&env.path, None).is_err());
        assert!(!core.quick_ready());
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
    fn dismissal_and_another_vault_keep_the_enrollment() {
        let env = Env::new();
        let _k = kdf();
        let backend = Arc::new(Dismissable(std::sync::atomic::AtomicBool::new(true)));
        let services = Arc::new(Platform(AndroidKeystore::new(backend.clone())));
        let core = env.core().with_linux_platform(services, true);
        let s = core.unlock(&env.path, &pw(PASSWORD), None).unwrap();
        s.enroll_quick(&pw(PASSWORD), QuickPolicy::Class3, None)
            .unwrap();
        s.lock();
        assert!(core.quick_ready_for(&env.path));
        for _ in 0..4 {
            assert!(matches!(
                core.unlock_quick(&env.path, None),
                Err(CoreError::Cancelled)
            ));
        }
        assert!(core.quick_ready_for(&env.path));
        // Another vault is refused before any prompt, keeping this one.
        let other = env.dir.path().join("other.qvault");
        core.create(&other, &pw(PASSWORD), "Other")
            .unwrap()
            .session
            .lock();
        assert!(!core.quick_ready_for(&other));
        assert!(!core.quick_ready_for(&env.dir.path().join("missing.qvault")));
        assert!(matches!(
            core.unlock_quick(&other, None),
            Err(CoreError::NotAllowed)
        ));
        assert!(core.quick_ready_for(&env.path));
        backend.0.store(false, Ordering::SeqCst);
        assert!(
            core.unlock_quick(&env.path, None)
                .unwrap()
                .verify(None)
                .unwrap()
                .ok()
        );
    }
}
