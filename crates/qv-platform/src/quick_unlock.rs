// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device-local, process-lifetime quick-unlock policy (0002 §5).
//! A process restart deliberately loses trusted policy and requires the password.
use crate::{Cancellation, Keystore, PlatformError};
use qv_crypto::SecretBytes;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum lifetime since password-authenticated enrollment, never extended by use.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Maximum canonical phrase size; no arbitrary application payloads.
pub const MAX_PLAINTEXT: usize = 1024;
/// Maximum versioned native envelope, before any copy/allocation.
pub const MAX_ENVELOPE: usize = 1536;
/// Authenticated vault and current password-slot identity, bound as AAD.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QuickBinding {
    /// Vault ID.
    pub vault: [u8; 16],
    /// Nonzero key generation.
    pub generation: u32,
    /// Current authenticated password-keyslot version.
    pub password_version: [u8; 16],
}
impl QuickBinding {
    /// Fixed-width encoding appended to the native AAD domain label.
    pub fn encode(self) -> [u8; 36] {
        let mut out = [0; 36];
        out[..16].copy_from_slice(&self.vault);
        out[16..20].copy_from_slice(&self.generation.to_be_bytes());
        out[20..].copy_from_slice(&self.password_version);
        out
    }
}
/// Explicitly distinct policies; neither is a fallback for the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QuickPolicy {
    /// Class 3 biometrics, invalidated by new enrollment.
    Class3 = 1,
    /// Device PIN/pattern/password becomes a vault credential: reduced protection.
    DeviceCredential = 2,
}
/// Native operation boundary; only a validated backend may be advertised.
pub trait AndroidKeystoreBackend: Send + Sync {
    /// Recorded device validation AND current native capability checks.
    fn validated(&self) -> bool;
    /// Hardware AES-GCM with provider nonce and per-operation OS authentication.
    fn seal(
        &self,
        binding: QuickBinding,
        policy: QuickPolicy,
        secret: &SecretBytes,
        cancel: Cancellation,
    ) -> Result<SecretBytes, PlatformError>;
    /// Authenticate and decrypt the exact bound envelope; never switch policy.
    fn open(
        &self,
        binding: QuickBinding,
        policy: QuickPolicy,
        envelope: &SecretBytes,
        cancel: Cancellation,
    ) -> Result<SecretBytes, PlatformError>;
    /// Destroy the exact handle described by this envelope.
    fn delete(&self, envelope: &SecretBytes) -> Result<(), PlatformError>;
}
struct Slot {
    binding: QuickBinding,
    policy: QuickPolicy,
    envelope: SecretBytes,
    since: Instant,
    failures: u8,
}
/// Serialized trusted policy. No persistence, export, Debug or plaintext cache.
pub struct AndroidKeystore {
    backend: Arc<dyn AndroidKeystoreBackend>,
    slot: Mutex<Option<Slot>>,
}
impl AndroidKeystore {
    /// Inject the native adapter; availability still requires device validation.
    pub fn new(backend: Arc<dyn AndroidKeystoreBackend>) -> Self {
        Self {
            backend,
            slot: Mutex::new(None),
        }
    }
    fn destroy(&self, slot: &mut Option<Slot>) -> Result<(), PlatformError> {
        if let Some(old) = slot.take() {
            self.backend.delete(&old.envelope)?;
        }
        Ok(())
    }
}
impl Drop for AndroidKeystore {
    fn drop(&mut self) {
        let old = self
            .slot
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(old) = old {
            let _ = self.backend.delete(&old.envelope);
        }
    }
}
impl Keystore for AndroidKeystore {
    fn available(&self) -> bool {
        self.backend.validated()
    }
    fn wrap(&self, _: &SecretBytes) -> Result<SecretBytes, PlatformError> {
        Err(PlatformError::Unavailable)
    }
    fn unwrap(&self, _: &SecretBytes) -> Result<SecretBytes, PlatformError> {
        Err(PlatformError::Unavailable)
    }
    fn binding(&self) -> Option<QuickBinding> {
        let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        if !self.available()
            || slot
                .as_ref()
                .is_some_and(|s| s.since.elapsed() >= MAX_AGE || s.failures >= 3)
        {
            let _ = self.destroy(&mut slot);
            return None;
        }
        slot.as_ref().map(|s| s.binding)
    }
    fn enroll(
        &self,
        binding: QuickBinding,
        policy: QuickPolicy,
        secret: &SecretBytes,
        cancel: Cancellation,
    ) -> Result<(), PlatformError> {
        let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        self.destroy(&mut slot)?;
        if !self.available() {
            return Err(PlatformError::Unavailable);
        }
        if binding.generation == 0 || secret.is_empty() || secret.len() > MAX_PLAINTEXT {
            return Err(PlatformError::InvalidInput);
        }
        if cancel() {
            return Err(PlatformError::Cancelled);
        }
        let envelope = self.backend.seal(binding, policy, secret, cancel.clone())?;
        if envelope.is_empty() || envelope.len() > MAX_ENVELOPE || cancel() {
            self.backend.delete(&envelope)?;
            return Err(PlatformError::Cancelled);
        }
        *slot = Some(Slot {
            binding,
            policy,
            envelope,
            since: Instant::now(),
            failures: 0,
        });
        Ok(())
    }
    fn unlock_bound(
        &self,
        binding: QuickBinding,
        cancel: Cancellation,
    ) -> Result<SecretBytes, PlatformError> {
        let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        if !self.available()
            || slot.as_ref().is_none_or(|s| {
                s.binding != binding || s.since.elapsed() >= MAX_AGE || s.failures >= 3
            })
        {
            self.destroy(&mut slot)?;
            return Err(PlatformError::Unavailable);
        }
        let Some(current) = slot.as_mut() else {
            return Err(PlatformError::Unavailable);
        };
        current.failures += 1; // Reserve the attempt before native authentication.
        let result = if cancel() {
            Err(PlatformError::Cancelled)
        } else {
            self.backend
                .open(binding, current.policy, &current.envelope, cancel.clone())
        };
        match result {
            Ok(plain) if !plain.is_empty() && plain.len() <= MAX_PLAINTEXT && !cancel() => {
                current.failures -= 1;
                Ok(plain)
            }
            result => {
                if current.failures >= 3 || matches!(result, Err(PlatformError::Unavailable)) {
                    self.destroy(&mut slot)?;
                }
                match result {
                    Err(e) => Err(e),
                    Ok(_) => Err(PlatformError::Cancelled),
                }
            }
        }
    }
    fn invalidate(&self) -> Result<(), PlatformError> {
        self.destroy(&mut self.slot.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Backend {
        fail: AtomicBool,
        unavailable: AtomicBool,
        deletes: AtomicUsize,
    }
    fn bytes() -> SecretBytes {
        SecretBytes::try_init(4, |b| {
            b.copy_from_slice(b"test");
            Ok::<(), ()>(())
        })
        .unwrap()
    }
    impl AndroidKeystoreBackend for Backend {
        fn validated(&self) -> bool {
            true
        }
        fn seal(
            &self,
            _: QuickBinding,
            _: QuickPolicy,
            _: &SecretBytes,
            _: Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            Ok(bytes())
        }
        fn open(
            &self,
            _: QuickBinding,
            _: QuickPolicy,
            _: &SecretBytes,
            _: Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            if self.unavailable.load(Ordering::SeqCst) {
                Err(PlatformError::Unavailable)
            } else if self.fail.load(Ordering::SeqCst) {
                Err(PlatformError::Io)
            } else {
                Ok(bytes())
            }
        }
        fn delete(&self, _: &SecretBytes) -> Result<(), PlatformError> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    fn binding() -> QuickBinding {
        QuickBinding {
            vault: [1; 16],
            generation: 1,
            password_version: [2; 16],
        }
    }
    fn cancel() -> Cancellation {
        Arc::new(|| false)
    }
    // 0012 §1: Hardware assumptions
    #[test]
    fn quick_policy_requires_state_binding_age_and_only_three_failed_attempts() {
        let backend = Arc::new(Backend {
            fail: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            deletes: AtomicUsize::new(0),
        });
        let os = AndroidKeystore::new(backend.clone());
        assert!(os.unlock_bound(binding(), cancel()).is_err());
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        assert_eq!(
            os.unlock_bound(binding(), cancel())
                .unwrap()
                .expose_secret(),
            b"test"
        );
        backend.fail.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            assert!(os.unlock_bound(binding(), cancel()).is_err());
        }
        assert!(os.binding().is_none());
        assert_eq!(backend.deletes.load(Ordering::SeqCst), 1);
        backend.fail.store(false, Ordering::SeqCst);
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        os.slot.lock().unwrap().as_mut().unwrap().since = Instant::now() - MAX_AGE;
        assert!(os.binding().is_none());
        os.enroll(binding(), QuickPolicy::DeviceCredential, &bytes(), cancel())
            .unwrap();
        let mut wrong = binding();
        wrong.generation += 1;
        assert!(os.unlock_bound(wrong, cancel()).is_err());
        assert!(os.binding().is_none());
        assert!(
            os.enroll(binding(), QuickPolicy::Class3, &bytes(), Arc::new(|| true))
                .is_err()
        );
        assert!(os.binding().is_none());
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        os.invalidate().unwrap();
        assert!(os.binding().is_none());
        assert!(os.wrap(&bytes()).is_err());
        assert!(os.unwrap(&bytes()).is_err());
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn permanently_unavailable_native_key_is_destroyed_on_first_attempt() {
        let backend = Arc::new(Backend {
            fail: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            deletes: AtomicUsize::new(0),
        });
        let os = AndroidKeystore::new(backend.clone());
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        backend.unavailable.store(true, Ordering::SeqCst);
        assert!(matches!(
            os.unlock_bound(binding(), cancel()),
            Err(PlatformError::Unavailable)
        ));
        assert!(os.binding().is_none());
        assert_eq!(backend.deletes.load(Ordering::SeqCst), 1);
    }
}
