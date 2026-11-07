// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device-local quick-unlock policy (0002 §5). The policy survives an app
//! restart only in the backend's private, non-backed-up state file and only
//! for the same boot (0002 §5.4, plan 0045); without a boot stamp it lasts
//! for this process alone.
use crate::{Cancellation, Keystore, PlatformError};
use qv_crypto::SecretBytes;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Maximum lifetime since password-authenticated enrollment, never extended by use.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Maximum canonical phrase size; no arbitrary application payloads.
pub const MAX_PLAINTEXT: usize = 1024;
/// Maximum versioned native envelope, before any copy/allocation.
pub const MAX_ENVELOPE: usize = 1536;
/// Smallest native envelope: 35-byte header, 12-byte nonce, 16-byte tag.
pub const MIN_ENVELOPE: usize = 63;
/// Failed attempts that end the enrollment.
pub const MAX_FAILURES: u8 = 3;
const MAGIC: &[u8; 4] = b"QVQU";
const STATE_VERSION: u8 = 1;
const STATE_HEADER: usize = 4 + 1 + 1 + 4 + 8 + 1 + 36 + 2;
/// Largest persisted state record read or written.
pub const STATE_MAX: usize = 1600;
const _: () = assert!(STATE_HEADER + MAX_ENVELOPE <= STATE_MAX);
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
    fn decode(b: &[u8]) -> Option<Self> {
        let vault: [u8; 16] = b.get(..16)?.try_into().ok()?;
        let generation = u32::from_be_bytes(b.get(16..20)?.try_into().ok()?);
        let password_version: [u8; 16] = b.get(20..36)?.try_into().ok()?;
        (generation != 0 && b.len() == 36).then_some(Self {
            vault,
            generation,
            password_version,
        })
    }
}
/// Explicitly distinct policies; neither is a fallback for the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QuickPolicy {
    /// Class 3 biometrics, invalidated by new enrollment.
    Class3 = 1,
    /// Device PIN/pattern/password becomes a vault credential: lower protection.
    DeviceCredential = 2,
}
impl QuickPolicy {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Class3),
            2 => Some(Self::DeviceCredential),
            _ => None,
        }
    }
}
/// The current boot and the time since it started (Android: the boot count
/// and `SystemClock.elapsedRealtime`, which never goes back within a boot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootStamp {
    /// Boots since the device was set up.
    pub count: u32,
    /// Milliseconds since this boot.
    pub uptime_ms: u64,
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
    /// `Cancelled` is a dismissal (not a failed attempt); `Denied` a lockout.
    fn open(
        &self,
        binding: QuickBinding,
        policy: QuickPolicy,
        envelope: &SecretBytes,
        cancel: Cancellation,
    ) -> Result<SecretBytes, PlatformError>;
    /// Destroy the exact handle described by this envelope.
    fn delete(&self, envelope: &SecretBytes) -> Result<(), PlatformError>;
    /// The current boot; `None` keeps the policy for this process only.
    fn boot(&self) -> Option<BootStamp> {
        None
    }
    /// The persisted state record, at most [`STATE_MAX`] bytes.
    fn load(&self) -> Option<Vec<u8>> {
        None
    }
    /// Replace the persisted state record atomically.
    fn save(&self, _state: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unavailable)
    }
    /// Remove the persisted state record.
    fn clear(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    /// Keep only this envelope's handle (with its enrollment uptime) and
    /// destroy every other QuickVault handle; `None` destroys them all.
    fn retain(&self, _keep: Option<(&SecretBytes, u64)>) {}
}
struct Slot {
    binding: QuickBinding,
    policy: QuickPolicy,
    envelope: SecretBytes,
    /// Age before this process: nonzero only for a slot loaded from state.
    offset: Duration,
    since: Instant,
    /// The boot stamp at enrollment; `None` without persistence.
    enrolled: Option<BootStamp>,
    failures: u8,
    serial: u64,
}
impl Slot {
    fn expired(&self) -> bool {
        self.offset.saturating_add(self.since.elapsed()) >= MAX_AGE || self.failures >= MAX_FAILURES
    }
    /// The persisted record; no plaintext secret (the envelope is
    /// hardware-key ciphertext).
    fn encode(&self, enrolled: BootStamp) -> Option<Vec<u8>> {
        let len = u16::try_from(self.envelope.len()).ok()?;
        let mut out = Vec::with_capacity(STATE_HEADER + self.envelope.len());
        out.extend_from_slice(MAGIC);
        out.push(STATE_VERSION);
        out.push(self.policy as u8);
        out.extend_from_slice(&enrolled.count.to_be_bytes());
        out.extend_from_slice(&enrolled.uptime_ms.to_be_bytes());
        out.push(self.failures);
        out.extend_from_slice(&self.binding.encode());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(self.envelope.expose_secret());
        Some(out)
    }
}
/// A decoded state record, before the boot and age checks.
struct Stored {
    policy: QuickPolicy,
    enrolled: BootStamp,
    failures: u8,
    binding: QuickBinding,
    envelope: SecretBytes,
}
fn decode(b: &[u8]) -> Option<Stored> {
    if b.len() < STATE_HEADER || b.len() > STATE_MAX || b.get(..4)? != MAGIC {
        return None;
    }
    if b[4] != STATE_VERSION {
        return None;
    }
    let policy = QuickPolicy::from_u8(b[5])?;
    let count = u32::from_be_bytes(b.get(6..10)?.try_into().ok()?);
    let uptime_ms = u64::from_be_bytes(b.get(10..18)?.try_into().ok()?);
    let failures = b[18];
    let binding = QuickBinding::decode(b.get(19..55)?)?;
    let len = usize::from(u16::from_be_bytes(b.get(55..57)?.try_into().ok()?));
    if !(MIN_ENVELOPE..=MAX_ENVELOPE).contains(&len)
        || b.len() != STATE_HEADER + len
        || failures >= MAX_FAILURES
    {
        return None;
    }
    let envelope = SecretBytes::try_init(len, |out| {
        out.copy_from_slice(&b[STATE_HEADER..]);
        Ok::<(), PlatformError>(())
    })
    .ok()?;
    Some(Stored {
        policy,
        enrolled: BootStamp { count, uptime_ms },
        failures,
        binding,
        envelope,
    })
}
/// Serialized trusted policy. No export, Debug or plaintext cache.
pub struct AndroidKeystore {
    backend: Arc<dyn AndroidKeystoreBackend>,
    slot: Mutex<Option<Slot>>,
    loaded: std::sync::Once,
    serial: std::sync::atomic::AtomicU64,
}
impl AndroidKeystore {
    /// Inject the native adapter; availability still requires device validation.
    pub fn new(backend: Arc<dyn AndroidKeystoreBackend>) -> Self {
        Self {
            backend,
            slot: Mutex::new(None),
            loaded: std::sync::Once::new(),
            serial: std::sync::atomic::AtomicU64::new(0),
        }
    }
    fn next_serial(&self) -> u64 {
        self.serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .wrapping_add(1)
    }
    /// The policy mutex, after the once-only restore of persisted state.
    fn lock(&self) -> MutexGuard<'_, Option<Slot>> {
        self.loaded.call_once(|| {
            let restored = self.restore();
            let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
            if slot.is_none() {
                *slot = restored;
            }
        });
        self.slot.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Restore a slot persisted during this boot; anything else clears the
    /// state and destroys every QuickVault handle.
    /// Without a boot stamp nothing is persisted or touched.
    fn restore(&self) -> Option<Slot> {
        let now = self.backend.boot()?;
        let bytes = self.backend.load();
        let restored = (|| {
            let stored = decode(bytes.as_deref()?)?;
            let age = now.uptime_ms.checked_sub(stored.enrolled.uptime_ms)?;
            let offset = Duration::from_millis(age);
            if !self.backend.validated() || now.count != stored.enrolled.count || offset >= MAX_AGE
            {
                return None;
            }
            self.backend
                .retain(Some((&stored.envelope, stored.enrolled.uptime_ms)));
            Some(Slot {
                binding: stored.binding,
                policy: stored.policy,
                envelope: stored.envelope,
                offset,
                since: Instant::now(),
                enrolled: Some(stored.enrolled),
                failures: stored.failures,
                serial: self.next_serial(),
            })
        })();
        if restored.is_none() {
            if bytes.is_some() {
                let _ = self.backend.clear();
            }
            self.backend.retain(None);
        }
        restored
    }
    /// Persist the slot (a no-op without a boot stamp).
    fn persist(&self, slot: &Slot) -> Result<(), PlatformError> {
        let Some(enrolled) = slot.enrolled else {
            return Ok(());
        };
        if slot.envelope.len() < MIN_ENVELOPE {
            return Err(PlatformError::InvalidInput);
        }
        let bytes = slot.encode(enrolled).ok_or(PlatformError::InvalidInput)?;
        self.backend.save(&bytes)
    }
    /// Clear the persisted state first, then destroy the handle, so a
    /// restart never refers to a destroyed key.
    fn destroy(&self, slot: &mut Option<Slot>) -> Result<(), PlatformError> {
        if let Some(old) = slot.take() {
            let cleared = if old.enrolled.is_some() {
                self.backend.clear()
            } else {
                Ok(())
            };
            self.backend.delete(&old.envelope)?;
            cleared?;
        }
        Ok(())
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
        let mut slot = self.lock();
        if !self.available() || slot.as_ref().is_some_and(Slot::expired) {
            let _ = self.destroy(&mut slot);
            return None;
        }
        slot.as_ref().map(|s| s.binding)
    }
    fn policy(&self) -> Option<QuickPolicy> {
        self.binding()?;
        self.lock().as_ref().map(|s| s.policy)
    }
    fn enroll(
        &self,
        binding: QuickBinding,
        policy: QuickPolicy,
        secret: &SecretBytes,
        cancel: Cancellation,
    ) -> Result<(), PlatformError> {
        let mut slot = self.lock();
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
        let new = Slot {
            binding,
            policy,
            envelope,
            offset: Duration::ZERO,
            since: Instant::now(),
            enrolled: self.backend.boot(),
            failures: 0,
            serial: self.next_serial(),
        };
        // Saved before success is reported; a failed save leaves no key.
        if let Err(e) = self.persist(&new) {
            let _ = self.backend.clear();
            self.backend.delete(&new.envelope)?;
            return Err(e);
        }
        *slot = Some(new);
        Ok(())
    }
    fn unlock_bound(
        &self,
        binding: QuickBinding,
        cancel: Cancellation,
    ) -> Result<SecretBytes, PlatformError> {
        // Reserve the attempt (persisted, so an interrupted prompt counts) and
        // copy the envelope, then release the policy mutex for the native
        // prompt so readiness queries never wait on it.
        let (serial, policy, envelope) = {
            let mut slot = self.lock();
            if !self.available()
                || slot
                    .as_ref()
                    .is_none_or(|s| s.binding != binding || s.expired())
            {
                self.destroy(&mut slot)?;
                return Err(PlatformError::Unavailable);
            }
            let Some(current) = slot.as_mut() else {
                return Err(PlatformError::Unavailable);
            };
            current.failures += 1;
            if let Err(e) = self.persist(current) {
                current.failures -= 1;
                return Err(e);
            }
            let envelope = SecretBytes::try_init(current.envelope.len(), |b| {
                b.copy_from_slice(current.envelope.expose_secret());
                Ok::<(), PlatformError>(())
            })?;
            (current.serial, current.policy, envelope)
        };
        let result = if cancel() {
            Err(PlatformError::Cancelled)
        } else {
            self.backend
                .open(binding, policy, &envelope, cancel.clone())
        };
        drop(envelope);
        let mut slot = self.lock();
        // Invalidated or re-enrolled during the prompt: the result belongs to
        // no current policy and is discarded without touching the new slot.
        let Some(current) = slot.as_mut().filter(|s| s.serial == serial) else {
            return Err(PlatformError::Cancelled);
        };
        match result {
            Ok(plain) if !plain.is_empty() && plain.len() <= MAX_PLAINTEXT && !cancel() => {
                current.failures -= 1;
                // The attempt stays recorded if this save fails; still open.
                let _ = self.persist(current);
                Ok(plain)
            }
            // A dismissal is not a failed attempt (0002 §5.4).
            Err(PlatformError::Cancelled) => {
                current.failures -= 1;
                let _ = self.persist(current);
                Err(PlatformError::Cancelled)
            }
            result => {
                if current.failures >= MAX_FAILURES
                    || matches!(result, Err(PlatformError::Unavailable))
                {
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
        self.destroy(&mut self.lock())
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

    /// Blocks `open` until released, so concurrent policy calls can be observed.
    struct Gated {
        entered: std::sync::mpsc::SyncSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl AndroidKeystoreBackend for Gated {
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
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            Ok(bytes())
        }
        fn delete(&self, _: &SecretBytes) -> Result<(), PlatformError> {
            Ok(())
        }
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn native_prompt_does_not_hold_policy_and_stale_results_are_discarded() {
        let (entered_tx, entered) = std::sync::mpsc::sync_channel(0);
        let (release, release_rx) = std::sync::mpsc::sync_channel(0);
        let os = Arc::new(AndroidKeystore::new(Arc::new(Gated {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        })));
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        let worker = {
            let os = os.clone();
            std::thread::spawn(move || os.unlock_bound(binding(), cancel()))
        };
        entered.recv().unwrap();
        // The prompt is in flight: readiness answers without waiting for it.
        assert!(os.binding().is_some());
        // Re-enrollment during the prompt replaces the slot; the old prompt's
        // plaintext must not be returned or charged to the new slot.
        os.enroll(binding(), QuickPolicy::DeviceCredential, &bytes(), cancel())
            .unwrap();
        release.send(()).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(PlatformError::Cancelled)
        ));
        assert_eq!(
            os.slot.lock().unwrap().as_ref().map(|s| s.failures),
            Some(0)
        );
        // Invalidation during a prompt likewise discards the late result.
        let worker = {
            let os = os.clone();
            std::thread::spawn(move || os.unlock_bound(binding(), cancel()))
        };
        entered.recv().unwrap();
        os.invalidate().unwrap();
        release.send(()).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(PlatformError::Cancelled)
        ));
        assert!(os.binding().is_none());
        // An undisturbed prompt still succeeds and restores the attempt.
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        let worker = {
            let os = os.clone();
            std::thread::spawn(move || os.unlock_bound(binding(), cancel()))
        };
        entered.recv().unwrap();
        release.send(()).unwrap();
        assert_eq!(worker.join().unwrap().unwrap().expose_secret(), b"test");
        assert_eq!(
            os.slot.lock().unwrap().as_ref().map(|s| s.failures),
            Some(0)
        );
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

    /// A persistent backend: an in-memory state file and a settable boot.
    #[derive(Default)]
    struct Disk {
        state: Mutex<Option<Vec<u8>>>,
        boot: Mutex<Option<BootStamp>>,
        open: Mutex<Option<PlatformError>>,
        save_fails: AtomicBool,
        deletes: AtomicUsize,
        retained: Mutex<Vec<Option<u64>>>,
        /// The state file seen while the prompt is open.
        during: Mutex<Option<Vec<u8>>>,
    }
    fn sealed() -> SecretBytes {
        SecretBytes::try_init(MIN_ENVELOPE, |b| {
            b.fill(7);
            Ok::<(), ()>(())
        })
        .unwrap()
    }
    impl AndroidKeystoreBackend for Disk {
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
            Ok(sealed())
        }
        fn open(
            &self,
            _: QuickBinding,
            _: QuickPolicy,
            _: &SecretBytes,
            _: Cancellation,
        ) -> Result<SecretBytes, PlatformError> {
            *self.during.lock().unwrap() = self.state.lock().unwrap().clone();
            match *self.open.lock().unwrap() {
                Some(e) => Err(e),
                None => Ok(bytes()),
            }
        }
        fn delete(&self, _: &SecretBytes) -> Result<(), PlatformError> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn boot(&self) -> Option<BootStamp> {
            *self.boot.lock().unwrap()
        }
        fn load(&self) -> Option<Vec<u8>> {
            self.state.lock().unwrap().clone()
        }
        fn save(&self, state: &[u8]) -> Result<(), PlatformError> {
            if self.save_fails.load(Ordering::SeqCst) {
                return Err(PlatformError::Io);
            }
            *self.state.lock().unwrap() = Some(state.to_vec());
            Ok(())
        }
        fn clear(&self) -> Result<(), PlatformError> {
            *self.state.lock().unwrap() = None;
            Ok(())
        }
        fn retain(&self, keep: Option<(&SecretBytes, u64)>) {
            self.retained.lock().unwrap().push(keep.map(|(_, t)| t));
        }
    }
    fn disk() -> Arc<Disk> {
        let d = Arc::new(Disk::default());
        *d.boot.lock().unwrap() = Some(BootStamp {
            count: 5,
            uptime_ms: 1_000,
        });
        d
    }
    fn set_boot(d: &Disk, count: u32, uptime_ms: u64) {
        *d.boot.lock().unwrap() = Some(BootStamp { count, uptime_ms });
    }
    fn failures(state: &[u8]) -> u8 {
        state[18]
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn enrollment_survives_restart_only_within_the_same_boot_and_age() {
        let d = disk();
        AndroidKeystore::new(d.clone())
            .enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        assert!(d.state.lock().unwrap().is_some());
        // The first process found no state and swept stale handles.
        assert_eq!(std::mem::take(&mut *d.retained.lock().unwrap()), vec![None]);
        // A restart in the same boot keeps it, and keeps the key.
        set_boot(&d, 5, 60_000);
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding() == Some(binding()));
        assert_eq!(os.policy(), Some(QuickPolicy::Class3));
        assert_eq!(*d.retained.lock().unwrap(), vec![Some(1_000)]);
        assert_eq!(
            os.unlock_bound(binding(), cancel())
                .unwrap()
                .expose_secret(),
            b"test"
        );
        assert_eq!(d.deletes.load(Ordering::SeqCst), 0);
        // Another boot, a clock that went back, or seven days: password.
        let stale = d.state.lock().unwrap().clone();
        for (count, uptime) in [
            (6, 60_000),
            (5, 999),
            (5, 1_000 + MAX_AGE.as_millis() as u64),
        ] {
            *d.state.lock().unwrap() = stale.clone();
            d.retained.lock().unwrap().clear();
            set_boot(&d, count, uptime);
            let os = AndroidKeystore::new(d.clone());
            assert!(os.binding().is_none(), "boot {count} uptime {uptime}");
            assert!(d.state.lock().unwrap().is_none());
            assert_eq!(*d.retained.lock().unwrap(), vec![None]);
        }
        // No boot stamp: nothing persisted is trusted, or touched.
        *d.state.lock().unwrap() = stale.clone();
        d.retained.lock().unwrap().clear();
        *d.boot.lock().unwrap() = None;
        assert!(AndroidKeystore::new(d.clone()).binding().is_none());
        assert_eq!(*d.state.lock().unwrap(), stale);
        assert!(d.retained.lock().unwrap().is_empty());
        // No state file: every leftover handle is destroyed.
        *d.state.lock().unwrap() = None;
        set_boot(&d, 5, 2_000);
        assert!(AndroidKeystore::new(d.clone()).binding().is_none());
        assert_eq!(*d.retained.lock().unwrap(), vec![None]);
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn malformed_state_files_are_cleared_and_every_handle_destroyed() {
        let d = disk();
        AndroidKeystore::new(d.clone())
            .enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        let good = d.state.lock().unwrap().clone().unwrap();
        assert_eq!(good.len(), STATE_HEADER + MIN_ENVELOPE);
        let mut bad: Vec<Vec<u8>> = vec![
            Vec::new(),
            good[..STATE_HEADER].to_vec(),
            good[..good.len() - 1].to_vec(),
            [good.clone(), vec![0]].concat(),
            vec![0; STATE_MAX + 1],
        ];
        for (at, value) in [(0, b'X'), (4, 2), (5, 0), (5, 3), (18, 3), (19 + 16, 0)] {
            let mut b = good.clone();
            b[at] = value;
            if at == 19 + 16 {
                b[19 + 16..19 + 20].fill(0); // generation 0
            }
            bad.push(b);
        }
        let mut short = good.clone();
        short[55..57].copy_from_slice(&((MIN_ENVELOPE - 1) as u16).to_be_bytes());
        short.pop();
        bad.push(short);
        let mut long = good.clone();
        long[55..57].copy_from_slice(&((MAX_ENVELOPE + 1) as u16).to_be_bytes());
        long.resize(STATE_HEADER + MAX_ENVELOPE + 1, 0);
        bad.push(long);
        for b in bad {
            *d.state.lock().unwrap() = Some(b.clone());
            d.retained.lock().unwrap().clear();
            let os = AndroidKeystore::new(d.clone());
            assert!(os.binding().is_none(), "{} bytes", b.len());
            assert!(d.state.lock().unwrap().is_none());
            assert_eq!(*d.retained.lock().unwrap(), vec![None]);
        }
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn dismissals_are_free_lockouts_count_and_attempts_persist_before_the_prompt() {
        let d = disk();
        let os = AndroidKeystore::new(d.clone());
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        // Dismissed many times: never a failed attempt.
        *d.open.lock().unwrap() = Some(PlatformError::Cancelled);
        for _ in 0..5 {
            assert!(matches!(
                os.unlock_bound(binding(), cancel()),
                Err(PlatformError::Cancelled)
            ));
            // Recorded while the prompt was open, given back afterwards.
            assert_eq!(failures(d.during.lock().unwrap().as_ref().unwrap()), 1);
            assert_eq!(failures(d.state.lock().unwrap().as_ref().unwrap()), 0);
        }
        assert!(os.binding().is_some());
        // A prompt killed with the process counts after the restart.
        let killed = d.during.lock().unwrap().clone();
        *d.state.lock().unwrap() = killed;
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding().is_some());
        // Lockouts count; the third ends the enrollment.
        *d.open.lock().unwrap() = Some(PlatformError::Denied);
        assert!(matches!(
            os.unlock_bound(binding(), cancel()),
            Err(PlatformError::Denied)
        ));
        assert_eq!(failures(d.state.lock().unwrap().as_ref().unwrap()), 2);
        assert!(matches!(
            os.unlock_bound(binding(), cancel()),
            Err(PlatformError::Denied)
        ));
        assert!(os.binding().is_none());
        assert!(d.state.lock().unwrap().is_none());
        assert_eq!(d.deletes.load(Ordering::SeqCst), 1);
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn failed_saves_leave_no_key_and_no_unrecorded_attempt() {
        let d = disk();
        d.save_fails.store(true, Ordering::SeqCst);
        let os = AndroidKeystore::new(d.clone());
        assert!(
            os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
                .is_err()
        );
        assert!(os.binding().is_none());
        assert_eq!(d.deletes.load(Ordering::SeqCst), 1);
        d.save_fails.store(false, Ordering::SeqCst);
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        // The attempt cannot be recorded: no prompt opens.
        d.save_fails.store(true, Ordering::SeqCst);
        *d.during.lock().unwrap() = None;
        assert!(os.unlock_bound(binding(), cancel()).is_err());
        assert!(d.during.lock().unwrap().is_none());
        assert_eq!(failures(d.state.lock().unwrap().as_ref().unwrap()), 0);
        // Invalidation clears the state before the key goes.
        d.save_fails.store(false, Ordering::SeqCst);
        os.invalidate().unwrap();
        assert!(d.state.lock().unwrap().is_none());
        assert!(AndroidKeystore::new(d.clone()).binding().is_none());
    }
}
