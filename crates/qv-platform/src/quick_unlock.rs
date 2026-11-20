// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device-local quick-unlock policy (0002 §5). Each vault has its own
//! enrollment, up to [`MAX_SLOTS`] on a device (plan 0074). The policy
//! survives an app restart only in the backend's private, non-backed-up
//! state file and only for the same boot (0002 §5.4, plan 0045); without a
//! boot stamp it lasts for this process alone.
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
/// Failed attempts that end a vault's enrollment.
pub const MAX_FAILURES: u8 = 3;
/// Vaults a device keeps enrolled at once (0002 §5.1, plan 0074).
pub const MAX_SLOTS: usize = 16;
const MAGIC: &[u8; 4] = b"QVQU";
/// Version 1 held one record; version 2 a count and up to [`MAX_SLOTS`].
const LEGACY_VERSION: u8 = 1;
const STATE_VERSION: u8 = 2;
/// Policy, boot count, boot uptime, failures, binding, envelope length.
const RECORD_HEADER: usize = 1 + 4 + 8 + 1 + 36 + 2;
/// Magic, version and record count.
const STATE_HEADER: usize = 4 + 1 + 1;
/// Largest persisted state file read or written.
pub const STATE_MAX: usize = STATE_HEADER + MAX_SLOTS * (RECORD_HEADER + MAX_ENVELOPE);
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
    /// The persisted state file, at most [`STATE_MAX`] bytes.
    fn load(&self) -> Option<Vec<u8>> {
        None
    }
    /// Replace the persisted state file atomically.
    fn save(&self, _state: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unavailable)
    }
    /// Remove the persisted state file.
    fn clear(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    /// Keep only these envelopes' handles (each with its enrollment uptime)
    /// and destroy every other QuickVault handle; empty destroys them all.
    fn retain(&self, _keep: &[(&SecretBytes, u64)]) {}
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
    /// Append the persisted record; no plaintext secret (the envelope is
    /// hardware-key ciphertext).
    fn encode(&self, enrolled: BootStamp, out: &mut Vec<u8>) -> Option<()> {
        let len = u16::try_from(self.envelope.len()).ok()?;
        out.push(self.policy as u8);
        out.extend_from_slice(&enrolled.count.to_be_bytes());
        out.extend_from_slice(&enrolled.uptime_ms.to_be_bytes());
        out.push(self.failures);
        out.extend_from_slice(&self.binding.encode());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(self.envelope.expose_secret());
        Some(())
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
/// The whole state file, or `None` when any part of it is malformed:
/// a bad header or count, a bad record, two records for one vault or
/// trailing bytes. A version-1 file is its one record.
fn decode(b: &[u8]) -> Option<Vec<Stored>> {
    if b.len() > STATE_MAX || b.get(..4)? != MAGIC {
        return None;
    }
    let (count, mut rest) = match *b.get(4)? {
        LEGACY_VERSION => (1, b.get(5..)?),
        STATE_VERSION => (usize::from(*b.get(5)?), b.get(STATE_HEADER..)?),
        _ => return None,
    };
    if count == 0 || count > MAX_SLOTS {
        return None;
    }
    let mut out: Vec<Stored> = Vec::with_capacity(count);
    for _ in 0..count {
        let (stored, next) = record(rest)?;
        if out.iter().any(|s| s.binding.vault == stored.binding.vault) {
            return None;
        }
        out.push(stored);
        rest = next;
    }
    rest.is_empty().then_some(out)
}
fn record(b: &[u8]) -> Option<(Stored, &[u8])> {
    let policy = QuickPolicy::from_u8(*b.first()?)?;
    let count = u32::from_be_bytes(b.get(1..5)?.try_into().ok()?);
    let uptime_ms = u64::from_be_bytes(b.get(5..13)?.try_into().ok()?);
    let failures = *b.get(13)?;
    let binding = QuickBinding::decode(b.get(14..50)?)?;
    let len = usize::from(u16::from_be_bytes(
        b.get(50..RECORD_HEADER)?.try_into().ok()?,
    ));
    if !(MIN_ENVELOPE..=MAX_ENVELOPE).contains(&len) || failures >= MAX_FAILURES {
        return None;
    }
    let body = b.get(RECORD_HEADER..RECORD_HEADER + len)?;
    let envelope = SecretBytes::try_init(len, |out| {
        out.copy_from_slice(body);
        Ok::<(), PlatformError>(())
    })
    .ok()?;
    Some((
        Stored {
            policy,
            enrolled: BootStamp { count, uptime_ms },
            failures,
            binding,
            envelope,
        },
        b.get(RECORD_HEADER + len..)?,
    ))
}
/// Serialized trusted policy. No export, Debug or plaintext cache.
pub struct AndroidKeystore {
    backend: Arc<dyn AndroidKeystoreBackend>,
    slots: Mutex<Vec<Slot>>,
    loaded: std::sync::Once,
    serial: std::sync::atomic::AtomicU64,
}
impl AndroidKeystore {
    /// Inject the native adapter; availability still requires device validation.
    pub fn new(backend: Arc<dyn AndroidKeystoreBackend>) -> Self {
        Self {
            backend,
            slots: Mutex::new(Vec::new()),
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
    fn lock(&self) -> MutexGuard<'_, Vec<Slot>> {
        self.loaded.call_once(|| {
            let restored = self.restore();
            let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            if slots.is_empty() {
                *slots = restored;
            }
        });
        self.slots.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Restore the slots persisted during this boot. A record past its age
    /// is dropped alone; anything else wrong (another boot, a clock that went
    /// back, a malformed file, an unvalidated backend) clears the state and
    /// destroys every QuickVault handle.
    /// Without a boot stamp nothing is persisted or touched.
    fn restore(&self) -> Vec<Slot> {
        let Some(now) = self.backend.boot() else {
            return Vec::new();
        };
        let bytes = self.backend.load();
        let restored = (|| {
            let stored = decode(bytes.as_deref()?)?;
            if !self.backend.validated() {
                return None;
            }
            let read = stored.len();
            let mut slots = Vec::with_capacity(read);
            for s in stored {
                let age = now.uptime_ms.checked_sub(s.enrolled.uptime_ms)?;
                if now.count != s.enrolled.count {
                    return None;
                }
                let offset = Duration::from_millis(age);
                if offset >= MAX_AGE {
                    continue;
                }
                slots.push(Slot {
                    binding: s.binding,
                    policy: s.policy,
                    envelope: s.envelope,
                    offset,
                    since: Instant::now(),
                    enrolled: Some(s.enrolled),
                    failures: s.failures,
                    serial: self.next_serial(),
                });
            }
            Some((slots, read))
        })();
        match restored {
            Some((slots, read)) if !slots.is_empty() => {
                let keep: Vec<(&SecretBytes, u64)> = slots
                    .iter()
                    .map(|s| (&s.envelope, s.enrolled.map_or(0, |e| e.uptime_ms)))
                    .collect();
                self.backend.retain(&keep);
                // Rewritten without the expired records (and as version 2).
                if slots.len() != read
                    || bytes.as_deref().and_then(|b| b.get(4)) != Some(&STATE_VERSION)
                {
                    let _ = self.save(&slots);
                }
                slots
            }
            _ => {
                if bytes.is_some() {
                    let _ = self.backend.clear();
                }
                self.backend.retain(&[]);
                Vec::new()
            }
        }
    }
    /// Persist every slot that has a boot stamp; with none left, remove the
    /// file. A no-op when no slot is persisted (no boot stamp).
    fn save(&self, slots: &[Slot]) -> Result<(), PlatformError> {
        let mut body = Vec::new();
        let mut count = 0u8;
        for s in slots {
            let Some(enrolled) = s.enrolled else {
                continue;
            };
            if s.envelope.len() < MIN_ENVELOPE {
                return Err(PlatformError::InvalidInput);
            }
            s.encode(enrolled, &mut body)
                .ok_or(PlatformError::InvalidInput)?;
            count += 1;
        }
        if count == 0 {
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(STATE_HEADER + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(STATE_VERSION);
        bytes.push(count);
        bytes.extend_from_slice(&body);
        self.backend.save(&bytes)
    }
    /// Save the slots after a persisted slot left: rewrite the file, or
    /// remove it when no persisted slot remains. A failed rewrite removes
    /// the file, so a restart never refers to a destroyed key (the other
    /// slots then last for this process only).
    fn forget(&self, slots: &[Slot]) -> Result<(), PlatformError> {
        let result = if slots.iter().any(|s| s.enrolled.is_some()) {
            self.save(slots)
        } else {
            self.backend.clear()
        };
        if result.is_err() {
            return self.backend.clear().and(result);
        }
        result
    }
    /// Remove one slot from the persisted state first, then destroy its
    /// handle.
    fn destroy(&self, slots: &mut Vec<Slot>, at: usize) -> Result<(), PlatformError> {
        if at >= slots.len() {
            return Ok(());
        }
        let old = slots.remove(at);
        let saved = if old.enrolled.is_some() {
            self.forget(slots)
        } else {
            Ok(())
        };
        self.backend.delete(&old.envelope)?;
        saved
    }
    /// Clear the persisted state first, then destroy every handle.
    fn destroy_all(&self, slots: &mut Vec<Slot>) -> Result<(), PlatformError> {
        let old = std::mem::take(slots);
        let cleared = if old.iter().any(|s| s.enrolled.is_some()) {
            self.backend.clear()
        } else {
            Ok(())
        };
        let mut deleted = Ok(());
        for s in &old {
            if let Err(e) = self.backend.delete(&s.envelope) {
                deleted = Err(e);
            }
        }
        deleted.and(cleared)
    }
    /// This vault's slot, after removing it if it has expired.
    fn find(&self, slots: &mut Vec<Slot>, vault: &[u8; 16]) -> Option<usize> {
        let at = slots.iter().position(|s| s.binding.vault == *vault)?;
        if slots[at].expired() {
            let _ = self.destroy(slots, at);
            return None;
        }
        Some(at)
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
    fn binding(&self, vault: &[u8; 16]) -> Option<QuickBinding> {
        let mut slots = self.lock();
        if !self.available() {
            let _ = self.destroy_all(&mut slots);
            return None;
        }
        let at = self.find(&mut slots, vault)?;
        Some(slots[at].binding)
    }
    fn policy(&self, vault: &[u8; 16]) -> Option<QuickPolicy> {
        let mut slots = self.lock();
        if !self.available() {
            let _ = self.destroy_all(&mut slots);
            return None;
        }
        let at = self.find(&mut slots, vault)?;
        Some(slots[at].policy)
    }
    fn enroll(
        &self,
        binding: QuickBinding,
        policy: QuickPolicy,
        secret: &SecretBytes,
        cancel: Cancellation,
    ) -> Result<(), PlatformError> {
        let mut slots = self.lock();
        if let Some(at) = slots.iter().position(|s| s.binding.vault == binding.vault) {
            self.destroy(&mut slots, at)?;
        }
        if !self.available() {
            return Err(PlatformError::Unavailable);
        }
        if binding.generation == 0 || secret.is_empty() || secret.len() > MAX_PLAINTEXT {
            return Err(PlatformError::InvalidInput);
        }
        // Expired slots do not count against the limit.
        while let Some(at) = slots.iter().position(Slot::expired) {
            self.destroy(&mut slots, at)?;
        }
        if slots.len() >= MAX_SLOTS {
            return Err(PlatformError::LimitExceeded);
        }
        if cancel() {
            return Err(PlatformError::Cancelled);
        }
        let envelope = self.backend.seal(binding, policy, secret, cancel.clone())?;
        if envelope.is_empty() || envelope.len() > MAX_ENVELOPE || cancel() {
            self.backend.delete(&envelope)?;
            return Err(PlatformError::Cancelled);
        }
        slots.push(Slot {
            binding,
            policy,
            envelope,
            offset: Duration::ZERO,
            since: Instant::now(),
            enrolled: self.backend.boot(),
            failures: 0,
            serial: self.next_serial(),
        });
        // Saved before success is reported; a failed save leaves no key.
        if let Err(e) = self.save(&slots) {
            if let Some(new) = slots.pop() {
                let _ = self.forget(&slots);
                self.backend.delete(&new.envelope)?;
            }
            return Err(e);
        }
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
            let mut slots = self.lock();
            if !self.available() {
                self.destroy_all(&mut slots)?;
                return Err(PlatformError::Unavailable);
            }
            let Some(at) = self.find(&mut slots, &binding.vault) else {
                return Err(PlatformError::Unavailable);
            };
            // A changed generation or password keyslot: this vault's slot is stale.
            if slots[at].binding != binding {
                self.destroy(&mut slots, at)?;
                return Err(PlatformError::Unavailable);
            }
            slots[at].failures += 1;
            if let Err(e) = self.save(&slots) {
                slots[at].failures -= 1;
                return Err(e);
            }
            let current = &slots[at];
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
        let mut slots = self.lock();
        // Invalidated or re-enrolled during the prompt: the result belongs to
        // no current policy and is discarded without touching the new slot.
        let Some(at) = slots.iter().position(|s| s.serial == serial) else {
            return Err(PlatformError::Cancelled);
        };
        // A successful prompt whose result is cancelled before delivery is
        // also a dismissal, not a failed authentication (0002 §5.4).
        if result.is_ok() && cancel() {
            slots[at].failures -= 1;
            let _ = self.save(&slots);
            return Err(PlatformError::Cancelled);
        }
        match result {
            Ok(plain) if !plain.is_empty() && plain.len() <= MAX_PLAINTEXT => {
                slots[at].failures -= 1;
                // The attempt stays recorded if this save fails; still open.
                let _ = self.save(&slots);
                Ok(plain)
            }
            // A dismissal is not a failed attempt (0002 §5.4).
            Err(PlatformError::Cancelled) => {
                slots[at].failures -= 1;
                let _ = self.save(&slots);
                Err(PlatformError::Cancelled)
            }
            result => {
                if slots[at].failures >= MAX_FAILURES
                    || matches!(result, Err(PlatformError::Unavailable))
                {
                    self.destroy(&mut slots, at)?;
                }
                match result {
                    Err(e) => Err(e),
                    Ok(_) => Err(PlatformError::Cancelled),
                }
            }
        }
    }
    fn invalidate(&self, vault: &[u8; 16]) -> Result<(), PlatformError> {
        let mut slots = self.lock();
        match slots.iter().position(|s| s.binding.vault == *vault) {
            Some(at) => self.destroy(&mut slots, at),
            None => Ok(()),
        }
    }
    fn invalidate_all(&self) -> Result<(), PlatformError> {
        self.destroy_all(&mut self.lock())
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
    const V: [u8; 16] = [1; 16];
    fn binding() -> QuickBinding {
        QuickBinding {
            vault: V,
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
        assert!(os.binding(&V).is_none());
        assert_eq!(backend.deletes.load(Ordering::SeqCst), 1);
        backend.fail.store(false, Ordering::SeqCst);
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        os.slots.lock().unwrap()[0].since = Instant::now() - MAX_AGE;
        assert!(os.binding(&V).is_none());
        os.enroll(binding(), QuickPolicy::DeviceCredential, &bytes(), cancel())
            .unwrap();
        let mut wrong = binding();
        wrong.generation += 1;
        assert!(os.unlock_bound(wrong, cancel()).is_err());
        assert!(os.binding(&V).is_none());
        assert!(
            os.enroll(binding(), QuickPolicy::Class3, &bytes(), Arc::new(|| true))
                .is_err()
        );
        assert!(os.binding(&V).is_none());
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        os.invalidate(&V).unwrap();
        assert!(os.binding(&V).is_none());
        assert!(os.wrap(&bytes()).is_err());
        assert!(os.unwrap(&bytes()).is_err());
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn quick_success_cancelled_before_delivery_never_spends_attempts() {
        let backend = Arc::new(Backend {
            fail: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            deletes: AtomicUsize::new(0),
        });
        let os = AndroidKeystore::new(backend.clone());
        os.enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        for _ in 0..4 {
            let calls = Arc::new(AtomicUsize::new(0));
            let cancelled: Cancellation =
                Arc::new(move || calls.fetch_add(1, Ordering::SeqCst) > 0);
            assert_eq!(
                os.unlock_bound(binding(), cancelled).err(),
                Some(PlatformError::Cancelled)
            );
            assert_eq!(os.slots.lock().unwrap()[0].failures, 0);
            assert!(os.binding(&V) == Some(binding()));
        }
        assert_eq!(backend.deletes.load(Ordering::SeqCst), 0);
        assert_eq!(
            os.unlock_bound(binding(), cancel())
                .unwrap()
                .expose_secret(),
            b"test"
        );
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
        assert!(os.binding(&V).is_some());
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
            os.slots.lock().unwrap().first().map(|s| s.failures),
            Some(0)
        );
        // Invalidation during a prompt likewise discards the late result.
        let worker = {
            let os = os.clone();
            std::thread::spawn(move || os.unlock_bound(binding(), cancel()))
        };
        entered.recv().unwrap();
        os.invalidate(&V).unwrap();
        release.send(()).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(PlatformError::Cancelled)
        ));
        assert!(os.binding(&V).is_none());
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
            os.slots.lock().unwrap().first().map(|s| s.failures),
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
        assert!(os.binding(&V).is_none());
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
        retained: Mutex<Vec<Vec<u64>>>,
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
        fn retain(&self, keep: &[(&SecretBytes, u64)]) {
            self.retained
                .lock()
                .unwrap()
                .push(keep.iter().map(|(_, t)| *t).collect());
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
    /// The first record's failed attempts.
    fn failures(state: &[u8]) -> u8 {
        state[STATE_HEADER + 13]
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
        assert_eq!(
            std::mem::take(&mut *d.retained.lock().unwrap()),
            vec![Vec::<u64>::new()]
        );
        // A restart in the same boot keeps it, and keeps the key.
        set_boot(&d, 5, 60_000);
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&V) == Some(binding()));
        assert_eq!(os.policy(&V), Some(QuickPolicy::Class3));
        assert_eq!(*d.retained.lock().unwrap(), vec![vec![1_000]]);
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
            assert!(os.binding(&V).is_none(), "boot {count} uptime {uptime}");
            assert!(d.state.lock().unwrap().is_none());
            assert_eq!(*d.retained.lock().unwrap(), vec![Vec::<u64>::new()]);
        }
        // No boot stamp: nothing persisted is trusted, or touched.
        *d.state.lock().unwrap() = stale.clone();
        d.retained.lock().unwrap().clear();
        *d.boot.lock().unwrap() = None;
        assert!(AndroidKeystore::new(d.clone()).binding(&V).is_none());
        assert_eq!(*d.state.lock().unwrap(), stale);
        assert!(d.retained.lock().unwrap().is_empty());
        // No state file: every leftover handle is destroyed.
        *d.state.lock().unwrap() = None;
        set_boot(&d, 5, 2_000);
        assert!(AndroidKeystore::new(d.clone()).binding(&V).is_none());
        assert_eq!(*d.retained.lock().unwrap(), vec![Vec::<u64>::new()]);
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn malformed_state_files_are_cleared_and_every_handle_destroyed() {
        let d = disk();
        AndroidKeystore::new(d.clone())
            .enroll(binding(), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        let good = d.state.lock().unwrap().clone().unwrap();
        assert_eq!(good.len(), STATE_HEADER + RECORD_HEADER + MIN_ENVELOPE);
        // The record starts after the magic, version and count.
        let r = STATE_HEADER;
        let mut bad: Vec<Vec<u8>> = vec![
            Vec::new(),
            good[..STATE_HEADER].to_vec(),
            good[..r + RECORD_HEADER].to_vec(),
            good[..good.len() - 1].to_vec(),
            [good.clone(), vec![0]].concat(),
            vec![0; STATE_MAX + 1],
            // Two records for one vault.
            [&good[..5], &[2], &good[r..], &good[r..]].concat(),
        ];
        for (at, value) in [
            (0, b'X'),
            (4, 0),
            (4, 3),
            (5, 0),
            (5, 2),
            (5, MAX_SLOTS as u8 + 1),
            (r, 0),
            (r, 3),
            (r + 13, 3),
            (r + 14 + 16, 0),
        ] {
            let mut b = good.clone();
            b[at] = value;
            if at == r + 14 + 16 {
                b[r + 30..r + 34].fill(0); // generation 0
            }
            bad.push(b);
        }
        let len = r + 50..r + RECORD_HEADER;
        let mut short = good.clone();
        short[len.clone()].copy_from_slice(&((MIN_ENVELOPE - 1) as u16).to_be_bytes());
        short.pop();
        bad.push(short);
        let mut long = good.clone();
        long[len].copy_from_slice(&((MAX_ENVELOPE + 1) as u16).to_be_bytes());
        long.resize(r + RECORD_HEADER + MAX_ENVELOPE + 1, 0);
        bad.push(long);
        // A version-1 file is one record with no count; trailing bytes are not.
        let legacy = [&good[..4], &[LEGACY_VERSION], &good[r..]].concat();
        bad.push([legacy.clone(), vec![0]].concat());
        for b in bad {
            *d.state.lock().unwrap() = Some(b.clone());
            d.retained.lock().unwrap().clear();
            let os = AndroidKeystore::new(d.clone());
            assert!(os.binding(&V).is_none(), "{} bytes", b.len());
            assert!(d.state.lock().unwrap().is_none());
            assert_eq!(*d.retained.lock().unwrap(), vec![Vec::<u64>::new()]);
        }
        // The version-1 file itself is read and rewritten as version 2, so
        // an enrollment from before plan 0074 survives the update.
        *d.state.lock().unwrap() = Some(legacy);
        d.retained.lock().unwrap().clear();
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&V) == Some(binding()));
        assert_eq!(*d.retained.lock().unwrap(), vec![vec![1_000]]);
        assert_eq!(d.state.lock().unwrap().as_deref(), Some(&good[..]));
    }

    fn vault(n: u8) -> QuickBinding {
        QuickBinding {
            vault: [n; 16],
            generation: 1,
            password_version: [n; 16],
        }
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn each_vault_keeps_its_own_enrollment_attempts_and_age() {
        let d = disk();
        let os = AndroidKeystore::new(d.clone());
        let (a, b) = (vault(1), vault(2));
        os.enroll(a, QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        os.enroll(b, QuickPolicy::DeviceCredential, &bytes(), cancel())
            .unwrap();
        assert!(os.binding(&a.vault) == Some(a) && os.binding(&b.vault) == Some(b));
        assert_eq!(os.policy(&a.vault), Some(QuickPolicy::Class3));
        assert_eq!(os.policy(&b.vault), Some(QuickPolicy::DeviceCredential));
        assert!(os.binding(&[3; 16]).is_none());
        // Re-enrolling one replaces only its own key.
        os.enroll(a, QuickPolicy::DeviceCredential, &bytes(), cancel())
            .unwrap();
        assert_eq!(d.deletes.load(Ordering::SeqCst), 1);
        assert_eq!(os.policy(&a.vault), Some(QuickPolicy::DeviceCredential));
        assert!(os.binding(&b.vault) == Some(b));
        // Both survive a restart in the same boot, each with its own key.
        set_boot(&d, 5, 60_000);
        d.retained.lock().unwrap().clear();
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&a.vault) == Some(a) && os.binding(&b.vault) == Some(b));
        assert_eq!(*d.retained.lock().unwrap(), vec![vec![1_000, 1_000]]);
        // Lockouts on one end only its enrollment.
        *d.open.lock().unwrap() = Some(PlatformError::Denied);
        for _ in 0..MAX_FAILURES {
            assert!(os.unlock_bound(a, cancel()).is_err());
        }
        assert!(os.binding(&a.vault).is_none());
        assert!(os.binding(&b.vault) == Some(b));
        assert_eq!(d.deletes.load(Ordering::SeqCst), 2);
        *d.open.lock().unwrap() = None;
        assert_eq!(
            os.unlock_bound(b, cancel()).unwrap().expose_secret(),
            b"test"
        );
        // A stale binding (another generation) ends only that vault's slot.
        os.enroll(a, QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        let mut rotated = b;
        rotated.generation += 1;
        assert!(os.unlock_bound(rotated, cancel()).is_err());
        assert!(os.binding(&b.vault).is_none());
        assert!(os.binding(&a.vault) == Some(a));
        // Turning one off leaves the other, in memory and on disk.
        os.enroll(b, QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        os.invalidate(&a.vault).unwrap();
        assert!(os.binding(&a.vault).is_none() && os.binding(&b.vault) == Some(b));
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&a.vault).is_none() && os.binding(&b.vault) == Some(b));
        // Seven days end each enrollment on its own; the file keeps the rest.
        os.enroll(a, QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        os.slots
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.binding == b)
            .unwrap()
            .since = Instant::now() - MAX_AGE;
        assert!(os.binding(&b.vault).is_none() && os.binding(&a.vault) == Some(a));
        assert_eq!(d.state.lock().unwrap().as_ref().unwrap()[5], 1);
        // The last one turned off removes the file.
        os.invalidate(&a.vault).unwrap();
        assert!(d.state.lock().unwrap().is_none());
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn a_restart_drops_expired_records_alone_and_a_new_boot_drops_all() {
        let d = disk();
        let os = AndroidKeystore::new(d.clone());
        os.enroll(vault(1), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        set_boot(&d, 5, 1_000 + MAX_AGE.as_millis() as u64 - 10);
        os.enroll(vault(2), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        let both = d.state.lock().unwrap().clone();
        // The first is seven days old; the second is not.
        set_boot(&d, 5, 1_000 + MAX_AGE.as_millis() as u64);
        d.retained.lock().unwrap().clear();
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&[1; 16]).is_none());
        assert!(os.binding(&[2; 16]) == Some(vault(2)));
        assert_eq!(
            *d.retained.lock().unwrap(),
            vec![vec![1_000 + MAX_AGE.as_millis() as u64 - 10]]
        );
        assert_eq!(d.state.lock().unwrap().as_ref().unwrap()[5], 1);
        // Another boot ends every enrollment and every key.
        *d.state.lock().unwrap() = both;
        d.retained.lock().unwrap().clear();
        set_boot(&d, 6, 5_000);
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&[1; 16]).is_none() && os.binding(&[2; 16]).is_none());
        assert!(d.state.lock().unwrap().is_none());
        assert_eq!(*d.retained.lock().unwrap(), vec![Vec::<u64>::new()]);
    }

    // 0012 §1: Hardware assumptions
    #[test]
    fn a_device_keeps_at_most_sixteen_enrolled_vaults() {
        let d = disk();
        let os = AndroidKeystore::new(d.clone());
        for n in 1..=MAX_SLOTS as u8 {
            os.enroll(vault(n), QuickPolicy::Class3, &bytes(), cancel())
                .unwrap();
        }
        let full = d.state.lock().unwrap().clone().unwrap();
        assert!(full.len() <= STATE_MAX);
        assert_eq!(full[5], MAX_SLOTS as u8);
        // A seventeenth is refused; nothing is moved or evicted.
        let extra = vault(MAX_SLOTS as u8 + 1);
        assert_eq!(
            os.enroll(extra, QuickPolicy::Class3, &bytes(), cancel()),
            Err(PlatformError::LimitExceeded)
        );
        assert_eq!(d.deletes.load(Ordering::SeqCst), 0);
        assert!((1..=MAX_SLOTS as u8).all(|n| os.binding(&[n; 16]).is_some()));
        // Re-enrolling one already counted is fine.
        os.enroll(vault(3), QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        // An expired slot makes room.
        os.slots.lock().unwrap()[0].since = Instant::now() - MAX_AGE;
        os.enroll(extra, QuickPolicy::Class3, &bytes(), cancel())
            .unwrap();
        assert!(os.binding(&extra.vault).is_some());
        // The full file is read back whole.
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&extra.vault).is_some());
        assert!((2..=MAX_SLOTS as u8).all(|n| os.binding(&[n; 16]).is_some()));
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
        assert!(os.binding(&V).is_some());
        // A prompt killed with the process counts after the restart.
        let killed = d.during.lock().unwrap().clone();
        *d.state.lock().unwrap() = killed;
        let os = AndroidKeystore::new(d.clone());
        assert!(os.binding(&V).is_some());
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
        assert!(os.binding(&V).is_none());
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
        assert!(os.binding(&V).is_none());
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
        os.invalidate(&V).unwrap();
        assert!(d.state.lock().unwrap().is_none());
        assert!(AndroidKeystore::new(d.clone()).binding(&V).is_none());
    }
}
