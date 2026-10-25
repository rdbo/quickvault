// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protected memory for secrets (spec 0008 §1.1–1.2).
//!
//! [`SecretBytes`] and [`SecretArray`] are the only types that hold secret
//! bytes. They are zeroized on drop, cannot be cloned, copied, compared or
//! displayed, and print as `<redacted>` under `Debug`. Contents are reached
//! only through `expose_secret` / `expose_secret_mut`.
//!
//! Their pages are locked into RAM (`mlock`/`VirtualLock`) before the
//! constructor returns, so callers fill only locked memory. A failed lock does
//! not fail the allocation: the buffer reports [`SecretBytes::is_locked`]
//! `false` and [`memory_protection`] reports reduced protection from then on.
//! Callers must surface that to the user.
//!
//! Limits, stated plainly: zeroizing does not erase copies made before a
//! secret was wrapped, copies made by other libraries, or anything the OS
//! already wrote to swap or a hibernation image. Locking does not protect
//! hibernation. Guard pages are not used.

use core::fmt;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng::{RngError, fill_random};

/// A heap secret of fixed length.
///
/// The allocation is never resized, so no unwiped copy is left behind by a
/// reallocation.
///
/// It cannot be cloned:
///
/// ```compile_fail,E0599
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// let _b = a.clone();
/// ```
///
/// ```
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// let _b = a;
/// ```
///
/// It is not `Copy`:
///
/// ```compile_fail,E0382
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// let _b = a;
/// let _ = a.len();
/// ```
///
/// ```
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// let b = a;
/// let _ = b.len();
/// ```
///
/// It cannot be displayed (and `Debug` is redacted):
///
/// ```compile_fail,E0277
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// let _ = format!("{}", a);
/// ```
///
/// ```
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// assert_eq!(format!("{:?}", a), "SecretBytes(<redacted>)");
/// ```
///
/// It cannot be compared with `==` (which would not be constant time):
///
/// ```compile_fail,E0369
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// let b = qv_crypto::SecretBytes::zeroed(4);
/// let _ = a == b;
/// ```
///
/// ```
/// let a = qv_crypto::SecretBytes::zeroed(4);
/// let b = qv_crypto::SecretBytes::zeroed(4);
/// let _ = (&a, &b);
/// ```
pub struct SecretBytes {
    buf: Box<[u8]>,
    locked: bool,
}

impl SecretBytes {
    /// Allocates `len` zeroed bytes and locks their pages before returning.
    pub fn zeroed(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        let locked = acquire(&buf);
        Self { buf, locked }
    }

    /// Allocates and locks a buffer, then lets `init` fill it in place.
    ///
    /// If `init` fails, the buffer is wiped and dropped, and its error returned.
    pub fn try_init<E>(
        len: usize,
        init: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut secret = Self::zeroed(len);
        init(&mut secret.buf)?;
        Ok(secret)
    }

    /// Copies `src` into a new locked buffer, then zeroizes `src`.
    ///
    /// This cannot erase copies of `src` made before this call.
    pub fn take_from(src: &mut [u8]) -> Self {
        let mut secret = Self::zeroed(src.len());
        secret.buf.copy_from_slice(src);
        src.zeroize();
        secret
    }

    /// Allocates and locks `len` bytes and fills them from the OS CSPRNG.
    ///
    /// Fails closed: on RNG failure no secret is returned.
    pub fn random(len: usize) -> Result<Self, RngError> {
        Self::try_init(len, fill_random)
    }

    /// Borrows the secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        &self.buf
    }

    /// Mutably borrows the secret bytes. The length cannot change.
    pub fn expose_secret_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// `false` if locking this buffer's pages failed (reduced protection).
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            release(&self.buf);
        }
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// A fixed-size secret, such as a key. Same guarantees as [`SecretBytes`].
///
/// ```compile_fail,E0599
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// let _b = a.clone();
/// ```
///
/// ```
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// let _b = a;
/// ```
///
/// ```compile_fail,E0382
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// let _b = a;
/// let _ = a.is_locked();
/// ```
///
/// ```
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// let b = a;
/// let _ = b.is_locked();
/// ```
///
/// ```compile_fail,E0277
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// let _ = format!("{}", a);
/// ```
///
/// ```
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// assert_eq!(format!("{:?}", a), "SecretArray(<redacted>)");
/// ```
///
/// ```compile_fail,E0369
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// let b = qv_crypto::SecretArray::<32>::zeroed();
/// let _ = a == b;
/// ```
///
/// ```
/// let a = qv_crypto::SecretArray::<32>::zeroed();
/// let b = qv_crypto::SecretArray::<32>::zeroed();
/// let _ = (&a, &b);
/// ```
pub struct SecretArray<const N: usize> {
    buf: Box<[u8; N]>,
    locked: bool,
}

impl<const N: usize> SecretArray<N> {
    /// Allocates `N` zeroed bytes and locks their pages before returning.
    pub fn zeroed() -> Self {
        let buf = Box::new([0u8; N]);
        let locked = acquire(&buf[..]);
        Self { buf, locked }
    }

    /// Allocates and locks the array, then lets `init` fill it in place.
    ///
    /// If `init` fails, the array is wiped and dropped, and its error returned.
    pub fn try_init<E>(init: impl FnOnce(&mut [u8; N]) -> Result<(), E>) -> Result<Self, E> {
        let mut secret = Self::zeroed();
        init(&mut secret.buf)?;
        Ok(secret)
    }

    /// Allocates and locks the array and fills it from the OS CSPRNG.
    ///
    /// Fails closed: on RNG failure no secret is returned.
    pub fn random() -> Result<Self, RngError> {
        Self::try_init(|buf| fill_random(buf))
    }

    /// Borrows the secret bytes.
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.buf
    }

    /// Mutably borrows the secret bytes.
    pub fn expose_secret_mut(&mut self) -> &mut [u8; N] {
        &mut self.buf
    }

    /// `false` if locking this array's pages failed (reduced protection).
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            release(&self.buf[..]);
        }
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretArray<N> {}

impl<const N: usize> fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretArray(<redacted>)")
    }
}

/// Process-wide memory-locking status since start.
///
/// Sticky: once a lock has failed, protection stays reported as reduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryProtection {
    /// Number of secret allocations whose pages could not be locked.
    pub lock_failures: u64,
}

impl MemoryProtection {
    /// Whether any secret allocation ran without locked memory.
    pub fn is_reduced(&self) -> bool {
        self.lock_failures > 0
    }
}

/// Returns the process-wide memory-locking status.
pub fn memory_protection() -> MemoryProtection {
    MemoryProtection {
        lock_failures: LOCK_FAILURES.load(Ordering::Relaxed),
    }
}

// Page-lock registry.
//
// `region::lock` works on whole pages and `munlock` does not nest, so a guard
// per buffer would unlock a page that a live neighbouring buffer still uses.
// Instead each locked page is refcounted by the live buffers that span it and
// unlocked (by dropping its guard) only when the last one is dropped.

struct LockedPage {
    /// Live locked buffers spanning this page. Bounded by the page size, since
    /// each one occupies at least one distinct byte of the page.
    refs: usize,
    _guard: region::LockGuard,
}

static PAGES: Mutex<BTreeMap<usize, LockedPage>> = Mutex::new(BTreeMap::new());
static LOCK_FAILURES: AtomicU64 = AtomicU64::new(0);

fn registry() -> MutexGuard<'static, BTreeMap<usize, LockedPage>> {
    // Every map update is a single insert, increment, decrement or remove, so
    // the map is consistent even if a holder panicked.
    PAGES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The first page start (with the buffer's provenance) and the page count.
fn page_span(buf: &[u8]) -> (*const u8, usize, usize) {
    let page = region::page::size();
    let ptr = buf.as_ptr();
    let offset = ptr.addr() % page;
    (
        ptr.wrapping_byte_sub(offset),
        (offset + buf.len()).div_ceil(page),
        page,
    )
}

/// Locks every page `buf` spans. Returns `false` (and records a failure) if
/// any page could not be locked, with no pages left registered for `buf`.
fn acquire(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    if inject::lock_should_fail() {
        LOCK_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let (first, count, page) = page_span(buf);
    let mut pages = registry();
    for i in 0..count {
        let start = first.wrapping_byte_add(i * page);
        match pages.entry(start.addr()) {
            Entry::Occupied(mut e) => e.get_mut().refs += 1,
            Entry::Vacant(e) => match region::lock(start, page) {
                Ok(guard) => {
                    e.insert(LockedPage {
                        refs: 1,
                        _guard: guard,
                    });
                }
                Err(_) => {
                    release_pages(&mut pages, first, i, page);
                    drop(pages);
                    LOCK_FAILURES.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            },
        }
    }
    true
}

/// Releases the pages of a buffer for which [`acquire`] returned `true`.
fn release(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    let (first, count, page) = page_span(buf);
    release_pages(&mut registry(), first, count, page);
}

fn release_pages(
    pages: &mut BTreeMap<usize, LockedPage>,
    first: *const u8,
    count: usize,
    page: usize,
) {
    for i in 0..count {
        let addr = first.wrapping_byte_add(i * page).addr();
        if let Entry::Occupied(mut e) = pages.entry(addr) {
            e.get_mut().refs -= 1;
            if e.get().refs == 0 {
                // Dropping the guard unlocks the page.
                e.remove();
            }
        }
    }
}

#[cfg(not(test))]
mod inject {
    #[inline(always)]
    pub(super) fn lock_should_fail() -> bool {
        false
    }
}

#[cfg(test)]
mod inject {
    use std::cell::Cell;

    thread_local! {
        static FAIL_LOCKS: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn lock_should_fail() -> bool {
        FAIL_LOCKS.with(Cell::get)
    }

    pub(super) fn set_lock_failure(fail: bool) {
        FAIL_LOCKS.with(|f| f.set(fail));
    }
}

/// Every unit test in this crate that allocates secrets holds this lock, so
/// the page registry's contents can be asserted exactly. The registry tests
/// below hold it exclusively; tests in other modules hold it shared.
#[cfg(test)]
static SECRETS_TEST_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Shared guard for tests outside this module that allocate secrets.
#[cfg(test)]
pub(crate) fn secrets_test_guard() -> std::sync::RwLockReadGuard<'static, ()> {
    SECRETS_TEST_LOCK.read().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serial() -> std::sync::RwLockWriteGuard<'static, ()> {
        SECRETS_TEST_LOCK.write().unwrap_or_else(|p| p.into_inner())
    }

    fn first_page(buf: &[u8]) -> usize {
        page_span(buf).0.addr()
    }

    fn refs(addr: usize) -> usize {
        registry().get(&addr).map_or(0, |p| p.refs)
    }

    #[test]
    fn memory_debug_is_redacted() {
        let _s = serial();
        let mut src = *b"hunter2-secret";
        let len = src.len();
        let a = SecretBytes::take_from(&mut src);
        let b = SecretArray::<14>::try_init(|buf| {
            buf.copy_from_slice(b"hunter2-secret");
            Ok::<(), ()>(())
        })
        .unwrap();
        for out in [format!("{a:?}"), format!("{b:?}"), format!("{a:#?}")] {
            assert!(!out.contains("hunter2"));
            assert!(!out.contains("104")); // b'h' as a decimal byte
            assert!(!out.contains(&len.to_string()));
        }
        assert_eq!(format!("{a:?}"), "SecretBytes(<redacted>)");
        assert_eq!(format!("{b:?}"), "SecretArray(<redacted>)");
    }

    #[test]
    fn memory_take_from_wipes_source() {
        let _s = serial();
        let mut src = [7u8; 40];
        let s = SecretBytes::take_from(&mut src);
        assert_eq!(src, [0u8; 40]);
        assert_eq!(s.expose_secret(), &[7u8; 40][..]);
        assert_eq!(s.len(), 40);
        assert!(!s.is_empty());
    }

    #[test]
    fn memory_try_init_passes_error_through() {
        let _s = serial();
        let r = SecretBytes::try_init(16, |buf| {
            buf[0] = 1;
            Err::<(), _>("init failed")
        });
        assert_eq!(r.err(), Some("init failed"));
        let r = SecretArray::<16>::try_init(|_| Err::<(), _>(3u8));
        assert_eq!(r.err(), Some(3));
    }

    #[test]
    fn memory_random_fills() {
        let _s = serial();
        let a = SecretArray::<32>::random().unwrap();
        let b = SecretBytes::random(32).unwrap();
        assert_ne!(a.expose_secret(), &[0u8; 32]);
        assert_ne!(a.expose_secret()[..], b.expose_secret()[..]);
    }

    #[test]
    fn memory_mutation_through_expose() {
        let _s = serial();
        let mut a = SecretBytes::zeroed(3);
        a.expose_secret_mut().copy_from_slice(&[1, 2, 3]);
        assert_eq!(a.expose_secret(), &[1, 2, 3]);
        let mut k = SecretArray::<2>::zeroed();
        k.expose_secret_mut()[1] = 9;
        assert_eq!(k.expose_secret(), &[0, 9]);
    }

    #[test]
    fn memory_empty_is_locked_without_pages() {
        let _s = serial();
        let before = registry().len();
        let e = SecretBytes::zeroed(0);
        let z = SecretArray::<0>::zeroed();
        assert!(e.is_locked() && z.is_locked());
        assert!(e.is_empty());
        assert_eq!(registry().len(), before);
    }

    #[test]
    fn memory_shared_pages_are_refcounted() {
        let _s = serial();
        let baseline = registry().len();
        let mut bufs: Vec<SecretBytes> = (0..32).map(|_| SecretBytes::zeroed(8)).collect();
        assert!(bufs.iter().all(SecretBytes::is_locked));

        // Small allocations from one thread share pages; find such a pair.
        let (i, j) = (0..bufs.len())
            .flat_map(|i| (i + 1..bufs.len()).map(move |j| (i, j)))
            .find(|&(i, j)| {
                first_page(bufs[i].expose_secret()) == first_page(bufs[j].expose_secret())
            })
            .expect("32 small allocations should share a page");
        let page = first_page(bufs[j].expose_secret());
        let shared = refs(page);
        assert!(shared >= 2);

        drop(bufs.swap_remove(j));
        assert_eq!(refs(page), shared - 1);
        assert!(bufs[i].is_locked());
        assert!(registry().contains_key(&page));

        drop(bufs);
        assert_eq!(registry().len(), baseline);
    }

    #[test]
    fn memory_multi_page_buffer_registers_every_page() {
        let _s = serial();
        let baseline = registry().len();
        let page = region::page::size();
        let s = SecretBytes::zeroed(3 * page);
        assert!(s.is_locked());
        let (first, count, _) = page_span(s.expose_secret());
        assert!(count >= 3);
        for k in 0..count {
            assert!(refs(first.wrapping_byte_add(k * page).addr()) >= 1);
        }
        drop(s);
        assert_eq!(registry().len(), baseline);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn memory_pages_are_locked_by_the_kernel() {
        fn vm_lck_kib() -> u64 {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let line = status.lines().find(|l| l.starts_with("VmLck:")).unwrap();
            line.split_whitespace().nth(1).unwrap().parse().unwrap()
        }
        let _s = serial();
        let before = vm_lck_kib();
        let s = SecretBytes::zeroed(64 * 1024);
        assert!(s.is_locked());
        assert!(vm_lck_kib() >= before + 64);
        drop(s);
        assert!(vm_lck_kib() < before + 64);
    }

    #[test]
    fn memory_lock_failure_is_reported() {
        let _s = serial();
        let baseline = registry().len();
        let failures = memory_protection().lock_failures;

        inject::set_lock_failure(true);
        let a = SecretBytes::zeroed(64);
        let k = SecretArray::<32>::zeroed();
        inject::set_lock_failure(false);

        assert!(!a.is_locked() && !k.is_locked());
        assert_eq!(memory_protection().lock_failures, failures + 2);
        assert!(memory_protection().is_reduced());
        assert_eq!(registry().len(), baseline);
        drop((a, k));
        assert_eq!(registry().len(), baseline);
    }
}
