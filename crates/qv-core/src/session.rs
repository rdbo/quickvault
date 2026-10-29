// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sessions, handles and cancellation (spec 0008 §1.4, §4.1).
//!
//! A [`Session`] owns one unlocked vault and its metadata index behind a
//! mutex. Every call takes the mutex for its whole duration, so calls are
//! serialized. [`Session::lock`] first raises a flag that every running call
//! checks between units of work, then takes the mutex and drops the vault
//! and the index (VK, keys, connection and every retained text zeroize on
//! drop). A locked session never unlocks again, so nothing can repopulate
//! it: a late result finds no state to write to, and a read that saw the
//! flag returns [`CoreError::Cancelled`] instead of its data.
//!
//! Handles carry the session's random 128-bit tag. Their fields are private
//! to this crate, so frontends cannot forge them; a handle of another
//! session is [`CoreError::StaleHandle`], and every call after a lock is
//! [`CoreError::SessionLocked`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use qv_crypto::RecordId;
use qv_model::{FieldId, Timestamp, VersionId};
use qv_store::{AnchorStatus, LocationWarnings, UnlockedVault};

use crate::error::CoreError;
use crate::index::{Index, MAX_VIEW_BYTES};
use crate::setup::TimeSource;
use crate::snapshot::{SnapshotPolicy, SnapshotReport};

/// Lets a caller cancel an unlock or streaming attachment operation in progress.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A token that is not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses a shared cancellation flag, for integration with signal/event loops.
    pub fn from_shared_flag(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }

    /// Cancels every operation watching this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`Self::cancel`] was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl core::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CancelToken({})", self.is_cancelled())
    }
}

/// A session's random tag.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SessionTag([u8; 16]);

macro_rules! handle_debug {
    ($($t:ident),+) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(..)"))
            }
        }
    )+};
}

/// An entry of one unlocked session.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryHandle {
    pub(crate) session: SessionTag,
    pub(crate) record: RecordId,
}

/// A group of one unlocked session.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupHandle {
    pub(crate) session: SessionTag,
    pub(crate) record: RecordId,
}

/// An entry or a group.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemHandle {
    /// An entry.
    Entry(EntryHandle),
    /// A group.
    Group(GroupHandle),
}

/// One field of one version of an entry. Naming the version makes the
/// choice explicit when an entry is in conflict (0005 §2.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldHandle {
    pub(crate) entry: EntryHandle,
    pub(crate) version: VersionId,
    pub(crate) field: FieldId,
}

handle_debug!(EntryHandle, GroupHandle, ItemHandle, FieldHandle);

impl EntryHandle {
    /// The entry's record ID as 32 lowercase hex digits (0011 §2.2 `@id`).
    /// IDs are metadata, not secrets.
    pub fn id_hex(&self) -> String {
        crate::setup::hex(&self.record.0)
    }
}

impl GroupHandle {
    /// The group's record ID as 32 lowercase hex digits.
    pub fn id_hex(&self) -> String {
        crate::setup::hex(&self.record.0)
    }
}

impl FieldHandle {
    /// Stable field identity, not a reveal capability without its version handle.
    pub fn field_id(&self) -> FieldId {
        self.field
    }
    /// The entry this field belongs to.
    pub fn entry(&self) -> EntryHandle {
        self.entry
    }
}

impl ItemHandle {
    /// The item's record ID as 32 lowercase hex digits.
    pub fn id_hex(&self) -> String {
        match self {
            Self::Entry(h) => h.id_hex(),
            Self::Group(h) => h.id_hex(),
        }
    }

    pub(crate) fn tag(&self) -> SessionTag {
        match self {
            Self::Entry(h) => h.session,
            Self::Group(h) => h.session,
        }
    }
}

/// The state of an unlocked session.
pub(crate) struct Open {
    pub(crate) vault: UnlockedVault,
    pub(crate) index: Index,
    /// Opened for recovery with a missing or mismatched anchor; writes stay
    /// blocked until `adopt_baseline`.
    pub(crate) read_only: bool,
    /// The head-versus-anchor comparison made at unlock, reported by
    /// [`Session::verify`] (0011 §4). It is not re-derived per call: the
    /// store re-checks and advances the anchor on every successful write.
    pub(crate) anchor: AnchorStatus,
    /// The local snapshot policy, when the frontend configured one
    /// (0007 §3.3).
    pub(crate) snapshots: Option<Arc<SnapshotPolicy>>,
    /// The automatic-policy outcome, for the frontend's stderr warnings
    /// (0011 §4).
    pub(crate) auto_snapshot: Option<SnapshotReport>,
    /// The archive ID of the recovery snapshot an in-progress destructive
    /// operation pins (0007 §3.2). Shared with the operation's handle so
    /// that dropping the handle releases the pin.
    pub(crate) pin: Arc<Mutex<Option<String>>>,
}

impl Open {
    /// The archive ID currently pinned by an in-progress operation.
    pub(crate) fn pinned(&self) -> Option<String> {
        self.pin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// What a call sees while it holds the session.
pub(crate) struct Ctx<'a> {
    pub(crate) open: &'a mut Open,
    session: &'a Session,
    /// Set when the index can no longer be trusted to match the vault; the
    /// session locks itself when the call returns (fail closed).
    pub(crate) poison: bool,
}

/// Checks for a lock request without borrowing the call's state.
#[derive(Clone, Copy)]
pub(crate) struct Canceller<'a>(&'a AtomicBool);

impl Canceller<'_> {
    /// [`CoreError::Cancelled`] once a lock was requested.
    pub(crate) fn check(&self) -> Result<(), CoreError> {
        if self.0.load(Ordering::SeqCst) {
            Err(CoreError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Whether a lock was requested, for the store's cancellation callbacks.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl<'a> Ctx<'a> {
    /// A lock-request check that outlives borrows of `open`.
    pub(crate) fn canceller(&self) -> Canceller<'a> {
        Canceller(&self.session.locking)
    }

    /// [`CoreError::Cancelled`] once a lock was requested.
    pub(crate) fn check_cancel(&self) -> Result<(), CoreError> {
        self.canceller().check()
    }

    /// The configured clock's time.
    pub(crate) fn now(&self) -> Timestamp {
        self.session.time.now()
    }

    pub(crate) fn tag(&self) -> SessionTag {
        self.session.tag
    }

    /// The handle's tag must be this session's.
    pub(crate) fn own(&self, tag: SessionTag) -> Result<(), CoreError> {
        if tag == self.session.tag {
            Ok(())
        } else {
            Err(CoreError::StaleHandle)
        }
    }

    pub(crate) fn entry_handle(&self, record: RecordId) -> EntryHandle {
        EntryHandle {
            session: self.session.tag,
            record,
        }
    }

    pub(crate) fn group_handle(&self, record: RecordId) -> GroupHandle {
        GroupHandle {
            session: self.session.tag,
            record,
        }
    }
}

/// One unlocked vault. `Send + Sync`: share it with an `Arc`; every method
/// takes `&self` and calls are serialized.
pub struct Session {
    tag: SessionTag,
    locking: AtomicBool,
    state: Mutex<Option<Open>>,
    time: Arc<dyn TimeSource>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Session(<redacted>)")
    }
}

impl Session {
    /// Builds the index of a verified vault and wraps it in a session.
    pub(crate) fn open(
        vault: UnlockedVault,
        time: Arc<dyn TimeSource>,
        anchor: AnchorStatus,
        snapshots: Option<Arc<SnapshotPolicy>>,
        read_only: bool,
        cancel: Option<&crate::CancelToken>,
    ) -> Result<Session, CoreError> {
        let tag = SessionTag(qv_crypto::random_array::<16>().map_err(|_| CoreError::Rng)?);
        let index = Index::build(
            &vault,
            &|| cancel.is_some_and(CancelToken::is_cancelled),
            MAX_VIEW_BYTES,
        )?;
        // Without a policy the automatic snapshot is indistinguishable from
        // "disabled"; frontends show that as reduced protection.
        let auto_snapshot = snapshots.is_none().then(SnapshotReport::disabled);
        Ok(Session {
            tag,
            locking: AtomicBool::new(false),
            state: Mutex::new(Some(Open {
                vault,
                index,
                read_only,
                anchor,
                snapshots,
                auto_snapshot,
                pin: Arc::new(Mutex::new(None)),
            })),
            time,
        })
    }

    /// Runs a read: its result is dropped if a lock was requested meanwhile.
    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&mut Ctx<'_>) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let r = self.run(f)?;
        if self.locking.load(Ordering::SeqCst) {
            return Err(CoreError::Cancelled);
        }
        Ok(r)
    }

    /// Runs a mutation. The mutation checks for cancellation itself, before
    /// its commit; after a commit the outcome is reported as it is.
    pub(crate) fn mutate<T>(
        &self,
        f: impl FnOnce(&mut Ctx<'_>) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        self.run(f)
    }

    fn run<T>(&self, f: impl FnOnce(&mut Ctx<'_>) -> Result<T, CoreError>) -> Result<T, CoreError> {
        if self.locking.load(Ordering::SeqCst) {
            return Err(CoreError::SessionLocked);
        }
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => {
                // A call panicked while holding the session: fail closed.
                self.locking.store(true, Ordering::SeqCst);
                *p.into_inner() = None;
                return Err(CoreError::Internal);
            }
        };
        let Some(open) = guard.as_mut() else {
            return Err(CoreError::SessionLocked);
        };
        #[cfg(test)]
        hooks::reached(hooks::Point::InCall);
        let mut ctx = Ctx {
            open,
            session: self,
            poison: false,
        };
        let r = f(&mut ctx);
        if ctx.poison {
            self.locking.store(true, Ordering::SeqCst);
            *guard = None;
        }
        r
    }

    /// Locks the session (0008 §1.4): running calls stop at their next
    /// check, then the vault, keys and views are dropped and zeroized.
    /// Idempotent; a locked session stays locked.
    pub fn lock(&self) {
        self.locking.store(true, Ordering::SeqCst);
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *guard = None;
    }

    /// Whether [`Self::lock`] was called (or the session locked itself).
    pub fn is_locked(&self) -> bool {
        self.locking.load(Ordering::SeqCst)
    }

    /// Location warnings for the vault's path (0004 §1.1).
    pub fn warnings(&self) -> Result<LocationWarnings, CoreError> {
        self.read(|ctx| Ok(ctx.open.vault.warnings()))
    }

    /// Whether writes are blocked until [`Self::adopt_baseline`] (a vault
    /// opened for recovery with a missing or mismatched anchor).
    pub fn is_read_only(&self) -> Result<bool, CoreError> {
        self.read(|ctx| Ok(ctx.open.read_only))
    }

    /// Explicit recovery (0005 §5.4): accepts the current verified state as
    /// the new baseline under a new writer ID and makes the session
    /// writable. Only for a session from
    /// [`crate::Core::unlock_for_recovery`] after the user chose to accept
    /// its state.
    pub fn adopt_baseline(&self) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            ctx.check_cancel()?;
            ctx.open.vault.adopt_baseline()?;
            ctx.open.read_only = false;
            // The adopted state is the new baseline (0005 §5.4).
            ctx.open.anchor = AnchorStatus::Verified;
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) mod hooks {
    //! Test-only pause points: the calling thread arms one, and when it is
    //! reached the thread reports arrival and waits for the test.

    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Point {
        /// Inside a call, holding the session.
        InCall,
        /// A mutation, just before its commit.
        BeforeCommit,
        /// A mutation, just after its commit.
        AfterCommit,
    }

    struct Armed {
        point: Point,
        arrived: Sender<()>,
        go: Receiver<()>,
    }

    thread_local! {
        static ARMED: RefCell<Option<Armed>> = const { RefCell::new(None) };
    }

    /// Arms `point` for the current thread.
    pub(crate) fn arm(point: Point, arrived: Sender<()>, go: Receiver<()>) {
        ARMED.with(|a| *a.borrow_mut() = Some(Armed { point, arrived, go }));
    }

    pub(crate) fn reached(p: Point) {
        let armed = ARMED.with(|a| {
            let mut a = a.borrow_mut();
            if a.as_ref().is_some_and(|x| x.point == p) {
                a.take()
            } else {
                None
            }
        });
        if let Some(a) = armed {
            let _ = a.arrived.send(());
            let _ = a.go.recv();
        }
    }
}

#[cfg(test)]
mod tests {
    use qv_crypto::{RecoveryPhrase, VaultKey};
    use qv_store::{AnchorStatus, StoreError};

    use super::*;
    use crate::testutil::TestDir;
    use crate::testutil::{Env, NAME, PASSWORD, err, kdf, pw, seq};
    use crate::{Core, CoreConfig, Protection};

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn session_is_send_and_sync() {
        assert_send_sync::<Session>();
        assert_send_sync::<Core>();
        assert_send_sync::<EntryHandle>();
    }

    #[test]
    fn session_create_returns_the_phrase() {
        let env = Env::empty(TestDir::new());
        let created = {
            let _k = kdf();
            env.core().create(&env.path, &pw(PASSWORD), "Mine").unwrap()
        };
        let phrase = created.recovery_phrase;
        assert_eq!(phrase.expose_secret().split(' ').count(), 24);
        let vk = VaultKey::from_recovery_phrase(phrase.expose_secret().as_bytes()).unwrap();
        let again = RecoveryPhrase::from_vault_key(&vk).unwrap();
        let s = created.session;
        let same = s
            .read(|ctx| {
                let stored = RecoveryPhrase::from_vault_key(ctx.open.vault.vault_key()).unwrap();
                Ok(stored.expose_secret() == again.expose_secret())
            })
            .unwrap();
        assert!(same);
        assert_eq!(s.overview().unwrap().name.expose(), "Mine");
        assert_eq!(seq(&s), 1);
        assert!(!s.is_read_only().unwrap());
        assert_eq!(format!("{s:?}"), "Session(<redacted>)");
        let created_dbg = format!(
            "{:?}",
            crate::Created {
                session: s,
                recovery_phrase: phrase
            }
        );
        assert_eq!(created_dbg, "Created(<redacted>)");
    }

    #[test]
    fn session_unlock_errors() {
        let env = Env::new();
        let core = env.core();
        {
            let _k = kdf();
            assert_eq!(
                err(core.unlock(&env.path, &pw("wrong"), None)),
                CoreError::Store(StoreError::WrongPassword)
            );
        }
        let token = CancelToken::new();
        token.cancel();
        assert_eq!(
            err(core.unlock(&env.path, &pw(PASSWORD), Some(&token))),
            CoreError::Cancelled
        );
        assert_eq!(
            err(core.unlock(&env.dir.path().join("none.qvault"), &pw(PASSWORD), None)),
            CoreError::Store(StoreError::NotFound)
        );
        assert_eq!(format!("{token:?}"), "CancelToken(true)");
    }

    #[test]
    fn session_lock_is_terminal() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        assert_eq!(s.overview().unwrap().name.expose(), NAME);
        s.lock();
        s.lock();
        assert!(s.is_locked());
        assert_eq!(err(s.overview()), CoreError::SessionLocked);
        assert_eq!(err(s.list(root)), CoreError::SessionLocked);
        assert_eq!(err(s.new_group(root, "x")), CoreError::SessionLocked);
        assert_eq!(err(s.warnings()), CoreError::SessionLocked);
        assert_eq!(err(s.adopt_baseline()), CoreError::SessionLocked);
    }

    #[test]
    fn session_handles_are_scoped() {
        let env = Env::new();
        let a = env.unlock();
        let root_a = a.root().unwrap();
        drop(a);
        let b = env.unlock();
        let root_b = b.root().unwrap();
        assert_ne!(root_a, root_b);
        assert_eq!(err(b.list(root_a)), CoreError::StaleHandle);
        assert_eq!(
            err(b.new_entry(root_a, "login", "x")),
            CoreError::StaleHandle
        );
        assert!(b.list(root_b).is_ok());
        assert_eq!(format!("{root_b:?}"), "GroupHandle(..)");
        assert_eq!(format!("{:?}", ItemHandle::Group(root_b)), "ItemHandle(..)");
    }

    #[test]
    fn session_missing_anchor_needs_recovery() {
        let env = Env::new();
        for e in std::fs::read_dir(&env.anchors).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
        let core = env.core();
        let _k = kdf();
        assert_eq!(
            err(core.unlock(&env.path, &pw(PASSWORD), None)),
            CoreError::Store(StoreError::NoAnchor)
        );
        let (s, status) = core
            .unlock_for_recovery(&env.path, &pw(PASSWORD), None)
            .unwrap();
        assert_eq!(status, AnchorStatus::Missing);
        assert!(s.is_read_only().unwrap());
        let root = s.root().unwrap();
        let d = s.new_group(root, "Work").unwrap();
        assert_eq!(err(s.save_group(d)), CoreError::Store(StoreError::NoAnchor));
        assert_eq!(seq(&s), 1);
        s.adopt_baseline().unwrap();
        assert!(!s.is_read_only().unwrap());
        assert_eq!(seq(&s), 2);
        let d = s.new_group(root, "Work").unwrap();
        s.save_group(d).unwrap();
        assert_eq!(seq(&s), 3);
        drop(s);
        let s = core.unlock(&env.path, &pw(PASSWORD), None).unwrap();
        assert_eq!(s.overview().unwrap().groups, 1);
    }

    #[test]
    fn session_protection_report() {
        let env = Env::new();
        let core: Core = env.core();
        let p: Protection = core.protection();
        assert_eq!(
            p.is_reduced(),
            p.process.is_reduced() || p.memory.is_reduced()
        );
        let _ = CoreConfig::new(qv_store::AnchorDir::open(&env.anchors).unwrap());
        assert_eq!(format!("{core:?}"), "Core(..)");
    }
}

#[cfg(test)]
mod lock_tests {
    use std::sync::Arc;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    use super::hooks::{Point, arm};
    use super::*;
    use crate::testutil::{Env, add_entry, err, seq};

    /// Runs `op` on another thread, paused at `point`; locks the session
    /// while it waits, then lets it continue. Returns the operation's
    /// result.
    fn race<T: Send + 'static>(
        s: &Arc<Session>,
        point: Point,
        op: impl FnOnce(&Session) -> Result<T, CoreError> + Send + 'static,
    ) -> Result<T, CoreError> {
        let (arrived_tx, arrived) = channel();
        let (go, go_rx) = channel();
        let worker = {
            let s = s.clone();
            std::thread::spawn(move || {
                arm(point, arrived_tx, go_rx);
                op(&s)
            })
        };
        arrived.recv_timeout(Duration::from_secs(30)).unwrap();
        let locker = {
            let s = s.clone();
            std::thread::spawn(move || s.lock())
        };
        // `lock` raises its flag at once, then waits for the paused call.
        while !s.is_locked() {
            std::thread::yield_now();
        }
        go.send(()).unwrap();
        let r = worker.join().unwrap();
        locker.join().unwrap();
        assert!(s.is_locked());
        r
    }

    #[test]
    fn lock_cancels_a_running_read() {
        let env = Env::new();
        let s = Arc::new(env.unlock());
        assert_eq!(
            race(&s, Point::InCall, |s| s.search("x").map(|_| ())),
            Err(CoreError::Cancelled)
        );
        assert_eq!(err(s.search("x")), CoreError::SessionLocked);
        assert_eq!(err(s.overview()), CoreError::SessionLocked);
    }

    #[test]
    fn credentials_snapshot_deletion_reports_completed_work_after_lock() {
        for point in [Point::BeforeCommit, Point::AfterCommit] {
            let env = Env::new();
            let s = Arc::new(env.unlock_with(Some(env.snapshot_policy())));
            let id = s.snapshots().unwrap().snapshots[0].archive_id.clone();
            let path = env
                .dir
                .path()
                .join("snapshots")
                .join(format!("{id}.qvsnap"));
            assert!(path.exists());
            let result = race(&s, point, move |s| s.delete_snapshots(&[id]));
            let completed = point == Point::AfterCommit;
            assert_eq!(
                result,
                if completed {
                    Ok(1)
                } else {
                    Err(CoreError::Cancelled)
                }
            );
            assert_eq!(path.exists(), !completed);
        }
    }

    #[test]
    fn credentials_password_lock_before_and_after_commit() {
        for point in [Point::BeforeCommit, Point::AfterCommit] {
            let env = Env::new();
            let s = Arc::new(env.unlock());
            let result = race(&s, point, |s| {
                let _k = crate::testutil::kdf();
                s.change_password(&crate::testutil::pw("new password after lock race"), None)
            });
            let durable = point == Point::AfterCommit;
            assert_eq!(
                result,
                if durable {
                    Ok(())
                } else {
                    Err(CoreError::Cancelled)
                }
            );
            let _k = crate::testutil::kdf();
            let password = if durable {
                "new password after lock race"
            } else {
                crate::testutil::PASSWORD
            };
            assert!(
                env.core()
                    .unlock(&env.path, &crate::testutil::pw(password), None)
                    .is_ok()
            );
        }
    }

    #[test]
    fn snapshot_restore_lock_before_and_after_publication() {
        for point in [Point::BeforeCommit, Point::AfterCommit] {
            let env = Env::new();
            let s = Arc::new(env.unlock_with(Some(env.snapshot_policy())));
            let id = s.snapshots().unwrap().snapshots[0].archive_id.clone();
            let source = std::fs::read(&env.path).unwrap();
            let target = env.path.with_file_name("restored.qvault");
            let checked = target.clone();
            let result = race(&s, point, move |s| s.restore_snapshot(&id, &target, None));
            let durable = point == Point::AfterCommit;
            assert_eq!(
                result,
                if durable {
                    Ok(())
                } else {
                    Err(CoreError::Cancelled)
                }
            );
            assert_eq!(checked.exists(), durable);
            assert_eq!(std::fs::read(&env.path).unwrap(), source);
            assert!(s.is_locked());
            if durable {
                let core = env.core();
                let _k = crate::testutil::kdf();
                let copy = core
                    .unlock(
                        &checked,
                        &crate::testutil::pw(crate::testutil::PASSWORD),
                        None,
                    )
                    .unwrap();
                assert!(copy.verify(None).unwrap().ok());
            }
        }
    }

    #[test]
    fn attachment_lock_before_and_after_durable_commit() {
        for point in [Point::BeforeCommit, Point::AfterCommit] {
            let env = Env::new();
            let s = Arc::new(env.unlock());
            let e = add_entry(&s, s.root().unwrap(), "Files");
            let before = seq(&s);
            let result = race(&s, point, move |s| {
                s.add_attachment(e, "x", "x", &mut &vec![3; 65_537][..], None)
                    .map(|_| ())
            });
            let durable = point == Point::AfterCommit;
            assert_eq!(
                result,
                if durable {
                    Ok(())
                } else {
                    Err(CoreError::Cancelled)
                }
            );
            let again = env.unlock();
            assert_eq!(seq(&again), before + u64::from(durable));
            let fresh = again.list(again.root().unwrap()).unwrap().entries[0].handle;
            let items = again.attachments(fresh).unwrap();
            assert_eq!(items.len(), usize::from(durable));
            if durable {
                again.verify_attachment(items[0].handle, None).unwrap();
            }
        }
    }

    #[test]
    fn history_purge_lock_before_and_after_durable_commit() {
        for point in [Point::BeforeCommit, Point::AfterCommit] {
            let env = Env::new();
            let s = Arc::new(env.unlock());
            let e = add_entry(&s, s.root().unwrap(), "History");
            s.save_entry(s.edit_entry(e).unwrap()).unwrap();
            let before = seq(&s);
            let result = race(&s, point, move |s| s.purge_history(e));
            let durable = point == Point::AfterCommit;
            assert_eq!(
                result,
                if durable {
                    Ok(())
                } else {
                    Err(CoreError::Cancelled)
                }
            );
            let again = env.unlock();
            assert_eq!(seq(&again), before + u64::from(durable));
            let e = again.list(again.root().unwrap()).unwrap().entries[0].handle;
            assert_eq!(again.history(e).unwrap().len(), usize::from(!durable));
        }
    }

    #[test]
    fn lock_before_commit_cancels_the_mutation() {
        let env = Env::new();
        let s = Arc::new(env.unlock());
        let root = s.root().unwrap();
        let before = seq(&s);
        let r = race(&s, Point::BeforeCommit, move |s| {
            let d = s.new_group(root, "late")?;
            s.save_group(d).map(|_| ())
        });
        assert_eq!(r, Err(CoreError::Cancelled));
        let again = env.unlock();
        assert_eq!(seq(&again), before);
        assert_eq!(again.overview().unwrap().groups, 0);
        // A handle from before the lock is stale in the new session.
        assert_eq!(err(again.list(root)), CoreError::StaleHandle);
    }

    #[test]
    fn lock_after_commit_reports_the_commit() {
        let env = Env::new();
        let s = Arc::new(env.unlock());
        let root = s.root().unwrap();
        let before = seq(&s);
        let r = race(&s, Point::AfterCommit, move |s| {
            let d = s.new_group(root, "durable")?;
            s.save_group(d).map(|_| ())
        });
        assert_eq!(r, Ok(()));
        assert_eq!(err(s.overview()), CoreError::SessionLocked);
        let again = env.unlock();
        assert_eq!(seq(&again), before + 1);
        assert_eq!(again.overview().unwrap().groups, 1);
    }

    #[test]
    fn lock_during_a_bulk_delete_changes_nothing() {
        let env = Env::new();
        let s = Arc::new(env.unlock());
        let root = s.root().unwrap();
        let g = crate::testutil::add_group(&s, root, "G");
        for i in 0..3 {
            add_entry(&s, g, &format!("e{i}"));
        }
        let before = seq(&s);
        let r = race(&s, Point::InCall, move |s| {
            s.delete(ItemHandle::Group(g), true)
        });
        assert_eq!(r, Err(CoreError::Cancelled));
        let again = env.unlock();
        assert_eq!(seq(&again), before);
        assert!(again.trash().unwrap().is_empty());
    }
}
