// SPDX-License-Identifier: AGPL-3.0-or-later

//! Headless workspace tests through the real controller and core, with a
//! fake OS (lifecycle and a recording clipboard). All values are synthetic.
// Tests fail loudly on fixture errors; never touch an existing user vault.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crate::controller::{Action, AppError, Controller, FormEpoch, InputField, Phase, private_dir};
use crate::views;
use crate::workspace::{ConfirmKind, CopyKey, Pane, Report, RevealKey, Screen, WsAction, WsField};
use qv_core::platform::autofill;
use qv_core::platform::*;
use qv_core::{FieldKind, SecretBytes};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) static KDF: Mutex<()> = Mutex::new(());
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) const PASSWORD: &str = "K4L!c8vP2zR9qT7W6nM5";
const SECRET: &str = "s3cret-canary-value";

#[derive(Default)]
pub(crate) struct Os {
    callbacks: Mutex<Vec<(u64, LockCallback)>>,
    next: AtomicU64,
    pub(crate) holds: Mutex<Vec<Vec<u8>>>,
    pub(crate) cancelled: AtomicU64,
    pub(crate) no_clipboard: AtomicBool,
}
struct Guard(Arc<Os>, u64);
impl Watch for Guard {}
impl Drop for Guard {
    fn drop(&mut self) {
        self.0
            .callbacks
            .lock()
            .unwrap()
            .retain(|(i, _)| *i != self.1);
    }
}
pub(crate) struct Platform(pub(crate) Arc<Os>);
impl Lifecycle for Platform {
    fn watch(&self, callback: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
        let id = self.0.next.fetch_add(1, Ordering::SeqCst);
        self.0.callbacks.lock().unwrap().push((id, callback));
        Ok(Box::new(Guard(self.0.clone(), id)))
    }
}
impl Clipboard for Platform {
    fn hold(
        &self,
        value: SecretBytes,
        timeout: Duration,
        cancel: Cancellation,
        progress: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        self.0
            .holds
            .lock()
            .unwrap()
            .push(value.expose_secret().to_vec());
        // Twenty fast ticks stand in for the 20 s hold.
        for left in (0..timeout.as_secs()).rev() {
            if cancel() {
                self.0.cancelled.fetch_add(1, Ordering::SeqCst);
                return Err(PlatformError::Cancelled);
            }
            progress(left)?;
            std::thread::sleep(Duration::from_millis(15));
        }
        Ok(())
    }
}
impl PlatformServices for Platform {
    fn status(&self) -> ProtectionStatus {
        ProtectionStatus {
            storage: Evidence::Unknown,
            swap: Evidence::Unknown,
            hibernation: Evidence::Unknown,
            lifecycle: true,
            clipboard: !self.0.no_clipboard.load(Ordering::SeqCst),
            quick_unlock: false,
        }
    }
    fn lifecycle(&self) -> &dyn Lifecycle {
        self
    }
    fn clipboard(&self) -> &dyn Clipboard {
        self
    }
    fn secure_input(&self) -> &dyn SecureInput {
        &Unavailable
    }
    fn keystore(&self) -> &dyn Keystore {
        &Unavailable
    }
}
impl Os {
    pub(crate) fn screen_lock(&self) {
        let callbacks: Vec<_> = self
            .callbacks
            .lock()
            .unwrap()
            .iter()
            .map(|(_, c)| c.clone())
            .collect();
        for c in callbacks {
            c(LockEvent::ScreenLocked);
        }
    }
}
pub(crate) struct Env {
    pub(crate) c: Controller,
    pub(crate) os: Arc<Os>,
    pub(crate) dir: PathBuf,
}
impl Drop for Env {
    fn drop(&mut self) {
        self.c.lock();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl Env {
    pub(crate) fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "qv-ws-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        private_dir(&dir).unwrap();
        let os = Arc::new(Os::default());
        let c = Controller::new(dir.clone(), Arc::new(Platform(os.clone()))).unwrap();
        Self { c, os, dir }
    }
    pub(crate) fn epoch(&self) -> FormEpoch {
        self.c.snapshot().epoch
    }
    pub(crate) fn fill(&self, field: InputField, value: &str) {
        let mut v = value.to_owned();
        self.c.input(self.epoch(), field, &mut v);
        assert!(v.is_empty());
    }
    pub(crate) fn put(&self, field: WsField, value: &str) {
        let mut v = value.to_owned();
        self.c.ws_input(self.epoch(), field, &mut v);
        assert!(v.is_empty());
    }
    pub(crate) fn wait(&self) {
        let end = Instant::now() + Duration::from_secs(60);
        while self.c.snapshot().busy && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!self.c.snapshot().busy, "operation deadline");
    }
    pub(crate) fn act(&self, action: WsAction) {
        self.c.act(self.epoch(), action);
        self.wait();
    }
    pub(crate) fn error(&self) -> Option<AppError> {
        self.c.status(self.epoch()).and_then(|s| s.1)
    }
    pub(crate) fn notice(&self) -> Option<&'static str> {
        self.c.status(self.epoch()).and_then(|s| s.0)
    }
    pub(crate) fn report(&self) -> Option<Report> {
        self.c.status(self.epoch()).and_then(|s| s.2)
    }
    pub(crate) fn screen(&self) -> Screen {
        self.c.screen(self.epoch()).expect("unlocked workspace")
    }
    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&qv_core::Session) -> Result<T, qv_core::CoreError>,
    ) -> T {
        self.c
            .read(self.epoch(), f)
            .expect("readable")
            .expect("core read")
    }
    /// Create the default vault, record a skip, and land in the workspace.
    pub(crate) fn unlocked() -> Self {
        let env = Self::new();
        env.fill(InputField::Password, PASSWORD);
        env.fill(InputField::Repeat, PASSWORD);
        env.c.submit(env.epoch(), Action::Create, true).unwrap();
        env.wait();
        assert_eq!(env.c.snapshot().phase, Phase::Phrase);
        env.c.submit(env.epoch(), Action::SkipPhrase, true).unwrap();
        env.wait();
        assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
        env
    }
    pub(crate) fn unlock(&self, password: &str) {
        self.fill(InputField::Password, password);
        self.c.submit(self.epoch(), Action::Unlock, true).unwrap();
        self.wait();
    }
    /// Add an entry titled `title` with a protected password through the form.
    pub(crate) fn add_entry(&self, title: &str, secret: &str) -> qv_core::EntryHandle {
        let root = self.read(|s| s.root());
        self.act(WsAction::NewEntry(root));
        assert_eq!(self.screen(), Screen::EditEntry);
        self.act(WsAction::StartAs(Some(crate::editor::ItemType::Login)));
        self.put(WsField::Title, title);
        let form = self.c.entry_form(self.epoch()).unwrap();
        let pw = form.rows.iter().find(|r| r.protected).unwrap().index;
        let user = form
            .rows
            .iter()
            .find(|r| crate::editor::same_slot(&r.name, "username"))
            .unwrap()
            .index;
        self.put(WsField::FieldValue(user), "alice@example.test");
        self.put(WsField::Replacement(pw), secret);
        self.act(WsAction::SaveEntry);
        assert_eq!(self.error(), None);
        match self.screen() {
            Screen::Entry(e) => e,
            _ => panic!("saved entry screen"),
        }
    }
}
fn field(v: &views::EntryView, name: &str) -> views::FieldRow {
    // Template names are capitalised ("Username", "Website" for "url").
    v.fields
        .iter()
        .find(|f| crate::editor::same_slot(&f.name, name))
        .unwrap()
        .clone()
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn workspace_navigation_reveal_expiry_stale_epoch_and_lock() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    assert_eq!(env.screen(), Screen::Browse(None));
    let e = env.add_entry("Mail", SECRET);
    assert_eq!(env.notice(), Some("Saved."));
    let view = env.read(|s| views::entry(s, e));
    let pw = field(&view, "password");
    assert!(pw.protected && pw.value.is_none());
    assert_eq!(
        field(&view, "username")
            .value
            .as_deref()
            .map(String::as_str),
        Some("alice@example.test")
    );
    let key = RevealKey::Field(pw.handle);
    assert!(env.c.revealed(env.epoch(), &key).is_none());
    env.act(WsAction::Reveal(key.clone()));
    assert_eq!(
        env.c.revealed(env.epoch(), &key).unwrap().expose_secret(),
        SECRET.as_bytes()
    );
    assert!(env.c.snapshot().live.reveal);
    // Expiry after 30 s.
    env.c.with_ws(env.epoch(), |ws, _| {
        let value = crate::workspace::protect(SECRET.as_bytes()).unwrap();
        Controller::set_reveal(ws, key.clone(), value);
    });
    {
        let mut s = env.c.state();
        let ws = s.workspace.as_mut().unwrap();
        crate::workspace::backdate_reveal(ws, Duration::from_secs(31));
    }
    assert!(!env.c.snapshot().live.reveal);
    assert!(env.c.revealed(env.epoch(), &key).is_none());
    // Reveal clears on navigation; stale epochs do nothing.
    env.act(WsAction::Reveal(key.clone()));
    let old = env.epoch();
    env.c.navigate(old, Screen::Trash);
    assert_eq!(env.screen(), Screen::Trash);
    assert!(env.c.revealed(env.epoch(), &key).is_none());
    env.c.navigate(old, Screen::Generator);
    env.c
        .act(old, WsAction::Delete(qv_core::ItemHandle::Entry(e)));
    let mut late = "late".to_owned();
    env.c.ws_input(old, WsField::Query, &mut late);
    assert!(late.is_empty());
    assert_eq!(env.screen(), Screen::Trash);
    assert_eq!(env.read(views::trash).items.len(), 0);
    env.c.back(env.epoch());
    assert_eq!(env.screen(), Screen::Entry(e));
    // Search bound and results over non-protected data only.
    env.c.navigate(env.epoch(), Screen::Search);
    env.put(WsField::Query, &"q".repeat(257));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    assert!(
        env.c
            .peek(env.epoch(), |ws| ws.input(WsField::Query).is_empty())
            .unwrap()
    );
    let (_, hits) = env.read(|s| views::search(s, "alice"));
    assert_eq!(hits.len(), 1);
    let (_, none) = env.read(|s| views::search(s, SECRET));
    assert!(none.is_empty());
    // Lock drops the workspace and its handles.
    env.os.screen_lock();
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
    assert!(env.c.screen(env.epoch()).is_none());
    assert!(env.c.state().workspace.is_none());
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn workspace_late_worker_result_after_lock_is_dropped() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let applied = Arc::new(AtomicBool::new(false));
    let flag = applied.clone();
    env.c
        .run_op(env.epoch(), None, move |_, _, _| {
            let _ = wait.recv_timeout(Duration::from_secs(10));
            Ok(crate::workspace::on_ws(move |_| {
                flag.store(true, Ordering::SeqCst)
            }))
        })
        .unwrap();
    assert!(env.c.snapshot().busy);
    assert_eq!(
        env.c
            .run_op(env.epoch(), None, |_, _, _| Ok(crate::workspace::on_ws(
                |_| {}
            ))),
        Err(AppError::Busy)
    );
    env.c.lock();
    assert!(env.c.snapshot().status.contains("in progress"));
    go.send(()).unwrap();
    env.wait();
    assert!(!applied.load(Ordering::SeqCst));
    assert!(env.c.state().workspace.is_none());
}

#[test]
fn releasing_the_worker_advances_the_revision_so_refused_reads_rerender() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    env.c.0.working.store(true, Ordering::SeqCst);
    let worker = crate::controller::Worker(env.c.0.clone());
    let busy = env.c.snapshot();
    // A screen rendered now gets no data; memoized screens re-render only on
    // a revision change, so the release itself must advance it.
    assert!(env.c.read(busy.epoch, views::overview).is_none());
    drop(worker);
    let idle = env.c.snapshot();
    assert!(!idle.busy);
    assert_ne!(idle.revision, busy.revision);
    assert!(matches!(
        env.c.read(idle.epoch, views::overview),
        Some(Ok(_))
    ));
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn workspace_phrase_screen_survives_short_idle_and_locks_with_explanation() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::new();
    env.fill(InputField::Password, PASSWORD);
    env.fill(InputField::Repeat, PASSWORD);
    env.c.submit(env.epoch(), Action::Create, true).unwrap();
    env.wait();
    assert_eq!(env.c.snapshot().phase, Phase::Phrase);
    env.c.state().active = Instant::now() - Duration::from_secs(61);
    assert_eq!(env.c.snapshot().phase, Phase::Phrase);
    env.c.state().active = Instant::now() - Duration::from_secs(301);
    let view = env.c.snapshot();
    assert_eq!(view.phase, Phase::Locked);
    assert!(view.status.contains("Show recovery phrase"));
    // A phrase unlock offers (does not force) a new password.
    let env = Env::unlocked();
    let phrase = {
        let s = env.c.state();
        let session = s.session.clone().unwrap();
        drop(s);
        session
            .recovery_phrase(&qv_core::MasterPassword::from_utf8(PASSWORD.as_bytes()).unwrap())
            .unwrap()
    };
    env.c.lock();
    env.c
        .select_mode(env.epoch(), crate::controller::Mode::Recover);
    env.fill(InputField::Phrase, phrase.expose_secret());
    env.c.submit(env.epoch(), Action::Recover, true).unwrap();
    env.wait();
    assert_eq!(env.screen(), Screen::Settings(Pane::Password));
    assert!(env.notice().unwrap().contains("recovery phrase"));
    env.c.navigate(env.epoch(), Screen::Browse(None));
    assert_eq!(env.screen(), Screen::Browse(None));
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn edit_bounds_blank_replacement_protection_fields_and_groups() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let e = env.add_entry("Bank", SECRET);
    env.act(WsAction::EditEntry(e));
    let form = env.c.entry_form(env.epoch()).unwrap();
    assert!(!form.new);
    let pw = form.rows.iter().find(|r| r.protected).unwrap().index;
    assert!(form.rows.iter().all(|r| !r.protected || r.value.is_none()));
    // Oversize and NUL inputs are refused and never stored.
    env.put(WsField::Title, &"t".repeat(crate::workspace::LINE_MAX + 1));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.put(WsField::Notes, "a\0b");
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.put(
        WsField::Replacement(pw),
        &"x".repeat(crate::workspace::MULTI_MAX + 1),
    );
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    // Typed then blanked replacement means unchanged.
    env.put(WsField::Replacement(pw), "temporary");
    env.put(WsField::Replacement(pw), "");
    env.put(WsField::Notes, "multi\nline");
    env.put(WsField::NewFieldName, "pin");
    env.act(WsAction::AddField(Some(FieldKind::Secret)));
    env.put(WsField::NewFieldName, "note2");
    env.act(WsAction::AddField(Some(FieldKind::Text)));
    // Adding without a typed name names the field after its kind.
    env.act(WsAction::AddField(Some(FieldKind::Email)));
    assert_eq!(env.error(), None);
    let form = env.c.entry_form(env.epoch()).unwrap();
    assert!(form.rows.iter().any(|r| *r.name == "Email"));
    let pin = form.rows.iter().find(|r| *r.name == "pin").unwrap();
    assert!(pin.protected);
    let pin = pin.index;
    env.act(WsAction::GenerateInto(pin));
    assert!(env.c.entry_form(env.epoch()).unwrap().rows[usize::from(pin)].generated);
    let note2 = form.rows.iter().find(|r| *r.name == "note2").unwrap().index;
    env.act(WsAction::RemoveField(note2));
    let url = form
        .rows
        .iter()
        .find(|r| crate::editor::same_slot(&r.name, "url"))
        .unwrap()
        .index;
    env.act(WsAction::ToggleProtect(url));
    env.act(WsAction::SaveEntry);
    assert_eq!(env.error(), None);
    let view = env.read(|s| views::entry(s, e));
    let pw_field = field(&view, "password");
    let value = env.read(|s| {
        s.reveal(pw_field.handle)
            .map(|v| v.expose_secret().to_vec())
    });
    assert_eq!(value, SECRET.as_bytes());
    assert!(field(&view, "url").protected);
    assert!(view.fields.iter().all(|f| *f.name != "note2"));
    assert_eq!(
        view.notes.as_deref().map(String::as_str),
        Some("multi\nline")
    );
    let pin_value = env.read(|s| {
        s.reveal(field(&view, "pin").handle)
            .map(|v| v.expose_secret().len())
    });
    assert!(pin_value >= 8);
    // Empty title refuses to save and keeps the form.
    env.act(WsAction::EditEntry(e));
    env.put(WsField::Title, "");
    env.act(WsAction::SaveEntry);
    assert_eq!(env.error(), Some(AppError::NameRequired));
    assert_eq!(env.screen(), Screen::EditEntry);
    // Groups: create, rename, move, delete with recursive confirmation.
    let root = env.read(|s| s.root());
    env.c.navigate(env.epoch(), Screen::Browse(None));
    env.act(WsAction::NewGroup(root));
    env.put(WsField::GroupName, "Work");
    env.act(WsAction::SaveGroup);
    let Screen::Browse(Some(g)) = env.screen() else {
        panic!("group screen")
    };
    env.act(WsAction::RenameGroup(g));
    env.put(WsField::GroupName, "Office");
    env.act(WsAction::SaveGroup);
    assert_eq!(
        &*env
            .read(|s| views::browse(s, Some(g)))
            .crumbs
            .last()
            .unwrap()
            .1,
        "Office"
    );
    env.act(WsAction::MoveTo(qv_core::ItemHandle::Entry(e), g));
    assert_eq!(env.read(|s| views::browse(s, Some(g))).entries.len(), 1);
    env.c.navigate(env.epoch(), Screen::Browse(Some(g)));
    env.act(WsAction::Delete(qv_core::ItemHandle::Group(g)));
    assert_eq!(
        env.c.pending(env.epoch()),
        Some(ConfirmKind::DeleteRecursive)
    );
    env.act(WsAction::Answer(false));
    assert_eq!(env.read(views::trash).items.len(), 0);
    env.act(WsAction::Delete(qv_core::ItemHandle::Group(g)));
    env.act(WsAction::Answer(true));
    assert_eq!(env.notice(), Some("Moved to the trash."));
    let trash = env.read(views::trash);
    assert!(!trash.items.is_empty());
    env.act(WsAction::Restore(trash.items[0].item));
    assert!(env.read(views::trash).items.len() < trash.items.len());
}

// 0012 §1: Snapshot disk growth
#[test]
fn trash_empty_needs_confirmation_snapshot_and_over_budget_consent() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let e = env.add_entry("Old", SECRET);
    env.act(WsAction::Delete(qv_core::ItemHandle::Entry(e)));
    env.c.navigate(env.epoch(), Screen::Trash);
    env.act(WsAction::EmptyTrash);
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::EmptyTrash));
    env.act(WsAction::Answer(false));
    assert_eq!(env.read(views::trash).items.len(), 1);
    env.act(WsAction::EmptyTrash);
    env.act(WsAction::Answer(true));
    assert_eq!(env.report(), Some(Report::Purged { purged: 1, kept: 0 }));
    assert!(env.read(views::trash).items.is_empty());
    assert!(!env.read(views::snapshots).0.is_empty());
    // A budget refusal asks once; refusal changes nothing, consent retries
    // the same action with the over-budget permission.
    let e = env.add_entry("Again", SECRET);
    env.act(WsAction::Delete(qv_core::ItemHandle::Entry(e)));
    env.c.navigate(env.epoch(), Screen::Trash);
    env.c
        .run_op(env.epoch(), Some(WsAction::EmptyTrash), |_, _, _| {
            Err(AppError::Core(qv_core::CoreError::SnapshotOverBudget {
                needed: 5,
            }))
        })
        .unwrap();
    env.wait();
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::OverBudget(5)));
    env.act(WsAction::Answer(false));
    assert_eq!(env.read(views::trash).items.len(), 1);
    env.c
        .run_op(env.epoch(), Some(WsAction::EmptyTrash), |_, _, _| {
            Err(AppError::Core(qv_core::CoreError::SnapshotOverBudget {
                needed: 5,
            }))
        })
        .unwrap();
    env.wait();
    env.act(WsAction::Answer(true));
    assert_eq!(env.report(), Some(Report::Purged { purged: 1, kept: 0 }));
}

// 0012 §1: Rotation/purge ambiguity
#[test]
fn records_history_snapshot_restore_archive_merge_conflict_resolve_verify() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let e = env.add_entry("Shared", SECRET);
    // History: an edit retains the previous version; restore it.
    env.act(WsAction::EditEntry(e));
    env.put(WsField::Title, "Shared v2");
    env.act(WsAction::SaveEntry);
    let rows = env.read(|s| views::history(s, e));
    assert_eq!(rows.len(), 1);
    let old = env.read(|s| views::history_version(s, e, &rows[0].version));
    assert_eq!(&*old.title, "Shared");
    env.c.navigate(
        env.epoch(),
        Screen::HistoryVersion(e, rows[0].version.clone()),
    );
    let pw = field(&old, "password");
    env.act(WsAction::Reveal(RevealKey::History(
        rows[0].version.clone(),
        pw.id,
    )));
    assert_eq!(
        env.c
            .revealed(
                env.epoch(),
                &RevealKey::History(rows[0].version.clone(), pw.id)
            )
            .unwrap()
            .expose_secret(),
        SECRET.as_bytes()
    );
    env.act(WsAction::RestoreHistory(e, rows[0].version.clone(), false));
    assert_eq!(&*env.read(|s| views::entry(s, e)).title, "Shared");
    env.act(WsAction::PurgeHistory(e));
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::PurgeHistory));
    env.act(WsAction::Answer(true));
    assert!(env.notice().unwrap().contains("suppressed"));
    // Snapshot restore into a branch, diverge, export there, merge here.
    env.c.lock();
    env.unlock(PASSWORD);
    let (snaps, _) = env.read(views::snapshots);
    assert!(!snaps.is_empty());
    let branch = env.dir.join("vaults/branch.qvault");
    env.c.navigate(env.epoch(), Screen::Snapshots);
    env.put(WsField::Path, branch.to_str().unwrap());
    env.act(WsAction::RestoreSnapshot("0".repeat(32)));
    assert!(env.error().is_some());
    assert!(!branch.exists());
    env.put(WsField::Path, "relative.qvault");
    env.act(WsAction::RestoreSnapshot(snaps[0].id.clone()));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.put(WsField::Path, branch.to_str().unwrap());
    env.act(WsAction::RestoreSnapshot(snaps[0].id.clone()));
    assert_eq!(env.error(), None);
    assert!(branch.exists());
    // Never overwrite: the same target is refused.
    env.act(WsAction::RestoreSnapshot(snaps[0].id.clone()));
    assert!(env.error().is_some());
    let exports = env.dir.join("exports");
    private_dir(&exports).unwrap();
    let file = {
        let core = env.c.core().unwrap();
        let remote = core
            .unlock(
                &branch,
                &qv_core::MasterPassword::from_utf8(PASSWORD.as_bytes()).unwrap(),
                None,
            )
            .unwrap();
        let re = match remote.search("Shared").unwrap().remove(0) {
            qv_core::SearchHit::Entry(x) => x.handle,
            _ => panic!(),
        };
        let mut d = remote.edit_entry(re).unwrap();
        d.entry_mut().title = qv_core::Text::new("remote title").unwrap();
        remote.save_entry(d).unwrap();
        let r = remote.export_archive(&exports, false, None).unwrap();
        remote.lock();
        exports.join(format!("{}.qvsnap", r.archive_id))
    };
    let le = match env.read(|s| s.search("Shared")).remove(0) {
        qv_core::SearchHit::Entry(x) => x.handle,
        _ => panic!(),
    };
    env.act(WsAction::EditEntry(le));
    env.put(WsField::Title, "local title");
    env.act(WsAction::SaveEntry);
    env.c.navigate(env.epoch(), Screen::Archives);
    env.put(WsField::Path, file.to_str().unwrap());
    env.act(WsAction::MergeArchive);
    let Some(Report::Merge {
        accepted: true,
        conflicts,
        ..
    }) = env.report()
    else {
        panic!("merge report {:?}", env.error())
    };
    assert!(conflicts >= 1);
    // Conflicted entries refuse copy and edit until resolved.
    let view = env.read(|s| views::entry(s, le));
    assert!(view.versions > 1);
    env.act(WsAction::Copy(CopyKey::Field(
        le,
        field(&view, "password").handle,
    )));
    assert_eq!(env.error(), Some(AppError::Conflict));
    assert!(env.os.holds.lock().unwrap().is_empty());
    env.act(WsAction::EditEntry(le));
    assert_eq!(env.error(), Some(AppError::Conflict));
    let rows = env.read(views::conflicts);
    let row = rows.iter().find(|r| r.kind == "Entry").unwrap().clone();
    let versions = env.read(|s| views::conflict_record(s, &row.record));
    assert_eq!(versions.len(), 2);
    let pick = versions
        .iter()
        .find(|v| v.details.iter().any(|(_, t)| **t == "remote title"))
        .unwrap();
    env.c
        .navigate(env.epoch(), Screen::ConflictRecord(row.record.clone()));
    env.act(WsAction::Resolve(row.record.clone(), pick.version.clone()));
    assert_eq!(
        env.c.pending(env.epoch()),
        Some(ConfirmKind::Resolve(false))
    );
    env.act(WsAction::Answer(true));
    assert!(
        matches!(env.report(), Some(Report::Resolved { .. })),
        "{:?}",
        env.error()
    );
    assert_eq!(&*env.read(|s| views::entry(s, le)).title, "remote title");
    // Export, then verify.
    env.c.navigate(env.epoch(), Screen::Archives);
    env.put(WsField::Path, exports.to_str().unwrap());
    env.act(WsAction::ExportArchive(true));
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::SelfContained));
    env.act(WsAction::Answer(true));
    assert!(matches!(
        env.report(),
        Some(Report::Export {
            self_contained: true,
            ..
        })
    ));
    env.c.navigate(env.epoch(), Screen::Settings(Pane::Verify));
    env.act(WsAction::Verify);
    let Some(Report::Verify { ok, anchor, .. }) = env.report() else {
        panic!("verify report")
    };
    assert!(ok);
    assert_eq!(anchor, "verified");
}

// 0012 §1: Impossible generator
#[test]
fn generator_display_expiry_impossible_settings_and_saved_defaults() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    env.c.navigate(env.epoch(), Screen::Generator);
    env.act(WsAction::Generate);
    let (value, bits) = env.c.generated(env.epoch()).unwrap();
    assert_eq!(value.expose_secret().len(), 24);
    assert!(bits > 100.0);
    env.act(WsAction::GenMode(crate::workspace::GenMode::Pin));
    assert!(env.c.generated(env.epoch()).is_none());
    env.put(WsField::GenLength, "3");
    env.act(WsAction::Generate);
    assert!(env.error().is_some());
    assert!(env.c.generated(env.epoch()).is_none());
    env.put(WsField::GenLength, "abc");
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.act(WsAction::GenMode(crate::workspace::GenMode::Words));
    env.put(WsField::GenWords, "7");
    env.put(WsField::GenSeparator, "-");
    env.act(WsAction::Generate);
    // EFF words contain hyphens, so core refuses that separator.
    assert!(env.error().is_some());
    env.put(WsField::GenSeparator, "_");
    env.act(WsAction::Generate);
    let (value, _) = env
        .c
        .generated(env.epoch())
        .unwrap_or_else(|| panic!("{:?}", env.error()));
    assert_eq!(
        std::str::from_utf8(value.expose_secret())
            .unwrap()
            .split('_')
            .count(),
        7
    );
    env.act(WsAction::SaveGeneratorDefaults);
    assert_eq!(env.notice(), Some("Generator defaults saved."));
    env.c.navigate(env.epoch(), Screen::Browse(None));
    env.c.navigate(env.epoch(), Screen::Generator);
    let form = env.c.generator_form(env.epoch()).unwrap();
    assert_eq!(form.mode, crate::workspace::GenMode::Words);
    assert_eq!(form.words, 7);
    {
        let mut s = env.c.state();
        crate::workspace::backdate_generated(
            s.workspace.as_mut().unwrap(),
            Duration::from_secs(31),
        );
    }
    let _ = env.c.snapshot();
    assert!(env.c.generated(env.epoch()).is_none());
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn clipboard_copy_replace_lock_cancel_and_unavailable() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let e = env.add_entry("Copy", SECRET);
    let view = env.read(|s| views::entry(s, e));
    let pw = field(&view, "password");
    env.act(WsAction::Copy(CopyKey::Field(e, pw.handle)));
    assert_eq!(env.error(), None);
    env.act(WsAction::Copy(CopyKey::Field(
        e,
        field(&view, "username").handle,
    )));
    let end = Instant::now() + Duration::from_secs(5);
    while env.os.holds.lock().unwrap().len() < 2 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
    }
    {
        let holds = env.os.holds.lock().unwrap();
        assert_eq!(holds[0], SECRET.as_bytes());
        assert_eq!(holds[1], b"alice@example.test");
    }
    assert!(env.c.snapshot().live.clipboard > 0);
    let end = Instant::now() + Duration::from_secs(5);
    while env.os.cancelled.load(Ordering::SeqCst) < 1 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(env.os.cancelled.load(Ordering::SeqCst), 1);
    env.c.lock();
    let end = Instant::now() + Duration::from_secs(5);
    while env.os.cancelled.load(Ordering::SeqCst) < 2 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(env.os.cancelled.load(Ordering::SeqCst), 2);
    env.unlock(PASSWORD);
    // Handles from the locked session are stale; read them again.
    let e = match env.read(|s| s.search("Copy")).remove(0) {
        qv_core::SearchHit::Entry(x) => x.handle,
        _ => panic!(),
    };
    let pw = field(&env.read(|s| views::entry(s, e)), "password");
    env.os.no_clipboard.store(true, Ordering::SeqCst);
    env.act(WsAction::Copy(CopyKey::Field(e, pw.handle)));
    assert_eq!(env.error(), Some(AppError::ClipboardUnavailable));
    assert_eq!(env.os.holds.lock().unwrap().len(), 2);
}

// 0012 §1: Mixed credentials
#[test]
fn security_settings_password_change_phrase_redisplay_and_rotation() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    env.c.navigate(env.epoch(), Screen::Settings(Pane::General));
    env.put(WsField::VaultName, "Renamed vault");
    env.put(WsField::HistoryDepth, "5");
    env.put(WsField::TrashDays, "x");
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.act(WsAction::SaveSettings);
    assert_eq!(env.notice(), Some("Settings saved."));
    assert_eq!(&*env.read(views::overview).name, "Renamed vault");
    // A freshly created vault has no pre-unlock header; an unlock captures it.
    assert!(env.c.about(env.epoch()).is_none());
    env.c.lock();
    env.unlock(PASSWORD);
    let about = env.c.about(env.epoch()).expect("about header");
    assert_eq!(about.vault_id.len(), 32);
    assert_eq!(about.key_generation, 1);
    // Password change: mismatch refused, weak needs confirmation.
    env.c
        .navigate(env.epoch(), Screen::Settings(Pane::Password));
    env.put(WsField::NewPassword, "new password one");
    env.put(WsField::Repeat, "different");
    env.act(WsAction::ChangePassword);
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.put(WsField::NewPassword, "password");
    env.put(WsField::Repeat, "password");
    env.act(WsAction::ChangePassword);
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::WeakPassword));
    env.act(WsAction::Answer(false));
    const NEW: &str = "Zq7!mV2#wL9$kR4^tB6&";
    env.put(WsField::NewPassword, NEW);
    env.put(WsField::Repeat, NEW);
    env.act(WsAction::ChangePassword);
    assert!(
        env.notice().unwrap().starts_with("Master password changed"),
        "{:?}",
        env.error()
    );
    if let Some(ConfirmKind::OldSnapshots(_)) = env.c.pending(env.epoch()) {
        env.act(WsAction::Answer(false));
    }
    env.c.lock();
    env.unlock(PASSWORD);
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
    env.unlock(NEW);
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    // Phrase redisplay needs the current password.
    env.c.navigate(env.epoch(), Screen::Settings(Pane::Phrase));
    env.put(WsField::Password, PASSWORD);
    env.act(WsAction::ShowPhrase);
    assert!(env.error().is_some());
    assert!(env.c.phrase_screen(env.epoch()).is_none());
    env.put(WsField::Password, NEW);
    env.act(WsAction::ShowPhrase);
    let screen = env.c.phrase_screen(env.epoch()).unwrap();
    let words = env.c.phrase_words(env.epoch()).unwrap();
    let words: Vec<String> = std::str::from_utf8(words.expose_secret())
        .unwrap()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    assert_eq!(words.len(), 24);
    for (i, p) in screen.positions.iter().enumerate() {
        env.put(WsField::Word(u8::try_from(i).unwrap()), "wrong");
        let _ = p;
    }
    env.act(WsAction::ConfirmWords);
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    for (i, p) in screen.positions.iter().enumerate() {
        env.put(WsField::Word(u8::try_from(i).unwrap()), &words[p - 1]);
    }
    env.act(WsAction::ConfirmWords);
    assert!(env.c.phrase_screen(env.epoch()).unwrap().confirmed);
    env.act(WsAction::HidePhrase);
    assert!(env.c.phrase_screen(env.epoch()).is_none());
    // Rotation: typed confirmation, new phrase checked, then install locks.
    env.c
        .navigate(env.epoch(), Screen::Settings(Pane::Rotation));
    const ROTATED: &str = "Hx3@pN8*cD5!yF1%gJ7(";
    env.put(WsField::NewPassword, ROTATED);
    env.put(WsField::Repeat, ROTATED);
    env.act(WsAction::BeginRotation);
    assert_eq!(env.error(), Some(AppError::Consent));
    env.put(WsField::Confirmation, "rotate");
    env.put(WsField::NewPassword, ROTATED);
    env.put(WsField::Repeat, ROTATED);
    env.act(WsAction::BeginRotation);
    // The prepared rotation consumed the session and awaits its new phrase.
    let view = env.c.snapshot();
    assert_eq!(
        view.phase,
        Phase::Rotation,
        "{:?} {}",
        env.c.snapshot().error,
        view.status
    );
    assert!(env.c.screen(env.epoch()).is_none());
    assert!(!view.rotation_confirmed);
    // Install refuses before confirmation; cancelling changes nothing.
    assert_eq!(
        env.c.submit(env.epoch(), Action::InstallRotation, false),
        Err(AppError::InvalidInput)
    );
    env.c
        .submit(env.epoch(), Action::CancelRotation, false)
        .unwrap();
    assert!(env.c.snapshot().status.contains("nothing changed"));
    env.unlock(NEW);
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    env.c
        .navigate(env.epoch(), Screen::Settings(Pane::Rotation));
    env.put(WsField::Confirmation, "rotate");
    env.put(WsField::NewPassword, ROTATED);
    env.put(WsField::Repeat, ROTATED);
    env.act(WsAction::BeginRotation);
    let view = env.c.snapshot();
    assert_eq!(view.phase, Phase::Rotation);
    let words = env.c.phrase(env.epoch()).unwrap();
    let words: Vec<String> = std::str::from_utf8(words.expose_secret())
        .unwrap()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    assert_eq!(words.len(), 24);
    for (field, p) in [InputField::Word0, InputField::Word1, InputField::Word2]
        .into_iter()
        .zip(view.positions)
    {
        env.fill(field, "wrong");
        let _ = p;
    }
    assert!(
        env.c
            .submit(env.epoch(), Action::ConfirmRotation, false)
            .is_err()
    );
    for (field, p) in [InputField::Word0, InputField::Word1, InputField::Word2]
        .into_iter()
        .zip(env.c.snapshot().positions)
    {
        env.fill(field, &words[p - 1]);
    }
    env.c
        .submit(env.epoch(), Action::ConfirmRotation, false)
        .unwrap();
    assert!(env.c.snapshot().rotation_confirmed);
    env.c
        .submit(env.epoch(), Action::InstallRotation, false)
        .unwrap();
    env.wait();
    let view = env.c.snapshot();
    assert_eq!(view.phase, Phase::Locked);
    assert!(
        view.status.contains("Key rotation complete"),
        "{}",
        view.status
    );
    env.unlock(NEW);
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
    env.unlock(ROTATED);
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn attachments_follow_path_rules_and_round_trip_where_ancestors_are_safe() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let e = env.add_entry("Files", SECRET);
    let input = env.dir.join("input.bin");
    std::fs::write(&input, b"attachment-bytes").unwrap();
    env.c.navigate(env.epoch(), Screen::Attachments(e));
    env.put(WsField::Path, "relative.bin");
    env.act(WsAction::AddAttachment(e));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.put(WsField::Path, input.to_str().unwrap());
    env.act(WsAction::AddAttachment(e));
    let safe = ancestors_safe(&input);
    if !safe {
        // This host's ancestors fail the 0011 §4 owner rule: refusal is correct.
        assert_eq!(env.error(), Some(AppError::InvalidInput));
        return;
    }
    assert_eq!(env.error(), None);
    let rows = env.read(|s| views::attachments(s, e));
    assert_eq!(rows.len(), 1);
    assert_eq!(&*rows[0].name, "input.bin");
    let out = env.dir.join("output.bin");
    env.put(WsField::Path, out.to_str().unwrap());
    env.act(WsAction::SaveAttachment(rows[0].handle));
    assert_eq!(
        env.c.pending(env.epoch()),
        Some(ConfirmKind::SaveAttachment)
    );
    env.act(WsAction::Answer(true));
    assert_eq!(env.notice(), Some("Attachment saved."));
    assert_eq!(std::fs::read(&out).unwrap(), b"attachment-bytes");
    // Never overwrite an existing destination.
    env.act(WsAction::SaveAttachment(rows[0].handle));
    env.act(WsAction::Answer(true));
    assert!(env.error().is_some() || env.notice().is_some_and(|n| n.contains("incomplete")));
    assert_eq!(std::fs::read(&out).unwrap(), b"attachment-bytes");
    env.act(WsAction::RemoveAttachment(rows[0].handle));
    env.act(WsAction::Answer(true));
    assert!(env.read(|s| views::attachments(s, e)).is_empty());
}
pub(crate) fn ancestors_safe(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX);
    path.ancestors().skip(1).all(|a| {
        std::fs::metadata(a)
            .is_ok_and(|s| s.mode() & 0o022 == 0 && (s.uid() == 0 || s.uid() == euid))
    })
}

#[test]
fn password_change_consent_has_a_rust_deadline_and_tracks_candidate_and_epoch() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    env.c
        .navigate(env.epoch(), Screen::Settings(Pane::Password));
    env.put(WsField::NewPassword, "password");
    env.put(WsField::Repeat, "password");
    env.act(WsAction::ChangePassword);
    assert_eq!(env.c.snapshot().live.weak_seconds, 5);
    env.act(WsAction::Answer(true));
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::WeakPassword));
    assert!(env.notice().is_none());
    env.put(WsField::Repeat, "different");
    assert!(env.c.pending(env.epoch()).is_none());
    env.put(WsField::Repeat, "password");
    env.act(WsAction::ChangePassword);
    env.c.with_ws(env.epoch(), |ws, _| {
        ws.weak_until = Some(Instant::now() - Duration::from_secs(1))
    });
    env.act(WsAction::Answer(true));
    assert!(
        env.notice()
            .is_some_and(|n| n.starts_with("Master password changed"))
    );
    let stale = env.epoch();
    env.c.back(stale);
    env.c.act(stale, WsAction::Answer(true));
    env.c.lock();
    env.unlock("password");
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    env.c
        .navigate(env.epoch(), Screen::Settings(Pane::Password));
    env.act(WsAction::SuggestPassword);
    let (value, bits) = env.c.generated(env.epoch()).unwrap();
    assert_eq!(
        std::str::from_utf8(value.expose_secret())
            .unwrap()
            .split('.')
            .count(),
        6
    );
    assert!(bits >= 70.0);
    env.c.navigate(env.epoch(), Screen::Browse(None));
    assert!(env.c.generated(env.epoch()).is_none());
}
#[test]
fn generator_preserves_require_each_class_through_ui_and_saved_defaults() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    env.c.navigate(env.epoch(), Screen::Generator);
    env.act(WsAction::GenToggle(crate::workspace::GenFlag::Each));
    env.act(WsAction::SaveGeneratorDefaults);
    let qv_core::GeneratorSettings::Characters(c) = env.read(|s| s.generator_defaults()) else {
        panic!("character defaults");
    };
    assert!(!c.require_each_class);
    env.c.navigate(env.epoch(), Screen::Browse(None));
    env.c.navigate(env.epoch(), Screen::Generator);
    assert!(!env.c.generator_form(env.epoch()).unwrap().flags[7]);
}

#[test]
fn quick_unlock_unavailable_never_falls_back_or_opens_a_session() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    env.c
        .navigate(env.epoch(), Screen::Settings(Pane::Password));
    env.put(WsField::Password, PASSWORD);
    env.act(WsAction::EnrollQuick(
        qv_core::platform::QuickPolicy::Class3,
    ));
    assert!(env.error().is_some());
    assert!(!env.c.protection().quick_unlock);
    env.act(WsAction::EnrollQuick(
        qv_core::platform::QuickPolicy::DeviceCredential,
    ));
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::ReducedQuick));
    env.act(WsAction::Answer(false));
    env.c.lock();
    env.c
        .submit(env.epoch(), Action::QuickUnlock, true)
        .unwrap();
    env.wait();
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
    assert!(env.c.snapshot().error.is_some());
}

type FillEvent = (i64, Option<Vec<u8>>, Option<Vec<u8>>);
static FILLS: Mutex<Vec<FillEvent>> = Mutex::new(Vec::new());
static CANCELS: Mutex<Vec<i64>> = Mutex::new(Vec::new());
static NATIVE: AtomicU64 = AtomicU64::new(1);
struct TestSink;
impl crate::autofill::AutofillSink for TestSink {
    fn complete(&self, native: i64, u: Option<&SecretBytes>, p: Option<&SecretBytes>) -> bool {
        if CANCELS.lock().unwrap().contains(&native) {
            return false;
        }
        let copy = |v: Option<&SecretBytes>| v.map(|v| v.expose_secret().to_vec());
        FILLS.lock().unwrap().push((native, copy(u), copy(p)));
        true
    }
    fn cancel(&self, native: i64) {
        CANCELS.lock().unwrap().push(native);
    }
}
fn native() -> i64 {
    crate::autofill::set_sink(Box::new(TestSink));
    NATIVE.fetch_add(1, Ordering::SeqCst) as i64
}
fn filled(native: i64) -> Option<FillEvent> {
    FILLS
        .lock()
        .unwrap()
        .iter()
        .find(|f| f.0 == native)
        .cloned()
}
fn cancelled(native: i64) -> bool {
    CANCELS.lock().unwrap().contains(&native)
}
fn both() -> autofill::Roles {
    autofill::Roles {
        username: true,
        password: true,
    }
}
fn bank_app() -> autofill::FillRequest {
    autofill::FillRequest::new("com.bank.app", &[7; 32], None, None, both()).unwrap()
}
fn find(env: &Env, id: &str) -> qv_core::EntryHandle {
    match env.read(|s| s.find_id(id, false))[0] {
        qv_core::ItemHandle::Entry(e) => e,
        _ => panic!("entry"),
    }
}

#[test]
fn autofill_request_waits_for_unlock_and_needs_link_confirmation_and_choice() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    // The title names the requesting app and service: it must not matter.
    let id = env.add_entry("com.bank.app Bank", SECRET).id_hex();
    env.c.lock();
    let n = native();
    let request = bank_app();
    env.c
        .autofill_offer(n, request.requester(&[]), request.roles);
    assert!(env.c.autofill_banner().unwrap().contains("com.bank.app"));
    // Survives the lock it is waiting on, then binds on unlock.
    env.c.lock();
    assert!(!cancelled(n));
    env.unlock(PASSWORD);
    assert_eq!(env.screen(), Screen::Autofill);
    assert!(env.c.autofill_banner().is_none());
    let requester = env.c.autofill_view().unwrap().requester;
    assert!(env.read(|s| s.autofill_candidates(&requester)).is_empty());
    // Linking is a separately confirmed action and still requires a choice.
    let entry = find(&env, &id);
    env.act(WsAction::AutofillLink(entry));
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::LinkApp));
    env.act(WsAction::Answer(true));
    assert_eq!(env.error(), None);
    assert!(filled(n).is_none());
    let found = env.read(|s| s.autofill_candidates(&requester));
    assert_eq!(found.len(), 1);
    env.act(WsAction::AutofillFill(found[0].key()));
    assert_eq!(env.error(), None);
    let (_, user, pass) = filled(n).unwrap();
    assert_eq!(user.unwrap(), b"alice@example.test");
    assert_eq!(pass.unwrap(), SECRET.as_bytes());
    assert!(env.c.autofill_view().is_none());
    assert!(!cancelled(n));
}

#[test]
fn autofill_bound_request_is_cancelled_by_lock_and_late_fill_is_refused() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let id = env.add_entry("Bank", SECRET).id_hex();
    let request = bank_app();
    let entry = find(&env, &id);
    env.read(|s| s.link_app(entry, &request.app));
    // Offered while unlocked: binds immediately.
    let n = native();
    env.c
        .autofill_offer(n, request.requester(&[]), request.roles);
    assert_eq!(env.screen(), Screen::Autofill);
    let requester = env.c.autofill_view().unwrap().requester;
    let key = env.read(|s| s.autofill_candidates(&requester))[0].key();
    env.c.lock();
    assert!(cancelled(n));
    env.unlock(PASSWORD);
    assert_ne!(env.screen(), Screen::Autofill);
    assert!(env.c.autofill_view().is_none());
    env.act(WsAction::AutofillFill(key));
    assert_eq!(env.error(), Some(AppError::AutofillExpired));
    assert!(filled(n).is_none());

    // A waiting request expires; unlocking then neither binds nor fills.
    env.c.lock();
    let n = native();
    env.c
        .autofill_offer(n, request.requester(&[]), request.roles);
    env.c.age_autofill(qv_core::platform::autofill::REQUEST_TTL);
    assert!(env.c.autofill_banner().is_none());
    env.unlock(PASSWORD);
    assert_ne!(env.screen(), Screen::Autofill);
    assert!(cancelled(n));

    // Explicit cancel abandons a bound request.
    let n = native();
    env.c
        .autofill_offer(n, request.requester(&[]), request.roles);
    env.act(WsAction::AutofillCancel);
    assert!(cancelled(n));
    assert_eq!(env.screen(), Screen::Browse(None));
}

#[test]
fn autofill_untrusted_origin_claim_lists_no_web_entries() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let id = env.add_entry("Bank", SECRET).id_hex();
    let entry = find(&env, &id);
    env.c.navigate(env.epoch(), Screen::Entry(entry));
    let mut d = env.read(|s| s.edit_entry(entry));
    d.add_field(
        "Website",
        FieldKind::Url,
        qv_core::FieldValue::text("https://bank.example").unwrap(),
    )
    .unwrap();
    env.read(|s| s.save_entry(d));
    const BROWSER: &[autofill::TrustedBrowser] = &[autofill::TrustedBrowser {
        package: "org.example.browser",
        signers: &[[9; 32]],
    }];
    let claim = |package: &str, signer: u8, host: &str| {
        autofill::FillRequest::new(package, &[signer; 32], Some("https"), Some(host), both())
            .unwrap()
            .requester(BROWSER)
    };
    for spoof in [
        claim("com.evil.webview", 9, "bank.example"),
        claim("org.example.browser", 8, "bank.example"),
        claim("org.example.browser", 9, "bank.example.evil.test"),
        claim("org.example.browser", 9, "evilbank.example"),
    ] {
        assert!(env.read(|s| s.autofill_candidates(&spoof)).is_empty());
    }
    let trusted = claim("org.example.browser", 9, "bank.example");
    let n = native();
    env.c.autofill_offer(n, trusted, both());
    assert!(
        env.c
            .autofill_view()
            .unwrap()
            .label
            .contains("https://bank.example")
    );
    assert!(env.c.autofill_view().unwrap().app.is_none());
    let requester = env.c.autofill_view().unwrap().requester;
    let found = env.read(|s| s.autofill_candidates(&requester));
    assert_eq!(found.len(), 1);
    env.act(WsAction::AutofillFill(found[0].key()));
    assert_eq!(filled(n).unwrap().2.unwrap(), SECRET.as_bytes());
}

#[test]
fn layout_list_context_select_and_more_keep_navigation_rules() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    let a = env.add_entry("Alpha", SECRET);
    let b = env.add_entry("Beta", "other-canary");
    assert_eq!(env.c.list_context(env.epoch()), Some(Screen::Browse(None)));
    // A list selection replaces the open entry, so Back returns to the list.
    env.c.navigate(env.epoch(), Screen::Browse(None));
    env.c.navigate(env.epoch(), Screen::Entry(b));
    env.c.select(env.epoch(), Screen::Entry(a));
    assert_eq!(env.screen(), Screen::Entry(a));
    env.c.back(env.epoch());
    assert_eq!(env.screen(), Screen::Browse(None));
    // From a list it is an ordinary navigation.
    env.c.select(env.epoch(), Screen::Entry(a));
    assert_eq!(env.screen(), Screen::Entry(a));
    env.c.back(env.epoch());
    assert_eq!(env.screen(), Screen::Browse(None));
    // A detail screen keeps the list it was opened from, and a form keeps it too.
    env.c.navigate(env.epoch(), Screen::Search);
    env.c.select(env.epoch(), Screen::Entry(b));
    assert_eq!(env.c.list_context(env.epoch()), Some(Screen::Search));
    env.c.navigate(env.epoch(), Screen::History(b));
    assert_eq!(env.c.list_context(env.epoch()), Some(Screen::Search));
    env.act(WsAction::EditEntry(b));
    assert_eq!(env.screen(), Screen::EditEntry);
    assert!(env.screen().is_form());
    assert_eq!(env.c.list_context(env.epoch()), Some(Screen::Search));
    // A select during a form is an ordinary navigation (the UI disables the
    // rows); the form is discarded like any navigation, never saved.
    env.put(WsField::Title, "Unsaved title");
    env.c.select(env.epoch(), Screen::Entry(a));
    assert_eq!(env.screen(), Screen::Entry(a));
    assert_eq!(env.read(|s| views::entry(s, b)).title.as_str(), "Beta");
    // More is an ordinary screen; stale epochs and lock behave as everywhere.
    let old = env.epoch();
    env.c.navigate(old, Screen::More);
    assert_eq!(env.screen(), Screen::More);
    env.c.select(old, Screen::Trash);
    assert_eq!(env.screen(), Screen::More);
    env.c.lock();
    assert!(env.c.screen(env.epoch()).is_none());
    assert!(env.c.list_context(env.epoch()).is_none());
}

#[test]
fn shortcuts_run_only_existing_actions_and_escape_never_confirms() {
    use crate::workspace::Shortcut;
    assert_eq!(Shortcut::from_key("Escape", false), Some(Shortcut::Escape));
    assert_eq!(Shortcut::from_key("Escape", true), None);
    assert_eq!(Shortcut::from_key("f", true), Some(Shortcut::Search));
    assert_eq!(Shortcut::from_key("F", true), Some(Shortcut::Search));
    assert_eq!(Shortcut::from_key("f", false), None);
    assert_eq!(Shortcut::from_key("n", true), Some(Shortcut::NewEntry));
    assert_eq!(Shortcut::from_key("l", true), Some(Shortcut::Lock));
    assert_eq!(Shortcut::from_key("s", true), Some(Shortcut::Save));
    assert_eq!(Shortcut::from_key("x", true), None);
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::unlocked();
    // Locked: nothing is handled.
    let locked = Env::new();
    assert!(!locked.c.shortcut(locked.epoch(), Shortcut::Lock));
    assert!(!locked.c.shortcut(locked.epoch(), Shortcut::Search));
    // New entry in the listed group, Escape cancels the form, Save saves.
    assert!(env.c.shortcut(env.epoch(), Shortcut::NewEntry));
    env.wait();
    assert_eq!(env.screen(), Screen::EditEntry);
    assert!(env.c.shortcut(env.epoch(), Shortcut::Escape));
    assert_eq!(env.screen(), Screen::Browse(None));
    assert!(env.read(views::overview).entries == 0);
    assert!(!env.c.shortcut(env.epoch(), Shortcut::Escape));
    assert!(!env.c.shortcut(env.epoch(), Shortcut::Save));
    assert!(env.c.shortcut(env.epoch(), Shortcut::NewEntry));
    env.wait();
    // Save does nothing in the start step; the type is chosen first.
    assert!(env.c.shortcut(env.epoch(), Shortcut::Save));
    env.wait();
    assert_eq!(env.error(), Some(AppError::NameRequired));
    assert_eq!(env.screen(), Screen::EditEntry);
    env.act(WsAction::StartAs(Some(crate::editor::ItemType::Note)));
    env.put(WsField::Title, "Keyboard");
    assert!(env.c.shortcut(env.epoch(), Shortcut::Save));
    env.wait();
    let e = match env.screen() {
        Screen::Entry(e) => e,
        other => panic!("saved entry screen, got {other:?}"),
    };
    // Search, and stale epochs do nothing.
    let old = env.epoch();
    assert!(env.c.shortcut(old, Shortcut::Search));
    assert_eq!(env.screen(), Screen::Search);
    assert!(!env.c.shortcut(old, Shortcut::Escape));
    assert_eq!(env.screen(), Screen::Search);
    // Escape answers a pending question with "no".
    env.c.navigate(env.epoch(), Screen::Entry(e));
    env.act(WsAction::Delete(qv_core::ItemHandle::Entry(e)));
    env.c.navigate(env.epoch(), Screen::Trash);
    env.act(WsAction::EmptyTrash);
    assert_eq!(env.c.pending(env.epoch()), Some(ConfirmKind::EmptyTrash));
    assert!(env.c.shortcut(env.epoch(), Shortcut::Escape));
    env.wait();
    assert_eq!(env.c.pending(env.epoch()), None);
    assert_eq!(env.screen(), Screen::Trash);
    assert_eq!(env.read(views::trash).items.len(), 1);
    // While a task runs only Lock applies.
    env.c.0.working.store(true, Ordering::SeqCst);
    assert!(!env.c.shortcut(env.epoch(), Shortcut::Search));
    assert!(!env.c.shortcut(env.epoch(), Shortcut::Escape));
    assert_eq!(env.screen(), Screen::Trash);
    env.c.0.working.store(false, Ordering::SeqCst);
    assert!(env.c.shortcut(env.epoch(), Shortcut::Lock));
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
}

#[test]
fn protection_acknowledgement_is_explicit_remembered_and_status_bound() {
    use crate::prefs::{Prefs, Theme};
    let env = Env::new();
    // The fake platform cannot establish storage/swap/hibernation: reduced.
    assert!(env.c.protection_ack_needed());
    assert!(!env.c.consent());
    // Unlocking without the acknowledgement is refused like the old checkbox.
    env.fill(InputField::Password, PASSWORD);
    env.fill(InputField::Repeat, PASSWORD);
    assert_eq!(
        env.c.submit(env.epoch(), Action::Create, env.c.consent()),
        Err(AppError::Consent)
    );
    env.c.acknowledge_protection().unwrap();
    assert!(env.c.consent());
    // Remembered across controllers through the private preferences file.
    let stored = Prefs::load(&env.dir);
    assert!(stored.protection.is_some());
    assert_eq!(stored.theme, Theme::Dark);
    // A different stored status asks again.
    Prefs {
        theme: Theme::Light,
        protection: Some("svwvhvl1c1p0".into()),
    }
    .save(&env.dir)
    .unwrap();
    let again = Controller::new(env.dir.clone(), Arc::new(Platform(env.os.clone()))).unwrap();
    assert!(again.protection_ack_needed());
    assert_eq!(again.theme(), Theme::Light);
    again.set_theme(Theme::System).unwrap();
    assert_eq!(Prefs::load(&env.dir).theme, Theme::System);
    again.lock();
}

/// Create a vault by name only and land in its workspace (plan 0041).
fn create_named(env: &Env, name: &str) -> Result<(), AppError> {
    env.c
        .select_mode(env.epoch(), crate::controller::Mode::Create);
    env.fill(InputField::Name, name);
    env.fill(InputField::Password, PASSWORD);
    env.fill(InputField::Repeat, PASSWORD);
    env.c.submit(env.epoch(), Action::Create, true).unwrap();
    env.wait();
    if let Some(e) = env.c.snapshot().error {
        return Err(e);
    }
    assert_eq!(env.c.snapshot().phase, Phase::Phrase);
    env.c.submit(env.epoch(), Action::SkipPhrase, true).unwrap();
    env.wait();
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    Ok(())
}

#[test]
fn vaults_are_created_by_name_listed_selected_and_imported_in_place() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::new();
    assert!(!env.c.app_vault_exists());
    create_named(&env, " Personal ").unwrap();
    let folder = env.dir.join("vaults");
    assert!(folder.join("Personal.qvault").is_file());
    env.c.lock();
    create_named(&env, "Work").unwrap();
    env.c.lock();
    let names = |env: &Env| {
        env.c
            .vaults()
            .into_iter()
            .map(|v| v.name)
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&env), ["Work", "Personal"]);
    assert_eq!(env.c.selected_vault().unwrap().name, "Work");
    assert!(env.c.vaults().iter().all(|v| v.exists && v.in_folder));

    // A duplicate or unusable name is refused and the file is untouched.
    let before = std::fs::read(folder.join("Work.qvault")).unwrap();
    assert_eq!(create_named(&env, "Work"), Err(AppError::VaultExists));
    assert_eq!(std::fs::read(folder.join("Work.qvault")).unwrap(), before);
    assert_eq!(create_named(&env, "a/b"), Err(AppError::VaultName));
    assert_eq!(create_named(&env, ".hidden"), Err(AppError::VaultName));

    // Unlock the other vault through the selection, which survives a lock.
    env.c
        .select_mode(env.epoch(), crate::controller::Mode::Unlock);
    env.c
        .select_vault(env.epoch(), &folder.join("Personal.qvault"));
    env.c.lock();
    assert_eq!(env.c.selected_vault().unwrap().name, "Personal");
    // An unlisted path cannot be selected.
    env.c
        .select_vault(env.epoch(), &env.dir.join("elsewhere.qvault"));
    assert_eq!(env.c.selected_vault().unwrap().name, "Personal");
    env.unlock(PASSWORD);
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    assert_eq!(env.c.open_vault().unwrap().name, "Personal");
    env.c.lock();

    // Import references a file where it is.
    let outside = env.dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::copy(folder.join("Work.qvault"), outside.join("Copy.qvault")).unwrap();
    env.c
        .import_vault(env.epoch(), &outside.join("Copy.qvault"));
    assert_eq!(env.c.snapshot().error, None);
    let copy = env.c.selected_vault().unwrap();
    assert_eq!((copy.name.as_str(), copy.in_folder), ("Copy", false));
    assert_eq!(names(&env), ["Copy", "Personal", "Work"]);
    // A vault that moved away is reported, never recreated, and can be removed.
    std::fs::remove_file(outside.join("Copy.qvault")).unwrap();
    assert!(!env.c.selected_vault().unwrap().exists);
    env.fill(InputField::Password, PASSWORD);
    env.c.submit(env.epoch(), Action::Unlock, true).unwrap();
    env.wait();
    assert_eq!(env.c.snapshot().error, Some(AppError::VaultMissing));
    assert!(!outside.join("Copy.qvault").exists());
    env.c
        .forget_vault(env.epoch(), &outside.join("Copy.qvault"));
    assert_eq!(names(&env), ["Personal", "Work"]);
    // Not a vault file, or not there: refused, nothing listed.
    std::fs::write(outside.join("notes.txt"), b"x").unwrap();
    env.c.import_vault(env.epoch(), &outside.join("notes.txt"));
    assert_eq!(env.c.snapshot().error, Some(AppError::InvalidInput));
    env.c
        .import_vault(env.epoch(), &outside.join("none.qvault"));
    assert_eq!(env.c.snapshot().error, Some(AppError::VaultMissing));
    assert_eq!(names(&env).len(), 2);

    // The list file survives a restart of the app.
    let again = Controller::new(env.dir.clone(), Arc::new(Platform(env.os.clone()))).unwrap();
    let listed: Vec<String> = again.vaults().into_iter().map(|v| v.name).collect();
    assert_eq!(listed, ["Personal", "Work"]);
    // A default folder must be an existing absolute directory.
    assert_eq!(
        again.set_default_folder(std::path::Path::new("rel")),
        Err(AppError::InvalidInput)
    );
    assert_eq!(
        again.set_default_folder(&outside.join("notes.txt")),
        Err(AppError::InvalidInput)
    );
    again.set_default_folder(&outside).unwrap();
    assert_eq!(
        crate::vaults::VaultList::load(&env.dir).folder.as_deref(),
        Some(outside.as_path())
    );
}

#[test]
fn the_vault_name_is_the_stored_one_and_files_are_never_renamed() {
    let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
    let env = Env::new();
    create_named(&env, "Personal").unwrap();
    let file = env.dir.join("vaults/Personal.qvault");
    // Rename in Settings: the stored (synced) name changes, the file does not.
    env.c.navigate(env.epoch(), Screen::Settings(Pane::General));
    env.put(WsField::VaultName, "Home");
    env.act(WsAction::SaveSettings);
    assert_eq!(env.error(), None);
    assert_eq!(env.read(views::overview).name.as_str(), "Home");
    env.c.lock();
    let v = env.c.selected_vault().unwrap();
    assert_eq!(
        (v.name.as_str(), v.file.as_str()),
        ("Home", "Personal.qvault")
    );
    assert!(file.is_file());
    assert!(!env.dir.join("vaults/Home.qvault").exists());
    // The copy survives a restart; an imported vault shows its file name
    // until it is opened here.
    let again = Controller::new(env.dir.clone(), Arc::new(Platform(env.os.clone()))).unwrap();
    assert_eq!(again.selected_vault().unwrap().name, "Home");
    let outside = env.dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::copy(&file, outside.join("Spare.qvault")).unwrap();
    env.c
        .import_vault(env.epoch(), &outside.join("Spare.qvault"));
    assert_eq!(env.c.selected_vault().unwrap().name, "Spare");
    env.unlock(PASSWORD);
    env.c.lock();
    let v = env.c.selected_vault().unwrap();
    assert_eq!((v.name.as_str(), v.file.as_str()), ("Home", "Spare.qvault"));
}
