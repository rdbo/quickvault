// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN sync through core (plans 0037 step 7, 0038 step 6, 0042 step 6; 0013
//! testing rows "Generation transitions", "No peer state", "Account-dependent
//! LAN sync" (loopback part), "Explicit initiation"; 0012 §1 "LAN discovery
//! mistaken for trust").

#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use qv_crypto::MasterPassword;
use qv_store::{AnchorDir, ArchiveScope, SnapshotDir, VaultFile};

use crate::lan::{
    ApproverUi, JoinCode, JoinerUi, LanError, LanTimeouts, ListenScope, LocalAcceptance, Sas,
    Served, SyncOptions, SyncReport, SyncWindow, SyncWindowOptions,
};
use crate::snapshot::SnapshotPolicy;
use crate::testutil::{Env, PASSWORD, TestDir, err, kdf, pw};
use crate::{CoreError, Session, TimeSource};
use qv_model::Text;

fn fast() -> LanTimeouts {
    LanTimeouts {
        message: Duration::from_secs(5),
        idle: Duration::from_secs(10),
        confirm: Duration::from_secs(20),
        connect: Duration::from_secs(2),
    }
}

fn options() -> SyncWindowOptions {
    SyncWindowOptions {
        scope: ListenScope::LoopbackForTests,
        limit: Duration::from_secs(30),
        timeouts: fast(),
        ..SyncWindowOptions::new()
    }
}

fn sync_options(port: u16) -> SyncOptions {
    SyncOptions {
        extra_endpoints: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)],
        allow_loopback: true,
        timeouts: fast(),
    }
}

/// The offering user: confirms a new device's code (sync never asks).
struct Yes(
    Option<String>,
    Option<Box<dyn FnMut() + Send>>,
    &'static str,
);
impl ApproverUi for Yes {
    fn master_password(&mut self, _: bool) -> Option<MasterPassword> {
        Some(pw(self.2))
    }
    fn confirm(&mut self, sas: &str, name: &str) -> bool {
        assert_eq!(name, crate::testutil::NAME);
        if let Some(f) = &mut self.1 {
            f();
        }
        self.0 = Some(sas.to_owned());
        true
    }
}

struct Joiner(Option<[u8; 6]>);
impl JoinerUi for Joiner {
    fn show_code(&mut self, sas: &Sas) -> bool {
        self.0 = Some(sas.digits());
        true
    }
    fn confirm_vault(&mut self, name: &[u8], _: &Sas) -> bool {
        assert_eq!(name, crate::testutil::NAME.as_bytes());
        true
    }
    fn master_password(&mut self) -> Option<MasterPassword> {
        Some(pw(PASSWORD))
    }
}

fn code(s: &Session) -> (SyncWindow, String, u16) {
    let w = s.open_sync_window(options()).unwrap();
    let c = w.code(&[]).unwrap();
    let manual = String::from_utf8(c.manual.expose_secret().to_vec()).unwrap();
    (w, manual, c.port)
}

fn joined_report(s: Served) -> (bool, Option<LanError>) {
    match s {
        Served::Joined {
            peer_confirmed,
            failure,
            ..
        } => (peer_confirmed, failure),
        Served::Synced(_) => panic!("not a join"),
    }
}

fn synced_report(s: Result<Served, CoreError>) -> Result<SyncReport, CoreError> {
    match s? {
        Served::Synced(r) => Ok(r),
        Served::Joined { .. } => panic!("not a sync"),
    }
}

/// Joins a new device from `a` into `b_env`'s directory with `password`.
fn join_new_with(
    a: &Session,
    b_env: &Env,
    dest: &std::path::Path,
    password: &'static str,
) -> (Served, Result<Session, CoreError>) {
    let (w, manual, port) = code(a);
    let mut yes = Yes(None, None, password);
    let mut joiner = JoinerPw(password);
    let core = b_env.core();
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(a, &mut yes, None));
        let joined = {
            let _k = kdf();
            core.join_new_device(
                JoinCode::from_manual(&manual).unwrap(),
                dest,
                sync_options(port),
                &mut joiner,
                None,
            )
        };
        (h.join().unwrap().unwrap(), joined)
    })
}

fn join_new(
    a: &Session,
    b_env: &Env,
    dest: &std::path::Path,
) -> (Served, Result<Session, CoreError>) {
    join_new_with(a, b_env, dest, PASSWORD)
}

struct JoinerPw(&'static str);
impl JoinerUi for JoinerPw {
    fn show_code(&mut self, _: &Sas) -> bool {
        true
    }
    fn confirm_vault(&mut self, _: &[u8], _: &Sas) -> bool {
        true
    }
    fn master_password(&mut self) -> Option<MasterPassword> {
        Some(pw(self.0))
    }
}

/// `lan_link` rows left in `s`'s file (0013 §9.1).
fn rows(s: &Session) -> usize {
    s.read(|ctx| Ok(ctx.open.vault.retired_lan_links()))
        .unwrap()
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_core_new_device_joins_and_neither_side_stores_the_other() {
    let a_env = Env::new();
    let a = a_env.unlock();
    let root = a.root().unwrap();
    crate::testutil::add_entry(&a, root, "shared over the LAN");
    let b_env = Env::empty(TestDir::new());
    let dest = b_env.dir.path().join("joined.qvault");
    let (served, joined) = join_new(&a, &b_env, &dest);
    let b = joined.unwrap();
    let (confirmed, failure) = joined_report(served);
    assert!(confirmed, "{failure:?}");
    let (ao, bo) = (a.overview().unwrap(), b.overview().unwrap());
    assert_eq!(ao.name.expose(), bo.name.expose());
    assert_eq!(ao.entries, bo.entries);
    assert_eq!(rows(&a) + rows(&b), 0);
}

/// Two replicas of one vault in `env` (B restored from an archive of A).
pub(super) fn replicas_with(env: &Env, policy_a: Option<SnapshotPolicy>) -> (Session, Session) {
    let a = env.unlock_with(policy_a);
    let b_path = env.dir.path().join("b.qvault");
    a.read(|ctx| {
        let mut bytes = Vec::new();
        let now = ctx.now();
        ctx.open.vault.write_archive(&mut bytes, now, &|| false)?;
        let h = ctx.open.vault.header();
        VaultFile::create_from_archive(
            &b_path,
            &mut std::io::Cursor::new(bytes),
            ArchiveScope::new(h.vault_id, h.key_generation),
            ctx.open.vault.vault_key(),
            &AnchorDir::open(&env.anchors)?,
            &|| false,
        )?;
        Ok(())
    })
    .unwrap();
    let b = {
        let _k = kdf();
        env.core().unlock(&b_path, &pw(PASSWORD), None).unwrap()
    };
    (a, b)
}

pub(super) fn replicas(env: &Env) -> (Session, Session) {
    replicas_with(env, None)
}

/// `w_side` shows a code; `scanner` syncs with it once.
fn round(
    w_side: &Session,
    scanner: &Session,
) -> (Result<SyncReport, CoreError>, Result<SyncReport, CoreError>) {
    let (w, manual, port) = code(w_side);
    let mut yes = Yes(None, None, PASSWORD);
    let (served, sent) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(w_side, &mut yes, None));
        let sent = scanner.sync_with_code(
            JoinCode::from_manual(&manual).unwrap(),
            sync_options(port),
            None,
        );
        (h.join().unwrap(), sent)
    });
    // A sync never shows a comparison code.
    assert!(yes.0.is_none());
    (synced_report(served), sent)
}

fn titles(s: &Session) -> Vec<String> {
    let mut t: Vec<String> = s
        .list(s.root().unwrap())
        .unwrap()
        .entries
        .iter()
        .map(|e| e.title.expose().to_owned())
        .collect();
    t.sort();
    t
}

// 0012 §1: Account-dependent LAN sync
#[test]
fn lan_core_sync_converges_both_ways_and_reports_conflicts() {
    let env = Env::new();
    let (a, b) = replicas(&env);
    crate::testutil::add_entry(&a, a.root().unwrap(), "from a");
    crate::testutil::add_entry(&b, b.root().unwrap(), "from b");
    let (got, sent) = round(&b, &a);
    let sent = sent.unwrap();
    assert_eq!(sent.local, LocalAcceptance::Committed);
    assert!(sent.peer_confirmed);
    assert!(sent.completion_error.is_none());
    assert_eq!(got.unwrap().local, LocalAcceptance::Committed);
    assert_eq!(titles(&a), ["from a", "from b"]);
    assert_eq!(titles(&a), titles(&b));
    // The other direction, then a conflict.
    let shared = crate::testutil::add_entry(&b, b.root().unwrap(), "shared");
    let (_, sent) = round(&a, &b);
    assert_eq!(sent.unwrap().local, LocalAcceptance::Unchanged);
    assert_eq!(titles(&a), titles(&b));
    let on_a = a
        .list(a.root().unwrap())
        .unwrap()
        .entries
        .into_iter()
        .find(|e| e.title.expose() == "shared")
        .unwrap()
        .handle;
    for (s, h, t) in [(&a, on_a, "shared, a"), (&b, shared, "shared, b")] {
        let mut d = s.edit_entry(h).unwrap();
        d.entry_mut().title = Text::new(t).unwrap();
        s.save_entry(d).unwrap();
    }
    let (got, sent) = round(&b, &a);
    let sent = sent.unwrap();
    assert_eq!(sent.local, LocalAcceptance::Committed);
    assert!(sent.conflicts >= 1);
    assert!(got.unwrap().conflicts >= 1);
    assert_eq!(rows(&a) + rows(&b), 0);
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_core_sync_with_another_vault_fails_on_both_sides() {
    let env = Env::new();
    let a = env.unlock();
    // A separately created vault (`Env::new` copies one shared fixture).
    let other_env = Env::empty(TestDir::new());
    let other = {
        let _k = kdf();
        other_env
            .core()
            .create(&other_env.path, &pw(PASSWORD), crate::testutil::NAME)
            .unwrap()
            .session
    };
    let (w, manual, port) = code(&a);
    let (served, sent) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut Yes(None, None, PASSWORD), None));
        let sent = other.sync_with_code(
            JoinCode::from_manual(&manual).unwrap(),
            sync_options(port),
            None,
        );
        (h.join().unwrap(), sent)
    });
    assert!(matches!(
        served.err(),
        Some(CoreError::Lan(LanError::Integrity))
    ));
    assert_eq!(err(sent), CoreError::Lan(LanError::Timeout));
}

#[test]
fn lan_core_lock_closes_the_window_without_a_grant() {
    let env = Env::new();
    let a = env.unlock();
    let (w, manual, port) = code(&a);
    let b_env = Env::empty(TestDir::new());
    let dest = b_env.dir.path().join("joined.qvault");
    // The offering session locks while the user compares the codes.
    let lock: &Session = &a;
    let comparing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = comparing.clone();
    let mut yes = Yes(
        None,
        Some(Box::new(move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
        })),
        PASSWORD,
    );
    let core = b_env.core();
    let mut joiner = Joiner(None);
    let (approved, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(lock, &mut yes, None));
        s.spawn(|| {
            while !comparing.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
            lock.lock();
        });
        let joined = core.join_new_device(
            JoinCode::from_manual(&manual).unwrap(),
            &dest,
            sync_options(port),
            &mut joiner,
            None,
        );
        (h.join().unwrap(), joined)
    });
    assert!(matches!(
        approved.err(),
        Some(CoreError::Lan(LanError::Cancelled))
    ));
    assert!(matches!(
        joined.err(),
        Some(CoreError::Lan(LanError::Timeout))
    ));
    assert!(!dest.exists());
}

#[test]
fn lan_core_lock_closes_a_waiting_window_promptly() {
    let env = Env::new();
    let a = env.unlock();
    let (w, _, _) = code(&a);
    let started = std::time::Instant::now();
    let r = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut Yes(None, None, PASSWORD), None));
        std::thread::sleep(Duration::from_millis(100));
        a.lock();
        h.join().unwrap()
    });
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(r.err(), Some(CoreError::Lan(LanError::Cancelled))));
}

#[test]
fn lan_core_refuses_invalid_options_and_recovery_sessions() {
    let env = Env::new();
    let s = env.unlock();
    let mut long = options();
    long.limit = Duration::from_secs(601);
    assert_eq!(err(s.open_sync_window(long)), CoreError::InvalidInput);
    let mut slow = options();
    slow.timeouts.message = Duration::from_secs(11);
    assert_eq!(err(s.open_sync_window(slow)), CoreError::InvalidInput);
    let mut slow = sync_options(1);
    slow.timeouts.message = Duration::from_secs(11);
    let code = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A";
    assert_eq!(
        err(s.sync_with_code(JoinCode::from_manual(code).unwrap(), slow, None)),
        CoreError::InvalidInput
    );
    drop(s);
    // A vault opened for recovery (no anchor) can neither offer nor sync.
    std::fs::remove_dir_all(&env.anchors).unwrap();
    let (r, _) = {
        let _k = kdf();
        env.core()
            .unlock_for_recovery(&env.path, &pw(PASSWORD), None)
            .unwrap()
    };
    assert!(r.open_sync_window(options()).is_err());
    assert!(
        r.sync_with_code(JoinCode::from_manual(code).unwrap(), sync_options(1), None)
            .is_err()
    );
}

#[test]
fn lan_core_new_device_refuses_an_anchor_directory_destination_before_connecting() {
    // As for `create`: a vault inside the anchor directory is refused before
    // any key is received (reviewer fix, plan 0037).
    let b_env = Env::empty(TestDir::new());
    let core = b_env.core();
    let dest = b_env.anchors.join("joined.qvault");
    let approver = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    approver.set_nonblocking(true).unwrap();
    let port = approver.local_addr().unwrap().port();
    let code = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A";
    let joined = core.join_new_device(
        JoinCode::from_manual(code).unwrap(),
        &dest,
        sync_options(port),
        &mut Joiner(None),
        None,
    );
    assert_eq!(err(joined), CoreError::AnchorLocation);
    assert!(!dest.exists());
    // Nothing contacted the endpoint.
    assert!(approver.accept().is_err());
}

fn policy(env: &Env) -> SnapshotPolicy {
    SnapshotPolicy {
        dir: SnapshotDir::open(&env.dir.path().join("snapshots")).unwrap(),
        max_count: 48,
        max_bytes: 512 * 1024 * 1024,
        max_age_seconds: 30 * 24 * 60 * 60,
    }
}

const NEW: &str = "replacement generation passphrase for lan rotation";

#[test]
fn lan_core_rotation_stops_old_copies_and_joining_again_works() {
    let a_env = Env::new();
    let core = a_env.core_with(Some(policy(&a_env)));
    let a = {
        let _k = kdf();
        core.unlock(&a_env.path, &pw(PASSWORD), None).unwrap()
    };
    let b_env = Env::empty(TestDir::new());
    let old_copy: PathBuf = b_env.dir.path().join("old.qvault");
    let (served, joined) = join_new(&a, &b_env, &old_copy);
    let old = joined.unwrap();
    assert!(joined_report(served).0);
    // Rotate A (0002 §3.5).
    let mut r = {
        let _k = kdf();
        a.begin_rotation(&pw(NEW), false, None).unwrap()
    };
    for i in [3usize, 11, 20] {
        let word = r.phrase().expose_word(i).unwrap().to_owned();
        assert!(r.confirm_word(i, word.as_bytes()).unwrap());
    }
    r.install(None).unwrap();
    let a2 = {
        let _k = kdf();
        core.unlock(&a_env.path, &pw(NEW), None).unwrap()
    };
    // The old-generation copy fails the sync proof (0013 §12.2).
    let (w, manual, port) = code(&a2);
    let (served, sent) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a2, &mut Yes(None, None, PASSWORD), None));
        let sent = old.sync_with_code(
            JoinCode::from_manual(&manual).unwrap(),
            sync_options(port),
            None,
        );
        (h.join().unwrap(), sent)
    });
    assert_eq!(err(sent), CoreError::Lan(LanError::Timeout));
    assert!(matches!(
        served.err(),
        Some(CoreError::Lan(LanError::Integrity))
    ));
    old.lock();
    let old_bytes = std::fs::read(&old_copy).unwrap();
    // Joining again in new-device mode creates a new file; the old copy
    // stays untouched (0013 §10.6, §12.2).
    let fresh = b_env.dir.path().join("fresh.qvault");
    let (served, joined) = join_new_with(&a2, &b_env, &fresh, NEW);
    assert!(joined_report(served).0);
    assert_eq!(rows(&joined.unwrap()), 0);
    assert_eq!(std::fs::read(&old_copy).unwrap(), old_bytes);
}

#[test]
fn lan_core_conflicted_keyslot_refuses_a_new_device() {
    let env = Env::new();
    let core = env.core_with(Some(policy(&env)));
    let a = {
        let _k = kdf();
        core.unlock(&env.path, &pw(PASSWORD), None).unwrap()
    };
    // A second replica changes the password concurrently, then its archive
    // merges back: two keyslot heads.
    let other = env.dir.path().join("other.qvault");
    a.read(|ctx| {
        let mut bytes = Vec::new();
        let now = ctx.now();
        ctx.open.vault.write_archive(&mut bytes, now, &|| false)?;
        let h = ctx.open.vault.header();
        VaultFile::create_from_archive(
            &other,
            &mut std::io::Cursor::new(bytes),
            ArchiveScope::new(h.vault_id, h.key_generation),
            ctx.open.vault.vault_key(),
            &AnchorDir::open(&env.anchors)?,
            &|| false,
        )?;
        Ok(())
    })
    .unwrap();
    let o = {
        let _k = kdf();
        core.unlock(&other, &pw(PASSWORD), None).unwrap()
    };
    {
        let _k = kdf();
        o.change_password(&pw("the other replica's password"), None)
            .unwrap();
        a.change_password(&pw("this replica's new password"), None)
            .unwrap();
    }
    let out = TestDir::new();
    let exported = o.export_archive(out.path(), false, None).unwrap();
    let archive = out.path().join(format!("{}.qvsnap", exported.archive_id));
    let merged = a.merge_archive(&archive, true, None).unwrap();
    assert!(merged.accepted);
    let b_env = Env::empty(TestDir::new());
    let dest = b_env.dir.path().join("joined.qvault");
    let (w, manual, port) = code(&a);
    let mut yes = Yes(None, None, PASSWORD);
    let mut joiner = Joiner(None);
    let core_b = b_env.core();
    let (served, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut yes, None));
        let joined = core_b.join_new_device(
            JoinCode::from_manual(&manual).unwrap(),
            &dest,
            sync_options(port),
            &mut joiner,
            None,
        );
        (h.join().unwrap(), joined)
    });
    assert_eq!(err(joined), CoreError::Lan(LanError::Timeout));
    assert!(matches!(served, Err(CoreError::Lan(LanError::Keyslot))));
    assert!(!dest.exists());
}

#[test]
fn lan_core_merges_take_an_ordinary_snapshot_at_most_once_per_interval() {
    let env = Env::new();
    let (a, b) = replicas_with(&env, Some(policy(&env)));
    let count = || a.snapshots().unwrap().snapshots.len();
    let before = count();
    crate::testutil::add_entry(&b, b.root().unwrap(), "one");
    let (_, sent) = round(&b, &a);
    assert_eq!(sent.unwrap().local, LocalAcceptance::Committed);
    // The unlock's snapshot is recent: the merge does not add another.
    assert_eq!(count(), before);
    env.time.set(env.time.now().0 + 2 * 60 * 60 * 1000);
    crate::testutil::add_entry(&b, b.root().unwrap(), "two");
    let (_, sent) = round(&b, &a);
    assert_eq!(sent.unwrap().local, LocalAcceptance::Committed);
    assert_eq!(count(), before + 1);
}

// 0012 §1: Account-dependent LAN sync
#[test]
fn lan_core_phrase_enrollment_preserves_password_and_publishes_a_writable_unlocked_vault() {
    struct PhraseJoin(Option<crate::SecretBytes>);
    impl JoinerUi for PhraseJoin {
        fn show_code(&mut self, _: &Sas) -> bool {
            panic!("key enrollment has no comparison prompt")
        }
        fn confirm_vault(&mut self, _: &[u8], _: &Sas) -> bool {
            panic!("key enrollment uses its authenticated-name prompt")
        }
        fn master_password(&mut self) -> Option<MasterPassword> {
            panic!("phrase enrollment must not ask for a password")
        }
        fn credentials(&mut self) -> Option<crate::EnrollmentCredential> {
            self.0
                .take()
                .map(crate::EnrollmentCredential::RecoveryPhrase)
        }
        fn confirm_recovered_vault(&mut self, name: &[u8]) -> bool {
            assert_eq!(name, crate::testutil::NAME.as_bytes());
            true
        }
    }
    let env = Env::new();
    let a = env.unlock();
    let phrase = a.recovery_phrase(&pw(PASSWORD)).unwrap();
    const NEW: &str = "phrase enrollment retains this changed source password";
    a.change_password(&pw(NEW), None).unwrap();
    let words = crate::SecretBytes::try_init(phrase.expose_secret().len(), |out| {
        out.copy_from_slice(phrase.expose_secret().as_bytes());
        Ok::<(), ()>(())
    })
    .unwrap();
    drop(phrase);
    let b_env = Env::empty(TestDir::new());
    let dest = b_env.dir.path().join("phrase-joined.qvault");
    let core = b_env.core();
    let (w, code, port) = code(&a);
    let mut yes = Yes(None, None, PASSWORD);
    let mut joiner = PhraseJoin(Some(words));
    let (served, b) = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run(&a, &mut yes, None));
        let b = core.join_new_device(
            JoinCode::from_manual(&code).unwrap(),
            &dest,
            sync_options(port),
            &mut joiner,
            None,
        );
        (h.join().unwrap().unwrap(), b.unwrap())
    });
    assert!(matches!(
        served,
        Served::Joined {
            key_disclosed: false,
            peer_confirmed: true,
            failure: None
        }
    ));
    assert!(
        yes.0.is_none(),
        "key enrollment never asks the source for a password/comparison"
    );
    assert!(!b.is_read_only().unwrap());
    assert_eq!(rows(&b), 0);
    crate::testutil::add_entry(&b, b.root().unwrap(), "created after phrase enrollment");
    b.lock();
    assert!(core.unlock(&dest, &pw(NEW), None).is_ok());
}

// 0012 §1: LAN partial acceptance
#[test]
fn lan_core_cancellation_after_publication_keeps_the_file_without_returning_a_session() {
    use crate::session::hooks::{self, Point};
    for point in [Point::LanPublished, Point::LanBound] {
        let env = Env::new();
        let a = env.unlock();
        let b_env = Env::empty(TestDir::new());
        let dest = b_env.dir.path().join("cancelled-joined.qvault");
        let core = b_env.core();
        let (window, code, port) = code(&a);
        let token = crate::CancelToken::new();
        let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel();
        let (served, joined) = std::thread::scope(|scope| {
            let source = scope.spawn(|| window.run(&a, &mut Yes(None, None, PASSWORD), None));
            let receiver = scope.spawn(|| {
                hooks::arm(point, arrived_tx, go_rx);
                core.join_new_device(
                    JoinCode::from_manual(&code).unwrap(),
                    &dest,
                    sync_options(port),
                    &mut Joiner(None),
                    Some(&token),
                )
            });
            arrived_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            token.cancel();
            go_tx.send(()).unwrap();
            (source.join().unwrap().unwrap(), receiver.join().unwrap())
        });
        assert!(matches!(
            served,
            Served::Joined {
                peer_confirmed: true,
                ..
            }
        ));
        assert_eq!(
            err(joined),
            CoreError::Store(qv_store::StoreError::PublicationIncomplete)
        );
        assert!(dest.exists());
        let reopened = core.unlock(&dest, &pw(PASSWORD), None).unwrap();
        assert!(!reopened.is_read_only().unwrap());
        crate::testutil::add_entry(
            &reopened,
            reopened.root().unwrap(),
            "retained after cancellation",
        );
    }
}
