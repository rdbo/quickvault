// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core rotation lifecycle and inventory-aware snapshot policy evidence
//! (plan 0023 steps 5–6; 0012 §1 rows "Rotation/purge ambiguity",
//! "Migration coupling" (data part) and old-generation archives).

use std::os::unix::fs::PermissionsExt;

use qv_store::{RotationChoice, RotationState, SnapshotDir, SnapshotKind};

use super::*;
use crate::snapshot::SnapshotPolicy;
use crate::testutil::{Env, PASSWORD, add_entry, err, kdf, pw};
use crate::{Core, CoreError, Session};

const NEW: &str = "replacement generation passphrase for core rotation";
const HOUR: i64 = 60 * 60 * 1000;

fn policy(env: &Env, max_count: u32, max_bytes: u64, max_age_seconds: i64) -> SnapshotPolicy {
    SnapshotPolicy {
        dir: SnapshotDir::open(&env.dir.path().join("snapshots")).unwrap(),
        max_count,
        max_bytes,
        max_age_seconds,
    }
}

fn wide(env: &Env) -> SnapshotPolicy {
    policy(env, 48, 512 * 1024 * 1024, 30 * 24 * 60 * 60)
}

fn unlock(core: &Core, env: &Env, password: &str) -> Result<Session, CoreError> {
    let _k = kdf();
    core.unlock(&env.path, &pw(password), None)
}

fn begin(s: &Session, over: bool) -> Result<Rotation, CoreError> {
    let _k = kdf();
    s.begin_rotation(&pw(NEW), over, None)
}

/// Confirms three words, as the frontend does after showing the phrase.
fn confirm(r: &mut Rotation) {
    for i in [3usize, 11, 20] {
        let word = r.phrase().expose_word(i).unwrap().to_owned();
        assert!(!r.confirm_word(i, b"wrongword").unwrap());
        assert!(r.confirm_word(i, word.as_bytes()).unwrap());
    }
}

fn rotate(s: &Session) -> RotationOutcome {
    let mut r = begin(s, false).unwrap();
    confirm(&mut r);
    r.install(None).unwrap()
}

fn files(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

// 0012 §1: Migration coupling
#[test]
fn rotate_full_lifecycle_through_core() {
    let env = Env::new();
    let core = env.core_with(Some(wide(&env)));
    let s = unlock(&core, &env, PASSWORD).unwrap();
    let root = s.root().unwrap();
    let entry = add_entry(&s, root, "kept across generations");
    let content = vec![5u8; 70_000];
    let a = s
        .add_attachment(
            entry,
            "a.bin",
            "application/octet-stream",
            &mut &content[..],
            None,
        )
        .unwrap();
    let _ = a;
    let before = s.overview().unwrap();
    let old_ids: Vec<String> = s
        .snapshots()
        .unwrap()
        .snapshots
        .into_iter()
        .map(|x| x.archive_id)
        .collect();
    assert!(!old_ids.is_empty());

    let mut r = begin(&s, false).unwrap();
    // The session is consumed.
    assert_eq!(err(s.overview()), CoreError::SessionLocked);
    assert_eq!(r.new_generation().0, 2);
    assert_eq!(r.leftovers(), Leftovers::default());
    assert_eq!(format!("{r:?}"), "Rotation(<redacted>)");
    assert_eq!(err(r.confirm_word(24, b"x")), CoreError::InvalidInput);
    confirm(&mut r);
    let done = r.install(None).unwrap();
    assert_eq!(done.new_generation.0, 2);
    assert!(!done.cleanup_pending);
    assert!(!core.rotation_pending(&env.path).unwrap());

    assert_eq!(
        err(unlock(&core, &env, PASSWORD)),
        CoreError::Store(qv_store::StoreError::WrongPassword)
    );
    let s = unlock(&core, &env, NEW).unwrap();
    let after = s.overview().unwrap();
    assert_eq!(after.entries, before.entries);
    assert_eq!(after.groups, before.groups);
    assert_eq!(after.local_seq, before.local_seq + 1);
    // Handles belong to their session: look the entry up again.
    let entry = s
        .list(s.root().unwrap())
        .unwrap()
        .entries
        .into_iter()
        .find(|e| e.title.expose() == "kept across generations")
        .unwrap()
        .handle;
    let atts = s.attachments(entry).unwrap();
    assert_eq!(atts.len(), 1);
    let mut out = Vec::new();
    s.save_attachment(atts[0].handle, &mut out, None).unwrap();
    assert_eq!(out, content);
    assert_eq!(s.verify(None).unwrap().key_generation, 2);

    // Old-generation copies are neither listed nor reported as unreadable,
    // and never restored or merged automatically.
    let listing = s.snapshots().unwrap();
    assert_eq!(listing.unreadable, 0);
    assert!(
        listing
            .snapshots
            .iter()
            .all(|x| !old_ids.contains(&x.archive_id))
    );
    let target = env.dir.path().join("restored.qvault");
    let refused = err(s.restore_snapshot(&old_ids[0], &target, None));
    assert!(
        matches!(refused, CoreError::Store(_) | CoreError::NotFound),
        "{refused:?}"
    );
    assert!(!target.exists());
    for id in &old_ids {
        assert!(
            files(&env.dir.path().join("snapshots"))
                .iter()
                .any(|f| f.contains(id.as_str()))
        );
    }
}

#[test]
fn rotate_refusals_leave_the_session_usable() {
    // No snapshot policy: a rotation has no recovery copy.
    let env = Env::new();
    let core = env.core();
    let s = unlock(&core, &env, PASSWORD).unwrap();
    assert_eq!(err(begin(&s, false).map(|_| ())), CoreError::NotAllowed);
    s.overview().unwrap();

    // A recovery session whose writes are blocked.
    let env = Env::new();
    for e in std::fs::read_dir(&env.anchors).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    let core = env.core_with(Some(wide(&env)));
    let (s, _) = {
        let _k = kdf();
        core.unlock_for_recovery(&env.path, &pw(PASSWORD), None)
            .unwrap()
    };
    assert_eq!(err(begin(&s, false).map(|_| ())), CoreError::NotAllowed);
    s.overview().unwrap();

    // Over budget: refused without consent, the session stays open, and
    // consent proceeds.
    let env = Env::new();
    let core = env.core_with(Some(policy(&env, 48, 1, 30 * 24 * 60 * 60)));
    let s = unlock(&core, &env, PASSWORD).unwrap();
    assert!(matches!(
        err(begin(&s, false).map(|_| ())),
        CoreError::SnapshotOverBudget { .. }
    ));
    s.overview().unwrap();
    let mut r = begin(&s, true).unwrap();
    confirm(&mut r);
    r.install(None).unwrap();
    unlock(&core, &env, NEW).unwrap();

    // Cancellation before anything: the session stays open.
    let env = Env::new();
    let core = env.core_with(Some(wide(&env)));
    let s = unlock(&core, &env, PASSWORD).unwrap();
    let token = CancelToken::new();
    token.cancel();
    assert_eq!(
        err(s.begin_rotation(&pw(NEW), false, Some(&token)).map(|_| ())),
        CoreError::Cancelled
    );
    s.overview().unwrap();
}

#[test]
fn rotate_without_confirmation_or_dropped_publishes_nothing() {
    let env = Env::new();
    let core = env.core_with(Some(wide(&env)));
    let vault = std::fs::read(&env.path).unwrap();
    let anchors: Vec<Vec<u8>> = std::fs::read_dir(&env.anchors)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    let s = unlock(&core, &env, PASSWORD).unwrap();
    let mut r = begin(&s, false).unwrap();
    let w = r.phrase().expose_word(0).unwrap().to_owned();
    assert!(r.confirm_word(0, w.as_bytes()).unwrap());
    assert!(r.confirm_word(0, w.as_bytes()).unwrap());
    // One distinct word twice is not three confirmations.
    let refused = r.install(None).unwrap_err();
    assert_eq!(refused.error, CoreError::NotAllowed);
    assert!(!refused.journal_published);
    assert_eq!(std::fs::read(&env.path).unwrap(), vault);
    let now: Vec<Vec<u8>> = std::fs::read_dir(&env.anchors)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(now, anchors);
    assert_eq!(
        files(env.dir.path())
            .iter()
            .filter(|f| f.contains(".qvrotate"))
            .count(),
        0
    );

    // A dropped rotation: same. Its recovery copy is reclassified as
    // ordinary by the next policy pass.
    let s = unlock(&core, &env, PASSWORD).unwrap();
    drop(begin(&s, false).unwrap());
    assert!(
        files(&env.dir.path().join("snapshots"))
            .iter()
            .any(|f| f.starts_with("recover-"))
    );
    env.time
        .set(env.time.0.load(std::sync::atomic::Ordering::SeqCst) + 2 * HOUR);
    let s = unlock(&core, &env, PASSWORD).unwrap();
    assert_eq!(s.verify(None).unwrap().key_generation, 1);
    assert!(
        !files(&env.dir.path().join("snapshots"))
            .iter()
            .any(|f| f.starts_with("recover-"))
    );
}

/// Installs with an unwritable anchor directory: the anchor step fails after
/// the journal is published (unlock and snapshots never write anchors).
fn interrupted(env: &Env, core: &Core) {
    let s = unlock(core, env, PASSWORD).unwrap();
    let mut r = begin(&s, false).unwrap();
    confirm(&mut r);
    std::fs::set_permissions(&env.anchors, std::fs::Permissions::from_mode(0o500)).unwrap();
    let failed = r.install(None).unwrap_err();
    std::fs::set_permissions(&env.anchors, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(failed.journal_published, "{failed:?} (running as root?)");
}

#[test]
fn rotate_resume_through_core_both_ways() {
    for choice in [RotationChoice::Complete, RotationChoice::RollBack] {
        let env = Env::new();
        let core = env.core_with(Some(wide(&env)));
        interrupted(&env, &core);
        assert!(core.rotation_pending(&env.path).unwrap());
        assert_eq!(
            err(unlock(&core, &env, PASSWORD)),
            CoreError::Store(qv_store::StoreError::Integrity)
        );
        let need = core.rotation_passwords(&env.path).unwrap();
        assert_eq!(
            need,
            NeededPasswords {
                old: true,
                new: true
            }
        );
        let t = {
            let _k = kdf();
            core.resume_rotation(&env.path, Some(&pw(PASSWORD)), Some(&pw(NEW)), None)
                .unwrap()
        };
        assert_eq!(t.state(), RotationState::AnchorPending);
        core.finish_rotation(t, choice, None).unwrap();
        assert!(!core.rotation_pending(&env.path).unwrap());
        let (good, bad, generation) = match choice {
            RotationChoice::Complete => (NEW, PASSWORD, 2),
            RotationChoice::RollBack => (PASSWORD, NEW, 1),
        };
        let s = unlock(&core, &env, good).unwrap();
        assert_eq!(s.verify(None).unwrap().key_generation, generation);
        assert!(s.verify(None).unwrap().ok());
        drop(s);
        assert!(matches!(
            err(unlock(&core, &env, bad)),
            CoreError::Store(qv_store::StoreError::WrongPassword)
        ));
    }
}

#[test]
fn rotate_resume_without_a_snapshot_policy_is_not_allowed() {
    let env = Env::new();
    let core = env.core_with(Some(wide(&env)));
    interrupted(&env, &core);
    let bare = env.core();
    assert_eq!(
        err(bare
            .resume_rotation(&env.path, Some(&pw(PASSWORD)), Some(&pw(NEW)), None)
            .map(|_| ())),
        CoreError::NotAllowed
    );
}

// ---- Step 5: inventory-aware policy ------------------------------------

/// Rotates a vault that has `n` ordinary generation-1 snapshots two hours
/// apart (plus the rotation's recovery copy). Returns the ordinary IDs.
fn rotated_with_old_copies(env: &Env, n: usize) -> Vec<String> {
    let start = env.time.0.load(std::sync::atomic::Ordering::SeqCst);
    let core = env.core_with(Some(wide(env)));
    for i in 0..n {
        env.time.set(start + (i as i64) * 2 * HOUR);
        drop(unlock(&core, env, PASSWORD).unwrap());
    }
    let s = unlock(&core, env, PASSWORD).unwrap();
    let old: Vec<String> = s
        .snapshots()
        .unwrap()
        .snapshots
        .into_iter()
        .map(|x| x.archive_id)
        .collect();
    assert_eq!(old.len(), n);
    rotate(&s);
    old
}

fn old_present(env: &Env, ids: &[String]) -> usize {
    let names = files(&env.dir.path().join("snapshots"));
    ids.iter()
        .filter(|id| names.iter().any(|f| f.contains(id.as_str())))
        .count()
}

#[test]
fn snapshot_inventory_policy_counts_and_prunes_old_generations() {
    let env = Env::new();
    let old = rotated_with_old_copies(&env, 3);
    // Count budget 3: the new copy plus the two newest old copies (the
    // recovery copy is the newest old one); the two oldest go.
    let core = env.core_with(Some(policy(&env, 3, 512 * 1024 * 1024, 30 * 24 * 60 * 60)));
    env.time
        .set(env.time.0.load(std::sync::atomic::Ordering::SeqCst) + 3 * HOUR);
    let s = unlock(&core, &env, NEW).unwrap();
    let report = s.snapshot_status().unwrap();
    assert!(report.published.is_some(), "{report:?}");
    assert!(!report.failed, "{report:?}");
    assert_eq!(report.pruned.len(), 2, "{report:?}");
    assert!(report.pruned.iter().all(|id| old.contains(id)));
    assert_eq!(old_present(&env, &old), 1);
    drop(s);

    // Age: everything older than an hour goes, old generations included.
    let core = env.core_with(Some(policy(&env, 48, 512 * 1024 * 1024, 60 * 60)));
    env.time
        .set(env.time.0.load(std::sync::atomic::Ordering::SeqCst) + 30 * HOUR);
    let s = unlock(&core, &env, NEW).unwrap();
    let report = s.snapshot_status().unwrap();
    assert!(!report.failed, "{report:?}");
    assert_eq!(old_present(&env, &old), 0);
}

#[test]
fn snapshot_inventory_policy_keeps_changed_files_and_fails_closed() {
    let env = Env::new();
    let old = rotated_with_old_copies(&env, 2);
    let dir = env.dir.path().join("snapshots");
    // Change one old copy in place (same size): its row no longer matches.
    let victim = files(&dir)
        .into_iter()
        .find(|f| old.iter().any(|id| f.contains(id.as_str())))
        .unwrap();
    let path = dir.join(&victim);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let core = env.core_with(Some(policy(&env, 48, 512 * 1024 * 1024, 60 * 60)));
    env.time
        .set(env.time.0.load(std::sync::atomic::Ordering::SeqCst) + 30 * HOUR);
    let s = unlock(&core, &env, NEW).unwrap();
    let report = s.snapshot_status().unwrap();
    assert!(report.failed, "{report:?}");
    assert!(path.exists());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    drop(s);

    // Without the inventory: no ordinary copy, no pruning; a recovery copy
    // needs explicit consent.
    for f in files(&dir) {
        if f.starts_with("inventory-") {
            std::fs::remove_file(dir.join(f)).unwrap();
        }
    }
    let before = files(&dir);
    env.time
        .set(env.time.0.load(std::sync::atomic::Ordering::SeqCst) + 30 * HOUR);
    let s = unlock(&core, &env, NEW).unwrap();
    let report = s.snapshot_status().unwrap();
    assert!(report.failed && report.published.is_none() && report.pruned.is_empty());
    assert_eq!(files(&dir), before);
    assert!(matches!(
        err(s.begin_destructive(false, None).map(|_| ())),
        CoreError::SnapshotOverBudget { .. }
    ));
    assert_eq!(files(&dir), before);
    let copy = s.begin_destructive(true, None).unwrap();
    assert_eq!(copy.summary().kind, SnapshotKind::Recovery);
    assert_eq!(files(&dir).len(), before.len() + 1);
}
