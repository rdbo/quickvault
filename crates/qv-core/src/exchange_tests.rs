// SPDX-License-Identifier: AGPL-3.0-or-later

// Test-only fixture setup intentionally fails on unexpected errors.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::testutil::{Env, PASSWORD, TestDir, err, kdf, pw};
use qv_store::{AnchorDir, VaultFile};
use std::sync::{Arc, mpsc};

fn export(s: &Session, dir: &TestDir, backup: bool) -> std::path::PathBuf {
    let r = s.export_archive(dir.path(), backup, None).unwrap();
    assert_eq!(r.self_contained, backup);
    dir.path().join(format!("{}.qvsnap", r.archive_id))
}

fn branch(env: &Env, s: &Session) -> Session {
    let path = env.dir.path().join("branch.qvault");
    s.read(|ctx| {
        let mut bytes = Vec::new();
        ctx.open
            .vault
            .write_archive(&mut bytes, ctx.now(), &|| false)?;
        let h = ctx.open.vault.header();
        VaultFile::create_from_archive(
            &path,
            &mut std::io::Cursor::new(bytes),
            ArchiveScope::new(h.vault_id, h.key_generation),
            ctx.open.vault.vault_key(),
            &AnchorDir::open(&env.anchors)?,
            &|| false,
        )?;
        Ok(())
    })
    .unwrap();
    let _k = kdf();
    env.core().unlock(&path, &pw(PASSWORD), None).unwrap()
}

fn add(s: &Session, title: &str) -> crate::EntryHandle {
    s.save_entry(s.new_entry(s.root().unwrap(), "login", title).unwrap())
        .unwrap()
}

// 0012 §1: Hostile files from sync folders
// 0012 §1: Deleted-entry resurrection
#[test]
fn exchange_merge_is_durable_idempotent_preserves_conflicts_and_rejects_changed_names() {
    let env = Env::new();
    let s = env.unlock_with(Some(env.snapshot_policy()));
    let entry = add(&s, "original");
    let remote = branch(&env, &s);
    let remote_entry = remote.search("original").unwrap().remove(0);
    let crate::SearchHit::Entry(remote_entry) = remote_entry else {
        panic!()
    };
    let mut d = remote.edit_entry(remote_entry.handle).unwrap();
    d.entry_mut().title = crate::Text::new("incoming complete version").unwrap();
    remote.save_entry(d).unwrap();
    s.delete(crate::ItemHandle::Entry(entry), false).unwrap();
    let dir = TestDir::new();
    let source = export(&remote, &dir, false);
    let r = s.merge_archive(&source, false, None).unwrap();
    assert!(r.accepted);
    assert_eq!(r.conflicts, 1);
    assert_eq!(r.completion_error, None);
    assert_eq!(s.trash().unwrap().len(), 1);
    assert!(s.verify(None).unwrap().ok());
    let seq = s.overview().unwrap().local_seq;
    assert!(!s.merge_archive(&source, false, None).unwrap().accepted);
    assert_eq!(s.overview().unwrap().local_seq, seq);
    s.lock();
    let s = env.unlock_with(Some(env.snapshot_policy()));
    assert!(!s.merge_archive(&source, false, None).unwrap().accepted);
    let newer = export(&remote, &dir, false);
    std::fs::copy(&newer, &source).unwrap();
    assert_eq!(
        err(s.merge_archive(&source, false, None)),
        CoreError::Store(StoreError::Integrity)
    );
    assert_eq!(s.overview().unwrap().local_seq, seq);
}

// 0012 §1: Snapshot disk growth
#[test]
fn exchange_requires_recovery_policy_budget_and_preflight_views_before_acceptance() {
    let env = Env::new();
    let s = env.unlock();
    add(&s, "confidential metadata");
    let dir = TestDir::new();
    let source = export(&s, &dir, false);
    assert_eq!(
        err(s.merge_archive(&source, false, None)),
        CoreError::NotAllowed
    );
    s.lock();
    let mut policy = env.snapshot_policy();
    policy.max_bytes = 1;
    let s = env.unlock_with(Some(policy));
    let seq = s.overview().unwrap().local_seq;
    assert!(matches!(
        err(s.merge_archive(&source, false, None)),
        CoreError::SnapshotOverBudget { .. }
    ));
    assert_eq!(
        err(s.merge_archive_with_budget(&source, true, None, 1)),
        CoreError::LimitExceeded
    );
    assert_eq!(s.overview().unwrap().local_seq, seq);
    assert!(s.merge_archive(&source, true, None).unwrap().accepted);
    assert!(
        s.snapshots()
            .unwrap()
            .snapshots
            .iter()
            .any(|r| r.created_at.0 > 0)
    );
    // A missing directory cannot be bypassed even by size approval.
    std::fs::rename(
        env.dir.path().join("snapshots"),
        env.dir.path().join("saved-snapshots"),
    )
    .unwrap();
    assert!(s.merge_archive(&source, true, None).is_err());
}

// 0012 §1: Exchange-file password guessing
#[test]
fn exchange_backup_slot_is_explicit_mac_bound_and_excluded_from_snapshot_policy() {
    let env = Env::new();
    let s = env.unlock_with(Some(env.snapshot_policy()));
    let dir = TestDir::new();
    for backup in [false, true] {
        let path = export(&s, &dir, backup);
        s.read(|ctx| {
            let h = ctx.open.vault.header();
            let scope = ArchiveScope::new(h.vault_id, h.key_generation);
            let mut file = std::fs::File::open(&path).unwrap();
            let header = qv_store::read_header(&mut file, scope, ctx.open.vault.vault_key())?;
            assert_eq!(header.is_self_contained(), backup);
            let restored = env.dir.path().join(format!("restored-{backup}.qvault"));
            VaultFile::create_from_archive(
                &restored,
                &mut std::fs::File::open(&path).unwrap(),
                scope,
                ctx.open.vault.vault_key(),
                &AnchorDir::open(&env.anchors)?,
                &|| false,
            )?;
            Ok(())
        })
        .unwrap();
        if backup {
            let id = path.file_name().unwrap();
            std::fs::copy(&path, env.dir.path().join("snapshots").join(id)).unwrap();
            assert!(s.snapshots().unwrap().unreadable > 0);
        }
    }
    assert_eq!(
        err(s.export_archive(&env.dir.path().join("snapshots"), false, None)),
        CoreError::Store(StoreError::UnsafeFile)
    );
    let token = CancelToken::new();
    token.cancel();
    assert_eq!(
        err(s.export_archive(dir.path(), true, Some(&token))),
        CoreError::Cancelled
    );
}

// 0012 §1: Anchor crash windows
#[test]
fn exchange_postcommit_anchor_error_reports_acceptance_and_keeps_matching_index() {
    let env = Env::new();
    let s = Arc::new(env.unlock_with(Some(env.snapshot_policy())));
    let remote = branch(&env, &s);
    add(&remote, "durably received");
    let dir = TestDir::new();
    let source = export(&remote, &dir, false);
    let (arrive_tx, arrive_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let worker = {
        let s = s.clone();
        std::thread::spawn(move || {
            crate::session::hooks::arm(
                crate::session::hooks::Point::BeforeCommit,
                arrive_tx,
                go_rx,
            );
            s.merge_archive(&source, false, None)
        })
    };
    arrive_rx.recv().unwrap();
    let saved = env.dir.path().join("saved-anchors");
    std::fs::rename(&env.anchors, &saved).unwrap();
    std::fs::write(&env.anchors, b"not a directory").unwrap();
    go_tx.send(()).unwrap();
    let report = worker.join().unwrap().unwrap();
    assert!(report.accepted);
    assert!(report.completion_error.is_some());
    assert_eq!(s.search("durably received").unwrap().len(), 1);
    std::fs::remove_file(&env.anchors).unwrap();
    std::fs::rename(saved, &env.anchors).unwrap();
    s.lock();
    assert_eq!(env.unlock().search("durably received").unwrap().len(), 1);
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn exchange_lock_before_and_after_commit_reports_actual_state() {
    for after in [false, true] {
        let env = Env::new();
        let s = Arc::new(env.unlock_with(Some(env.snapshot_policy())));
        let remote = branch(&env, &s);
        add(&remote, "racing import");
        let dir = TestDir::new();
        let source = export(&remote, &dir, false);
        let (arrive_tx, arrive_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        let worker = {
            let s = s.clone();
            std::thread::spawn(move || {
                use crate::session::hooks::{self, Point};
                hooks::arm(
                    if after {
                        Point::AfterCommit
                    } else {
                        Point::BeforeCommit
                    },
                    arrive_tx,
                    go_rx,
                );
                s.merge_archive(&source, false, None)
            })
        };
        arrive_rx.recv().unwrap();
        let locker = {
            let s = s.clone();
            std::thread::spawn(move || s.lock())
        };
        while !s.is_locked() {
            std::thread::yield_now();
        }
        go_tx.send(()).unwrap();
        let result = worker.join().unwrap();
        if after {
            assert!(result.unwrap().accepted);
        } else {
            assert_eq!(err(result), CoreError::Cancelled);
        }
        locker.join().unwrap();
        assert!(s.is_locked());
        assert_eq!(
            env.unlock().search("racing import").unwrap().len(),
            usize::from(after)
        );
    }
}

// 0012 §1: Mixed credentials
#[test]
fn exchange_backup_preserves_working_slot_when_imported_keyslots_conflict() {
    let env = Env::new();
    let s = env.unlock_with(Some(env.snapshot_policy()));
    let remote = branch(&env, &s);
    let local_password = "this is the local working password";
    let remote_password = "this is the remote conflicting password";
    {
        let _k = kdf();
        s.change_password(&pw(local_password), None).unwrap();
        remote.change_password(&pw(remote_password), None).unwrap();
    }
    let dir = TestDir::new();
    let source = export(&remote, &dir, false);
    let report = s.merge_archive(&source, false, None).unwrap();
    assert!(report.accepted);
    assert_eq!(report.conflicts, 1);
    let backup = export(&s, &dir, true);
    let restored = env.dir.path().join("conflicted-backup.qvault");
    s.read(|ctx| {
        let h = ctx.open.vault.header();
        VaultFile::create_from_archive(
            &restored,
            &mut std::fs::File::open(&backup).unwrap(),
            ArchiveScope::new(h.vault_id, h.key_generation),
            ctx.open.vault.vault_key(),
            &AnchorDir::open(&env.anchors)?,
            &|| false,
        )?;
        Ok(())
    })
    .unwrap();
    let _k = kdf();
    assert_eq!(
        err(env.core().unlock(&restored, &pw(remote_password), None)),
        CoreError::Store(StoreError::WrongPassword)
    );
    let restored = env
        .core()
        .unlock(&restored, &pw(local_password), None)
        .unwrap();
    assert_eq!(restored.overview().unwrap().conflicts, 1);
}
