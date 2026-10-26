// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash, rollback and linkage suites (plan 0009 step 9; 0012 §1 rows
//! "Whole-file rollback", "Anchor crash windows" and "Server-visible record
//! linkage", envelope level).
//!
//! A crash is simulated with the `crash` hooks: at the armed point the
//! vault file, its journal and the anchor directory are copied as a killed
//! process would leave them, and the operation stops. The copy is then
//! opened like any vault.

use std::path::{Path, PathBuf};

use qv_crypto::RecordId;
use qv_model::RandomId;

use crate::anchor::AnchorDir;
use crate::crash::CrashPoint;
use crate::crash::test::{arm, disarm};
use crate::error::StoreError;
use crate::fs::test_dir::{TestDir, write_file};
use crate::head::AnchorStatus;
use crate::vault::tests::{
    NAME, PASSWORD, anchors, copy_fixture, edit, entry_version, err, fixture, kdf, pw, unlock,
};
use crate::vault::{UnlockedVault, VaultFile};

fn new_record() -> RecordId {
    <RecordId as RandomId>::generate().unwrap()
}

/// Opens a snapshot written by the crash hook.
fn open_snapshot(s: &TestDir, name: &str) -> Result<(UnlockedVault, AnchorStatus), StoreError> {
    let dir = AnchorDir::open(&s.join("anchors"))?;
    let _k = kdf();
    VaultFile::open(&s.join(name))?.unlock_for_recovery(&pw(PASSWORD), &dir)
}

/// One edit creating `record`, which stops at the armed point.
fn crashing_edit(u: &mut UnlockedVault, record: RecordId) -> Result<(), StoreError> {
    let root = u.manifest().root_group_id();
    let mut w = u.write()?;
    let c = w.reserve_counter()?;
    w.put_local(record, entry_version(root, "crash", w.writer_id(), c, &[]))?;
    w.commit()
}

#[test]
fn crash_every_mutation_point() {
    use CrashPoint::*;
    let cases = [
        (Begun, false, AnchorStatus::Verified),
        (ObjectsWritten, false, AnchorStatus::Verified),
        (ManifestWritten, false, AnchorStatus::Verified),
        (HeadWritten, false, AnchorStatus::Verified),
        (Pruned, false, AnchorStatus::Verified),
        (Committed, true, AnchorStatus::Advanced),
        (AnchorTempWritten, true, AnchorStatus::Advanced),
        (AnchorReplaced, true, AnchorStatus::Verified),
    ];
    for (point, new_state, expected) in cases {
        let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let r = new_record();
        {
            let mut u = unlock(&p, &dir, PASSWORD).unwrap();
            // A first commit, so that a later crash has history to keep.
            edit(&mut u, new_record(), "before");
            arm(point, &p, &a.join("anchors"), s.path());
            assert_eq!(
                crashing_edit(&mut u, r),
                Err(StoreError::Internal),
                "{point:?}"
            );
            assert!(!disarm(), "{point:?} was not reached");
        }
        // Between the first write and COMMIT the snapshot holds SQLite's
        // journal (bundled SQLite 3.53.2). These small transactions have not
        // written the vault file yet, so the journal is not hot and SQLite
        // ignores it; `crash_spilled_transaction_rolls_back` covers a hot one.
        let journal = s.join("v.qvault-journal").exists();
        let mid_transaction = !new_state && point != Begun;
        assert_eq!(journal, mid_transaction, "{point:?}");
        let (u, status) = open_snapshot(&s, "v.qvault").unwrap();
        assert_eq!(status, expected, "{point:?}");
        let seq = if new_state { 3 } else { 2 };
        assert_eq!(u.local_seq(), seq, "{point:?}");
        assert_eq!(u.manifest().record(r).is_some(), new_state, "{point:?}");
        assert_eq!(u.manifest().records().len(), if new_state { 5 } else { 4 });
        drop(u);
        // After the open (which advanced the anchor if needed), an ordinary
        // unlock succeeds.
        let dir = AnchorDir::open(&s.join("anchors")).unwrap();
        let u = unlock(&s.join("v.qvault"), &dir, PASSWORD).unwrap();
        assert_eq!(u.local_seq(), seq, "{point:?}");
    }
}

#[test]
fn crash_spilled_transaction_rolls_back() {
    use qv_model::{Payload, RecordBody, Text};
    // Enough data to spill SQLite's 2 MiB page cache into the vault file
    // before COMMIT: the crash then leaves a hot journal that must be rolled
    // back on open.
    let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let before = std::fs::read(&p).unwrap();
    {
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        let root = u.manifest().root_group_id();
        arm(CrashPoint::Pruned, &p, &a.join("anchors"), s.path());
        let mut w = u.write().unwrap();
        for _ in 0..24 {
            let c = w.reserve_counter().unwrap();
            let mut v = entry_version(root, "big", w.writer_id(), c, &[]);
            if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
                e.notes = Some(Text::new(&"n".repeat(200 * 1024)).unwrap());
            }
            w.put_local(new_record(), v).unwrap();
        }
        assert_eq!(w.commit(), Err(StoreError::Internal));
        assert!(!disarm());
    }
    let snap = s.join("v.qvault");
    assert!(s.join("v.qvault-journal").exists());
    assert_ne!(std::fs::read(&snap).unwrap(), before, "nothing spilled");
    let (u, status) = open_snapshot(&s, "v.qvault").unwrap();
    assert_eq!(status, AnchorStatus::Verified);
    assert_eq!(u.local_seq(), 1);
    assert_eq!(u.manifest().records().len(), 3);
    // SQLite rolled the hot journal back and removed it.
    assert!(!s.join("v.qvault-journal").exists());
}

#[test]
fn crash_every_create_point() {
    for point in [CrashPoint::CreateBuilt, CrashPoint::CreateAnchored] {
        let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
        let p = d.join("v.qvault");
        let dir = anchors(&a);
        arm(point, &p, &a.join("anchors"), s.path());
        let r = {
            let _k = kdf();
            VaultFile::create(&p, &pw(PASSWORD), NAME, &dir)
        };
        assert_eq!(err(r), StoreError::Internal, "{point:?}");
        assert!(!disarm());
        // A crash before the rename never leaves a vault at the path.
        assert_eq!(err(open_snapshot(&s, "v.qvault")), StoreError::NotFound);
        let orphans = std::fs::read_dir(s.join("anchors")).unwrap().count();
        assert_eq!(orphans, usize::from(point == CrashPoint::CreateAnchored));
        // The failed create cleaned up after itself.
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(a.join("anchors")).unwrap().count(), 0);
    }
}

fn anchor_file(a: &TestDir) -> PathBuf {
    a.join("anchors").join(&fixture().anchor.0)
}

#[test]
fn rollback_two_commits_ahead() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let anchored = std::fs::read(anchor_file(&a)).unwrap();
    {
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        edit(&mut u, new_record(), "one");
        edit(&mut u, new_record(), "two");
    }
    // The anchor from before both commits: the DB is two steps ahead.
    write_file(&anchor_file(&a), &anchored, 0o600);
    assert_eq!(err(unlock(&p, &dir, PASSWORD)), StoreError::Rollback);
}

#[test]
fn rollback_fork_and_old_copy() {
    // Two copies of one state (same replica), each one commit ahead.
    let (d1, a1) = (TestDir::new(), TestDir::new());
    let (d2, a2) = (TestDir::new(), TestDir::new());
    let (p1, dir1) = copy_fixture(&d1, &a1, "v.qvault");
    let (p2, dir2) = copy_fixture(&d2, &a2, "v.qvault");
    let old_copy = std::fs::read(&p1).unwrap();
    for (p, dir) in [(&p1, &dir1), (&p2, &dir2)] {
        let mut u = unlock(p, dir, PASSWORD).unwrap();
        edit(&mut u, new_record(), "fork");
    }
    // Each fork against the other's anchor: same sequence, other digest.
    let anchor1 = std::fs::read(anchor_file(&a1)).unwrap();
    write_file(&anchor_file(&a2), &anchor1, 0o600);
    assert_eq!(err(unlock(&p2, &dir2, PASSWORD)), StoreError::Rollback);
    // The old copy of the DB with the newer anchor.
    write_file(&p1, &old_copy, 0o600);
    assert_eq!(err(unlock(&p1, &dir1, PASSWORD)), StoreError::Rollback);
    // A DB from another installation: no anchor for its replica here.
    let other = TestDir::new();
    let dir3 = anchors(&other);
    assert_eq!(err(unlock(&p2, &dir3, PASSWORD)), StoreError::NoAnchor);
}

/// Whether `needle` occurs in `hay`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn read_with_journal(p: &Path) -> Vec<u8> {
    let mut bytes = std::fs::read(p).unwrap();
    if let Ok(j) = std::fs::read(crate::fs::with_suffix(p, "-journal")) {
        bytes.extend(j);
    }
    bytes
}

#[test]
fn linkage_no_record_or_version_ids_in_plaintext() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let records = [new_record(), new_record()];
    let mut ids: Vec<[u8; 16]> = Vec::new();
    {
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        for r in records {
            edit(&mut u, r, "first");
            edit(&mut u, r, "second");
        }
        let m = u.manifest();
        for rec in m.records() {
            ids.push(rec.record_id().0);
            for v in rec.heads().iter().chain(rec.history()) {
                ids.push(v.version_id().to_bytes());
                assert!(!v.chunks().is_some_and(|c| !c.is_empty()));
            }
        }
        // While the session is open too (the journal is gone after commit).
        let bytes = read_with_journal(&p);
        for id in &ids {
            assert!(!contains(&bytes, id), "an ID is stored in plaintext");
        }
        // The object table holds exactly the envelope fields.
        let cols: Vec<String> = u
            .file
            .conn
            .prepare("SELECT name FROM pragma_table_info('object') ORDER BY cid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            cols,
            [
                "key_generation",
                "object_id",
                "data_profile",
                "nonce",
                "ciphertext"
            ]
        );
    }
    // 3 control records, 2 entries; versions: 3 + 4.
    assert_eq!(ids.len(), 5 + 7);
    let bytes = read_with_journal(&p);
    for id in &ids {
        assert!(!contains(&bytes, id), "an ID is stored in plaintext");
    }
    // The vault ID is in the header (allowed); a sanity check that the scan
    // finds IDs that are there.
    let u = unlock(&p, &dir, PASSWORD).unwrap();
    assert!(contains(&bytes, &u.header().vault_id.0));
}
