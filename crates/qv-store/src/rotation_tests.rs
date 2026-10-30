// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rotation replacement evidence (plan 0022 steps 3–4; 0012 §1 rows
//! "Migration coupling" (data part) and "Rotation/purge ambiguity"
//! (replacement part)). Every case checks that the source file and the
//! anchor directory are byte-identical afterwards.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use qv_crypto::{KeyGeneration, RecordId, VaultKey};
use qv_model::{Clock, ObjectId, RandomId, RecordBody, RecordKind, RecordVersion, WriterId};

use super::*;
use crate::fs::test_dir::{TestDir, write_file};
use crate::object::seal_record;
use crate::vault::tests::{
    PASSWORD, copy_fixture, edit, entry_version, err, kdf, pw, rewrite_manifest, unlock,
};
use crate::vault::{FileRole, Keys, scope};
use crate::{AnchorDir, StoreError, VaultFile};

const NEW: &str = "replacement generation passphrase with several words";

fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut rows: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    rows.sort();
    rows
}

/// The vault directory and anchor directory contents, for byte equality.
struct Evidence {
    vaults: Vec<(PathBuf, Vec<u8>)>,
    anchors: Vec<(PathBuf, Vec<u8>)>,
}

impl Evidence {
    fn of(d: &TestDir, anchors: &AnchorDir) -> Self {
        Self {
            vaults: files(d.path()),
            anchors: files(anchors.path()),
        }
    }
    fn unchanged(&self, d: &TestDir, anchors: &AnchorDir) {
        assert_eq!(files(d.path()), self.vaults, "vault directory changed");
        assert_eq!(files(anchors.path()), self.anchors, "anchor changed");
    }
}

fn prepare(u: UnlockedVault) -> Result<PreparedRotation, StoreError> {
    let _k = kdf();
    u.prepare_rotation(&pw(NEW), &|| false)
}

/// A rich source: retained history, a floor, a final tombstone and a
/// multi-chunk attachment (from `verify_tests::setup`).
fn rich() -> (TestDir, TestDir, UnlockedVault) {
    let (d, a, mut u, record) = crate::verify_tests::setup();
    let floor = <RecordId as RandomId>::generate().unwrap();
    edit(&mut u, floor, "old");
    edit(&mut u, floor, "new");
    let mut w = u.write().unwrap();
    w.purge_history(floor).unwrap();
    w.commit().unwrap();
    edit(&mut u, record, "third");
    let gone = <RecordId as RandomId>::generate().unwrap();
    edit(&mut u, gone, "to delete");
    {
        let mut w = u.write().unwrap();
        let counter = w.reserve_counter().unwrap();
        let clock = Clock::for_edit(&w.head_clocks(gone), w.writer_id(), counter).unwrap();
        let tombstone = RecordVersion {
            version_id: <qv_model::VersionId as RandomId>::generate().unwrap(),
            clock,
            modified_at: qv_model::Timestamp(1_700_000_000_000),
            body: RecordBody::Tombstone(RecordKind::Entry),
            ext: qv_model::Extensions::new(),
        };
        w.put_local(gone, tombstone).unwrap();
        w.commit().unwrap();
    }
    (d, a, u)
}

fn object_rows(conn: &rusqlite::Connection) -> Vec<(i64, Vec<u8>, Vec<u8>)> {
    conn.prepare("SELECT key_generation, object_id, nonce FROM object")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn temp_of(p: &PreparedRotation) -> PathBuf {
    p._cleanup.0.clone().unwrap()
}

#[test]
fn rotation_replacement_preserves_logical_state_with_fresh_objects() {
    let (d, a, u) = rich();
    let anchors = u.anchors.clone();
    let evidence = Evidence::of(&d, &anchors);
    let source_manifest = u.manifest().clone();
    let source_head = u.state.head.clone();
    let source_digest = u.state.digest;
    let source_replica = u.state.replica;
    let source_rows = object_rows(&u.file.conn);
    let generation = u.header().key_generation;
    let p = prepare(u).unwrap();
    let temp = temp_of(&p);
    assert!(crate::rotation_guard::is_reserved(&temp));
    assert_eq!(p.new_generation(), KeyGeneration(generation.0 + 1));
    let r = &p.replacement;
    assert_eq!(r.header().key_generation, p.new_generation());
    assert_eq!(r.header().vault_id, p.source.header().vault_id);
    assert_eq!(r.state.head.local_seq, source_head.local_seq + 1);
    assert_eq!(r.state.head.previous_digest, Some(source_digest));
    assert!(r.state.head.remote.is_none());
    assert_eq!(r.state.replica.replica_id, source_replica.replica_id);
    assert_eq!(r.state.replica.writer_id, source_replica.writer_id);
    assert_eq!(
        r.state.replica.next_counter,
        source_replica.next_counter + 1
    );

    // Fresh object IDs and nonces, all in the new generation.
    let rows = object_rows(&r.file.conn);
    assert_eq!(rows.len(), source_rows.len() + 1);
    let old_ids: BTreeSet<_> = source_rows.iter().map(|x| x.1.clone()).collect();
    let old_nonces: BTreeSet<_> = source_rows.iter().map(|x| x.2.clone()).collect();
    for (g, id, nonce) in &rows {
        assert_eq!(*g, i64::from(p.new_generation().0));
        assert!(!old_ids.contains(id) && !old_nonces.contains(nonce));
    }

    // Same records, heads, history, floors, IDs and clocks; one keyslot edit.
    let m = r.manifest();
    let keyslot = source_manifest.keyslot_id();
    assert_eq!(m.records().len(), source_manifest.records().len());
    for (x, y) in source_manifest.records().iter().zip(m.records()) {
        assert_eq!(x.record_id(), y.record_id());
        assert_eq!(x.floor(), y.floor());
        let ids = |v: &[crate::VersionRef]| -> Vec<_> {
            v.iter()
                .map(|v| (v.version_id(), v.clock().clone()))
                .collect()
        };
        if x.record_id() == keyslot {
            let (old, new) = (&x.heads()[0], &y.heads()[0]);
            assert_eq!(y.heads().len(), 1);
            assert_ne!(old.version_id(), new.version_id());
            assert_eq!(new.clock().compare(old.clock()), qv_model::Causality::After);
            assert_eq!(
                new.clock()
                    .get(WriterId::from_bytes(source_replica.writer_id).unwrap()),
                source_replica.next_counter
            );
            assert!(y.version(old.version_id()).is_some());
            assert_eq!(y.history().len(), x.history().len() + 1);
        } else {
            assert_eq!(ids(x.heads()), ids(y.heads()));
            assert_eq!(ids(x.history()), ids(y.history()));
            for (a, b) in x
                .heads()
                .iter()
                .chain(x.history())
                .zip(y.heads().iter().chain(y.history()))
            {
                assert_ne!(a.object_id(), b.object_id());
                assert_eq!(a.chunks().map(<[_]>::len), b.chunks().map(<[_]>::len));
            }
        }
    }
    assert!(m.records().iter().any(|r| !r.history().is_empty()));
    assert!(m.records().iter().any(|r| {
        r.heads()
            .iter()
            .any(|h| h.chunks().is_some_and(|c| c.len() == 2))
    }));
    assert!(m.records().iter().any(|r| !r.floor().clock().is_empty()));
    let counts = r.verify_all(&|| false).unwrap();
    assert_eq!(counts.tombstones, 1);

    // The replacement is never reachable through an ordinary open.
    assert_eq!(err(VaultFile::open(&temp)), StoreError::Integrity);
    drop(p);
    assert!(!temp.exists());
    evidence.unchanged(&d, &anchors);
    // The source still unlocks with its password and is unchanged.
    let u = unlock(&d.join("v.qvault"), &anchors, PASSWORD).unwrap();
    assert_eq!(u.manifest(), &source_manifest);
    drop(a);
}

#[test]
fn rotation_replacement_credentials_are_new_and_independent() {
    let (d, _a, u) = rich();
    let anchors = u.anchors.clone();
    let old_phrase = {
        let _k = kdf();
        u.recovery_phrase(&pw(PASSWORD)).unwrap()
    };
    let p = prepare(u).unwrap();
    assert_eq!(format!("{p:?}"), "PreparedRotation(<redacted>)");
    assert_ne!(p.phrase().expose_secret(), old_phrase.expose_secret());
    let temp = temp_of(&p);
    let h = *p.replacement.header();
    // A second, internal Candidate open of the same bytes (copied, since the
    // prepared rotation holds the replacement's lock).
    let copy = d.join("v.qvault.qvrotate-new-copy");
    std::fs::copy(&temp, &copy).unwrap();
    // An orphan left by a crash is inert: ordinary opens refuse it before
    // SQLite or any anchor comparison.
    let anchored = files(anchors.path());
    assert_eq!(err(VaultFile::open(&copy)), StoreError::Integrity);
    assert_eq!(files(anchors.path()), anchored);
    let file = VaultFile::open_locked_as(
        &copy,
        crate::fs::open_existing(&copy).unwrap(),
        FileRole::Candidate,
    )
    .unwrap();
    let slot = &crate::slot::password_slot(&file.slots)
        .unwrap()
        .keyslot
        .slot;
    {
        let _k = kdf();
        assert!(
            slot.unlock(&pw(PASSWORD), h.vault_id, h.key_generation)
                .is_err()
        );
        let vk = slot.unlock(&pw(NEW), h.vault_id, h.key_generation).unwrap();
        file.verify_header(&vk).unwrap();
    }
    let phrase_vk = VaultKey::from_recovery_phrase(p.phrase().expose_secret().as_bytes()).unwrap();
    file.verify_header(&phrase_vk).unwrap();
    let old_vk = VaultKey::from_recovery_phrase(old_phrase.expose_secret().as_bytes()).unwrap();
    assert_eq!(file.verify_header(&old_vk), Err(StoreError::Integrity));
    // The replacement session refuses every write path.
    let mut r = file.finish_candidate(phrase_vk, &anchors).unwrap();
    assert_eq!(err(r.write()), StoreError::Integrity);
    assert_eq!(r.adopt_baseline(), Err(StoreError::Integrity));
    let before = files(anchors.path());
    drop(r);
    assert_eq!(files(anchors.path()), before);
    std::fs::remove_file(&copy).unwrap();
}

#[test]
fn rotation_replacement_drop_failure_and_cancellation_leave_nothing() {
    for case in 0..6 {
        let (d, _a, u) = rich();
        let anchors = u.anchors.clone();
        let evidence = Evidence::of(&d, &anchors);
        let objects = u.manifest().references().len();
        let calls = std::cell::Cell::new(0usize);
        let result = {
            let _k = kdf();
            match case {
                0 => u.prepare_rotation(&pw(NEW), &|| true),
                // Cancelled once the replacement file exists.
                1 => u.prepare_rotation(&pw(NEW), &|| {
                    std::fs::read_dir(d.path()).unwrap().any(|e| {
                        e.unwrap()
                            .file_name()
                            .to_string_lossy()
                            .contains(".qvrotate")
                    })
                }),
                // Cancelled late: during the persisted comparison.
                2 => u.prepare_rotation(&pw(NEW), &|| {
                    calls.set(calls.get() + 1);
                    calls.get() > 4 * objects + 40
                }),
                3..=5 => {
                    let at = [Some(0), Some(objects / 2), Some(usize::MAX)][case - 3];
                    FAIL_AFTER.with(|f| f.set(at));
                    let r = u.prepare_rotation(&pw(NEW), &|| false);
                    FAIL_AFTER.with(|f| f.set(None));
                    r
                }
                _ => unreachable!(),
            }
        };
        let e = err(result);
        assert!(
            matches!(e, StoreError::Io | StoreError::Internal),
            "case {case}: {e:?}"
        );
        evidence.unchanged(&d, &anchors);
    }
}

#[test]
fn rotation_replacement_rejects_corrupted_builds() {
    for corrupt in [1u8, 2] {
        let (d, _a, u) = rich();
        let anchors = u.anchors.clone();
        let evidence = Evidence::of(&d, &anchors);
        CORRUPT.with(|c| c.set(corrupt));
        let r = prepare(u);
        CORRUPT.with(|c| c.set(0));
        assert_eq!(err(r), StoreError::Integrity, "corruption {corrupt}");
        evidence.unchanged(&d, &anchors);
    }
}

#[test]
fn rotation_replacement_refuses_unsafe_sources_before_work() {
    // Missing anchor: the explicit-recovery session stays blocked.
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    for entry in std::fs::read_dir(anchors.path()).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let (u, _) = {
        let _k = kdf();
        VaultFile::open(&path)
            .unwrap()
            .unlock_for_recovery(&pw(PASSWORD), &anchors)
            .unwrap()
    };
    let evidence = Evidence::of(&d, &anchors);
    assert_eq!(err(prepare(u)), StoreError::NoAnchor);
    evidence.unchanged(&d, &anchors);

    // A rotation marker, remote state, a conflicted control record and
    // exhausted counters are refused before any KDF or file work.
    for case in 0..5 {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
        let expected = match case {
            0 => {
                write_file(&crate::fs::with_suffix(&path, ".qvrotate"), b"", 0o600);
                StoreError::Integrity
            }
            1 => {
                u.state.head.remote = Some(([1; 32], 1));
                StoreError::Unsupported
            }
            2 => {
                let id = u.manifest().vault_meta_id();
                let head = u.manifest().record(id).unwrap().heads()[0].clone();
                let other = crate::ObjectRef::new(
                    ObjectId::generate().unwrap(),
                    u.header().data_profile,
                    &[0; 40],
                )
                .unwrap();
                let version = crate::VersionRef::new(
                    <qv_model::VersionId as RandomId>::generate().unwrap(),
                    head.clock().clone(),
                    other.object_id(),
                );
                u.state
                    .manifest
                    .add_head_for_test(id, version, other)
                    .unwrap();
                StoreError::InvalidEdit
            }
            3 => {
                u.state.replica.next_counter = crate::write::MAX_COUNTER;
                StoreError::LimitExceeded
            }
            _ => {
                u.file.header.key_generation = KeyGeneration(u32::MAX);
                StoreError::LimitExceeded
            }
        };
        let evidence = Evidence::of(&d, &anchors);
        let started = std::time::Instant::now();
        assert_eq!(
            err(u.prepare_rotation(&pw(NEW), &|| false)),
            expected,
            "case {case}"
        );
        // Refused before the (slow) password KDF.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "case {case}"
        );
        evidence.unchanged(&d, &anchors);
    }
}

#[test]
fn rotation_replacement_retries_a_pending_anchor_and_refuses_changed_heads() {
    use crate::crash::{CrashPoint, test};
    let (d, a, copied) = (TestDir::new(), TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
    test::arm(CrashPoint::Committed, &path, anchors.path(), copied.path());
    assert_eq!(u.write().unwrap().commit(), Err(StoreError::Internal));
    assert!(!test::disarm());
    let stale = files(anchors.path());
    let p = prepare(u).unwrap();
    // The ordinary retry advanced the anchor to the committed source head.
    assert_ne!(files(anchors.path()), stale);
    assert_eq!(
        p.replacement.state.head.previous_digest,
        Some(p.source.state.digest)
    );
    drop(p);

    // Another session committed after this one unlocked: Changed.
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let u = unlock(&path, &anchors, PASSWORD).unwrap();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute("UPDATE replica SET next_counter = next_counter + 1", [])
            .unwrap();
    }
    let evidence = Evidence::of(&d, &anchors);
    assert_eq!(err(prepare(u)), StoreError::Changed);
    evidence.unchanged(&d, &anchors);
}

#[test]
fn rotation_replacement_preserves_conflicting_entry_heads() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
    let record = <RecordId as RandomId>::generate().unwrap();
    edit(&mut u, record, "ours");
    // A concurrent version by another writer, as a merge would add (2.2).
    let root = u.manifest().root_group_id();
    let theirs = entry_version(root, "theirs", WriterId::generate().unwrap(), 1, &[]);
    let header = *u.header();
    let keys = Keys::derive(&u.vk, &header).unwrap();
    let object = seal_record(
        &keys.record,
        scope(&header),
        header.data_profile,
        record,
        &theirs,
    )
    .unwrap();
    crate::vault::insert_object(&u.file.conn, header.key_generation, &object).unwrap();
    let reference =
        crate::ObjectRef::new(object.object_id, object.data_profile, &object.ciphertext).unwrap();
    let role = crate::VersionRef::new(theirs.version_id, theirs.clock.clone(), object.object_id);
    rewrite_manifest(&mut u, |m| {
        m.add_head_for_test(record, role, reference).unwrap()
    });
    drop(u);
    let (mut u, _) = {
        let _k = kdf();
        VaultFile::open(&path)
            .unwrap()
            .unlock_for_recovery(&pw(PASSWORD), &anchors)
            .unwrap()
    };
    u.adopt_baseline().unwrap();
    assert_eq!(u.manifest().record(record).unwrap().heads().len(), 2);
    let p = prepare(u).unwrap();
    let heads = p.replacement.manifest().record(record).unwrap().heads();
    assert_eq!(heads.len(), 2);
    assert!(heads.iter().any(|h| h.version_id() == theirs.version_id));
    drop(p);
    drop(d);
}

#[test]
fn rotation_replacement_refuses_a_mismatched_anchor() {
    // The anchor from two commits ago: an explicit-recovery session whose
    // writes stay blocked, so rotation is refused with the same error.
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let anchored = files(anchors.path());
    {
        let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
        edit(&mut u, <RecordId as RandomId>::generate().unwrap(), "one");
        edit(&mut u, <RecordId as RandomId>::generate().unwrap(), "two");
    }
    for (file, bytes) in &anchored {
        write_file(file, bytes, 0o600);
    }
    let (u, status) = {
        let _k = kdf();
        VaultFile::open(&path)
            .unwrap()
            .unlock_for_recovery(&pw(PASSWORD), &anchors)
            .unwrap()
    };
    assert_eq!(status, crate::AnchorStatus::Mismatch);
    let evidence = Evidence::of(&d, &anchors);
    assert_eq!(err(prepare(u)), StoreError::Rollback);
    evidence.unchanged(&d, &anchors);
}

#[test]
fn rotation_replacement_preserves_unknown_extension_fields() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
    let root = u.manifest().root_group_id();
    // An entry version with an unknown envelope key (0003 §2.2), built by
    // decoding, the only way extensions arise.
    let extended = <RecordId as RandomId>::generate().unwrap();
    let ext_version = {
        let mut w = u.write().unwrap();
        let counter = w.reserve_counter().unwrap();
        let plain = entry_version(root, "ext", w.writer_id(), counter, &[]);
        let mut bytes = plain.encode().unwrap().to_vec();
        assert!((0xa0..0xb7).contains(&bytes[0]), "small map header");
        bytes[0] += 1;
        bytes.extend_from_slice(&[0x14, 0x61, 0x78]); // 20: "x"
        let v = RecordVersion::decode(&bytes).unwrap();
        assert_eq!(v.ext.len(), 1);
        let id = v.version_id;
        w.put_local(extended, v).unwrap();
        w.commit().unwrap();
        id
    };
    let source_ext = u.read_version(extended, ext_version).unwrap();
    let evidence = Evidence::of(&d, &anchors);

    let p = prepare(u).unwrap();
    let replaced = p.replacement.read_version(extended, ext_version).unwrap();
    assert_eq!(replaced.ext.len(), 1);
    assert!(replaced.ext.content_eq(&source_ext.ext));
    drop(p);
    evidence.unchanged(&d, &anchors);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 6, ..ProptestConfig::default() })]
    #[test]
    fn rotation_replacement_property_random_histories(ops in proptest::collection::vec((0usize..3, 0usize..3), 1..6)) {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
        let records: Vec<RecordId> = (0..3).map(|_| <RecordId as RandomId>::generate().unwrap()).collect();
        for (i, (which, op)) in ops.into_iter().enumerate() {
            let r = records[which];
            if op == 2 && u.manifest().record(r).is_some() {
                let mut w = u.write().unwrap();
                w.purge_history(r).unwrap();
                w.commit().unwrap();
            } else {
                edit(&mut u, r, &format!("v{i}"));
            }
        }
        let source = u.manifest().clone();
        let evidence = Evidence::of(&d, &anchors);
        let p = prepare(u).unwrap();
        for x in source.records() {
            let y = p.replacement.manifest().record(x.record_id()).unwrap();
            prop_assert_eq!(x.floor(), y.floor());
            if x.record_id() != source.keyslot_id() {
                prop_assert_eq!(x.heads().len(), y.heads().len());
                prop_assert_eq!(x.history().len(), y.history().len());
            }
        }
        drop(p);
        evidence.unchanged(&d, &anchors);
    }
}
