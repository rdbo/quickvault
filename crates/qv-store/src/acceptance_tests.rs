// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::fs::test_dir::TestDir;
use crate::vault::tests::{PASSWORD, copy_fixture, edit, entry_version, pw, unlock};
use crate::{
    AnchorDir, ArchiveScope, IncomingRead, Manifest, StoreError, VaultFile, VerifiedIncoming,
};
use crate::{
    crash::{
        CrashPoint,
        test::{arm, disarm},
    },
    receipt_store, vault,
};
use qv_crypto::RecordId;
use qv_model::{Clock, RandomId, RecordBody, RecordKind, Timestamp, VersionId};

fn local(d: &TestDir, a: &TestDir) -> vault::UnlockedVault {
    let (path, anchors) = copy_fixture(d, a, "v.qvault");
    unlock(&path, &anchors, PASSWORD).unwrap()
}
fn incoming(
    u: &vault::UnlockedVault,
    source: &std::path::Path,
    private: &TestDir,
) -> VerifiedIncoming {
    VerifiedIncoming::open(
        source,
        private.path(),
        ArchiveScope::new(u.header().vault_id, u.header().key_generation),
        u.vault_key(),
        &|| false,
    )
    .unwrap()
}
fn export(u: &mut vault::UnlockedVault, path: &std::path::Path) {
    u.write_archive(std::fs::File::create(path).unwrap(), Timestamp(1), &|| {
        false
    })
    .unwrap();
}
fn proposed(
    _: &Manifest,
    incoming: &Manifest,
    _: &mut IncomingRead<'_>,
) -> Result<Manifest, StoreError> {
    Ok(incoming.clone()) // Only appropriate for these ancestor-local fixtures.
}
fn receipt_count(u: &vault::UnlockedVault) -> usize {
    receipt_store::open(
        &receipt_store::read(&u.file.conn).unwrap(),
        &u.state.head.archive_receipts_digest,
        &vault::Keys::derive(u.vault_key(), u.header()).unwrap(),
        u.header(),
        &u.state.replica.replica_id,
    )
    .unwrap()
    .len()
}

// 0012 §1: Hostile files from sync folders
#[test]
fn acceptance_atomic_receipts_redelivery_restart_and_changed_filename() {
    let (d, a, r, ra, private) = (
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
    );
    let mut u = local(&d, &a);
    let mut remote = local(&r, &ra);
    let id = <RecordId as RandomId>::generate().unwrap();
    edit(&mut remote, id, "incoming secret");
    let source = d.join("incoming.qvsnap");
    export(&mut remote, &source);
    let before = u.state.replica;
    let slot = u.file.slots[0].body.clone();
    let mut input = incoming(&u, &source, &private);
    let refs = input.manifest().references().to_vec();
    assert!(
        u.accept_incoming(&mut input, &mut proposed, &|| false)
            .unwrap()
    );
    assert_eq!(u.state.replica, before);
    assert_eq!(u.file.slots[0].body, slot);
    assert_eq!(u.manifest().references(), refs);
    u.verify_all(&|| false).unwrap();
    assert_eq!(receipt_count(&u), 1);
    let seq = u.local_seq();
    assert!(
        !u.accept_incoming(&mut input, &mut proposed, &|| false)
            .unwrap()
    );
    assert_eq!(u.local_seq(), seq);
    let anchors = u.anchors.clone();
    drop(u);
    let mut u = unlock(&d.join("v.qvault"), &anchors, PASSWORD).unwrap();
    assert!(
        !u.accept_incoming(&mut input, &mut proposed, &|| false)
            .unwrap()
    );
    assert_eq!(u.local_seq(), seq);
    // Same path, newly authenticated different bytes; refuses even after restart.
    edit(&mut remote, id, "changed");
    export(&mut remote, &source);
    let mut changed = incoming(&u, &source, &private);
    assert_eq!(
        u.accept_incoming(&mut changed, &mut proposed, &|| false),
        Err(StoreError::Integrity)
    );
    assert_eq!(u.local_seq(), seq);
    assert_eq!(receipt_count(&u), 1);
}

// 0012 §1: Self-referential/incomplete commitments
#[test]
fn acceptance_rejects_omitted_state_forged_floors_and_cancellation() {
    let (d, a, r, ra, private) = (
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
    );
    let mut u = local(&d, &a);
    let mut remote = local(&r, &ra);
    edit(
        &mut remote,
        <RecordId as RandomId>::generate().unwrap(),
        "required",
    );
    let source = d.join("in.qvsnap");
    export(&mut remote, &source);
    let mut input = incoming(&u, &source, &private);
    let seq = u.local_seq();
    assert_eq!(
        u.accept_incoming(&mut input, &mut |l, _, _| Ok(l.clone()), &|| false),
        Err(StoreError::Integrity)
    );
    assert_eq!(
        u.accept_incoming(
            &mut input,
            &mut |_, m, _| {
                let mut records = m.records().to_vec();
                let r = &records[0];
                records[0] = crate::RecordEntry::from_parts(
                    r.record_id(),
                    r.heads().to_vec(),
                    r.history().to_vec(),
                    qv_model::HistoryFloor::new(r.heads()[0].clock().clone()),
                )?;
                m.candidate(records, m.references().to_vec())
            },
            &|| false
        ),
        Err(StoreError::Integrity)
    );
    let cancelled = std::cell::Cell::new(false);
    assert_eq!(
        u.accept_incoming(
            &mut input,
            &mut |_, m, _| {
                cancelled.set(true);
                Ok(m.clone())
            },
            &|| cancelled.get()
        ),
        Err(StoreError::Io)
    );
    assert_eq!(u.local_seq(), seq);
    assert_eq!(receipt_count(&u), 0);
    u.verify_all(&|| false).unwrap();
    assert!(
        u.accept_incoming(&mut input, &mut proposed, &|| false)
            .unwrap()
    );
}

// 0012 §1: Anchor crash windows
#[test]
fn acceptance_crash_matrix_data_receipt_head_anchor_are_one_commit() {
    let (r, ra) = (TestDir::new(), TestDir::new());
    let mut remote = local(&r, &ra);
    let id = <RecordId as RandomId>::generate().unwrap();
    edit(&mut remote, id, "crash incoming");
    let source = r.join("in.qvsnap");
    export(&mut remote, &source);
    for (point, committed) in [
        (CrashPoint::Begun, false),
        (CrashPoint::ObjectsWritten, false),
        (CrashPoint::ReceiptsWritten, false),
        (CrashPoint::ManifestWritten, false),
        (CrashPoint::HeadWritten, false),
        (CrashPoint::Pruned, false),
        (CrashPoint::Committed, true),
        (CrashPoint::AnchorTempWritten, true),
        (CrashPoint::AnchorReplaced, true),
    ] {
        let (d, a, private, snapshot) = (
            TestDir::new(),
            TestDir::new(),
            TestDir::new(),
            TestDir::new(),
        );
        let mut u = local(&d, &a);
        let mut input = incoming(&u, &source, &private);
        let seq = u.local_seq();
        arm(
            point,
            &d.join("v.qvault"),
            &a.join("anchors"),
            snapshot.path(),
        );
        assert_eq!(
            u.accept_incoming(&mut input, &mut proposed, &|| false),
            Err(StoreError::Internal),
            "{point:?}"
        );
        assert!(!disarm(), "{point:?}");
        if committed {
            assert!(
                !u.accept_incoming(&mut input, &mut proposed, &|| false)
                    .unwrap()
            );
            assert_eq!(u.local_seq(), seq + 1); // pending anchor retry creates no second commit.
        }
        drop(u);
        let anchors = AnchorDir::open(&snapshot.join("anchors")).unwrap();
        let mut restarted = unlock(&snapshot.join("v.qvault"), &anchors, PASSWORD).unwrap();
        assert_eq!(
            restarted.manifest().record(id).is_some(),
            committed,
            "{point:?}"
        );
        assert_eq!(
            receipt_count(&restarted),
            usize::from(committed),
            "{point:?}"
        );
        assert_eq!(
            restarted
                .accept_incoming(&mut input, &mut proposed, &|| false)
                .unwrap(),
            !committed
        );
        assert_eq!(restarted.local_seq(), seq + 1);
        assert_eq!(receipt_count(&restarted), 1);
        restarted.verify_all(&|| false).unwrap();
    }
}

// 0012 §1: Deleted-entry resurrection
#[test]
fn acceptance_tombstones_survive_later_edits_purge_final_delete_restore_and_rotation() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let mut u = local(&d, &a);
    let id = <RecordId as RandomId>::generate().unwrap();
    edit(&mut u, id, "original");
    let finalize = |u: &mut vault::UnlockedVault| {
        let mut w = u.write().unwrap();
        let counter = w.reserve_counter().unwrap();
        let version = qv_model::RecordVersion {
            version_id: VersionId::generate().unwrap(),
            clock: Clock::for_edit(w.head_clocks(id).iter(), w.writer_id(), counter).unwrap(),
            modified_at: Timestamp(1),
            body: RecordBody::Tombstone(RecordKind::Entry),
            ext: qv_model::Extensions::new(),
        };
        w.put_local(id, version).unwrap();
        w.commit().unwrap();
    };
    finalize(&mut u);
    // Deliberate causal restore creates a new complete version, retaining the old tombstone.
    let root = u.manifest().root_group_id();
    let mut w = u.write().unwrap();
    let c = w.reserve_counter().unwrap();
    let mut restored = entry_version(root, "restored", w.writer_id(), c, &[]);
    restored.clock = Clock::for_edit(w.head_clocks(id).iter(), w.writer_id(), c).unwrap();
    w.put_local(id, restored).unwrap();
    w.commit().unwrap();
    let mut w = u.write().unwrap();
    w.purge_history(id).unwrap();
    w.commit().unwrap();
    assert_eq!(u.manifest().record(id).unwrap().history().len(), 1);
    finalize(&mut u);
    assert_eq!(u.manifest().record(id).unwrap().history().len(), 1);
    assert!(u.manifest().record(id).unwrap().history()[0].is_tombstone());
    u.verify_all(&|| false).unwrap();
    let mut archive = Vec::new();
    u.write_archive(&mut archive, Timestamp(1), &|| false)
        .unwrap();
    VaultFile::create_from_archive(
        &d.join("restored.qvault"),
        &mut std::io::Cursor::new(archive),
        ArchiveScope::new(u.header().vault_id, u.header().key_generation),
        u.vault_key(),
        &u.anchors,
        &|| false,
    )
    .unwrap();
    let restored = unlock(&d.join("restored.qvault"), &u.anchors, PASSWORD).unwrap();
    assert_eq!(restored.manifest().record(id).unwrap().history().len(), 1);
    let _k = vault::tests::kdf();
    let rotated = u
        .prepare_rotation(&pw("new rotation password"), &|| false)
        .unwrap();
    assert!(rotated.replacement.manifest().record(id).unwrap().history()[0].is_tombstone());
}

// 0012 §1: Hostile files from sync folders
#[test]
fn acceptance_paths_normalize_without_symlink_traversal_or_filename_spoofing() {
    use std::os::unix::fs::symlink;
    let (d, a, private) = (TestDir::new(), TestDir::new(), TestDir::new());
    let mut u = local(&d, &a);
    let source = d.join("in.qvsnap");
    export(&mut u, &source);
    let alias = d.join("missing/.././in.qvsnap");
    let mut first = incoming(&u, &alias, &private);
    assert!(
        u.accept_incoming(&mut first, &mut proposed, &|| false)
            .unwrap()
    );
    let mut same = incoming(&u, &source, &private);
    assert!(
        !u.accept_incoming(&mut same, &mut proposed, &|| false)
            .unwrap()
    );
    let link = d.join("link");
    symlink(d.path(), &link).unwrap();
    assert!(
        VerifiedIncoming::open(
            &link.join("in.qvsnap"),
            private.path(),
            ArchiveScope::new(u.header().vault_id, u.header().key_generation),
            u.vault_key(),
            &|| false
        )
        .is_err()
    );
    let bytes =
        crate::incoming_path::normalize(std::path::Path::new("./a/../receipt-test")).unwrap();
    assert!(bytes.expose_secret().ends_with(b"/receipt-test"));
    assert_eq!(
        crate::incoming_path::normalize(std::path::Path::new("/../../a"))
            .unwrap()
            .expose_secret(),
        b"/a"
    );
}

// 0012 §1: Mixed credentials
#[test]
fn acceptance_preserves_working_slot_rejects_foreign_scope_and_false_tombstone_marker() {
    let (d, a, r, ra, private) = (
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
    );
    let mut u = local(&d, &a);
    let mut remote = local(&r, &ra);
    let keyslot = remote.manifest().keyslot_id();
    let mut w = remote.write().unwrap();
    let descriptor = {
        let _k = vault::tests::kdf();
        w.stage_password(
            &pw("changed remote password"),
            qv_crypto::PasswordKdfProfile::V1,
            qv_crypto::PasswordWrapProfile::V1,
        )
        .unwrap()
    };
    let counter = w.reserve_counter().unwrap();
    let v = qv_model::RecordVersion {
        version_id: VersionId::generate().unwrap(),
        clock: Clock::for_edit(w.head_clocks(keyslot).iter(), w.writer_id(), counter).unwrap(),
        modified_at: Timestamp(1),
        body: RecordBody::Live(qv_model::Payload::PasswordKeyslot(descriptor)),
        ext: qv_model::Extensions::new(),
    };
    w.put_local(keyslot, v).unwrap();
    w.commit().unwrap();
    let source = d.join("slot.qvsnap");
    export(&mut remote, &source);
    let slot = u.file.slots[0].body.clone();
    let mut input = incoming(&u, &source, &private);
    u.accept_incoming(&mut input, &mut proposed, &|| false)
        .unwrap();
    assert_eq!(u.file.slots[0].body, slot);
    let anchors = u.anchors.clone();
    drop(u);
    let mut u = unlock(&d.join("v.qvault"), &anchors, PASSWORD).unwrap();
    let root = u.manifest().root_group_id();
    let role = u.manifest().record(root).unwrap().heads()[0].clone();
    let version = u.read_version(root, role.version_id()).unwrap();
    assert_eq!(
        crate::validation::check_head(u.manifest(), root, &role.with_tombstone(), &version),
        Err(StoreError::Integrity)
    );
    let mut foreign = {
        let _k = vault::tests::kdf();
        VaultFile::create(
            &r.join("foreign.qvault"),
            &pw(PASSWORD),
            "foreign",
            &remote.anchors,
        )
        .unwrap()
    };
    export(&mut foreign, &source);
    let mut input = VerifiedIncoming::open(
        &source,
        private.path(),
        ArchiveScope::new(foreign.header().vault_id, foreign.header().key_generation),
        foreign.vault_key(),
        &|| false,
    )
    .unwrap();
    let seq = u.local_seq();
    assert_eq!(
        u.accept_incoming(&mut input, &mut proposed, &|| false),
        Err(StoreError::Integrity)
    );
    assert_eq!(u.local_seq(), seq);
}

// 0012 §1: Budget inconsistency
#[test]
fn acceptance_receipt_capacity_allows_identical_delivery_and_rejects_new_name_atomically() {
    let (d, a, private) = (TestDir::new(), TestDir::new(), TestDir::new());
    let mut u = local(&d, &a);
    let source = d.join("in.qvsnap");
    export(&mut u, &source);
    let mut input = incoming(&u, &source, &private);
    let mut receipts = crate::ArchiveReceipts::new();
    receipts
        .remember(input.path.expose_secret(), *input.digest())
        .unwrap();
    for i in 1..crate::MAX_ARCHIVE_RECEIPTS {
        receipts
            .remember(format!("/receipt-fixture-{i}").as_bytes(), [7; 32])
            .unwrap();
    }
    // A signed at-capacity starting fixture, not a production acceptance API.
    let keys = vault::Keys::derive(u.vault_key(), u.header()).unwrap();
    let blob =
        receipt_store::seal(&receipts, &keys, u.header(), &u.state.replica.replica_id).unwrap();
    let mut head = u.state.head.clone();
    head.archive_receipts_digest = receipt_store::digest(&blob);
    let (stored, _) = vault::sign_head(&keys, u.header(), &head).unwrap();
    u.file.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    u.file
        .conn
        .execute("UPDATE archive_receipts SET sealed=?1", [&blob])
        .unwrap();
    u.file
        .conn
        .execute(
            "UPDATE local_head SET body=?1,mac=?2",
            rusqlite::params![stored.body, stored.mac.as_slice()],
        )
        .unwrap();
    u.file.conn.execute_batch("COMMIT").unwrap();
    u.state = vault::load_state(&u.file.conn, u.header(), u.vault_key()).unwrap();
    u.anchors
        .store(&u.state.replica.replica_id, &vault::anchor_of(&u.state))
        .unwrap();
    let seq = u.local_seq();
    assert!(
        !u.accept_incoming(
            &mut input,
            &mut |_, _, _| panic!("duplicate must not merge"),
            &|| false
        )
        .unwrap()
    );
    let second = d.join("new.qvsnap");
    std::fs::copy(&source, &second).unwrap();
    let mut input = incoming(&u, &second, &private);
    assert_eq!(
        u.accept_incoming(
            &mut input,
            &mut |_, _, _| panic!("capacity must not merge"),
            &|| false
        ),
        Err(StoreError::LimitExceeded)
    );
    assert_eq!(u.local_seq(), seq);
    assert_eq!(receipt_store::read(&u.file.conn).unwrap(), blob);
}

// 0012 §1: Anchor crash windows
#[test]
fn acceptance_cancellation_through_staging_and_last_precommit_check_is_atomic() {
    let (r, ra) = (TestDir::new(), TestDir::new());
    let mut remote = local(&r, &ra);
    let id = <RecordId as RandomId>::generate().unwrap();
    edit(&mut remote, id, "cancel incoming");
    let source = r.join("in.qvsnap");
    export(&mut remote, &source);
    let total = {
        let (d, a, private) = (TestDir::new(), TestDir::new(), TestDir::new());
        let mut u = local(&d, &a);
        let mut input = incoming(&u, &source, &private);
        let calls = std::cell::Cell::new(0);
        u.accept_incoming(&mut input, &mut proposed, &|| {
            calls.set(calls.get() + 1);
            false
        })
        .unwrap();
        calls.get()
    };
    for boundary in [1, total / 4, total / 2, total - 1, total] {
        let (d, a, private) = (TestDir::new(), TestDir::new(), TestDir::new());
        let mut u = local(&d, &a);
        let mut input = incoming(&u, &source, &private);
        let seq = u.local_seq();
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            u.accept_incoming(&mut input, &mut proposed, &|| {
                calls.set(calls.get() + 1);
                calls.get() >= boundary
            }),
            Err(StoreError::Io)
        );
        assert_eq!(u.local_seq(), seq);
        assert_eq!(receipt_count(&u), 0);
        assert!(u.manifest().record(id).is_none());
        assert!(
            u.accept_incoming(&mut input, &mut proposed, &|| false)
                .unwrap()
        );
        assert_eq!(u.local_seq(), seq + 1);
        assert_eq!(receipt_count(&u), 1);
    }
}
