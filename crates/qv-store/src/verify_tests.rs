// SPDX-License-Identifier: AGPL-3.0-or-later

//! `verify` suites (plan 0018 step 6; 0012 §1 rows "Whole-file rollback" and
//! "Self-referential/incomplete commitments", store level).
//!
//! A healthy vault reports exact counts; a deleted, short, long, flipped or
//! substituted object, a truncated history version and a corrupt attachment
//! chunk are each an integrity failure. A purge-created floor is expected
//! state, not damage. Nothing is repaired and the vault is never modified.

use qv_crypto::RecordId;
use qv_model::{
    Clock, Extensions, ObjectId, Payload, RandomId, RecordBody, RecordVersion, Text, Timestamp,
};

use crate::fs::test_dir::TestDir;
use crate::vault::UnlockedVault;
use crate::vault::tests::{PASSWORD, copy_fixture, edit, err, unlock};
use crate::{StoreError, VerifyCounts};

/// One vault with a recorded history version and one attachment.
fn setup() -> (TestDir, TestDir, UnlockedVault, RecordId) {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let record = <RecordId as RandomId>::generate().unwrap();
    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    // Two edits of one record: the first becomes retained history.
    edit(&mut u, record, "first");
    edit(&mut u, record, "second");
    let attachment = <RecordId as RandomId>::generate().unwrap();
    {
        let entry = u.manifest().root_group_id();
        let mut w = u.write().unwrap();
        let staged = w
            .stage_attachment(attachment, &mut &vec![9u8; 65_537][..], &|| false)
            .unwrap();
        let meta = staged.into_meta(entry, Text::new("a.bin").unwrap(), Text::new("x").unwrap());
        let counter = w.reserve_counter().unwrap();
        let clock = Clock::for_edit(&w.head_clocks(attachment), w.writer_id(), counter).unwrap();
        let version = RecordVersion {
            version_id: <qv_model::VersionId as RandomId>::generate().unwrap(),
            clock,
            modified_at: Timestamp(1_700_000_000_000),
            body: RecordBody::Live(Payload::AttachmentMeta(meta)),
            ext: Extensions::new(),
        };
        w.put_local(attachment, version).unwrap();
        w.commit().unwrap();
    }
    (d, a, u, record)
}

/// The first chunk object of the fixture's attachment.
fn chunk_object(u: &UnlockedVault) -> ObjectId {
    u.manifest()
        .records()
        .iter()
        .flat_map(|r| r.heads())
        .find_map(|h| h.chunks().and_then(|c| c.first().copied()))
        .expect("the fixture has an attachment")
}

#[test]
fn verify_reports_exact_counts_on_a_healthy_vault() {
    let (d, _a, u, record) = setup();
    let counts = u.verify_all(&|| false).unwrap();
    let m = u.manifest();
    let references = m.references().len() as u64;
    let total: u64 = m.references().iter().map(crate::ObjectRef::length).sum();
    let heads: u64 = m.records().iter().map(|r| r.heads().len() as u64).sum();
    let history: u64 = m.records().iter().map(|r| r.history().len() as u64).sum();
    assert_eq!(counts.objects, references);
    assert_eq!(counts.total_bytes, total);
    assert_eq!(counts.records, m.records().len() as u64);
    assert_eq!(counts.active_heads, heads);
    assert_eq!(counts.retained_versions, history);
    assert_eq!(counts.tombstones, 0);
    assert_eq!(counts.suppressed_records, 0);
    assert_eq!(
        m.record(record).unwrap().history().len(),
        1,
        "the fixture has no retained history"
    );
    assert!(
        !m.records().iter().all(|r| r.heads()[0].chunks().is_none()),
        "the fixture has no attachment"
    );
    // Deterministic.
    assert_eq!(counts, u.verify_all(&|| false).unwrap());
    // Read-only: the vault file is byte-identical afterwards.
    let before = std::fs::read(d.join("v.qvault")).unwrap();
    u.verify_all(&|| false).unwrap();
    assert_eq!(std::fs::read(d.join("v.qvault")).unwrap(), before);
    // The counts are the aggregate integers `verify` prints, nothing else.
    assert!(!format!("{:?}", VerifyCounts::default()).is_empty());
}

#[test]
fn verify_rejects_missing_short_long_flipped_and_substituted_objects() {
    // Every way a disk or a storage layer can damage one object row.
    let cases = [
        "DELETE FROM object WHERE rowid = (SELECT min(rowid) FROM object)",
        "UPDATE object SET ciphertext = substr(ciphertext, 1, length(ciphertext) - 1) \
         WHERE rowid = (SELECT min(rowid) FROM object)",
        "UPDATE object SET ciphertext = CAST(ciphertext || x'00' AS BLOB) \
         WHERE rowid = (SELECT min(rowid) FROM object)",
        "UPDATE object SET ciphertext = CAST((CASE WHEN substr(ciphertext, 1, 1) = x'00' \
         THEN x'01' ELSE x'00' END) || substr(ciphertext, 2) AS BLOB) \
         WHERE rowid = (SELECT min(rowid) FROM object)",
        "UPDATE object SET nonce = zeroblob(24) WHERE rowid = (SELECT min(rowid) FROM object)",
        "UPDATE object SET data_profile = 2 WHERE rowid = (SELECT min(rowid) FROM object)",
        "CREATE TEMP TABLE t AS SELECT * FROM object;
         UPDATE object SET ciphertext = (SELECT ciphertext FROM t \
         WHERE t.object_id <> object.object_id ORDER BY t.object_id LIMIT 1), \
         nonce = (SELECT nonce FROM t \
         WHERE t.object_id <> object.object_id ORDER BY t.object_id LIMIT 1);",
    ];
    for sql in cases {
        let (_d, _a, u, _r) = setup();
        u.file.conn.execute_batch(sql).unwrap();
        assert_eq!(err(u.verify_all(&|| false)), StoreError::Integrity, "{sql}");
    }
}

#[test]
fn verify_rejects_a_truncated_history_version() {
    // The history object alone goes away or changes length: the head still
    // verifies, so only the full pass can find it.
    let (_d, _a, u, record) = setup();
    let history = u.manifest().record(record).unwrap().history()[0].object_id();
    u.file
        .conn
        .execute(
            "DELETE FROM object WHERE object_id = ?1",
            [history.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(err(u.verify_all(&|| false)), StoreError::Integrity);

    let (_d, _a, u, record) = setup();
    let history = u.manifest().record(record).unwrap().history()[0].object_id();
    u.file
        .conn
        .execute(
            "UPDATE object SET ciphertext = CAST(ciphertext || x'00' AS BLOB) \
             WHERE object_id = ?1",
            [history.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(err(u.verify_all(&|| false)), StoreError::Integrity);
}

#[test]
fn verify_rejects_a_corrupt_attachment_chunk() {
    let (_d, _a, u, _record) = setup();
    let chunk = chunk_object(&u);
    assert_eq!(
        u.manifest().reference(chunk).unwrap().length(),
        crate::manifest::chunk_ciphertext_len().unwrap()
    );
    u.file
        .conn
        .execute(
            "UPDATE object SET ciphertext = CAST((CASE WHEN substr(ciphertext, 1, 1) = x'00' \
             THEN x'01' ELSE x'00' END) || substr(ciphertext, 2) AS BLOB) WHERE object_id = ?1",
            [chunk.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(err(u.verify_all(&|| false)), StoreError::Integrity);
}

#[test]
fn verify_treats_a_purge_floor_as_expected_state() {
    let (_d, _a, mut u, record) = setup();
    let healthy = u.verify_all(&|| false).unwrap();
    assert_eq!(healthy.suppressed_records, 0);
    // An explicit purge advances the floor and drops the retained version
    // (0007 §1.4).
    {
        let mut w = u.write().unwrap();
        w.purge_history(record).unwrap();
        w.commit().unwrap();
    }
    let m = u.manifest();
    assert!(m.record(record).unwrap().history().is_empty());
    assert!(!m.record(record).unwrap().floor().clock().pairs().is_empty());
    // The pass still succeeds and reports the floor as expected state, not
    // as damage.
    let after = u.verify_all(&|| false).unwrap();
    assert_eq!(after.suppressed_records, 1);
    assert_eq!(after.retained_versions, healthy.retained_versions - 1);
    assert_eq!(after.active_heads, healthy.active_heads);
    assert_eq!(after.tombstones, healthy.tombstones);
    // No repair: the next pass reports the same thing.
    assert_eq!(u.verify_all(&|| false).unwrap(), after);
}

#[test]
fn verify_rejects_a_changed_head_and_cancels_between_objects() {
    let (_d, _a, u, _record) = setup();
    // Cancellation between objects is an I/O error, not a silent success.
    assert_eq!(err(u.verify_all(&|| true)), StoreError::Io);
    // A head written behind this session's back.
    u.file
        .conn
        .execute_batch("UPDATE local_head SET body = x'a0'")
        .unwrap();
    assert_eq!(err(u.verify_all(&|| false)), StoreError::Changed);
}

#[test]
fn verify_ignores_unreferenced_object_rows() {
    let (_d, _a, u, _record) = setup();
    // An object row no reference names is ignored (0004 §3.6).
    let stray = <ObjectId as RandomId>::generate().unwrap();
    u.file
        .conn
        .execute(
            "INSERT INTO object (key_generation, object_id, data_profile, nonce, ciphertext) \
             VALUES (1, ?1, 1, zeroblob(24), x'00')",
            [stray.to_bytes().as_slice()],
        )
        .unwrap();
    let counts = u.verify_all(&|| false).unwrap();
    assert_eq!(
        counts.objects,
        u.manifest().references().len() as u64,
        "an unreferenced row was counted"
    );
}
