// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::fs::test_dir::TestDir;
use crate::vault::tests::{PASSWORD, copy_fixture, unlock};
use crate::{ArchiveReceipts, ArchiveScope, StoreError, VaultFile};
use crate::{receipt_store, schema, vault};
use qv_encoding::encode_array;

fn plaintext(paths: &[&[u8]]) -> Vec<u8> {
    encode_array(|a| {
        a.uint(1);
        a.array(|rows| {
            for path in paths {
                rows.array(|r| {
                    r.bytes(path);
                    r.bytes(&[7; 32]);
                    Ok(())
                })?;
            }
            Ok(())
        })
    })
    .unwrap()
    .to_vec()
}

// 0012 §1: Hostile SQLite/CBOR
#[test]
fn receipts_canonical_vector_paths_and_malformed_plaintext() {
    let mut receipts = ArchiveReceipts::new();
    assert!(receipts.is_empty());
    assert!(receipts.remember(b"/a", [7; 32]).unwrap());
    let mut expected = vec![0x82, 1, 0x81, 0x82, 0x42, b'/', b'a', 0x58, 0x20];
    expected.extend_from_slice(&[7; 32]);
    assert_eq!(receipts.encode().unwrap().expose_secret(), expected);
    let decoded = ArchiveReceipts::decode(&expected).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded.encode().unwrap().expose_secret(), expected);
    assert_eq!(format!("{receipts:?}"), "ArchiveReceipts(<redacted>)");
    assert!(!receipts.remember(b"/a", [7; 32]).unwrap());
    assert_eq!(
        receipts.remember(b"/a", [8; 32]),
        Err(StoreError::Integrity)
    );
    assert_eq!(receipts.encode().unwrap().expose_secret(), expected);
    for path in [
        b"".as_slice(),
        b"/",
        b"a",
        b"/a/",
        b"/a//b",
        b"/./b",
        b"/a/../b",
        b"/a\0b",
    ] {
        assert_eq!(receipts.remember(path, [7; 32]), Err(StoreError::Integrity));
        assert!(ArchiveReceipts::decode(&plaintext(&[path])).is_err());
    }
    assert!(receipts.remember(b"/non-utf8-\xff", [1; 32]).unwrap());
    for paths in [vec![b"/a".as_slice(), b"/a"], vec![b"/b".as_slice(), b"/a"]] {
        assert_eq!(
            ArchiveReceipts::decode(&plaintext(&paths)).unwrap_err(),
            StoreError::Integrity
        );
    }
    for bad in [
        vec![],
        vec![0x82, 2, 0x80],
        vec![0x82, 1, 0x9f, 0xff],
        vec![0x82, 1, 0x80, 0],
    ] {
        assert!(ArchiveReceipts::decode(&bad).is_err());
    }
}

// 0012 §1: Budget inconsistency
#[test]
fn receipts_limits_allow_redelivery_and_fit_envelope_budget() {
    let mut receipts = ArchiveReceipts::new();
    for i in 0..crate::MAX_ARCHIVE_RECEIPTS {
        let mut path = vec![b'x'; crate::MAX_RECEIPT_PATH_BYTES];
        path[0] = b'/';
        path[1..9].copy_from_slice(format!("{i:08x}").as_bytes());
        receipts.remember(&path, [7; 32]).unwrap();
    }
    let encoded = receipts.encode().unwrap();
    assert!(qv_crypto::sealed_len(encoded.len()).unwrap() <= crate::MAX_RECEIPT_CIPHERTEXT);
    assert_eq!(
        ArchiveReceipts::decode(encoded.expose_secret())
            .unwrap()
            .len(),
        crate::MAX_ARCHIVE_RECEIPTS
    );
    let mut first = vec![b'x'; crate::MAX_RECEIPT_PATH_BYTES];
    first[0] = b'/';
    first[1..9].copy_from_slice(b"00000000");
    assert!(!receipts.remember(&first, [7; 32]).unwrap());
    assert_eq!(
        receipts.remember(&first, [8; 32]),
        Err(StoreError::Integrity)
    );
    assert_eq!(
        receipts.remember(b"/new", [7; 32]),
        Err(StoreError::LimitExceeded)
    );
    let long = vec![b'/'; crate::MAX_RECEIPT_PATH_BYTES + 1];
    assert_eq!(
        receipts.remember(&long, [0; 32]),
        Err(StoreError::LimitExceeded)
    );
    let too_many = plaintext(&vec![b"/a".as_slice(); crate::MAX_ARCHIVE_RECEIPTS + 1]);
    assert_eq!(
        ArchiveReceipts::decode(&too_many).unwrap_err(),
        StoreError::LimitExceeded
    );
}

fn vault(d: &TestDir, a: &TestDir) -> vault::UnlockedVault {
    let (p, anchors) = copy_fixture(d, a, "v.qvault");
    unlock(&p, &anchors, PASSWORD).unwrap()
}

fn receipts(u: &vault::UnlockedVault) -> ArchiveReceipts {
    receipt_store::open(
        &receipt_store::read(&u.file.conn).unwrap(),
        &u.state.head.archive_receipts_digest,
        &vault::Keys::derive(u.vault_key(), u.header()).unwrap(),
        u.header(),
        &u.state.replica.replica_id,
    )
    .unwrap()
}

/// Synthetic already-accepted state for storage tests only. This is not an
/// incoming acceptance implementation: it installs no archive or record data.
fn fixture_receipts(u: &mut vault::UnlockedVault) -> Vec<u8> {
    let keys = vault::Keys::derive(u.vault_key(), u.header()).unwrap();
    let mut rows = ArchiveReceipts::new();
    rows.remember(b"/confidential/receipt-canary.qvsnap", [9; 32])
        .unwrap();
    let blob = receipt_store::seal(&rows, &keys, u.header(), &u.state.replica.replica_id).unwrap();
    let mut head = u.state.head.clone();
    head.archive_receipts_digest = receipt_store::digest(&blob);
    let (stored, _) = vault::sign_head(&keys, u.header(), &head).unwrap();
    u.file.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    u.file
        .conn
        .execute("UPDATE archive_receipts SET sealed=?1 WHERE id=1", [&blob])
        .unwrap();
    u.file
        .conn
        .execute(
            "UPDATE local_head SET body=?1, mac=?2 WHERE id=1",
            rusqlite::params![stored.body, stored.mac.as_slice()],
        )
        .unwrap();
    u.file.conn.execute_batch("COMMIT").unwrap();
    u.state = vault::load_state(&u.file.conn, u.header(), u.vault_key()).unwrap();
    u.anchors
        .store(&u.state.replica.replica_id, &vault::anchor_of(&u.state))
        .unwrap();
    blob
}

// 0012 §1: Whole-file rollback
#[test]
fn receipt_store_preserves_nonempty_state_across_commit_restart_and_restore_reset() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let mut u = vault(&d, &a);
    let empty = receipt_store::read(&u.file.conn).unwrap();
    let blob = fixture_receipts(&mut u);
    assert!(
        !blob
            .windows(b"receipt-canary".len())
            .any(|w| w == b"receipt-canary")
    );
    assert_eq!(receipts(&u).len(), 1);
    u.write().unwrap().commit().unwrap();
    assert_eq!(receipt_store::read(&u.file.conn).unwrap(), blob);
    let anchors = u.anchors.clone();
    drop(u);
    let mut u = unlock(&d.join("v.qvault"), &anchors, PASSWORD).unwrap();
    let mut current = receipts(&u);
    assert!(
        !current
            .remember(b"/confidential/receipt-canary.qvsnap", [9; 32])
            .unwrap()
    );
    assert_eq!(
        current.remember(b"/confidential/receipt-canary.qvsnap", [8; 32]),
        Err(StoreError::Integrity)
    );
    let mut archive = Vec::new();
    u.write_archive(&mut archive, qv_model::Timestamp(1), &|| false)
        .unwrap();
    let path = d.join("restored.qvault");
    VaultFile::create_from_archive(
        &path,
        &mut std::io::Cursor::new(archive),
        ArchiveScope::new(u.header().vault_id, u.header().key_generation),
        u.vault_key(),
        &anchors,
        &|| false,
    )
    .unwrap();
    let restored = unlock(&path, &anchors, PASSWORD).unwrap();
    assert!(receipts(&restored).is_empty());
    assert_ne!(
        restored.state.replica.replica_id,
        u.state.replica.replica_id
    );
    // Swapping back an authentic old receipt envelope cannot roll back just
    // this local table, or get through begin's changed-state check.
    let seq = u.local_seq();
    u.file
        .conn
        .execute("UPDATE archive_receipts SET sealed=?1", [&empty])
        .unwrap();
    assert!(matches!(u.write(), Err(StoreError::Integrity)));
    assert_eq!(u.local_seq(), seq);
    drop(u);
    assert!(matches!(
        unlock(&d.join("v.qvault"), &anchors, PASSWORD),
        Err(StoreError::Integrity)
    ));
}

// 0012 §1: Hostile SQLite/CBOR
#[test]
fn receipt_store_checks_aad_digest_and_sql_bounds_before_decode() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let u = vault(&d, &a);
    let keys = vault::Keys::derive(u.vault_key(), u.header()).unwrap();
    let blob = receipt_store::read(&u.file.conn).unwrap();
    let digest = receipt_store::digest(&blob);
    assert!(receipt_store::open(&blob, &digest, &keys, u.header(), &[0; 16]).is_err());
    let mut other = *u.header();
    other.key_generation = qv_crypto::KeyGeneration(other.key_generation.0 + 1);
    assert!(
        receipt_store::open(&blob, &digest, &keys, &other, &u.state.replica.replica_id).is_err()
    );
    let mut bad = blob.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(
        receipt_store::open(
            &bad,
            &digest,
            &keys,
            u.header(),
            &u.state.replica.replica_id
        )
        .is_err()
    );
    assert!(
        receipt_store::open(
            &bad,
            &receipt_store::digest(&bad),
            &keys,
            u.header(),
            &u.state.replica.replica_id
        )
        .is_err()
    );
    for sql in [
        "DELETE FROM archive_receipts",
        "UPDATE archive_receipts SET sealed=x'00'",
        "UPDATE archive_receipts SET sealed=zeroblob(33554561)",
    ] {
        let before = u.state.digest;
        u.file.conn.execute_batch("SAVEPOINT receipt_test").unwrap();
        u.file.conn.execute_batch(sql).unwrap();
        assert!(vault::load_state(&u.file.conn, u.header(), u.vault_key()).is_err());
        assert_eq!(u.state.digest, before);
        u.file
            .conn
            .execute_batch("ROLLBACK TO receipt_test; RELEASE receipt_test")
            .unwrap();
    }
    // A schema which relaxes SQL constraints cannot substitute another row ID/type.
    schema::tests::tamper(
        &u.file.conn,
        "PRAGMA ignore_check_constraints=ON; UPDATE archive_receipts SET id=2",
    );
    assert_eq!(
        receipt_store::read(&u.file.conn).unwrap_err(),
        StoreError::Integrity
    );
}

// 0012 §1: Rotation/purge ambiguity
#[test]
fn receipt_store_rotation_resets_new_generation_only() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let mut u = vault(&d, &a);
    let blob = fixture_receipts(&mut u);
    let _k = vault::tests::kdf();
    let prepared = u
        .prepare_rotation(&vault::tests::pw("a different rotation password"), &|| {
            false
        })
        .unwrap();
    assert_eq!(
        receipt_store::read(&prepared.source.file.conn).unwrap(),
        blob
    );
    assert_eq!(receipts(&prepared.source).len(), 1);
    assert!(receipts(&prepared.replacement).is_empty());
    assert_ne!(
        prepared.source.header().key_generation,
        prepared.replacement.header().key_generation
    );
    assert_eq!(
        prepared.source.state.replica.replica_id,
        prepared.replacement.state.replica.replica_id
    );
}

#[test]
fn receipt_store_aad_independent_vector_and_authenticated_malformed_plaintext() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let u = vault(&d, &a);
    let replica = u.state.replica.replica_id;
    let mut expected = b"\x85\x76qv/archive-receipts/v1\x50".to_vec();
    expected.extend_from_slice(&u.header().vault_id.0);
    expected.push(1);
    expected.push(0x50);
    expected.extend_from_slice(&replica);
    expected.push(1);
    assert_eq!(
        receipt_store::aad(u.header(), &replica, 1)
            .unwrap()
            .as_slice(),
        expected
    );
    let keys = vault::Keys::derive(u.vault_key(), u.header()).unwrap();
    // These bytes authenticate, so rejection exercises plaintext invariants
    // rather than merely failing the ciphertext tag.
    let plain = plaintext(&[b"/b", b"/a"]);
    let sealed = qv_crypto::seal(
        &keys.local,
        u.header().data_profile,
        &expected,
        &plain,
        crate::MAX_RECEIPT_CIPHERTEXT,
    )
    .unwrap();
    let blob = encode_array(|a| {
        a.uint(1);
        a.uint(1);
        a.bytes(&sealed.nonce);
        a.bytes(&sealed.ciphertext);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        receipt_store::open(
            &blob,
            &receipt_store::digest(&blob),
            &keys,
            u.header(),
            &replica
        )
        .unwrap_err(),
        StoreError::Integrity
    );
}
