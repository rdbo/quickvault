// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retired LAN peer state (plans 0037 step 4, 0042 step 4; 0013 §9.1,
//! testing rows "Peer state rollback" and "No peer state"): files written
//! before 0014 may hold `lan_link` rows; they open, and their next commit
//! clears them. Planted or modified rows are still integrity errors.

use qv_model::{ObjectId, RandomId, RecordId, Timestamp};

use crate::anchor::AnchorDir;
use crate::crash::CrashPoint;
use crate::crash::test::{arm, disarm};
use crate::fs::test_dir::TestDir;
use crate::head::AnchorStatus;
use crate::lan_store::{StoredLink, empty_digest};
use crate::vault::tests::{PASSWORD, copy_fixture, edit, err, kdf, pw, unlock};
use crate::vault::{UnlockedVault, VaultFile};
use crate::{ArchiveScope, StoreError};

/// Commits `ids` as `lan_link` rows, as a pre-0014 file could hold them.
/// The sealed blobs are opaque: rows are never decrypted.
fn plant(u: &mut UnlockedVault, ids: &[u8]) {
    let mut w = u.write().unwrap();
    w.plant_lan_links(
        ids.iter()
            .map(|&id| StoredLink {
                link_id: [id; 16],
                sealed: vec![id; 40],
            })
            .collect(),
    );
    w.commit().unwrap();
}

fn sql(path: &std::path::Path, f: impl FnOnce(&rusqlite::Connection)) {
    let conn = rusqlite::Connection::open(path).unwrap();
    f(&conn);
}

fn count(path: &std::path::Path, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn lan_links_left_by_an_older_file_open_and_clear_at_the_next_commit() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    assert_eq!(u.state.head.lan_links_digest, empty_digest().unwrap());
    plant(&mut u, &[2, 1]);
    assert_ne!(u.state.head.lan_links_digest, empty_digest().unwrap());
    drop(u);
    // The older file opens and verifies; its rows are kept until a commit.
    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    assert_eq!(u.state.links.len(), 2);
    assert_eq!(count(&p, "lan_link"), 2);
    edit(
        &mut u,
        <RecordId as RandomId>::generate().unwrap(),
        "any edit",
    );
    assert!(u.state.links.is_empty());
    assert_eq!(u.state.head.lan_links_digest, empty_digest().unwrap());
    assert_eq!(count(&p, "lan_link"), 0);
    drop(u);
    let u = unlock(&p, &dir, PASSWORD).unwrap();
    assert!(u.state.links.is_empty());
}

#[test]
fn lan_link_rows_planted_back_modified_or_foreign_are_integrity_errors() {
    for case in 0..4 {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        plant(&mut u, &[1]);
        drop(u);
        let removed: (Vec<u8>, i64, Vec<u8>) = rusqlite::Connection::open(&p)
            .unwrap()
            .query_row(
                "SELECT link_id, key_generation, sealed FROM lan_link WHERE link_id = ?1",
                [[1u8; 16].as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        if case == 0 {
            // A commit clears the row; planting it back must fail.
            let mut u = unlock(&p, &dir, PASSWORD).unwrap();
            edit(
                &mut u,
                <RecordId as RandomId>::generate().unwrap(),
                "clears links",
            );
            drop(u);
        }
        sql(&p, |c| {
            match case {
                // A cleared row planted back (0013 §9.1).
                0 => c
                    .execute(
                        "INSERT INTO lan_link VALUES (?1, ?2, ?3)",
                        rusqlite::params![removed.0, removed.1, removed.2],
                    )
                    .unwrap(),
                // A modified sealed blob.
                1 => c
                    .execute(
                        "UPDATE lan_link SET sealed = CAST(sealed || x'00' AS BLOB)",
                        [],
                    )
                    .unwrap(),
                // A row claiming another generation.
                2 => c
                    .execute("UPDATE lan_link SET key_generation = 2", [])
                    .unwrap(),
                // The row deleted behind the head's back.
                _ => c.execute("DELETE FROM lan_link", []).unwrap(),
            };
        });
        let _k = kdf();
        assert_eq!(
            err(VaultFile::open(&p).and_then(|f| f.unlock(&pw(PASSWORD), &dir))),
            StoreError::Integrity,
            "case {case}"
        );
    }
}

#[test]
fn lan_link_row_count_is_bounded_before_reading() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    sql(&p, |c| {
        for i in 0..65u8 {
            c.execute(
                "INSERT INTO lan_link VALUES (?1, 1, x'00')",
                [[i; 16].as_slice()],
            )
            .unwrap();
        }
    });
    let _k = kdf();
    assert_eq!(
        err(VaultFile::open(&p).and_then(|f| f.unlock(&pw(PASSWORD), &dir))),
        StoreError::LimitExceeded
    );
}

#[test]
fn lan_link_clearing_crash_points_leave_old_or_new_state() {
    use CrashPoint::*;
    for (point, durable) in [
        (LanLinksWritten, false),
        (HeadWritten, false),
        (Committed, true),
        (AnchorReplaced, true),
    ] {
        let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        {
            let mut u = unlock(&p, &dir, PASSWORD).unwrap();
            plant(&mut u, &[1]);
            arm(point, &p, &a.join("anchors"), s.path());
            let w = u.write().unwrap();
            assert_eq!(err(w.commit()), StoreError::Internal, "{point:?}");
            assert!(!disarm(), "{point:?} was not reached");
        }
        let anchors = AnchorDir::open(&s.join("anchors")).unwrap();
        let _k = kdf();
        let (u, status) = VaultFile::open(&s.join("v.qvault"))
            .unwrap()
            .unlock_for_recovery(&pw(PASSWORD), &anchors)
            .unwrap();
        // Durable: the rows are cleared; otherwise the old rows remain.
        assert_eq!(u.state.links.is_empty(), durable, "{point:?}");
        let want = match point {
            Committed => AnchorStatus::Advanced,
            _ => AnchorStatus::Verified,
        };
        assert_eq!(status, want, "{point:?}");
    }
}

#[test]
fn lan_links_never_enter_archives_or_restores() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    plant(&mut u, &[1]);
    let mut bytes = Vec::new();
    u.write_archive(&mut bytes, Timestamp(1), &|| false)
        .unwrap();
    let target = d.join("restored.qvault");
    VaultFile::create_from_archive(
        &target,
        &mut std::io::Cursor::new(&bytes),
        ArchiveScope::new(u.header().vault_id, u.header().key_generation),
        u.vault_key(),
        &u.anchors,
        &|| false,
    )
    .unwrap();
    let r = unlock(&target, &u.anchors, PASSWORD).unwrap();
    assert!(r.state.links.is_empty());
    assert_eq!(count(&target, "lan_link"), 0);
}

#[test]
fn lan_serve_state_matches_the_committed_manifest_and_archive_frames() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    edit(&mut u, qv_model::RandomId::generate().unwrap(), "served");
    let state = u.lan_serve_state().unwrap();
    assert_eq!(state.manifest_hash(), &u.state.head.manifest_hash);
    assert_eq!(
        qv_crypto::object_hash(qv_crypto::ObjectHashProfile::V1, state.envelope()).0,
        u.state.head.manifest_hash
    );
    assert_eq!(state.object_count(), u.manifest().references().len());
    // The same bytes as an archive's frames.
    let mut archive = Vec::new();
    u.write_archive(&mut archive, Timestamp(1), &|| false)
        .unwrap();
    let find = |needle: &[u8]| archive.windows(needle.len()).any(|w| w == needle);
    assert!(find(state.envelope()));
    for r in u.manifest().references() {
        let env = u.lan_object_envelope(&state, r.object_id()).unwrap();
        assert!(find(&env));
    }
    let unknown: ObjectId = qv_model::RandomId::generate().unwrap();
    assert_eq!(
        err(u.lan_object_envelope(&state, unknown)),
        StoreError::InvalidEdit
    );
    // A pruned row: the served state can no longer be served.
    let first = u.manifest().references()[0].object_id();
    drop(state);
    let state = u.lan_serve_state().unwrap();
    u.file
        .conn
        .execute(
            "DELETE FROM object WHERE object_id = ?1",
            [qv_model::RandomId::to_bytes(&first).as_slice()],
        )
        .unwrap();
    assert_eq!(
        err(u.lan_object_envelope(&state, first)),
        StoreError::NotFound
    );
}
