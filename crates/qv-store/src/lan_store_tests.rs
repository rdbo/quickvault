// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN peer-state suites (plan 0037 step 4; 0013 §9, testing rows "Peer state
//! rollback" and "Generation transitions").

use qv_crypto::lan::{LinkKey, LinkRoot, PairNonce};
use qv_crypto::{DerivationProfile, XWingDecapsKey};
use qv_model::{ObjectId, Timestamp};

use crate::anchor::AnchorDir;
use crate::crash::CrashPoint;
use crate::crash::test::{arm, disarm};
use crate::fs::test_dir::TestDir;
use crate::head::AnchorStatus;
use crate::vault::tests::{PASSWORD, copy_fixture, edit, err, kdf, pw, unlock};
use crate::vault::{UnlockedVault, VaultFile};
use crate::{ArchiveScope, StoreError};

/// A real link key for `u`'s vault and generation.
pub(crate) fn link_key(u: &UnlockedVault, link_id: &[u8; 16]) -> LinkKey {
    let h = u.header();
    let root = LinkRoot::derive(
        u.vault_key(),
        h.vault_id,
        h.key_generation,
        DerivationProfile::V1,
    )
    .unwrap();
    let (_, ek) = XWingDecapsKey::generate().unwrap();
    let (ss, _) = ek.encapsulate().unwrap();
    root.link_key(
        &ss,
        &[1; 32],
        &PairNonce::generate().unwrap(),
        link_id,
        h.vault_id,
        h.key_generation,
    )
    .unwrap()
}

fn add(u: &mut UnlockedVault, id: u8) -> Result<(), StoreError> {
    let key = link_key(u, &[id; 16]);
    let mut w = u.write()?;
    w.add_lan_link(
        [id; 16],
        &key,
        &format!("peer {id}"),
        Timestamp(1_000 + i64::from(id)),
    )?;
    w.commit()
}

fn remove(u: &mut UnlockedVault, id: u8) -> Result<(), StoreError> {
    let mut w = u.write()?;
    w.remove_lan_link(&[id; 16])?;
    w.commit()
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
fn lan_links_add_list_remove_and_survive_reopen() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    assert!(u.lan_links().unwrap().is_empty());
    let digest = u.state.head.lan_links_digest;
    assert_eq!(digest, crate::lan_store::empty_digest().unwrap());
    add(&mut u, 2).unwrap();
    add(&mut u, 1).unwrap();
    assert_ne!(u.state.head.lan_links_digest, digest);
    let links = u.lan_links().unwrap();
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].link_id, [1; 16]);
    assert_eq!(links[0].label.expose_secret(), b"peer 1");
    assert_eq!(links[1].created_at, Timestamp(1_002));
    let key = u.lan_link_key(&[1; 16]).unwrap();
    assert!(!key.ct_eq(&u.lan_link_key(&[2; 16]).unwrap()));
    assert_eq!(
        err(u.lan_link_key(&[3; 16]).map(drop)),
        StoreError::NotFound
    );
    drop(u);

    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    assert_eq!(u.lan_links().unwrap().len(), 2);
    assert!(u.lan_link_key(&[1; 16]).unwrap().ct_eq(&key));
    remove(&mut u, 2).unwrap();
    assert_eq!(err(remove(&mut u, 2)), StoreError::NotFound);
    drop(u);
    let u = unlock(&p, &dir, PASSWORD).unwrap();
    let links = u.lan_links().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].link_id, [1; 16]);
}

#[test]
fn lan_links_limits_and_invalid_edits_change_nothing() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (p, dir) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&p, &dir, PASSWORD).unwrap();
    let keys: Vec<_> = (0..=64u8).map(|id| link_key(&u, &[id; 16])).collect();
    {
        let mut w = u.write().unwrap();
        for id in 0..64u8 {
            w.add_lan_link([id; 16], &keys[usize::from(id)], "x", Timestamp(1))
                .unwrap();
        }
        let key = &keys[64];
        assert_eq!(
            err(w.add_lan_link([64; 16], key, "x", Timestamp(1))),
            StoreError::LimitExceeded
        );
        w.commit().unwrap();
    }
    assert_eq!(u.lan_links().unwrap().len(), 64);
    assert_eq!(err(add(&mut u, 99)), StoreError::LimitExceeded);
    remove(&mut u, 63).unwrap();
    let seq = u.local_seq();
    let key = link_key(&u, &[1; 16]);
    let mut w = u.write().unwrap();
    assert_eq!(
        err(w.add_lan_link([1; 16], &key, "dup", Timestamp(1))),
        StoreError::InvalidEdit
    );
    assert_eq!(
        err(w.add_lan_link([70; 16], &key, "", Timestamp(1))),
        StoreError::InvalidEdit
    );
    assert_eq!(
        err(w.add_lan_link([70; 16], &key, &"x".repeat(65), Timestamp(1))),
        StoreError::InvalidEdit
    );
    assert_eq!(
        err(w.add_lan_link([70; 16], &key, "ok", Timestamp(-1))),
        StoreError::InvalidEdit
    );
    drop(w);
    assert_eq!(u.local_seq(), seq);
    assert_eq!(u.lan_links().unwrap().len(), 63);
}

#[test]
fn lan_link_rows_planted_back_modified_or_foreign_are_integrity_errors() {
    for case in 0..4 {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        add(&mut u, 1).unwrap();
        add(&mut u, 2).unwrap();
        drop(u);
        let removed: (Vec<u8>, i64, Vec<u8>) = rusqlite::Connection::open(&p)
            .unwrap()
            .query_row(
                "SELECT link_id, key_generation, sealed FROM lan_link WHERE link_id = ?1",
                [[2u8; 16].as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        remove(&mut u, 2).unwrap();
        drop(u);
        sql(&p, |c| {
            match case {
                // A removed row planted back (0013 §9.1).
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
                // The row deleted (rollback to "no links").
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
fn lan_link_commit_crash_points_leave_old_or_new_state() {
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
            arm(point, &p, &a.join("anchors"), s.path());
            assert_eq!(err(add(&mut u, 1)), StoreError::Internal, "{point:?}");
            assert!(!disarm(), "{point:?} was not reached");
        }
        let anchors = AnchorDir::open(&s.join("anchors")).unwrap();
        let _k = kdf();
        let (u, status) = VaultFile::open(&s.join("v.qvault"))
            .unwrap()
            .unlock_for_recovery(&pw(PASSWORD), &anchors)
            .unwrap();
        assert_eq!(
            u.lan_links().unwrap().len(),
            usize::from(durable),
            "{point:?}"
        );
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
    add(&mut u, 1).unwrap();
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
    assert!(r.lan_links().unwrap().is_empty());
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
