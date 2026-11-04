// SPDX-License-Identifier: AGPL-3.0-or-later

//! New-device staging and creation suites (plan 0037 step 5; 0013 §10).

use std::path::Path;

use qv_crypto::{KeyGeneration, VaultId, VaultKey};
use qv_model::Timestamp;

use crate::anchor::AnchorDir;
use crate::crash::CrashPoint;
use crate::crash::test::{arm, disarm};
use crate::fs::test_dir::{TestDir, write_file};
use crate::lan_store_tests::link_key;
use crate::vault::UnlockedVault;
use crate::vault::tests::{NAME, PASSWORD, err, kdf, pw, unlock};
use crate::{LanStaging, NewLanLink, StagedKeyslot, StoreError, VaultFile, VerifiedLanStaging};

fn begin(u: &UnlockedVault, dir: &Path) -> Result<LanStaging, StoreError> {
    let state = u.lan_serve_state()?;
    let h = u.header();
    LanStaging::begin(
        dir,
        u.vault_key(),
        h.vault_id,
        h.key_generation,
        state.manifest_hash(),
        state.envelope(),
        &|| false,
    )
}

/// Stages `u` completely, as a joining device would receive it.
fn staged(u: &UnlockedVault, dir: &Path) -> VerifiedLanStaging {
    let state = u.lan_serve_state().unwrap();
    let mut s = begin(u, dir).unwrap();
    for id in s.requested() {
        s.add_object(&u.lan_object_envelope(&state, id).unwrap())
            .unwrap();
    }
    s.finish(u.vault_key(), &|| false).unwrap()
}

fn private(d: &TestDir) -> std::path::PathBuf {
    d.subdir("private", 0o700)
}

fn create(
    u: &UnlockedVault,
    mut staging: VerifiedLanStaging,
    path: &Path,
    anchors: &AnchorDir,
) -> Result<(), StoreError> {
    let key = link_key(u, &[9; 16]);
    let proof = {
        let _k = kdf();
        staging.verify_password(u.vault_key(), &pw(PASSWORD))?
    };
    VaultFile::create_from_lan(
        path,
        staging,
        proof,
        u.vault_key(),
        anchors,
        NewLanLink {
            link_id: [9; 16],
            key: &key,
            label: "Laptop",
            created_at: Timestamp(5),
        },
        &|| false,
    )
}

#[test]
fn lan_staging_builds_an_identical_vault_with_one_link() {
    let (d, _a, u, _record) = crate::verify_tests::setup();
    let mut staging = staged(&u, &private(&d));
    assert_eq!(staging.manifest(), u.manifest());
    assert_eq!(
        staging.keyslot(u.vault_key()).unwrap(),
        StagedKeyslot::Unique
    );
    assert_eq!(
        staging.vault_name(u.vault_key()).unwrap().expose_secret(),
        NAME.as_bytes()
    );
    {
        let _k = kdf();
        assert_eq!(
            err(staging.verify_password(u.vault_key(), &pw("wrong password here"))),
            StoreError::WrongPassword
        );
        // A keyslot that does not wrap the received VK.
        assert_eq!(
            err(staging.verify_password(&VaultKey::generate().unwrap(), &pw(PASSWORD))),
            StoreError::Integrity
        );
    }
    let b = TestDir::new();
    let anchors = AnchorDir::open(&b.join("anchors")).unwrap();
    let path = b.join("joined.qvault");
    create(&u, staging, &path, &anchors).unwrap();
    let joined = unlock(&path, &anchors, PASSWORD).unwrap();
    assert_eq!(joined.manifest(), u.manifest());
    assert_eq!(joined.header().vault_id, u.header().vault_id);
    let links = joined.lan_links().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].link_id, [9; 16]);
    assert_eq!(links[0].label.expose_secret(), b"Laptop");
    assert_eq!(joined.local_seq(), 1);
    // A fresh replica, never the source's.
    assert_ne!(joined.state.replica.replica_id, u.state.replica.replica_id);
    // An existing destination is never replaced.
    let again = staged(&u, &private(&TestDir::new()));
    assert_eq!(err(create(&u, again, &path, &anchors)), StoreError::Exists);
}

#[test]
fn lan_staging_refuses_bad_manifests_before_staging() {
    let (d, _a, u, _record) = crate::verify_tests::setup();
    let dir = private(&d);
    let state = u.lan_serve_state().unwrap();
    let h = u.header();
    let start = |vk: &VaultKey, vault: VaultId, g: KeyGeneration, hash: &[u8; 32], env: &[u8]| {
        LanStaging::begin(&dir, vk, vault, g, hash, env, &|| false).map(drop)
    };
    let (vk, v, g) = (u.vault_key(), h.vault_id, h.key_generation);
    assert_eq!(
        err(start(vk, v, g, &[0; 32], state.envelope())),
        StoreError::Integrity
    );
    let mut flipped = state.envelope().to_vec();
    let n = flipped.len() - 1;
    flipped[n] ^= 1;
    let fh = qv_crypto::object_hash(qv_crypto::ObjectHashProfile::V1, &flipped).0;
    assert_eq!(err(start(vk, v, g, &fh, &flipped)), StoreError::Integrity);
    let other = VaultKey::generate().unwrap();
    assert!(start(&other, v, g, state.manifest_hash(), state.envelope()).is_err());
    assert_eq!(
        err(start(
            vk,
            v,
            KeyGeneration(2),
            state.manifest_hash(),
            state.envelope()
        )),
        StoreError::Integrity
    );
    assert!(
        start(
            vk,
            VaultId([0; 16]),
            g,
            state.manifest_hash(),
            state.envelope()
        )
        .is_err()
    );
    let big = vec![0; crate::MAX_ARCHIVE_MANIFEST_FRAME + 1];
    assert_eq!(
        err(start(vk, v, g, &[0; 32], &big)),
        StoreError::LimitExceeded
    );
    // A world-writable staging directory.
    let open = d.subdir("open", 0o777);
    assert!(
        LanStaging::begin(
            &open,
            vk,
            v,
            g,
            state.manifest_hash(),
            state.envelope(),
            &|| false
        )
        .is_err()
    );
    // Nothing was left behind.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

#[test]
fn lan_staging_refuses_wrong_missing_and_reordered_objects() {
    let (d, _a, u, _record) = crate::verify_tests::setup();
    let dir = private(&d);
    let state = u.lan_serve_state().unwrap();
    let mut s = begin(&u, &dir).unwrap();
    let wanted = s.requested();
    assert!(wanted.len() >= 3);
    let env = |i: usize| u.lan_object_envelope(&state, wanted[i]).unwrap();
    // Out of order, then a duplicate.
    assert_eq!(err(s.add_object(&env(1))), StoreError::NotFound);
    s.add_object(&env(0)).unwrap();
    assert_eq!(err(s.add_object(&env(0))), StoreError::NotFound);
    // A flipped ciphertext byte fails the reference hash before staging.
    let mut bad = env(1);
    let n = bad.len() - 1;
    bad[n] ^= 1;
    assert_eq!(err(s.add_object(&bad)), StoreError::Integrity);
    assert_eq!(err(s.add_object(&[0x85, 0x00])), StoreError::Integrity);
    s.add_object(&env(1)).unwrap();
    // Missing the remaining objects.
    assert_eq!(
        err(s.finish(u.vault_key(), &|| false).map(drop)),
        StoreError::Integrity
    );

    // Everything, then one more.
    let mut s = begin(&u, &dir).unwrap();
    for i in 0..wanted.len() {
        s.add_object(&env(i)).unwrap();
    }
    assert_eq!(err(s.add_object(&env(0))), StoreError::NotFound);
    s.finish(u.vault_key(), &|| false).unwrap();
}

#[test]
fn lan_creation_crashes_publish_nothing_and_the_next_attempt_cleans_up() {
    use CrashPoint::*;
    for point in [CreateBuilt, CreateAnchored] {
        let (d, _a, u, _record) = crate::verify_tests::setup();
        let (b, s) = (TestDir::new(), TestDir::new());
        let anchors = AnchorDir::open(&b.join("anchors")).unwrap();
        let path = b.join("joined.qvault");
        let staging = staged(&u, &private(&d));
        // An unrelated dot-file must survive the cleanup.
        write_file(&b.join(".joined.qvault.keep"), b"x", 0o600);
        arm(point, &path, &b.join("anchors"), s.path());
        assert_eq!(
            err(create(&u, staging, &path, &anchors)),
            StoreError::Internal,
            "{point:?}"
        );
        assert!(!disarm(), "{point:?}");
        assert!(!path.exists(), "{point:?}");
        // Simulate the killed process's leftover temp file.
        write_file(
            &b.join(".joined.qvault.tmp-0123456789abcdef"),
            b"left",
            0o600,
        );
        let staging = staged(&u, &private(&TestDir::new()));
        create(&u, staging, &path, &anchors).unwrap();
        assert!(!b.join(".joined.qvault.tmp-0123456789abcdef").exists());
        assert!(b.join(".joined.qvault.keep").exists());
        unlock(&path, &anchors, PASSWORD).unwrap();
    }
}

// ---- merge staging against an existing vault (plan 0038 step 4) ----

fn replica(d: &TestDir, a: &TestDir) -> UnlockedVault {
    let (path, anchors) = crate::vault::tests::copy_fixture(d, a, "v.qvault");
    unlock(&path, &anchors, PASSWORD).unwrap()
}

/// Stages `peer`'s committed state into `u` the way an exchange does:
/// local copies for planned-local objects, peer envelopes for the rest.
fn merge_staged(u: &UnlockedVault, peer: &UnlockedVault) -> VerifiedLanStaging {
    let state = peer.lan_serve_state().unwrap();
    let mut s = u
        .lan_stage(state.manifest_hash(), state.envelope(), &|| false)
        .unwrap();
    let mut requested = s.requested().into_iter();
    while let Some(next) = s.next() {
        match next {
            crate::Planned::Local => u.lan_stage_local(&mut s).unwrap(),
            crate::Planned::Peer => {
                let id = requested.next().unwrap();
                s.add_object(&peer.lan_object_envelope(&state, id).unwrap())
                    .unwrap();
            }
        }
    }
    assert!(requested.next().is_none());
    u.lan_finish(s, &|| false).unwrap()
}

/// No staging file name is left in the anchor directory (staging files
/// are unlinked at once).
fn no_staging_left(a: &TestDir) -> bool {
    std::fs::read_dir(a.join("anchors")).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .contains("lan-staging")
    })
}

/// Only for ancestor-local inputs, as in the acceptance suites.
fn proposed(
    _: &crate::Manifest,
    incoming: &crate::Manifest,
    _: &mut crate::IncomingRead<'_>,
) -> Result<crate::Manifest, StoreError> {
    Ok(incoming.clone())
}

#[test]
fn lan_merge_staging_copies_common_objects_and_accepts_new_ones() {
    let (d, a, r, ra) = (
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
    );
    let mut u = replica(&d, &a);
    let mut peer = replica(&r, &ra);
    let id = <qv_crypto::RecordId as qv_model::RandomId>::generate().unwrap();
    crate::vault::tests::edit(&mut peer, id, "over the LAN");
    let state = peer.lan_serve_state().unwrap();
    let s = u
        .lan_stage(state.manifest_hash(), state.envelope(), &|| false)
        .unwrap();
    // Common objects come from local rows; only the new ones are requested.
    let new: Vec<_> = peer
        .manifest()
        .references()
        .iter()
        .map(|r| r.object_id())
        .filter(|o| u.manifest().reference(*o).is_none())
        .collect();
    assert!(!new.is_empty());
    assert_eq!(s.requested(), new);
    assert_eq!(
        s.plan().len() - new.len(),
        s.plan()
            .iter()
            .filter(|(_, p)| *p == crate::Planned::Local)
            .count()
    );
    drop(s);
    let receipts = u.state.head.archive_receipts_digest;
    let mut staged = merge_staged(&u, &peer);
    let seq = u.local_seq();
    assert!(u.accept_lan(&mut staged, &mut proposed, &|| false).unwrap());
    // The same manifest; its envelope hash differs (a fresh nonce per seal).
    assert_eq!(u.manifest(), peer.manifest());
    assert_eq!(u.local_seq(), seq + 1);
    // No filename receipt is written for LAN.
    assert_eq!(u.state.head.archive_receipts_digest, receipts);
    u.verify_all(&|| false).unwrap();
    // The same state again, or this vault's own state: nothing new, no commit.
    assert!(!u.accept_lan(&mut staged, &mut proposed, &|| false).unwrap());
    let mut own = merge_staged(&u, &u);
    assert!(own_plan_is_local(&u));
    assert!(
        !u.accept_lan(&mut own, &mut |l, _, _| Ok(l.clone()), &|| false)
            .unwrap()
    );
    assert_eq!(u.local_seq(), seq + 1);
    assert!(no_staging_left(&a));
}

fn own_plan_is_local(u: &UnlockedVault) -> bool {
    let state = u.lan_serve_state().unwrap();
    let s = u
        .lan_stage(state.manifest_hash(), state.envelope(), &|| false)
        .unwrap();
    s.requested().is_empty()
}

/// `m` sealed as `u`'s manifest envelope: (hash, envelope).
fn sealed(u: &UnlockedVault, m: &crate::Manifest) -> ([u8; 32], Vec<u8>) {
    let h = u.header();
    let key = u
        .vault_key()
        .purpose_key::<qv_crypto::purpose::Manifest>(
            h.vault_id,
            h.key_generation,
            crate::ARCHIVE_DERIVATION_PROFILE,
        )
        .unwrap();
    let scope = crate::object::Scope {
        vault_id: h.vault_id,
        key_generation: h.key_generation,
    };
    let s = crate::manifest::seal_manifest(&key, scope, h.data_profile, m).unwrap();
    let env =
        crate::manifest::envelope_bytes(s.key_generation, s.data_profile, &s.nonce, &s.ciphertext)
            .unwrap();
    (s.hash, env.to_vec())
}

#[test]
fn lan_merge_staging_refuses_substitution_and_vanished_rows() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let u = replica(&d, &a);
    // A peer manifest naming one of our object IDs with other bytes: the
    // substitution evidence of 0013 §7.4, refused before anything is staged.
    let m = u.manifest();
    let mut refs = m.references().to_vec();
    let victim = refs[0];
    let other = vec![0xab; usize::try_from(victim.length()).unwrap()];
    refs[0] = crate::ObjectRef::new(victim.object_id(), victim.data_profile(), &other).unwrap();
    let forged = m.candidate(m.records().to_vec(), refs).unwrap();
    let (hash, env) = sealed(&u, &forged);
    assert_eq!(
        err(u.lan_stage(&hash, &env, &|| false).map(drop)),
        StoreError::Integrity
    );
    // The genuine envelope sealed the same way stages fine.
    let (hash, env) = sealed(&u, m);
    let mut s = u.lan_stage(&hash, &env, &|| false).unwrap();
    assert!(s.requested().is_empty());
    // A planned-local row that vanished after planning.
    let first = s.plan()[0].0;
    u.file
        .conn
        .execute(
            "DELETE FROM object WHERE object_id = ?1",
            [qv_model::RandomId::to_bytes(&first).as_slice()],
        )
        .unwrap();
    assert_eq!(err(u.lan_stage_local(&mut s)), StoreError::NotFound);
    // A peer object where a local one is planned is refused.
    assert_eq!(err(s.add_object(&[0x85])), StoreError::NotFound);
    drop(s);
    assert!(no_staging_left(&a));
}

#[test]
fn lan_merge_acceptance_crash_points_leave_old_or_new_state() {
    let (r, ra) = (TestDir::new(), TestDir::new());
    let mut peer = replica(&r, &ra);
    let id = <qv_crypto::RecordId as qv_model::RandomId>::generate().unwrap();
    crate::vault::tests::edit(&mut peer, id, "crash over the LAN");
    for (point, committed) in [
        (CrashPoint::Begun, false),
        (CrashPoint::ObjectsWritten, false),
        (CrashPoint::ManifestWritten, false),
        (CrashPoint::HeadWritten, false),
        (CrashPoint::Pruned, false),
        (CrashPoint::Committed, true),
        (CrashPoint::AnchorTempWritten, true),
        (CrashPoint::AnchorReplaced, true),
    ] {
        let (d, a, snapshot) = (TestDir::new(), TestDir::new(), TestDir::new());
        let mut u = replica(&d, &a);
        let mut staged = merge_staged(&u, &peer);
        let seq = u.local_seq();
        arm(
            point,
            &d.join("v.qvault"),
            &a.join("anchors"),
            snapshot.path(),
        );
        assert_eq!(
            u.accept_lan(&mut staged, &mut proposed, &|| false),
            Err(StoreError::Internal),
            "{point:?}"
        );
        assert!(!disarm(), "{point:?}");
        if committed {
            // The pending anchor completes; nothing is committed twice.
            assert!(!u.accept_lan(&mut staged, &mut proposed, &|| false).unwrap());
            assert_eq!(u.local_seq(), seq + 1);
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
            restarted
                .accept_lan(&mut staged, &mut proposed, &|| false)
                .unwrap(),
            !committed
        );
        assert_eq!(restarted.local_seq(), seq + 1);
        restarted.verify_all(&|| false).unwrap();
    }
}
