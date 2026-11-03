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
    for id in s.wanted().to_vec() {
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
    let wanted = s.wanted().to_vec();
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
