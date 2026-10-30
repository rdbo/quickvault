// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential transaction rejection, migration and crash evidence.
use crate::fs::test_dir::TestDir;
use crate::vault::tests::{PASSWORD, copy_fixture, err, kdf, pw, unlock};
use crate::{AnchorDir, StoreError, UnlockedVault, VaultFile};
use qv_crypto::{PasswordKdfProfile, PasswordWrapProfile};
use qv_model::{Clock, Payload, RandomId, RecordBody, RecordVersion, Timestamp, VersionId};

const NEW: &str = "new independent master passphrase with enough words";

fn replace(u: &mut UnlockedVault, password: &str) -> Result<(), StoreError> {
    replace_cancellable(u, password, false)
}

fn replace_cancellable(
    u: &mut UnlockedVault,
    password: &str,
    cancel: bool,
) -> Result<(), StoreError> {
    let _k = kdf();
    let id = u.manifest().keyslot_id();
    let head = &u
        .manifest()
        .record(id)
        .ok_or(StoreError::Integrity)?
        .heads()[0];
    let mut previous = u.read_version(id, head.version_id())?;
    let mut w = u.write()?;
    let keyslot = w.stage_password(
        &pw(password),
        PasswordKdfProfile::V1,
        PasswordWrapProfile::V1,
    )?;
    let counter = w.reserve_counter()?;
    previous.clock = Clock::for_edit(w.head_clocks(id).iter(), w.writer_id(), counter)?;
    previous.version_id = VersionId::generate()?;
    previous.modified_at = Timestamp(1_700_000_001_000);
    previous.body = RecordBody::Live(Payload::PasswordKeyslot(keyslot));
    w.put_local(id, previous)?;
    w.commit_cancellable(&|| cancel)
}

// 0012 §1: Migration coupling
#[test]
fn credentials_rewrap_preserves_objects_and_phrase_and_reauthenticates_current_slot() {
    // Exercise real entry history and multi-chunk attachment envelopes as well
    // as the control records, not just an otherwise empty vault.
    let (d, _a, mut u, _record) = crate::verify_tests::setup();
    let path = d.join("v.qvault");
    let anchors = u.anchors.clone();
    let phrase = {
        let _k = kdf();
        u.recovery_phrase(&pw(PASSWORD)).unwrap()
    };
    let original_header = *u.header();
    let objects: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = u
        .file
        .conn
        .prepare("SELECT object_id, nonce, ciphertext FROM object")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    replace(&mut u, NEW).unwrap();
    assert_eq!(u.header(), &original_header);
    for (id, nonce, ciphertext) in objects {
        let actual: (Vec<u8>, Vec<u8>) = u
            .file
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM object WHERE object_id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(actual, (nonce, ciphertext));
    }
    {
        let _k = kdf();
        assert_eq!(
            err(u.recovery_phrase(&pw(PASSWORD))),
            StoreError::WrongPassword
        );
        assert_eq!(
            u.recovery_phrase(&pw(NEW)).unwrap().expose_secret(),
            phrase.expose_secret()
        );
    }
    u.verify_all(&|| false).unwrap();
    drop(u);
    assert_eq!(
        err(unlock(&path, &anchors, PASSWORD)),
        StoreError::WrongPassword
    );
    let u = unlock(&path, &anchors, NEW).unwrap();
    drop(u);
    let (mut u, _) = VaultFile::open(&path)
        .unwrap()
        .unlock_with_phrase(phrase.expose_secret().as_bytes(), &anchors)
        .unwrap();
    // Same-password rewrap is the current fixed-profile migration path.
    replace(&mut u, NEW).unwrap();
    u.verify_all(&|| false).unwrap();
}

#[test]
fn credentials_partial_staging_and_cancellation_roll_back() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
    let seq = u.local_seq();
    {
        let _k = kdf();
        let mut w = u.write().unwrap();
        w.stage_password(&pw(NEW), PasswordKdfProfile::V1, PasswordWrapProfile::V1)
            .unwrap();
        assert_eq!(w.commit(), Err(StoreError::InvalidEdit));
    }
    assert_eq!(u.local_seq(), seq);
    assert_eq!(replace_cancellable(&mut u, NEW, true), Err(StoreError::Io));
    assert_eq!(u.local_seq(), seq);
    {
        let _k = kdf();
        assert!(u.recovery_phrase(&pw(PASSWORD)).is_ok());
    }
    // A fresh write after the rejected one can still commit correctly.
    replace(&mut u, NEW).unwrap();
    drop(u);
    assert!(unlock(&path, &anchors, NEW).is_ok());
}

#[test]
fn credentials_phrase_validation_and_authenticated_damage_are_distinct() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let u = unlock(&path, &anchors, PASSWORD).unwrap();
    let phrase = {
        let _k = kdf();
        u.recovery_phrase(&pw(PASSWORD)).unwrap()
    };
    let foreign =
        qv_crypto::RecoveryPhrase::from_vault_key(&qv_crypto::VaultKey::generate().unwrap())
            .unwrap();
    drop(u);
    let before = std::fs::read(&path).unwrap();
    for bytes in [b"bad phrase".as_slice(), foreign.expose_secret().as_bytes()] {
        assert_eq!(
            err(VaultFile::open(&path)
                .unwrap()
                .unlock_with_phrase(bytes, &anchors)),
            StoreError::WrongPhrase
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let file = VaultFile::open(&path).unwrap();
    file.conn
        .execute("UPDATE local_head SET mac = zeroblob(32)", [])
        .unwrap();
    drop(file);
    assert_eq!(
        err(VaultFile::open(&path)
            .unwrap()
            .unlock_with_phrase(phrase.expose_secret().as_bytes(), &anchors)),
        StoreError::Integrity
    );
}

#[test]
fn credentials_crash_every_slot_transaction_and_anchor_boundary() {
    use crate::crash::{
        CrashPoint::*,
        test::{arm, disarm},
    };
    let cases = [
        Begun,
        ObjectsWritten,
        PasswordSlotWritten,
        ManifestWritten,
        HeadWritten,
        Pruned,
        Committed,
        AnchorTempWritten,
        AnchorReplaced,
    ];
    for point in cases {
        let (d, a, snap) = (TestDir::new(), TestDir::new(), TestDir::new());
        let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
        arm(point, &path, anchors.path(), snap.path());
        assert_eq!(replace(&mut u, NEW), Err(StoreError::Internal), "{point:?}");
        assert!(!disarm());
        drop(u);
        let durable = matches!(point, Committed | AnchorTempWritten | AnchorReplaced);
        let anchors = AnchorDir::open(&snap.join("anchors")).unwrap();
        let path = snap.join("v.qvault");
        let right = if durable { NEW } else { PASSWORD };
        let wrong = if durable { PASSWORD } else { NEW };
        let u = unlock(&path, &anchors, right).unwrap();
        u.verify_all(&|| false).unwrap();
        let id = u.manifest().keyslot_id();
        let head = &u.manifest().record(id).unwrap().heads()[0];
        let RecordVersion {
            body: RecordBody::Live(Payload::PasswordKeyslot(descriptor)),
            ..
        } = u.read_version(id, head.version_id()).unwrap()
        else {
            panic!("keyslot");
        };
        assert_eq!(
            descriptor.encode().unwrap().as_slice(),
            u.file.slots[0].body.as_slice()
        );
        drop(u);
        assert_eq!(
            err(unlock(&path, &anchors, wrong)),
            StoreError::WrongPassword,
            "{point:?}"
        );
    }
}

#[test]
fn credentials_mismatched_or_unstaged_encrypted_descriptor_is_refused() {
    for staged in [false, true] {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
        let id = u.manifest().keyslot_id();
        let head = &u.manifest().record(id).unwrap().heads()[0];
        let mut previous = u.read_version(id, head.version_id()).unwrap();
        let _k = kdf();
        let mut w = u.write().unwrap();
        if staged {
            let mut slot = w
                .stage_password(&pw(NEW), PasswordKdfProfile::V1, PasswordWrapProfile::V1)
                .unwrap();
            slot.slot.wrapped_vk[0] ^= 1;
            previous.body = RecordBody::Live(Payload::PasswordKeyslot(slot));
        }
        let counter = w.reserve_counter().unwrap();
        previous.clock = Clock::for_edit(w.head_clocks(id).iter(), w.writer_id(), counter).unwrap();
        previous.version_id = VersionId::generate().unwrap();
        w.put_local(id, previous).unwrap();
        assert_eq!(w.commit(), Err(StoreError::InvalidEdit));
        assert!(u.recovery_phrase(&pw(PASSWORD)).is_ok());
    }
}
