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
        assert_eq!(
            replace(&mut u, NEW),
            Err(
                if matches!(point, Committed | AnchorTempWritten | AnchorReplaced) {
                    StoreError::CommittedAnchorPending
                } else {
                    StoreError::Internal
                }
            ),
            "{point:?}"
        );
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

// 0012 §1: Mixed credentials
// 0012 §1: Exchange-file password guessing
#[test]
fn credentials_extensions_stay_encrypted_across_adoption_restore_backup_and_lan() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
    let id = u.manifest().keyslot_id();
    let head = u.manifest().record(id).unwrap().heads()[0].version_id();
    let mut previous = u.read_version(id, head).unwrap();
    let mut w = u.write().unwrap();
    let mut descriptor = {
        let _k = kdf();
        w.stage_password(&pw(NEW), PasswordKdfProfile::V1, PasswordWrapProfile::V1)
            .unwrap()
    };
    let encoded = descriptor.encode().unwrap();
    let mut decoder = qv_encoding::Decoder::new(&encoded).unwrap();
    let count = decoder.map().unwrap();
    let mut encoder = qv_encoding::Encoder::new();
    encoder
        .map(|map| {
            for _ in 0..count {
                let key = decoder.int().unwrap();
                let value = decoder.raw_value().unwrap();
                map.raw_entry(key, &value)?;
            }
            map.entry(99, |e| {
                e.text("secret");
                Ok(())
            })
        })
        .unwrap();
    decoder.finish().unwrap();
    descriptor = qv_model::Keyslot::decode(&encoder.finish().unwrap()).unwrap();
    let counter = w.reserve_counter().unwrap();
    previous.clock = Clock::for_edit(w.head_clocks(id).iter(), w.writer_id(), counter).unwrap();
    previous.version_id = VersionId::generate().unwrap();
    previous.body = RecordBody::Live(Payload::PasswordKeyslot(descriptor));
    w.put_local(id, previous).unwrap();
    w.commit().unwrap();
    assert!(u.file.slots[0].keyslot.ext.is_empty());
    let head = u.manifest().record(id).unwrap().heads()[0].version_id();
    let RecordBody::Live(Payload::PasswordKeyslot(encrypted)) =
        u.read_version(id, head).unwrap().body
    else {
        panic!("keyslot");
    };
    assert_eq!(encrypted.ext.len(), 1);
    let public = encrypted.encode_public_descriptor().unwrap();
    assert_eq!(u.file.slots[0].body.as_slice(), public.as_slice());

    for backup in [false, true] {
        let mut bytes = Vec::new();
        u.write_export_archive(&mut bytes, Timestamp(1), backup, &|| false)
            .unwrap();
        let scope = crate::ArchiveScope::new(u.header().vault_id, u.header().key_generation);
        let opened = crate::archive::read_archive(
            &mut std::io::Cursor::new(&bytes),
            scope,
            u.vault_key(),
            &mut |_| Ok(()),
            &|| false,
        )
        .unwrap();
        assert_eq!(
            opened.header().password_slot.as_deref().map(Vec::as_slice),
            backup.then_some(public.as_slice())
        );
        let destination = d.join(if backup {
            "backup.qvault"
        } else {
            "restore.qvault"
        });
        VaultFile::create_from_archive(
            &destination,
            &mut std::io::Cursor::new(bytes),
            scope,
            u.vault_key(),
            &anchors,
            &|| false,
        )
        .unwrap();
        let restored = unlock(&destination, &anchors, NEW).unwrap();
        assert_eq!(restored.file.slots[0].body.as_slice(), public.as_slice());
        let RecordBody::Live(Payload::PasswordKeyslot(record)) =
            restored.read_version(id, head).unwrap().body
        else {
            panic!("restored keyslot");
        };
        assert_eq!(record.ext.len(), 1);
    }

    let private = d.subdir("lan-private", 0o700);
    let state = u.lan_serve_state().unwrap();
    let mut staging = crate::LanStaging::begin(
        &private,
        u.vault_key(),
        u.header().vault_id,
        u.header().key_generation,
        state.manifest_hash(),
        state.envelope(),
        &|| false,
    )
    .unwrap();
    for object in staging.requested() {
        staging
            .add_object(&u.lan_object_envelope(&state, object).unwrap())
            .unwrap();
    }
    let mut verified = staging.finish(u.vault_key(), &|| false).unwrap();
    let proof = verified.verify_enrollment(u.vault_key(), None).unwrap();
    let phrase = qv_crypto::RecoveryPhrase::from_vault_key(u.vault_key()).unwrap();
    let vk = qv_crypto::VaultKey::from_recovery_phrase(phrase.expose_secret().as_bytes()).unwrap();
    let joined_path = d.join("joined.qvault");
    let joined =
        VaultFile::create_from_verified_lan(&joined_path, verified, proof, vk, &anchors, &|| false)
            .unwrap();
    let RecordBody::Live(Payload::PasswordKeyslot(staged)) =
        joined.read_version(id, head).unwrap().body
    else {
        panic!("staged keyslot")
    };
    assert_eq!(staged.ext.len(), 1);
    assert_eq!(joined.file.slots[0].body.as_slice(), public.as_slice());
}

// 0012 §1: Whole-file rollback
#[test]
fn credentials_authenticated_identical_copy_and_move_open_before_runtime_tracking() {
    let (d, a) = (TestDir::new(), TestDir::new());
    let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
    let u = unlock(&path, &anchors, PASSWORD).unwrap();
    let header = *u.header();
    drop(u);
    let copy = d.join("copy.qvault");
    std::fs::copy(&path, &copy).unwrap();
    let opened = unlock(&copy, &anchors, PASSWORD).unwrap();
    assert_eq!(*opened.header(), header);
    opened.verify_all(&|| false).unwrap();
    drop(opened);
    let moved = d.join("moved.qvault");
    std::fs::rename(&copy, &moved).unwrap();
    let opened = unlock(&moved, &anchors, PASSWORD).unwrap();
    assert_eq!(*opened.header(), header);
    opened.verify_all(&|| false).unwrap();
}
