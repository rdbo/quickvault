// SPDX-License-Identifier: AGPL-3.0-or-later

//! New-path archive restoration using the existing durable creation protocol.
use crate::{
    AnchorDir, ArchiveScope, StoreError, VaultFile,
    archive::{self, OpenedArchive},
    crash::{CrashPoint, point},
    creation, fs,
    head::LocalHead,
    header::Header,
    manifest::seal_manifest,
    object::SealedObject,
    schema::{ObjectReader, StoredReplica, StoredSlot},
    slot::LocalSlot,
    vault::{self, Keys, insert_object, load_state, scope, sign_head},
};
use qv_crypto::VaultKey;
use qv_model::{Payload, RandomId, RecordBody, WriterId};
use std::{
    io::{Read, Seek},
    path::Path,
};

fn check_cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
    if cancelled() {
        Err(StoreError::Io)
    } else {
        Ok(())
    }
}

impl VaultFile {
    /// Restores a fully authenticated archive as a new local recovery baseline.
    /// Never replaces `path` and never reuses a source writer, replica or anchor.
    pub fn create_from_archive<R: Read + Seek>(
        path: &Path,
        input: &mut R,
        expect: ArchiveScope,
        vk: &VaultKey,
        anchors: &AnchorDir,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), StoreError> {
        crate::rotation_guard::check(path)?;
        check_cancel(cancelled)?;
        if path.extension().and_then(|e| e.to_str()) != Some(vault::VAULT_EXTENSION) {
            return Err(StoreError::Unsupported);
        }
        match rustix::fs::lstat(path) {
            Ok(_) => return Err(StoreError::Exists),
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(crate::error::errno_err(e)),
        }
        fs::check_parent(path)?;
        // An anchor stored/restored beside its vault cannot detect rollback.
        let parent = std::fs::canonicalize(fs::parent_of(path)).map_err(|_| StoreError::Io)?;
        let anchor_path = std::fs::canonicalize(anchors.path()).map_err(|_| StoreError::Io)?;
        if parent.starts_with(anchor_path) {
            return Err(StoreError::UnsafeFile);
        }
        let opened = archive::read_archive(input, expect, vk, &mut |_| Ok(()), cancelled)?;
        let h = opened.header();
        let (min_data, min_derivation) = h.minimum_profiles();
        let header = Header {
            vault_id: h.vault_id(),
            key_generation: h.key_generation(),
            data_profile: h.data_profile(),
            derivation_profile: archive::ARCHIVE_DERIVATION_PROFILE,
            mac_profile: archive::ARCHIVE_MAC_PROFILE,
            min_data_profile: min_data,
            min_derivation_profile: min_derivation,
        };
        let keys = Keys::derive(vk, &header)?;
        let entry = opened
            .manifest()
            .record(opened.manifest().keyslot_id())
            .ok_or(StoreError::Integrity)?;
        let [role] = entry.heads() else {
            return Err(StoreError::Integrity);
        };
        let version = crate::archive_verify::read_version(
            input,
            h,
            opened.manifest(),
            &opened.frames,
            &keys.record,
            entry.record_id(),
            role,
        )?;
        let RecordBody::Live(Payload::PasswordKeyslot(slot)) = version.body else {
            return Err(StoreError::Integrity);
        };
        let body = slot.encode()?;
        let local = LocalSlot::from_stored(StoredSlot {
            slot_id: slot.slot.slot_id.0,
            kind: crate::slot::PASSWORD_SLOT,
            body: body.to_vec(),
        })?;
        let (lock, temp) = fs::create_temp(path)?;
        let mut anchored = None;
        let mut published = false;
        let result = (|| {
            build(&temp, input, &opened, &header, &local, vk, cancelled)?;
            let file = Self::open_locked(&temp, lock)?;
            file.verify_header(vk)?;
            let state = load_state(&file.conn, &header, vk)?;
            if &state.manifest != opened.manifest() {
                return Err(StoreError::Integrity);
            }
            // Re-read persisted objects and compare complete envelopes to the fully
            // authenticated archive. Ciphertext, nonce and role bindings all agree.
            let mut reader = ObjectReader::new(&file.conn)?;
            for (reference, indexed) in opened.manifest().references().iter().zip(&opened.frames) {
                check_cancel(cancelled)?;
                let frame = indexed.read(input, h, reference)?;
                let expected = archive::object_envelope(&frame, h, reference)?;
                let (profile, nonce, ciphertext) = reader.read(
                    header.key_generation,
                    &reference.object_id().to_bytes(),
                    reference.length(),
                )?;
                if profile != expected.data_profile().id()
                    || nonce != *expected.nonce()
                    || ciphertext != expected.ciphertext()
                {
                    return Err(StoreError::Integrity);
                }
            }
            file.sync()?;
            point(CrashPoint::CreateBuilt)?;
            check_cancel(cancelled)?;
            // Remember the new ID before storing: clean it even if directory fsync fails.
            crate::rotation_guard::check(path)?;
            anchored = Some(state.replica.replica_id);
            anchors.store(&state.replica.replica_id, &vault::anchor_of(&state))?;
            point(CrashPoint::CreateAnchored)?;
            check_cancel(cancelled)?;
            crate::rotation_guard::check(path)?;
            fs::rename_noreplace(&temp, path)?;
            published = true;
            fs::sync_dir(fs::parent_of(path))?;
            Ok(())
        })();
        if result.is_err() && !published {
            fs::remove_best_effort(&fs::with_suffix(&temp, "-journal"));
            fs::remove_best_effort(&temp);
            if let Some(id) = anchored {
                anchors.remove_best_effort(&id);
            }
        }
        result
    }
}

fn build<R: Read + Seek>(
    temp: &Path,
    input: &mut R,
    opened: &OpenedArchive,
    header: &Header,
    local: &LocalSlot,
    vk: &VaultKey,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), StoreError> {
    let keys = Keys::derive(vk, header)?;
    let replica = StoredReplica {
        replica_id: qv_crypto::random_array::<16>().map_err(|_| StoreError::Rng)?,
        writer_id: WriterId::generate()?.to_bytes(),
        next_counter: 1,
    };
    creation::write_database(
        temp,
        header,
        vk,
        local,
        replica,
        |tx| {
            for (reference, indexed) in opened.manifest().references().iter().zip(&opened.frames) {
                check_cancel(cancelled)?;
                let frame = indexed.read(input, opened.header(), reference)?;
                let o = archive::object_envelope(&frame, opened.header(), reference)?;
                let sealed = SealedObject {
                    object_id: o.object_id(),
                    data_profile: o.data_profile(),
                    nonce: *o.nonce(),
                    ciphertext: o.ciphertext().to_vec(),
                };
                insert_object(tx, header.key_generation, &sealed)?;
            }
            let manifest = seal_manifest(
                &keys.manifest,
                scope(header),
                header.data_profile,
                opened.manifest(),
            )?;
            let head = LocalHead {
                vault_id: header.vault_id,
                key_generation: header.key_generation,
                local_seq: 1,
                previous_digest: None,
                manifest_hash: manifest.hash,
                remote: None,
                archive_receipts_digest: crate::receipt_store::initialize(
                    tx,
                    &keys,
                    header,
                    &replica.replica_id,
                )?,
            };
            let (head, _) = sign_head(&keys, header, &head)?;
            Ok(creation::Filled { manifest, head })
        },
        cancelled,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};
    use crate::vault::tests::{PASSWORD, edit, err, unlock};
    use qv_crypto::RecordId;
    use qv_model::Timestamp;

    fn archive(source: &mut crate::UnlockedVault) -> Vec<u8> {
        let mut bytes = Vec::new();
        source
            .write_archive(&mut bytes, Timestamp(1_700_000_000_000), &|| false)
            .unwrap();
        bytes
    }
    fn source_scope(source: &crate::UnlockedVault) -> ArchiveScope {
        ArchiveScope::new(source.header().vault_id, source.header().key_generation)
    }
    fn restore(
        source: &crate::UnlockedVault,
        bytes: &[u8],
        target: &Path,
    ) -> Result<(), StoreError> {
        VaultFile::create_from_archive(
            target,
            &mut std::io::Cursor::new(bytes),
            source_scope(source),
            source.vault_key(),
            &source.anchors,
            &|| false,
        )
    }
    fn anchors(source: &crate::UnlockedVault) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let mut rows: Vec<_> = std::fs::read_dir(source.anchors.path())
            .unwrap()
            .map(|e| {
                let path = e.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    #[test]
    fn restore_preserves_history_floors_chunks_and_source_with_fresh_baseline() {
        let (d, _a, mut source, _record) = crate::verify_tests::setup();
        let floor_record = <RecordId as RandomId>::generate().unwrap();
        edit(&mut source, floor_record, "old");
        edit(&mut source, floor_record, "new");
        let mut w = source.write().unwrap();
        w.purge_history(floor_record).unwrap();
        w.commit().unwrap();
        let before = std::fs::read(d.join("v.qvault")).unwrap();
        let old_anchors = anchors(&source);
        let bytes = archive(&mut source);
        let path = d.join("restored.qvault");
        restore(&source, &bytes, &path).unwrap();
        let mut copy = unlock(&path, &source.anchors, PASSWORD).unwrap();
        assert_eq!(copy.manifest(), source.manifest());
        assert_eq!(copy.header(), source.header());
        assert_ne!(
            copy.state.replica.replica_id,
            source.state.replica.replica_id
        );
        assert_ne!(copy.writer_id(), source.writer_id());
        assert_eq!(copy.state.replica.next_counter, 1);
        assert_eq!(copy.local_seq(), 1);
        assert!(copy.state.head.previous_digest.is_none() && copy.state.head.remote.is_none());
        assert_eq!(
            copy.verify_all(&|| false).unwrap(),
            source.verify_all(&|| false).unwrap()
        );
        assert_eq!(std::fs::read(d.join("v.qvault")).unwrap(), before);
        for (path, bytes) in old_anchors {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        assert_eq!(anchors(&source).len(), 2);
        // A new local edit is causal and does not reuse the source writer's counter.
        edit(&mut copy, floor_record, "restored edit");
        assert_eq!(copy.local_seq(), 2);
        assert_eq!(std::fs::read(d.join("v.qvault")).unwrap(), before);
    }

    #[test]
    fn restore_rejects_bad_archives_without_destination_or_anchor_changes() {
        let (d, _a, mut source, _) = crate::verify_tests::setup();
        let good = archive(&mut source);
        let old_anchors = anchors(&source);
        let path = d.join("restored.qvault");
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        let mut trailing = good.clone();
        trailing.push(0);
        for bytes in [&good[..7], &good[..good.len() - 1], &bad[..], &trailing[..]] {
            assert!(restore(&source, bytes, &path).is_err());
            assert!(!path.exists());
            assert_eq!(anchors(&source), old_anchors);
            assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
        }
        let other = TestDir::new();
        let other_a = TestDir::new();
        let (other_path, other_anchors) =
            crate::vault::tests::copy_fixture(&other, &other_a, "other.qvault");
        let other_source = unlock(&other_path, &other_anchors, PASSWORD).unwrap();
        // Fixture copies share a key, so force a foreign scope explicitly.
        let foreign = ArchiveScope::new(
            qv_crypto::VaultId([0x99; 16]),
            source.header().key_generation,
        );
        assert_eq!(
            err(VaultFile::create_from_archive(
                &path,
                &mut std::io::Cursor::new(&good),
                foreign,
                other_source.vault_key(),
                &source.anchors,
                &|| false
            )),
            StoreError::Integrity
        );
        assert!(!path.exists());
        assert_eq!(anchors(&source), old_anchors);
    }

    #[test]
    fn restore_refuses_existing_unsafe_and_cancelled_targets() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (d, _a, mut source, _) = crate::verify_tests::setup();
        let good = archive(&mut source);
        let path = d.join("restored.qvault");
        write_file(&path, b"keep", 0o600);
        assert_eq!(err(restore(&source, &good, &path)), StoreError::Exists);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        let link = d.join("link.qvault");
        symlink(&path, &link).unwrap();
        assert_eq!(err(restore(&source, &good, &link)), StoreError::Exists);
        let new = d.join("new.qvault");
        assert_eq!(
            err(VaultFile::create_from_archive(
                &new,
                &mut std::io::Cursor::new(&good),
                source_scope(&source),
                source.vault_key(),
                &source.anchors,
                &|| true
            )),
            StoreError::Io
        );
        assert!(!new.exists());
        let cancelled_during_build = std::cell::Cell::new(false);
        let result = VaultFile::create_from_archive(
            &new,
            &mut std::io::Cursor::new(&good),
            source_scope(&source),
            source.vault_key(),
            &source.anchors,
            &|| {
                let temporary_exists = std::fs::read_dir(d.path())
                    .unwrap()
                    .any(|e| e.unwrap().file_name().to_string_lossy().contains(".tmp-"));
                if temporary_exists {
                    cancelled_during_build.set(true);
                }
                temporary_exists
            },
        );
        assert_eq!(err(result), StoreError::Io);
        assert!(cancelled_during_build.get());
        assert!(!new.exists());

        let unsafe_dir = TestDir::new();
        std::fs::set_permissions(unsafe_dir.path(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert_eq!(
            err(restore(&source, &good, &unsafe_dir.join("new.qvault"))),
            StoreError::UnsafeFile
        );
        std::fs::set_permissions(unsafe_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert_eq!(
            err(restore(
                &source,
                &good,
                &source.anchors.path().join("new.qvault")
            )),
            StoreError::UnsafeFile
        );
        assert_eq!(anchors(&source).len(), 1);
    }

    #[test]
    fn restore_creation_crash_points_preserve_source_and_clean_new_state() {
        use crate::crash::test::{arm, disarm};
        let (d, _a, mut source, _) = crate::verify_tests::setup();
        let good = archive(&mut source);
        let before = std::fs::read(d.join("v.qvault")).unwrap();
        let old_anchors = anchors(&source);
        for point in [CrashPoint::CreateBuilt, CrashPoint::CreateAnchored] {
            let crash = TestDir::new();
            let target = d.join("restored.qvault");
            arm(point, &target, source.anchors.path(), crash.path());
            assert_eq!(err(restore(&source, &good, &target)), StoreError::Internal);
            assert!(!disarm());
            assert!(!target.exists());
            assert_eq!(anchors(&source), old_anchors);
            assert_eq!(std::fs::read(d.join("v.qvault")).unwrap(), before);
            assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
            assert!(!crash.join("restored.qvault").exists());
            assert_eq!(
                std::fs::read_dir(crash.join("anchors")).unwrap().count(),
                if point == CrashPoint::CreateAnchored {
                    2
                } else {
                    1
                }
            );
        }
    }
}
