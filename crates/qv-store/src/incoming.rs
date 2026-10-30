// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable hostile archive input, with no accepted-state mutation (0005 §4).

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use qv_crypto::{ObjectHashProfile, ObjectHasher, RecordId, SecretArray, VaultKey, purpose};
use qv_model::{ObjectId, RecordVersion, VersionId};
use rustix::fs::FileType;

use crate::{
    ArchiveHeader, ArchiveScope, Manifest, ObjectEnvelope, OpenedArchive, StoreError,
    archive::{object_envelope, read_archive},
    fs,
};

/// A complete authenticated archive held in a private, unlinked file.
///
/// Construction bounds the encrypted copy, verifies every role and attachment,
/// and checks exact EOF. It never opens exchange input as SQLite. This is a
/// read capability only: it neither accepts a merge nor remembers filenames.
pub struct VerifiedIncoming {
    file: File,
    opened: OpenedArchive,
    digest: [u8; 32],
    pub(crate) path: qv_crypto::SecretBytes,
}

impl core::fmt::Debug for VerifiedIncoming {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedIncoming(..)")
    }
}

impl VerifiedIncoming {
    /// Copy a regular hostile input into `private_dir` and fully authenticate it.
    ///
    /// Source permissions need not be private. Symlinks at the input name and
    /// special files are refused; NONBLOCK prevents a FIFO from hanging open.
    /// Only the caller-supplied private destination is used for temporary data.
    pub fn open(
        source: &Path,
        private_dir: &Path,
        scope: ArchiveScope,
        vk: &VaultKey,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, StoreError> {
        if cancelled() {
            return Err(StoreError::Io);
        }
        fs::check_private_dir(private_dir)?;
        let path = crate::incoming_path::normalize(source)?;
        let fd = crate::incoming_path::open_source(&path)?;
        let stat = rustix::fs::fstat(&fd).map_err(crate::error::errno_err)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(StoreError::UnsafeFile);
        }
        let size = u64::try_from(stat.st_size).map_err(|_| StoreError::Integrity)?;
        if size > crate::MAX_DB_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        let mut input = File::from(fd);
        let (locked, name) = fs::create_temp(&private_dir.join("incoming.qvsnap"))?;
        // Unlink before any copy: success/failure/cancellation leaves no name.
        // A crash between creation and unlink can leave an empty file; no
        // content is written before unlink. Only encrypted bytes are staged.
        if std::fs::remove_file(&name).is_err() {
            fs::remove_best_effort(&name);
            return Err(StoreError::Io);
        }
        let mut file = locked.into_file();
        let mut buffer = SecretArray::<65536>::zeroed();
        let mut total = 0u64;
        let mut hash = ObjectHasher::new(ObjectHashProfile::V1);
        loop {
            if cancelled() {
                return Err(StoreError::Io);
            }
            let n = match input.read(buffer.expose_secret_mut()) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                r => r.map_err(|_| StoreError::Io)?,
            };
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n as u64)
                .filter(|n| *n <= crate::MAX_DB_BYTES)
                .ok_or(StoreError::LimitExceeded)?;
            let bytes = &buffer.expose_secret()[..n];
            hash.update(bytes);
            file.write_all(bytes).map_err(|_| StoreError::Io)?;
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| StoreError::Io)?;
        let opened = read_archive(&mut file, scope, vk, &mut |_| Ok(()), cancelled)?;
        Ok(Self {
            file,
            opened,
            digest: hash.finalize().0,
            path,
        })
    }

    /// The authenticated archive header.
    pub fn header(&self) -> &ArchiveHeader {
        self.opened.header()
    }

    /// The authenticated complete manifest.
    pub fn manifest(&self) -> &Manifest {
        self.opened.manifest()
    }

    /// SHA-256 of the entire copied stream, including framing and header.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Read a complete role-bound record, rechecking its frame and AEAD.
    pub fn read_version(
        &mut self,
        vk: &VaultKey,
        record: RecordId,
        version: VersionId,
    ) -> Result<RecordVersion, StoreError> {
        let header = self.opened.header();
        let manifest = self.opened.manifest();
        let role = manifest
            .record(record)
            .and_then(|r| r.version(version))
            .ok_or(StoreError::NotFound)?;
        let key = vk.purpose_key::<purpose::Record>(
            header.vault_id(),
            header.key_generation(),
            crate::ARCHIVE_DERIVATION_PROFILE,
        )?;
        let decoded = crate::archive_verify::read_version(
            &mut self.file,
            header,
            manifest,
            &self.opened.frames,
            &key,
            record,
            role,
        )?;
        crate::validation::check_head(manifest, record, role, &decoded)?;
        Ok(decoded)
    }

    /// Read one encrypted object with its complete-envelope commitment checked.
    ///
    /// The returned envelope is not authorization to insert it into a vault.
    pub fn read_object(&mut self, object: ObjectId) -> Result<ObjectEnvelope, StoreError> {
        let manifest = self.opened.manifest();
        let index = manifest
            .references()
            .binary_search_by_key(&object, |r| r.object_id())
            .map_err(|_| StoreError::NotFound)?;
        let reference = &manifest.references()[index];
        let header = self.opened.header();
        let frame = self.opened.frames[index].read(&mut self.file, header, reference)?;
        let envelope = object_envelope(&frame, header, reference)?;
        Ok(ObjectEnvelope {
            object_id: envelope.object_id(),
            key_generation: envelope.key_generation(),
            data_profile: envelope.data_profile(),
            nonce: *envelope.nonce(),
            ciphertext: envelope.ciphertext().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};
    use crate::vault::tests::{PASSWORD, copy_fixture, edit, unlock};
    use crate::{UnlockedVault, VaultFile};
    use qv_crypto::{KeyGeneration, ObjectHashProfile, VaultId, object_hash};
    use qv_model::{RandomId, Timestamp};
    use std::os::unix::fs::symlink;

    fn vault(d: &TestDir, a: &TestDir) -> UnlockedVault {
        let (path, anchors) = copy_fixture(d, a, "local.qvault");
        unlock(&path, &anchors, PASSWORD).unwrap()
    }

    fn archive(vault: &mut UnlockedVault) -> Vec<u8> {
        let mut bytes = Vec::new();
        vault
            .write_archive(&mut bytes, Timestamp(1), &|| false)
            .unwrap();
        bytes
    }

    fn scope(u: &UnlockedVault) -> ArchiveScope {
        ArchiveScope::new(u.header().vault_id, u.header().key_generation)
    }

    #[test]
    fn incoming_stable_private_copy_and_verified_role_access() {
        let (d, a, private) = (TestDir::new(), TestDir::new(), TestDir::new());
        let mut u = vault(&d, &a);
        let record = <RecordId as RandomId>::generate().unwrap();
        let version = edit(&mut u, record, "stable secret");
        let bytes = archive(&mut u);
        let source = d.join("input.qvsnap");
        write_file(&source, &bytes, 0o644);
        let before_seq = u.local_seq();
        let db_before = std::fs::read(d.join("local.qvault")).unwrap();
        let mut incoming =
            VerifiedIncoming::open(&source, private.path(), scope(&u), u.vault_key(), &|| false)
                .unwrap();
        assert_eq!(
            incoming.digest(),
            &object_hash(ObjectHashProfile::V1, &bytes).0
        );
        assert_eq!(incoming.manifest(), u.manifest());
        assert_eq!(format!("{incoming:?}"), "VerifiedIncoming(..)");
        assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
        std::fs::write(&source, b"replaced").unwrap();
        assert_eq!(
            incoming
                .read_version(u.vault_key(), record, version)
                .unwrap()
                .encode()
                .unwrap()
                .as_slice(),
            u.read_version(record, version)
                .unwrap()
                .encode()
                .unwrap()
                .as_slice()
        );
        for r in u.manifest().references() {
            let obj = incoming.read_object(r.object_id()).unwrap();
            assert_eq!(
                &object_hash(ObjectHashProfile::V1, &obj.ciphertext).0,
                r.sha256()
            );
        }
        assert_eq!(u.local_seq(), before_seq);
        assert_eq!(std::fs::read(d.join("local.qvault")).unwrap(), db_before);
        // Even accidental mutation of the private descriptor cannot bypass
        // the complete-envelope commitment retained by the reader.
        let last = u.manifest().references().last().unwrap().object_id();
        incoming.file.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0];
        incoming.file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        incoming.file.seek(SeekFrom::End(-1)).unwrap();
        incoming.file.write_all(&byte).unwrap();
        assert_eq!(
            incoming.read_object(last).unwrap_err(),
            StoreError::Integrity
        );
        drop(incoming);
        assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
    }

    // 0012 §1: Hostile files from sync folders
    #[test]
    fn incoming_rejects_incomplete_changed_foreign_and_sqlite_files() {
        let (d, a, private) = (TestDir::new(), TestDir::new(), TestDir::new());
        let mut u = vault(&d, &a);
        let bytes = archive(&mut u);
        let source = d.join("input.qvsnap");
        let seq = u.local_seq();
        for end in [0, 7, 10, bytes.len() / 2, bytes.len() - 1] {
            write_file(&source, &bytes[..end], 0o600);
            assert!(
                VerifiedIncoming::open(&source, private.path(), scope(&u), u.vault_key(), &|| {
                    false
                })
                .is_err()
            );
            assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
        }
        let mut bad = bytes.clone();
        bad.push(1);
        write_file(&source, &bad, 0o600);
        assert!(
            VerifiedIncoming::open(&source, private.path(), scope(&u), u.vault_key(), &|| false)
                .is_err()
        );
        bad = bytes.clone();
        *bad.last_mut().unwrap() ^= 1;
        write_file(&source, &bad, 0o600);
        assert!(
            VerifiedIncoming::open(&source, private.path(), scope(&u), u.vault_key(), &|| false)
                .is_err()
        );
        write_file(&source, &bytes, 0o600);
        for other in [
            ArchiveScope::new(VaultId([9; 16]), u.header().key_generation),
            ArchiveScope::new(u.header().vault_id, KeyGeneration(2)),
        ] {
            assert!(
                VerifiedIncoming::open(&source, private.path(), other, u.vault_key(), &|| false)
                    .is_err()
            );
        }
        let database = d.join("local.qvault");
        let db_before = std::fs::read(&database).unwrap();
        assert!(
            VerifiedIncoming::open(&database, private.path(), scope(&u), u.vault_key(), &|| {
                false
            })
            .is_err()
        );
        assert_eq!(std::fs::read(database).unwrap(), db_before);
        assert_eq!(u.local_seq(), seq);
        assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
    }

    #[test]
    fn incoming_rejects_symlink_special_oversize_and_cancellation() {
        let (d, a, private) = (TestDir::new(), TestDir::new(), TestDir::new());
        let mut u = vault(&d, &a);
        let bytes = archive(&mut u);
        let source = d.join("input.qvsnap");
        write_file(&source, &bytes, 0o600);
        let link = d.join("link");
        symlink(&source, &link).unwrap();
        let fifo = d.join("fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        assert_eq!(
            VerifiedIncoming::open(&fifo, private.path(), scope(&u), u.vault_key(), &|| false)
                .unwrap_err(),
            StoreError::UnsafeFile
        );
        assert!(
            VerifiedIncoming::open(&link, private.path(), scope(&u), u.vault_key(), &|| false)
                .is_err()
        );
        assert!(
            VerifiedIncoming::open(d.path(), private.path(), scope(&u), u.vault_key(), &|| {
                false
            })
            .is_err()
        );
        assert_eq!(
            VerifiedIncoming::open(&source, private.path(), scope(&u), u.vault_key(), &|| true)
                .unwrap_err(),
            StoreError::Io
        );
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            VerifiedIncoming::open(&source, private.path(), scope(&u), u.vault_key(), &|| {
                calls.set(calls.get() + 1);
                calls.get() > 2
            })
            .unwrap_err(),
            StoreError::Io
        );
        File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_len(crate::MAX_DB_BYTES + 1)
            .unwrap();
        assert_eq!(
            VerifiedIncoming::open(&source, private.path(), scope(&u), u.vault_key(), &|| false)
                .unwrap_err(),
            StoreError::LimitExceeded
        );
        assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
        // Verify that no hidden source path or key data appears in failures.
        assert_eq!(
            StoreError::Integrity.to_string(),
            "vault integrity check failed"
        );
        drop(u);
        let _ = VaultFile::open(&d.join("local.qvault")).unwrap();
    }
}
