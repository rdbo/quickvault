// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit user-selected raw vault input (0004 §5.4). Only ciphertext is staged.
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};

use qv_crypto::MasterPassword;
use qv_model::Timestamp;

use crate::{AnchorDir, ArchiveScope, SnapshotDir, StoreError, UnlockedVault, VaultFile, fs};

struct Staging {
    dir: PathBuf,
}

impl Drop for Staging {
    fn drop(&mut self) {
        // The same directory/identity/lease checks as crash cleanup. Live inputs
        // belonging to another producer are retained, including their journals.
        let _ = fs::remove_stale_temps(&self.dir.join("source.qvault"));
        let _ = fs::remove_stale_temps(&self.dir.join("archive.qvsnap"));
    }
}

/// A private immutable candidate, retaining its lock across password retries.
pub struct PendingVaultImport {
    file: Arc<Mutex<Option<VaultFile>>>,
    staging: Arc<Staging>,
}

/// A fully verified candidate; only consuming publication can create a vault.
pub struct VerifiedVaultImport {
    vault: Option<UnlockedVault>,
    pending: Arc<Mutex<Option<VaultFile>>>,
    staging: Arc<Staging>,
}

impl core::fmt::Debug for PendingVaultImport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PendingVaultImport(<redacted>)")
    }
}
impl core::fmt::Debug for VerifiedVaultImport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedVaultImport(<redacted>)")
    }
}

impl Drop for VerifiedVaultImport {
    fn drop(&mut self) {
        if let Some(vault) = self.vault.take() {
            // A failed pre-publication attempt leaves the immutable source
            // leased and reusable. Its key and decrypted state are dropped.
            let mut held = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            *held = Some(vault.file);
        }
        // A failed archive write must release disk space immediately even while
        // the password-retry candidate remains alive. Producers retain leases.
        let _ = fs::remove_stale_temps(&self.staging.dir.join("archive.qvsnap"));
        let _ = fs::remove_stale_temps(&self.staging.dir.join("source.qvault"));
    }
}

impl PendingVaultImport {
    /// Reap only known unleased ciphertext temporaries after a restart. The
    /// same inode/directory leases protect active candidates across processes.
    pub fn cleanup(dir: &Path) -> Result<(), StoreError> {
        let dir = SnapshotDir::open(dir)?;
        fs::remove_stale_temps(&dir.path().join("source.qvault"))?;
        fs::remove_stale_temps(&dir.path().join("archive.qvsnap"))
    }
    /// Stage actual bytes up to the physical database limit, then identify and
    /// harden the private file. Never follow or write back to a provider path.
    pub fn stage(
        dir: &Path,
        input: &mut dyn Read,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, StoreError> {
        stage_bounded(dir, input, crate::MAX_DB_BYTES, cancelled)
    }

    /// Authenticate the same candidate. A wrong password retains its connection
    /// and file lease; no provider reread or path substitution is possible.
    pub fn authenticate(
        &self,
        password: &MasterPassword,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedVaultImport, StoreError> {
        check_cancel(cancelled)?;
        let mut held = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let file = held.as_ref().ok_or(StoreError::Unsupported)?;
        file.check_identity()?;
        file.budget.reset();
        let slot = crate::slot::password_slot(&file.slots)?;
        let vk =
            slot.keyslot
                .slot
                .unlock(password, file.header.vault_id, file.header.key_generation)?;
        file.verify_header(&vk)?;
        check_cancel(cancelled)?;
        // This directory is used only for import inspection; no baseline is
        // adopted, and no existing local vault's anchor is read or updated.
        let anchors = AnchorDir::open(&self.staging.dir.join("source-anchors"))?;
        let file = held.take().ok_or(StoreError::Unsupported)?;
        let (vault, _) = file.finish_unlock(vk, &anchors)?;
        vault.verify_all(cancelled)?;
        let entry = vault
            .manifest()
            .record(vault.manifest().keyslot_id())
            .ok_or(StoreError::Integrity)?;
        let [head] = entry.heads() else {
            return Err(StoreError::Integrity);
        };
        let version = vault.read_version(entry.record_id(), head.version_id())?;
        let qv_model::RecordBody::Live(qv_model::Payload::PasswordKeyslot(slot)) = version.body
        else {
            return Err(StoreError::Integrity);
        };
        if slot.encode_public_descriptor()?
            != crate::slot::password_slot(&vault.file.slots)?
                .keyslot
                .encode_public_descriptor()?
        {
            return Err(StoreError::Integrity);
        }
        check_cancel(cancelled)?;
        Ok(VerifiedVaultImport {
            vault: Some(vault),
            pending: self.file.clone(),
            staging: self.staging.clone(),
        })
    }
}

fn check_cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
    if cancelled() {
        Err(StoreError::Io)
    } else {
        Ok(())
    }
}

fn stage_bounded(
    dir: &Path,
    input: &mut dyn Read,
    limit: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<PendingVaultImport, StoreError> {
    check_cancel(cancelled)?;
    let dir = SnapshotDir::open(dir)?;
    let staging = Arc::new(Staging {
        dir: dir.path().to_owned(),
    });
    fs::remove_stale_temps(&dir.path().join("source.qvault"))?;
    fs::remove_stale_temps(&dir.path().join("archive.qvsnap"))?;
    let (lock, path) = fs::create_temp(&dir.path().join("source.qvault"))?;
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        check_cancel(cancelled)?;
        let available = usize::try_from((limit - total).min(buffer.len() as u64))
            .map_err(|_| StoreError::LimitExceeded)?;
        // Read one extra byte at the boundary, without writing it to staging.
        let wanted = available.max(1);
        let count = match input.read(&mut buffer[..wanted]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(crate::error::io_err)?,
        };
        if count == 0 {
            break;
        }
        if count > available {
            return Err(StoreError::LimitExceeded);
        }
        let mut remaining = &buffer[..count];
        while !remaining.is_empty() {
            check_cancel(cancelled)?;
            match rustix::io::write(lock.fd(), remaining) {
                Ok(0) => return Err(StoreError::Io),
                Ok(n) => remaining = &remaining[n..],
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(crate::error::errno_err(e)),
            }
        }
        total += count as u64;
    }
    lock.sync()?;
    check_cancel(cancelled)?;
    let file = VaultFile::open_locked(&path, lock)?;
    Ok(PendingVaultImport {
        file: Arc::new(Mutex::new(Some(file))),
        staging,
    })
}

impl VerifiedVaultImport {
    /// Verified source for core's pre-publication projection. No key is exposed.
    pub fn vault(&self) -> Result<&UnlockedVault, StoreError> {
        self.vault.as_ref().ok_or(StoreError::Unsupported)
    }

    /// Stream through the ordinary verified archive restore path, creating a
    /// new writer/replica/head/anchor. No source local state is cloned.
    pub fn publish(
        mut self,
        path: &Path,
        anchors: &AnchorDir,
        now: Timestamp,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<UnlockedVault, StoreError> {
        check_cancel(cancelled)?;
        let vault = self.vault.as_mut().ok_or(StoreError::Unsupported)?;
        let (lock, _) = fs::create_temp(&self.staging.dir.join("archive.qvsnap"))?;
        let mut archive = lock.into_archive_file();
        let stats = vault.write_archive(&mut archive, now, cancelled)?;
        archive.flush().map_err(crate::error::io_err)?;
        archive.sync_all().map_err(crate::error::io_err)?;
        archive
            .seek(SeekFrom::Start(0))
            .map_err(crate::error::io_err)?;
        let scope = ArchiveScope::new(stats.vault_id, stats.key_generation);
        let published = VaultFile::create_from_import_archive(
            path,
            &mut archive,
            scope,
            &vault.vk,
            anchors,
            cancelled,
        );
        if matches!(published, Err(StoreError::PublicationIncomplete)) {
            self.vault = None;
        }
        published?;
        let source = self.vault.take().ok_or(StoreError::PublicationIncomplete)?;
        // Publication is durable. Preserve its outcome even if cancellation,
        // opening or platform binding fails after this point.
        let reopened = (|| {
            check_cancel(cancelled)?;
            let UnlockedVault {
                file,
                vk,
                state,
                anchors: source_anchors,
                gate: _,
            } = source;
            drop(file);
            drop(state);
            drop(source_anchors);
            let file = VaultFile::open(path)?;
            file.verify_header(&vk)?;
            let (vault, status) = file.finish_unlock(vk, anchors)?;
            if status != crate::AnchorStatus::Verified {
                return Err(StoreError::Integrity);
            }
            check_cancel(cancelled)?;
            Ok(vault)
        })();
        reopened.map_err(|_| StoreError::PublicationIncomplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::test_dir::TestDir;
    use crate::vault::tests::{PASSWORD, err, fixture, kdf, pw};
    use std::io::Cursor;

    // 0012 §1: Budget inconsistency
    #[test]
    fn vault_import_bounds_actual_bytes_and_cleans_failed_staging() {
        let dir = TestDir::new();
        let mut source = Cursor::new(vec![7; 17]);
        assert_eq!(
            err(stage_bounded(dir.path(), &mut source, 16, &|| false)),
            StoreError::LimitExceeded
        );
        assert_eq!(source.position(), 17);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let mut exact = Cursor::new(vec![7; 16]);
        assert_ne!(
            err(stage_bounded(dir.path(), &mut exact, 16, &|| false)),
            StoreError::LimitExceeded
        );
        assert_eq!(exact.position(), 16);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    // 0012 §1: Hostile SQLite/CBOR
    #[test]
    fn vault_import_retries_same_candidate_and_preserves_fresh_local_identity() {
        let dir = TestDir::new();
        let anchors = TestDir::new();
        let destination = TestDir::new();
        let bytes = fixture().bytes.clone();
        let pending =
            PendingVaultImport::stage(dir.path(), &mut Cursor::new(&bytes), &|| false).unwrap();
        let _k = kdf();
        assert_eq!(
            err(pending.authenticate(&pw("incorrect"), &|| false)),
            StoreError::WrongPassword
        );
        let verified = pending.authenticate(&pw(PASSWORD), &|| false).unwrap();
        let old_replica = verified.vault().unwrap().state.replica;
        let old_manifest = verified.vault().unwrap().manifest().clone();
        let path = destination.join("imported.qvault");
        let anchors = AnchorDir::open(anchors.path()).unwrap();
        let imported = verified
            .publish(&path, &anchors, Timestamp(1), &|| false)
            .unwrap();
        assert_eq!(imported.manifest(), &old_manifest);
        assert_ne!(imported.state.replica.replica_id, old_replica.replica_id);
        assert_ne!(imported.state.replica.writer_id, old_replica.writer_id);
        assert_eq!(imported.state.head.local_seq, 1);
        assert_eq!(imported.state.replica.next_counter, 1);
        assert!(imported.verify_all(&|| false).is_ok());
        drop(imported);
        let reopened = VaultFile::open(&path)
            .unwrap()
            .unlock(&pw(PASSWORD), &anchors)
            .unwrap();
        assert!(reopened.verify_all(&|| false).is_ok());
    }

    // 0012 §1: Anchor crash windows
    #[test]
    fn vault_import_distinguishes_pre_and_post_publication_failures() {
        use crate::crash::{
            CrashPoint,
            test::{arm, disarm},
        };
        let bytes = fixture().bytes.clone();
        let _k = kdf();
        for (point, published) in [
            (CrashPoint::CreateBuilt, false),
            (CrashPoint::ImportPublished, true),
        ] {
            let staging = TestDir::new();
            let output = TestDir::new();
            let anchors_dir = TestDir::new();
            let snapshot = TestDir::new();
            let anchors = AnchorDir::open(anchors_dir.path()).unwrap();
            let pending =
                PendingVaultImport::stage(staging.path(), &mut Cursor::new(&bytes), &|| false)
                    .unwrap();
            let verified = pending.authenticate(&pw(PASSWORD), &|| false).unwrap();
            let path = output.join("copy.qvault");
            arm(point, &path, anchors.path(), snapshot.path());
            let result = verified.publish(&path, &anchors, Timestamp(1), &|| false);
            assert!(!disarm(), "import crash point was reached");
            assert_eq!(
                err(result),
                if published {
                    StoreError::PublicationIncomplete
                } else {
                    StoreError::Internal
                }
            );
            assert_eq!(path.exists(), published);
            assert!(!std::fs::read_dir(staging.path()).unwrap().any(|e| {
                e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".archive.qvsnap.tmp-")
            }));
            if published {
                let opened = VaultFile::open(&path)
                    .unwrap()
                    .unlock(&pw(PASSWORD), &anchors)
                    .unwrap();
                assert!(opened.verify_all(&|| false).is_ok());
            } else {
                // The failed attempt returned the still-leased source connection.
                let verified = pending.authenticate(&pw(PASSWORD), &|| false).unwrap();
                assert!(
                    verified
                        .publish(&path, &anchors, Timestamp(1), &|| false)
                        .is_ok()
                );
            }
        }
    }

    // 0012 §1: Live SQLite copying
    #[test]
    fn vault_import_cleanup_retains_active_sources_and_reaps_unleased_temps() {
        let dir = TestDir::new();
        let (abandoned, path) = fs::create_temp(&dir.join("source.qvault")).unwrap();
        drop(abandoned);
        let first =
            PendingVaultImport::stage(dir.path(), &mut Cursor::new(&fixture().bytes), &|| false)
                .unwrap();
        assert!(!path.exists());
        let second =
            PendingVaultImport::stage(dir.path(), &mut Cursor::new(&fixture().bytes), &|| false)
                .unwrap();
        let _k = kdf();
        assert!(first.authenticate(&pw(PASSWORD), &|| false).is_ok());
        drop(first);
        assert!(second.authenticate(&pw(PASSWORD), &|| false).is_ok());
        drop(second);
        let remaining = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec![std::ffi::OsString::from("source-anchors")]);
    }
}
