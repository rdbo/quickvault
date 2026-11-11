// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit selected-document import and fresh-local publication (0004 §5.4).
use std::{io::Read, path::Path};

use crate::index::{Index, MAX_VIEW_BYTES};
use crate::session::SessionTag;
use crate::{CancelToken, Core, CoreError, MasterPassword, Session};

/// A private, immutable staged document. Retained across wrong-password retries.
pub struct PendingVaultImport(qv_store::PendingVaultImport);

/// Source-bound authentication and projection; publication consumes this value.
pub struct VerifiedVaultImport {
    source: qv_store::VerifiedVaultImport,
    index: Index,
    tag: SessionTag,
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

fn map<T>(
    result: Result<T, qv_store::StoreError>,
    cancel: Option<&CancelToken>,
) -> Result<T, CoreError> {
    match result {
        Err(qv_store::StoreError::PublicationIncomplete) => {
            Err(qv_store::StoreError::PublicationIncomplete.into())
        }
        Err(_) if cancel.is_some_and(CancelToken::is_cancelled) => Err(CoreError::Cancelled),
        other => other.map_err(Into::into),
    }
}

impl Core {
    /// Clean only unleased import staging in this core's private state root.
    /// This never visits a provider or published vault directory.
    pub fn cleanup_vault_imports(&self) -> Result<(), CoreError> {
        let base = self
            .anchors
            .path()
            .parent()
            .ok_or(CoreError::InvalidInput)?;
        qv_store::PendingVaultImport::cleanup(&base.join("imports")).map_err(Into::into)
    }
    /// Stream a selected encrypted document into leased private staging. The
    /// physical database bound is independent of the archive ciphertext budget.
    pub fn stage_vault_import(
        &self,
        input: &mut dyn Read,
        cancel: Option<&CancelToken>,
    ) -> Result<PendingVaultImport, CoreError> {
        self.platform_gate()?;
        let base = self
            .anchors
            .path()
            .parent()
            .ok_or(CoreError::InvalidInput)?;
        map(
            qv_store::PendingVaultImport::stage(&base.join("imports"), input, &|| {
                cancel.is_some_and(CancelToken::is_cancelled)
            }),
            cancel,
        )
        .map(PendingVaultImport)
    }

    /// Authenticate all contents and preflight the same bounded index used by
    /// normal opening, without touching another local replica's anchor.
    pub fn authenticate_vault_import(
        &self,
        source: &PendingVaultImport,
        password: &MasterPassword,
        cancel: Option<&CancelToken>,
    ) -> Result<VerifiedVaultImport, CoreError> {
        self.platform_gate()?;
        let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
        let source = map(source.0.authenticate(password, &cancelled), cancel)?;
        let index = Index::build(source.vault()?, &cancelled, MAX_VIEW_BYTES)?;
        if cancelled() {
            return Err(CoreError::Cancelled);
        }
        Ok(VerifiedVaultImport {
            source,
            index,
            tag: SessionTag::generate()?,
        })
    }

    /// Publish an authenticated independent local replica without replacing any
    /// path. The caller must first obtain explicit copy/baseline acknowledgement.
    pub fn publish_vault_import(
        &self,
        source: VerifiedVaultImport,
        destination: &Path,
        cancel: Option<&CancelToken>,
    ) -> Result<Session, CoreError> {
        self.platform_gate()?;
        self.check_anchor_location(destination)?;
        let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
        let vault = map(
            source
                .source
                .publish(destination, &self.anchors, self.time.now(), &cancelled),
            cancel,
        )?;
        let session = Session::open_indexed(
            vault,
            source.index,
            source.tag,
            self.time.clone(),
            qv_store::AnchorStatus::Verified,
            self.snapshots.clone(),
            false,
        );
        let session = self
            .bind_platform(session)
            .map_err(|_| CoreError::Store(qv_store::StoreError::PublicationIncomplete))?;
        if cancelled() || session.is_locked() || self.platform_gate().is_err() {
            session.lock();
            return Err(qv_store::StoreError::PublicationIncomplete.into());
        }
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Env, PASSWORD, err, kdf, pw};
    use std::io::{Cursor, Read};

    // 0012 §1: Budget inconsistency
    #[test]
    #[ignore = "disk-backed qualification writes several GiB; run explicitly for plan 0049"]
    fn vault_import_near_budget_streams_actual_bytes_and_reopens() {
        struct Counted {
            file: std::fs::File,
            bytes: u64,
            largest: usize,
        }
        impl Read for Counted {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                self.largest = self.largest.max(out.len());
                let count = self.file.read(out)?;
                self.bytes += count as u64;
                Ok(count)
            }
        }
        let env = Env::new();
        let source = env.unlock();
        let mut ids = Vec::new();
        let mut final_entry = None;
        for group in 0..4 {
            let entry = source
                .save_entry(
                    source
                        .new_entry(
                            source.root().unwrap(),
                            "login",
                            &format!("capacity entry {group}"),
                        )
                        .unwrap(),
                )
                .unwrap();
            let parts = if group == 3 { 24 } else { 25 };
            ids.push((entry.id_hex(), parts));
            final_entry = Some(entry);
            for part in 0..parts {
                let mut input = std::io::repeat((group * 25 + part) as u8).take(10 * 1024 * 1024);
                source
                    .add_attachment(
                        entry,
                        &format!("capacity-{part}.bin"),
                        "application/octet-stream",
                        &mut input,
                        None,
                    )
                    .unwrap();
            }
            eprintln!(
                "import qualification fixture: {} MiB written",
                (group * 25 + parts) * 10
            );
        }
        let sequence = source.overview().unwrap().local_seq;
        assert_eq!(
            err(source.add_attachment(
                final_entry.unwrap(),
                "over-budget.bin",
                "application/octet-stream",
                &mut std::io::repeat(7).take(10 * 1024 * 1024),
                None
            )),
            CoreError::Store(qv_store::StoreError::LimitExceeded)
        );
        assert_eq!(source.overview().unwrap().local_seq, sequence);
        let referenced = source
            .read(|ctx| {
                Ok(ctx
                    .open
                    .vault
                    .manifest()
                    .references()
                    .iter()
                    .map(|r| r.length())
                    .sum::<u64>())
            })
            .unwrap();
        assert!(referenced >= qv_store::MAX_TOTAL_CIPHERTEXT * 99 / 100);
        assert!(referenced <= qv_store::MAX_TOTAL_CIPHERTEXT);
        assert!(source.verify(None).unwrap().ok());
        source.lock();
        let physical = std::fs::metadata(&env.path).unwrap().len();
        assert!(physical >= 990 * 1024 * 1024);
        assert!(physical <= qv_store::MAX_DB_BYTES);
        let mut input = Counted {
            file: std::fs::File::open(&env.path).unwrap(),
            bytes: 0,
            largest: 0,
        };
        let core = env.core();
        let pending = core.stage_vault_import(&mut input, None).unwrap();
        eprintln!("import qualification: bounded ciphertext staging complete");
        assert_eq!(input.bytes, physical);
        assert!(input.largest <= 64 * 1024);
        drop(input);
        let verified = {
            let _k = kdf();
            core.authenticate_vault_import(&pending, &pw(PASSWORD), None)
                .unwrap()
        };
        let path = env.dir.path().join("capacity-import.qvault");
        let imported = core.publish_vault_import(verified, &path, None).unwrap();
        assert_eq!(imported.overview().unwrap().local_seq, 1);
        for (id, count) in ids {
            let entries = imported.find_id(&id, false).unwrap();
            let [crate::ItemHandle::Entry(entry)] = entries.as_slice() else {
                panic!("missing capacity entry")
            };
            assert_eq!(imported.attachments(*entry).unwrap().len(), count);
        }
        assert!(imported.verify(None).unwrap().ok());
        imported.lock();
        let reopened = {
            let _k = kdf();
            core.unlock(&path, &pw(PASSWORD), None).unwrap()
        };
        assert!(reopened.verify(None).unwrap().ok());
        reopened.lock();
        eprintln!(
            "explicit import qualification: 990 MiB attachment plaintext; {referenced} referenced ciphertext bytes; {physical} physical source bytes; bounded reads and durable reopen pass"
        );
    }

    // 0012 §1: Live SQLite copying
    #[test]
    fn vault_import_verifies_records_history_and_attachments_without_changing_source() {
        let env = Env::new();
        let source = env.unlock();
        let group = source
            .save_group(
                source
                    .new_group(source.root().unwrap(), "Imported group")
                    .unwrap(),
            )
            .unwrap();
        let entry = source
            .save_entry(source.new_entry(group, "login", "Original title").unwrap())
            .unwrap();
        let mut draft = source.edit_entry(entry).unwrap();
        draft.entry_mut().title = crate::Text::new("Imported title").unwrap();
        let entry = source.save_entry(draft).unwrap();
        source
            .add_attachment(
                entry,
                "fixture.txt",
                "text/plain",
                &mut Cursor::new(b"synthetic attachment"),
                None,
            )
            .unwrap();
        source.lock();
        let original = std::fs::read(&env.path).unwrap();
        let core = env.core();
        let pending = core
            .stage_vault_import(&mut Cursor::new(&original), None)
            .unwrap();
        let _k = kdf();
        let verified = core
            .authenticate_vault_import(&pending, &pw(PASSWORD), None)
            .unwrap();
        let path = env.dir.path().join("imported.qvault");
        let imported = core.publish_vault_import(verified, &path, None).unwrap();
        assert_eq!(imported.overview().unwrap().local_seq, 1);
        assert_eq!(imported.search("Imported title").unwrap().len(), 1);
        let entries = imported.find_id(&entry.id_hex(), false).unwrap();
        assert_eq!(entries.len(), 1);
        let crate::ItemHandle::Entry(entry) = entries[0] else {
            panic!("missing imported entry")
        };
        assert!(!imported.history(entry).unwrap().is_empty());
        assert_eq!(imported.attachments(entry).unwrap().len(), 1);
        assert!(imported.verify(None).unwrap().ok());
        imported.lock();
        assert!(
            core.unlock(&path, &pw(PASSWORD), None)
                .unwrap()
                .verify(None)
                .unwrap()
                .ok()
        );
        assert_eq!(std::fs::read(&env.path).unwrap(), original);
    }

    // 0012 §1: Whole-file rollback
    #[test]
    fn vault_import_wrong_password_collision_and_cancellation_are_retryable_before_publication() {
        let env = Env::new();
        let core = env.core();
        let original = std::fs::read(&env.path).unwrap();
        let pending = core
            .stage_vault_import(&mut Cursor::new(&original), None)
            .unwrap();
        let _k = kdf();
        assert_eq!(
            err(core.authenticate_vault_import(&pending, &pw("wrong"), None)),
            CoreError::Store(qv_store::StoreError::WrongPassword)
        );
        let verified = core
            .authenticate_vault_import(&pending, &pw(PASSWORD), None)
            .unwrap();
        assert_eq!(
            err(core.publish_vault_import(verified, &env.path, None)),
            CoreError::Store(qv_store::StoreError::Exists)
        );
        let verified = core
            .authenticate_vault_import(&pending, &pw(PASSWORD), None)
            .unwrap();
        let token = CancelToken::new();
        token.cancel();
        let path = env.dir.path().join("cancelled.qvault");
        assert_eq!(
            err(core.publish_vault_import(verified, &path, Some(&token))),
            CoreError::Cancelled
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read(&env.path).unwrap(), original);
        let verified = core
            .authenticate_vault_import(&pending, &pw(PASSWORD), None)
            .unwrap();
        assert!(core.publish_vault_import(verified, &path, None).is_ok());
    }

    // 0012 §1: Hostile SQLite/CBOR
    #[test]
    fn vault_import_hostile_or_cancelled_input_is_never_published() {
        let env = Env::new();
        let core = env.core();
        assert!(
            core.stage_vault_import(&mut Cursor::new(b"not a database"), None)
                .is_err()
        );
        let token = CancelToken::new();
        token.cancel();
        assert_eq!(
            err(core.stage_vault_import(&mut Cursor::new(b""), Some(&token))),
            CoreError::Cancelled
        );
        assert_eq!(
            std::fs::read_dir(env.dir.path().join("imports"))
                .unwrap()
                .count(),
            0
        );
    }

    // 0012 §1: Anchor crash windows
    #[test]
    fn vault_import_cancellation_during_platform_binding_preserves_publication() {
        use crate::platform::*;
        use std::sync::Arc;
        struct AfterPublication(CancelToken);
        struct Guard;
        impl Watch for Guard {}
        impl Lifecycle for AfterPublication {
            fn watch(&self, _: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
                self.0.cancel();
                Ok(Box::new(Guard))
            }
        }
        impl PlatformServices for AfterPublication {
            fn status(&self) -> ProtectionStatus {
                ProtectionStatus {
                    storage: Evidence::Unknown,
                    swap: Evidence::Unknown,
                    hibernation: Evidence::Unknown,
                    lifecycle: true,
                    clipboard: false,
                    quick_unlock: false,
                }
            }
            fn lifecycle(&self) -> &dyn Lifecycle {
                self
            }
            fn clipboard(&self) -> &dyn Clipboard {
                &Unavailable
            }
            fn secure_input(&self) -> &dyn SecureInput {
                &Unavailable
            }
            fn keystore(&self) -> &dyn Keystore {
                &Unavailable
            }
        }
        let env = Env::new();
        let core = env.core();
        let bytes = std::fs::read(&env.path).unwrap();
        let pending = core
            .stage_vault_import(&mut Cursor::new(bytes), None)
            .unwrap();
        let _k = kdf();
        let verified = core
            .authenticate_vault_import(&pending, &pw(PASSWORD), None)
            .unwrap();
        let token = CancelToken::new();
        let guarded = env
            .core()
            .with_platform(Arc::new(AfterPublication(token.clone())), true);
        let path = env.dir.path().join("published.qvault");
        assert_eq!(
            err(guarded.publish_vault_import(verified, &path, Some(&token))),
            CoreError::Store(qv_store::StoreError::PublicationIncomplete)
        );
        assert!(token.is_cancelled());
        assert!(
            core.unlock(&path, &pw(PASSWORD), None)
                .unwrap()
                .verify(None)
                .unwrap()
                .ok()
        );
    }
}
