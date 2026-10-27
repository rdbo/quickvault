// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session-bound attachment operations. Stream callbacks must not reenter Session.
use crate::{
    CancelToken, CoreError, EntryHandle, Session,
    edit::{Change, commit, commit_with},
    error::{data, input},
    session::{Ctx, SessionTag},
    views::{decrypt, record},
};
use qv_crypto::RecordId;
use qv_model::{Extensions, Payload, RandomId, RecordBody, RecordKind, Text, VersionId};

/// An attachment head, scoped to its owning entry and unlocked session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttachmentHandle {
    session: SessionTag,
    entry: EntryHandle,
    record: RecordId,
    version: VersionId,
}
impl core::fmt::Debug for AttachmentHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AttachmentHandle(<redacted>)")
    }
}
impl AttachmentHandle {
    /// Record ID as lowercase hex (metadata).
    pub fn id_hex(&self) -> String {
        crate::setup::hex(&self.record.0)
    }
    /// Version ID as lowercase hex (metadata).
    pub fn version_hex(&self) -> String {
        crate::setup::hex(&self.version.to_bytes())
    }
}
/// One live metadata head; conflicts are emitted as separate summaries.
pub struct AttachmentSummary {
    /// Session-scoped head handle.
    pub handle: AttachmentHandle,
    /// Untrusted file name.
    pub name: Text,
    /// Untrusted MIME type; never executed/sniffed.
    pub mime: Text,
    /// Measured plaintext length in bytes.
    pub size: u64,
    /// Whether this record has unresolved heads.
    pub conflicted: bool,
}
impl core::fmt::Debug for AttachmentSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AttachmentSummary(<redacted>)")
    }
}
fn owner(ctx: &Ctx<'_>, entry: EntryHandle, single: bool) -> Result<(), CoreError> {
    ctx.own(entry.session)?;
    let r = record(&ctx.open.index, entry.record, RecordKind::Entry)?;
    if single {
        r.single_head()?;
    }
    if r.status.in_trash || r.status.finally_deleted {
        return Err(CoreError::NotFound);
    }
    Ok(())
}
fn validate(ctx: &Ctx<'_>, handle: AttachmentHandle) -> Result<(), CoreError> {
    ctx.own(handle.session)?;
    owner(ctx, handle.entry, true)?;
    let r = record(&ctx.open.index, handle.record, RecordKind::AttachmentMeta)?;
    if r.single_head()? != handle.version {
        return Err(CoreError::StaleHandle);
    }
    match decrypt(ctx, handle.record, handle.version)?.body {
        RecordBody::Live(Payload::AttachmentMeta(a)) if a.entry == handle.entry.record => Ok(()),
        _ => Err(CoreError::NotFound),
    }
}
impl Session {
    /// Lists each live attachment metadata head without combining conflicts.
    pub fn attachments(&self, entry: EntryHandle) -> Result<Vec<AttachmentSummary>, CoreError> {
        self.read(|ctx| {
            owner(ctx, entry, false)?;
            let mut out = Vec::new();
            let mut budget = 0usize;
            for (id, r) in &ctx.open.index.records {
                ctx.check_cancel()?;
                if r.kind != RecordKind::AttachmentMeta || r.status.finally_deleted {
                    continue;
                }
                for v in &r.heads {
                    if let RecordBody::Live(Payload::AttachmentMeta(a)) =
                        decrypt(ctx, *id, *v)?.body
                        && a.entry == entry.record
                    {
                        budget = budget
                            .checked_add(
                                a.name.expose().len()
                                    + a.mime.expose().len()
                                    + std::mem::size_of::<AttachmentSummary>(),
                            )
                            .ok_or(CoreError::LimitExceeded)?;
                        if budget > crate::index::MAX_VIEW_BYTES {
                            return Err(CoreError::LimitExceeded);
                        }
                        out.push(AttachmentSummary {
                            handle: AttachmentHandle {
                                session: ctx.tag(),
                                entry,
                                record: *id,
                                version: *v,
                            },
                            name: Text::new(a.name.expose()).map_err(data)?,
                            mime: Text::new(a.mime.expose()).map_err(data)?,
                            size: a.size,
                            conflicted: r.status.conflict,
                        });
                    }
                }
            }
            out.sort_by_key(|a| (a.handle.record, a.handle.version));
            Ok(out)
        })
    }
    /// Imports bounded content in one transaction; callbacks must not reenter Session.
    pub fn add_attachment(
        &self,
        entry: EntryHandle,
        name: &str,
        mime: &str,
        source: &mut impl std::io::Read,
        cancel: Option<&CancelToken>,
    ) -> Result<AttachmentHandle, CoreError> {
        let name = Text::new(name).map_err(input)?;
        let mime = Text::new(mime).map_err(input)?;
        self.mutate(|ctx| {
            owner(ctx, entry, true)?;
            let record = RecordId::generate().map_err(data)?;
            let canceller = ctx.canceller();
            let cancelled =
                || canceller.check().is_err() || cancel.is_some_and(CancelToken::is_cancelled);
            if cancelled() {
                return Err(CoreError::Cancelled);
            }
            let result = commit_with(
                ctx,
                |w| {
                    let staged = w.stage_attachment(record, source, &cancelled);
                    if cancelled() {
                        return Err(CoreError::Cancelled);
                    }
                    let meta = staged?.into_meta(entry.record, name, mime);
                    Ok(vec![Change {
                        record,
                        kind: RecordKind::AttachmentMeta,
                        body: RecordBody::Live(Payload::AttachmentMeta(meta)),
                        ext: Extensions::new(),
                    }])
                },
                &cancelled,
            );
            result?;
            Ok(AttachmentHandle {
                session: ctx.tag(),
                entry,
                record,
                version: record_head(ctx, record)?,
            })
        })
    }
    /// Verifies complete content before a frontend creates an output file.
    pub fn verify_attachment(
        &self,
        handle: AttachmentHandle,
        cancel: Option<&CancelToken>,
    ) -> Result<(), CoreError> {
        self.save_attachment(handle, &mut std::io::sink(), cancel)
    }
    /// Streams authenticated chunks; only Ok confirms full content integrity.
    /// Partial output on failure must not be accepted. Callbacks must not reenter Session.
    pub fn save_attachment(
        &self,
        handle: AttachmentHandle,
        sink: &mut impl std::io::Write,
        cancel: Option<&CancelToken>,
    ) -> Result<(), CoreError> {
        self.read(|ctx| {
            validate(ctx, handle)?;
            let cancelled =
                || ctx.check_cancel().is_err() || cancel.is_some_and(CancelToken::is_cancelled);
            let result =
                ctx.open
                    .vault
                    .read_attachment(handle.record, handle.version, sink, &cancelled);
            if cancelled() {
                return Err(CoreError::Cancelled);
            }
            Ok(result?)
        })
    }
    /// Permanently removes this attachment using the existing causal tombstone path.
    pub fn remove_attachment(&self, handle: AttachmentHandle) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            validate(ctx, handle)?;
            commit(
                ctx,
                vec![Change {
                    record: handle.record,
                    kind: RecordKind::AttachmentMeta,
                    body: RecordBody::Tombstone(RecordKind::AttachmentMeta),
                    ext: Extensions::new(),
                }],
            )
        })
    }
}
fn record_head(ctx: &Ctx<'_>, id: RecordId) -> Result<VersionId, CoreError> {
    record(&ctx.open.index, id, RecordKind::AttachmentMeta)?.single_head()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Env, err};
    use std::io::{Read, Write};
    struct Pattern {
        remaining: usize,
        offset: usize,
        largest: usize,
    }
    impl Read for Pattern {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.largest = self.largest.max(out.len());
            let n = out.len().min(self.remaining).min(777);
            for (i, b) in out[..n].iter_mut().enumerate() {
                *b = ((self.offset + i) % 251) as u8;
            }
            self.remaining -= n;
            self.offset += n;
            Ok(n)
        }
    }
    #[derive(Default)]
    struct Check {
        offset: usize,
        largest: usize,
    }
    impl Write for Check {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.largest = self.largest.max(bytes.len());
            let n = bytes.len().min(1234);
            for (i, b) in bytes[..n].iter().enumerate() {
                assert_eq!(*b, ((self.offset + i) % 251) as u8);
            }
            self.offset += n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn entry(s: &Session) -> EntryHandle {
        s.save_entry(s.new_entry(s.root().unwrap(), "login", "Files").unwrap())
            .unwrap()
    }
    #[test]
    fn attachment_lock_stops_output_between_chunks() {
        use std::{
            sync::{Arc, mpsc::channel},
            time::Duration,
        };
        let env = Env::new();
        let s = Arc::new(env.unlock());
        let e = entry(&s);
        let h = s
            .add_attachment(e, "x", "x", &mut &vec![8; 65_537][..], None)
            .unwrap();
        let (arrive, arrived) = channel();
        let (go, resume) = channel();
        struct Paused {
            arrive: Option<std::sync::mpsc::Sender<()>>,
            resume: std::sync::mpsc::Receiver<()>,
            bytes: usize,
        }
        impl Write for Paused {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes += bytes.len();
                if let Some(tx) = self.arrive.take() {
                    tx.send(()).unwrap();
                    self.resume.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let worker = {
            let s = s.clone();
            std::thread::spawn(move || {
                let mut sink = Paused {
                    arrive: Some(arrive),
                    resume,
                    bytes: 0,
                };
                let result = s.save_attachment(h, &mut sink, None);
                (result, sink.bytes)
            })
        };
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        let locker = {
            let s = s.clone();
            std::thread::spawn(move || s.lock())
        };
        while !s.is_locked() {
            std::thread::yield_now();
        }
        go.send(()).unwrap();
        let (result, bytes) = worker.join().unwrap();
        locker.join().unwrap();
        assert_eq!(result, Err(CoreError::Cancelled));
        assert_eq!(bytes, 65_536);
    }

    #[test]
    fn attachment_anchor_failure_keeps_index_and_read_only_refuses_staging() {
        let env = Env::new();
        let s = env.unlock();
        let e = entry(&s);
        let before = s.overview().unwrap().local_seq;
        let held = env.dir.path().join("held-anchors");
        std::fs::rename(&env.anchors, &held).unwrap();
        std::fs::write(&env.anchors, b"block directory access").unwrap();
        assert_eq!(
            err(s.add_attachment(e, "durable", "x", &mut &b"abc"[..], None)),
            CoreError::Store(qv_store::StoreError::Io)
        );
        assert_eq!(s.overview().unwrap().local_seq, before + 1);
        let items = s.attachments(e).unwrap();
        assert_eq!(items.len(), 1);
        s.verify_attachment(items[0].handle, None).unwrap();
        std::fs::remove_file(&env.anchors).unwrap();
        std::fs::rename(&held, &env.anchors).unwrap();
        s.remove_attachment(items[0].handle).unwrap();
        drop(s);
        for file in std::fs::read_dir(&env.anchors).unwrap() {
            std::fs::remove_file(file.unwrap().path()).unwrap();
        }
        let core = env.core();
        let _k = crate::testutil::kdf();
        let (s, _) = core
            .unlock_for_recovery(
                &env.path,
                &crate::testutil::pw(crate::testutil::PASSWORD),
                None,
            )
            .unwrap();
        let e = s.list(s.root().unwrap()).unwrap().entries[0].handle;
        assert_eq!(
            err(s.add_attachment(e, "refused", "x", &mut &b"abc"[..], None)),
            CoreError::Store(qv_store::StoreError::NoAnchor)
        );
    }
    #[test]
    fn attachment_conflict_policy_refuses_writes_and_export() {
        let env = Env::new();
        let s = env.unlock();
        let e = entry(&s);
        let h = s
            .add_attachment(e, "x", "x", &mut &b"abc"[..], None)
            .unwrap();
        s.mutate(|ctx| {
            ctx.open
                .index
                .records
                .get_mut(&h.record)
                .unwrap()
                .heads
                .push(VersionId::generate().unwrap());
            Ok(())
        })
        .unwrap();
        assert_eq!(err(s.remove_attachment(h)), CoreError::Conflict);
        assert_eq!(err(s.verify_attachment(h, None)), CoreError::Conflict);
        s.mutate(|ctx| {
            ctx.open
                .index
                .records
                .get_mut(&e.record)
                .unwrap()
                .heads
                .push(VersionId::generate().unwrap());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            err(s.add_attachment(e, "x", "x", &mut &b"abc"[..], None)),
            CoreError::Conflict
        );
    }

    #[test]
    fn attachment_streaming_boundaries_retention_and_handles() {
        let env = Env::new();
        let s = env.unlock();
        let e = entry(&s);
        for size in [0, 1, 65_535, 65_536, 65_537, 10 * 1024 * 1024] {
            let mut source = Pattern {
                remaining: size,
                offset: 0,
                largest: 0,
            };
            let h = s
                .add_attachment(
                    e,
                    "untrusted\nname",
                    "application/octet-stream",
                    &mut source,
                    None,
                )
                .unwrap();
            assert!(source.largest <= 65_536);
            let mut sink = Check::default();
            s.save_attachment(h, &mut sink, None).unwrap();
            assert_eq!(sink.offset, size);
            assert!(sink.largest <= 65_536);
            assert_eq!(s.attachments(e).unwrap()[0].size, size as u64);
            s.delete(crate::ItemHandle::Entry(e), false).unwrap();
            assert_eq!(err(s.verify_attachment(h, None)), CoreError::NotFound);
            s.restore(crate::ItemHandle::Entry(e)).unwrap();
            s.verify_attachment(h, None).unwrap();
            s.remove_attachment(h).unwrap();
            assert!(s.attachments(e).unwrap().is_empty());
            assert_eq!(err(s.verify_attachment(h, None)), CoreError::NotFound);
        }
        let seq = s.overview().unwrap().local_seq;
        let mut oversized = Pattern {
            remaining: 10 * 1024 * 1024 + 1,
            offset: 0,
            largest: 0,
        };
        assert_eq!(
            err(s.add_attachment(e, "large", "x", &mut oversized, None)),
            CoreError::Store(qv_store::StoreError::LimitExceeded)
        );
        assert_eq!(s.overview().unwrap().local_seq, seq);
        assert!(s.attachments(e).unwrap().is_empty());
        let h = s
            .add_attachment(e, "keep", "x", &mut &b"abc"[..], None)
            .unwrap();
        let other = env.core(); // cannot unlock concurrently; session handles expire after reopen
        s.lock();
        let _k = crate::testutil::kdf();
        let reopened = other
            .unlock(
                &env.path,
                &crate::testutil::pw(crate::testutil::PASSWORD),
                None,
            )
            .unwrap();
        assert_eq!(
            err(reopened.verify_attachment(h, None)),
            CoreError::StaleHandle
        );
        let fresh = reopened.entry_versions(e);
        assert_eq!(err(fresh), CoreError::StaleHandle);
    }
    #[test]
    fn attachment_read_errors_cancel_and_purge() {
        let env = Env::new();
        let s = env.unlock();
        let e = entry(&s);
        struct Fail;
        impl Read for Fail {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::Other.into())
            }
        }
        let seq = s.overview().unwrap().local_seq;
        assert!(s.add_attachment(e, "bad", "x", &mut Fail, None).is_err());
        assert_eq!(s.overview().unwrap().local_seq, seq);
        let token = CancelToken::new();
        token.cancel();
        assert_eq!(
            err(s.add_attachment(e, "cancel", "x", &mut &b"abc"[..], Some(&token))),
            CoreError::Cancelled
        );
        let h = s
            .add_attachment(e, "good", "x", &mut &b"abc"[..], None)
            .unwrap();
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(28))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(s.save_attachment(h, &mut Full, None).is_err());
        s.verify_attachment(h, None).unwrap();
        assert_eq!(
            err(s.verify_attachment(h, Some(&token))),
            CoreError::Cancelled
        );
        s.delete(crate::ItemHandle::Entry(e), false).unwrap();
        s.purge(&[crate::ItemHandle::Entry(e)]).unwrap();
        s.read(|ctx| {
            let role = ctx.open.vault.manifest().record(h.record).unwrap();
            assert!(role.history().is_empty());
            assert!(role.heads()[0].chunks().is_none());
            Ok(())
        })
        .unwrap();
    }
}
