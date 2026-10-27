// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retained entry history, intentional restore and local history purge (0007 §1).
use crate::{
    CoreError, EntryHandle, Session,
    error::data,
    session::{Ctx, SessionTag},
    views::record,
};
use qv_crypto::ContentHasher;
use qv_model::{
    Entry, FieldId, FieldValue, Payload, RandomId, RecordBody, RecordKind, RecordVersion, Text,
    Timestamp, VersionId, WriterId,
};

/// A session-bound retained entry version.
#[derive(Clone, Copy)]
pub struct HistoryHandle {
    session: SessionTag,
    entry: EntryHandle,
    version: VersionId,
}

impl core::fmt::Debug for HistoryHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HistoryHandle(<redacted>)")
    }
}
impl HistoryHandle {
    /// The historical version ID as lowercase hexadecimal metadata.
    pub fn version_hex(&self) -> String {
        crate::setup::hex(&self.version.to_bytes())
    }
}

/// Metadata for one retained entry version; values are never included.
pub struct HistorySummary {
    /// Session-bound historical handle.
    pub handle: HistoryHandle,
    /// Version modification time.
    pub modified_at: Timestamp,
    /// Version vector components.
    pub writers: Vec<(WriterId, u64)>,
    /// Whether the entry currently has multiple active heads.
    pub conflict: bool,
    /// Current representative used for the comparison.
    pub compared_to: VersionId,
    /// Changed top-level properties.
    pub changed_properties: Vec<Text>,
    /// Changed field IDs and names.
    pub changed_fields: Vec<(FieldId, Text)>,
    /// Whether unknown extension content changed.
    pub unknown_extensions_changed: bool,
}
impl core::fmt::Debug for HistorySummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HistorySummary(<redacted>)")
    }
}

fn entry_payload(v: RecordVersion) -> Result<Entry, CoreError> {
    match v.body {
        RecordBody::Live(Payload::Entry(e)) => Ok(e),
        _ => Err(CoreError::NotFound),
    }
}
fn digest(v: &FieldValue) -> qv_crypto::SecretArray<32> {
    let mut h = ContentHasher::new();
    h.update(v.expose_secret());
    h.finalize()
}
fn same_field(a: &qv_model::Field, b: &qv_model::Field) -> bool {
    a.id == b.id
        && a.name.expose() == b.name.expose()
        && a.kind == b.kind
        && a.protected == b.protected
        && matches!(
            (&a.value, &b.value),
            (FieldValue::Text(_), FieldValue::Text(_))
                | (FieldValue::Bytes(_), FieldValue::Bytes(_))
        )
        && a.ext.content_eq(&b.ext)
        && digest(&a.value).ct_eq(digest(&b.value).expose_secret())
}
fn text(s: &str) -> Result<Text, CoreError> {
    Text::new(s).map_err(data)
}
type Changes = (Vec<Text>, Vec<(FieldId, Text)>);
fn changed(a: &Entry, b: &Entry) -> Result<Changes, CoreError> {
    let mut props = Vec::new();
    if a.group != b.group {
        props.push(text("group")?);
    }
    if a.type_hint.expose() != b.type_hint.expose() {
        props.push(text("type_hint")?);
    }
    if a.title.expose() != b.title.expose() {
        props.push(text("title")?);
    }
    if a.notes.as_ref().map(Text::expose) != b.notes.as_ref().map(Text::expose) {
        props.push(text("notes")?);
    }
    if a.icon.as_ref().map(Text::expose) != b.icon.as_ref().map(Text::expose) {
        props.push(text("icon")?);
    }
    if a.expires_at != b.expires_at {
        props.push(text("expires_at")?);
    }
    if a.deleted_at != b.deleted_at {
        props.push(text("deleted_at")?);
    }
    if a.created_at != b.created_at {
        props.push(text("created_at")?);
    }
    if a.modified_at != b.modified_at {
        props.push(text("modified_at")?);
    }
    let mut fields = Vec::new();
    for old in &a.fields {
        match b.fields.iter().find(|f| f.id == old.id) {
            Some(new)
                if same_field(old, new)
                    && a.fields.iter().position(|f| f.id == old.id)
                        == b.fields.iter().position(|f| f.id == old.id) => {}
            Some(new) => fields.push((new.id, text(new.name.expose())?)),
            None => fields.push((old.id, text(old.name.expose())?)),
        }
    }
    for new in &b.fields {
        if !a.fields.iter().any(|f| f.id == new.id) {
            fields.push((new.id, text(new.name.expose())?));
        }
    }
    fields.sort_by_key(|(id, _)| *id);
    props.sort_by(|a, b| a.expose().cmp(b.expose()));
    Ok((props, fields))
}
fn validate_history(ctx: &Ctx<'_>, h: HistoryHandle) -> Result<RecordVersion, CoreError> {
    ctx.own(h.session)?;
    if h.entry.session != h.session {
        return Err(CoreError::StaleHandle);
    }
    let r = record(&ctx.open.index, h.entry.record, RecordKind::Entry)?;
    if r.status.finally_deleted {
        return Err(CoreError::NotFound);
    }
    if !ctx
        .open
        .vault
        .manifest()
        .record(h.entry.record)
        .is_some_and(|r| r.history().iter().any(|v| v.version_id() == h.version))
    {
        return Err(CoreError::StaleHandle);
    }
    ctx.open
        .vault
        .read_version(h.entry.record, h.version)
        .map_err(Into::into)
}

impl Session {
    /// Reveals one retained historical field explicitly, never through a current
    /// FieldHandle capability. The caller must drop the value on lock.
    pub fn reveal_history(
        &self,
        h: HistoryHandle,
        field: FieldId,
    ) -> Result<FieldValue, CoreError> {
        self.read(|ctx| {
            let e = entry_payload(validate_history(ctx, h)?)?;
            e.fields
                .into_iter()
                .find(|f| f.id == field)
                .map(|f| f.value)
                .ok_or(CoreError::NotFound)
        })
    }

    /// Restores the complete retained entry as a fresh causal edit.
    /// Multiple current heads require explicit conflict-resolution consent.
    pub fn restore_history(
        &self,
        h: HistoryHandle,
        resolve_conflicts: bool,
    ) -> Result<EntryHandle, CoreError> {
        self.mutate(|ctx| {
            let old = validate_history(ctx, h)?;
            let info = record(&ctx.open.index, h.entry.record, RecordKind::Entry)?;
            if info.status.in_trash || info.status.finally_deleted {
                return Err(CoreError::NotAllowed);
            }
            if info.status.conflict && !resolve_conflicts {
                return Err(CoreError::Conflict);
            }
            let current = entry_payload(
                ctx.open
                    .vault
                    .read_version(h.entry.record, info.shown.ok_or(CoreError::NotFound)?)?,
            )?;
            let mut e = match old.body {
                RecordBody::Live(Payload::Entry(e)) => e,
                _ => return Err(CoreError::NotFound),
            };
            if ctx.open.index.tree.parent(e.group).is_none()
                || !ctx.open.index.get(e.group).is_some_and(|r| {
                    r.kind == RecordKind::Group && !r.status.in_trash && !r.status.finally_deleted
                })
            {
                return Err(CoreError::NotAllowed);
            }
            e.created_at = current.created_at;
            e.deleted_at = current.deleted_at;
            e.modified_at = ctx.now();
            crate::edit::commit(
                ctx,
                vec![crate::edit::Change {
                    record: h.entry.record,
                    kind: RecordKind::Entry,
                    body: RecordBody::Live(Payload::Entry(e)),
                    ext: old.ext,
                }],
            )?;
            Ok(h.entry)
        })
    }

    /// Lists authenticated retained history, without exposing values.
    pub fn history(&self, entry: EntryHandle) -> Result<Vec<HistorySummary>, CoreError> {
        self.read(|ctx| {
            ctx.own(entry.session)?;
            let info = record(&ctx.open.index, entry.record, RecordKind::Entry)?;
            let compared = info.shown.ok_or(CoreError::NotFound)?;
            let current_version = ctx.open.vault.read_version(entry.record, compared)?;
            let current_ext = &current_version.ext;
            let current = match &current_version.body {
                RecordBody::Live(Payload::Entry(e)) => e,
                _ => return Err(CoreError::NotFound),
            };
            let versions: Vec<_> = ctx
                .open
                .vault
                .manifest()
                .record(entry.record)
                .ok_or(CoreError::NotFound)?
                .history()
                .iter()
                .map(|v| v.version_id())
                .collect();
            let initial = versions
                .len()
                .checked_mul(std::mem::size_of::<HistorySummary>())
                .ok_or(CoreError::LimitExceeded)?;
            if initial > crate::index::MAX_VIEW_BYTES {
                return Err(CoreError::LimitExceeded);
            }
            let mut out = Vec::with_capacity(versions.len());
            let mut budget = out.capacity() * std::mem::size_of::<HistorySummary>();
            for id in versions {
                ctx.check_cancel()?;
                let version = ctx.open.vault.read_version(entry.record, id)?;
                let version_id = version.version_id;
                let clock = version.clock.pairs().to_vec();
                let modified_at = version.modified_at;
                let historical = match &version.body {
                    RecordBody::Live(Payload::Entry(e)) => e,
                    _ => return Err(CoreError::NotFound),
                };
                let unknown_extensions_changed = !version.ext.content_eq(current_ext)
                    || !historical.ext.content_eq(&current.ext)
                    || historical.fields.iter().any(|f| {
                        current
                            .fields
                            .iter()
                            .find(|c| c.id == f.id)
                            .map_or(!f.ext.is_empty(), |c| !f.ext.content_eq(&c.ext))
                    })
                    || current.fields.iter().any(|f| {
                        !f.ext.is_empty() && !historical.fields.iter().any(|h| h.id == f.id)
                    });
                let required = historical
                    .fields
                    .iter()
                    .chain(current.fields.iter())
                    .try_fold(0usize, |n, f| {
                        n.checked_add(
                            f.name.expose().len() + std::mem::size_of::<(FieldId, Text)>(),
                        )
                    })
                    .ok_or(CoreError::LimitExceeded)?;
                if required > crate::index::MAX_VIEW_BYTES.saturating_sub(budget) {
                    return Err(CoreError::LimitExceeded);
                }
                let (changed_properties, changed_fields) = changed(historical, current)?;
                budget = budget
                    .checked_add(
                        changed_properties
                            .iter()
                            .map(|t| t.expose().len())
                            .sum::<usize>()
                            + changed_properties.capacity() * std::mem::size_of::<Text>()
                            + changed_fields
                                .iter()
                                .map(|(_, t)| t.expose().len())
                                .sum::<usize>()
                            + changed_fields.capacity() * std::mem::size_of::<(FieldId, Text)>()
                            + clock.len() * std::mem::size_of::<(WriterId, u64)>(),
                    )
                    .ok_or(CoreError::LimitExceeded)?;
                if budget > crate::index::MAX_VIEW_BYTES {
                    return Err(CoreError::LimitExceeded);
                }
                out.push(HistorySummary {
                    handle: HistoryHandle {
                        session: ctx.tag(),
                        entry,
                        version: version_id,
                    },
                    modified_at,
                    writers: clock,
                    conflict: info.status.conflict,
                    compared_to: compared,
                    changed_properties,
                    changed_fields,
                    unknown_extensions_changed,
                });
            }
            out.sort_by_key(|h| {
                (
                    core::cmp::Reverse(h.modified_at),
                    core::cmp::Reverse(h.handle.version),
                )
            });
            Ok(out)
        })
    }

    /// Reads one retained version for an explicit historical display.
    pub fn history_entry(&self, h: HistoryHandle) -> Result<crate::views::EntryDetail, CoreError> {
        self.read(|ctx| {
            let v = validate_history(ctx, h)?;
            let e = entry_payload(v)?;
            crate::views::entry_detail_for_history(ctx, h.entry, h.version, e)
        })
    }

    /// Purges retained history while preserving active heads and floors.
    pub fn purge_history(&self, entry: EntryHandle) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            ctx.own(entry.session)?;
            if ctx.open.read_only {
                return Err(qv_store::StoreError::NoAnchor.into());
            }
            let r = record(&ctx.open.index, entry.record, RecordKind::Entry)?;
            if r.status.finally_deleted {
                return Err(CoreError::NotFound);
            }
            let cancel = ctx.canceller();
            let seq = ctx.open.vault.local_seq();
            let mut w = ctx.open.vault.write()?;
            w.purge_history(entry.record)?;
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::BeforeCommit);
            cancel.check()?;
            let result = w.commit_cancellable(&|| cancel.check().is_err());
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::AfterCommit);
            if ctx.open.vault.local_seq() == seq && cancel.check().is_err() {
                return Err(CoreError::Cancelled);
            }
            result?;
            // A floor-only write changes no indexed heads, so the index already
            // matches even when the durable commit's anchor advancement fails.
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Env, err};
    use qv_model::{Extensions, Field, FieldKind};
    fn create(s: &Session) -> EntryHandle {
        let mut d = s.new_entry(s.root().unwrap(), "login", "History").unwrap();
        d.entry_mut().fields.push(Field {
            id: FieldId::generate().unwrap(),
            name: Text::new("password").unwrap(),
            kind: FieldKind::Secret,
            protected: true,
            value: FieldValue::text("old-secret").unwrap(),
            ext: Extensions::new(),
        });
        s.save_entry(d).unwrap()
    }
    fn edit(s: &Session, e: EntryHandle, n: usize) {
        let mut d = s.edit_entry(e).unwrap();
        d.entry_mut().title = Text::new(&format!("History-{n}")).unwrap();
        d.entry_mut().fields[0].value = FieldValue::text(&format!("secret-{n}")).unwrap();
        s.save_entry(d).unwrap();
    }
    #[test]
    fn history_retention_restore_purge_and_handle_capabilities() {
        let env = Env::new();
        let s = env.unlock();
        env.time.set(1_699_999_999_999);
        let e = create(&s);
        let original = s.entry(e).unwrap().version;
        for n in 0..14 {
            env.time.set(1_700_000_000_000 + n as i64);
            edit(&s, e, n);
        }
        let rows = s.history(e).unwrap();
        assert_eq!(rows.len(), 10);
        assert!(
            rows.windows(2)
                .all(|r| (r[0].modified_at, r[0].handle.version)
                    > (r[1].modified_at, r[1].handle.version))
        );
        assert!(!rows.iter().any(|r| r.handle.version == original));
        let h = rows[5].handle;
        let historical = s.history_entry(h).unwrap();
        let field = historical.fields[0].handle;
        assert!(historical.fields[0].value.is_none());
        assert_eq!(err(s.reveal(field)), CoreError::StaleHandle);
        let want = s.reveal_history(h, field.field_id()).unwrap();
        assert!(!want.expose_secret().is_empty());
        let before = s.entry(e).unwrap().version;
        s.restore_history(h, false).unwrap();
        let restored = s.entry(e).unwrap();
        assert_ne!(restored.version, before);
        assert_ne!(restored.version, h.version);
        assert_eq!(restored.title.expose(), historical.title.expose());
        assert_eq!(
            s.reveal(restored.fields[0].handle).unwrap().expose_secret(),
            want.expose_secret()
        );
        let current_clock = s
            .read(|ctx| {
                Ok(ctx
                    .open
                    .vault
                    .read_version(e.record, restored.version)?
                    .clock)
            })
            .unwrap();
        let seq = s.overview().unwrap().local_seq;
        s.purge_history(e).unwrap();
        assert_eq!(s.overview().unwrap().local_seq, seq + 1);
        assert!(s.history(e).unwrap().is_empty());
        assert_eq!(err(s.history_entry(h)), CoreError::StaleHandle);
        edit(&s, e, 99);
        assert!(
            s.history(e).unwrap().is_empty(),
            "purged current head must stay suppressed after an edit"
        );
        s.read(|ctx| {
            assert!(
                ctx.open
                    .vault
                    .manifest()
                    .record(e.record)
                    .unwrap()
                    .floor()
                    .suppresses(&current_clock)
            );
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn history_foreign_lock_and_unavailable_group_rejected() {
        let env = Env::new();
        let s = env.unlock();
        let e = create(&s);
        let group = s
            .save_group(s.new_group(s.root().unwrap(), "Old").unwrap())
            .unwrap();
        let mut d = s.edit_entry(e).unwrap();
        d.entry_mut().group = group.record;
        s.save_entry(d).unwrap();
        let mut d = s.edit_entry(e).unwrap();
        d.entry_mut().group = s.root().unwrap().record;
        s.save_entry(d).unwrap();
        let rows = s.history(e).unwrap();
        let h = rows
            .iter()
            .find(|r| s.history_entry(r.handle).unwrap().group == Some(group))
            .unwrap()
            .handle;
        s.delete(crate::ItemHandle::Group(group), false).unwrap();
        assert_eq!(err(s.restore_history(h, false)), CoreError::NotAllowed);
        s.lock();
        assert_eq!(err(s.history_entry(h)), CoreError::SessionLocked);
        let fresh = env.unlock();
        assert_eq!(err(fresh.history_entry(h)), CoreError::StaleHandle);
    }

    #[test]
    fn history_conflict_consent_purge_and_durable_anchor_failure() {
        let env = Env::new();
        let s = env.unlock();
        let e = create(&s);
        edit(&s, e, 1);
        let h = s.history(e).unwrap()[0].handle;
        s.mutate(|ctx| {
            let r = ctx.open.index.records.get_mut(&e.record).unwrap();
            r.status.conflict = true;
            r.heads.push(VersionId::generate().unwrap());
            Ok(())
        })
        .unwrap();
        assert!(s.history(e).unwrap()[0].conflict);
        let seq = s.overview().unwrap().local_seq;
        assert_eq!(err(s.restore_history(h, false)), CoreError::Conflict);
        assert_eq!(s.overview().unwrap().local_seq, seq);
        // This policy fixture alters the index only; actual multi-head floor
        // preservation is independently tested at the manifest layer.
        s.restore_history(h, true).unwrap();
        assert!(!s.entry_versions(e).unwrap().is_empty());
        let keep = s
            .add_attachment(e, "kept", "x", &mut &b"content"[..], None)
            .unwrap();
        let held = env.dir.path().join("held-anchors");
        std::fs::rename(&env.anchors, &held).unwrap();
        std::fs::write(&env.anchors, b"blocked").unwrap();
        let seq = s.overview().unwrap().local_seq;
        assert_eq!(
            err(s.purge_history(e)),
            CoreError::Store(qv_store::StoreError::Io)
        );
        assert_eq!(s.overview().unwrap().local_seq, seq + 1);
        assert!(s.history(e).unwrap().is_empty());
        s.verify_attachment(keep, None).unwrap();
        std::fs::remove_file(&env.anchors).unwrap();
        std::fs::rename(&held, &env.anchors).unwrap();
        s.lock();
        let s = env.unlock();
        let e = s.list(s.root().unwrap()).unwrap().entries[0].handle;
        assert!(s.history(e).unwrap().is_empty());
    }

    #[test]
    fn history_diff_order_variants_and_unknown_fields_restore() {
        let env = Env::new();
        let s = env.unlock();
        let e = create(&s);
        let raw = qv_encoding::RawValue::from_canonical(&[0x01]).unwrap();
        let mut enc = qv_encoding::Encoder::new();
        enc.map(|m| {
            m.raw_entry(100, &raw)?;
            Ok(())
        })
        .unwrap();
        let bytes = enc.finish().unwrap();
        // Build preserved optional extensions through the public model decoder
        // by splicing a canonical extra key into an otherwise valid record.
        s.mutate(|ctx| {
            let id = ctx.open.index.records[&e.record].shown.unwrap();
            let mut version = ctx.open.vault.read_version(e.record, id)?;
            let original = version.encode().unwrap();
            let mut extended = original.to_vec();
            assert_eq!(extended[0], 0xa6);
            extended[0] = 0xa7;
            extended.extend_from_slice(&bytes[1..]);
            version = RecordVersion::decode(&extended).unwrap();
            crate::edit::commit(
                ctx,
                vec![crate::edit::Change {
                    record: e.record,
                    kind: RecordKind::Entry,
                    body: version.body,
                    ext: version.ext,
                }],
            )
        })
        .unwrap();
        edit(&s, e, 3);
        let rows = s.history(e).unwrap();
        assert!(rows.iter().any(|r| r.unknown_extensions_changed));
        let selected = rows
            .iter()
            .find(|r| !r.unknown_extensions_changed)
            .unwrap()
            .handle;
        s.restore_history(selected, false).unwrap();
        s.read(|ctx| {
            let id = ctx.open.index.records[&e.record].shown.unwrap();
            assert_eq!(ctx.open.vault.read_version(e.record, id)?.ext.len(), 1);
            Ok(())
        })
        .unwrap();
        let a = s.edit_entry(e).unwrap();
        let mut b = s.edit_entry(e).unwrap();
        let f = &mut b.entry_mut().fields[0];
        let bytes = f.value.expose_secret().to_vec();
        f.value = FieldValue::bytes(&bytes).unwrap();
        let (_, differences) = changed(a.entry(), b.entry()).unwrap();
        assert_eq!(differences.len(), 1);
    }

    #[test]
    fn history_read_only_reads_but_refuses_restore_and_purge() {
        let env = Env::new();
        let s = env.unlock();
        let e = create(&s);
        edit(&s, e, 1);
        s.lock();
        for path in std::fs::read_dir(&env.anchors).unwrap() {
            std::fs::remove_file(path.unwrap().path()).unwrap();
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
        let h = s.history(e).unwrap()[0].handle;
        assert!(s.history_entry(h).is_ok());
        assert_eq!(
            err(s.restore_history(h, false)),
            CoreError::Store(qv_store::StoreError::NoAnchor)
        );
        assert_eq!(
            err(s.purge_history(e)),
            CoreError::Store(qv_store::StoreError::NoAnchor)
        );
    }
}
