// SPDX-License-Identifier: AGPL-3.0-or-later

//! All-kind conflict capabilities and deliberate complete-version resolution.

use crate::edit::{Change, commit_with};
use crate::session::{Ctx, SessionTag};
use crate::{CancelToken, CoreError, EntryDetail, MasterPassword, Session, Text};
use qv_crypto::RecordId;
use qv_model::RandomId;
use qv_model::{
    Deletion, Extensions, Group, Payload, RecordBody, RecordKind, RecordVersion, Timestamp,
    VaultMeta, VersionId, WriterId,
};

/// One record in an unlocked session, including non-browsable control records.
#[derive(Clone, Copy)]
pub struct ConflictRecordHandle {
    session: SessionTag,
    record: RecordId,
}
impl ConflictRecordHandle {
    /// Full record ID for explicit addressing.
    pub fn id_hex(&self) -> String {
        crate::setup::hex(&self.record.0)
    }
}
/// A selected head together with the complete head set the caller inspected.
#[derive(Clone)]
pub struct ConflictVersionHandle {
    record: ConflictRecordHandle,
    version: VersionId,
    heads: Vec<VersionId>,
}
impl ConflictVersionHandle {
    /// Full version ID for an explicit complete-version choice.
    pub fn version_hex(&self) -> String {
        crate::setup::hex(&self.version.to_bytes())
    }
}
/// Metadata-only listing row; no decrypted payloads are retained.
pub struct ConflictRecord {
    /// Session capability.
    pub handle: ConflictRecordHandle,
    /// The immutable record kind.
    pub kind: RecordKind,
    /// Number of active versions.
    pub versions: usize,
}
/// One masked typed view, bounded by a single record's existing limits.
pub struct ConflictVersion {
    /// The selected version's timestamp (display, not causality).
    pub modified_at: Timestamp,
    /// Complete causal vector.
    pub clock: Vec<(WriterId, u64)>,
    /// Live, soft-deleted or permanent tombstone.
    pub state: Deletion,
    /// Unknown optional data is preserved on resolution, never dumped.
    pub unknown_extensions: bool,
    /// Safe per-kind contents; protected entry fields need explicit reveal.
    pub details: ConflictDetails,
}
/// Safe per-kind data. Keyslot wrapping material never reaches a frontend.
pub enum ConflictDetails {
    /// Entry metadata and masked fields; existing field handles allow reveal.
    Entry {
        /// Known entry metadata and masked protected fields.
        detail: Box<EntryDetail>,
        /// Stored group ID before display repair/projection.
        group: RecordId,
    },
    /// Group metadata, with confidential text in protected model containers.
    Group(Box<Group>),
    /// Vault metadata/settings, with protected model containers.
    VaultMeta(Box<VaultMeta>),
    /// Attachment metadata; content/hash and raw chunk IDs are excluded.
    Attachment {
        /// Stored owning entry.
        entry: RecordId,
        /// Untrusted attachment name.
        name: Text,
        /// Declared MIME type, never executed/sniffed.
        mime: Text,
        /// Verified content length.
        size: u64,
        /// Number of encrypted chunks.
        chunks: usize,
    },
    /// Only public selection metadata, even on an explicit reveal.
    PasswordSlot {
        /// Slot identity as hexadecimal metadata.
        slot_id: String,
        /// Pinned password KDF profile ID.
        kdf_profile: u16,
        /// Pinned password wrapping profile ID.
        wrap_profile: u16,
    },
    /// A permanent deletion, with no payload.
    Tombstone(RecordKind),
}
/// Actual durable local resolution, independently of completion errors.
pub struct ResolutionReport {
    /// Remaining conflicts across all record kinds.
    pub conflicts: usize,
    /// Failure after durable publication; the edit must still be reported.
    pub completion_error: Option<CoreError>,
}
macro_rules! redacted {
    ($($t:ty),+) => {$(impl core::fmt::Debug for $t {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str(concat!(stringify!($t), "(<redacted>)"))
        }
    })+};
}
redacted!(
    ConflictRecordHandle,
    ConflictVersionHandle,
    ConflictRecord,
    ConflictVersion,
    ConflictDetails,
    ResolutionReport
);

fn selected(ctx: &Ctx<'_>, h: &ConflictVersionHandle) -> Result<RecordVersion, CoreError> {
    ctx.own(h.record.session)?;
    let r = ctx
        .open
        .index
        .get(h.record.record)
        .ok_or(CoreError::NotFound)?;
    if r.heads != h.heads || !r.heads.contains(&h.version) {
        return Err(CoreError::StaleHandle);
    }
    Ok(ctx.open.vault.read_version(h.record.record, h.version)?)
}
fn unknown(v: &RecordVersion) -> bool {
    !v.ext.is_empty()
        || match &v.body {
            RecordBody::Tombstone(_) => false,
            RecordBody::Live(Payload::Entry(e)) => {
                !e.ext.is_empty() || e.fields.iter().any(|f| !f.ext.is_empty())
            }
            RecordBody::Live(Payload::Group(g)) => !g.ext.is_empty(),
            RecordBody::Live(Payload::VaultMeta(m)) => {
                !m.ext.is_empty()
                    || !m.settings.ext.is_empty()
                    || m.settings
                        .generator
                        .as_ref()
                        .is_some_and(|g| !g.ext.is_empty())
            }
            RecordBody::Live(Payload::AttachmentMeta(a)) => !a.ext.is_empty(),
            RecordBody::Live(Payload::PasswordKeyslot(s)) => !s.ext.is_empty(),
        }
}
impl Session {
    /// List every conflicting record kind without collecting plaintext versions.
    pub fn conflict_records(&self) -> Result<Vec<ConflictRecord>, CoreError> {
        self.read(|ctx| {
            Ok(ctx
                .open
                .index
                .records
                .iter()
                .filter(|(_, r)| r.status.conflict)
                .map(|(id, r)| ConflictRecord {
                    handle: ConflictRecordHandle {
                        session: ctx.tag(),
                        record: *id,
                    },
                    kind: r.kind,
                    versions: r.heads.len(),
                })
                .collect())
        })
    }
    /// Match an explicit record prefix, including trash/control/attachment IDs.
    pub fn conflict_matches(&self, prefix: &str) -> Result<Vec<ConflictRecordHandle>, CoreError> {
        let prefix = prefix.strip_prefix('@').unwrap_or(prefix);
        if !(6..=32).contains(&prefix.len()) || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidInput);
        }
        let prefix = prefix.to_ascii_lowercase();
        self.read(|ctx| {
            Ok(ctx
                .open
                .index
                .records
                .keys()
                .filter_map(|id| {
                    let h = ConflictRecordHandle {
                        session: ctx.tag(),
                        record: *id,
                    };
                    h.id_hex().starts_with(&prefix).then_some(h)
                })
                .collect())
        })
    }
    /// Handles only: decrypt/emit each version separately to bound total memory.
    pub fn conflict_versions(
        &self,
        record: ConflictRecordHandle,
    ) -> Result<Vec<ConflictVersionHandle>, CoreError> {
        self.read(|ctx| {
            ctx.own(record.session)?;
            let r = ctx
                .open
                .index
                .get(record.record)
                .ok_or(CoreError::NotFound)?;
            Ok(r.heads
                .iter()
                .map(|v| ConflictVersionHandle {
                    record,
                    version: *v,
                    heads: r.heads.clone(),
                })
                .collect())
        })
    }
    /// One complete known view, masked by default and discarded on a lock race.
    pub fn conflict_version(
        &self,
        h: &ConflictVersionHandle,
    ) -> Result<ConflictVersion, CoreError> {
        self.read(|ctx| {
            let v = selected(ctx, h)?;
            let unknown_extensions = unknown(&v);
            let state = v.deletion();
            let details = match v.body {
                RecordBody::Tombstone(k) => ConflictDetails::Tombstone(k),
                RecordBody::Live(Payload::Entry(e)) => {
                    let group = e.group;
                    ConflictDetails::Entry {
                        group,
                        detail: Box::new(crate::views::entry_detail_for_history(
                            ctx,
                            ctx.entry_handle(h.record.record),
                            h.version,
                            e,
                        )?),
                    }
                }
                RecordBody::Live(Payload::Group(g)) => ConflictDetails::Group(Box::new(g)),
                RecordBody::Live(Payload::VaultMeta(m)) => ConflictDetails::VaultMeta(Box::new(m)),
                RecordBody::Live(Payload::AttachmentMeta(a)) => ConflictDetails::Attachment {
                    entry: a.entry,
                    name: Text::new(a.name.expose()).map_err(crate::error::data)?,
                    mime: Text::new(a.mime.expose()).map_err(crate::error::data)?,
                    size: a.size,
                    chunks: a.chunk_object_ids.len(),
                },
                RecordBody::Live(Payload::PasswordKeyslot(s)) => ConflictDetails::PasswordSlot {
                    slot_id: crate::setup::hex(&s.slot.slot_id.0),
                    kdf_profile: s.slot.kdf_profile.id(),
                    wrap_profile: s.slot.wrap_profile.id(),
                },
            };
            Ok(ConflictVersion {
                modified_at: v.modified_at,
                clock: v.clock.pairs().to_vec(),
                state,
                unknown_extensions,
                details,
            })
        })
    }
    /// Create one deliberate causal edit from a complete inspected active version.
    /// Password slots require that selected slot's password, even if already working.
    pub fn resolve_version(
        &self,
        h: &ConflictVersionHandle,
        password: Option<&MasterPassword>,
        cancel: Option<&CancelToken>,
    ) -> Result<ResolutionReport, CoreError> {
        self.mutate(|ctx| {
            let c = ctx.canceller();
            let cancelled = || c.is_cancelled() || cancel.is_some_and(CancelToken::is_cancelled);
            if cancelled() {
                return Err(CoreError::Cancelled);
            }
            let mut v = selected(ctx, h)?;
            let id = h.record.record;
            let kind = v.kind();
            if (kind == RecordKind::PasswordKeyslot) != password.is_some() {
                return Err(CoreError::InvalidInput);
            }
            if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
                e.modified_at = ctx.now();
            }
            let mut changes = Vec::new();
            if matches!(v.body, RecordBody::Tombstone(RecordKind::Entry)) {
                for (attachment, info) in &ctx.open.index.records {
                    if info.kind != RecordKind::AttachmentMeta {
                        continue;
                    }
                    let mut owned = false;
                    for version in &info.heads {
                        if let RecordBody::Live(Payload::AttachmentMeta(meta)) =
                            ctx.open.vault.read_version(*attachment, *version)?.body
                        {
                            owned |= meta.entry == id;
                        }
                    }
                    if owned {
                        info.single_head()?;
                        changes.push(Change {
                            record: *attachment,
                            kind: RecordKind::AttachmentMeta,
                            body: RecordBody::Tombstone(RecordKind::AttachmentMeta),
                            ext: Extensions::new(),
                        });
                    }
                }
            }
            if let RecordBody::Live(Payload::AttachmentMeta(meta)) = &v.body {
                let owner = ctx
                    .open
                    .index
                    .get(meta.entry)
                    .ok_or(CoreError::NotAllowed)?;
                if owner.kind != RecordKind::Entry || owner.status.finally_deleted {
                    return Err(CoreError::NotAllowed);
                }
            }
            if v.deletion() == Deletion::Final {
                v.ext = Extensions::new();
            }
            let seq = ctx.open.vault.local_seq();
            let result = commit_with(
                ctx,
                |w| {
                    if let Some(password) = password {
                        w.stage_selected_password(h.version, password)?;
                    }
                    if let RecordBody::Live(Payload::AttachmentMeta(mut meta)) = v.body {
                        let staged = w.restage_attachment(id, h.version, &cancelled)?;
                        let mut copied = staged.into_meta(
                            meta.entry,
                            Text::new(meta.name.expose()).map_err(crate::error::data)?,
                            Text::new(meta.mime.expose()).map_err(crate::error::data)?,
                        );
                        copied.ext = core::mem::take(&mut meta.ext);
                        v.body = RecordBody::Live(Payload::AttachmentMeta(copied));
                    }
                    changes.push(Change {
                        record: id,
                        kind,
                        body: v.body,
                        ext: v.ext,
                    });
                    Ok(changes)
                },
                &cancelled,
            );
            if ctx.open.vault.local_seq() == seq {
                return Err(result.err().unwrap_or(CoreError::Internal));
            }
            Ok(ResolutionReport {
                completion_error: result.err(),
                conflicts: ctx
                    .open
                    .index
                    .records
                    .values()
                    .filter(|r| r.status.conflict)
                    .count(),
            })
        })
    }
}

#[cfg(test)]
#[path = "conflict_tests.rs"]
mod tests;
