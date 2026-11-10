// SPDX-License-Identifier: AGPL-3.0-or-later

//! The metadata index (spec 0004 §5.1, 0008 §1.2, 0005 §2.3–2.5, 0003 §4).
//!
//! Structural metadata remains resident; representative text is loaded on demand
//! into an evictable, zeroizing cache. A valid record that cannot fit the cache
//! is read transiently. Protected values and notes never enter searchable views.
//! Conflict heads are summarized one at a time before selecting a representative.

use std::collections::BTreeMap;

use qv_crypto::{GeneratorSettings, RecordId};
use qv_model::{
    FieldKind, FieldValue, GroupNode, GroupTree, HeadSummary, Payload, RecordBody, RecordKind,
    RecordStatus, RecordVersion, Text, Timestamp, VersionId, Versioned, View, merge_record,
    merge_summaries, project_groups,
};
use qv_store::UnlockedVault;

use crate::error::{CoreError, data};
use crate::view_cache::{ViewCache, ViewRef};

/// Ceiling for owned cache, query, sort-key and cursor text (0004 §7).
pub(crate) const MAX_VIEW_BYTES: usize = 64 * 1024 * 1024;

/// A non-protected field value kept for listings and search.
pub(crate) struct FieldInfo {
    pub(crate) name: Text,
    pub(crate) kind: FieldKind,
    pub(crate) value: Text,
}

pub(crate) struct EntryInfo {
    pub(crate) title: Text,
    pub(crate) type_hint: Text,
    pub(crate) icon: Option<Text>,
    pub(crate) group: RecordId,
    pub(crate) fields: Vec<FieldInfo>,
    pub(crate) modified_at: Timestamp,
    pub(crate) expires_at: Option<Timestamp>,
    pub(crate) deleted_at: Option<Timestamp>,
    pub(crate) delete_operation: Option<qv_model::DeleteOperationId>,
}

pub(crate) struct GroupInfo {
    pub(crate) name: Text,
    pub(crate) icon: Option<Text>,
    pub(crate) order: Text,
    pub(crate) parent: Option<RecordId>,
    pub(crate) deleted_at: Option<Timestamp>,
    pub(crate) delete_operation: Option<qv_model::DeleteOperationId>,
}

pub(crate) struct MetaView {
    pub(crate) name: Text,
    pub(crate) retention_days: u32,
    pub(crate) generator: Option<GeneratorSettings>,
}

impl Drop for MetaView {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(GeneratorSettings::Characters(c)) = &mut self.generator {
            c.exclude_chars.zeroize();
        }
    }
}

/// What the index keeps of a record's representative.
pub(crate) enum ViewData {
    Entry(EntryInfo),
    Group(GroupInfo),
    Meta(MetaView),
    Attachment {
        entry: RecordId,
    },
    /// Nothing to show (a keyslot, or only final tombstones).
    None,
}

pub(crate) struct EntryMeta {
    pub(crate) group: RecordId,
    pub(crate) deleted_at: Option<Timestamp>,
    pub(crate) delete_operation: Option<qv_model::DeleteOperationId>,
}
pub(crate) struct GroupMeta {
    pub(crate) parent: Option<RecordId>,
    pub(crate) deleted_at: Option<Timestamp>,
    pub(crate) delete_operation: Option<qv_model::DeleteOperationId>,
}
pub(crate) struct MetaInfo {
    pub(crate) retention_days: u32,
}
/// Text-free structural projection; independent of cache residency.
pub(crate) enum Data {
    Entry(EntryMeta),
    Group(GroupMeta),
    Meta(MetaInfo),
    Attachment { entry: RecordId },
    None,
}
impl Data {
    fn of(view: &ViewData) -> Self {
        match view {
            ViewData::Entry(e) => Self::Entry(EntryMeta {
                group: e.group,
                deleted_at: e.deleted_at,
                delete_operation: e.delete_operation,
            }),
            ViewData::Group(g) => Self::Group(GroupMeta {
                parent: g.parent,
                deleted_at: g.deleted_at,
                delete_operation: g.delete_operation,
            }),
            ViewData::Meta(m) => Self::Meta(MetaInfo {
                retention_days: m.retention_days,
            }),
            ViewData::Attachment { entry } => Self::Attachment { entry: *entry },
            ViewData::None => Self::None,
        }
    }
}

pub(crate) struct RecordInfo {
    pub(crate) kind: RecordKind,
    /// Head version IDs, ascending.
    pub(crate) heads: Vec<VersionId>,
    pub(crate) payload_heads: usize,
    pub(crate) status: RecordStatus,
    /// The representative's version ID.
    pub(crate) shown: Option<VersionId>,
    /// The latest timestamp in any head (clock-anomaly checks, overview).
    pub(crate) latest: Timestamp,
    pub(crate) node: Option<GroupNode>,
    pub(crate) data: Data,
    #[cfg(test)]
    pub(crate) bytes: usize,
    pending: Option<ViewData>,
}

fn copy(t: &Text) -> Result<Text, CoreError> {
    Text::new(t.expose()).map_err(data)
}

fn opt_len(t: Option<&Text>) -> usize {
    t.map_or(0, Text::allocated_bytes)
}

impl ViewData {
    pub(crate) fn bytes(&self) -> usize {
        match self {
            Self::Entry(e) => {
                e.title.allocated_bytes()
                    + e.type_hint.allocated_bytes()
                    + opt_len(e.icon.as_ref())
                    + e.fields
                        .iter()
                        .map(|f| f.name.allocated_bytes() + f.value.allocated_bytes())
                        .sum::<usize>()
            }
            Self::Group(g) => {
                g.name.allocated_bytes() + opt_len(g.icon.as_ref()) + g.order.allocated_bytes()
            }
            Self::Meta(m) => {
                m.name.allocated_bytes()
                    + match &m.generator {
                        Some(GeneratorSettings::Characters(c)) => c.exclude_chars.capacity(),
                        _ => 0,
                    }
            }
            Self::Attachment { .. } | Self::None => 0,
        }
    }
}

/// Whether a field's value may be retained and searched: non-protected,
/// textual and of a kind that names or locates the entry.
fn searchable(protected: bool, kind: FieldKind) -> bool {
    !protected && matches!(kind, FieldKind::Text | FieldKind::Url | FieldKind::Email)
}

/// Moves what the index keeps out of a decrypted representative.
fn extract(v: RecordVersion) -> Result<ViewData, CoreError> {
    Ok(match v.body {
        RecordBody::Live(Payload::Entry(e)) => {
            let mut fields = Vec::new();
            for f in &e.fields {
                if let (true, FieldValue::Text(s)) = (searchable(f.protected, f.kind), &f.value) {
                    fields.push(FieldInfo {
                        name: copy(&f.name)?,
                        kind: f.kind,
                        value: Text::new(s.expose_secret()).map_err(data)?,
                    });
                }
            }
            ViewData::Entry(EntryInfo {
                title: e.title,
                type_hint: e.type_hint,
                icon: e.icon,
                group: e.group,
                fields,
                modified_at: e.modified_at,
                expires_at: e.expires_at,
                deleted_at: e.deleted_at,
                delete_operation: e.delete_operation,
            })
        }
        RecordBody::Live(Payload::Group(g)) => ViewData::Group(GroupInfo {
            name: g.name,
            icon: g.icon,
            order: g.order,
            parent: g.parent,
            deleted_at: g.deleted_at,
            delete_operation: g.delete_operation,
        }),
        RecordBody::Live(Payload::VaultMeta(m)) => ViewData::Meta(MetaView {
            retention_days: m.settings.trash_retention_days_or_default(),
            generator: m.settings.generator.map(|g| g.settings),
            name: m.name,
        }),
        RecordBody::Live(Payload::AttachmentMeta(a)) => ViewData::Attachment { entry: a.entry },
        RecordBody::Live(Payload::PasswordKeyslot(_)) | RecordBody::Tombstone(_) => ViewData::None,
    })
}

/// The latest timestamp a version carries.
fn latest(v: &RecordVersion) -> Timestamp {
    let mut t = v.modified_at;
    match &v.body {
        RecordBody::Live(Payload::Entry(e)) => {
            for x in [Some(e.created_at), Some(e.modified_at), e.deleted_at]
                .into_iter()
                .flatten()
            {
                t = t.max(x);
            }
        }
        RecordBody::Live(Payload::Group(g)) => {
            if let Some(d) = g.deleted_at {
                t = t.max(d);
            }
        }
        _ => {}
    }
    t
}

impl RecordInfo {
    /// Indexes one record from all of its heads, which must have `kind`.
    pub(crate) fn from_heads(
        kind: RecordKind,
        heads: Vec<RecordVersion>,
    ) -> Result<RecordInfo, CoreError> {
        if heads.is_empty() || heads.iter().any(|v| v.kind() != kind) {
            return Err(CoreError::Store(qv_store::StoreError::Integrity));
        }
        let latest = heads.iter().map(latest).max().unwrap_or(Timestamp(0));
        let merged = merge_record(heads).map_err(data)?;
        let status = merged.status();
        let node = if kind == RecordKind::Group {
            Some(GroupNode::from_merged(&merged).map_err(data)?)
        } else {
            None
        };
        let shown = merged
            .representative(View::Live)
            .or_else(|| merged.representative(View::Trash))
            .map(|v| v.version_id);
        let head_ids: Vec<VersionId> = merged.heads().iter().map(|v| v.version_id).collect();
        let heads_count = merged
            .heads()
            .iter()
            .filter(|v| v.deletion() != qv_model::Deletion::Final)
            .count();
        let (heads, _) = merged.into_parts();
        let data = match heads.into_iter().find(|v| Some(v.version_id) == shown) {
            Some(v) => extract(v)?,
            None => ViewData::None,
        };
        #[cfg(test)]
        let bytes = data.bytes();
        let structural = Data::of(&data);
        Ok(RecordInfo {
            kind,
            heads: head_ids,
            payload_heads: heads_count,
            status,
            shown,
            latest,
            node,
            data: structural,
            #[cfg(test)]
            bytes,
            pending: Some(data),
        })
    }

    /// Preflight retains only structural metadata, not every changed view.
    pub(crate) fn discard_view(&mut self) {
        self.pending = None;
    }

    /// The single head, or [`CoreError::Conflict`].
    pub(crate) fn single_head(&self) -> Result<VersionId, CoreError> {
        match self.heads.as_slice() {
            [v] => Ok(*v),
            _ => Err(CoreError::Conflict),
        }
    }
}

/// The whole index.
pub(crate) struct Index {
    pub(crate) root: RecordId,
    pub(crate) vault_meta: RecordId,
    pub(crate) records: BTreeMap<RecordId, RecordInfo>,
    pub(crate) tree: GroupTree,
    pub(crate) group_counts: BTreeMap<RecordId, usize>,
    pub(crate) recovered_count: usize,
    pub(crate) cache: ViewCache,
}

impl Index {
    pub(crate) fn new(
        root: RecordId,
        vault_meta: RecordId,
        budget: usize,
    ) -> Result<Index, CoreError> {
        Ok(Index {
            root,
            vault_meta,
            records: BTreeMap::new(),
            tree: project_groups(root, &BTreeMap::new()).map_err(data)?,
            group_counts: BTreeMap::new(),
            recovered_count: 0,
            cache: ViewCache::new(budget),
        })
    }

    /// Builds the index of a verified vault, decrypting every head once.
    /// `cancelled` is checked between records.
    pub(crate) fn build(
        vault: &UnlockedVault,
        cancelled: &dyn Fn() -> bool,
        budget: usize,
    ) -> Result<Index, CoreError> {
        Self::from_manifest(
            vault.manifest(),
            &mut |r, v| vault.read_version(r, v).map_err(Into::into),
            cancelled,
            budget,
        )
    }

    /// Preflight a complete candidate through authenticated, source-bound reads.
    pub(crate) fn from_manifest(
        manifest: &qv_store::Manifest,
        read: &mut impl FnMut(RecordId, VersionId) -> Result<RecordVersion, CoreError>,
        cancelled: &dyn Fn() -> bool,
        budget: usize,
    ) -> Result<Index, CoreError> {
        let mut index = Index::new(manifest.root_group_id(), manifest.vault_meta_id(), budget)?;
        for rec in manifest.records() {
            if cancelled() {
                return Err(CoreError::Cancelled);
            }
            let mut summaries = Vec::with_capacity(rec.heads().len());
            for head in rec.heads() {
                if cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let version = read(rec.record_id(), head.version_id())?;
                if version.version_id != head.version_id() {
                    return Err(CoreError::Store(qv_store::StoreError::Integrity));
                }
                summaries.push(HeadSummary::from_version(&version).map_err(data)?);
                // Only the compact projection survives this iteration.
            }
            let kind = summaries.first().ok_or(CoreError::Internal)?.kind();
            let latest = summaries
                .iter()
                .map(HeadSummary::latest)
                .max()
                .unwrap_or(Timestamp(0));
            let merged = merge_summaries(summaries).map_err(data)?;
            let status = merged.status();
            let shown = merged
                .representative(View::Live)
                .or_else(|| merged.representative(View::Trash));
            let node = (kind == RecordKind::Group).then(|| GroupNode {
                parent: shown.and_then(HeadSummary::group_parent),
                live: status.live,
            });
            let content = if let Some(summary) = shown {
                if cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let version = read(rec.record_id(), summary.version_id())?;
                if !summary.matches_version(&version).map_err(data)? {
                    return Err(CoreError::Store(qv_store::StoreError::Integrity));
                }
                extract(version)?
            } else {
                ViewData::None
            };
            let info = RecordInfo {
                kind,
                latest,
                status,
                node,
                shown: shown.map(Versioned::version_id),
                heads: merged.heads().iter().map(Versioned::version_id).collect(),
                payload_heads: merged
                    .heads()
                    .iter()
                    .filter(|v| v.deletion() != qv_model::Deletion::Final)
                    .count(),
                #[cfg(test)]
                bytes: content.bytes(),
                data: Data::of(&content),
                pending: Some(content),
            };
            index.insert(rec.record_id(), info)?;
        }
        index.retree()?;
        Ok(index)
    }

    /// Checks structural metadata; total text is never an eligibility limit.
    pub(crate) fn check<'a>(
        &self,
        changes: impl IntoIterator<Item = (RecordId, &'a RecordInfo)>,
    ) -> Result<(), CoreError> {
        for (_, info) in changes {
            if info.heads.is_empty() || info.heads.len() > qv_model::MAX_HEADS {
                return Err(CoreError::Store(qv_store::StoreError::Integrity));
            }
        }
        Ok(())
    }

    pub(crate) fn insert(&mut self, id: RecordId, info: RecordInfo) -> Result<(), CoreError> {
        self.check([(id, &info)])?;
        self.replace(id, info);
        Ok(())
    }

    pub(crate) fn replace(&mut self, id: RecordId, mut info: RecordInfo) {
        self.cache.invalidate(id);
        if let (Some(version), Some(view)) = (info.shown, info.pending.take()) {
            self.cache.put(id, version, view);
        }
        self.records.insert(id, info);
    }

    /// A verified representative view, either resident or bounded transient data.
    pub(crate) fn view(&self, vault: &UnlockedVault, id: RecordId) -> Result<ViewRef, CoreError> {
        let info = self.get(id).ok_or(CoreError::NotFound)?;
        let version = info.shown.ok_or(CoreError::NotFound)?;
        if let Some(view) = self.cache.get(id, version) {
            return Ok(view);
        }
        let record = vault.read_version(id, version)?;
        if record.version_id != version || record.kind() != info.kind {
            return Err(CoreError::Store(qv_store::StoreError::Integrity));
        }
        Ok(self.cache.put(id, version, extract(record)?))
    }

    /// Recomputes the display tree from the groups' nodes (0003 §4.1).
    pub(crate) fn retree(&mut self) -> Result<(), CoreError> {
        let nodes: BTreeMap<RecordId, GroupNode> = self
            .records
            .iter()
            .filter_map(|(id, r)| r.node.map(|n| (*id, n)))
            .collect();
        self.tree = project_groups(self.root, &nodes).map_err(data)?;
        let mut children: BTreeMap<RecordId, Vec<RecordId>> = BTreeMap::new();
        let mut counts: BTreeMap<RecordId, usize> = BTreeMap::new();
        let mut recovered = 0usize;
        for (&id, info) in &self.records {
            if info.kind == RecordKind::Group {
                if let Some(Some(parent)) = self.tree.parent(id) {
                    children.entry(parent).or_default().push(id);
                }
            } else if info.status.live
                && let Data::Entry(entry) = &info.data
            {
                match self.tree.place_entry(entry.group) {
                    qv_model::EntryPlace::Group(group) => *counts.entry(group).or_default() += 1,
                    qv_model::EntryPlace::Recovered => recovered += 1,
                }
            }
        }
        let mut pending = vec![(self.root, false)];
        while let Some((id, expanded)) = pending.pop() {
            if expanded {
                let mut total = counts.get(&id).copied().unwrap_or(0);
                for child in children.get(&id).into_iter().flatten() {
                    total = total
                        .checked_add(counts.get(child).copied().unwrap_or(0))
                        .ok_or(CoreError::Internal)?;
                }
                counts.insert(id, total);
            } else {
                pending.push((id, true));
                pending.extend(
                    children
                        .get(&id)
                        .into_iter()
                        .flatten()
                        .map(|id| (*id, false)),
                );
            }
        }
        self.group_counts = counts;
        self.recovered_count = recovered;
        Ok(())
    }

    pub(crate) fn get(&self, id: RecordId) -> Option<&RecordInfo> {
        self.records.get(&id)
    }

    /// The vault metadata's indexed part.
    pub(crate) fn meta(&self) -> Option<&MetaInfo> {
        match self.records.get(&self.vault_meta).map(|r| &r.data) {
            Some(Data::Meta(m)) => Some(m),
            _ => None,
        }
    }

    /// Retained text in bytes.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.cache.bytes()
    }

    /// A comparable summary of everything indexed (tests: a refreshed index
    /// must equal a rebuilt one).
    #[cfg(test)]
    pub(crate) fn summary(&self, vault: Option<&UnlockedVault>) -> Result<Vec<String>, CoreError> {
        let mut out = vec![
            format!(
                "{:?} {:?} recovered {}",
                self.tree, self.group_counts, self.recovered_count
            ),
            "logical bytes pending".to_owned(),
        ];
        let mut logical_bytes = 0;
        for (id, r) in &self.records {
            let view = if r.shown.is_some() {
                match vault {
                    Some(vault) => Some(self.view(vault, *id)?),
                    None => r.shown.and_then(|version| self.cache.get(*id, version)),
                }
            } else {
                None
            };
            if let Some(view) = &view {
                logical_bytes += view.bytes();
            }
            let text = match view.as_deref().map(|v| &**v) {
                Some(ViewData::Entry(e)) => format!(
                    "entry {} {} {:?} {:?} {:?} {:?}",
                    e.title.expose(),
                    e.type_hint.expose(),
                    e.group,
                    e.deleted_at,
                    e.modified_at,
                    e.fields
                        .iter()
                        .map(|f| format!("{}={}", f.name.expose(), f.value.expose()))
                        .collect::<Vec<_>>()
                ),
                Some(ViewData::Group(g)) => format!(
                    "group {} {} {:?} {:?}",
                    g.name.expose(),
                    g.order.expose(),
                    g.parent,
                    g.deleted_at
                ),
                Some(ViewData::Meta(m)) => format!("meta {} {}", m.name.expose(), m.retention_days),
                Some(ViewData::Attachment { entry }) => format!("attachment {entry:?}"),
                Some(ViewData::None) | None => "none".into(),
            };
            out.push(format!(
                "{id:?} {:?} {:?} {:?} {:?} {:?} {}",
                r.kind, r.heads, r.status, r.shown, r.node, text
            ));
        }
        out[1] = format!("logical bytes {logical_bytes}");
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use qv_model::{
        Clock, Entry, Extensions, Field, FieldId, FieldKind, FieldValue, Group, Payload, RandomId,
        RecordBody, RecordKind, RecordVersion, Text, Timestamp, VersionId, WriterId,
    };

    use super::*;
    use crate::testutil::Env;

    pub(crate) fn rid() -> RecordId {
        RecordId::generate().unwrap()
    }

    pub(crate) fn version(clock: &[(WriterId, u64)], body: RecordBody) -> RecordVersion {
        RecordVersion {
            version_id: VersionId::generate().unwrap(),
            clock: Clock::from_pairs(clock.to_vec()).unwrap(),
            modified_at: Timestamp(10),
            body,
            ext: Extensions::new(),
        }
    }

    fn field(name: &str, kind: FieldKind, value: &str, protected: bool) -> Field {
        Field {
            id: FieldId::generate().unwrap(),
            name: Text::new(name).unwrap(),
            kind,
            value: FieldValue::text(value).unwrap(),
            protected,
            ext: Extensions::new(),
        }
    }

    pub(crate) fn entry(group: RecordId, title: &str, deleted: bool) -> RecordBody {
        RecordBody::Live(Payload::Entry(Entry {
            group,
            type_hint: Text::new("login").unwrap(),
            title: Text::new(title).unwrap(),
            fields: vec![
                field("Username", FieldKind::Text, "alice", false),
                field("Password", FieldKind::Secret, "hunter2", true),
                field("Site", FieldKind::Url, "https://example.org", false),
                field("PIN", FieldKind::Text, "4321", true),
                field("Memo", FieldKind::Multiline, "memo text", false),
            ],
            notes: Some(Text::new("private notes").unwrap()),
            icon: None,
            expires_at: None,
            created_at: Timestamp(1),
            modified_at: Timestamp(2),
            deleted_at: deleted.then_some(Timestamp(5)),
            delete_operation: None,
            ext: Extensions::new(),
        }))
    }

    pub(crate) fn group(parent: Option<RecordId>, name: &str) -> RecordBody {
        RecordBody::Live(Payload::Group(Group {
            parent,
            name: Text::new(name).unwrap(),
            notes: None,
            icon: None,
            order: Text::new("n").unwrap(),
            deleted_at: None,
            delete_operation: None,
            ext: Extensions::new(),
        }))
    }

    fn info(kind: RecordKind, heads: Vec<RecordVersion>) -> RecordInfo {
        RecordInfo::from_heads(kind, heads).unwrap()
    }

    #[test]
    fn index_record_states() {
        let (w1, w2) = (WriterId::generate().unwrap(), WriterId::generate().unwrap());
        let root = rid();
        // Live: only non-protected text, URL and e-mail values are kept.
        let live = info(
            RecordKind::Entry,
            vec![version(&[(w1, 1)], entry(root, "Bank", false))],
        );
        assert!(live.status.live && !live.status.in_trash && !live.status.conflict);
        let Some(ViewData::Entry(e)) = &live.pending else {
            panic!("not an entry")
        };
        let kept: Vec<_> = e
            .fields
            .iter()
            .map(|f| f.value.expose().to_owned())
            .collect();
        assert_eq!(kept, ["alice", "https://example.org"]);
        assert_eq!(
            live.bytes,
            "Bank".len() + "login".len() + "Usernamealice".len() + "Sitehttps://example.org".len()
        );

        // Soft-deleted: in the trash.
        let trashed = info(
            RecordKind::Entry,
            vec![version(&[(w1, 1)], entry(root, "Old", true))],
        );
        assert!(trashed.status.in_trash && !trashed.status.live);

        // Final tombstone: hidden, nothing kept.
        let gone = info(
            RecordKind::Entry,
            vec![version(
                &[(w1, 2)],
                RecordBody::Tombstone(RecordKind::Entry),
            )],
        );
        assert!(gone.status.finally_deleted);
        assert!(matches!(gone.data, Data::None));

        // Two concurrent live heads: a conflict shown by the largest version ID.
        let a = version(&[(w1, 1)], entry(root, "A", false));
        let b = version(&[(w2, 1)], entry(root, "B", false));
        let larger = a.version_id.max(b.version_id);
        let c = info(RecordKind::Entry, vec![a, b]);
        assert!(c.status.conflict);
        assert_eq!(c.shown, Some(larger));
        assert!(matches!(c.single_head(), Err(CoreError::Conflict)));

        // A delete/edit race: live, in the trash and in conflict.
        let race = info(
            RecordKind::Entry,
            vec![
                version(&[(w1, 3)], entry(root, "Edited", false)),
                version(&[(w2, 3)], entry(root, "Deleted", true)),
            ],
        );
        assert!(race.status.live && race.status.in_trash && race.status.conflict);

        // Heads of another kind are an integrity failure.
        assert_eq!(
            RecordInfo::from_heads(
                RecordKind::Group,
                vec![version(&[(w1, 1)], entry(root, "x", false))]
            )
            .map(|_| ())
            .unwrap_err(),
            CoreError::Store(qv_store::StoreError::Integrity)
        );
    }

    #[test]
    fn index_tree_repair_and_recovered_entries() {
        let w = WriterId::generate().unwrap();
        let (root, meta) = (rid(), rid());
        let (g1, g2, g3, missing) = (rid(), rid(), rid(), rid());
        let mut index = Index::new(root, meta, MAX_VIEW_BYTES).unwrap();
        index
            .insert(
                root,
                info(
                    RecordKind::Group,
                    vec![version(&[(w, 1)], group(None, "Root"))],
                ),
            )
            .unwrap();
        // g1 and g2 form a cycle; g3's parent does not exist.
        index
            .insert(
                g1,
                info(
                    RecordKind::Group,
                    vec![version(&[(w, 2)], group(Some(g2), "One"))],
                ),
            )
            .unwrap();
        index
            .insert(
                g2,
                info(
                    RecordKind::Group,
                    vec![version(&[(w, 3)], group(Some(g1), "Two"))],
                ),
            )
            .unwrap();
        index
            .insert(
                g3,
                info(
                    RecordKind::Group,
                    vec![version(&[(w, 4)], group(Some(missing), "Three"))],
                ),
            )
            .unwrap();
        index.retree().unwrap();
        let smaller = g1.min(g2);
        assert_eq!(index.tree.parent(smaller), Some(Some(root)));
        assert!(index.tree.is_repaired(smaller));
        assert_eq!(index.tree.parent(g3), Some(Some(root)));
        assert!(index.tree.is_repaired(g3));
        assert_eq!(
            index.tree.place_entry(missing),
            qv_model::EntryPlace::Recovered
        );
        assert_eq!(index.tree.place_entry(g3), qv_model::EntryPlace::Group(g3));
    }

    #[test]
    fn index_budget() {
        let w = WriterId::generate().unwrap();
        let (root, meta, e) = (rid(), rid(), rid());
        let one = || {
            info(
                RecordKind::Entry,
                vec![version(&[(w, 1)], entry(root, "Bank", false))],
            )
        };
        let size = one().bytes;
        let mut at = Index::new(root, meta, size).unwrap();
        at.insert(e, one()).unwrap();
        assert_eq!(at.bytes(), size);
        // Replacement invalidates old residency; uncachable rows remain structural.
        at.insert(e, one()).unwrap();
        let mut over = Index::new(root, meta, size - 1).unwrap();
        over.insert(e, one()).unwrap();
        assert_eq!(over.records.len(), 1);
        assert_eq!(over.bytes(), 0);
        assert!(at.check([(rid(), &one())]).is_ok());
        let another = rid();
        at.insert(another, one()).unwrap();
        assert_eq!(at.records.len(), 2);
        assert!(at.bytes() <= size);
    }

    #[test]
    fn index_refresh_equals_rebuild() {
        let w = WriterId::generate().unwrap();
        let (root, meta, g, e) = (rid(), rid(), rid(), rid());
        let enc = |v: RecordVersion| v.encode().unwrap();
        let dec = |b: &[u8]| vec![RecordVersion::decode(b).unwrap()];
        let root_v = enc(version(&[(w, 1)], group(None, "Root")));
        let g_v = enc(version(&[(w, 2)], group(Some(root), "G")));
        let before = enc(version(&[(w, 3)], entry(g, "Before", false)));
        let after = enc(version(
            &[(w, 4)],
            entry(g, "After, with a longer title", false),
        ));
        let build = |entry_v: &[u8]| {
            let mut index = Index::new(root, meta, MAX_VIEW_BYTES).unwrap();
            index
                .insert(root, info(RecordKind::Group, dec(&root_v)))
                .unwrap();
            index.insert(g, info(RecordKind::Group, dec(&g_v))).unwrap();
            index
                .insert(e, info(RecordKind::Entry, dec(entry_v)))
                .unwrap();
            index.retree().unwrap();
            index
        };
        let mut refreshed = build(&before);
        refreshed.replace(e, info(RecordKind::Entry, dec(&after)));
        refreshed.retree().unwrap();
        let rebuilt = build(&after);
        assert_eq!(
            refreshed.summary(None).unwrap(),
            rebuilt.summary(None).unwrap()
        );
        assert_eq!(refreshed.bytes(), rebuilt.bytes());
    }

    #[test]
    fn index_build_is_cancellable() {
        let env = Env::new();
        let s = env.unlock();
        let r = s.read(|ctx| Index::build(&ctx.open.vault, &|| true, MAX_VIEW_BYTES).map(|_| ()));
        assert_eq!(r, Err(CoreError::Cancelled));
        let ok = s.read(|ctx| {
            Index::build(&ctx.open.vault, &|| false, MAX_VIEW_BYTES).map(|i| i.records.len())
        });
        assert_eq!(ok, Ok(3));
    }
}
