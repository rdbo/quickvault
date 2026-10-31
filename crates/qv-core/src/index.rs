// SPDX-License-Identifier: AGPL-3.0-or-later

//! The metadata index (spec 0004 §5.1, 0008 §1.2, 0005 §2.3–2.5, 0003 §4).
//!
//! Built once after unlock from every record's decrypted heads, and updated
//! from the new head after each commit. Per record it keeps the kind, the
//! head version IDs, the merge status (live, trash, conflict, finally
//! deleted) and, from the representative version (live view, else trash
//! view), the **non-protected** metadata that listings and search need:
//! titles, names, type hints, icons, timestamps, and the values of
//! non-protected `text`, `url` and `email` fields. Protected values, notes
//! and other field kinds are never retained; they are decrypted on demand.
//! Every retained string is a zeroizing [`Text`], and the total is bounded
//! by a budget ([`MAX_VIEW_BYTES`]). Decrypted versions are dropped as soon
//! as their record is indexed.
//!
//! References inside authenticated data can still dangle (any VK holder can
//! author records): a missing group puts an entry under recovered items, a
//! missing attachment owner is ignored.

use std::collections::BTreeMap;

use qv_crypto::{GeneratorSettings, RecordId};
use qv_model::{
    FieldKind, FieldValue, GroupNode, GroupTree, Payload, RecordBody, RecordKind, RecordStatus,
    RecordVersion, Text, Timestamp, VersionId, View, merge_record, project_groups,
};
use qv_store::UnlockedVault;

use crate::error::{CoreError, data};

/// The most text the index retains (development value, frozen in 1.16).
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
}

pub(crate) struct GroupInfo {
    pub(crate) name: Text,
    pub(crate) icon: Option<Text>,
    pub(crate) order: Text,
    pub(crate) parent: Option<RecordId>,
    pub(crate) deleted_at: Option<Timestamp>,
}

pub(crate) struct MetaInfo {
    pub(crate) name: Text,
    pub(crate) retention_days: u32,
    pub(crate) generator: Option<GeneratorSettings>,
}

/// What the index keeps of a record's representative.
pub(crate) enum Data {
    Entry(EntryInfo),
    Group(GroupInfo),
    Meta(MetaInfo),
    Attachment {
        entry: RecordId,
    },
    /// Nothing to show (a keyslot, or only final tombstones).
    None,
}

pub(crate) struct RecordInfo {
    pub(crate) kind: RecordKind,
    /// Head version IDs, ascending.
    pub(crate) heads: Vec<VersionId>,
    pub(crate) status: RecordStatus,
    /// The representative's version ID.
    pub(crate) shown: Option<VersionId>,
    /// The latest timestamp in any head (clock-anomaly checks, overview).
    pub(crate) latest: Timestamp,
    pub(crate) node: Option<GroupNode>,
    pub(crate) data: Data,
    pub(crate) bytes: usize,
}

fn copy(t: &Text) -> Result<Text, CoreError> {
    Text::new(t.expose()).map_err(data)
}

fn opt_len(t: Option<&Text>) -> usize {
    t.map_or(0, |t| t.expose().len())
}

impl Data {
    fn bytes(&self) -> usize {
        match self {
            Self::Entry(e) => {
                e.title.expose().len()
                    + e.type_hint.expose().len()
                    + opt_len(e.icon.as_ref())
                    + e.fields
                        .iter()
                        .map(|f| f.name.expose().len() + f.value.expose().len())
                        .sum::<usize>()
            }
            Self::Group(g) => {
                g.name.expose().len() + opt_len(g.icon.as_ref()) + g.order.expose().len()
            }
            Self::Meta(m) => m.name.expose().len(),
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
fn extract(v: RecordVersion) -> Result<Data, CoreError> {
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
            Data::Entry(EntryInfo {
                title: e.title,
                type_hint: e.type_hint,
                icon: e.icon,
                group: e.group,
                fields,
                modified_at: e.modified_at,
                expires_at: e.expires_at,
                deleted_at: e.deleted_at,
            })
        }
        RecordBody::Live(Payload::Group(g)) => Data::Group(GroupInfo {
            name: g.name,
            icon: g.icon,
            order: g.order,
            parent: g.parent,
            deleted_at: g.deleted_at,
        }),
        RecordBody::Live(Payload::VaultMeta(m)) => Data::Meta(MetaInfo {
            retention_days: m.settings.trash_retention_days_or_default(),
            generator: m.settings.generator.map(|g| g.settings),
            name: m.name,
        }),
        RecordBody::Live(Payload::AttachmentMeta(a)) => Data::Attachment { entry: a.entry },
        RecordBody::Live(Payload::PasswordKeyslot(_)) | RecordBody::Tombstone(_) => Data::None,
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
        let (heads, _) = merged.into_parts();
        let data = match heads.into_iter().find(|v| Some(v.version_id) == shown) {
            Some(v) => extract(v)?,
            None => Data::None,
        };
        let bytes = data.bytes();
        Ok(RecordInfo {
            kind,
            heads: head_ids,
            status,
            shown,
            latest,
            node,
            data,
            bytes,
        })
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
    bytes: usize,
    budget: usize,
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
            bytes: 0,
            budget,
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
            let heads = rec
                .heads()
                .iter()
                .map(|h| read(rec.record_id(), h.version_id()))
                .collect::<Result<Vec<_>, _>>()?;
            let kind = heads.first().ok_or(CoreError::Internal)?.kind();
            index.insert(rec.record_id(), RecordInfo::from_heads(kind, heads)?)?;
        }
        index.retree()?;
        Ok(index)
    }

    /// The retained-text total after replacing `changes`.
    fn bytes_after<'a>(
        &self,
        changes: impl IntoIterator<Item = (RecordId, &'a RecordInfo)>,
    ) -> Result<usize, CoreError> {
        let mut total = self.bytes;
        for (id, info) in changes {
            let old = self.records.get(&id).map_or(0, |r| r.bytes);
            total = total
                .checked_sub(old)
                .and_then(|t| t.checked_add(info.bytes))
                .ok_or(CoreError::Internal)?;
        }
        if total > self.budget {
            return Err(CoreError::LimitExceeded);
        }
        Ok(total)
    }

    /// [`CoreError::LimitExceeded`] if replacing `changes` would exceed the
    /// budget.
    pub(crate) fn check<'a>(
        &self,
        changes: impl IntoIterator<Item = (RecordId, &'a RecordInfo)>,
    ) -> Result<(), CoreError> {
        self.bytes_after(changes).map(|_| ())
    }

    /// Inserts or replaces one record (without recomputing the tree).
    pub(crate) fn insert(&mut self, id: RecordId, info: RecordInfo) -> Result<(), CoreError> {
        self.bytes = self.bytes_after([(id, &info)])?;
        self.records.insert(id, info);
        Ok(())
    }

    /// Replaces one record after a commit whose changes already passed
    /// [`Self::check`] together.
    pub(crate) fn replace(&mut self, id: RecordId, info: RecordInfo) {
        let old = self.records.get(&id).map_or(0, |r| r.bytes);
        self.bytes = self.bytes.saturating_sub(old).saturating_add(info.bytes);
        self.records.insert(id, info);
    }

    /// Recomputes the display tree from the groups' nodes (0003 §4.1).
    pub(crate) fn retree(&mut self) -> Result<(), CoreError> {
        let nodes: BTreeMap<RecordId, GroupNode> = self
            .records
            .iter()
            .filter_map(|(id, r)| r.node.map(|n| (*id, n)))
            .collect();
        self.tree = project_groups(self.root, &nodes).map_err(data)?;
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
        self.bytes
    }

    /// A comparable summary of everything indexed (tests: a refreshed index
    /// must equal a rebuilt one).
    #[cfg(test)]
    pub(crate) fn summary(&self) -> Vec<String> {
        let mut out = vec![format!("{:?}", self.tree), format!("bytes {}", self.bytes)];
        for (id, r) in &self.records {
            let text = match &r.data {
                Data::Entry(e) => format!(
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
                Data::Group(g) => format!(
                    "group {} {} {:?} {:?}",
                    g.name.expose(),
                    g.order.expose(),
                    g.parent,
                    g.deleted_at
                ),
                Data::Meta(m) => format!("meta {} {}", m.name.expose(), m.retention_days),
                Data::Attachment { entry } => format!("attachment {entry:?}"),
                Data::None => "none".into(),
            };
            out.push(format!(
                "{id:?} {:?} {:?} {:?} {:?} {:?} {}",
                r.kind, r.heads, r.status, r.shown, r.node, text
            ));
        }
        out
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
        let Data::Entry(e) = &live.data else {
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
        // Replacing the record counts its old size out first.
        at.insert(e, one()).unwrap();
        let mut over = Index::new(root, meta, size - 1).unwrap();
        assert_eq!(over.insert(e, one()), Err(CoreError::LimitExceeded));
        assert!(over.records.is_empty());
        assert_eq!(at.check([(rid(), &one())]), Err(CoreError::LimitExceeded));
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
        assert_eq!(refreshed.summary(), rebuilt.summary());
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
