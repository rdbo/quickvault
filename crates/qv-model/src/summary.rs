// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compact authenticated-head summaries for bounded view construction (0003 §8).
//!
//! A summary keeps causal/structural metadata and a protected content digest,
//! never a title, field, note or payload. The ordinary merge algorithm therefore
//! runs without keeping every full conflicted head in plaintext simultaneously.

use qv_crypto::{ContentHasher, SecretArray};

use crate::{
    Clock, Deletion, Merged, ModelError, Payload, RecordBody, RecordId, RecordKind, RecordVersion,
    Timestamp, VersionId, Versioned, merge,
};

/// The causal and group-tree projection of one fully decoded record version.
/// It is not a substitute for authenticating and validating the source record.
pub struct HeadSummary {
    version: VersionId,
    clock: Clock,
    kind: RecordKind,
    deletion: Deletion,
    parent: Option<RecordId>,
    latest: Timestamp,
    content: SecretArray<32>,
}

crate::redacted_debug!(HeadSummary);

impl HeadSummary {
    /// Summarizes a validated version, binding its complete canonical content.
    /// The encoding scratch is wiped on return, including on error.
    pub fn from_version(version: &RecordVersion) -> Result<Self, ModelError> {
        let encoded = version.encode()?;
        let mut digest = ContentHasher::new();
        digest.update(&encoded);
        let mut latest = version.modified_at;
        let parent = match &version.body {
            RecordBody::Live(Payload::Entry(e)) => {
                latest = latest.max(e.created_at).max(e.modified_at);
                if let Some(deleted) = e.deleted_at {
                    latest = latest.max(deleted);
                }
                None
            }
            RecordBody::Live(Payload::Group(g)) => {
                if let Some(deleted) = g.deleted_at {
                    latest = latest.max(deleted);
                }
                g.parent
            }
            _ => None,
        };
        Ok(Self {
            version: version.version_id,
            clock: version.clock.clone(),
            kind: version.kind(),
            deletion: version.deletion(),
            parent,
            latest,
            content: digest.finalize(),
        })
    }

    /// The immutable record kind.
    pub fn kind(&self) -> RecordKind {
        self.kind
    }

    /// The latest timestamp in the original head, including payload timestamps.
    pub fn latest(&self) -> Timestamp {
        self.latest
    }

    /// The original group parent; absent for other kinds and tombstones.
    pub fn group_parent(&self) -> Option<RecordId> {
        self.parent
    }

    /// Whether a reread has the exact same canonical logical content.
    pub fn matches_version(&self, version: &RecordVersion) -> Result<bool, ModelError> {
        let other = Self::from_version(version)?;
        Ok(self.version == other.version && self.same_version(&other))
    }
}

impl Versioned for HeadSummary {
    fn version_id(&self) -> VersionId {
        self.version
    }
    fn clock(&self) -> &Clock {
        &self.clock
    }
    fn deletion(&self) -> Deletion {
        self.deletion
    }
    fn same_version(&self, other: &Self) -> bool {
        self.content.ct_eq(other.content.expose_secret())
    }
}

/// Merges compact summaries with the ordinary identity/clock/deletion rules.
/// Rejects mixed kinds exactly as [`crate::merge_record`] does.
pub fn merge_summaries(
    summaries: impl IntoIterator<Item = HeadSummary>,
) -> Result<Merged<HeadSummary>, ModelError> {
    let summaries: Vec<_> = summaries.into_iter().collect();
    if let Some(first) = summaries.first()
        && summaries.iter().any(|v| v.kind != first.kind)
    {
        return Err(ModelError::Integrity);
    }
    merge(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Extensions, Group, RandomId, Text, View, WriterId, merge_record};

    fn group(id: VersionId, writer: WriterId, count: u64, deleted: bool) -> RecordVersion {
        RecordVersion {
            version_id: id,
            clock: Clock::from_pairs(vec![(writer, count)]).unwrap(),
            modified_at: Timestamp(10),
            body: RecordBody::Live(Payload::Group(Group {
                parent: None,
                name: Text::new("confidential title").unwrap(),
                notes: Some(Text::new("confidential notes").unwrap()),
                icon: None,
                order: Text::new("n").unwrap(),
                deleted_at: deleted.then_some(Timestamp(20)),
                delete_operation: None,
                ext: Extensions::new(),
            })),
            ext: Extensions::new(),
        }
    }

    proptest::proptest! {
        // 0012 §1: Order-dependent merges
        #[test]
        fn generated_compact_projection_matches_full_merge(rows in proptest::collection::vec((0u64..8, 0u64..8, 0u8..3), 1..24)) {
            let writers = [WriterId::generate().unwrap(), WriterId::generate().unwrap()];
            let mut versions = Vec::new();
            for (a, b, deletion) in rows {
                let mut v = group(VersionId::generate().unwrap(), writers[0], 1, deletion == 1);
                let mut pairs = Vec::new();
                if a != 0 { pairs.push((writers[0], a)); }
                if b != 0 { pairs.push((writers[1], b)); }
                if pairs.is_empty() { pairs.push((writers[0], 1)); }
                pairs.sort_by_key(|(writer, _)| *writer);
                v.clock = Clock::from_pairs(pairs).unwrap();
                if deletion == 2 { v.body = RecordBody::Tombstone(RecordKind::Group); }
                versions.push(v);
            }
            let summaries = versions.iter().map(HeadSummary::from_version).collect::<Result<Vec<_>, _>>().unwrap();
            match (merge_summaries(summaries), merge_record(versions)) {
                (Ok(compact), Ok(full)) => {
                    proptest::prop_assert_eq!(compact.status(), full.status());
                    for view in [View::Live, View::Trash] {
                        proptest::prop_assert_eq!(compact.representative(view).map(Versioned::version_id), full.representative(view).map(Versioned::version_id));
                    }
                    proptest::prop_assert_eq!(compact.heads().iter().map(Versioned::version_id).collect::<Vec<_>>(), full.heads().iter().map(Versioned::version_id).collect::<Vec<_>>());
                }
                (Err(a), Err(b)) => proptest::prop_assert_eq!(a, b),
                _ => proptest::prop_assert!(false, "compact/full acceptance mismatch"),
            }
        }
    }

    // 0012 §1: Order-dependent merges
    #[test]
    fn summary_projection_matches_complete_merge_for_deletion_and_dominance() {
        let writers = [WriterId::generate().unwrap(), WriterId::generate().unwrap()];
        for deletion_mask in 0u8..16 {
            let mut versions = Vec::new();
            for i in 0..4 {
                let mut v = group(
                    VersionId::generate().unwrap(),
                    writers[i % 2],
                    (i / 2 + 1) as u64,
                    deletion_mask & (1 << i) != 0,
                );
                if deletion_mask == 15 && i % 2 == 0 {
                    v.body = RecordBody::Tombstone(RecordKind::Group);
                }
                versions.push(v);
            }
            let summaries = versions
                .iter()
                .map(HeadSummary::from_version)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let compact = merge_summaries(summaries).unwrap();
            let complete = merge_record(versions).unwrap();
            assert_eq!(compact.status(), complete.status());
            assert_eq!(
                compact
                    .heads()
                    .iter()
                    .map(Versioned::version_id)
                    .collect::<Vec<_>>(),
                complete
                    .heads()
                    .iter()
                    .map(Versioned::version_id)
                    .collect::<Vec<_>>()
            );
            for view in [View::Live, View::Trash] {
                assert_eq!(
                    compact.representative(view).map(Versioned::version_id),
                    complete.representative(view).map(Versioned::version_id)
                );
            }
        }
    }

    // 0012 §1: Order-dependent merges
    #[test]
    fn summary_identity_does_not_discard_confidential_payload_differences() {
        let mut v = group(
            VersionId::generate().unwrap(),
            WriterId::generate().unwrap(),
            1,
            false,
        );
        let original = HeadSummary::from_version(&v).unwrap();
        assert!(original.matches_version(&v).unwrap());
        let RecordBody::Live(Payload::Group(g)) = &mut v.body else {
            panic!("group")
        };
        g.notes = Some(Text::new("changed hidden content").unwrap());
        assert!(!original.matches_version(&v).unwrap());
        let changed = HeadSummary::from_version(&v).unwrap();
        assert_eq!(
            merge_summaries(vec![original, changed]).err(),
            Some(ModelError::Integrity)
        );
    }
}
