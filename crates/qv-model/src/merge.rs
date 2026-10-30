// SPDX-License-Identifier: AGPL-3.0-or-later

//! The maximal-version merge (spec 0005 §2) and history floors (0007 §1.2).
//!
//! [`merge`] takes every known version of one record, from any number of
//! sources, and returns the **heads**: the versions no other version strictly
//! dominates. Everything else is **dominated** and becomes history under
//! 0007. The merge is pure: it never creates, re-encrypts or re-dates a
//! version, so union followed by removal of dominated versions is
//! commutative, associative and idempotent (0005 §2.2). Dates play no part
//! (0005 §1.5).
//!
//! Identity checks (0005 §1.4): the same version ID with different content,
//! or equal clocks under different version IDs, are [`ModelError::Integrity`].
//! More than [`MAX_HEADS`] heads is [`ModelError::LimitExceeded`]; the merge
//! then returns nothing, so the caller keeps its accepted state.
//!
//! **Deletion visibility** (0005 §2.3, §2.5; plan 0007). The *live*
//! representative is the largest version ID among live heads. The *trash*
//! representative is the largest among soft-deleted heads or, when the record
//! is in trash only because a final tombstone is concurrent with a live head,
//! the largest live head (a tombstone has nothing to show). A record is in
//! trash if any head is soft-deleted, or if a final tombstone is concurrent
//! with a non-final head. Nothing is dropped: every head stays available.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};

use crate::clock::{Causality, Clock};
use crate::error::ModelError;
use crate::ids::VersionId;
use crate::record::{Deletion, RecordVersion};

/// The most concurrent heads of one record (0004 §4.1).
pub const MAX_HEADS: usize = 256;

/// A version as the merge sees it.
pub trait Versioned {
    /// The version's ID.
    fn version_id(&self) -> VersionId;
    /// Its clock.
    fn clock(&self) -> &Clock;
    /// Its deletion state.
    fn deletion(&self) -> Deletion;
    /// Whether `other` (with the same version ID) is the same logical
    /// version. Anything else is an integrity error.
    fn same_version(&self, other: &Self) -> bool;
}

impl Versioned for RecordVersion {
    fn version_id(&self) -> VersionId {
        self.version_id
    }

    fn clock(&self) -> &Clock {
        &self.clock
    }

    fn deletion(&self) -> Deletion {
        RecordVersion::deletion(self)
    }

    /// Identical canonical encodings. An encoding failure counts as
    /// different, so it fails closed as an integrity error.
    fn same_version(&self, other: &Self) -> bool {
        match (self.encode(), other.encode()) {
            (Ok(a), Ok(b)) => a.as_slice() == b.as_slice(),
            _ => false,
        }
    }
}

/// Which view a representative is chosen for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    /// Normal browsing.
    Live,
    /// The trash.
    Trash,
}

/// Where a merged record appears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordStatus {
    /// Some head is live.
    pub live: bool,
    /// Some head is soft-deleted, or a final tombstone is concurrent with a
    /// non-final head.
    pub in_trash: bool,
    /// More than one head: an unresolved conflict (0005 §2.3).
    pub conflict: bool,
    /// Every head is a final tombstone.
    pub finally_deleted: bool,
}

/// The result of a merge: heads and dominated versions, each sorted by
/// version ID.
pub struct Merged<V> {
    heads: Vec<V>,
    dominated: Vec<V>,
}

/// Merges every known version of one record (0005 §2.1).
pub fn merge<V: Versioned>(versions: impl IntoIterator<Item = V>) -> Result<Merged<V>, ModelError> {
    // 1. Union, deduplicated by version ID.
    let mut by_id: BTreeMap<VersionId, V> = BTreeMap::new();
    for v in versions {
        match by_id.entry(v.version_id()) {
            Entry::Vacant(slot) => {
                slot.insert(v);
            }
            Entry::Occupied(slot) => {
                if !slot.get().same_version(&v) {
                    return Err(ModelError::Integrity);
                }
            }
        }
    }
    // 2. Valid clocks, and no clock under two version IDs.
    {
        let mut clocks: HashMap<&Clock, VersionId> = HashMap::with_capacity(by_id.len());
        for (id, v) in &by_id {
            if v.clock().is_empty() {
                return Err(ModelError::Malformed);
            }
            if clocks.insert(v.clock(), *id).is_some() {
                return Err(ModelError::Integrity);
            }
        }
    }
    // 3. Largest counter sum first. A strictly dominating clock has a
    // strictly larger sum, so every version that could dominate `v` comes
    // before it; `v` is a head iff no head so far dominates it (a dominated
    // dominator is itself dominated by a head, by transitivity). Heads only
    // grow, so the limit can be enforced as they are found.
    let mut order: Vec<V> = by_id.into_values().collect();
    order.sort_by(|a, b| {
        b.clock()
            .total()
            .cmp(&a.clock().total())
            .then_with(|| a.version_id().cmp(&b.version_id()))
    });
    let mut heads: Vec<V> = Vec::new();
    let mut dominated = Vec::new();
    for v in order {
        if heads.iter().any(|h| h.clock().dominates(v.clock())) {
            dominated.push(v);
        } else {
            if heads.len() == MAX_HEADS {
                return Err(ModelError::LimitExceeded);
            }
            heads.push(v);
        }
    }
    heads.sort_by_key(|v| v.version_id());
    dominated.sort_by_key(|v| v.version_id());
    Ok(Merged { heads, dominated })
}

/// Merges record versions, which must all have the same kind (0003 §2.3).
pub fn merge_record(
    versions: impl IntoIterator<Item = RecordVersion>,
) -> Result<Merged<RecordVersion>, ModelError> {
    let versions: Vec<RecordVersion> = versions.into_iter().collect();
    if let Some(first) = versions.first()
        && versions.iter().any(|v| v.kind() != first.kind())
    {
        return Err(ModelError::Integrity);
    }
    merge(versions)
}

impl<V: Versioned> Merged<V> {
    /// The heads: the current state.
    pub fn heads(&self) -> &[V] {
        &self.heads
    }

    /// Versions strictly dominated by a head: history candidates (0007 §1.1).
    pub fn dominated(&self) -> &[V] {
        &self.dominated
    }

    /// Heads and dominated versions.
    pub fn into_parts(self) -> (Vec<V>, Vec<V>) {
        (self.heads, self.dominated)
    }

    /// Whether the record is in unresolved conflict.
    pub fn is_conflict(&self) -> bool {
        self.heads.len() > 1
    }

    fn largest(&self, state: Deletion) -> Option<&V> {
        // Heads are sorted by version ID.
        self.heads.iter().rev().find(|v| v.deletion() == state)
    }

    /// The deterministic representative for `view` (0005 §2.3), or `None`
    /// if the record does not appear there.
    pub fn representative(&self, view: View) -> Option<&V> {
        match view {
            View::Live => self.largest(Deletion::Live),
            View::Trash => {
                if !self.status().in_trash {
                    return None;
                }
                self.largest(Deletion::SoftDeleted)
                    .or_else(|| self.largest(Deletion::Live))
            }
        }
    }

    /// Where the record appears.
    pub fn status(&self) -> RecordStatus {
        let has = |d: Deletion| self.heads.iter().any(|v| v.deletion() == d);
        let any_final = has(Deletion::Final);
        let all_final =
            !self.heads.is_empty() && self.heads.iter().all(|v| v.deletion() == Deletion::Final);
        RecordStatus {
            live: has(Deletion::Live),
            in_trash: has(Deletion::SoftDeleted) || (any_final && !all_final),
            conflict: self.is_conflict(),
            finally_deleted: all_final,
        }
    }

    /// Splits the dominated versions into `(history, suppressed)` by the
    /// record's history floor (0007 §1.2). Heads are never filtered.
    pub fn split_history(&self, floor: &HistoryFloor) -> (Vec<&V>, Vec<&V>) {
        self.dominated
            .iter()
            .partition(|v| !floor.suppresses(v.clock()))
    }
}

/// A record's monotonic history suppression frontier (0007 §1.2).
/// The default is the zero floor, which suppresses nothing.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HistoryFloor(Clock);

impl HistoryFloor {
    /// A floor at `clock`.
    pub fn new(clock: Clock) -> Self {
        Self(clock)
    }

    /// The floor's clock.
    pub fn clock(&self) -> &Clock {
        &self.0
    }

    /// Floors merge componentwise by maximum.
    pub fn join(&self, other: &HistoryFloor) -> Result<HistoryFloor, ModelError> {
        Ok(Self(self.0.join(&other.0)?))
    }

    /// Whether a historical version with `clock` is suppressed: its clock is
    /// at most the floor.
    pub fn suppresses(&self, clock: &Clock) -> bool {
        matches!(clock.compare(&self.0), Causality::Equal | Causality::Before)
    }
}

#[cfg(test)]
pub(crate) mod test_versions {
    use super::*;

    /// A minimal version for merge tests; `content` stands in for the payload.
    #[derive(Clone, Debug)]
    pub(crate) struct Tv {
        pub(crate) id: VersionId,
        pub(crate) clock: Clock,
        pub(crate) deletion: Deletion,
        pub(crate) content: u32,
    }

    impl Versioned for Tv {
        fn version_id(&self) -> VersionId {
            self.id
        }
        fn clock(&self) -> &Clock {
            &self.clock
        }
        fn deletion(&self) -> Deletion {
            self.deletion
        }
        fn same_version(&self, other: &Self) -> bool {
            self.clock == other.clock
                && self.deletion == other.deletion
                && self.content == other.content
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_versions::Tv;
    use super::*;
    use crate::clock::test_clock::clock;
    use crate::ids::test_ids::{v4, vid};
    use crate::ids::{RandomId, WriterId};
    use crate::record::test_records::{envelope, map};

    fn tv(id: u8, c: &[(u8, u64)]) -> Tv {
        Tv {
            id: vid(id),
            clock: clock(c),
            deletion: Deletion::Live,
            content: u32::from(id),
        }
    }

    fn deleted(mut v: Tv, d: Deletion) -> Tv {
        v.deletion = d;
        v
    }

    fn ids(vs: &[Tv]) -> Vec<VersionId> {
        vs.iter().map(|v| v.id).collect()
    }

    fn err<V: Versioned>(r: Result<Merged<V>, ModelError>) -> ModelError {
        match r {
            Ok(_) => panic!("merge succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn merge_duplicates_are_idempotent() {
        let a = tv(1, &[(1, 1)]);
        let m = merge([a.clone(), a.clone(), a]).unwrap();
        assert_eq!(ids(m.heads()), [vid(1)]);
        assert!(m.dominated().is_empty());
        assert!(!m.is_conflict());
    }

    #[test]
    fn merge_identity_violations() {
        // Same ID, different clock or content.
        let a = tv(1, &[(1, 1)]);
        let mut b = tv(1, &[(1, 2)]);
        assert_eq!(err(merge([a.clone(), b.clone()])), ModelError::Integrity);
        b.clock = a.clock.clone();
        b.content = 99;
        assert_eq!(err(merge([a.clone(), b])), ModelError::Integrity);
        // Equal clocks under different IDs, also when both are dominated.
        assert_eq!(
            err(merge([tv(1, &[(1, 1)]), tv(2, &[(1, 1)])])),
            ModelError::Integrity
        );
        assert_eq!(
            err(merge([
                tv(1, &[(1, 1)]),
                tv(2, &[(1, 1)]),
                tv(3, &[(1, 5)])
            ])),
            ModelError::Integrity
        );
        // An empty clock.
        let mut z = tv(4, &[]);
        z.clock = Clock::new();
        assert_eq!(err(merge([z])), ModelError::Malformed);
    }

    #[test]
    fn merge_dominance_and_concurrency() {
        let old = tv(9, &[(1, 1)]);
        let new = tv(1, &[(1, 2)]);
        let m = merge([old.clone(), new]).unwrap();
        assert_eq!(ids(m.heads()), [vid(1)]);
        assert_eq!(ids(m.dominated()), [vid(9)]);
        // Three concurrent versions stay three heads; the old one is dominated
        // by the first.
        let m = merge([tv(3, &[(1, 2)]), tv(1, &[(2, 1)]), tv(2, &[(3, 1)]), old]).unwrap();
        assert_eq!(ids(m.heads()), [vid(1), vid(2), vid(3)]);
        assert_eq!(ids(m.dominated()), [vid(9)]);
        assert!(m.is_conflict());
        let (heads, dominated) = m.into_parts();
        assert_eq!((heads.len(), dominated.len()), (3, 1));
        // An empty merge.
        let m = merge(Vec::<Tv>::new()).unwrap();
        assert!(m.heads().is_empty());
        assert_eq!(m.representative(View::Live).map(|v| v.id), None);
        assert!(!m.status().finally_deleted);
    }

    fn concurrent(n: usize) -> Vec<Tv> {
        (0..n)
            .map(|i| {
                let mut w = v4(0);
                w[1] = (i >> 8) as u8;
                w[2] = i as u8;
                let mut id = v4(0x55);
                id[1] = (i >> 8) as u8;
                id[2] = i as u8;
                Tv {
                    id: VersionId::from_bytes(id).unwrap(),
                    clock: Clock::from_pairs(vec![(WriterId::from_bytes(w).unwrap(), 1)]).unwrap(),
                    deletion: Deletion::Live,
                    content: 0,
                }
            })
            .collect()
    }

    #[test]
    fn merge_head_limit() {
        assert_eq!(merge(concurrent(256)).unwrap().heads().len(), 256);
        assert_eq!(err(merge(concurrent(257))), ModelError::LimitExceeded);
        // 300 concurrent versions and one that dominates them all: one head.
        // The limit applies to the result, not to intermediate state.
        let many = concurrent(300);
        // A clock can hold at most 256 writers, so dominate 256 of them and
        // let the other 44 be dominated by a second version over the rest.
        let first: Vec<_> = many[..256].iter().map(|v| v.clock.pairs()[0]).collect();
        let rest: Vec<_> = many[256..].iter().map(|v| v.clock.pairs()[0]).collect();
        let top = |pairs: Vec<(WriterId, u64)>, id: u8| Tv {
            id: vid(id),
            clock: Clock::from_pairs(pairs.into_iter().map(|(w, c)| (w, c + 1)).collect()).unwrap(),
            deletion: Deletion::Live,
            content: 0,
        };
        let mut input = many.clone();
        input.push(top(first, 1));
        input.push(top(rest, 2));
        let m = merge(input).unwrap();
        assert_eq!(ids(m.heads()), [vid(1), vid(2)]);
        assert_eq!(m.dominated().len(), 300);
    }

    fn record(kind: u64, deleted: bool, payload: Option<Vec<u8>>) -> RecordVersion {
        RecordVersion::decode(&map(&envelope(kind, deleted, payload))).unwrap()
    }

    fn group() -> Vec<u8> {
        use crate::record::test_records::{null, text};
        map(&[(0, null()), (1, text("G")), (4, text("a"))])
    }

    #[test]
    fn merge_record_checks_kind_and_content() {
        let g = record(1, false, Some(group()));
        let t = record(2, true, None);
        // The fixture gives both the same version ID and clock, so first
        // check kinds with distinct IDs.
        let mut t2 = t;
        t2.version_id = vid(0x77);
        t2.clock = clock(&[(0xb1, 2)]);
        assert_eq!(err(merge_record([g, t2])), ModelError::Integrity);
        // Same version ID and clock, different payload.
        use crate::record::test_records::{null, text};
        let other = map(&[(0, null()), (1, text("H")), (4, text("a"))]);
        assert_eq!(
            err(merge_record([
                record(1, false, Some(group())),
                record(1, false, Some(other))
            ])),
            ModelError::Integrity
        );
        // Identical versions deduplicate.
        let m = merge_record([
            record(1, false, Some(group())),
            record(1, false, Some(group())),
        ])
        .unwrap();
        assert_eq!(m.heads().len(), 1);
        assert!(m.status().live);
    }

    #[test]
    fn merge_representative_and_status() {
        let live_a = tv(1, &[(1, 1)]);
        let live_b = tv(2, &[(2, 1)]);
        let soft = deleted(tv(3, &[(3, 1)]), Deletion::SoftDeleted);
        let fin = deleted(tv(4, &[(4, 1)]), Deletion::Final);
        let rep = |m: &Merged<Tv>, view| m.representative(view).map(|v| v.id);

        // Two live heads: the larger ID, not in trash.
        let m = merge([live_b.clone(), live_a.clone()]).unwrap();
        assert_eq!(rep(&m, View::Live), Some(vid(2)));
        assert_eq!(rep(&m, View::Trash), None);
        assert_eq!(
            m.status(),
            RecordStatus {
                live: true,
                in_trash: false,
                conflict: true,
                finally_deleted: false
            }
        );

        // Live + soft-deleted: in both views.
        let m = merge([live_a.clone(), soft.clone()]).unwrap();
        assert_eq!(rep(&m, View::Live), Some(vid(1)));
        assert_eq!(rep(&m, View::Trash), Some(vid(3)));
        assert_eq!(
            m.status(),
            RecordStatus {
                live: true,
                in_trash: true,
                conflict: true,
                finally_deleted: false
            }
        );

        // Only soft-deleted.
        let m = merge([soft.clone()]).unwrap();
        assert_eq!(rep(&m, View::Live), None);
        assert_eq!(rep(&m, View::Trash), Some(vid(3)));

        // Final tombstone concurrent with a live edit: a conflict in trash,
        // shown through the live head.
        let m = merge([fin.clone(), live_a.clone()]).unwrap();
        assert_eq!(rep(&m, View::Live), Some(vid(1)));
        assert_eq!(rep(&m, View::Trash), Some(vid(1)));
        assert_eq!(
            m.status(),
            RecordStatus {
                live: true,
                in_trash: true,
                conflict: true,
                finally_deleted: false
            }
        );

        // Final + soft: the soft version represents the trash.
        let m = merge([fin.clone(), soft]).unwrap();
        assert_eq!(rep(&m, View::Trash), Some(vid(3)));
        assert_eq!(rep(&m, View::Live), None);

        // Only final.
        let m = merge([fin]).unwrap();
        assert_eq!(rep(&m, View::Live), None);
        assert_eq!(rep(&m, View::Trash), None);
        assert_eq!(
            m.status(),
            RecordStatus {
                live: false,
                in_trash: false,
                conflict: false,
                finally_deleted: true
            }
        );
    }

    #[test]
    fn merge_history_floors() {
        let a = HistoryFloor::new(clock(&[(1, 3), (2, 1)]));
        let b = HistoryFloor::new(clock(&[(1, 1), (2, 4), (3, 1)]));
        assert_eq!(
            a.join(&b).unwrap(),
            HistoryFloor::new(clock(&[(1, 3), (2, 4), (3, 1)]))
        );
        assert!(HistoryFloor::default().clock().is_empty());

        let head = tv(9, &[(1, 5)]);
        let at_floor = tv(1, &[(1, 3)]);
        let below = tv(2, &[(1, 2)]);
        let concurrent_with_floor = tv(3, &[(1, 1), (2, 1)]);
        let m = merge([head, at_floor, below, concurrent_with_floor]).unwrap();
        // (1,1),(2,1) is concurrent with the head (1,5), so it is a head too.
        assert_eq!(ids(m.heads()), [vid(3), vid(9)]);
        let floor = HistoryFloor::new(clock(&[(1, 3)]));
        let (history, suppressed) = m.split_history(&floor);
        assert!(history.is_empty());
        assert_eq!(
            suppressed.iter().map(|v| v.id).collect::<Vec<_>>(),
            [vid(1), vid(2)]
        );
        let low = HistoryFloor::new(clock(&[(1, 2)]));
        let (history, suppressed) = m.split_history(&low);
        assert_eq!(history.iter().map(|v| v.id).collect::<Vec<_>>(), [vid(1)]);
        assert_eq!(
            suppressed.iter().map(|v| v.id).collect::<Vec<_>>(),
            [vid(2)]
        );
        let sideways = HistoryFloor::new(clock(&[(2, 9)]));
        let (history, suppressed) = m.split_history(&sideways);
        assert_eq!(history.len(), 2);
        assert!(suppressed.is_empty());
        // A floor covering a head does not hide it.
        let covering = HistoryFloor::new(clock(&[(1, 9), (2, 9)]));
        assert!(covering.suppresses(&clock(&[(1, 5)])));
        let m2 = merge([tv(9, &[(1, 5)])]).unwrap();
        assert_eq!(m2.heads().len(), 1);
        assert!(m2.split_history(&covering).1.is_empty());
    }

    // ---- Step 6: properties over honest histories and 0012 scenarios ----

    mod properties {
        use std::collections::BTreeSet;

        use proptest::prelude::*;

        use super::super::test_versions::Tv;
        use super::super::*;
        use crate::clock::Causality;
        use crate::ids::test_ids::{vid, wid};

        /// One generated edit: its writer, and which earlier versions it
        /// knows (a bitmask over them).
        type Op = (u8, u32);

        /// Builds an honest history: each version's clock is `for_edit` over
        /// the versions it knows, with its writer's next counter.
        fn history(writers: u8, ops: &[Op]) -> Vec<Tv> {
            let mut versions: Vec<Tv> = Vec::new();
            let mut next = [0u64; 4];
            for (i, &(w, known)) in ops.iter().enumerate() {
                let w = w % writers;
                next[usize::from(w)] += 1;
                let heads: Vec<&Clock> = versions
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| known & (1 << j) != 0)
                    .map(|(_, v)| &v.clock)
                    .collect();
                let clock = Clock::for_edit(heads, wid(w), next[usize::from(w)]).unwrap();
                // IDs unrelated to creation order (37 is coprime to 256).
                let id = vid((i as u8).wrapping_mul(37).wrapping_add(11));
                versions.push(Tv {
                    id,
                    clock,
                    deletion: Deletion::Live,
                    content: i as u32,
                });
            }
            versions
        }

        fn arb_history() -> impl Strategy<Value = Vec<Tv>> {
            (
                2u8..=4,
                proptest::collection::vec((any::<u8>(), any::<u32>()), 1..=24),
            )
                .prop_map(|(w, ops)| history(w, &ops))
        }

        fn head_ids(vs: impl IntoIterator<Item = Tv>) -> Vec<VersionId> {
            merge(vs).unwrap().heads().iter().map(|v| v.id).collect()
        }

        /// The maximal versions by brute force.
        fn reference_heads(vs: &[Tv]) -> Vec<VersionId> {
            let mut out: Vec<VersionId> = vs
                .iter()
                .filter(|v| !vs.iter().any(|o| o.clock.dominates(&v.clock)))
                .map(|v| v.id)
                .collect();
            out.sort();
            out
        }

        proptest! {
            #[test]
            fn merge_matches_brute_force(h in arb_history()) {
                let m = merge(h.clone()).unwrap();
                let heads: Vec<_> = m.heads().iter().map(|v| v.id).collect();
                prop_assert_eq!(&heads, &reference_heads(&h));
                prop_assert_eq!(m.heads().len() + m.dominated().len(), h.len());
            }

            // 0012 §1: Order-dependent merges
            #[test]
            fn merge_is_permutation_invariant(
                (h, shuffled) in arb_history().prop_flat_map(|h| (Just(h.clone()), Just(h).prop_shuffle()))
            ) {
                let a = merge(h).unwrap();
                let b = merge(shuffled).unwrap();
                let ids = |vs: &[Tv]| vs.iter().map(|v| v.id).collect::<Vec<_>>();
                prop_assert_eq!(ids(a.heads()), ids(b.heads()));
                prop_assert_eq!(ids(a.dominated()), ids(b.dominated()));
            }

            // 0012 §1: Order-dependent merges
            #[test]
            fn merge_regrouping_converges(h in arb_history(), split in any::<u32>(), split2 in any::<u32>()) {
                let all = head_ids(h.clone());
                let (a, b): (Vec<Tv>, Vec<Tv>) =
                    h.iter().cloned().enumerate().partition(|(i, _)| split & (1 << i) != 0)
                        .into_iter_pair();
                let ha = merge(a.clone()).unwrap().into_parts().0;
                let hb = merge(b.clone()).unwrap().into_parts().0;
                prop_assert_eq!(head_ids(ha.into_iter().chain(hb)), all.clone());
                // Three-way: (A ∪ B1) ∪ B2 with intermediate merges.
                let (b1, b2): (Vec<Tv>, Vec<Tv>) =
                    b.into_iter().enumerate().partition(|(i, _)| split2 & (1 << i) != 0)
                        .into_iter_pair();
                let left = merge(a.into_iter().chain(b1)).unwrap().into_parts().0;
                prop_assert_eq!(head_ids(left.into_iter().chain(b2)), all);
            }

            // 0012 §1: Order-dependent merges
            #[test]
            fn merge_ignores_duplicate_delivery(h in arb_history(), reps in proptest::collection::vec(1usize..=3, 24)) {
                let all = head_ids(h.clone());
                let dup: Vec<Tv> = h
                    .iter()
                    .zip(&reps)
                    .flat_map(|(v, &n)| std::iter::repeat_n(v.clone(), n))
                    .collect();
                prop_assert_eq!(head_ids(dup), all);
            }

            #[test]
            fn merge_heads_are_inputs_and_maximal(h in arb_history()) {
                let m = merge(h.clone()).unwrap();
                let inputs: BTreeSet<(VersionId, u32)> = h.iter().map(|v| (v.id, v.content)).collect();
                for head in m.heads() {
                    prop_assert!(inputs.contains(&(head.id, head.content)));
                    for other in m.heads() {
                        if other.id != head.id {
                            prop_assert_eq!(head.clock.compare(&other.clock), Causality::Concurrent);
                        }
                    }
                }
                for v in &h {
                    prop_assert!(m.heads().iter().any(|head| matches!(
                        v.clock.compare(&head.clock),
                        Causality::Equal | Causality::Before
                    )));
                }
            }
        }

        /// `partition` on enumerated items, then drop the indices.
        trait IntoIterPair {
            fn into_iter_pair(self) -> (Vec<Tv>, Vec<Tv>);
        }

        impl IntoIterPair for (Vec<(usize, Tv)>, Vec<(usize, Tv)>) {
            fn into_iter_pair(self) -> (Vec<Tv>, Vec<Tv>) {
                (
                    self.0.into_iter().map(|(_, v)| v).collect(),
                    self.1.into_iter().map(|(_, v)| v).collect(),
                )
            }
        }
    }

    mod scenarios {
        use super::super::*;
        use crate::clock::test_clock::clock;
        use crate::ids::test_ids::{fid, rid, vid, wid};
        use crate::payload::{Entry, Field, FieldKind, Payload};
        use crate::record::{RecordBody, RecordVersion};
        use crate::text::{Extensions, FieldValue, Text};
        use crate::time::Timestamp;

        const YEAR_MS: i64 = 365 * 24 * 3600 * 1000;

        fn field(n: u8, name: &str, kind: FieldKind, value: &str) -> Field {
            Field {
                id: fid(n),
                name: Text::new(name).unwrap(),
                kind,
                value: FieldValue::text(value).unwrap(),
                protected: kind.protected_by_default(),
                ext: Extensions::new(),
            }
        }

        /// An entry version with a login's three credential fields.
        fn login(id: u8, c: &[(u8, u64)], at: i64, creds: (&str, &str, &str)) -> RecordVersion {
            RecordVersion {
                version_id: vid(id),
                clock: clock(c),
                modified_at: Timestamp(at),
                body: RecordBody::Live(Payload::Entry(Entry {
                    group: rid(1),
                    type_hint: Text::new("login").unwrap(),
                    title: Text::new("Bank").unwrap(),
                    fields: vec![
                        field(1, "Username", FieldKind::Text, creds.0),
                        field(2, "Password", FieldKind::Secret, creds.1),
                        field(3, "TOTP", FieldKind::Totp, creds.2),
                    ],
                    notes: None,
                    icon: None,
                    expires_at: None,
                    created_at: Timestamp(0),
                    modified_at: Timestamp(at),
                    deleted_at: None,
                    ext: Extensions::new(),
                })),
                ext: Extensions::new(),
            }
        }

        fn tombstone(id: u8, c: &[(u8, u64)], at: i64) -> RecordVersion {
            RecordVersion {
                version_id: vid(id),
                clock: clock(c),
                modified_at: Timestamp(at),
                body: RecordBody::Tombstone(crate::record::RecordKind::Entry),
                ext: Extensions::new(),
            }
        }

        fn encodings(vs: &[RecordVersion]) -> Vec<Vec<u8>> {
            vs.iter().map(|v| v.encode().unwrap().to_vec()).collect()
        }

        fn ids(vs: &[RecordVersion]) -> Vec<VersionId> {
            vs.iter().map(|v| v.version_id).collect()
        }

        /// 0012 row "Old-date concurrent edits".
        // 0012 §1: Old-date concurrent edits
        #[test]
        fn scenario_old_date_concurrent_edit_survives() {
            let creds = |p| ("a", p, "otpauth://totp/a?secret=AA");
            let newer = || login(1, &[(1, 2)], 30 * YEAR_MS, creds("new"));
            // Concurrent, but dated decades earlier.
            let older = || login(2, &[(1, 1), (2, 1)], YEAR_MS, creds("old"));
            for input in [vec![newer(), older()], vec![older(), newer()]] {
                let m = merge_record(input).unwrap();
                assert_eq!(ids(m.heads()), [vid(1), vid(2)]);
                assert!(m.is_conflict());
            }
        }

        /// 0012 row "Mixed credentials": no synthetic combination.
        // 0012 §1: Mixed credentials
        #[test]
        fn scenario_mixed_credentials_stay_whole() {
            let a = || {
                login(
                    1,
                    &[(1, 2)],
                    10,
                    ("alice", "pw-a", "otpauth://totp/a?secret=AAAA"),
                )
            };
            let b = || {
                login(
                    2,
                    &[(1, 1), (2, 1)],
                    20,
                    ("bob", "pw-b", "otpauth://totp/b?secret=BBBB"),
                )
            };
            let inputs = encodings(&[a(), b()]);
            let m = merge_record([b(), a()]).unwrap();
            assert_eq!(m.heads().len(), 2);
            for head in encodings(m.heads()) {
                assert!(inputs.contains(&head));
            }
            let rep = m.representative(View::Live).unwrap();
            assert!(
                inputs
                    .iter()
                    .any(|i| i.as_slice() == rep.encode().unwrap().as_slice())
            );
            for head in m.heads() {
                let RecordBody::Live(Payload::Entry(e)) = &head.body else {
                    panic!("not an entry");
                };
                let user = e.fields[0].value.expose_secret();
                let pass = e.fields[1].value.expose_secret();
                let totp = e.fields[2].value.expose_secret();
                let a_set = (
                    &b"alice"[..],
                    &b"pw-a"[..],
                    &b"otpauth://totp/a?secret=AAAA"[..],
                );
                let b_set = (
                    &b"bob"[..],
                    &b"pw-b"[..],
                    &b"otpauth://totp/b?secret=BBBB"[..],
                );
                assert!((user, pass, totp) == a_set || (user, pass, totp) == b_set);
            }
        }

        /// 0012 row "Deleted-entry resurrection" (model level).
        // 0012 §1: Deleted-entry resurrection
        #[test]
        fn scenario_deleted_entry_stays_deleted() {
            let creds = ("u", "p", "otpauth://totp/x?secret=AA");
            // An edit dated years after the tombstone that covers it.
            let edit = || login(1, &[(1, 1)], 30 * YEAR_MS, creds);
            let tomb = || tombstone(2, &[(1, 2)], YEAR_MS);
            for input in [vec![edit(), tomb()], vec![tomb(), edit()]] {
                let m = merge_record(input).unwrap();
                assert_eq!(ids(m.heads()), [vid(2)]);
                assert!(m.status().finally_deleted);
                assert_eq!(m.representative(View::Live).map(|v| v.version_id), None);
            }
            // The old edit delivered later, after the tombstone was accepted.
            let accepted = merge_record([tomb()]).unwrap().into_parts().0;
            let late = merge_record(accepted.into_iter().chain([edit()])).unwrap();
            assert_eq!(ids(late.heads()), [vid(2)]);
            assert_eq!(ids(late.dominated()), [vid(1)]);
            let (history, suppressed) = late.split_history(&HistoryFloor::new(clock(&[(1, 1)])));
            assert!(history.is_empty());
            assert_eq!(suppressed.len(), 1);

            // A tombstone concurrent with an edit: a conflict in trash.
            let m = merge_record([tombstone(3, &[(2, 1)], 0), edit()]).unwrap();
            assert_eq!(ids(m.heads()), [vid(1), vid(3)]);
            let s = m.status();
            assert!(s.conflict && s.in_trash && s.live && !s.finally_deleted);
            assert_eq!(
                m.representative(View::Live).map(|v| v.version_id),
                Some(vid(1))
            );
            assert_eq!(
                m.representative(View::Trash).map(|v| v.version_id),
                Some(vid(1))
            );
            assert!(m.heads().iter().any(|v| v.deletion() == Deletion::Final));
        }

        /// A late edit that the resolution did not see stays concurrent
        /// (0005 §2.4).
        #[test]
        fn scenario_late_edit_after_resolution() {
            let creds = ("u", "p", "t");
            let a = login(1, &[(1, 1)], 0, creds);
            let b = login(2, &[(2, 1)], 0, creds);
            let resolved = Clock::for_edit([&a.clock, &b.clock], wid(1), 2).unwrap();
            let r = login(3, &[(1, 2), (2, 1)], 0, creds);
            assert_eq!(r.clock, resolved);
            let late = login(4, &[(3, 1)], 0, creds);
            let m = merge_record([a, b, r, late]).unwrap();
            assert_eq!(ids(m.heads()), [vid(3), vid(4)]);
            assert_eq!(ids(m.dominated()), [vid(1), vid(2)]);
        }
    }
}
