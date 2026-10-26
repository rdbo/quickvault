// SPDX-License-Identifier: AGPL-3.0-or-later

//! The deterministic group-tree projection (spec 0003 §4.1–4.2).
//!
//! Merges can leave groups orphaned or in parent cycles. The projection turns
//! the groups' current representatives into a display tree **without writing
//! anything**: source records keep their original parents (0003 §4.2,
//! 0005 §2.6), and the projection is recomputed on every merge.
//!
//! Rules, applied to live groups:
//! 1. The root's parent is `None`.
//! 2. A non-root group whose parent is `None`, itself, missing or not live
//!    is shown under the root.
//! 3. In each remaining parent cycle, the group with the smallest ID is shown
//!    under the root.
//!
//! Each cycle of the parent graph is broken exactly at its smallest member,
//! so the result does not depend on traversal order. Traversal is iterative,
//! visits each group once, and is bounded by [`MAX_GROUPS`].

use std::collections::{BTreeMap, BTreeSet};

use crate::error::ModelError;
use crate::ids::RecordId;
use crate::merge::{Merged, View};
use crate::payload::Payload;
use crate::record::{RecordBody, RecordKind, RecordVersion};

/// The most groups a projection accepts (the 0004 §4.1 record budget).
pub const MAX_GROUPS: usize = 50_000;

/// One group as the projection sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupNode {
    /// The representative's parent.
    pub parent: Option<RecordId>,
    /// Whether the group has a live head (plan 0007: a group is deleted for
    /// the tree only when no head is live).
    pub live: bool,
}

impl GroupNode {
    /// The node of a merged group record: the live representative's parent
    /// if there is one, else the trash representative's. A record that is
    /// not a group is [`ModelError::Malformed`].
    pub fn from_merged(m: &Merged<RecordVersion>) -> Result<GroupNode, ModelError> {
        if m.heads().iter().any(|v| v.kind() != RecordKind::Group) {
            return Err(ModelError::Malformed);
        }
        let parent_of = |v: &RecordVersion| match &v.body {
            RecordBody::Live(Payload::Group(g)) => g.parent,
            _ => None,
        };
        let live = m.representative(View::Live);
        let shown = live.or_else(|| m.representative(View::Trash));
        Ok(GroupNode {
            parent: shown.and_then(parent_of),
            live: live.is_some(),
        })
    }
}

/// The display tree.
#[derive(Debug, PartialEq, Eq)]
pub struct GroupTree {
    /// Every group in the tree (the root and the live groups) and its
    /// displayed parent; the root's is `None`.
    parents: BTreeMap<RecordId, Option<RecordId>>,
    /// Groups shown under a different parent than their record names.
    repaired: BTreeSet<RecordId>,
}

/// Where an entry is shown (0003 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryPlace {
    /// In this group.
    Group(RecordId),
    /// In the recovered-items view under the root: its group is missing or
    /// deleted.
    Recovered,
}

/// Projects `groups` (every group record's node, keyed by record ID) into a
/// tree rooted at `root`. The root is in the tree even if it is absent from
/// `groups`.
pub fn project_groups(
    root: RecordId,
    groups: &BTreeMap<RecordId, GroupNode>,
) -> Result<GroupTree, ModelError> {
    if groups.len() > MAX_GROUPS {
        return Err(ModelError::LimitExceeded);
    }
    let mut parents: BTreeMap<RecordId, Option<RecordId>> = BTreeMap::new();
    let mut repaired = BTreeSet::new();
    parents.insert(root, None);
    if groups.get(&root).is_some_and(|n| n.parent.is_some()) {
        repaired.insert(root);
    }
    let is_live = |id: &RecordId| *id == root || groups.get(id).is_some_and(|n| n.live);
    for (&id, node) in groups {
        if id == root || !node.live {
            continue;
        }
        let parent = match node.parent {
            Some(p) if p != id && is_live(&p) => p,
            _ => {
                repaired.insert(id);
                root
            }
        };
        parents.insert(id, Some(parent));
    }

    // Break cycles. `done` holds groups known to reach the root.
    let mut done: BTreeSet<RecordId> = BTreeSet::new();
    done.insert(root);
    let mut path: Vec<RecordId> = Vec::new();
    let mut on_path: BTreeSet<RecordId> = BTreeSet::new();
    let ids: Vec<RecordId> = parents.keys().copied().collect();
    for start in ids {
        let mut cur = start;
        // Each step either reaches a done group or adds a new one to the
        // path, so at most `parents.len()` steps.
        for _ in 0..=parents.len() {
            if done.contains(&cur) {
                break;
            }
            if on_path.contains(&cur) {
                // `cur` closes a cycle: the path from `cur` to the end.
                let at = path
                    .iter()
                    .position(|&g| g == cur)
                    .ok_or(ModelError::Internal)?;
                let smallest = path
                    .get(at..)
                    .and_then(|cycle| cycle.iter().min().copied())
                    .ok_or(ModelError::Internal)?;
                parents.insert(smallest, Some(root));
                repaired.insert(smallest);
                break;
            }
            on_path.insert(cur);
            path.push(cur);
            cur = parents
                .get(&cur)
                .copied()
                .flatten()
                .ok_or(ModelError::Internal)?;
        }
        done.extend(path.drain(..));
        on_path.clear();
    }
    Ok(GroupTree { parents, repaired })
}

impl GroupTree {
    /// The displayed parent of `group`: `Some(None)` for the root, `None` if
    /// the group is not in the tree (missing or deleted).
    pub fn parent(&self, group: RecordId) -> Option<Option<RecordId>> {
        self.parents.get(&group).copied()
    }

    /// The displayed children of `group`, sorted by ID.
    pub fn children(&self, group: RecordId) -> Vec<RecordId> {
        self.parents
            .iter()
            .filter(|&(_, &p)| p == Some(group))
            .map(|(&id, _)| id)
            .collect()
    }

    /// Whether `group` is shown under a different parent than its record
    /// names.
    pub fn is_repaired(&self, group: RecordId) -> bool {
        self.repaired.contains(&group)
    }

    /// Where an entry whose record names `group` is shown.
    pub fn place_entry(&self, group: RecordId) -> EntryPlace {
        if self.parents.contains_key(&group) {
            EntryPlace::Group(group)
        } else {
            EntryPlace::Recovered
        }
    }

    /// The number of groups in the tree, including the root.
    pub fn len(&self) -> usize {
        self.parents.len()
    }

    /// Always `false`: the root is always in the tree.
    pub fn is_empty(&self) -> bool {
        self.parents.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::ids::RandomId;
    use crate::ids::test_ids::{rid, v4};
    use crate::merge::merge_record;
    use crate::record::test_records::{bytes, envelope, map, null, text};

    const ROOT: u8 = 0;

    fn node(parent: Option<u8>, live: bool) -> GroupNode {
        GroupNode {
            parent: parent.map(rid),
            live,
        }
    }

    fn tree(nodes: &[(u8, Option<u8>, bool)]) -> GroupTree {
        let groups = nodes
            .iter()
            .map(|&(id, p, live)| (rid(id), node(p, live)))
            .collect();
        project_groups(rid(ROOT), &groups).unwrap()
    }

    fn parent(t: &GroupTree, id: u8) -> Option<Option<RecordId>> {
        t.parent(rid(id))
    }

    #[test]
    fn tree_simple_and_orphans() {
        let t = tree(&[
            (ROOT, None, true),
            (1, Some(ROOT), true),
            (2, Some(1), true),
            (3, Some(99), true), // missing parent
            (4, Some(5), true),  // deleted parent
            (5, Some(ROOT), false),
            (6, None, true),    // non-root with a null parent
            (7, Some(7), true), // self-parent
        ]);
        assert_eq!(parent(&t, ROOT), Some(None));
        assert_eq!(parent(&t, 2), Some(Some(rid(1))));
        for g in [3, 4, 6, 7] {
            assert_eq!(parent(&t, g), Some(Some(rid(ROOT))), "group {g}");
            assert!(t.is_repaired(rid(g)));
        }
        assert!(!t.is_repaired(rid(1)) && !t.is_repaired(rid(2)));
        assert_eq!(parent(&t, 5), None);
        assert_eq!(t.children(rid(ROOT)), [1, 3, 4, 6, 7].map(rid));
        assert_eq!(t.children(rid(1)), [rid(2)]);
        assert_eq!(t.len(), 7);
        assert!(!t.is_empty());
        assert_eq!(t.place_entry(rid(2)), EntryPlace::Group(rid(2)));
        assert_eq!(t.place_entry(rid(5)), EntryPlace::Recovered);
        assert_eq!(t.place_entry(rid(98)), EntryPlace::Recovered);
        assert_eq!(t.place_entry(rid(ROOT)), EntryPlace::Group(rid(ROOT)));
    }

    #[test]
    fn tree_root_is_fixed() {
        // The root's record names a parent: still the root.
        let t = tree(&[(ROOT, Some(1), true), (1, Some(ROOT), true)]);
        assert_eq!(parent(&t, ROOT), Some(None));
        assert!(t.is_repaired(rid(ROOT)));
        assert_eq!(parent(&t, 1), Some(Some(rid(ROOT))));
        // The root is in the tree even if absent from the input.
        let t = tree(&[(1, Some(ROOT), true)]);
        assert_eq!(parent(&t, ROOT), Some(None));
        assert_eq!(parent(&t, 1), Some(Some(rid(ROOT))));
    }

    #[test]
    fn tree_cycles_break_at_smallest_id() {
        let t = tree(&[
            (ROOT, None, true),
            // 2-cycle 5 ↔ 3.
            (5, Some(3), true),
            (3, Some(5), true),
            // 3-cycle 9 → 7 → 8 → 9, with a tail 10 → 9 and 11 → 10.
            (9, Some(7), true),
            (7, Some(8), true),
            (8, Some(9), true),
            (10, Some(9), true),
            (11, Some(10), true),
        ]);
        assert_eq!(parent(&t, 3), Some(Some(rid(ROOT))));
        assert_eq!(parent(&t, 5), Some(Some(rid(3))));
        assert_eq!(parent(&t, 7), Some(Some(rid(ROOT))));
        assert_eq!(parent(&t, 8), Some(Some(rid(9))));
        assert_eq!(parent(&t, 9), Some(Some(rid(7))));
        assert_eq!(parent(&t, 10), Some(Some(rid(9))));
        assert_eq!(parent(&t, 11), Some(Some(rid(10))));
        let repaired: Vec<_> = (0..12).filter(|&g| t.is_repaired(rid(g))).collect();
        assert_eq!(repaired, [3, 7]);
    }

    fn wide(n: u32) -> RecordId {
        let mut b = v4(0x01);
        b[1] = (n >> 16) as u8;
        b[2] = (n >> 8) as u8;
        b[3] = n as u8;
        RecordId::from_bytes(b).unwrap()
    }

    #[test]
    fn tree_deep_chain_and_limit() {
        let root = rid(ROOT);
        let chain = |n: u32| {
            (0..n)
                .map(|i| {
                    let parent = if i == 0 { root } else { wide(i - 1) };
                    (
                        wide(i),
                        GroupNode {
                            parent: Some(parent),
                            live: true,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let t = project_groups(root, &chain(50_000)).unwrap();
        assert_eq!(t.len(), 50_001);
        assert_eq!(t.parent(wide(49_999)), Some(Some(wide(49_998))));
        assert!(!t.is_repaired(wide(49_999)));
        // A 50,000-group cycle (the chain closed onto itself).
        let mut cycle = chain(50_000);
        cycle.insert(
            wide(0),
            GroupNode {
                parent: Some(wide(49_999)),
                live: true,
            },
        );
        let t = project_groups(root, &cycle).unwrap();
        assert_eq!(t.parent(wide(0)), Some(Some(root)));
        assert!(t.is_repaired(wide(0)));
        assert_eq!(
            project_groups(root, &chain(50_001)),
            Err(ModelError::LimitExceeded)
        );
    }

    fn group_version(id: u8, parent: Option<[u8; 16]>, deleted_at: bool) -> RecordVersion {
        let mut p = vec![
            (0, parent.map_or_else(null, |p| bytes(&p))),
            (1, text("G")),
            (4, text("a")),
        ];
        if deleted_at {
            p.push((5, crate::record::test_records::int(1)));
        }
        let mut env = envelope(1, false, Some(map(&p)));
        env[1] = (1, bytes(&v4(id)));
        env[2] = (2, crate::record::test_records::clock1(v4(id), 1));
        RecordVersion::decode(&map(&env)).unwrap()
    }

    #[test]
    fn tree_node_from_merged() {
        // Two live heads: the larger version ID's parent.
        let m = merge_record([
            group_version(1, Some(v4(7)), false),
            group_version(2, Some(v4(8)), false),
        ])
        .unwrap();
        assert_eq!(GroupNode::from_merged(&m).unwrap(), node(Some(8), true));
        // Live and soft-deleted: live, with the live head's parent.
        let m = merge_record([
            group_version(1, Some(v4(7)), false),
            group_version(2, Some(v4(8)), true),
        ])
        .unwrap();
        assert_eq!(GroupNode::from_merged(&m).unwrap(), node(Some(7), true));
        // Only soft-deleted: not live, parent kept for inspection.
        let m = merge_record([group_version(2, Some(v4(8)), true)]).unwrap();
        assert_eq!(GroupNode::from_merged(&m).unwrap(), node(Some(8), false));
        // A tombstone.
        let m =
            merge_record([RecordVersion::decode(&map(&envelope(1, true, None))).unwrap()]).unwrap();
        assert_eq!(GroupNode::from_merged(&m).unwrap(), node(None, false));
        // Not a group.
        let m =
            merge_record([RecordVersion::decode(&map(&envelope(2, true, None))).unwrap()]).unwrap();
        assert_eq!(GroupNode::from_merged(&m), Err(ModelError::Malformed));
    }

    fn arb_groups() -> impl Strategy<Value = BTreeMap<RecordId, GroupNode>> {
        // Up to 64 groups (IDs 0–63; 0 is the root); parents 0–69, so some are missing.
        proptest::collection::btree_map(
            0u8..64,
            (
                proptest::option::weighted(0.95, 0u8..70),
                proptest::bool::weighted(0.85),
            ),
            0..64,
        )
        .prop_map(|m| {
            m.into_iter()
                .map(|(id, (p, live))| (rid(id), node(p, live)))
                .collect()
        })
    }

    proptest! {
        #[test]
        fn tree_projection_invariants(groups in arb_groups()) {
            let root = rid(ROOT);
            let t = project_groups(root, &groups).unwrap();
            for (&id, &shown) in &t.parents {
                // Every group reaches the root within len steps.
                let mut cur = id;
                let mut steps = 0;
                while cur != root {
                    cur = t.parents[&cur].unwrap();
                    steps += 1;
                    prop_assert!(steps <= t.len());
                }
                if id == root {
                    continue;
                }
                let original = groups[&id].parent;
                let valid = |p: RecordId| p != id && (p == root || groups.get(&p).is_some_and(|n| n.live));
                if !t.is_repaired(id) {
                    prop_assert_eq!(shown, original);
                } else if original.is_some_and(valid) {
                    // Repaired despite a valid parent: the smallest member of
                    // a cycle of valid parents.
                    let mut cur = original.unwrap();
                    let mut steps = 0;
                    while cur != id {
                        prop_assert!(cur > id);
                        let next = groups[&cur].parent;
                        prop_assert!(next.is_some_and(|n| n != cur && (n == root || groups.get(&n).is_some_and(|g| g.live))));
                        cur = next.unwrap();
                        steps += 1;
                        prop_assert!(steps <= groups.len());
                    }
                    prop_assert_eq!(shown, Some(root));
                } else {
                    prop_assert_eq!(shown, Some(root));
                }
            }
            // Only live groups (and the root) are in the tree.
            for (id, n) in &groups {
                prop_assert_eq!(t.parent(*id).is_some(), n.live || *id == root);
            }
        }

        #[test]
        fn tree_projection_is_order_independent(groups in arb_groups(), seed in any::<u64>()) {
            let root = rid(ROOT);
            let t = project_groups(root, &groups).unwrap();
            // Rebuild the map from a shuffled list.
            let mut list: Vec<_> = groups.iter().map(|(k, v)| (*k, *v)).collect();
            let n = list.len();
            if n > 1 {
                let mut s = seed;
                for i in (1..n).rev() {
                    s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    list.swap(i, (s >> 33) as usize % (i + 1));
                }
            }
            let rebuilt: BTreeMap<_, _> = list.into_iter().collect();
            prop_assert_eq!(project_groups(root, &rebuilt).unwrap(), t);
        }
    }
}
