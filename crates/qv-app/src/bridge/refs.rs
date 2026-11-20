// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rust handles never reach the page (0008 §4.1): frames carry random
//! 128-bit references from this table. A handle keeps its reference while it
//! stays on screen; references unused for many frames are pruned, and a lock
//! clears every session reference, so a stale one names nothing.
use qv_core::autofill::CandidateKey;
use qv_core::{AttachmentHandle, EntryHandle, FieldHandle, FieldId, GroupHandle};
use qv_ui_api::Ref;
use std::collections::HashMap;
use std::path::PathBuf;

/// What a reference names.
#[derive(Clone, PartialEq)]
pub(crate) enum Target {
    Entry(EntryHandle),
    Group(GroupHandle),
    Field(FieldHandle),
    FieldId(FieldId),
    Attachment(AttachmentHandle),
    Candidate(CandidateKey),
    /// A listed vault (kept across locks).
    Vault(PathBuf),
}

/// The hashable identity of a target.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Entry(EntryHandle),
    Group(GroupHandle),
    Field(FieldHandle),
    FieldId(FieldId),
    /// Record and version IDs (attachment handles are not `Hash`).
    Attachment(String, String),
    Vault(PathBuf),
}

/// At most this many references; older ones are pruned past it.
const MAX: usize = 8192;
/// References unused for this many frames may be pruned.
const KEEP_FRAMES: u64 = 64;

#[derive(Default)]
pub(crate) struct Refs {
    by_ref: HashMap<Ref, (Target, u64)>,
    by_key: HashMap<Key, Ref>,
    candidates: Vec<(CandidateKey, Ref)>,
    frame: u64,
}

fn key(t: &Target) -> Option<Key> {
    Some(match t {
        Target::Entry(h) => Key::Entry(*h),
        Target::Group(h) => Key::Group(*h),
        Target::Field(h) => Key::Field(*h),
        Target::FieldId(h) => Key::FieldId(*h),
        Target::Attachment(h) => Key::Attachment(h.id_hex(), h.version_hex()),
        Target::Vault(p) => Key::Vault(p.clone()),
        Target::Candidate(_) => return None,
    })
}

fn random() -> Ref {
    let mut r = [0u8; 16];
    // A failed OS RNG leaves zeros; such a reference is refused on lookup.
    let _ = getrandom::fill(&mut r);
    Ref(r)
}

impl Refs {
    /// Starts a frame; prunes references unused for a while when full.
    pub(crate) fn next_frame(&mut self) {
        self.frame = self.frame.wrapping_add(1);
        if self.by_ref.len() > MAX {
            let frame = self.frame;
            self.by_ref
                .retain(|_, (_, seen)| frame.wrapping_sub(*seen) < KEEP_FRAMES);
            let by_ref = &self.by_ref;
            self.by_key.retain(|_, r| by_ref.contains_key(r));
            self.candidates.retain(|(_, r)| by_ref.contains_key(r));
        }
    }

    /// The reference for `target`, the same while it stays on screen.
    pub(crate) fn issue(&mut self, target: Target) -> Ref {
        let existing = match key(&target) {
            Some(k) => self.by_key.get(&k).copied(),
            None => match &target {
                Target::Candidate(c) => self
                    .candidates
                    .iter()
                    .find(|(k, _)| k == c)
                    .map(|(_, r)| *r),
                _ => None,
            },
        };
        if let Some(r) = existing
            && let Some(entry) = self.by_ref.get_mut(&r)
        {
            entry.1 = self.frame;
            return r;
        }
        let mut r = random();
        while r == Ref::default() || self.by_ref.contains_key(&r) {
            r = random();
        }
        match key(&target) {
            Some(k) => {
                self.by_key.insert(k, r);
            }
            None => {
                if let Target::Candidate(c) = &target {
                    self.candidates.push((*c, r));
                }
            }
        }
        self.by_ref.insert(r, (target, self.frame));
        r
    }

    /// What a reference names.
    pub(crate) fn get(&self, r: Ref) -> Option<&Target> {
        if r == Ref::default() {
            return None;
        }
        self.by_ref.get(&r).map(|(t, _)| t)
    }

    /// Forgets every session reference (on lock); listed vaults stay.
    pub(crate) fn clear_session(&mut self) {
        self.by_ref
            .retain(|_, (t, _)| matches!(t, Target::Vault(_)));
        self.by_key.retain(|k, _| matches!(k, Key::Vault(_)));
        self.candidates.clear();
    }

    pub(crate) fn entry(&self, r: Ref) -> Option<EntryHandle> {
        match self.get(r)? {
            Target::Entry(h) => Some(*h),
            _ => None,
        }
    }
    pub(crate) fn group(&self, r: Ref) -> Option<GroupHandle> {
        match self.get(r)? {
            Target::Group(h) => Some(*h),
            _ => None,
        }
    }
    pub(crate) fn field(&self, r: Ref) -> Option<FieldHandle> {
        match self.get(r)? {
            Target::Field(h) => Some(*h),
            _ => None,
        }
    }
    pub(crate) fn field_id(&self, r: Ref) -> Option<FieldId> {
        match self.get(r)? {
            Target::FieldId(h) => Some(*h),
            _ => None,
        }
    }
    pub(crate) fn attachment(&self, r: Ref) -> Option<AttachmentHandle> {
        match self.get(r)? {
            Target::Attachment(h) => Some(*h),
            _ => None,
        }
    }
    pub(crate) fn candidate(&self, r: Ref) -> Option<CandidateKey> {
        match self.get(r)? {
            Target::Candidate(h) => Some(*h),
            _ => None,
        }
    }
    pub(crate) fn vault(&self, r: Ref) -> Option<PathBuf> {
        match self.get(r)? {
            Target::Vault(p) => Some(p.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_stable_random_and_cleared_on_lock() {
        let mut refs = Refs::default();
        let a = refs.issue(Target::Vault(PathBuf::from("a.qvault")));
        assert_eq!(refs.issue(Target::Vault(PathBuf::from("a.qvault"))), a);
        let b = refs.issue(Target::Vault(PathBuf::from("b.qvault")));
        assert_ne!(a, b);
        assert_eq!(refs.vault(a), Some(PathBuf::from("a.qvault")));
        assert!(refs.entry(a).is_none(), "a vault is not an entry");
        assert!(refs.get(Ref([9; 16])).is_none());
        assert!(refs.get(Ref::default()).is_none());
        refs.clear_session();
        assert_eq!(refs.vault(a), Some(PathBuf::from("a.qvault")));
    }

    #[test]
    fn unused_references_are_pruned_when_full() {
        let mut refs = Refs::default();
        let kept = refs.issue(Target::Vault(PathBuf::from("kept")));
        for n in 0..=MAX {
            refs.issue(Target::Vault(PathBuf::from(format!("v{n}"))));
        }
        for _ in 0..KEEP_FRAMES {
            refs.next_frame();
            refs.issue(Target::Vault(PathBuf::from("kept")));
        }
        refs.next_frame();
        assert!(refs.by_ref.len() < MAX);
        assert_eq!(refs.vault(kept), Some(PathBuf::from("kept")));
    }
}
