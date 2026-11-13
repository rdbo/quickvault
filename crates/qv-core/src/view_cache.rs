// SPDX-License-Identifier: AGPL-3.0-or-later

//! Evictable confidential view text. Structural validity never depends on residency.
//! Labels (normalized short text) outlive full views; scans never evict (0004 §7.3).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use qv_crypto::RecordId;
use qv_model::VersionId;
use zeroize::Zeroizing;

use crate::index::ViewData;

/// Counts text until its last reader or cursor drops, including evicted readers.
pub(crate) struct TextBudget {
    used: AtomicUsize,
    limit: usize,
}

pub(crate) struct TextLease {
    budget: Arc<TextBudget>,
    bytes: usize,
}

impl Drop for TextLease {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl TextBudget {
    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<TextLease> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(bytes).filter(|v| *v <= self.limit)?;
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(TextLease {
                        budget: Arc::clone(self),
                        bytes,
                    });
                }
                Err(actual) => used = actual,
            }
        }
    }
}

/// An immutable cached view; a transient uncacheable row has no cache lease.
pub(crate) struct CachedView {
    view: ViewData,
    _lease: Option<TextLease>,
}

impl Deref for CachedView {
    type Target = ViewData;
    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

pub(crate) type ViewRef = Arc<CachedView>;

/// What paged scans sort and filter by (0004 §7.3): normalized copies of a
/// view's short text. Searchable field values are never part of a label.
pub(crate) enum Label {
    Entry {
        /// The lowercased title.
        title: Zeroizing<String>,
        /// The index of the type hint's bucket in [`crate::paging::TYPE_BUCKETS`].
        bucket: u8,
    },
    Group {
        /// The lowercased name.
        name: Zeroizing<String>,
        /// The order key, unchanged.
        order: Zeroizing<String>,
    },
    Other,
}

impl Label {
    pub(crate) fn bytes(&self) -> usize {
        match self {
            Self::Entry { title, .. } => title.capacity(),
            Self::Group { name, order } => name.capacity() + order.capacity(),
            Self::Other => 0,
        }
    }
}

pub(crate) struct CachedLabel {
    label: Label,
    _lease: Option<TextLease>,
}

impl Deref for CachedLabel {
    type Target = Label;
    fn deref(&self) -> &Self::Target {
        &self.label
    }
}

pub(crate) type LabelRef = Arc<CachedLabel>;

/// How a read uses the cache. A [`Access::Scan`] visits many records once,
/// so it is admitted only into free space and never evicts (0004 §7.3); a
/// [`Access::Point`] read (a row, a detail, an edit) may evict older views.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Scan,
    Point,
}

trait Charged {
    fn size(&self) -> usize;
}
impl Charged for CachedView {
    fn size(&self) -> usize {
        self.view.bytes()
    }
}
impl Charged for CachedLabel {
    fn size(&self) -> usize {
        self.label.bytes()
    }
}

/// One tier, evicted oldest-inserted first.
struct Tier<T> {
    entries: BTreeMap<RecordId, (VersionId, Arc<T>, u64)>,
    order: BTreeMap<u64, RecordId>,
    owned: usize,
}

impl<T: Charged> Tier<T> {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            order: BTreeMap::new(),
            owned: 0,
        }
    }

    fn get(&self, id: RecordId, version: VersionId) -> Option<Arc<T>> {
        self.entries
            .get(&id)
            .filter(|(v, ..)| *v == version)
            .map(|(_, data, _)| Arc::clone(data))
    }

    fn remove(&mut self, id: RecordId) {
        if let Some((_, data, seq)) = self.entries.remove(&id) {
            self.order.remove(&seq);
            self.owned = self.owned.saturating_sub(data.size());
        }
    }

    fn evict(&mut self) -> Option<()> {
        let (_, id) = self.order.pop_first()?;
        if let Some((_, data, _)) = self.entries.remove(&id) {
            self.owned = self.owned.saturating_sub(data.size());
        }
        Some(())
    }

    fn insert(&mut self, id: RecordId, version: VersionId, data: Arc<T>, seq: u64) {
        self.owned = self.owned.saturating_add(data.size());
        self.order.insert(seq, id);
        self.entries.insert(id, (version, data, seq));
    }
}

/// Cached views and labels share one owned-text limit and the 64 MiB
/// budget. Views are evicted before labels, each tier oldest first.
/// Readers never retain a cache borrow.
pub(crate) struct ViewCache {
    views: RefCell<Tier<CachedView>>,
    labels: RefCell<Tier<CachedLabel>>,
    budget: Arc<TextBudget>,
    cache_limit: usize,
    seq: Cell<u64>,
}

impl ViewCache {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            views: RefCell::new(Tier::new()),
            labels: RefCell::new(Tier::new()),
            budget: Arc::new(TextBudget {
                used: AtomicUsize::new(0),
                limit: crate::index::MAX_VIEW_BYTES,
            }),
            cache_limit: limit.min(crate::index::MAX_VIEW_BYTES),
            seq: Cell::new(0),
        }
    }

    fn owned(&self) -> usize {
        self.views
            .borrow()
            .owned
            .saturating_add(self.labels.borrow().owned)
    }

    fn next_seq(&self) -> u64 {
        let seq = self.seq.get();
        self.seq.set(seq.wrapping_add(1));
        seq
    }

    pub(crate) fn get(&self, id: RecordId, version: VersionId) -> Option<ViewRef> {
        self.views.borrow().get(id, version)
    }

    pub(crate) fn label(&self, id: RecordId, version: VersionId) -> Option<LabelRef> {
        self.labels.borrow().get(id, version)
    }

    pub(crate) fn invalidate(&self, id: RecordId) {
        self.views.borrow_mut().remove(id);
        self.labels.borrow_mut().remove(id);
    }

    /// Makes room without revoking existing readers; their leases remain charged.
    pub(crate) fn reserve(&self, bytes: usize) -> Option<TextLease> {
        self.reserve_evicting(bytes, true)
    }

    fn reserve_evicting(&self, bytes: usize, labels: bool) -> Option<TextLease> {
        if bytes > self.budget.limit {
            return None;
        }
        loop {
            if let Some(lease) = self.budget.reserve(bytes) {
                return Some(lease);
            }
            self.evict(labels)?;
        }
    }

    fn evict(&self, labels: bool) -> Option<()> {
        self.views.borrow_mut().evict().or_else(|| {
            if labels {
                self.labels.borrow_mut().evict()
            } else {
                None
            }
        })
    }

    /// Caches `view` if it fits under `access`'s rules; otherwise it is
    /// returned transient, without a cache lease. Views never evict labels.
    pub(crate) fn put(
        &self,
        id: RecordId,
        version: VersionId,
        view: ViewData,
        access: Access,
    ) -> ViewRef {
        self.views.borrow_mut().remove(id);
        let bytes = view.bytes();
        let lease = if bytes <= self.cache_limit {
            let mut room = true;
            while self.owned().saturating_add(bytes) > self.cache_limit {
                if access == Access::Scan || self.views.borrow_mut().evict().is_none() {
                    room = false;
                    break;
                }
            }
            if !room {
                None
            } else if access == Access::Scan {
                self.budget.reserve(bytes)
            } else {
                self.reserve_evicting(bytes, false)
            }
        } else {
            None
        };
        let cacheable = lease.is_some();
        let data = Arc::new(CachedView {
            view,
            _lease: lease,
        });
        if cacheable {
            let seq = self.next_seq();
            self.views
                .borrow_mut()
                .insert(id, version, Arc::clone(&data), seq);
        }
        data
    }

    /// Caches a label, evicting views and then older labels as needed.
    pub(crate) fn put_label(&self, id: RecordId, version: VersionId, label: Label) -> LabelRef {
        self.labels.borrow_mut().remove(id);
        let bytes = label.bytes();
        let lease = if bytes <= self.cache_limit {
            while self.owned().saturating_add(bytes) > self.cache_limit {
                if self.evict(true).is_none() {
                    break;
                }
            }
            self.reserve(bytes)
        } else {
            None
        };
        let cacheable = lease.is_some();
        let data = Arc::new(CachedLabel {
            label,
            _lease: lease,
        });
        if cacheable {
            let seq = self.next_seq();
            self.labels
                .borrow_mut()
                .insert(id, version, Arc::clone(&data), seq);
        }
        data
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.owned()
    }

    #[cfg(test)]
    pub(crate) fn total_bytes(&self) -> usize {
        self.budget.used.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn resident(&self) -> (usize, usize) {
        (
            self.views.borrow().entries.len(),
            self.labels.borrow().entries.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qv_model::{RandomId, Text};

    fn row() -> ViewData {
        ViewData::Group(crate::index::GroupInfo {
            name: Text::new("12345678").unwrap(),
            order: Text::new("").unwrap(),
            icon: None,
            parent: None,
            deleted_at: None,
            delete_operation: None,
        })
    }

    // 0012 §1: Budget inconsistency
    #[test]
    fn evicted_readers_remain_charged_until_their_text_is_dropped() {
        let cache = ViewCache::new(8);
        let a = cache.put(
            RecordId::generate().unwrap(),
            VersionId::generate().unwrap(),
            row(),
            Access::Point,
        );
        let b = cache.put(
            RecordId::generate().unwrap(),
            VersionId::generate().unwrap(),
            row(),
            Access::Point,
        );
        assert_eq!(cache.bytes(), 8);
        assert_eq!(cache.total_bytes(), 16);
        assert!(cache.reserve(crate::index::MAX_VIEW_BYTES - 8).is_none());
        assert_eq!(cache.bytes(), 0);
        assert_eq!(cache.total_bytes(), 16);
        drop(a);
        let lease = cache.reserve(crate::index::MAX_VIEW_BYTES - 8).unwrap();
        assert_eq!(cache.total_bytes(), crate::index::MAX_VIEW_BYTES);
        drop(lease);
        drop(b);
        assert_eq!(cache.total_bytes(), 0);
    }

    fn ids() -> (RecordId, VersionId) {
        (
            RecordId::generate().unwrap(),
            VersionId::generate().unwrap(),
        )
    }

    fn label(text: &str) -> Label {
        Label::Entry {
            title: Zeroizing::new(text.to_owned()),
            bucket: 0,
        }
    }

    #[test]
    fn scans_never_evict_resident_views() {
        let cache = ViewCache::new(8);
        let (a, av) = ids();
        let (b, bv) = ids();
        drop(cache.put(a, av, row(), Access::Scan));
        // Full: a scan read is returned but not admitted.
        let transient = cache.put(b, bv, row(), Access::Scan);
        assert_eq!(transient.bytes(), 8);
        assert!(cache.get(a, av).is_some());
        assert!(cache.get(b, bv).is_none());
        // A point read may evict the oldest view.
        drop(cache.put(b, bv, row(), Access::Point));
        assert!(cache.get(a, av).is_none());
        assert!(cache.get(b, bv).is_some());
        drop(transient);
        assert_eq!(cache.total_bytes(), 8);
    }

    #[test]
    fn labels_outlive_views_and_views_never_evict_labels() {
        let cache = ViewCache::new(16);
        let (a, av) = ids();
        let (b, bv) = ids();
        let (c, cv) = ids();
        drop(cache.put(a, av, row(), Access::Point));
        drop(cache.put_label(b, bv, label("12345678")));
        assert_eq!(cache.resident(), (1, 1));
        // A new label evicts the view, not the older label.
        drop(cache.put_label(c, cv, label("abcdefgh")));
        assert_eq!(cache.resident(), (0, 2));
        // A view does not evict labels to fit: it stays transient.
        drop(cache.put(a, av, row(), Access::Point));
        assert_eq!(cache.resident(), (0, 2));
        assert!(cache.label(b, bv).is_some() && cache.label(c, cv).is_some());
        // Only a stale version misses.
        assert!(cache.label(b, cv).is_none());
        cache.invalidate(b);
        assert!(cache.label(b, bv).is_none());
        assert_eq!(cache.bytes(), 8);
    }
}
