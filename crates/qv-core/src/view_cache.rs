// SPDX-License-Identifier: AGPL-3.0-or-later

//! Evictable confidential view text. Structural validity never depends on residency.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use qv_crypto::RecordId;
use qv_model::VersionId;

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

/// Cache entries are evicted in record-ID order. Readers never retain a cache borrow.
pub(crate) struct ViewCache {
    entries: RefCell<BTreeMap<RecordId, (VersionId, ViewRef)>>,
    budget: Arc<TextBudget>,
    cache_limit: usize,
    owned: Cell<usize>,
}

impl ViewCache {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            entries: RefCell::new(BTreeMap::new()),
            budget: Arc::new(TextBudget {
                used: AtomicUsize::new(0),
                limit: crate::index::MAX_VIEW_BYTES,
            }),
            cache_limit: limit.min(crate::index::MAX_VIEW_BYTES),
            owned: Cell::new(0),
        }
    }

    pub(crate) fn get(&self, id: RecordId, version: VersionId) -> Option<ViewRef> {
        self.entries
            .borrow()
            .get(&id)
            .filter(|(v, _)| *v == version)
            .map(|(_, data)| Arc::clone(data))
    }

    pub(crate) fn invalidate(&self, id: RecordId) {
        if let Some((_, view)) = self.entries.borrow_mut().remove(&id) {
            self.owned
                .set(self.owned.get().saturating_sub(view.bytes()));
        }
    }

    /// Makes room without revoking existing readers; their leases remain charged.
    pub(crate) fn reserve(&self, bytes: usize) -> Option<TextLease> {
        if bytes > self.budget.limit {
            return None;
        }
        loop {
            if let Some(lease) = self.budget.reserve(bytes) {
                return Some(lease);
            }
            self.evict()?;
        }
    }

    fn evict(&self) -> Option<()> {
        let (_, (_, view)) = self.entries.borrow_mut().pop_first()?;
        self.owned
            .set(self.owned.get().saturating_sub(view.bytes()));
        Some(())
    }

    pub(crate) fn put(&self, id: RecordId, version: VersionId, view: ViewData) -> ViewRef {
        self.invalidate(id);
        let bytes = view.bytes();
        let lease = if bytes <= self.cache_limit {
            while self.owned.get().saturating_add(bytes) > self.cache_limit {
                if self.evict().is_none() {
                    break;
                }
            }
            self.reserve(bytes)
        } else {
            None
        };
        let cacheable = lease.is_some();
        let data = Arc::new(CachedView {
            view,
            _lease: lease,
        });
        if cacheable {
            self.owned.set(self.owned.get().saturating_add(bytes));
            self.entries
                .borrow_mut()
                .insert(id, (version, Arc::clone(&data)));
        }
        data
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.owned.get()
    }

    #[cfg(test)]
    pub(crate) fn total_bytes(&self) -> usize {
        self.budget.used.load(Ordering::Acquire)
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
        );
        let b = cache.put(
            RecordId::generate().unwrap(),
            VersionId::generate().unwrap(),
            row(),
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
}
