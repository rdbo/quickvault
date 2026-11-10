// SPDX-License-Identifier: AGPL-3.0-or-later

//! Three bounded view lanes, one worker and one replaceable request per lane.
//! Late/cancelled results cannot repopulate an invalidated workspace.

use qv_core::{CancelToken, CoreError, GroupHandle, ItemFilter, PageLimit, Session, ViewCursor};
use std::sync::{Arc, atomic::Ordering};
use zeroize::Zeroizing;

use crate::controller::{AppError, Controller, FormEpoch, Phase};
use crate::views::{ConflictRow, EntryRow, GroupRow, ItemRow, TrashRow};

type Z = Zeroizing<String>;

/// Rows sharing one cache slot. Popovers may temporarily preempt a lower-priority owner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lane {
    Main = 0,
    Groups = 1,
    Kinds = 2,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Owner {
    lane: Lane,
    priority: u8,
    id: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Spec {
    Items {
        group: Option<GroupHandle>,
        kind: Option<Z>,
        query: Z,
        recovered: bool,
        full_search: bool,
    },
    Groups {
        parent: Option<GroupHandle>,
        query: Z,
    },
    Kinds,
    Search(Z),
    Trash,
    Conflicts,
    Autofill(qv_core::platform::autofill::Requester),
}

#[derive(Clone, PartialEq)]
pub(crate) struct KindRow {
    pub(crate) kind: Z,
    pub(crate) count: usize,
}

pub(crate) enum Rows {
    Items {
        items: Vec<ItemRow>,
        groups: Vec<GroupRow>,
    },
    Groups(Vec<GroupRow>),
    Kinds(Vec<KindRow>),
    Search {
        groups: Vec<GroupRow>,
        entries: Vec<EntryRow>,
    },
    Trash(Vec<TrashRow>),
    Conflicts(Vec<ConflictRow>),
    Autofill(Vec<qv_core::autofill::FillCandidate>),
}

pub(crate) struct Page {
    pub(crate) rows: Rows,
    pub(crate) next: Option<ViewCursor>,
    pub(crate) previous: Option<ViewCursor>,
    pub(crate) revision: u64,
}

impl PartialEq for Page {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

#[derive(Clone, PartialEq)]
pub(crate) struct Read {
    pub(crate) page: Option<Arc<Page>>,
    pub(crate) loading: bool,
    pub(crate) error: Option<AppError>,
    pub(crate) serial: u64,
}

struct Job {
    spec: Spec,
    cursor: Option<ViewCursor>,
    serial: u64,
    cancel: CancelToken,
    revision: u64,
}

#[derive(Default)]
struct Slot {
    owner: Option<Owner>,
    spec: Option<Spec>,
    revision: Option<u64>,
    serial: u64,
    ready: Option<Arc<Page>>,
    error: Option<AppError>,
    running: bool,
    cancel: Option<CancelToken>,
    pending: Option<Job>,
}
impl Slot {
    fn clear(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        if let Some(job) = self.pending.take() {
            job.cancel.cancel();
        }
        self.ready = None;
        self.error = None;
        self.spec = None;
        self.revision = None;
        self.serial = self.serial.wrapping_add(1);
    }
    fn request(&mut self, spec: Spec, revision: u64, cursor: Option<ViewCursor>) {
        self.clear();
        self.spec = Some(spec.clone());
        self.revision = Some(revision);
        self.pending = Some(Job {
            spec,
            revision,
            cursor,
            serial: self.serial,
            cancel: CancelToken::new(),
        });
    }
    fn snapshot(&self) -> Read {
        Read {
            page: self.ready.clone(),
            loading: self.running || self.pending.is_some(),
            error: self.error,
            serial: self.serial,
        }
    }
}

/// At most three cached pages and three active view workers; no page history.
#[derive(Default)]
pub(crate) struct Reads {
    slots: [Slot; 3],
}
impl Reads {
    #[cfg(test)]
    pub(crate) fn main_items(&self) -> usize {
        match self.slots[Lane::Main as usize]
            .ready
            .as_deref()
            .map(|p| &p.rows)
        {
            Some(Rows::Items { items, .. }) => items.len(),
            _ => 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        for slot in &mut self.slots {
            slot.clear();
            slot.owner = None;
            slot.running = false;
        }
    }
}

impl Spec {
    fn load(
        &self,
        session: &Session,
        cursor: Option<ViewCursor>,
        cancel: &CancelToken,
    ) -> Result<Page, CoreError> {
        let limit = PageLimit::default();
        Ok(match self {
            Self::Items {
                group,
                kind,
                query,
                recovered,
                full_search,
            } => {
                if let Some(group) = group
                    && kind.is_none()
                    && !recovered
                    && !full_search
                {
                    let page = session.browse_items_page(*group, query, cursor, limit, cancel)?;
                    let mut groups = Vec::new();
                    let mut items = Vec::new();
                    for hit in page.items {
                        match hit {
                            qv_core::SearchHit::Group(g) => {
                                groups.push(crate::views::group_row(&g))
                            }
                            qv_core::SearchHit::Entry(e) => items.push(crate::views::paged_item(e)),
                        }
                    }
                    Page {
                        rows: Rows::Items { items, groups },
                        next: page.next,
                        previous: page.previous,
                        revision: page.revision,
                    }
                } else {
                    let page = session.items_page(
                        ItemFilter {
                            group: *group,
                            kind: kind.as_deref().map(String::as_str),
                            text: Some(query.as_str()),
                            recovered: *recovered,
                            search_all_fields: *full_search,
                        },
                        cursor,
                        limit,
                        cancel,
                    )?;
                    Page {
                        rows: Rows::Items {
                            items: page
                                .items
                                .into_iter()
                                .map(crate::views::paged_item)
                                .collect(),
                            groups: Vec::new(),
                        },
                        next: page.next,
                        previous: page.previous,
                        revision: page.revision,
                    }
                }
            }
            Self::Groups { parent, query } => {
                let page = session.groups_page(*parent, query, cursor, limit, cancel)?;
                Page {
                    rows: Rows::Groups(page.items.iter().map(crate::views::group_row).collect()),
                    next: page.next,
                    previous: page.previous,
                    revision: page.revision,
                }
            }
            Self::Kinds => {
                let page = session.kinds_page(cursor, limit, cancel)?;
                Page {
                    rows: Rows::Kinds(
                        page.items
                            .into_iter()
                            .map(|r| KindRow {
                                kind: r.kind,
                                count: r.count,
                            })
                            .collect(),
                    ),
                    next: page.next,
                    previous: page.previous,
                    revision: page.revision,
                }
            }
            Self::Autofill(requester) => {
                let page = session.autofill_candidates_page(requester, cursor, limit, cancel)?;
                Page {
                    rows: Rows::Autofill(page.items),
                    next: page.next,
                    previous: page.previous,
                    revision: page.revision,
                }
            }
            Self::Search(query) => {
                if query.is_empty() {
                    return Ok(Page {
                        rows: Rows::Search {
                            groups: Vec::new(),
                            entries: Vec::new(),
                        },
                        next: None,
                        previous: None,
                        revision: session.view_revision()?,
                    });
                }
                let page = session.search_page(query, cursor, limit, cancel)?;
                let mut groups = Vec::new();
                let mut entries = Vec::new();
                for hit in page.items {
                    match hit {
                        qv_core::SearchHit::Group(g) => groups.push(crate::views::group_row(&g)),
                        qv_core::SearchHit::Entry(e) => entries.push(crate::views::entry_row(&e)),
                    }
                }
                Page {
                    rows: Rows::Search { groups, entries },
                    next: page.next,
                    previous: page.previous,
                    revision: page.revision,
                }
            }
            Self::Trash => {
                let page = session.trash_page(cursor, limit, cancel)?;
                Page {
                    rows: Rows::Trash(
                        page.items
                            .into_iter()
                            .map(crate::views::trash_row)
                            .collect(),
                    ),
                    next: page.next,
                    previous: page.previous,
                    revision: page.revision,
                }
            }
            Self::Conflicts => {
                let page = session.conflict_records_page(cursor, limit, cancel)?;
                Page {
                    rows: Rows::Conflicts(
                        page.items
                            .into_iter()
                            .map(crate::views::conflict_row)
                            .collect(),
                    ),
                    next: page.next,
                    previous: page.previous,
                    revision: page.revision,
                }
            }
        })
    }
}

impl Controller {
    pub(crate) fn page_owner(&self, lane: Lane, priority: u8) -> Option<Owner> {
        self.0
            .page_owner
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .ok()
            .map(|id| Owner { lane, priority, id })
    }

    pub(crate) fn release_page(&self, owner: Owner) {
        let mut state = self.state();
        let slot = &mut state.pages.slots[owner.lane as usize];
        if slot.owner.is_some_and(|current| current.id == owner.id) {
            slot.clear();
            slot.owner = None;
            state.revision = state.revision.wrapping_add(1);
        }
    }

    pub(crate) fn page(&self, epoch: FormEpoch, owner: Owner, spec: Spec) -> Option<Read> {
        let (session, generation) = {
            let mut state = self.state();
            if state.epoch != epoch.0 || state.phase != Phase::Unlocked {
                return None;
            }
            let slot = &mut state.pages.slots[owner.lane as usize];
            if slot.owner.is_some_and(|current| {
                current.id != owner.id
                    && (current.priority > owner.priority
                        || current.priority == owner.priority && current.id > owner.id)
            }) {
                return None;
            }
            if slot.owner.is_none_or(|current| current.id != owner.id) {
                slot.clear();
                slot.owner = Some(owner);
            }
            if self.0.working.load(Ordering::SeqCst) {
                return (slot.spec.as_ref() == Some(&spec)).then(|| slot.snapshot());
            }
            (state.session.clone()?, state.lock_gen)
        };
        let revision = match session.view_revision() {
            Ok(revision) => revision,
            Err(error) => {
                return Some(Read {
                    page: None,
                    loading: false,
                    error: Some(error.into()),
                    serial: 0,
                });
            }
        };
        let (start, result) = {
            let mut state = self.state();
            if state.epoch != epoch.0
                || state.lock_gen != generation
                || state.phase != Phase::Unlocked
            {
                return None;
            }
            let slot = &mut state.pages.slots[owner.lane as usize];
            if slot.owner.is_none_or(|current| current.id != owner.id) {
                return None;
            }
            if slot.spec.as_ref() != Some(&spec) || slot.revision != Some(revision) {
                slot.request(spec, revision, None);
            }
            let start = !slot.running && slot.pending.is_some();
            if start {
                slot.running = true;
            }
            (start, slot.snapshot())
        };
        if start {
            self.start_page_worker(epoch, generation, owner.lane, session);
        }
        Some(result)
    }

    /// Turn an existing immutable snapshot; stale revisions are refreshed by the next read.
    pub(crate) fn page_turn(&self, epoch: FormEpoch, owner: Owner, serial: u64, forward: bool) {
        let mut state = self.state();
        if state.epoch != epoch.0 || state.phase != Phase::Unlocked {
            return;
        }
        let slot = &mut state.pages.slots[owner.lane as usize];
        if slot.owner.is_none_or(|current| current.id != owner.id) {
            return;
        }
        if slot.serial != serial {
            return;
        }
        let Some(page) = &slot.ready else { return };
        let cursor = if forward {
            page.next.clone()
        } else {
            page.previous.clone()
        };
        let Some(cursor) = cursor else { return };
        let revision = page.revision;
        let Some(spec) = slot.spec.clone() else {
            return;
        };
        slot.request(spec, revision, Some(cursor));
        state.revision = state.revision.wrapping_add(1);
    }

    fn start_page_worker(
        &self,
        epoch: FormEpoch,
        generation: u64,
        lane: Lane,
        session: Arc<Session>,
    ) {
        let controller = self.clone();
        let spawned = std::thread::Builder::new()
            .name("qv-app-view".into())
            .spawn(move || {
                loop {
                    let job = {
                        let mut state = controller.state();
                        if state.epoch != epoch.0
                            || state.lock_gen != generation
                            || state.phase != Phase::Unlocked
                        {
                            return;
                        }
                        let slot = &mut state.pages.slots[lane as usize];
                        let Some(job) = slot.pending.take() else {
                            slot.running = false;
                            state.revision = state.revision.wrapping_add(1);
                            return;
                        };
                        slot.cancel = Some(job.cancel.clone());
                        job
                    };
                    let result = job.spec.load(&session, job.cursor, &job.cancel);
                    let mut state = controller.state();
                    if state.epoch != epoch.0
                        || state.lock_gen != generation
                        || state.phase != Phase::Unlocked
                    {
                        return;
                    }
                    let slot = &mut state.pages.slots[lane as usize];
                    if slot.serial == job.serial && !job.cancel.is_cancelled() {
                        slot.cancel = None;
                        match result {
                            Ok(page) if page.revision == job.revision => {
                                slot.ready = Some(Arc::new(page));
                                slot.error = None;
                            }
                            Ok(_) => slot.error = Some(AppError::Core(CoreError::StaleHandle)),
                            Err(error) => slot.error = Some(error.into()),
                        }
                        state.revision = state.revision.wrapping_add(1);
                    }
                    // Loop on the same worker for the single replaceable pending request.
                }
            });
        if spawned.is_err() {
            let mut state = self.state();
            if state.epoch == epoch.0 && state.lock_gen == generation {
                let slot = &mut state.pages.slots[lane as usize];
                slot.running = false;
                slot.pending = None;
                slot.error = Some(AppError::Unavailable);
                state.revision = state.revision.wrapping_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_tests::{Env, KDF, PASSWORD};
    use std::time::{Duration, Instant};

    fn items(query: &str) -> Spec {
        Spec::Items {
            group: None,
            kind: None,
            query: Zeroizing::new(query.to_owned()),
            recovered: false,
            full_search: false,
        }
    }
    fn ready(env: &Env, owner: Owner, spec: Spec) -> Arc<Page> {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let read = env.c.page(env.epoch(), owner, spec.clone()).unwrap();
            assert!(read.error.is_none());
            if !read.loading
                && let Some(page) = read.page
            {
                return page;
            }
            assert!(Instant::now() < until, "page worker did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn page_reader_replaces_queries_cancels_on_lock_and_restarts_after_unlock() {
        let _k = KDF.lock().unwrap_or_else(|e| e.into_inner());
        let env = Env::unlocked();
        env.add_entry("Bank", "secret");
        let owner = env.c.page_owner(Lane::Main, 1).unwrap();
        env.c.page(env.epoch(), owner, items("Bank"));
        let page = ready(&env, owner, items("absent"));
        let Rows::Items { items: rows, .. } = &page.rows else {
            panic!("items")
        };
        assert!(rows.is_empty());
        let old_epoch = env.epoch();
        env.c.lock();
        assert!(env.c.page(old_epoch, owner, items("Bank")).is_none());
        assert!(
            env.c
                .state()
                .pages
                .slots
                .iter()
                .all(|s| s.ready.is_none() && !s.running)
        );
        env.unlock(PASSWORD);
        let page = ready(&env, owner, items("Bank"));
        let Rows::Items { items: rows, .. } = &page.rows else {
            panic!("items")
        };
        assert_eq!(rows.len(), 1);
        env.c.release_page(owner);
        assert!(
            env.c.state().pages.slots[Lane::Main as usize]
                .ready
                .is_none()
        );
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn page_reader_preemption_is_bounded_and_previous_pages_need_no_retained_history() {
        let _k = KDF.lock().unwrap_or_else(|e| e.into_inner());
        let env = Env::unlocked();
        env.read(|s| {
            let root = s.root()?;
            for i in 0..40 {
                s.save_entry(s.new_entry(root, "login", &format!("row {i:02}"))?)?;
            }
            Ok(())
        });
        let owner = env.c.page_owner(Lane::Main, 1).unwrap();
        let first = ready(&env, owner, items(""));
        let Rows::Items { items: rows, .. } = &first.rows else {
            panic!("items")
        };
        assert_eq!(rows.len(), 32);
        let serial = env.c.state().pages.slots[Lane::Main as usize].serial;
        env.c.page_turn(env.epoch(), owner, serial, true);
        let second = ready(&env, owner, items(""));
        let Rows::Items { items: rows, .. } = &second.rows else {
            panic!("items")
        };
        assert_eq!(rows.len(), 8);
        let serial = env.c.state().pages.slots[Lane::Main as usize].serial;
        env.c.page_turn(env.epoch(), owner, serial, false);
        let previous = ready(&env, owner, items(""));
        let Rows::Items { items: rows, .. } = &previous.rows else {
            panic!("items")
        };
        assert_eq!(rows.len(), 32);
        // A callback captured on the preceding page cannot turn the current page.
        let stable_serial = env.c.state().pages.slots[Lane::Main as usize].serial;
        env.c.page_turn(env.epoch(), owner, serial, true);
        assert_eq!(
            env.c.state().pages.slots[Lane::Main as usize].serial,
            stable_serial
        );
        let peer = env.c.page_owner(Lane::Main, 1).unwrap();
        ready(&env, peer, items("absent"));
        assert!(env.c.page(env.epoch(), owner, items("")).is_none());
        env.c.release_page(peer);
        ready(&env, owner, items(""));
        let overlay = env.c.page_owner(Lane::Main, 2).unwrap();
        ready(&env, overlay, items("absent"));
        assert!(env.c.page(env.epoch(), owner, items("")).is_none());
        env.c.release_page(overlay);
        let restored = ready(&env, owner, items(""));
        assert!(matches!(&restored.rows, Rows::Items { items, .. } if items.len() == 32));
        assert!(
            env.c
                .state()
                .pages
                .slots
                .iter()
                .filter(|s| s.ready.is_some())
                .count()
                <= 3
        );
    }
}
