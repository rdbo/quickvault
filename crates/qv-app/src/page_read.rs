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
    /// The item list, or a full page (trash, conflicts, autofill).
    Main = 0,
    /// The sidebar's groups.
    Groups = 1,
    /// The sidebar's type counts, and popovers and pickers (command bar,
    /// group choices, autofill links). The shell keeps the five counts as
    /// numbers, so preempting it changes nothing on screen (plan 0051).
    Overlay = 2,
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

/// The main list's window (0004 §7.4, plan 0072): consecutive pages loaded
/// as the list scrolls, so an ordinary vault shows every row. A full window
/// is replaced by the next one ("Show more"), never trimmed while it
/// scrolls: WebKitGTK has no scroll anchoring, so removing rows above the
/// viewport would make the list jump.
pub(crate) const WINDOW_PAGES: usize = 32;
/// Row text the window may hold, a bound beside the page count.
pub(crate) const WINDOW_TEXT: usize = 8 * 1024 * 1024;

impl Rows {
    /// Lists that scroll as one window; others keep one page.
    fn windowed(&self) -> bool {
        matches!(
            self,
            Self::Items { .. } | Self::Trash(_) | Self::Conflicts(_)
        )
    }
    /// Approximate owned row text, for [`WINDOW_TEXT`].
    fn text_bytes(&self) -> usize {
        const ROW: usize = 64;
        match self {
            Self::Items { items, groups } => {
                items
                    .iter()
                    .map(|i| ROW + i.row.title.len() + i.row.subtitle.len())
                    .sum::<usize>()
                    + groups.iter().map(|g| ROW + g.name.len()).sum::<usize>()
            }
            Self::Trash(rows) => rows
                .iter()
                .map(|r| ROW + r.name.len() + r.deleted.as_ref().map_or(0, String::len))
                .sum(),
            Self::Conflicts(rows) => rows
                .iter()
                .map(|r| ROW + r.record.len() + r.name.as_ref().map_or(0, |n| n.len()))
                .sum(),
            _ => 0,
        }
    }
}

/// One page holding a window's rows in order, with the outer cursors.
fn merge(parts: &[Arc<Page>]) -> Option<Arc<Page>> {
    let (first, last) = (parts.first()?, parts.last()?);
    if parts.len() == 1 {
        return Some(first.clone());
    }
    let rows = match &first.rows {
        Rows::Items { .. } => {
            let (mut items, mut groups) = (Vec::new(), Vec::new());
            for part in parts {
                if let Rows::Items {
                    items: i,
                    groups: g,
                } = &part.rows
                {
                    items.extend(i.iter().cloned());
                    groups.extend(g.iter().cloned());
                }
            }
            Rows::Items { items, groups }
        }
        Rows::Trash(_) => Rows::Trash(
            parts
                .iter()
                .flat_map(|p| match &p.rows {
                    Rows::Trash(r) => r.clone(),
                    _ => Vec::new(),
                })
                .collect(),
        ),
        Rows::Conflicts(_) => Rows::Conflicts(
            parts
                .iter()
                .flat_map(|p| match &p.rows {
                    Rows::Conflicts(r) => r.clone(),
                    _ => Vec::new(),
                })
                .collect(),
        ),
        // Not windowed: never more than one part.
        _ => return Some(last.clone()),
    };
    Some(Arc::new(Page {
        rows,
        next: last.next.clone(),
        previous: first.previous.clone(),
        revision: last.revision,
    }))
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
    /// `page` is the owner's previous page, kept on screen while its
    /// replacement loads (plan 0051); see `ui::use_page`.
    pub(crate) stale: bool,
    /// A scrolling window (plan 0072): it starts at the list's first row,
    /// and it can take another page.
    pub(crate) window: Option<(bool, bool)>,
}

struct Job {
    spec: Spec,
    cursor: Option<ViewCursor>,
    serial: u64,
    cancel: CancelToken,
    revision: u64,
    /// Adds a page to the window instead of replacing it.
    append: bool,
}

#[derive(Default)]
struct Slot {
    owner: Option<Owner>,
    spec: Option<Spec>,
    revision: Option<u64>,
    serial: u64,
    ready: Option<Arc<Page>>,
    /// The owner's previous page while its replacement loads (plan 0051), so
    /// a new filter, query, revision or page swaps rows instead of blanking
    /// them. It takes `ready`'s place until the replacement is shown.
    held: Option<Arc<Page>>,
    /// The window's pages; `ready` is their merged view.
    parts: Vec<Arc<Page>>,
    /// The window starts at the list's first row.
    origin: bool,
    /// Pages to reload before showing a replaced window (a revision change
    /// keeps the rows the user had, plan 0072); 0 shows the first page.
    fill: usize,
    /// A smaller page bound for tests.
    #[cfg(test)]
    test_pages: Option<usize>,
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
        self.held = None;
        self.parts.clear();
        self.fill = 0;
        self.error = None;
        self.spec = None;
        self.revision = None;
        self.serial = self.serial.wrapping_add(1);
    }
    fn request(&mut self, spec: Spec, revision: u64, cursor: Option<ViewCursor>) {
        let held = self.ready.take().or_else(|| self.held.take());
        self.clear();
        self.held = held;
        self.origin = cursor.is_none();
        self.spec = Some(spec.clone());
        self.revision = Some(revision);
        self.pending = Some(Job {
            spec,
            revision,
            cursor,
            serial: self.serial,
            cancel: CancelToken::new(),
            append: false,
        });
    }
    /// Whether the window can take another page.
    fn room(&self) -> bool {
        #[cfg(test)]
        let pages = self.test_pages.unwrap_or(WINDOW_PAGES);
        #[cfg(not(test))]
        let pages = WINDOW_PAGES;
        self.parts.len() < pages
            && self
                .parts
                .iter()
                .map(|p| p.rows.text_bytes())
                .sum::<usize>()
                < WINDOW_TEXT
    }
    /// Queues the window's next page, keeping what is shown.
    fn append(&mut self, cursor: ViewCursor) {
        let (Some(spec), Some(revision)) = (self.spec.clone(), self.revision) else {
            return;
        };
        self.pending = Some(Job {
            spec,
            revision,
            cursor: Some(cursor),
            serial: self.serial,
            cancel: CancelToken::new(),
            append: true,
        });
    }
    /// A failed read: a refill shows the pages it already has.
    fn failed(&mut self, error: AppError) {
        if self.fill > 0 && !self.parts.is_empty() {
            self.ready = merge(&self.parts);
        }
        self.held = None;
        self.fill = 0;
        self.error = Some(error);
    }
    /// A loaded page: grows or replaces the window, keeps refilling a
    /// replaced window up to `fill` pages, then shows it.
    fn loaded(&mut self, page: Page, append: bool) {
        let page = Arc::new(page);
        if !append {
            self.parts.clear();
        }
        let windowed = page.rows.windowed();
        self.parts.push(page);
        if windowed
            && self.parts.len() < self.fill
            && self.room()
            && let Some(next) = self.parts.last().and_then(|p| p.next.clone())
        {
            // Still refilling: the held rows stay on screen.
            self.append(next);
            return;
        }
        self.fill = 0;
        self.held = None;
        self.ready = merge(&self.parts);
    }
    fn snapshot(&self) -> Read {
        let loading = self.running || self.pending.is_some();
        let held = self
            .held
            .clone()
            .filter(|_| (loading || self.fill > 0) && self.ready.is_none());
        let window = self
            .ready
            .as_ref()
            .filter(|p| p.rows.windowed())
            .map(|_| (self.origin, self.room()));
        Read {
            // Reloading the same list after a vault change shows its rows as
            // current (no dimming); another list's rows are stale.
            stale: held.is_some() && self.fill == 0,
            page: self.ready.clone().or(held),
            loading,
            error: self.error,
            serial: self.serial,
            window,
        }
    }
}

/// Three lanes and at most three active view workers; no page history. A
/// scrolling list's lane holds its window (at most [`WINDOW_PAGES`] pages),
/// the others one page.
#[derive(Default)]
pub(crate) struct Reads {
    slots: [Slot; 3],
}
impl Reads {
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
                    stale: false,
                    window: None,
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
                // A changed vault reloads the same list as far as it was
                // read, so an edit keeps the user's rows and place.
                let fill = if slot.spec.as_ref() == Some(&spec) && slot.origin {
                    slot.parts.len()
                } else {
                    0
                };
                slot.request(spec, revision, None);
                slot.fill = fill;
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
        let revision = page.revision;
        let Some(spec) = slot.spec.clone() else {
            return;
        };
        if page.rows.windowed() {
            // The window grows as the list scrolls; a full one is replaced
            // by the next ("Show more"), and Back returns to the start.
            if slot.running || slot.pending.is_some() {
                return;
            }
            if !forward {
                if !slot.origin {
                    slot.request(spec, revision, None);
                }
            } else if let Some(next) = page.next.clone() {
                if slot.room() {
                    slot.append(next);
                } else {
                    slot.request(spec, revision, Some(next));
                }
            }
            state.revision = state.revision.wrapping_add(1);
            return;
        }
        let cursor = if forward {
            page.next.clone()
        } else {
            page.previous.clone()
        };
        let Some(cursor) = cursor else { return };
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
                            drop(state);
                            crate::controller::wake_ui();
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
                                slot.loaded(page, job.append);
                                slot.error = None;
                            }
                            Ok(_) => {
                                slot.failed(AppError::Core(CoreError::StaleHandle));
                            }
                            Err(error) => slot.failed(error.into()),
                        }
                        state.revision = state.revision.wrapping_add(1);
                        drop(state);
                        crate::controller::wake_ui();
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
                slot.held = None;
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

    /// The wake flag is process-wide: tests that consume it take turns.
    static WAKE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_wake_reaches_the_ui_poll_at_once() {
        let _w = WAKE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        crate::controller::wake_ui();
        let start = Instant::now();
        assert!(crate::controller::wait_ui(Duration::from_secs(5)));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_finished_page_wakes_the_ui_poll_before_its_tick() {
        let _w = WAKE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let _k = KDF.lock().unwrap_or_else(|e| e.into_inner());
        let env = Env::unlocked();
        env.add_entry("Bank", "secret");
        let owner = env.c.page_owner(Lane::Main, 1).unwrap();
        env.c.page(env.epoch(), owner, items("Bank")).unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            // Drop older wakes, then check: a worker that finishes after the
            // check leaves its wake set, so the wait below cannot miss it.
            while crate::controller::wait_ui(Duration::ZERO) {}
            let read = env.c.page(env.epoch(), owner, items("Bank")).unwrap();
            if !read.loading {
                assert!(read.page.is_some());
                return;
            }
            let start = Instant::now();
            assert!(crate::controller::wait_ui(Duration::from_secs(5)));
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(Instant::now() < until, "page worker did not finish");
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

    #[test]
    fn a_new_request_keeps_the_previous_page_until_its_replacement_lands() {
        let _k = KDF.lock().unwrap_or_else(|e| e.into_inner());
        let env = Env::unlocked();
        env.add_entry("Bank", "one");
        env.add_entry("Mail", "two");
        let owner = env.c.page_owner(Lane::Main, 1).unwrap();
        let all = ready(&env, owner, items(""));
        // The filter changes: the old rows stay, marked stale, while the
        // request is queued (the worker starts after this snapshot).
        let read = env.c.page(env.epoch(), owner, items("bank")).unwrap();
        assert!(read.loading && read.stale);
        assert!(read.page.as_ref().is_some_and(|p| Arc::ptr_eq(p, &all)));
        let bank = ready(&env, owner, items("bank"));
        assert!(matches!(&bank.rows, Rows::Items { items, .. } if items.len() == 1));
        let read = env.c.page(env.epoch(), owner, items("bank")).unwrap();
        assert!(!read.stale);
        // The lane holds one page: the held one went when the new one landed.
        assert!(
            env.c.state().pages.slots[Lane::Main as usize]
                .held
                .is_none()
        );
        // A popover (command bar, group picker) reads in the overlay lane and
        // leaves the list's page in place.
        let popover = env.c.page_owner(Lane::Overlay, 2).unwrap();
        ready(
            &env,
            popover,
            Spec::Search(Zeroizing::new("mail".to_owned())),
        );
        let read = env.c.page(env.epoch(), owner, items("bank")).unwrap();
        assert!(!read.loading && read.page.as_ref().is_some_and(|p| Arc::ptr_eq(p, &bank)));
        env.c.release_page(popover);
        drop((all, bank, read));
        // Lock drops everything, held page included.
        let epoch = env.epoch();
        env.c.page_turn(epoch, owner, 0, true);
        env.c.page(epoch, owner, items(""));
        env.c.lock();
        assert!(env.c.page(epoch, owner, items("")).is_none());
        assert!(
            env.c
                .state()
                .pages
                .slots
                .iter()
                .all(|s| s.ready.is_none() && s.held.is_none())
        );
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn page_reader_preemption_is_bounded_and_previous_pages_need_no_retained_history() {
        let _k = KDF.lock().unwrap_or_else(|e| e.into_inner());
        let env = Env::unlocked();
        // Groups are not a scrolling window: they turn page by page.
        let root = env.read(|s| s.root());
        env.read(|s| {
            for i in 0..40 {
                s.save_group(s.new_group(root, &format!("group {i:02}"))?)?;
            }
            Ok(())
        });
        let groups = || Spec::Groups {
            parent: Some(root),
            query: Zeroizing::new(String::new()),
        };
        let count = |p: &Page| match &p.rows {
            Rows::Groups(g) => g.len(),
            _ => panic!("groups"),
        };
        let owner = env.c.page_owner(Lane::Main, 1).unwrap();
        let first = ready(&env, owner, groups());
        assert_eq!(count(&first), 32);
        let serial = env.c.state().pages.slots[Lane::Main as usize].serial;
        env.c.page_turn(env.epoch(), owner, serial, true);
        let second = ready(&env, owner, groups());
        assert_eq!(count(&second), 8);
        let serial = env.c.state().pages.slots[Lane::Main as usize].serial;
        env.c.page_turn(env.epoch(), owner, serial, false);
        let previous = ready(&env, owner, groups());
        assert_eq!(count(&previous), 32);
        // A callback captured on the preceding page cannot turn the current page.
        let stable_serial = env.c.state().pages.slots[Lane::Main as usize].serial;
        env.c.page_turn(env.epoch(), owner, serial, true);
        assert_eq!(
            env.c.state().pages.slots[Lane::Main as usize].serial,
            stable_serial
        );
        let peer = env.c.page_owner(Lane::Main, 1).unwrap();
        ready(&env, peer, items("absent"));
        assert!(env.c.page(env.epoch(), owner, groups()).is_none());
        env.c.release_page(peer);
        ready(&env, owner, groups());
        let overlay = env.c.page_owner(Lane::Main, 2).unwrap();
        ready(&env, overlay, items("absent"));
        assert!(env.c.page(env.epoch(), owner, groups()).is_none());
        env.c.release_page(overlay);
        let restored = ready(&env, owner, groups());
        assert_eq!(count(&restored), 32);
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

    fn rows(page: &Page) -> usize {
        match &page.rows {
            Rows::Items { items, .. } => items.len(),
            _ => panic!("items"),
        }
    }
    fn slot(env: &Env) -> std::sync::MutexGuard<'_, crate::controller::State> {
        env.c.state()
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn the_item_window_grows_as_the_list_scrolls_and_keeps_its_rows_across_an_edit() {
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
        assert_eq!(rows(&first), 32);
        let read = env.c.page(env.epoch(), owner, items("")).unwrap();
        assert_eq!(read.window, Some((true, true)), "at the start, with room");
        // Scrolling to the end appends the next page to the same window.
        let serial = read.serial;
        env.c.page_turn(env.epoch(), owner, serial, true);
        let read = env.c.page(env.epoch(), owner, items("")).unwrap();
        assert!(
            read.loading && !read.stale,
            "the shown rows stay while it loads"
        );
        assert!(read.page.as_ref().is_some_and(|p| Arc::ptr_eq(p, &first)));
        let all = ready(&env, owner, items(""));
        assert_eq!(rows(&all), 40);
        assert!(all.next.is_none());
        assert_eq!(slot(&env).pages.slots[Lane::Main as usize].parts.len(), 2);
        // At the start, Back does nothing; a stale callback turns nothing.
        env.c.page_turn(env.epoch(), owner, serial, false);
        env.c
            .page_turn(env.epoch(), owner, serial.wrapping_sub(1), true);
        assert!(
            slot(&env).pages.slots[Lane::Main as usize]
                .pending
                .is_none()
        );
        // An edit reloads the window as far as it was read, showing the old
        // rows as current (not dimmed) until the whole window is back.
        env.add_entry("row 99", "secret");
        let read = env.c.page(env.epoch(), owner, items("")).unwrap();
        assert!(read.loading && !read.stale);
        assert!(read.page.as_ref().is_some_and(|p| Arc::ptr_eq(p, &all)));
        let after = ready(&env, owner, items(""));
        assert_eq!(rows(&after), 41, "both pages reloaded before showing");
        // Another list starts from its first page; a lock drops the window.
        let other = ready(&env, owner, items("row 0"));
        assert_eq!(rows(&other), 10);
        env.c.lock();
        assert!(
            slot(&env)
                .pages
                .slots
                .iter()
                .all(|s| s.parts.is_empty() && s.ready.is_none() && s.held.is_none())
        );
    }

    #[test]
    fn a_full_window_is_replaced_by_the_next_and_back_returns_to_the_start() {
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
        ready(&env, owner, items(""));
        slot(&env).pages.slots[Lane::Main as usize].test_pages = Some(1);
        let read = env.c.page(env.epoch(), owner, items("")).unwrap();
        assert_eq!(read.window, Some((true, false)), "full: Show more");
        env.c.page_turn(env.epoch(), owner, read.serial, true);
        let rest = ready(&env, owner, items(""));
        assert_eq!(rows(&rest), 8, "the next window replaces the full one");
        let read = env.c.page(env.epoch(), owner, items("")).unwrap();
        assert_eq!(
            read.window.map(|w| w.0),
            Some(false),
            "Back to the start offered"
        );
        env.c.page_turn(env.epoch(), owner, read.serial, false);
        let start = ready(&env, owner, items(""));
        assert_eq!(rows(&start), 32);
        let read = env.c.page(env.epoch(), owner, items("")).unwrap();
        assert_eq!(read.window.map(|w| w.0), Some(true));
    }

    #[test]
    fn the_window_is_bounded_by_pages_and_by_row_text() {
        let page = |text: usize| {
            Arc::new(Page {
                rows: Rows::Conflicts(vec![crate::views::ConflictRow {
                    record: "r".repeat(text),
                    kind: "entry",
                    name: None,
                    versions: 2,
                }]),
                next: None,
                previous: None,
                revision: 0,
            })
        };
        let mut s = Slot {
            parts: (0..WINDOW_PAGES - 1).map(|_| page(10)).collect(),
            ..Slot::default()
        };
        assert!(s.room());
        s.parts.push(page(10));
        assert!(!s.room(), "at most {WINDOW_PAGES} pages");
        s.parts = vec![page(WINDOW_TEXT / 2), page(WINDOW_TEXT / 2)];
        assert!(!s.room(), "at most {WINDOW_TEXT} bytes of row text");
        let merged = merge(&s.parts).unwrap();
        assert!(matches!(&merged.rows, Rows::Conflicts(r) if r.len() == 2));
        assert!(merge(&[]).is_none());
    }
}
