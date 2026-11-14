# Plan 0053 — Performance: unlock, paged views, search and bulk changes

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed — approved 2026-11-14 (REVIEW.md); phone run pending | 2026-11-13 | 2026-11-13 (owner request; design owner-delegated, standing 2026-11-02) | 0004 §7.2–7.3 (amended, step 1); 0008 §2, §6 (amended, step 1); 0012 §1 |

## Intent

The owner (2026-11-13): "Let's try improving performance. Of course, avoiding
openings for side channel attacks. Let's make a full step for performance
improvements, including the search and memory thing." The search item is the
0048 phone result: a complete search of 180 rows / 135 MiB took 70.9 s, and a
complete traversal with no query took 70.6 s. The memory item is 0048 step 3:
bulk changes hold every affected record decoded until commit, about 140 MiB
extra at 180 rows (CAPACITY.md). Make both fast and bounded, with the same
results, the same atomicity and no new leak.

## Scope

**In scope:**
- Baseline and repeat measurements with a checked-in harness (host; phone when
  the owner connects it).
- Unlock: decode each head once instead of up to three times.
- Paged views: resident label tier, scan-resistant cache admission,
  allocation-free case folding for ASCII text.
- Search: text-free per-query match sets and query refinement, so a complete
  paged search runs one matching pass instead of one per page.
- Bulk changes: stage changed records one at a time inside the existing
  single transaction.

**Out of scope:**
- KDF parameters, crypto profiles, AEAD, the verification coverage at unlock,
  and any vault, archive, LAN or wire format change.
- Any on-disk search index, blind index, token hashes or plaintext cache.
- Chunked commits or any change to all-or-nothing behaviour.
- LAN sync throughput, attachment streaming and app rendering. The app gains
  through `qv-core` alone. App-specific profiling is a later plan if the
  owner still sees lag.
- Store read micro-optimizations (cached subkeys, cached prepared
  statements). HKDF and statement preparation cost microseconds per read,
  against milliseconds of AEAD for large records. Record them in PERF.md
  only if step 2 profiling shows them above 5% of traversal time.
- Raising or lowering any budget (0004 §4, §7.1). 0004 OQ1 stays open.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Unlock authenticates and validates every required object; one head decoded at a time | 0004 §7.2 | Accepted | Step 1 allows the verification pass to hand each authenticated head to the index builder |
| 64 MiB owned-text ceiling for cache, sort, query and cursor text | 0004 §7.1, §7.3 | Accepted | Unchanged; the new label tier and folded copies count against it |
| Top-k selection, no all-results plaintext accumulation | 0004 §7.3 | Accepted | Step 1 adds text-free match sets (record IDs only), held by the session, never in cursors |
| Same case-insensitive matching and ordering | 0004 §7.3 | Accepted | Unchanged; the fast path must equal `str::to_lowercase` results |
| 16 records per session read, cancellation, stale revisions | 0004 §7.3 | Accepted | Unchanged |
| Zeroize query/sort/cursor/cache buffers; no persistent plaintext index | 0008 §6 | Draft, §6 approved for 0047 | Step 1 adds match sets and the label tier to the list |
| Constant-time crypto comparisons | 0008 §2 | Draft | Step 1 adds one sentence: performance paths add no secret-dependent comparison or early exit on protected values, keys or MACs |
| Bulk changes are one atomic commit; durable and anchor-pending outcomes | 0004 §5, 0005 §5.4 | Accepted | Unchanged; only the preparation order changes |

**Spec changes required:** step 1 amends 0004 §7.2 and §7.3 and 0008 §2 and
§6, with Changelog lines and a `specs/README.md` note. These are
owner-delegated amendments to an Accepted spec (standing delegation,
2026-11-02, as in plan 0051). The owner can veto them before implementation
starts.

## Decisions needed

All resolved under the owner's standing delegation (2026-11-02). Recorded here
so the owner can override.

1. **Targets.** The owner set no latency or RSS goal (0048). Delegated
   defaults, measured on the 0048 fixtures with the harness from step 2:
   - complete paged search, 180 rows / 135 MiB: host ≤ 2 s (was 19.0 s),
     phone ≤ 7 s (was 70.9 s);
   - complete paged traversal with no query, 180 rows: phone ≤ 3 s (was
     70.6 s);
   - batch and recursive delete at 180 rows: peak RSS minus pre-operation
     RSS ≤ 32 MiB on the host (was about 140 MiB);
   - no stage on the 30- or 90-row fixtures more than 10% slower than its
     baseline.

   Unlock gets no time target. It gets a deterministic decode count (step 3).
   Timings are development evidence, not a release threshold. Rejected:
   claiming a total-RSS bound (0004 §7.1 forbids it).
2. **Search acceleration.** Chosen: text-free match sets (record IDs of the
   matches) kept in session state, plus a resident label tier. Rejected:
   - a sorted all-results title list inside the cursor: plaintext
     accumulation that §7.3 forbids, and cursors outlive locks in frontends;
   - a persistent encrypted search index: format change, freshness and
     rollback binding, and a new on-disk leak surface before 1.0;
   - blind or keyed token indexes: leak equality patterns and need a format.
3. **Bulk changes.** Chosen: compact prevalidation, then sequential staging
   inside the existing single transaction (CAPACITY.md's first option).
   Rejected:
   - chunked commits: they change all-or-nothing behaviour and cancellation
     outcomes;
   - encrypted private staging: temporary keys, cleanup, disk-full and crash
     complexity, with no gain over sequential staging;
   - two-pass with a full stale-base re-check: needed only if the base could
     change mid-operation, and it cannot, because the session mutex is held
     and the write checks the head (`StoreError::Changed`).
4. **Unlock fusion.** Chosen: the store hands each authenticated head to a
   caller sink during its existing verification pass. Rejected: keeping
   separate passes (three decodes per single-head record).

## Design

**Components touched:** `qv-store` (unlock verification sink, `Write` read
access), `qv-core` (index build, view cache, paging, edit commit path),
`qv-model` untouched. No new trust boundary or crate; frontends unchanged
except for call sites if unlock signatures move. `ARCHITECTURE.md` §3's
qv-core and qv-store text gets the label tier, match sets and unlock sink.

### Security invariants (every step; the reviewer checks each)

1. Nothing new reaches disk. No plaintext, folded text, match set or derived
   token is persisted or put in a temporary file. No format change.
2. Protected values and notes never enter the cache, labels, match sets or
   matching (`index::searchable` unchanged).
3. All new derived text (label tier, folded titles, query copies) lives in
   zeroizing containers. It is charged to the 64 MiB `TextBudget`, including
   allocated capacity and lowercase expansion. Match sets are zeroizing
   `Vec`s of record IDs, bounded by `qv_store::MAX_RECORDS` (50,000 × 16 B
   ≈ 800 KiB). They are also charged to the budget, conservatively.
4. Lock, revision change, session end and a new query or scope discard match
   sets. Lock discards the whole cache, as today. Cursors keep only what they
   hold today. A match set is never reachable from a `ViewCursor` or a page.
5. Unlock still authenticates the manifest and every head before returning a
   session. The sink sees only versions that passed AEAD and `check_head`. If
   unlock fails after the sink saw heads, the caller drops the partial index
   and its zeroizing cache (Rust drop order; covered by a test).
6. Bulk changes stay one SQLite transaction with the same crash points,
   cancellation outcomes and durable/anchor-pending reporting. An error or
   cancellation at any staged record rolls everything back. The index is
   updated only after `local_seq` advances, as today.
7. No comparison on keys, MACs, fingerprints or protected values becomes
   variable-time. Cursor and match-set binding keep `ct_eq` on the query
   fingerprint. Timing of text matching depends on unprotected text and
   query, as it does today; search stays local and generates no network
   traffic (0008 §2).
8. The 16-records-per-read, cancellation-between-heads and stale-revision
   rules of 0004 §7.3 hold on every new path.

### Step 3 — unlock sink

```rust
// qv-store
pub trait HeadSink {
    type Error: From<StoreError>;
    /// One authenticated, role-checked head; `last` is true for a record's final head.
    fn head(&mut self, record: RecordId, version: RecordVersion, last: bool)
        -> Result<(), Self::Error>;
}
pub struct NoSink; // Error = StoreError; existing entry points use it
impl VaultFile {
    pub fn unlock_into<S: HeadSink>(self, password: &MasterPassword, anchors: &AnchorDir, sink: &mut S)
        -> Result<UnlockedVault, S::Error>;
    pub fn unlock_for_recovery_into<S: HeadSink>(..) -> Result<(UnlockedVault, AnchorStatus), S::Error>;
    pub fn unlock_with_phrase_into<S: HeadSink>(..) -> ..;
}
// finish_unlock and load_state gain the sink. Each existing unlock_* keeps its
// signature and calls its *_into twin with NoSink.
```

`load_state` calls `sink.head(...)` in its existing head loop, after
`read_role` and `check_head` succeed, moving the version in. The history
tombstone loop does not call the sink. The other `finish_unlock` callers
(`restore.rs`, `vault_import.rs`) pass `NoSink`; their core callers keep
`Index::build`. `Index::build` stays for paths that index an already-unlocked
vault.

```rust
// qv-core index.rs
pub(crate) struct IndexBuilder { /* Index, per-record HeadSummary vec, held single head, cancel fn */ }
impl HeadSink for IndexBuilder { type Error = CoreError; /* checks cancel per head */ }
impl IndexBuilder {
    pub(crate) fn new(budget: usize, cancelled: &dyn Fn() -> bool) -> Self;
    /// Re-reads only conflicted records' representatives, then retree.
    pub(crate) fn finish(self, vault: &UnlockedVault) -> Result<Index, CoreError>;
}
```

The root and vault-meta IDs come from the manifest, which the sink has not
seen. `Index::new` can take them in `finish`: build the `records` map and
summaries first, assemble `Index` in `finish`. Per record:
- push `HeadSummary::from_version(&v)`;
- if this is the record's only head (`last` on the first call), keep `v`;
  otherwise drop it;
- at `last`, merge the summaries. With one head, `extract` the kept version.
  With several, record the representative's version ID for `finish` to
  re-read and match (`summary.matches_version`, as today).

Logic shared with `from_manifest` moves into one helper so the two builds
cannot diverge. The test `index_refresh_equals_rebuild` is extended to show
that the sink build equals `Index::build`.

Core unlock call sites (`setup.rs` ×4, `quick_unlock.rs`) call the `*_into`
variant with an `IndexBuilder`, then `Session::open_indexed`. `Session::open`
remains for the other callers.

### Step 4 — label tier and cache admission

Split `ViewData::Entry` into a label part and a field part:

```rust
pub(crate) struct EntryLabel { title: Text, title_folded: Text, type_hint: Text,
    icon: Option<Text>, group: RecordId, modified_at, expires_at, deleted_at, delete_operation }
pub(crate) struct EntryFields { fields: Vec<FieldInfo> }   // searchable fields only, as today
// Group and Meta views are labels only; group label adds name_folded.
```

`ViewCache` gets two maps sharing the one `TextBudget`: `labels` and
`fields`. `reserve` evicts from `fields` first, then `labels`. Admission:

```rust
pub(crate) enum Access { Scan, Point }
Index::label(&self, vault, id, Access) -> Result<LabelRef, CoreError>;
Index::fields(&self, vault, id, Access) -> Result<FieldsRef, CoreError>;
```

- A `Point` access (row building, detail, edit, autofill display) inserts and
  may evict in FIFO insertion order.
- A `Scan` access inserts only if it fits without evicting. Otherwise it
  returns the view transient (unleased beyond its own reservation, as
  oversize rows are today).
- A miss on either tier decrypts once and fills both tiers, subject to the
  same admission.

Sequential scans then keep a stable resident set instead of evicting what the
next page needs. During unlock, labels for every record are admitted before
any field text (the builder inserts labels first, fields with `Scan`).
`ViewData::bytes` and the leases count the folded copies. `index::extract`
builds both parts.

`paging::key` reads only the label tier for every scope. It reads the field
tier only when the scope is `Search` or `Items { all_fields: true }` with a
non-empty query whose folded title did not match. `Types` uses
`type_hint` from the label.

### Step 5 — folding fast path

```rust
/// Equal to `s.to_lowercase().contains(q_folded)`; q_folded is already folded.
fn folded_contains(scratch: &mut Zeroizing<Vec<u8>>, s: &str, q_folded: &str) -> bool;
```

If `s.is_ascii()`, copy it into the reused zeroizing scratch, call
`make_ascii_lowercase` and search with `str::contains`, which is linear-time
Two-Way. Otherwise fall back to `to_lowercase`. `str::is_ascii` checks the
whole text: a non-ASCII text can fold to ASCII (U+212A KELVIN SIGN → `k`),
so a query being ASCII is not enough. The scratch is charged once per scan,
at the largest size used, and zeroized on drop. No new dependency.

### Step 6 — match sets and refinement

```rust
// qv-core paging.rs, inside Open (session state, under the session mutex)
struct MatchSet {
    revision: u64,
    scope: Scope,
    fingerprint: Arc<SecretArray<32>>, // same value the cursor binds
    query_folded: BudgetText,          // charged; needed for refinement
    ids: Zeroizing<Vec<[u8; 16]>>,     // ascending record IDs of all matches
    _lease: TextLease,                 // ids.capacity() * 16, conservatively
}
const MAX_MATCH_SETS: usize = 4; // newest kept; the app uses at most three lanes
```

Created by a full scan for a query-bearing scope (`Search`, `Items` with a
query, `GroupItems` with a query, `Groups` with a query). While scanning, push
the ID of every match, not only the top-k.

Lookup at the start of `scan_page`, under the read lock:
- **Continuation:** same revision, scope and `fingerprint.ct_eq`. Iterate
  `ids` in batches of 16 instead of `index.records`, skip text matching, and
  build sort keys from labels.
- **Refinement:** same revision and scope, no cursor, and the new folded
  query contains the memo's folded query. A text containing the longer query
  contains the shorter one, so the new matches are a subset. Scan only `ids`,
  matching normally, and store a new set.
- **Otherwise:** a full scan. If the budget cannot fit the set, run without
  one (today's behaviour) and do not fail.

The set is evicted oldest-first beyond `MAX_MATCH_SETS`. It is dropped on lock
and on any revision change (checked at lookup; stale sets are discarded).
Results and order are identical to today (property test in step 6).

### Step 7 — sequential bulk staging

```rust
// qv-store write.rs
impl Write<'_> {
    /// Reads a version of the base state this write started from. A record this
    /// write already touched is refused (StoreError::InvalidEdit).
    pub fn read_base_version(&self, record: RecordId, version: VersionId)
        -> Result<RecordVersion, StoreError>;
}
// qv-core edit.rs
fn stage(w: &mut Write<'_>, now: Timestamp, ch: Change) -> Result<(RecordId, RecordInfo), CoreError>;
// The current loop body of commit_with: counter, clock, encode→decode copy, RecordInfo, put_local.
pub(crate) fn commit_each(
    ctx: &mut Ctx<'_>,
    ids: &[RecordId],
    make: impl FnMut(&Index, &Write<'_>, RecordId) -> Result<Option<Change>, CoreError>,
) -> Result<(), CoreError>;
```

`commit_each` ordering:
1. The caller has already prevalidated every ID compactly from the index:
   exists, kind, single head, live or trashed as the operation needs, batch
   cap. Refusals return before a write opens, as today.
2. `open.vault.write()`. A split borrow keeps `&open.index` alongside the
   write.
3. For each ID: cancel check, then `make` loads through
   `w.read_base_version`, applies the edit or returns `None`, then `stage`.
   The decoded body is dropped before the next ID.
4. `open.index.check(...)`, cancel check, `commit_cancellable`, and the index
   replace/retree after `local_seq` advances. All exactly as `commit_with`.

Convert `set_deleted`, `edit_entries`, `deleted_with` and `purge_in`
(`edit.rs:434, 479, 583`, and the restore path), and any other `commit`
caller that passes more than a constant number of changes (`rg -n
'commit\(ctx' crates/qv-core/src`). Single-record saves keep `commit`.
`commit` and `commit_with` share `stage`.

**Errors:** no new error variants. `read_base_version` refusing a touched
record is a programming error surfaced as `InvalidEdit`; it cannot happen,
because IDs are deduplicated by `live_entries` / `subtree`.

**Dependencies:** none added or changed.

## Steps

### Step 1 — Spec amendments

- [x] **Do:** amend 0004 §7.2: verification may pass each authenticated head
  to the index builder so a head is decoded once at unlock. Amend 0004 §7.3:
  - a session may keep text-free match sets (record IDs only), bounded by the
    record limit, charged to the ceiling, never in cursors or pages,
    discarded on lock, revision, scope or query change;
  - query refinement scans a prior set only when the new folded query
    contains the prior one;
  - the label tier (titles, type hints, icons, group names and order, and
    their folded copies) is evicted after field text.

  Amend 0008 §6: zeroize match sets and the label tier. Amend 0008 §2:
  performance paths add no secret-dependent comparison. Add Changelog lines
  (2026-11-13, plan 0053, owner-delegated) and a `specs/README.md` note.
- **Files:** `specs/0004-local-storage.md`, `specs/0008-memory-and-side-channels.md`, `specs/README.md`.
- **Done when:** the text permits exactly the step 3–7 designs and nothing broader.
- **Verify:** `sh scripts/check-spdx.sh` (docs only); re-read the amended ranges.

### Step 2 — Baseline harness and measurements

- [x] **Do:** copy `plans/0048-security-release-validation/capacity-harness.rs`
  and `measure-capacity.py` to `plans/0053-performance/perf-harness.rs` and
  `measure-perf.py`; 0048's evidence stays untouched. Keep the 0048
  safeguards: 0700 temp dir, product lockfile subset, product SQLite flags,
  no personal vaults. Add stages:
  - `unlock`: core password open, KDF reported separately;
  - `traverse`: complete paged `items_page` with no query;
  - `kinds`;
  - `refine`: `search_page` for "s", "sy", "syn", "synt", first page each,
    then complete paging of the last.

  The `search`, `batch` and `recursive` stages stay. Run 30/90/180 rows plus
  `budget_bench measure` P0–P3 on the host, three samples each. Record
  medians in `plans/0053-performance/PERF.md`. Add a short CPU profile of the
  180-row `search` stage (`perf record`, if available on the host) naming the
  top functions; it informs step order only.
- **Files:** `plans/0053-performance/{perf-harness.rs,measure-perf.py,PERF.md}`.
- **Done when:** PERF.md has a baseline table for every stage and fixture and names the profile's top functions.
- **Verify:** `python3 plans/0053-performance/measure-perf.py` completes; logs retained under its printed directory.

### Step 3 — Unlock: one decode per head

- [x] **Do:** implement the step 3 design: `HeadSink`, the `*_into` unlock
  variants, `IndexBuilder`, and the core call-site changes. Add a test-only
  decode counter (`cfg(test)` hook on `read_role` in qv-store, and on
  `Index`'s reads in qv-core).
- **Files:** `crates/qv-store/src/vault.rs` (`load_state`, `finish_unlock`, unlock variants), `crates/qv-store/src/lib.rs` (exports), `crates/qv-core/src/index.rs`, `crates/qv-core/src/setup.rs`, `crates/qv-core/src/quick_unlock.rs`, `crates/qv-core/src/session.rs`.
- **Done when:**
  - a vault of N single-head records and C conflicted records unlocks with
    exactly heads + tombstone-history + C record decodes;
  - the sink-built index equals `Index::build` (records, tree, counts, views);
  - a test that fails unlock after the sink saw heads (damaged later head,
    anchor mismatch) returns the error with no session;
  - a cancel during the sink pass returns `Cancelled`.
- **Verify:** `cargo test --locked -p qv-store unlock`, `cargo test --locked -p qv-core index`, `cargo test --locked -p qv-core setup`, `cargo clippy --all-targets --locked -- -D warnings`.

### Step 4 — Label tier and scan-resistant admission

- [x] **Do:** implement the step 4 design: the `EntryLabel`/`EntryFields`
  split, two-tier `ViewCache` with fields-first eviction, `Access::{Scan,
  Point}`, and `key` reading labels only. Update `views.rs`, `autofill.rs`
  and `conflict.rs` callers of `ctx.view` to the tier they need.
- **Files:** `crates/qv-core/src/{index.rs,view_cache.rs,paging.rs,views.rs,session.rs,autofill.rs,conflict.rs}`.
- **Done when:**
  - with field text above the cache, a complete no-query traversal decrypts
    each record at most once (counter test);
  - labels stay resident while fields are evicted;
  - the existing `evicted_readers_remain_charged…` and budget tests pass
    unchanged;
  - a new test shows a `Scan` never evicts a resident entry;
  - all `paging_tests` and `large_vault_tests` pass unchanged.
- **Verify:** `cargo test --locked -p qv-core view_cache paging index large_vault`.

### Step 5 — Allocation-free ASCII folding

- [x] **Do:** add `folded_contains` with its scratch buffer and use it in
  `key` for titles, group names and field values. Fold the query once per
  request, as today.
- **Files:** `crates/qv-core/src/paging.rs` (or a small `fold.rs` module in qv-core).
- **Done when:** a property test over random strings agrees with
  `to_lowercase().contains` for each of: ASCII, Latin-1, U+212A, U+0130
  (İ, which lowercases to two code points), ẞ, combining marks and an empty
  query. Scratch charging is covered by a budget test.
- **Verify:** `cargo test --locked -p qv-core fold paging`.

### Step 6 — Match sets and refinement

- [x] **Do:** implement `MatchSet` as designed. Use it for continuation and
  refinement, drop it on lock and stale revision, and fall back without it
  when the budget is short.
- **Files:** `crates/qv-core/src/{paging.rs,session.rs}`.
- **Done when:**
  - property test: for random vaults and query sequences (including
    refinements, non-refinements, deletions between pages and lock between
    pages), pages and order equal the memo-free path, and stale cursors
    still return `StaleHandle`;
  - counter test: complete paged search of N records decodes field text at
    most N times plus returned rows;
  - a refinement decodes only the prior matches;
  - lock drops every set (budget back to zero after cursors drop);
  - an exhausted budget still returns correct pages.
- **Verify:** `cargo test --locked -p qv-core paging large_vault`, `cargo test --locked -p qv-cli search`, `cargo test --locked -p qv-app page_read`.

### Step 7 — Sequential bulk staging

- [x] **Do:** implement `Write::read_base_version`, `stage` and
  `commit_each`, and convert the multi-record callers listed in the design.
  Add a `cfg(test)` live-`Change` counter (increment on construction,
  decrement on drop) with a high-water read.
- **Files:** `crates/qv-store/src/write.rs`, `crates/qv-core/src/edit.rs`, other converted callers found by the `rg` above.
- **Done when:**
  - batch icon set, batch move, batch delete/restore, recursive group delete
    and restore, purge and empty trash over 50 records peak at ≤ 2 live
    decoded changes;
  - `batch_entry_operations_are_all_or_nothing`, the trash tests, the random
    edit property test and the store crash matrix pass unchanged;
  - new tests: cancellation after k of n staged records commits nothing and
    leaves the index unchanged; an injected read failure at record k rolls
    back; `read_base_version` on a touched record is refused.
- **Verify:** `cargo test --locked -p qv-store write crash`, `cargo test --locked -p qv-core edit`.

### Step 8 — Measure, document, gates

- [x] **Do:** rerun `measure-perf.py` and `budget_bench` on the final tree.
  Add the after table and the target check (decision 1) to PERF.md. A missed
  target is recorded with its cause, never hidden. Package the phone run using
  0048's isolated-UID instructions. If the phone is connected, run the 90 and
  180 searchable-text fixtures and the traversal; otherwise record "phone run
  pending". In `plans/0048-security-release-validation/PLAN.md`, log that the
  step 3 memory decision is resolved by 0053. Update the docs listed below.
  Run all gates.
- **Files:** `plans/0053-performance/PERF.md`, `plans/0048-security-release-validation/PLAN.md` (log line), docs below.
- **Done when:** PERF.md has before/after for every stage, all gates pass on the final tree, and plan status is `Implemented — fresh review pending`.
- **Verify:** the full test plan below.

## Test plan

- Final verification: all `AGENTS.md` gates (`sh scripts/check-spdx.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked`), `sh scripts/check-matrix.sh`,
  `cargo clippy --target x86_64-pc-windows-gnu --all-targets --locked -- -D warnings`
  (store/core paths run on Windows), the Android arm64 Clippy build used in
  0048, and `cargo test -p qv-app --features validation` (the real-engine
  flows; `RUST_TEST_THREADS=1` only there). `cargo deny check` and
  `cargo vet --locked` are run to confirm no dependency drift.
- Unit and property tests: sink build equals `Index::build`; memo and
  no-memo pages are equal; fold equivalence; the tier eviction order.
- Deterministic work-count tests replace timing assertions: decode counters
  for unlock, traversal, search and refinement, and the live-`Change`
  high-water mark. No test asserts wall-clock time.
- Rejection, malformed-input and crash-path tests:
  - damaged head after earlier heads were sunk;
  - anchor mismatch with a built index;
  - cancel during the sink pass, during scans and mid-staging;
  - injected read failure mid-staging;
  - the store crash matrix for bulk commits, unchanged;
  - stale cursor and revision change with a live match set;
  - budget exhaustion with match sets.
- Vectors: none (no format change).
- 0012 §1 matrix rows: keep every existing row's test passing, including
  "Budget inconsistency". A new test that covers an existing row carries the
  `// 0012 §1: <exact row>` comment. No row is added or removed.

## Risks and stop conditions

- Stop if any design requires persisting derived data, a format change, or a
  budget change; that is outside this plan.
- Stop if the sink cannot run inside `load_state` without reordering the
  manifest authentication before head reads. Authentication order is not
  negotiable.
- Stop if `Write` cannot read base versions without exposing staged
  (uncommitted) objects. Reading staged state would change the semantics.
- Stop if match-set or label results differ from the current ordering in any
  property-test case and the cause is a spec ambiguity rather than a bug.
- Stop if converting a bulk caller would change its all-or-nothing or outcome
  behaviour (for example, a caller that today commits several times).
- A target missed after steps 3–7 is not a stop: record it in PERF.md with
  the profile and propose follow-up work. Do not tune budgets, eviction
  constants beyond the design, or tests to meet a number.
- If the phone is unavailable, step 8 records it as pending; the plan can
  still reach `Implemented`.

## Documentation

- [ ] `CHANGELOG.md` — Unreleased "Changed": faster unlock, list, search and
  bulk changes on large vaults, with the PERF.md headline numbers.
- [ ] `ARCHITECTURE.md` — §3 qv-core (label tier, admission, match sets,
  sequential bulk staging) and qv-store (unlock head sink, base reads on
  `Write`).
- [ ] Specs — 0004 §7.2/§7.3 and 0008 §2/§6 amendments with Changelog lines
  (step 1); `specs/README.md` note. No status change.
- [ ] `plans/README.md` — index row and status.
- [ ] `plans/0048-security-release-validation/PLAN.md` — log line that step 3 is resolved by 0053.
- [ ] `AGENTS.md` — no change.

## Revisions

- 2026-11-13b (owner request, design owner-delegated under the standing
  2026-11-02 delegation). The owner noticed a short delay when choosing a
  group or item type in the app. Cause: the app's poll thread checks for
  finished background work only every 200 ms (`ui::app`), so a page read that
  completes in about a millisecond waits up to 200 ms (about 100 ms on
  average) before the list redraws. Add step 9. No spec change: this is
  in-process redraw scheduling, with no data path, secret or timing
  dependence on vault content.

### Step 9 — Redraw as soon as background work lands

- [x] **Do:**
  - Add a process-wide UI wake signal in `controller.rs`: a `Mutex<bool>`
    plus `Condvar`, both `const`, with `wake_ui()` and
    `wait_ui(timeout) -> bool`. Wakes coalesce: many wakes before the
    wait returns cause one pass.
  - The `ui::app` poll thread calls `wait_ui(200 ms)` instead of sleeping.
    The 200 ms tick stays as the fallback for countdowns, inactivity and
    OS-lock checks.
  - Call `wake_ui()` after the state lock is released wherever background
    work finishes and bumps the revision: the page worker (a result, or
    the end of its queue) and the app operation thread (`qv-app-op`).
- **Files:** `crates/qv-app/src/controller.rs`, `crates/qv-app/src/ui/mod.rs`,
  `crates/qv-app/src/page_read.rs`, `crates/qv-app/src/workspace.rs`.
- **Done when:**
  - a unit test shows `wait_ui` returns at once after a wake, and only at
    its timeout without one;
  - a page-reader test shows a finished page wakes the waiter well before
    200 ms;
  - all qv-app tests and validation flows pass.
- **Verify:** `cargo test --locked -p qv-app`,
  `RUST_TEST_THREADS=1 cargo test --locked -p qv-app --features validation`,
  and the full gates.

## Execution log

- 2026-11-13: Planned at owner request, clean tree `0c838e4`. Findings from
  code reading, before measurement:
  - `scan_page` rescans every record on every page;
  - `ViewCache` evicts in record-ID order, which is also the scan order, so
    every read misses once text exceeds the cache;
  - `key` folds every field with `to_lowercase` on every page;
  - unlock decodes each single-head record three times: store verification,
    the index summary, then the representative;
  - `set_deleted`/`edit_entries` hold every decoded body in `Vec<Change>`
    before the write opens.

  Design choices owner-delegated (standing 2026-11-02); see Decisions needed.
- 2026-11-13: Owner instruction "go ahead and implement it all".
  - **Step 1:** amended 0004 §7.2 and §7.3 and 0008 §2 and §6, with
    Changelog lines and the `specs/README.md` note.
  - **Step 2:** `perf-harness.rs` and `measure-perf.py` are derived from
    0048's tools; 0048's files are unchanged. Stages: unlock, traverse,
    search, fieldsearch, refine, kinds, batch, recursive. `--source-root`
    measures a `git archive` of a baseline in a private target directory.
    Each sample copy is deleted after use.
  - **Steps 3–7:** implemented. Deviations from the design sketch:
    - `HeadSink` has a `begin(&Manifest)` call: the index needs the root and
      vault-meta IDs before the first head, and holding all views until
      `finish` would buffer every record's text.
    - Only `unlock_for_recovery_into` and `unlock_with_phrase_into` were
      added, because core opens only through those.
    - The cache tiers are labels and full views, not labels and a separate
      field-only structure. Callers keep the full `ViewData` API. When both
      tiers hold a record, its title text is cached twice, and both copies
      are charged.
    - `commit_each` opens the write only at the first change, so a batch that
      changes nothing still writes nothing, as `commit` did.
    - `purge_in` keeps `commit`: tombstones carry no decoded payload.
  - **Tests:** `index_budget` now expects the label to be charged alongside
    the view; with room for only the view, the label stays and the view goes.
    No assertion was weakened. With match sets forced off, the new count
    test reads 209 records for 14 hits against a bound of 54.
- 2026-11-13: Steps 2 and 8 done. See PERF.md; raw summaries are in
  `evidence/`. Results at 180 rows:

  | Stage | Before | After |
  |-------|--------|-------|
  | search | 16.1 s | 0.40 s |
  | traverse | 16.3 s | 0.35 s |
  | refine | 16.9 s | 0.40 s |
  | kinds | 180 ms | 2 ms |
  | unlock | 1.90 s | 1.32 s |
  | batch/recursive growth | ~146 MiB | ~4 MiB |

  P2 unlock went from 3.59 s to 1.66 s; P2 peak RSS rose by about 16 MiB
  (labels and map nodes).
  - **Targets:** the host targets are met; the phone targets await the phone
    run. Stages under 3 ms differ only by the sampler's 2 ms granularity.
  - **deny/vet not rerun:** no manifest or lockfile changed, and AGENTS.md
    requires them only for dependency changes.
  - **Found, not fixed** (see PERF.md):
    - one ordinary edit at P2 takes about 2.5 s, growing with the record
      count;
    - a no-hit field search above the cache size decrypts every record once
      per new query.
- 2026-11-13: Step 9 done (revision 2026-11-13b).
  - **Code:** `controller::{wake_ui, wait_ui, WakeOnDrop}`. The `ui::app`
    poll waits on the wake signal with the same 200 ms ceiling. The page
    worker wakes after each result and when its queue ends. Every
    background thread (`qv-app-op`, clipboard, confirm, vault, rotation,
    resume, QR scan, vault import, picker) declares `WakeOnDrop` first, so
    it wakes after its state lock and permit drop.
  - **Tests:** `a_wake_reaches_the_ui_poll_at_once` and
    `a_finished_page_wakes_the_ui_poll_before_its_tick`, serialized by a
    test lock because the flag is process-wide. The second test drains old
    wakes, checks, then waits, so it cannot swallow the worker's own wake.
- 2026-11-13: Final-tree gates, all exit 0:
  - SPDX, `cargo fmt --check` and `sh scripts/check-matrix.sh`;
  - `cargo clippy --all-targets --locked -- -D warnings`, plus `-p qv-app`
    with `--features desktop` and with `--features validation`;
  - `cargo clippy --target x86_64-pc-windows-gnu` for the workspace and
    `-p qv-app --features desktop`; the only warnings are the existing
    vendored dioxus-desktop ones;
  - `cargo clippy --target aarch64-linux-android -p qv-store -p qv-core -p qv-app --features qv-app/mobile`;
  - `cargo test --locked`: 1,034 passed, 0 failed, 7 ignored;
  - `RUST_TEST_THREADS=1 cargo test --locked -p qv-app --features validation`:
    104 tests and 3 real-engine flows pass.
