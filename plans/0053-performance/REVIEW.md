# Review — Plan 0053: Performance: unlock, paged views, search and bulk changes

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-11-14 | commit `71c2376` ("performance improvements"), `crates/qv-store` and `crates/qv-core` in full; qv-app step 9 wake signal skimmed |

## Summary

The plan replaces up to three decodes per record at unlock with one (a
`HeadSink` fed by the existing verification pass), adds a resident label
tier and scan-resistant cache admission, text-free per-query match sets
with refinement, an allocation-free ASCII fold, and sequential bulk staging
inside the one existing transaction. The code matches the design and its
eight security invariants. No format, budget, profile or dependency
changed. Reviewed in a fresh context as part of the 1.0 preparation
(plan 0056); this is a focused review of the security-relevant paths, not a
line-by-line audit of the app wake signal.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 Spec amendments | yes | 0004 §7.2/§7.3, 0008 §2/§6 with Changelog lines |
| 2 Harness | yes | Moved to `scripts/perf/` by the 2026-11-14 cleanup (plan 0056) |
| 3 Unlock sink | yes | `begin(&Manifest)` deviation is logged and sound (see below) |
| 4 Label tier | yes | Tiers are labels + full views (logged deviation) |
| 5 Fold fast path | yes | `str::is_ascii` on the value, not the query (Kelvin sign case handled) |
| 6 Match sets | yes | |
| 7 Bulk staging | yes | `purge_in` keeps `commit` (logged; tombstones carry no payload) |
| 8 Measure, gates | yes | Phone run pending (recorded) |
| 9 UI wake | yes | |

Out-of-scope changes: `crates/qv-win/src/fs.rs` (22 lines, Windows store
path) rode along in the same commit; it belongs to plan 0052.

## Findings

Security invariants checked:

- **Authentication order (invariant 5).** `load_state_into` authenticates
  the head, LAN-link digest, manifest envelope and config digest and checks
  every referenced object row before `sink.begin`; each `sink.head` runs
  after `read_role` (AEAD) and `check_head`. Tombstone history is read but
  not sunk. A failure after some heads were sunk returns the error and no
  vault; `IndexBuilder` is then dropped with its zeroizing cache. Tests
  `unlock_sink_sees_each_authenticated_head_once` and
  `unlock_sink_errors_abort_the_unlock` cover it.
- **`IndexBuilder::finish`** rejects a builder whose record count disagrees
  with the verified manifest, so a sink that missed `begin` or a head cannot
  produce a partial index.
- **Nothing persisted (1), protected values excluded (2).** Labels hold only
  the lowercased title, type bucket, group name and order key; field text
  stays in full views built by the unchanged `extract`/`searchable`.
- **Zeroizing and budget (3).** Labels and match-set IDs are `Zeroizing` and
  leased against the shared 64 MiB `TextBudget`; the fold scratch grows by
  replacement so no unzeroized buffer is freed. `to_lowercase()`
  intermediates are best-effort, as before the plan.
- **Match-set lifetime (4).** Sets live in `Index` (dropped on lock), are
  filtered by revision at every lookup and keep, and are found by scope plus
  `ct_eq` on the query fingerprint. Refinement requires the same scope and
  type kind and a containing query, which is sound because substring
  matching is monotonic.
- **Bulk atomicity (6).** `commit_each` reads with the session mutex held,
  opens one `Write`, stages each record before reading the next, and rolls
  back by dropping the write on any error or cancellation; the index is
  replaced only after `local_seq` advances. `read_base_version` refuses
  touched or staged records, so staged state is never read.
- **Constant time (7).** No new comparison on keys, MACs or fingerprints
  other than the existing `ct_eq`.

1. **[low] Title text is cached twice when both tiers hold a record** —
   `crates/qv-core/src/view_cache.rs`. Logged deviation; both copies are
   charged to the budget, so it costs residency, not correctness.
   Action: none.
2. **[low] Lowercasing intermediates** — `crates/qv-core/src/index.rs`
   `label_of`. `to_lowercase()` may reallocate while growing before the
   result is wrapped in `Zeroizing`; freed intermediates are not wiped.
   Same best-effort limit as the pre-plan paging code (0008 §6).
   Action: none for 1.0; recorded.

No critical, high or medium findings.

## Fixes applied by reviewer

None.

## Gates

Run on the final 2026-11-14 tree (which also contains plan 0056's
test-only KDF memo and repository cleanup); see plan 0056's execution log.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (see plan 0056 log for counts) |
| `cargo deny check` / `cargo vet --locked` | n/a (no dependency change) |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 qv-core/qv-store)
- [x] Spec Changelogs (0004, 0008)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None. The phone performance run stays open in plan 0056 step 5.
