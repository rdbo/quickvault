# Review — Plan 0017: Entry history, restore and purge

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-27 | `git show 2dc7ac5` ("phase 1.12", tree clean) |

## Summary

The phase adds bounded retention (target ten, safe monotonic floors), authenticated
history views and explicit reveal, restore as a fresh whole-record causal edit, and a
floor-only purge that keeps active heads, conflicts and tombstones. It does so by
extending the existing single write transaction/anchor path, not a second one. The
implementation matches the owner-approved 0011 amendment and the plan's retention,
suppression and error contracts; I re-derived the conservative cumulative-floor rule,
the reference pruning and the post-purge "suppressed head does not reappear" behaviour
from the code and the tests rather than from the execution log. Findings are all
low-severity: one whole-vault write-cost/failure-mode note for phase 1.13, two
informational nits and two documentation cross-references I was not allowed to edit.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 — Adopt the concrete CLI amendment | yes | `specs/0011-cli.md:208-256` adds the milestone-1 history contracts; Changelog line and `specs/README.md:25-27` note present. No spec promoted; 0007 normtext unchanged, as required. |
| 2 — Store retention, suppression, floor-only purge | yes | `crates/qv-store/src/write.rs:640,654,721`, `crates/qv-store/src/manifest.rs:887,908`. Conservative component rule implemented and tested (`write.rs:780`); purge keeps heads/refs (`manifest.rs:1154`); crash windows (`crash_tests.rs:100`); rows pruned, `object` count matches references. |
| 3 — Core handles, diffs, reveal, restore | yes | `crates/qv-core/src/history.rs:165,182,229,339,348`. History handles revalidate session tag, record kind and exact retained reference; `reveal`/`totp` stay head-only (`views.rs:475-480`); restore builds one `edit::commit` change with `ext`. |
| 4 — CLI history/show/restore/purge | yes | `crates/qv-cli/src/cmd/history.rs`, `cli.rs:69,213`, `show.rs:118`. Scoped resolver (`:21,:35`; `run` at `:60`), `--resolve-conflicts` only on `restore`, JSON rejected for mutations before unlock, `--password-stdin` purge requires `--yes` before unlock. |
| 5 — Cross-layer rejection, suppression, crash evidence | yes | Store corruption/cancellation/missing-object/budget tests, core lock/read-only/foreign/conflict/anchor tests, model `merge_record`+`split_history` old-delivery fixture, CLI 3 network-blocked tests incl. PTY cancel/SIGINT/TERM/HUP. |
| 6 — Documentation and final gates | yes | CHANGELOG Added/Changed, `ARCHITECTURE.md:135-145`, crate docs (`qv-store/src/lib.rs:77-89`, `qv-core/src/lib.rs:20,59-70`), plan/index/roadmap records; gates pass on the reviewed tree (below). |

Out-of-scope changes in the same commit (justified and documented elsewhere, not a
plan 0017 scope violation): the plan 0016 review remediation — `SecretArray::ct_eq`
(`crates/qv-crypto/src/memory.rs:251`), the two confidential digest call sites
(`crates/qv-store/src/write.rs:370`, `attachment.rs:146`) and the widened
first/middle/last-byte rejection tests (`write.rs:1685-1760`). Logged in plan 0016's
revision/execution log, its REVIEW.md, the CHANGELOG "Changed" entry and the roadmap
log; it strengthens tests and adds no dependency. Two comment-only edits
(`write.rs:491-493`, `qv-core/src/settings.rs:52`) are cosmetic.

## Findings

1. **[low] Retention makes every commit scan and decrypt all retained history** —
   `crates/qv-store/src/write.rs:640-720`
   `commit_cancellable` runs `retain_history` on every mutation, walking each record
   with history and decrypting every retained version (hash-checked, one payload at a
   time) before sealing. Consequences worth recording: write cost is
   O(all retained history), and one corrupt history object now aborts *every*
   subsequent write with `Integrity` (deliberate fail-closed, asserted at
   `write.rs:900`, but it turns a single bad history object into a vault-wide write
   block until `verify`/repair exists). No spec violation and no measured problem at
   current sizes; flagged so phase 1.13 (`verify`, snapshots) and any large-vault
   budget work plan for it.
   Action: escalated as informational for the next phase.

2. **[low] `changed_properties` always reports `modified_at`** —
   `crates/qv-core/src/history.rs:115-117`
   History rows are compared against the current representative, whose
   `Entry.modified_at` is written from `ctx.now()` on every edit, so nearly every row
   lists `modified_at` as changed. It is truthful but tautological, since the row's
   own date is already printed, and it dilutes "which fields changed" for the user
   (0011 §4). Consider excluding the version's own timestamp from the comparison, or
   documenting that it is included. Not a spec violation; no fix applied (source edits
   are outside this review's scope).
   Action: escalated.

3. **[low] Multi-head conflict consent is only exercised with an index-only fixture** —
   `crates/qv-core/src/history.rs:500-520`
   `restore_history(.., true)` is tested against a record whose extra head exists only
   in the core index, so the joining of several real manifest heads and the
   post-consent head replacement never run on a genuinely multi-head manifest. This is
   disclosed in the test comment and in the plan/execution log (real multi-head arrives
   with 2.2, and local writes must dominate all heads today); multi-head preservation
   *is* covered at the manifest layer (`crates/qv-store/src/manifest.rs:1154-1171`).
   Acceptable for this phase; the 2.2 work must replace the fixture with a real merge.
   Action: escalated as informational.

4. **[low] Write-module transaction doc omits the retention pass** —
   `crates/qv-store/src/write.rs:3-19`
   The numbered steps still read "`commit` seals the new manifest", without the
   retention/floor/reference-release step that now runs between `put_local` and
   sealing (and its cancellation point before `COMMIT`). `qv-store/src/lib.rs:77-89`
   does describe it. Comment-only fix; not applied because product files are out of
   scope for this review.
   Action: escalated.

5. **[low] Roadmap cross-reference becomes stale** — `plans/0002-roadmap/PLAN.md:445`
   The phase 1.12 line reads "Plan: 0017 (Implemented)". After this review the plan is
   `Reviewed`; only the plan status line and the `plans/README.md` row are in this
   review's edit scope, so the parenthetical should be refreshed by the next session.
   Action: escalated.

6. **[info] `entry_detail_for_history` is a pure pass-through** —
   `crates/qv-core/src/views.rs:451-458`
   It only forwards to `entry_detail`; the real protection is `field_of`'s
   `heads.contains` check. Harmless, but the name suggests an extra check that does not
   exist; a doc comment saying so would prevent a future false assumption.

Verified as correct rather than assumed:
retention never regresses a floor and never drops a version it cannot cover
(`retention_floor` accumulates accepted component advances and re-checks the whole
protected set each time, `write.rs:721-755`); dropped objects cannot be shared with
heads because `Manifest::validate` rejects a reference used twice
(`manifest.rs:639-661`) and requires every reference to be used; purge joins head
clocks without creating a version/counter and leaves heads, pairwise-concurrency and
tombstones intact; the suppressed prior head is filtered by the next commit's
retention pass, so a purged head cannot reappear as history; restore sets `now`,
current `created_at`/`deleted_at`, the historical payload and record extensions, and
refuses an unavailable/unlive destination group; protected-value and unknown-extension
differences use `ContentHasher` + `SecretArray::ct_eq` with the Text/Bytes variant
compared separately, no digest is persisted, and no payload value reaches a
`Debug`, error, log or argv; `history show` cannot reach `copy`, `totp` or generic
`reveal`; purge output states the local-only/no-erasure limits.

## Fixes applied by reviewer

None. No source, test or spec file was modified; only this review, the plan status
line and the `plans/README.md` row changed.

## Gates

Run on the reviewed tree (`2dc7ac5`, clean) in `/tmp/opencode/qv17-rereview/`; full
output kept, exit statuses preserved.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass (exit 0) — `spdx.log` |
| `cargo fmt --check` | pass (exit 0) — `fmt.log` |
| `cargo clippy --all-targets --locked -- -D warnings` | pass (exit 0) — `clippy.log` |
| `cargo test --locked` | 508 passed / 2 failed / 2 ignored (`test-nff.log`); the 2 failures are the pre-existing `qv-cli` clipboard integration tests that need a private Xvfb, absent in this container (`qv-cli/tests/clipboard.rs:43`) |
| `cargo test --locked --no-fail-fast` with the previous session's private Xvfb (`QV_TEST_XVFB=/tmp/opencode/qv17-review/xvfb/usr/bin/Xvfb`) | pass (exit 0): 31 targets, **510 passed, 0 failed, 2 ignored**, incl. clipboard integration and doctests — `test-full-xvfb.log` |
| `unshare -rn cargo test --locked -p qv-cli --test history` | pass: 3 passed (production offline) — `history-offline.log` |
| `git diff 2dc7ac5^ 2dc7ac5 --check` | clean |
| `cargo deny check` / `cargo vet --locked` | n/a — no manifest, lockfile or MSRV change in this commit |

## Documentation

- [x] CHANGELOG.md — Added (history/restore/purge, limits) and Changed (0011
      amendment; plan 0016 digest-comparison remediation).
- [x] ARCHITECTURE.md — §3 responsibilities updated; no crate/trust-boundary change.
- [x] Spec statuses and Changelogs — 0011 history amendment + Changelog; no spec
      promoted to `Implemented`; `specs/README.md` note added.
- [x] Plan ticks, execution log, `plans/README.md` row (set to `Reviewed` by this
      review); roadmap phase line noted in finding 5.

## Escalations for the owner

None blocking. For phase 1.13 (archives, local snapshots, `verify`): the whole-vault
retention scan (finding 1) is now on every write path and makes one corrupt history
object block all writes, so `verify`/repair ordering, the pre-operation recovery
snapshot and any snapshot-while-writing test should take that failure mode into
account, and snapshot/archive code must reuse the existing manifest/transaction/anchor
ordering that retention and purge already share. Findings 2–5 need no re-plan: 2 and 4
are small developer/doc cleanups, 3 is a fixture limitation already assigned to phase
2.2, and 5 is a one-line status refresh for the next session.
