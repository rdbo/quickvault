# Review — Plan 0010: qv-core sessions and vault operations

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-26 | `git show 06dccc7` (phase 1.8): `crates/qv-core/`, `crates/qv-store/src/{manifest,write,lib}.rs`, `crates/qv-model/src/payload/vault_meta.rs`, docs |

## Summary

Phase 1.8 adds `qv-core` (`Core`, `Session`, handles, the metadata index,
views, drafts, edits, the trash and settings), the `qv-store` final-deletion
hook and redacted manifest `Debug`, and generator defaults at settings key 2
in `qv-model`. The work matches the plan and the cited specs. The session
state machine is small and correct: `lock` is terminal, a read that saw a
lock request returns `Cancelled`, and a poisoned mutex fails closed. Every
mutation goes through the one `commit` helper and the store's single
`Write`. The tests are real: exact errors, `local_seq` unchanged on refusals,
lock races at three pause points, and a reopen-equivalence property test.
One low-severity bug was found in the settings codec. It fails closed and
does not block.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | `finalize` drops heads and history, joins every dropped clock into the floor and removes their references (each object has exactly one role, so the removal cannot hit a shared chunk). `check_edit` also refuses tombstones of the vault metadata and keyslot as `InvalidEdit`, which the plan asked for. |
| 2 | yes | Key-2 codec per *Design*. The changed input of an older test (`{0: 1}` → `{0: 9}`) keeps that test's intent. See finding 1. |
| 3 | yes | `setup.rs` instead of `core.rs` (logged: the name would shadow the `core` crate). The real index replaced the stub. |
| 4 | yes | Protected values and notes are structurally absent (`EntryInfo` has no field for them), and the retained-value assertion checks it too. |
| 5 | yes | Populated through core drafts, not `qv-store` writes (logged; the coverage is the same). |
| 6 | yes | Deviation logged: a 257 KiB title is `LimitExceeded`, not `InvalidInput`. It is consistent with every other size budget, so I agree. |
| 7 | yes | Group delete and restore, purge with attachment tombstones, skipped conflicts, expiry and anomaly thresholds. |
| 8 | yes | Pauses at `InCall`, `BeforeCommit` and `AfterCommit`; bulk delete cancelled. |
| 9 | yes | Public-API offline lifecycle; 6-case property test. |

Out-of-scope changes: the `adopt_baseline` pending-anchor fix in `write.rs`
belongs to the plan 0009 review, which landed in the same commit. Nothing else.

## Findings

1. **[low] New generator defaults can't replace a key-2 value this version can't read** — `crates/qv-model/src/payload/vault_meta.rs:294`
   When the stored key-2 value has an unknown mode, word list or
   capitalization, decode keeps it raw in `Settings::ext` under key 2. If a
   frontend then sets `settings.generator = Some(..)` and saves, `encode`
   writes key 2 from `generator` and again from `ext`, and the encoder
   returns `DuplicateKey`. I reproduced this with a throwaway test (since
   removed). `qv-core` maps the error to `InvalidInput`, so nothing malformed
   is written and the behaviour fails closed. But the user can never change
   generator defaults that a newer client wrote, and the error message gives
   no reason. Suggested direction: when `generator` is `Some`, the known value
   replaces the unreadable one. Either skip ext key 2 in `encode`, or have
   qv-model clear it through a setter. Add a test for each path. No 1.10 CLI
   command edits the defaults (0011 has none), so the first consumer is the
   app settings screen (2.5). Fix it before then; 1.10 can take it cheaply.
   Action: escalated (qv-model payload-encoding code, not a reviewer fix).

Agreed with the developer's *Found, not fixed* notes (1)–(5) in the plan's
log. Note (3) needs a decision in 1.10: does `trash rm <group>` purge the
group's trashed contents? If not, the contents stay in the trash under a
tombstoned group and are restored into recovered items.

## Fixes applied by reviewer

None.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (400 passed, 0 failed, 2 ignored) |
| `cargo deny check` (if deps changed) | n/a: only the path crate `qv-core` was added to the lockfile; the developer's deny/vet run is logged |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 "Implemented so far")
- [x] Spec statuses and Changelogs (no spec change)
- [x] Plan ticks, execution log, plans/README.md row (now `Reviewed`)

## Escalations for the owner

Finding 1 is low and doesn't block. It is routed to the next phase that
touches settings (1.10 can take it; it must be fixed by 2.5). No re-plan is
needed.
