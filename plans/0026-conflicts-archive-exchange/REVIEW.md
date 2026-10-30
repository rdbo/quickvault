# Review — Plan 0026: Verified archive input and merge candidates

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-30 | `5fe3495..5b3462f`, scoped to 0026 changes |

## Summary

Fresh-context review of qv-sync, VerifiedIncoming, validated manifest assembly
and their callers/tests found no blocking defect. The candidate-only boundary
matches the plan: nothing publishes incoming state or records an exchange as
complete. Other phases bundled into the owner commit already have their own
reviews and were not re-reviewed here.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Delegation and a/b/c split recorded before code |
| 2 | yes | Bounded private unlinked copy, full authentication, stable rereads |
| 3 | yes | Validated assembly preserves existing manifest invariants |
| 4 | yes | Shared bounded metadata merge, complete-version identity checks |
| 5 | yes | Permutations/regroupings, collisions, floors, real archive/store test |
| 6 | yes | Architecture, changelog, plan/index/roadmap accurately scoped |

Out-of-scope changes: none within the reviewed 0026 delta.

## Findings

None requiring changes. The explicitly documented covered-dominated permanent
tombstone refusal remains fail closed, with a regression test; subsequent
acceptance must revisit that representation before publishing incoming state.
Candidate metadata and caller-supplied authenticated reads are not a storage
authorization boundary; the new APIs document that limitation.

## Fixes applied by reviewer

None. Updated only review/status records.

## Gates

All checks ran independently against the committed implementation at 5b3462f.
Full logs: `/tmp/qv27-review/`.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass, 663 passed, 0 failed, 2 existing ignored |
| `cargo test --locked -p qv-sync` | pass, 10 tests |
| `cargo test --locked -p qv-store incoming` | pass, 3 tests |
| `sh scripts/check-matrix.sh` | pass |
| `cargo deny check` | pass, advisory/license/bans/source checks; existing syn duplicate warning |
| `cargo vet --locked` | pass, 27 fully audited, 6 partially audited, 79 exempted |

The first full test attempt lacked Xvfb and failed the two tests needing it.
Fetched the Alpine xvfb package into `/tmp`, then reran the complete suite with
`QV_TEST_XVFB=/tmp/qv27-xvfb/usr/bin/Xvfb`; its exit status was zero. No tests
were skipped or weakened. CI-pinned deny 0.20.2 and vet 0.10.3 were installed
under `/tmp/qv27-tools`. Deny used an identical temporary policy except for
its writable advisory-cache path. Vet used the actual Cargo executable.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md §3/§7
- [x] Spec statuses and Changelogs (no normative amendment in 0026)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None. Atomic acceptance, durable filename receipts, source-path rules, keyslot
adoption and core/CLI commands remain later phases as planned.
