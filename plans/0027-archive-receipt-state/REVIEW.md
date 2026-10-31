# Review — Plan 0027: Archive receipts and atomic incoming acceptance

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-31 | `git diff 4eeb787^ 4eeb787` |

## Summary

Fresh-context review of committed phase 2.2b. Receipt codecs, sealing/head binding,
safe source traversal, conservative candidate validation, tombstone preservation
and the existing Write/anchor path match the approved combined plan. No blocking
finding or reviewer code fix. This review and passing gates are limited evidence,
not a security validation claim (0012).

## Plan conformance

| Steps | Done | Evidence inspected |
|-------|------|--------------------|
| 1–7 | yes | Canonical protected receipts, bounded SQL singleton, MAC/AEAD and replica/generation bindings, creation/restore/rotation resets, CI fuzz target |
| 8–9 | yes | Tombstone role codec/authentication/preservation; normalized capability-owned paths and no-follow descriptor traversal |
| 10 | yes | Complete provenance/floor/identity checks, full immutable envelope comparisons, role/chunk authentication and shared transaction/anchor ordering |
| 11–12 | yes | Acceptance crash/restart/cancellation matrix, receipt-capacity and filename reuse, actual archive permutations, lifecycle regressions and documentation |

Out-of-scope changes: none. The owner's continuation expressly covers model/core
history adaptations and normative tombstone amendments. Core recovery-snapshot
policy, commands and selected-slot reauthentication remain 2.2c as planned.

## Findings

None requiring a change. Acceptance retains the working operational slot and
never turns received metadata into a new local version. Failure paths drop the
Write transaction; durable commits update session state before anchor retry.
Complete candidate/role verification is independent of the merge callback.

## Fixes applied by reviewer

None.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 679 passed, 0 failed, 2 pre-existing ignored |
| `cargo fmt --check --manifest-path fuzz/Cargo.toml` | pass |
| `cargo check --locked --manifest-path fuzz/Cargo.toml --bin archive_receipts --bin manifest_decode --bin vault_open` | pass |
| deny/vet | not required: no dependency input changed by 0027 |

Logs: `/tmp/qv-next-review/`. The initial full test run stopped at two clipboard
failures because Xvfb was absent. Downloaded Alpine's Xvfb and runtime libraries
to `/tmp` only; the separate clipboard suite and complete rerun passed with
`QV_TEST_XVFB` and `LD_LIBRARY_PATH` pointing there. No assertions skipped or
changed. An initial fuzz invocation used nonexistent bin names; corrected to
the actual targets above. All commands above completed with zero exit status.

## Documentation

- [x] CHANGELOG.md and ARCHITECTURE.md §3/§7 reflect completed B and deferred C.
- [x] 0004/0005/0007 amendments, Changelogs and spec index; no status promotions.
- [x] Plan ticks/log and plans/README.md updated to Reviewed.

## Escalations for the owner

None. D12 remains a future release gate, outside this storage review.
