# Review — Plan 0028: Conflict resolution and archive exchange

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-31 | `git diff cbb084a^ cbb084a`, followed by the working-tree publication repair |

## Summary

The fresh-context review of combined phase 2.2c found a publication outcome
reporting gap and initially requested changes. The owner then explicitly
requested fixing it and proceeding to phase 2.3 on the current tree. The
architect revision and developer repair are recorded in plan 0028; this
follow-up verifies that repair and closes the finding. It is not a separate
fresh-context review of the repair or a security/release approval.

## Plan conformance

| Steps | Done | Notes |
|-------|------|-------|
| 1–8 | yes | Archive commands, authenticated optional slot, recovery/preflight and durable merge outcomes. |
| 9–14 | yes | All-kind views, inspected-head binding, slot proof, restaging and recovery. |
| 15 | yes | Original combined-phase implementation and documentation. |
| 16–17 | yes | Owner-authorized publication result repair and current verification. |

The original roadmap/workflow changes and isolated feasibility lock maintenance
are covered by the recorded continuation/revision. The repair changes no
format, crypto, dependency, error category or CLI exit code.

## Findings

1. **[medium, resolved] Export lost an already-published file's identity on
   completion failure.** Originally `archive.rs:1515` returned a directory-sync
   error after rename, and core/CLI propagated it without reporting the ID.
   A file could remain, including a self-contained guessing target, with its
   crash durability unknown. This violated 0011 §4's actual-publication outcome
   contract. The existing ArchivePublished crash test established the error/
   surviving-file distinction; it was not itself an fsync fault injection.

   Repair: `crates/qv-store/src/archive.rs:1545` preserves the published identity
   and completion error after rename. `publish` still converts completion
   failure into Err, so a mandatory recovery copy is not treated as ready
   without directory sync. `crates/qv-core/src/exchange.rs:201` propagates the
   status; `crates/qv-cli/src/cmd/snapshot.rs:168` prints and flushes the ID before
   warning that crash durability is unconfirmed and returning the mapped error.
   All call sites of `publish_export` were checked for the new completion
   contract. Pre-rename failure/cancellation cleanup remains unchanged.

   Evidence: private-helper fault injection returns Io from directory sync for
   both slotless and self-contained exports, then reads/authenticates the files,
   checks the returned IDs and manifest, checks the vault sequence is unchanged,
   and verifies a retry leaves prior publications intact. Existing snapshot
   publication crash tests still pass. A CLI subprocess test covers successful
   and completion-error output, warning presence and mapped error code. Core
   exchange tests also check normal completion status.

No unresolved finding is carried into phase 2.3. Passing tests and this source
review do not prove security (0012).

## Fixes applied by reviewer

None as minor reviewer fixes. The storage/API repair was made in the developer
role after an architect revision and explicit owner authorization; the
follow-up source review checked its ordering, callers and tests. The owner's
instruction overrides the intermediate commit/session boundary; no independent
review of newly written code is claimed here.

## Gates

Logs: `/tmp/qv-work/fix-*.log`. All final commands returned zero. Product source
and dependency inputs were unchanged during the follow-up review; final record
edits affect Markdown only. The earlier `/tmp/qv-phase-review/` failures are
historical: missing Xvfb and deny/vet were remedied with tools under /tmp.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | Pass |
| `sh scripts/check-matrix.sh` | Pass |
| `cargo fmt --check` | Pass |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass |
| `QV_TEST_XVFB=/tmp/qv-tools/root/usr/bin/Xvfb cargo test --locked` | Pass: 701 passed, 0 failed, 2 pre-existing ignored |
| `cargo test --locked -p qv-store archive` | Pass: 27 selected tests |
| `cargo test --locked -p qv-cli export_completion_failure` | Pass: one selected subprocess test |
| `cargo deny check` | Pass: advisories, bans, licenses and sources; CI-pinned 0.20.2, isolated CARGO_HOME because the default advisory lock location is read-only |
| `cargo vet --locked` | Pass: CI-pinned 0.10.3; 27 fully audited, 6 partially audited, 79 unchanged exemptions |
| `cargo fmt --check --manifest-path fuzz/Cargo.toml` | Pass |
| `cargo check --locked --manifest-path fuzz/Cargo.toml --bin archive_read --bin manifest_decode --bin vault_open --bin archive_receipts` | Pass |
| `git diff --check` | Pass |

## Documentation

- [x] CHANGELOG.md describes the combined phase and publication repair.
- [x] ARCHITECTURE.md describes current component responsibilities; repair adds no component/boundary.
- [x] 0004/0011 amendments and index are present without unsupported status promotions; repair implements the existing contract.
- [x] Plan/index/roadmap record the repair and next-phase authorization status.

## Escalations for the owner

The 0028 finding is resolved. Phase 2.3 has a separate proposed plan 0029;
roadmap Session protocol step 4 requires approval for its new zbus dependency
and CLI file scope needed to consolidate the existing clipboard adapter.
The owner subsequently delegated those choices and instructed continuation;
plan 0029 is now Implemented and awaits its own fresh-context review. Phase 2.4's D13 architecture
review remains pending and is outside this work. No commit, push or branch.
