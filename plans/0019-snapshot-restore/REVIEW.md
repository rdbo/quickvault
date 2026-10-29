# Review — Plan 0019: Restore a local snapshot to a new vault

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-29 | `git diff 66474cb..f0e60d2`, clean initial tree |

## Summary

New-path restore preserves archived causal state and objects, reconstructs the
password slot, and publishes a fresh local replica/head/anchor through the
existing durable creation ordering. The committed archive remediation also
authenticates record/history/chunk roles and binds complete envelopes across
seek passes. The reproduced CLI exit-code violation was corrected under owner authorization
on 2026-10-29; resumed review approves the change (see below). No acceptance
of the refused archive or source-data modification was observed.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1: verified new-vault builder | yes | Full archive verification before temp creation; exact object rereads; fresh writer/replica/head; no-replace publication and cleanup. |
| 2: core and CLI | yes | Selection, deferred pruning, cancellation and post-publication lock semantics implemented; slot-bearing exit code corrected in resumed review. |
| 3: documentation and gates | yes | Implementation documented; independent checks recorded below; finding 1 resolved in resumed review. |

Out-of-scope changes: the commit includes the explicitly authorized plan 0018
remediation and its review records. No dependency, schema or format change.

## Original findings — resolved on 2026-10-29

1. **[medium] Slot-bearing snapshot restore returns exit 1 instead of 7** —
   `crates/qv-store/src/archive.rs:265`, propagated by
   `crates/qv-store/src/archive.rs:1352` and
   `crates/qv-cli/src/cmd/snapshot.rs:72` through
   `crates/qv-cli/src/exit.rs:77`.
   The bounded header decoder returns `StoreError::Unsupported` immediately
   upon seeing password-slot key 10. Restore propagates this to the generic
   CLI mapping, which returns exit 1. Spec 0011 §4, *Snapshots and
   verification*, explicitly requires exit 7 for a selected slot-bearing
   archive whose header cannot be authenticated with the available vault key;
   plan 0019's interface contract also names this integrity outcome. Scripts
   therefore receive a generic failure instead of the promised integrity
   classification. The rejection itself remains fail closed.

   Reproduced through production `qvault snapshot restore`: create a vault,
   take an ordinary snapshot, insert canonical key 10 with an empty-map value
   into its bounded header, adjust map count/header length, and select its
   full archive ID. This is the same slot-bearing-header construction used
   by the existing store rejection test; MAC verification cannot be reached.
   The command exits 1 with the unsupported-format error; no destination is
   created and the active vault bytes are unchanged.

   Correct the contextual error classification within plan 0019, preserving
   refusal of slot-bearing archives and the existing general handling of
   unrelated unsupported formats/features. Add a CLI regression that expects
   exit 7 and verifies no destination, source or source-anchor changes. Also
   cover the core/store propagation path rather than changing the generic
   mapping of every `Unsupported` error.
   Action: escalated as a spec violation under the reviewer workflow; no
   product fix applied. No new spec or design decision is needed to require 7.

## Fixes applied by reviewer

None. A temporary diagnostic test asserted the observed exit 1 to establish
the defect, then was removed and the source restored byte-for-byte. Probe
source/output are in `/tmp/qv-next-review/slot-exit-probe.rs` and
`slot-exit-probe.log`. This is defect reproduction, not passing acceptance
evidence. Review records and roadmap/index/changelog notes are the only
retained changes.

## Gates

Independent results for the reviewed source tree (full logs under
`/tmp/qv-next-review/`):

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | Pass (`spdx-final.log`). |
| `cargo fmt --check` | Pass (`fmt-final.log`). |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass (`clippy-final.log`). |
| `cargo test --locked` | Pass with private Xvfb: 575 passed, 0 failed, 2 pre-existing ignored, 33 groups (`test-xvfb.log`). Includes the temporary defect probe; after removing it, `cargo test --locked -p qv-cli --test snapshots` passes all 6 retained tests (`snapshots-final.log`). All other source/test inputs unchanged. Initial run failed because Xvfb was absent (`test.log`). |
| `cargo deny check`, `cargo vet --locked` | Not required: no dependency changes. |

An Alpine Xvfb fixture and runtime packages were fetched/extracted only under
`/tmp/qv-next-review/`, without a system install or repository dependency
change. Tests use its `QV_TEST_XVFB`, `LD_LIBRARY_PATH`, `PATH` and
`XKB_CONFIG_ROOT` and private X servers; the shared clipboard is not accessed.
No extended fuzz campaign, external audit, security proof or global-freshness
claim is made by this review.

The networking-blocked test has a runtime skip when namespaces are unavailable.
An independent `unshare -rn true` probe fails with `No space left on device`
(`network-namespace.log`), so this review claims no networking-blocked pass,
regardless of the test harness's successful aggregate result.

## Documentation

- [x] CHANGELOG.md — implementation and this review outcome recorded.
- [x] ARCHITECTURE.md — implemented restore responsibilities present.
- [x] Spec statuses and Changelogs — no normative changes in 0019.
- [x] Plan ticks, execution log and plans/README.md — review escalation recorded;
  plan remains Implemented.

## Original escalation — superseded by resumed review

Finding 1 is a bounded correction within plan 0019. Roadmap 0002 Session
protocol step 2 requires stopping when the previous phase's review escalates
problems, so phase 1.14 has not been planned or implemented. Correct and
re-review this exit-code contract before continuing. No commit, push or branch.

## Resumed review — 2026-10-29

Owner authorized correction and phase continuation. Inspected the narrow
classification change: only the explicit password-slot header rejection now
returns Integrity; unknown keys/profiles/versions still return Unsupported.
The store rejection assertions follow the exact specified error. The retained
production CLI regression expects 7 and verifies no target, unchanged vault
bytes and all original anchors/count. No parser acceptance, format, crypto,
secret-lifetime or general CLI mapping change. Finding 1 resolved.

Independent resumed gates all pass: SPDX, fmt, Clippy -D warnings and full
locked workspace tests with private Xvfb, logs /tmp/qv20/fix-*.log. Focused CLI
slot and store archive checks pass (slot-cli.log, slot-store.log). Verdict
Approved; no outstanding escalation. This resumes the existing fresh-context
review, not a new independent audit. Phase 1.14 may now proceed under the
owner's explicit continuation. No commit, push or branch.
