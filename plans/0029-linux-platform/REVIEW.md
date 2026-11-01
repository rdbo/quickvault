# Review — Plan 0029: Platform traits and Linux adapters

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-31 | `git diff 7e5c118^ 7e5c118` (clean starting tree) |

## Summary

Fresh-context review found no unresolved defect in the phase's implemented
scope. The injected platform boundary, Linux lifecycle monitoring, conservative
protection reporting and shared clipboard engine match the plan and cited
requirements. No product source or policy changes were needed. Passing checks
and this review do not prove security or authorize release (0012).

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Typed OS traits; Core builder preserves existing construction; unsupported services refuse. |
| 2 | yes | Bounded conservative probes and no-follow, owner-only, never-unlinked instance lock. |
| 3 | yes | Pinned system endpoint and service owner, subscription before initial state queries, typed events, weak session references and bounded shutdown. |
| 4 | yes | Existing X11 transport reused with injected cancellation; CLI behavior and protected outgoing storage retained. |
| 5 | yes | Architecture, dependency debt, manual validation, CI and working-tree matrix coverage documented. |

Related 0028 publication repairs share this commit. Their authorization and
review are recorded in 0028; this review also checked the completion-error
ordering and core/CLI propagation. The added dependency/runtime edges,
isolated spike metadata and matrix-checker changes have dated plan revisions.

## Findings

No unresolved findings. Checked lifecycle sender/session/type filtering,
initial locked-state delivery, owner loss, cancellation, watcher drop ordering,
reduced-protection consent and refusal of unavailable monitoring. Core's
create/unlock/recovery and interrupted-rotation consent entry points were
cross-checked. Pending frontend tasks, external views and rotation artifacts
remain the production app's documented lifecycle responsibilities.

The dependency addition has 26 new external package records, with no previous
external record removed or changed. The 24 new exact-version exemptions remain
explicit audit debt; neither an audit attestation nor an advisory ignore was
introduced. Linux quick unlock stays disabled.

Vendor provenance was independently checked against the downloaded x11rb
0.13.2 archive: SHA-256
`9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414`.
Source differences match the documented Cargo metadata, protected write ring
and bounded packet-reader patch; upstream license files are unchanged. Reviewed
those patches as application-maintained source and ran their focused tests.

## Fixes applied by reviewer

None. Only review/status/handoff documentation changed.

## Gates

Independent logs are in `/tmp/qv29-review/`. All final checks below returned
zero. An initial suite attempt stopped because Xvfb was absent; the complete
successful rerun supersedes it. Tools were provisioned under `/tmp` without
changing repository dependencies. cargo-deny uses a writable temporary
CARGO_HOME because the default advisory database location is read-only.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | Pass |
| `sh scripts/test-check-spdx.sh` | Pass |
| `sh scripts/check-matrix.sh` | Pass: all 23 offline rows |
| `cargo fmt --check` | Pass |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass |
| `LD_LIBRARY_PATH=/tmp/qv29-xvfb/usr/lib QV_TEST_XVFB=/tmp/qv29-xvfb/usr/bin/Xvfb cargo test --locked` | Pass: 712 passed, 0 failed, 2 pre-existing ignored; `test-final.log` |
| `cargo test --locked -p qv-platform` | Pass: 10 tests, including private D-Bus fixture |
| `cargo test --locked -p qv-core platform` | Pass: 5 tests |
| `cargo test --locked -p qv-cli --test clipboard` with private Xvfb | Pass: 3 tests |
| `cargo test --manifest-path third-party/x11rb/Cargo.toml --locked --lib rust_connection` | Pass: 12 tests |
| `cargo deny check` (CI-pinned 0.20.2) | Pass: advisories/bans/licenses/sources; `deny-final.log` |
| `cargo vet --locked` (CI-pinned 0.10.3) | Pass: 29 fully audited, 6 partially audited, 103 exempted; `vet-independent.log` |
| Root and isolated spike `cargo metadata --locked` | Pass |
| `git diff --check` | Pass |

Final record edits affect Markdown only; source, dependency and feature inputs
are unchanged from these checks. No real desktop/suspend or Android validation
was performed in this review. Network-namespace validation remains an existing
environmental limitation, not additional passing evidence.

## Documentation

- [x] CHANGELOG.md records platform scope, limitations and this review.
- [x] ARCHITECTURE.md describes the implemented boundary and D13 hold.
- [x] No normative spec amendment or unsupported status promotion.
- [x] Plan/index/roadmap record Reviewed status and the D13 handoff.

## Escalations for the owner

No phase-0029 blocker. Real-desktop validation, native Wayland clipboard,
Android production adapters and Linux quick unlock remain as documented.
Roadmap D13 explicitly requires owner architecture review before planning
phase 2.4; it remains pending. No phase-2.4 plan or GUI implementation was
started. No commit, push or branch.
