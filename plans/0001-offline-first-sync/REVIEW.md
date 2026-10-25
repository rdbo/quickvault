# Review — Plan 0001: Offline-first sync direction

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes (specification amendment only) | 2026-10-24 | Working-tree document diff and new plan/review documents |

## Summary

The specifications now define complete offline operation plus two independent
optional sync modes: direct account-free LAN sync and account-based remote
server sync. Architecture, lifecycle scope, roadmap, CLI and validation criteria
agree on that direction. This is a consistency review by the editing agent,
not independent security review, protocol acceptance or implementation evidence.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Offline/LAN/remote/combined operation; shared causal merge; LAN phase 2 |
| 2 | yes | Accounts, server state/rotation/retention scoped to remote mode |
| 3 | yes | Client/CLI scope, release gates, indexes and amendment Changelogs |
| 4 | yes | Document checks, status preservation, consistency review and records |

Out-of-scope changes: None. No code, dependencies, crypto parameters, DDL or
byte-level wire protocol were introduced.

## Findings

No unresolved inconsistency found within the amendment's scope. LAN discovery,
peer enrollment/session design and persistence, listening mechanics and removal
remain explicitly undecided in 0005 OQ3–OQ6. The initial scheduling question was
settled by the owner follow-up reviewed below. Other owner questions remain open.

## Fixes applied by reviewer

- `ARCHITECTURE.md` §4 — Include peer approvals alongside server grants in the
  summary of rotation; this matches the amended 0002 §3.5 requirement.
- Minor paragraph wrapping and clearer wording that the LAN is untrusted.

The rotation journal's optional server operation ID and explicit LAN session
protection were clarified during execution before final review.

## Gates

| Check | Result |
|-------|--------|
| `git diff --check` | pass |
| Local Markdown targets and balanced code fences | pass |
| Changed spec metadata status equals original; amendment Changelogs present | pass |
| Required spec sections; synchronization §0–§6 and six Open Questions | pass |
| `cargo fmt --check` | not run: no tracked Cargo workspace |
| `cargo clippy --all-targets --locked -- -D warnings` | not run: no tracked Cargo workspace |
| `cargo test --locked` | not run: no tracked Cargo workspace |
| `cargo deny check` / `cargo vet` | not applicable: no dependencies changed |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md and AGENTS.md topic map
- [x] Spec statuses, per-spec Changelogs and specs/README.md
- [x] Plan ticks, execution log and plans/README.md row

## Escalations for the owner

None block the requested direction amendment. Before LAN implementation, decide
0005 OQ3–OQ6 and accept a concrete protocol amendment. The existing account
login/key-release separation remains in force; changing it requires a separate
key-custody design, not reinterpretation of this amendment.

## Follow-up review — Manual sync first (2026-10-24)

Step 5 matches the owner's refinement: both LAN and remote sync initially start
only on explicit user action. Remote unlock/edit/timer triggers are removed;
background retries are deferred. Bounded retries within an active operation
preserve existing idempotency and lock cancellation. Pending edits survive
failure and wait for the next manually requested operation.

Architecture, client/CLI behavior, validation criteria and Changelogs agree.
OQ5 retains the LAN receiving/listening design without reopening initial manual
initiation or silently choosing discovery. Local Markdown links/fences/
whitespace, follow-up Changelogs and obsolete-trigger checks passed, as did
`git diff --check`. Cargo gates remain inapplicable without a workspace.
Verdict: Approved for this specification follow-up; no implementation or
independent security review is claimed.

## Follow-up review — Android priority and shared UI (2026-10-24)

Step 6 matches the owner's Android priority and cross-platform reuse intent.
Android participates in phase-1 framework validation and phase-2 usable apps
with Linux, ahead of the remote server; iOS remains later. Shared application/UI
code and isolated OS adapters are explicit. Existing Dioxus/renderer questions
remain open and are evaluated earlier; no framework replacement was selected.

The architecture, 0009, validation matrix and spec index agree on delivery order
and platform boundaries. The original memory/secret-handling requirements in
0008 before Open Questions are unchanged, as are spec metadata statuses.
Official Dioxus and Android/Apple autofill documentation supports the distinction
between UI portability and OS integration; it is not evidence that QuickVault
already implements or validates those features.

`git diff --check`, local Markdown links/fences/whitespace, roadmap ordering,
amendment Changelogs and unchanged-security-text checks passed. No Cargo
workspace exists, so implementation gates remain inapplicable. Verdict:
Approved for the specification follow-up; no implementation or independent
security audit is claimed.
