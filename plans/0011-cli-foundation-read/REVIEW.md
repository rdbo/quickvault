# Review — Plan 0011: CLI foundation, vault and read commands

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Changes requested | 2026-10-26 | Phase 1.10a paths in `git diff b270ecf..5ea17f9`; clean tree at entry |

## Summary

The CLI foundation and read commands are present, with PTY integration tests,
escaped output, core-only vault access and documented dependency decisions.
Review found a password-stdin parsing violation and a depth-dependent listing
failure. Phase 1.10a remains Implemented; roadmap session protocol step 2
requires stopping before the next phase.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Header/profile accessors and settings additions present. |
| 2 | yes | Core frontend APIs and approved zxcvbn ceiling treatment present. |
| 3 | yes | Command tree, config, selection and exit mapping present. |
| 4 | partial | EOF carriage return is incorrectly stripped; finding 1. |
| 5 | yes | Paths and ID resolution, ambiguity and trash exclusion present. |
| 6 | yes | Init/phrase confirmation and header/full info present. |
| 7 | partial | Recursive listing uses an unbounded call stack; finding 2. |
| 8 | yes | Show, TOTP and generator commands present. |
| 9 | partial | Existing tests pass as recorded below, but miss the findings. Network-isolated scenario remains environment-dependent. |

Out-of-scope changes: none identified in the phase-specific paths. The base
commit also includes earlier phases; this review does not re-review those
already Reviewed plans.

## Findings

1. **[medium] Password input loses a carriage return at EOF** —
   `crates/qv-cli/src/term.rs:292`.
   `read_first_line` strips the last CR regardless of whether reading ended
   at LF or EOF. For bytes `ends in cr\r` followed by EOF, the result is
   `ends in cr`. Spec 0011 §3.2 and plan step 4 permit removing only LF or
   CRLF, nothing else. This changes the supplied password and can prevent
   a script from unlocking the correct vault. A temporary assertion in the
   existing pipe test reproduced the failure (exit 101); it was then removed,
   restoring the source exactly. Full log: `/tmp/qv-review-cr-repro.log`.
   Track whether LF was consumed and strip CR only in that case. Add EOF-CR,
   CRLF and limit-boundary regression cases.
   Action: escalated (secret-input parsing/spec violation); no fix applied.

2. **[medium] Recursive listing consumes the process stack per group level** —
   `crates/qv-cli/src/cmd/ls.rs:95`.
   `collect` calls itself for every child with `-r`. The model allows up to
   50,000 groups (`qv-model/src/tree.rs:30`) and imposes no corresponding
   depth bound. The core's accepted metadata budget does not constrain call
   stack depth. A sufficiently deep valid hierarchy can therefore exhaust
   the CLI stack and abort instead of listing or returning a policy error.
   This is a static control-flow finding; no maximum-depth vault was built
   and no crash is claimed as reproduced. Use an explicit traversal stack,
   preserve the intended order, and test a deep hierarchy. Also inspect
   `Paths::walk`'s aggregate full-path allocation for the same hierarchy;
   it materializes every ancestor prefix and has no aggregate byte bound.
   Action: escalated (resource handling); no fix applied.

## Fixes applied by reviewer

None. Only review records were added; the regression probe left no source diff.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 453 passed, 0 failed, 2 ignored |
| `cargo deny check` | pass with advisory-cache path override described below |
| `cargo vet --locked` | pass: 27 fully audited, 6 partially audited, 75 exempted |

Full final logs: `/tmp/qv-next-{spdx,fmt,clippy,final-test,deny,vet}.log`.
The temporary regression assertion failed as intended and was removed before
this final gate run. The normal suite's success does not cover that missing case.
The network-isolated offline scenario is still skipped, not passed:
`unshare -rn true` fails with `No space left on device` in this environment
(`/tmp/qv-review-unshare.log`).

The pinned CI tools (cargo-deny 0.20.2, cargo-vet 0.10.3) were missing and
were installed under `/tmp/qv-review-tools`; the default Cargo install root
is read-only. Deny also could not create its advisory cache under the
read-only Cargo home. The successful equivalent command was
`PATH="/tmp/qv-review-tools/bin:$PATH" cargo deny --config /tmp/qv-review-deny.toml check`;
that temporary config is the repository's unchanged policy with only
`advisories.db-path = "/tmp/qv-review-advisory-dbs"` added. Advisories, bans,
licenses and sources all passed; the existing duplicate-syn warning remains.
No dependency or repository policy was changed.

## Documentation

- [x] CHANGELOG.md: phase entry present; review outcome added.
- [x] ARCHITECTURE.md: qv-cli component and technology entries present.
- [x] Spec statuses and Changelogs: approved 0010 amendment recorded; no new spec amendment in this review.
- [x] Plan ticks, execution log, plans/README.md row: remains Implemented with review note.

## Escalations for the owner

Resolve findings 1 and 2 before the roadmap proceeds. Both fit the existing
phase's input correctness and bounded traversal scope; the developer should
add regression coverage and request another fresh-context review. If aggregate
path budgeting needs a new policy, use quickvault-architect and record that
decision explicitly. No security assurance is inferred from passing gates.


## Developer remediation — 2026-10-26

The owner authorized fixes after this review. Finding 1 now preserves CR
at EOF and removes it only before LF, with limit-boundary regression tests.
Finding 2 now uses heap traversal frames; the path map stores parent indices
and escaped components rather than every full ancestor prefix. Paths are
assembled on demand in preallocated zeroizing strings, with no recursive
traversal or destruction. Listing/search flush each row or JSON object,
so their output buffer no longer retains the aggregate rendered paths.

The 50,000-level test uses a synthetic source for the production traversal
and a component arena, avoiding 50,000 durable writes; it does not claim a
maximum-size persisted vault test. Persisted fixtures cover branching order,
non-recursive listings, escaped/root/recovered paths, show/search integration,
exact JSON across incremental flushes and write-error propagation.

This follow-up records remediation; it does not replace the historical
review verdict or provide fresh-context approval. Final verification results
are recorded in PLAN.md. A fresh session must review these fixes before
marking plan 0011 Reviewed or proceeding to the next roadmap phase.
