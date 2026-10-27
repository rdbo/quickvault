# Review — Plan 0014: CLI editing, trash and signal cleanup

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-27 | `git diff 18e1345^ 18e1345`; clean tree at session entry |

## Summary

Fresh-context review approves the implemented 1.10b scope. Entry edits use a
single protected core draft; group and trash operations use existing core
authorization and durable writes. Signal callbacks only set a flag; ordinary
control flow restores terminal state and drops secret containers. No blocking
finding or reviewer code fix.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Owner-approved split and signal-hook dependency; exemptions recorded |
| 2 | yes | Bounded polling, protected prompts and RAII terminal cleanup |
| 3 | yes | Command tree, generator options and prompt/stdin preflight |
| 4 | yes | Protected argv replacement refused before applying changes; one draft save |
| 5 | yes | Iterative mkdir, mixed-kind addressing, core move/delete rules |
| 6 | yes | Separate trash scope, escaped/JSON output, confirmed final deletion |
| 7 | yes | Production-binary/PTY persistence, cancellation and signal tests |
| 8 | yes | Implementation documented; clipboard remains pending |

Read the changed source/tests and affected address, output, terminal, selection
and core draft/mutation paths against 0011 §1–6, 0003 §4–5, 0007 §2,
0008 §1–3 and 0012 §1–3. Checked duplicate/contradictory edits, original
protected-field policy, preservation of IDs and untouched fields, refusal before
save, group ambiguity, separate live/trash selection, permanent tombstones,
no-echo bounds/UTF-8 handling and termination during prompts/countdowns.
The documented partial success of `mkdir -p` remains explicit: each missing
parent is its own core transaction.

Out-of-scope implementation changes: none. The commit also retains the prior
phase's fresh review and the owner's scope approval as session documentation.

## Findings

None requiring a fix or escalation for phase 1.10b. Clipboard dependency concerns
are prospective integration work for 1.10c, not defects in this implementation.

## Fixes applied by reviewer

None.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | Pass |
| `cargo fmt --check` | Pass |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass |
| `cargo test --locked` | Pass: 467 passed, 0 failed, 2 ignored, including doctests |
| `cargo deny --locked --config /tmp/qv15-deny.toml check` | Pass: advisories, bans, licenses, sources |
| `cargo vet --locked` | Pass: 27 fully audited, 6 partially audited, 77 exempted |
| `git diff --check` | Pass |

Independent logs: `/tmp/qv15-review-{spdx,fmt,clippy,test,deny,vet}.log`.
CI-pinned cargo-deny 0.20.2 and cargo-vet 0.10.3 were installed under
`/tmp/qv-next-tools`. The temporary deny policy changes only the advisory cache
path; vet uses `XDG_CACHE_HOME=/tmp/qv15-cache`. No policy, audit store,
dependency or test assertion changed. The network-namespace test's early return
when isolation is unavailable remains a skip, not evidence of blocked networking.
Passing gates do not establish security.

At handoff only Markdown changed. SPDX and fmt were repeated successfully
(`/tmp/qv15-handoff-{spdx,fmt}.log`); the independent Clippy, locked test,
deny and vet results above still cover unchanged code/build/policy inputs.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md
- [x] Spec statuses unchanged; no normative amendment or implementation promotion
- [x] Plan ticks/log/index and roadmap updated for this fresh review

## Escalations for the owner

None for 1.10b. The separate 1.10c plan must resolve clipboard plaintext
intermediates and ownership-safe release before implementation. No shared
clipboard or phone operation was performed during this review.
