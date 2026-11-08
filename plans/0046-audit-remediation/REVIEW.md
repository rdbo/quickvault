# Review — Plan 0046: Initial assessment repairs

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes — initial batch only | 2026-11-08 | Working-tree diff and new plan/decision/finding documents |

## Summary

The initial repair batch matches the plan and preserves the three policies the
owner explicitly asked to discuss first. Nine findings are addressed by code or
the assessment's documentation alternatives; partial repairs and all remaining
findings are explicitly distinguished in FINDINGS.md. This same-session
implementation review does not close the security assessment or constitute an
independent audit, fresh-context review or release approval.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | All 32 IDs matched exactly against the supplied register. Spec clarifications preceded code; DECISIONS.md records alternatives without accepting a policy. |
| 2 | yes | Git-listing failure rejects; declared vendor metadata is not represented as source provenance; ambient SQLite weakening flag loses to forced config. Endpoint and advertisement policy agree, and typed addresses replace hints without fallback. |
| 3 | yes | Command guard covers dispatch; prompt guards nest; terminal signals remain enabled between prompts; pending input is flushed before original modes restore. PTY regression covers success and handled cancellation after password Enter. |
| 4 | yes | Current docs, full gates and explicit remaining-work ledger. No component, storage/wire format, crypto construction or dependency change. |

Out-of-scope changes: none. Placing the command guard in `cli::run`, rather than
`main`, is recorded in the plan; the former covers dispatch without changing
help parsing.

## Findings

No additional defect found in the reviewed initial repair diff. The following
existing findings remain escalated rather than implicitly approved:

1. **Low, availability — index policy and new-device publication.** The
   assessment's oversized fixture uses a raised-cap author; stock edits and
   archive/LAN merges already preflight. `Core::join_new_device` publishes its
   destination before the final unlock builds the index, a source-observed
   ordering gap to cover in the pending policy design. The oversized-join case
   has not been execution-reproduced.
2. **Low, protocol warning — QV-005/006.** Accepted sessions lose ongoing
   second-hello protection; failure-budget/session policy is pending owner
   discussion. The endpoint repair does not close those findings.
3. **Low, filesystem substitution — QV-013.** Directory descriptor pinning
   alone does not establish pre-start identity. Trusted-path vs persistent
   binding/relocation policy remains pending.
4. **Low, conflict availability — T3-09.** Head-count reduction alone does not
   bound the union of writer components or reserve a local resolving writer.
   Needs a complete causal-budget design; no metadata was dropped or limits
   changed here.
5. **Informational, misleading durability result — VW-02.** Durable commit
   followed by anchor failure can still report generic failure and encourage
   duplicate-producing retries. Define store/core/frontend outcome semantics
   before fixing; equal payloads are not cross-invocation operation identity.

Other open/partial findings, exact qualifications and proposed next designs are
in FINDINGS.md. No incomplete fix is counted as a closed finding.

## Fixes applied by reviewer

- `ARCHITECTURE.md` — removed a duplicated article and rewrapped the corrected
  healthy-source password-slot explanation. Local wording only.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass, 930 tests; `QV_TEST_KDF_JOBS=2`, temporary `QV_TEST_XVFB` launcher |
| `sh scripts/check-matrix.sh` | pass |
| `sh scripts/test-check-spdx.sh` | pass |
| `cargo test --locked -p qv-sync` | pass; final workspace run also includes later QR regression cases |
| `LIBSQLITE3_FLAGS=-DSQLITE_DQS=3 cargo test --locked -p qv-store compile_options` | pass, one matching test |
| `cargo test --locked -p qv-cli --test audit` | pass, four tests; also passed in final workspace run |
| `cargo deny check`, `cargo vet --locked` | not required; no dependency changes |

Full gate output: `/tmp/qv-0046-review-{spdx,fmt,clippy,test,matrix}.log`.
Focused logs: `/tmp/qv-0046-{sync,audit,sqlite-flags}.log`.
The first workspace attempt stopped because Xvfb was absent. Signed Alpine
packages were fetched and extracted under `/tmp/qv-0046-xvfb` to supply it;
the complete suite was then rerun successfully, with no skipped/relaxed tests
or project/system dependency changes. Real-window validation features and the
external audit's unbundled harness/fuzz campaigns were not rerun.

## Documentation

- [x] CHANGELOG.md accurately scopes the initial batch.
- [x] ARCHITECTURE.md corrections; no structural architecture change.
- [x] Spec statuses preserved; 0011/0013 Changelogs and index updated.
- [x] Plan ticks, execution log, finding/decision ledger and index updated.

## Escalations for the owner

The three discussion requests are still pending, not rejected or approved:
index budget/recovery, filesystem location identity, and active LAN-window
closure. DECISIONS.md explains the concrete choices. Plan 0046 closes only its
initial repair batch; the remaining assessment requires subsequent designs
and implementation/review, starting with durability outcomes and the selected
availability/protocol policies. Never infer full security assurance from these
gates or the supplied assessment.
