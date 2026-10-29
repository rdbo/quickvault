# Review — Plan 0020: Password change and recovery flows

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-29 | `git diff f0e60d2 acc1021` |

## Summary

Fresh-context review of committed phase 1.14. Traced complete slot staging,
encrypted descriptor binding, SQL/header-MAC atomicity, post-durable cache and
anchor ordering, phrase-key confirmation, current-password reauthentication,
core lock/cancellation and CLI snapshot consent. No blocking product finding.
One local status-table correction is recorded below. Required gates pass.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 — Storage credentials | yes | Complete staged descriptor must match the sole encrypted head before commit; failed staging poisons the transaction. |
| 2 — Core flows | yes | Shared commit/index repair, serialized reauthentication, read-only missing/mismatched-anchor recovery. |
| 3 — CLI | yes | Protected prompts; alternate-screen phrase; explicit baseline/recovery copy and separate snapshot-deletion consent. |
| 4 — Rejection/crash evidence | yes | Slot staging and all nine mutation/anchor crash points; ciphertext/history/chunk preservation; TTY and lock races. |
| 5 — Documentation/gates | yes | Implementation coverage accurately limits archive recovery and future-profile migration; all required gates pass. |

The owner-authorized plan 0019 correction is included in the commit and was
rechecked: slot-bearing archive headers are refused as Integrity, while
unknown unsupported features retain their classification. Its production CLI
test checks exit 7, no destination and unchanged source/anchors. No unexplained
out-of-scope product changes.

## Findings

1. **[low] Plan status disagrees with completion record** —
   `plans/0020-password-recovery/PLAN.md:5` still says Approved, although its
   execution log, completed steps, roadmap and index say Implemented.
   Action: fixed by reviewer; table now Reviewed.

## Fixes applied by reviewer

Status correction only. No production code, API, format,
cryptography, dependency or test change. No other escalation.

## Gates

Independent checks on committed `acc1021` before the phase 1.15a continuation;
full logs in `/tmp/qv21-review/`. At that review handoff only planning/review
documentation had changed. The owner's subsequent delegated approval starts
the separate plan 0021 implementation; its current-tree checks live in
`/tmp/qv21/` and do not retroactively change this reviewed commit or verdict.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | Pass (`spdx.log`, repeated as `final-spdx.log`). |
| `cargo fmt --check` | Pass (`fmt.log`, repeated as `final-fmt.log`). |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass (`clippy.log`, repeated as `final-clippy.log`). |
| `cargo test --locked` | Pass with private Xvfb: 591 passed, 0 failed, 2 pre-existing ignored, 34 groups (`test-with-xvfb.log`). No product/test inputs changed before this review handoff. |
| `cargo deny check`, `cargo vet --locked` | Not required; no dependency inputs changed. |

Initial full run failed because Xvfb was absent (`test.log`). Downloaded the
Alpine xvfb package to `/tmp/qv21-review/xvfb/` and extracted its binary there;
no system install or repo dependency change. Rerun uses
`QV_TEST_XVFB=/tmp/qv21-review/xvfb/usr/bin/Xvfb`; clipboard tests create private
servers and do not use the shared clipboard.

`unshare -rn true` fails with `No space left on device`
(`network-namespace.log`). The networking-blocked test's successful harness
result does not establish that isolation ran; no networking-blocked pass is
claimed. No new device evidence, extended fuzz campaign, external audit,
security proof, key-copy revocation or global-freshness claim.

## Documentation

- [x] CHANGELOG.md — credential implementation and restore correction present.
- [x] ARCHITECTURE.md — accurate component coverage, no new component.
- [x] Spec statuses/Changelogs — no normative change in the reviewed phase.
- [x] Plan status/log, roadmap and index — Reviewed and phase 1.15 proposal recorded.

## Escalations for the owner

None in phase 1.14. Plan 0021 separately records a phase 1.15 scope decision;
it is not a defect or an unresolved requirement in this implementation.
