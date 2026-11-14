# Review — Plan 0045: fingerprint first, protection levels, Android polish (partial)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Partial — not a verdict on the whole plan | 2026-11-14 | commit `0ccc080`: `crates/qv-platform/src/quick_unlock.rs`, `crates/qv-core/src/quick_unlock.rs` |

## Summary

Plan 0056 (1.0 preparation) asked for focused reviews of the riskiest
unreviewed code. Of 0045 this covers the persistent quick-unlock policy
(state file, boot binding, attempt counting, destroy order) and core's vault
pre-check and invalidation. The Kotlin keystore glue, the app controller's
offer/auto-prompt and the UI steps (5–11) still need a fresh review; the
plan stays `Implemented`.

## Plan conformance

Not assessed for the whole plan. The reviewed code matches the Design
section's state-file layout, load/enroll/unlock/destroy order and result
kinds.

## Findings

Checked: the state file is bounded (`STATE_MAX`) and parsed with an exact
length, magic, version, policy, nonzero generation, envelope bounds and a
failure count below the limit before any allocation of the envelope, which
goes straight into `SecretBytes`; restore requires a validated backend, the
same boot count, a non-negative age under 7 days, and otherwise clears the
file and every QuickVault key; enrollment persists before reporting success
and deletes the new key if the save fails; the attempt is reserved and saved
before the prompt and released only on success or a dismissal; a result
that arrives after re-enrollment or invalidation (serial mismatch) is
discarded; core refuses another vault before prompting and invalidates only
after the phrase was obtained and the open failed for a reason other than
cancellation.

1. **[low] A cancellation after a successful prompt counts as a failed
   attempt** — `crates/qv-platform/src/quick_unlock.rs` `unlock_bound`. If
   `open` succeeds but `cancel()` is set by then (for example the user locks
   during the prompt), the `Ok` arm is skipped and the reserved attempt is
   kept, so three such cancellations destroy the enrollment. Conservative,
   not a security problem; a UX nit. Action: recorded.
2. **[low] Any non-cancel open failure invalidates the enrollment** —
   `crates/qv-core/src/quick_unlock.rs`. A transient failure after the phrase
   was obtained (the vault busy in another process, an I/O error) also
   discards quick unlock, so the user must re-enroll with the password.
   Fails safe. Action: recorded.
3. **[info] No integrity tag on the state file** — documented residual in
   the plan: a party able to write the app's private storage could reset the
   counter or age; hardware lockout and per-use authentication still apply.

No critical, high or medium findings in the reviewed files.

## Fixes applied by reviewer

None.

## Gates

See plan 0056's execution log for the 2026-11-14 tree.

## Documentation

Not assessed.

## Escalations for the owner

None blocking. The device check and the review of the remaining 0045 steps
are in plan 0056 steps 3 and 5.
