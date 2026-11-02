# Review — Plan 0033: Android quick unlock

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-11-02 | `1a40186..54e9764` (phase 2.6 commit, including the plan 0031 repair revision and the 0032 review record) |

## Summary

Fresh-context review of the committed phase 2.6 tree. The implementation matches
0002 §5 and the plan's resolved choices. The Rust policy manager owns age,
attempts and binding. Core reauthenticates enrollment and opens only through the
existing phrase/header/manifest/anchor path, then compares the current
password-slot binding. Kotlin validates KeyInfo before every use, feeds AAD only
after CryptoObject authentication, and drops late callbacks. Normal builds keep
every device disabled (empty fingerprint allowlist). One low-severity
concurrency finding goes to phase 2.7. This review is not a security audit,
release approval or hardware evidence. The physical matrix rows in
VALIDATION.md remain unverified.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | `qv-platform/src/quick_unlock.rs`: bounds, 7-day age, attempt reservation before native auth, permanent-loss destruction, unbound wrap/unwrap refused, Linux unavailable by trait defaults. |
| 2 | yes | `qv-core/src/quick_unlock.rs`: reauth-derived binding; enrollment releases the session mutex before prompting and rechecks binding/cancellation afterwards; `change_password` (also the phrase-recovery path) and rotation invalidate first; merged slot changes are caught by binding comparison before a session is returned; any post-unwrap failure destroys the handle. |
| 3 | yes | `MainActivity.kt` `NativeQuickUnlock`: AES-256-GCM, generated origin, nonexportable, TEE/StrongBox only, hardware-enforced auth, timeout 0, exact authenticator type, enrollment invalidation for Class 3, StrongBox→TEE retry only on `StrongBoxUnavailableException`. Header/device ID/policy and process-local `elapsedRealtime` age are checked before `cipher.init`. JNI lengths are bounded before Rust copies. JVM arrays are zero-filled best-effort. |
| 4 | yes | Separate `ReducedQuick` confirmation, re-dispatched with `confirmed = true` (no loop); explicit lock-screen action only; the unlock watch cancels the token on lock events; no fallback. |
| 5 | yes (delivery) | Owner closed the delivery step on 2026-11-02. VALIDATION.md keeps passed and pending rows separate; nothing pending is promoted. |

Out-of-scope changes: the plan 0031 repair revision (owner-directed, recorded in
0031) and the vendor `edits.rs` RefCell fix (dated 0033 revision). Both were
reviewed here. Plan 0031's repairs for findings 1–4 are confirmed in code:
- candidate-bound Rust deadline in `strength_consent` and `dispatch`;
- `forget_pick` on Back and on screen transitions;
- `require_each_class` round trip;
- engine flows.

The device PlatformTest including Back/destination cleanup is recorded in 0033
VALIDATION.md.

## Findings

1. **[low] Lock-screen render can block for a whole native prompt** —
   `crates/qv-app/src/ui/mod.rs:244`, `crates/qv-platform/src/quick_unlock.rs:166`.
   `unlock_bound` holds the slot mutex across `backend.open`, which polls a
   biometric prompt for up to 60 s. The lock screen calls
   `keystore().binding()` during render, and that takes the same mutex. A
   re-render while quick unlock is in flight therefore stalls the Rust render
   thread until the prompt ends.

   No controller state lock is held at that point, and lock delivery uses the
   separate native polling thread. So lock and cancellation still reach the
   in-flight operation: no security effect, a UI stall only. Suggested
   direction: don't hold the policy mutex across the native call. Reserve the
   attempt, release, then reacquire and confirm the same slot (envelope
   identity) before accounting the result. Alternatively, expose a
   non-blocking readiness query to the UI. This is concurrency in
   secret-policy code, so it was not changed in review. Carry it into the
   phase 2.7 plan, which touches the same unlock handoff.
   Action: escalated (follow-up in 2.7).

Observation (no defect): recreating the activity constructs a new
`NativeQuickUnlock`. It deletes QuickVault aliases and draws a new device ID,
so quick unlock fails closed to the master password. This is consistent with
"loss of trusted local policy state" (0002 §5.4).

## Fixes applied by reviewer

None.

## Gates

Run on the clean committed tree `54e9764`; logs in this session's scratchpad.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh`, `sh scripts/test-check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 747 passed, 0 failed, 2 existing ignored (with `QV_TEST_XVFB` private Xvfb; the first run without Xvfb failed only in the Xvfb-requiring clipboard/engine tests) |
| `cargo clippy --locked -p qv-app --all-targets --features validation -- -D warnings` | pass |
| `cargo test --locked -p qv-app --features validation` | pass: 28 (25 unit + 3 real-WebKit) |
| vendor `dioxus-desktop --lib hardened` | pass: 6 |
| `cargo deny check` / `cargo vet --locked` | n/a: no dependency or `Cargo.lock` change in the reviewed diff |

The private Xvfb is Alpine's package, unpacked in the session scratchpad
without changing the host install. Android builds/instrumentation were not
rerun. Device results remain those recorded in VALIDATION.md.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 qv-platform row, Android paragraph, diagram)
- [x] Spec statuses and Changelogs (no change; 0002 §5 stays Accepted, not Implemented, because device evidence is incomplete)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None blocking. Device enablement still requires the pending VALIDATION.md rows:
- biometric-enrollment invalidation;
- the credential app workflow;
- restart/reboot;
- in-flight prompt lock races.

Finding 1 carries into phase 2.7.
