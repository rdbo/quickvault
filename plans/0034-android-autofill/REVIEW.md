# Review — Plan 0034: Android autofill

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-11-02 | `54e9764..87f1267` (phase 2.7 commit, which also carries plan 0035) |

## Summary

Fresh-context review of the committed phase 2.7 tree. The design matches 0009
§4.3–4.4 and 0008 §3. Matching is exact. App identity is the OS-reported
package plus the full signer set. A web origin counts only from a pinned
browser on an empty allowlist. The stored-identity parsers are bounded and
reject every ambiguous form. The handoff is a non-exported, one-shot,
token-bound in-process registry, and the requester's signers are re-checked at
delivery. Locking cancels a bound request.

The review found and fixed two functional defects:
- every cold-start handoff was cancelled;
- an empty login field failed the whole fill.

Both failed closed, so no secret was exposed. One spec wording gap was also
fixed. This review is not a security audit, release approval or device
evidence. Autofill stays disabled on every device, and the device rows in
VALIDATION.md remain pending.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | 0009 §4.4, OQ2 note, Changelog, roadmap Revision. The lifetime wording needed a fix (finding 3). |
| 2 | yes | Slot serial. The mutex is released across `open` and the result is discarded on re-enroll/invalidate. The new gated-backend test covers readiness, both discard paths and an undisturbed success. |
| 3 | yes | `qv-platform/src/autofill.rs`: exact parsers and matcher. Tests cover the substring/subdomain/userinfo/custom-scheme/IDN/percent/IPv6/trailing-dot classes, signer subset/superset and untrusted origin claims. `TRUSTED_BROWSERS` is empty. |
| 4 | yes | Candidates per live head; values re-read and re-matched; `StaleHandle` after edits; `link_app` through `edit_entry`/`save_entry` only; conflicted entries cannot be linked. Empty-value handling fixed (finding 2). |
| 5 | yes, as revised | Kotlin lives in `MainActivity.kt` (logged revision). Service gate, system-reported package, signers via PackageManager without `QUERY_ALL_PACKAGES`, bounded traversal, mixed-origin detection refused, generic presentation, no `SaveInfo`. The registry zeroes results on replace/cancel/consume/expiry access; the auth activity is non-exported. |
| 6 | yes | Bridge validation and bounds; `bind` on unlock; `on_lock` from `invalidate`; worker Fill checks the cancel token before completing. Cold-start poll ordering fixed (finding 1). |
| 7 | partial (as planned) | `AutofillTest` in-process handoff and the reviewer's cold-start method pass on the Android test phone. The framework round trip, WebView claims and trusted-browser rows are pending. |
| 8 | yes | ARCHITECTURE, CHANGELOG, app README, index. |

Out-of-scope changes: plan 0035 (same commit), reviewed in its own REVIEW.md.

## Findings

1. **[high, functional; fails closed] Cold-start handoff always cancelled** —
   `crates/qv-app/src/android.rs` (poll loop).
   - The auth activity claims the request before it starts MainActivity.
   - The Rust loop called `poll_autofill()` before it created the controller.
   - `AutofillRegistry.pending()` reports a claimed id only once. The first
     poll therefore found no `ui::ACTIVE` and cancelled the request.
   - After plan 0035, a destroyed MainActivity ends the process, so most
     handoffs start cold.
   - The device test missed this because it started QuickVault before it
     registered the request.

   Nothing was released (fails closed), but the common production path could
   never fill. Action: **fixed by reviewer**. The registry is now polled only
   after the controller is set, and the reviewer added
   `AutofillTest#testColdStartRequestWaitsForControllerAndUnlock`, which
   registers and claims before launch. Android arm64 Clippy and both APK
   builds pass. Device: passes on the Android test phone, and fails with the old
   ordering (VALIDATION.md).
2. **[medium, functional] An empty login field failed the whole fill** —
   `crates/qv-core/src/autofill.rs` `copy_value`.
   - New app logins start with empty `username`/`password`/`url` fields
     (`qv-app/src/ops.rs:281`).
   - An empty selected value returned `InvalidInput`, so an entry with only a
     password could never fill.

   Plan decision 8 fills "only roles the request contains". An empty value now
   fills nothing for that role; an oversized value still fails the fill. Action:
   **fixed by reviewer**, with a regression assertion in
   `autofill_candidates_match_identity_not_titles_and_release_chosen_values`.
3. **[low, spec wording] Handoff lifetime** — `specs/0009-clients-and-platforms.md` §4.4.
   - The spec said the pending request is "valid at most 120 seconds".
   - The implementation gives 120 s to claim, and a claimed request lives up
     to 10 minutes while the user unlocks and chooses.

   The text now states both limits, and that an expired result is never
   delivered and is zeroed. Changelog line added; status stays Draft. Action:
   **fixed by reviewer** (Draft spec, owner standing delegation).
4. **[low, pre-existing lint] Android Clippy failed on `qv-store`** —
   `crates/qv-store/src/location.rs:154`. `s.f_type as u64` is an
   unnecessary cast on Android, where `f_type` is already `u64`. The 0034 log's
   Android Clippy pass covered app and platform only. Action: **fixed by
   reviewer**: a statement-level `allow(clippy::unnecessary_cast)` with the
   reason. No behaviour change.

Observations, not defects:
- `bind` runs only on the password/quick unlock path. A request waiting during
  vault creation or phrase recovery binds at the next unlock.
- The autofill screen decrypts candidates on each render, which is slow for
  very large vaults but correct. Revisit with the 2.10a redesign.
- A cancel never revokes a COMPLETED result (documented). A lock between the
  worker's token check and `complete` therefore still delivers the explicitly
  chosen login. This matches the user's choice and the spec ("a lock after
  the request is bound cancels it" applies to requests not yet completed).

## Fixes applied by reviewer

- `crates/qv-app/src/android.rs`: `poll_autofill()` runs only after the
  controller is published (`if ready`).
- `crates/qv-app/android/tests/AutofillTest.java`: new cold-start method.
- `crates/qv-core/src/autofill.rs`: `copy_value` returns `Option`; empty → no
  value for that role; plus a test.
- `specs/0009-clients-and-platforms.md`: §4.4 lifetimes and a Changelog line.
- `crates/qv-store/src/location.rs`: target-dependent cast lint allow.

## Gates

On the committed tree before fixes: SPDX, matrix, fmt and workspace Clippy pass.
`cargo test --locked` gave 759 passed, 0 failed, 2 ignored (private Xvfb). App
validation Clippy passes, and 31 app validation tests pass.

Final tree after fixes:

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 759 passed, 0 failed, 2 ignored (private Xvfb) |
| `cargo clippy/test -p qv-app --features validation` | pass: 31 passed |
| Android arm64 Clippy (`mobile`, `mobile,validation`; app, platform, core, store) | pass |
| Validation and normal APK + instrumentation builds, with manifest inspection | pass (rebuilt on the final tree, including plan 0036; normal gate closed, one reused `dist/android-project`) |
| `cargo deny` / `cargo vet` | n/a (no dependency or lockfile change) |
| Device: `AutofillTest` cold-start method | pass on the Android test phone (6.1 s); fails on a build with the old poll order, so the test catches finding 1. See VALIDATION.md |

## Documentation

- [x] CHANGELOG.md (existing entry; reviewer fixes are local and need no new entry)
- [x] ARCHITECTURE.md
- [x] Spec status (Draft) and Changelog
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None blocking. Pending device work before any device is added to
`AutofillGate`:
- run the new cold-start method and the framework round trip from a foreign
  app (VALIDATION.md);
- record WebView claims;
- for browser fills, read signer digests on the device.
