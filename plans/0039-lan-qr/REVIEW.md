# Review — Plan 0039: LAN QR display and camera scanning (roadmap 2.10b)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-11-04 | 0039 parts of `531650d` (combined owner commit "phase 2.10, 2.10b"; 0038 parts were reviewed in its own REVIEW.md) |

## Summary

Steps 1–5 are implemented as planned. The shared app renders the binary pairing
and address-only codes as SVG from protected modules. qv-sync/qv-core inspect
scanned payloads strictly (canonical codec, profile, production endpoint policy)
without network I/O. Scans only fill the current Join/Link/Sync form under the
epoch, worker-permit and cancellation checks. The Android Camera2 adapter is
bounded, runs in memory and asks for permission only at Scan; ordinary packages
keep it gated off. Code quality is good and the security-relevant bounds hold.
Step 6 (attended two-device pairing/sync with the Internet blocked, plus the
carried 2.10 rows) is still pending. This review does not replace it, and the
roadmap 2.10b acceptance box correctly stays unticked.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | 0009 §1.7 amended with Changelog and index note; deferral recorded in roadmap/0038 |
| 2 | yes | exact pins, encoder/decoder, `inspect_lan_qr`, round-trip/rotation/scale/multi-code/bounds/profile/address tests; reviewer added the missing non-byte-mode test |
| 3 | yes | SVG with quiet zone, protected symbol copies, cleanup on close/lock, form-only acceptance, manual edits clear hints, real-core QR join/link/sync test |
| 4 | yes | Camera2 dialog with FLAG_SECURE check, stride-aware bounded frames, request ids, lifecycle cancellation, action-only permission, optional hardware features, gate false in ordinary builds (script asserts the single source occurrence) |
| 5 | yes | `lan_qr` fuzz target in CI smoke/extended lists; records, ARCHITECTURE §3/§6, CHANGELOG |
| 6 | partial (owner-deferred) | native camera, permission prompt, stale-request, pause/timeout and optical Join→form passes recorded; real-peer pairing, address sync, Internet-blocked and interruption rows pending; last install is the marked validation APK with Wi-Fi left on (recorded) |

Out-of-scope changes: none. The CLI keeps the text fallback, which the plan
justifies (the Linux app shows the desktop QR).

## Findings

1. **[medium] A 2.10 LAN test fails intermittently on committed master** —
   `crates/qv-sync/src/lan/sync_tests.rs` (`with_window`, used by
   `lan_sync_failures_before_acceptance_change_nothing_and_after_it_keep_the_commit`).
   The helper closed the receive window as soon as the initiator returned.
   After an initiator cancel, the responder could see its own window cancel
   before it read the peer's Cancel frame. It then reported `Cancelled`
   instead of `PeerCancelled`. The reviewer's full run hit it, and it failed
   1 in 5 runs even without load, so CI would flake too. Production behaviour
   is correct: a window the user closes while a cancel is in flight may report
   either. The bug is in the test harness, which comes from plan 0038 and
   landed in the same commit. Action: fixed by reviewer (test-only).

2. **[low] The first camera permission prompt locks the vault** —
   `crates/qv-app/android/MainActivity.kt` (`NativeQrCamera.start`),
   `crates/qv-app/src/android.rs` (lifecycle poller).
   The system permission dialog pauses MainActivity. A pause is a background
   transition, so the vault locks and the scan is cancelled. For Link/Sync the
   user has to grant the permission, unlock again, go back to Devices and scan
   again. With Android's one-time grants this can happen on every app session.
   This follows 0009 §1.7 ("Scans do not defer background locking"), and the
   execution log already records it for Join. So it is not a defect against
   the spec, but the user experience is poor. The document picker has a
   bounded `BackgroundDeferral` for its system UI. Any similar deferral for
   the permission dialog needs a 0009 §1.7 amendment, so it is not fixed here.
   Action: escalated as a follow-up candidate (2.10a usability or the 2.11
   camera-gate decision).

3. **[low] A foreign QR code in view ends the scan instead of being skipped** —
   `crates/qv-app/src/android.rs` (`capture_qr`, `decode_frame(..)?`).
   The decoder returns `InvalidInput` for a non-byte-mode, ECI or multi-code
   frame, and `capture_qr` propagates it. One frame with an unrelated QR
   (for example a URL poster next to the screen) or two codes therefore ends
   the action with an error rather than retrying within the 30 s / 60-frame
   bound. This matches the plan ("a malformed complete QR is refused") and
   0009 §1.7 ("reject ambiguous multiple codes"), and it fails closed. Note it
   for step 6 and the camera-gate decision. Action: no change.

No security, spec or correctness defects were found in the 0039 product code.
Checked specifically:
- every bound is applied before allocation (Kotlin `packFrame`, the JNI length
  check, `decode`/`decode_frame`);
- payloads up to 1024 bytes; at most 8 endpoints, with loopback, link-local
  and mapped IPv6 rejected and the whole code refused if any endpoint is unusable;
- displayed addresses already exclude link-local, so the app's own QR is accepted;
- results after cancel or lock are dropped (epoch, `scan` token, `working`
  permit, native request id and `qvQrState` recheck);
- redacted `Debug` on `Symbol` and `LanQrInfo`; no payload text in errors;
- `inspect_lan_qr` ignores the pairing secret; `JoinCode::from_qr` and typed
  `from_manual` cannot be confused (canonical CBOR is not ASCII);
- the webview never receives the scanned code (`value: None` inputs).

## Fixes applied by reviewer

- `crates/qv-app/src/qr.rs` (`qr_non_byte_mode_is_refused`): added the missing
  test for planned behaviour. A numeric-mode QR decodes cleanly in quircs and
  must be refused (`Err`, not `None`), so the data-type check is now covered.
  Test only.
- `crates/qv-sync/src/lan/sync_tests.rs` (`with_window`): a one-round window
  now waits, at most 3 s, for the responder to report its round before the
  test closes it. Assertions are unchanged. The test passed 25 of 25 runs
  after the fix, against 1 failure in 5 runs before. Test only.

## Gates

Run by the reviewer on the final tree (commit `531650d` plus the two test-only fixes above).
Logs are in the session scratchpad.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `RUST_TEST_THREADS=1 QV_TEST_XVFB=<scratch Xvfb> cargo test --locked --no-fail-fast` | pass: 877 passed, 0 failed, 2 ignored (pre-existing), 48 result lines; serialized for the known platform instance-lock fixture interference |
| `cargo test --locked -p qv-app --features validation` (real-engine WebKit flows) | pass: 42 passed, 0 failed, 7 binaries |
| `cargo deny check`; fuzz `deny check advisories bans sources` | pass; pass |
| `cargo vet --locked` | pass (94 fully audited, 11 partially audited, 460 exempted; the three 0039 exemptions are recorded audit debt) |
| Cargo.lock checksums vs DEPENDENCIES.md | match for all three packages |
| `lan_qr` fuzz smoke (`-s none`, 60 s, `-use_cmp=0`, nightly-2026-10-01, musl) | pass: 30,220 runs in 61 s, 58 MB RSS, no crash |

Not rerun: Android arm64 Clippy/APK builds and device instrumentation. No
phone is connected, and the reviewer fix touches no Android code.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 component rows, §6 QR technology row)
- [x] Spec statuses and Changelogs (0009 §1.7 Draft amendment with Changelog; 0013 status unchanged)
- [x] Plan ticks, execution log, plans/README.md row (updated by this review)

## Escalations for the owner

- Step 6 attended validation is still owed. Before 1.0 it should run with
  2.11's per-platform LAN/GUI/mobile gates on Linux and Android, together with
  the ordinary-package camera-gate decision.
- Finding 2 (permission prompt locks the vault) is a usability decision for
  you. Option A: keep it as is. Option B: amend 0009 §1.7 to allow a bounded
  deferral for the permission dialog, like the document picker's. Screen
  lock and the inactivity lock would still apply.
- The phone was left with the marked validation APK installed and Wi-Fi on
  (both recorded in the plan). Reinstall the ordinary APK and restore Wi-Fi
  when convenient.
