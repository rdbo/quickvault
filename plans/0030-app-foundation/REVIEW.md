# Review — Plan 0030: Shared app foundation and webview security boundary

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-11-01 | `git diff a6b2252^ a6b2252` (clean starting tree) |

## Summary

Fresh-context review of roadmap phase 2.4. qv-app's controller, shared screens,
Linux/Android startup, the core Linux platform policy and the hardened Dioxus
desktop integration match the plan and the cited 0008 §1.4/§4 and 0009 §5
requirements, including the owner's optional-Linux-monitoring amendment. One
local startup bug was fixed. Two design gaps and one transport robustness gap
are escalated for later planning; none blocks this phase. Passing checks and this
review do not prove security or authorize release (0012).

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | All six vendored packages re-downloaded from crates.io: SHA-256 matches `UPSTREAM.sha256`. `diff -r` against the archives shows changes only in the files `third-party/README.md` lists. glib backport is the exact gtk-rs-core#1343 `&mut p` fix. |
| 2 | yes | Hardened protocol handler runs before stock routing: exact origin, method/query/body checks, compiled assets only, CSP + nosniff + no-store on every response. Native IPC is checked for origin, 64 KiB limit, duplicate keys and method allowlist before queueing (cap 32). Single exact navigation; popups, downloads, permissions, file chooser and devtools denied on both platforms. Loopback transport has bounded handshake, frame and connection limits plus timeouts. |
| 3 | yes | Epoch-scoped protected inputs; stale, oversized and NUL input refused and the framework String is zeroized; one worker permit; lock cancels and drops session, phrase and suggestion; late results dropped. |
| 4 | yes | Uses existing core create/unlock/phrase/recovery APIs; baseline adoption takes a verified recovery snapshot first (same ordering as the CLI). Fixed, data-free error categories. |
| 5 | yes | Linux private root, instance lock, reduced-lifecycle disclosure on every screen, acknowledgement gate. Startup category bug fixed (below). |
| 6 | yes | FLAG_SECURE before the window is shown; the controller is created only after secure-window plus hardening are observed. Generation counter catches pause/resume between polls; immediate background lock; backup off; noBackupFilesDir. |
| 7 | yes, within stated limits | Physical test-phone instrumentation and owner observations are recorded separately from automated tests in VALIDATION.md. Positive real-desktop lock/sleep evidence is absent, which the amendment makes optional. |
| 8 | yes | ARCHITECTURE, CHANGELOG, specs index/Changelogs, README updated; no spec status promotion. |

Out-of-scope changes: None. The 0008 §1.4 / 0009 §5 amendment is owner-directed
and logged with a dated Changelog entry.

## Findings

1. **[medium] Idle lock during phrase display leaves a vault with neither
   confirmation nor recorded skip** — `crates/qv-app/src/controller.rs:458`
   The 60 s inactivity lock also fires in `Phase::Phrase`. Writing down 24
   words without touching the UI easily takes longer. The session and phrase are
   dropped, status just says "Locked", and nothing records that confirmation is
   still pending. 0002 §4.2 requires confirmation or an explicit recorded skip.
   The plan's "drop phrase on lock" is followed literally; the CLI has the same
   gap only when interrupted. Deciding between a longer phrase-phase allowance,
   a durable "confirmation pending" marker with reauthenticated redisplay
   (0002 §4.2), or another approach is a design decision.
   Action: escalated to the phase 2.5 plan (settings/redisplay lives there).

2. **[low] Edit transport drops a DOM batch silently when its bounded queue is
   full** — `third-party/dioxus-desktop/src/edits.rs:547`
   `add_message_pair` discards batches when Pending holds 2, when `try_send`
   finds the channel full, or when a batch exceeds 8 MiB. Dropping the oneshot
   sender makes `poll_edits_flushed` report success, so the renderer could fall
   out of sync with Rust state, for example keeping a stale screen after a lock.
   Today the VirtualDom has only one batch in flight and this UI is tiny, so this
   is not reachable in practice. Failing closed (close the connection and lock)
   would be safer than a silent drop.
   Action: escalated (boundary design in a maintained vendor patch).

3. **[low] Real-engine harness does not assert forbidden-IPC outcomes** —
   `crates/qv-app/src/bin/harness.js:20`
   `browser_open`, `query` and 65 537-byte IPC messages are posted, but nothing
   observable is checked. Rejection is proven by the native `hardened.rs` unit
   tests, not by the engine test.
   Action: escalated as a test improvement; no false claim exists in VALIDATION.md.

4. **[low] Baseline adoption has no over-budget consent path** —
   `crates/qv-app/src/controller.rs:698`
   `begin_destructive(false, …)` reports `SnapshotOverBudget` as a generic core
   error. The CLI offers explicit over-budget consent. This is safe (nothing
   adopted) but leaves the user stuck. Natural fit for the 2.5 snapshot screens.
   Action: escalated to the 2.5 plan.

5. **[low] Linux startup refusal lost its category** —
   `crates/qv-app/src/runtime.rs:14`
   Any setup error stored `AppError::Unavailable`, so the "Private storage
   unavailable" and "already running" screens in `ui.rs` could never appear.
   The CHANGELOG and execution log already claimed that distinction.
   Action: fixed by reviewer.

## Fixes applied by reviewer

- `crates/qv-app/src/runtime.rs` — moved the Linux setup into `linux_setup()`,
  which returns the specific `AppError`, and stores that error instead of
  `Unavailable`. Added `linux_startup_reports_the_specific_storage_or_instance_refusal`
  (second instance → `AlreadyRunning`, non-directory root → `PrivateStorage`).
  Local, no API/format/crypto change; intent is stated in plan step 5 and the
  2026-11-01 log.

## Gates

Run on the final tree after the fix; logs kept outside the repository.
This host lacked Xvfb. The first run failed only on the required Xvfb tests
(clipboard and engine). The xvfb 21.1.25 and misc-font Alpine packages were
then unpacked into the session scratchpad, without system installation, and
named through `QV_TEST_XVFB`. Both suites were rerun.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh`, `sh scripts/test-check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo clippy --locked -p qv-app --all-targets --features validation -- -D warnings` | pass |
| `cargo test --locked` | pass — 724 passed, 2 existing ignored |
| `cargo test --locked -p qv-app --features validation` | pass — 10 unit + 3 real-WebKit (boundary, synthetic flow, real Linux services) |
| `cargo deny check` (cargo-deny 0.20.2, fresh advisory DB) | pass — advisories, bans, licenses, sources ok |
| `cargo vet --locked` (0.10.3) | pass — 93 fully / 11 partially audited, 404 exempted (recorded debt, not audits) |
| Vendor focused: glib `variant_iter` (optimized), selectors lib, desktop `hardened`, x11rb `rust_connection` + rustfmt | pass — 11, 7, 3, 13 |
| Vendor focused: `-p glib-macros -p gtk3-macros --tests` | pass — 21 |

Not re-run: the Android cross-build and phone instrumentation, since no
Android source changed. The upstream doctests of the macro packages (outside
the recorded command) fail here: they cannot link this host's
`-lglib-2.0`/`-lintl`, and the published gtk3-macros package omits a `.ui`
file. This is unrelated to the patches.

## Documentation

- [x] CHANGELOG.md — the startup-category entry is now accurate after fix 5
- [x] ARCHITECTURE.md
- [x] Spec statuses and Changelogs (0008/0009 stay Draft; amendment dated)
- [x] Plan ticks, execution log, plans/README.md row, roadmap entry

## Escalations for the owner

- Findings 1 and 4: carry into the phase 2.5 plan. Problem statement for
  quickvault-architect: "The 60 s idle lock can end the creation phrase screen
  before confirmation or a recorded skip, leaving no durable pending state, and
  baseline adoption cannot proceed when the mandatory recovery snapshot exceeds
  budget. Design phrase-phase timing or a pending-confirmation marker with
  reauthenticated redisplay (0002 §4.2), and an over-budget consent flow,
  without weakening 0008 §1.4 locking."
- Finding 2: fail-closed edit-drop handling in the maintained desktop patch.
- Third-party footprint (owner question, recommendation only, not decided):
  - glib, glib-macros, gtk3-macros and selectors (174 files, ~68.6k of
    ~118k vendored lines, ~58%) are maintained only to clear advisories
    under the no-ignore policy.
  - RUSTSEC-2024-0429's `VariantStrIter`/`array_iter_str` is not called by
    gtk/gio/gdk/webkit2gtk/tao/wry 0.18-era sources, QuickVault crates or the
    desktop patch. Checked on 2026-11-01 against cached sources.
  - The other three advisories are "unmaintained" (build-time proc-macro
    helper, fxhash), plus the rand 0.7 advisory, which needs a feature that is
    not enabled.
  - Alternative: scoped `deny.toml` ignores with written reachability notes,
    `unmaintained = "workspace"`, and a CI guard against calls to the unsound
    API. This would drop four forks but reverses plan 0030 D2's "no advisory
    ignores" choice.
  - dioxus-desktop remains necessary. Shrink it by proposing an opt-in strict
    mode upstream, and add a CI check that compares the tree against the hashed
    archive and a committed patch.
