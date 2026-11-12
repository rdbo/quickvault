# Phase 2.4 validation record — 2026-11-01

Implementation evidence, not an independent security review or release approval.
The foundation is Implemented following the owner's optional Linux monitoring
amendment below; fresh-context review and release validation remain outstanding.
Physical Android observations and automated flows are recorded with their exact
build identities. Real logind-desktop lock/suspend behavior remains unclaimed;
absence of those services is now an allowed, explicitly disclosed Linux mode. Source implementation,
container tests and APK packaging do not establish supported-device behavior.

## Container evidence

Host: Linux x86_64, stable Rust 1.98.1, system GTK 3/WebKitGTK 4.1, private Xvfb.
Tests use synthetic credentials and newly created private fixture directories.
Full logs for this continuation are in `/tmp/qv30-work`; they are temporary.

| Command / scope | Result |
|-----------------|--------|
| `sh scripts/check-spdx.sh` | Pass; six exact vendored identities/provenance checks |
| `sh scripts/test-check-spdx.sh` | Pass; rejection fixtures |
| `sh scripts/check-matrix.sh` | Pass |
| `cargo fmt --check` | Pass |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass |
| `cargo test --locked` | Pass: 720 passed, 2 ignored |
| `cargo test --locked -p qv-app --features validation` | Pass: 7 controller tests and 2 actual-engine tests |
| `cargo clippy --all-targets --locked -p qv-app --features validation -- -D warnings` | Pass |
| `cargo deny check` | Pass: advisories, bans, licenses, sources; no advisory ignores |
| `cargo vet --locked` | Pass: 93 fully audited, 11 partially audited, 404 exempted; exemptions are development debt |

The full workspace run preceded the final app-only rejected-password cleanup
and integration-test lint annotation. Both default app tests and validation
feature tests were rerun after those edits, along with workspace/UI Clippy,
format, header and matrix checks. Other tested packages' inputs did not change.
Unmodified upstream warnings remain visible under the approved vendor lint policy.
The ignored tests are the existing KAT data generator and subprocess lock helper;
neither is a skipped device/engine check.

Controller tests exercise bounded/stale input, protected intermediary cleanup,
password-repeat rejection, weak-password delay, generated-password expiry,
phrase confirmation/recorded skip, wrong-password refusal, password/phrase
unlock, snapshot-backed explicit anchor adoption, idle/OS lock and late KDF
completion. The generated six-word suggestion uses Accepted 0010 defaults.

Actual WebKit tests exercise strict CSP inline/eval rejection, escaped HTML,
remote fetch/subframe/popup/navigation denial, inaccessible file-dialog and
filesystem routes, malformed/duplicate JSON events, oversized native IPC and
renderer copy handling. A second harness drives the actual shared screens
through create, phrase confirmation, lock, wrong password, cleared controls,
correct unlock and phrase recovery with real core crypto/storage. Native OS
lifecycle is simulated in that fixture; it does not test a real logind session.

The rendered-flow test exposed a real cleanup defect: clearing Rust input did
not clear a reused DOM node's value. Compiled same-origin app.js now clears text
controls on submitted actions and epoch changes and clears phrase/input display
when hidden. Consent checkboxes remain epoch-controlled. The rendered flow
passes after this fix. Cleanup still cannot guarantee erasure of engine/OS copies.
Android native transition generations preserve pause/screen-off notifications
that occur entirely between Rust polling intervals.

Visual inspection: read-only shared preview at 1180×900 and 390×844. The narrow
layout starts with the form; no horizontal clipping was observed. Captures:
`crates/qv-app/dist/screenshots/desktop.png` and `mobile.png` (ignored build output).
No real credentials were used.

## Maintained source checks

Commands use `--manifest-path third-party/Cargo.toml --locked`:

- GLib `-p glib --lib variant_iter`: 11 passed with GLib test optimization enabled.
- selectors `-p selectors --lib`: 7 passed.
- Macro packages `-p glib-macros -p gtk3-macros --tests`: 21 tests passed across
  unit/compile/integration suites; gtk3-macros has no standalone tests and is
  additionally exercised by real GTK/UI compilation.
- Desktop `-p dioxus-desktop --no-default-features --features tokio_runtime --lib hardened`: 3 passed.

Tests cover patched behavior and compatibility, not the whole upstream packages.
The desktop suite includes an actual stalled/bounded loopback handshake reader.
[Dependency disposition](DEPENDENCIES.md) records versions, license scope and
exact audit debt; [provenance](../../third-party/README.md) records source hashes.

## Android packages

Built with pinned SDK 35/build-tools 35.0.0, NDK 27.3.13750724, JDK 21,
Dioxus CLI 0.7.10, Rust aarch64-linux-android and `--locked`. Native code is
release-profile; Gradle produces debug-signed app and instrumentation APKs.
Build script: `sh crates/qv-app/scripts/build-android.sh` after the setup recipe.

| Artifact | SHA-256 |
|----------|---------|
| `crates/qv-app/dist/quickvault-debug.apk` | `255cd15d1cdffbe4938ff6c771445bd3f127fd2f408b49a9e3ac56762e2286ce` |
| `crates/qv-app/dist/quickvault-tests.apk` | `d3743c2b1e183d2238fd90d9089cb84bfebc120d2d31528e4180a12440c94939` |

Both signatures verified using build-tools apksigner (v2). Debug certificate
SHA-256: `9bd6ccea5821be2a6faa734fd792e90227cfebf50d9a25122bd12f4456cd9e39`.
The debug key is local build state, not a stable distribution identity.

Inspected final APK manifest with `aapt dump xmltree`: package org.quickvault.app,
minimum SDK 29, target SDK 35, arm64 native library, allowBackup=false and
fullBackupContent=false. Debuggable=true as expected for this test package.
Requested permissions: INTERNET (loopback renderer transport) and generated
signature-only DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION. MainActivity is the
launcher; AndroidX startup provider is not exported. The generated profile
receiver is exported under android.permission.DUMP. No autofill service is
packaged. Network-security config denies remote cleartext, allowing exact
127.0.0.1 only. These are test APKs, not release artifacts.

## Physical Android instrumentation — 2026-11-01

Device: the owner's Android test phone, Android 15/API 35,
arm64-v8a, Google Android WebView 156.0.8078.47. Both packages installed
successfully. The app APK hash is unchanged; the test APK hash above now identifies the expanded flow suite described
below. The earlier passing baseline used test APK
`d39187a02693622c6f94e07500a97335e80bb130f094e779be2bff4a6c99d2bb`.
The expanded package is rebuilt and signature verified; its passing full run
is recorded below.

Result: `OK (1 test)` in 9.803 seconds. Native FLAG_SECURE and WebView restrictions,
inline/eval CSP rejection, password autocomplete hints, pause-generation retention
and cleared text controls/consent after pause/resume passed on the actual engine.
This does not test actual keyboard learning, screenshots, a live unlocked session
across screen lock, or every manual recovery scenario.

Initial run failed the final clearing assertion because it checked `!input.value`
for checkboxes, whose default value is `on` even when unchecked. Corrected the
fixture to assert text values are empty and checkbox/radio states are unchecked.
No product cleanup or security requirement was relaxed. A retry with default
runner discovery then hit an OS startup ANR. Explicitly selecting the test class
and launching MainActivity from ADB while the runner waited for its activity
completed successfully; preserve this OEM/runner limitation rather than count
the failed runs as passes. Logs: `/tmp/qv30-device`, including initial failure,
ANR exit information, build/signature checks and `instrumentation-focused.log`.
Only the app process's startup logs are relevant to this evidence.

Connection note: the SDK ADB server started in the workspace could not access
USB. After terminating that server at the owner's request, the host `/usr/bin/adb`
server exposed the authorized phone. Use `adb` against that server; do not start
a competing SDK server. No device data was cleared or existing vault opened.

To repeat on this connected, authorized phone, use synthetic values only:

```sh
adb install -r crates/qv-app/dist/quickvault-debug.apk
adb install -r crates/qv-app/dist/quickvault-tests.apk
adb shell am instrument -w -e class org.quickvault.app.PlatformTest org.quickvault.app.test/android.test.InstrumentationTestRunner
```

On this phone, bring the app forward from a second terminal while the runner
waits if automatic launch is blocked:

```sh
adb shell am start -W -n org.quickvault.app/dev.dioxus.main.MainActivity
```

## Owner-observed phone checks — 2026-11-01

On the same Android test phone and installed app build, the owner reports:

| Scenario | Observed result |
|----------|-----------------|
| Create a vault using the installed UI | Completed successfully |
| Lock the phone screen with the vault open | Vault locked |
| Leave the foreground task with the vault open | Vault locked |
| Attempt screenshot capture | Owner confirms screenshot protection works |

These are owner-reported manual observations, separate from instrumentation.
They do not establish phrase recovery/skip, lock during KDF, IME behavior,
backup exclusion or Linux lifecycle behavior. No vault contents or
credentials were collected to record these results.

## Expanded automated phone checks — passed 2026-11-01

The agent owns engineering validation; the owner is not expected to design or
execute low-level recovery, error or race tests. Added instrumentation-only
`android/tests/flows.js` and a native driver for real shared-screen creation,
three-word phrase confirmation, wrong-password refusal and cleared input,
password unlock, phrase recovery, pause while opening, no late reopen and
recorded skip. The fixture uses a fresh canonical private directory, deletes
only its own files, and never opens or clears the owner's app vault. Recovery
words remain in the engine fixture closure, not test logs.

Final result: `OK (1 test)` in 15.287 seconds, covering the complete native
protection checks plus shared-screen creation, recovery-word confirmation,
wrong-password refusal/cleared input, password unlock, phrase recovery,
pause while the UI reports opening, cancellation/no late reopen after five
seconds, and explicit recorded skip. The UI-reported opening state is observed
before the native pause; this does not prove a particular CPU instruction in
the KDF was executing at that instant. Deterministic controller cancellation
and late-result tests supply the complementary state-machine coverage.

Final log: `/tmp/qv-android-tests-cd1jkwm8/instrumentation.log`, also retained
in `/tmp/qv30-device/flows-run9.log`. The production app hash is unchanged.
Test fixture files were removed from their new private root; the owner's vault
was not opened or cleared. No recovery phrase was returned to native test logs.

Preserve failed attempts as diagnostic history: the asynchronous driver stalled,
and the synchronous run initially failed at second-vault creation. The second
fixture was incorrectly named `vault.qvault-skip`; core correctly requires the
`.qvault` extension. Corrected the fixture to `vault-skip.qvault`, without
relaxing product validation. Some runs were also interrupted by secure screen
timeout; the final fixture holds FLAG_KEEP_SCREEN_ON only for its test window
and clears it on exit. No device timeout or production lock behavior changed.
A pending reinstall subsequently killed a run with OS reason PACKAGE_UPDATED;
that run is not counted as a pass. The runner now checks installed APK SHA-256
before reinstalling, avoiding unnecessary replacements and OEM install prompts.
The final passing run skipped both packages only after exact hash matches.

Build, Java compilation, JS/shell syntax, SPDX, matrix, Rust format/Clippy and
diff checks pass. Production Rust/dependency/test inputs are unchanged from
prior full gates. Logs for failed attempts and builds remain in
`/tmp/qv30-device/flows-*` and `/tmp/qv-android-tests-*`.

Repeatable engineering runner (build APKs first, phone authorized/unlocked):

```sh
sh crates/qv-app/scripts/test-android.sh
```

It compares installed APK hashes and installs changed packages with `-r`,
preserving app data; requires exactly
one authorized device; explicitly selects the test class and brings the test
activity forward for OEM launch restrictions; retains logs and returns failure
when instrumentation fails even if ADB exits zero. Uses host `adb` or `QV_ADB`,
without replacing its server. This is instrumentation code, excluded from the
production app APK; the production app SHA-256 remains unchanged.

Remaining engineering evidence: missing-anchor adoption on the phone if
feasible, real desktop lifecycle checks and fresh-context review.
Screenshot blocking, ordinary screen lock and foreground exit have owner-reported
phone observations above. Keyboard learning and backup exclusion require
platform evidence; report limits rather than give the owner an undefined
manual test assignment. No further owner checklist is implied by this record.

Linux check in this continuation: the system bus returns ServiceUnknown for
org.freedesktop.login1. The production desktop binary builds. Attempts to
observe production startup under a new private Xvfb and private XDG_STATE_HOME
produced black captures rather than a readable protection-unavailable screen,
even after explicit mapping and forcing X11. This is inconclusive startup/UI
evidence, not a passing missing-monitor test. Investigate that startup path or
repeat on a supported desktop; do not substitute the earlier synthetic engine
harness for this unresolved production-runtime check. Logs/captures are in
`/tmp/qv30-linux-real`. No host session was locked or suspended.

On a supported Linux desktop with logind, run the production desktop binary in
a separate private XDG_STATE_HOME, exercise the same core-backed flows and
screen lock/suspend during KDF, and verify second-instance rejection and
monitor-loss refusal. No real user vaults are needed. Record desktop/session,
WebKit version and results. Plan 0029 has the earlier private-bus evidence and
manual lifecycle procedure. Complete step 7 and request fresh-context review
only once the required runtime evidence is recorded; keep spec statuses unchanged.

## Linux startup diagnosis follow-up — 2026-11-01

Owner observes the production "Protection unavailable" screen in their own
window. This confirms a rendered startup-refusal screen there; it does not
turn the earlier black private-Xvfb captures into a passing test. The agent's
fixed system-bus endpoint returns NameHasNoOwner for org.freedesktop.login1.
The owner confirms launching from their normal desktop terminal. The agent
bus is not established as identical to that host bus, so the agent's missing
logind service does not diagnose the owner's exact failure. The owner reran it and reports "Lock monitoring unavailable". Their subsequent
read-only GetSessionByPID probe returns ServiceUnknown for org.freedesktop.login1.
This confirms the required logind-compatible service is absent on the host bus
queried by the production adapter, rather than merely absent in the agent
workspace. It is a backend coverage/prerequisite gap, not a vault-password error.

Startup errors now distinguish missing lock monitoring, private storage and
instance contention using fixed data-free categories. The render fingerprint
also tracks asynchronous startup errors, so a failure arriving after initial
render refreshes its message. Failed operation-time
watch rearming invalidates the epoch, locks/drops session state and clears
protected inputs before refusal. The added regression covers startup denial
and protected-form clearing when monitoring becomes unavailable. Requirements
and platform/backend selection are unchanged. Current verification logs are
in `/tmp/qv30-startup`; final results are appended to the execution log.

The installed Android APKs and earlier phone evidence precede this shared
controller/status follow-up. Do not present those artifact hashes as newly
rebuilt APKs; current source is additionally cross-checked for Android compilation.

Final follow-up checks: SPDX, matrix, fmt, workspace Clippy and workspace tests
pass (721 passed, 2 existing ignored). Shared UI validation passes 8 controller
and 2 engine tests; UI Clippy and Android arm64/mobile compilation pass. Existing
upstream vendor warnings remain; the app has no Android unused-import warning.
No dependency change or new audit/advisory disposition was introduced.

Host service absence is now established. A temporary, untracked `temp.sh` was
updated to collect read-only OS/init/session metadata and a filtered list of
lock/portal service names from the owner's desktop. This identifies an
appropriate integration direction before changing backend policy or asking for
system reconfiguration. No alternate watcher or monitoring bypass is implemented.
Product Rust/dependency/test inputs are unchanged from the latest passing gates.

## Host desktop identified — 2026-11-01

Owner's normal-terminal probe: Alpine Linux edge 3.25.0_alpha20260805, init
process `init`, Wayland, XDG_CURRENT_DESKTOP=mango. Only the desktop portal
appears in the filtered running/activatable service names. logind-only watcher
coverage is therefore insufficient for this environment. The portal name is
not evidence that its selected backend implements CreateMonitor, delivers
an initial lock state or supplies sleep transitions. Official
[Inhibit API](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Inhibit.html)
documents screensaver/session-end monitoring; a complete replacement must also
meet the separate OS sleep requirement. Temporary helper now queries the
portal Inhibit version and installed backend descriptors. No monitoring bypass
or unsupported success status added; phase remains In progress.

## Owner-directed Linux optional monitoring — 2026-11-01

This policy supersedes the earlier missing-monitor startup blocker. The owner
explicitly directs that automatic OS screen-lock/sleep handling is optional on
Linux. Normative amendments were applied to 0008 §1.4 and 0009 §5, with index
and Changelog updates, before implementation; both remain Draft overall with
owner approval for these phase-2.4 sections.

`Core::with_linux_platform` selects optional lifecycle attachment with explicit
reduced-protection acknowledgement. The generic `with_platform` and Android
remain strict. Successful subscriptions still react to initial lock, sleep,
lock and loss; a known locked session still cancels opening. A missing watcher
permits acknowledged local use. App startup/rearm tracks availability, shows a
persistent unavailable-automatic-lock warning, and retains manual/60-second
idle locking. Losing a previously installed monitor invalidates prior forms/
consent and locks once; a subsequent explicit reduced-mode attempt succeeds.
No portal/compositor integration, dependency, primitive or on-disk format changed.

Focused evidence: 7 core-platform tests, 9 protected-controller tests and 3
actual-WebKit tests pass, including a new run using the real LinuxPlatform in
this environment whose fixed system bus has no login1 owner. That run performs
create/phrase-confirmation/wrong-password refusal/password unlock/phrase
recovery/manual lock through shared screens. Deterministic unavailable-provider
regressions cover consent rejection before writes, successful local flows,
manual and idle lock, and a successful retry after watch loss. Available and
required watchers retain event/initial-lock rejection tests.

The production desktop binary builds, and Android arm64/mobile compilation
passes with its required monitoring policy. A new private-Xvfb root capture
remains black/inconclusive; no visual-production-window pass is claimed from
that capture. DOM-driven actual-engine flows above pass with real Linux services;
owner's normal desktop window can be reopened to inspect the disclosed mode.
Earlier phone runtime evidence and APK hashes remain historical evidence for
the unchanged Android policy; no new APK/device pass is claimed here.

Current logs: `/tmp/qv30-optional`. Final complete gate results are appended to
the execution log. Fresh-context implementation review remains outstanding;
passing checks do not establish security or release readiness.

Final owner-amendment gates: 724 workspace tests passed, 2 existing ignored;
9 controller and 3 actual-WebKit tests passed; SPDX, matrix, fmt, workspace/UI
Clippy, Android arm64/mobile check and production desktop build passed. Android
packages were also rebuilt and signatures/final manifest inspected. New app
SHA-256: `5704f2d55fd921bb838bc49db0cbe490f2504343e7f90f33c38ac4fe91407f8d`;
unchanged test package: `d3743c2b1e183d2238fd90d9089cb84bfebc120d2d31528e4180a12440c94939`.
Both use the previously recorded debug certificate. Latest packages were not
installed/run on the phone during this Linux-policy follow-up. Earlier table
hashes and runtime results remain historical; do not attribute a device run to
the newly built app. Backups remain off, minimum API29, target35, test-debuggable.

Implementation handoff is now ready for fresh-context review; no Reviewed,
security-audited or release-ready status is claimed. temp.sh is now a normal
app launcher, explicitly replacing the diagnostic probe, to accommodate the
owner's terminal-copy problem. All product source/dependency inputs are frozen
after the above final checks; final documentation checks are recorded in plan.

## Owner confirmation of updated Linux startup — 2026-11-01

After the optional-monitor amendment, the owner reports seeing the vault
screen and warning in their normal Alpine/Mango desktop terminal session.
This directly confirms the startup block is removed and the unavailable-OS-
monitoring disclosure renders on that desktop. It does not claim the owner
performed another create/unlock/recovery sequence; those functional flows are
covered by the recorded actual-engine tests. Earlier black private-Xvfb
captures remain inconclusive capture evidence, superseded for real-window
startup observation by this report. Manual/inactivity locking remains active;
automatic OS screen-lock/sleep locking is not advertised for this session.
Fresh-context implementation review is the next step.
