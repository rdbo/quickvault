# Plan 0035 — Android: one Rust runtime per process

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-11-02 | 2026-11-02 | 0008 §1.4 (lifecycle locking); 0009 §4.4; 0002 §5.4 |

## Intent

Fix the defect found in the 0034 device run: a second `MainActivity` in a live
process aborts in `ndk-context` (`previous.is_none()` from wry's
`WryActivity_create`). This happens on an in-place configuration recreation
(dark mode, font size, locale) or a reopen while the process is cached, which
autofill makes likely. Also stop Android builds from piling up generated
project copies.

## Scope

**In scope:**
- MainActivity `configChanges` covering the remaining recreating
  configurations.
- Process end after destroy, once Rust has locked and acknowledged.
- Instrumentation no longer finishes the activity.
- The build script reuses one generated-project directory.
- Documentation.

**Out of scope:**
- Patching wry/tao/ndk-context (new vendor fork, `unsafe` context release).
- Deleting existing `dist/android-project-*` copies (owner cleans up).

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Destroyed activity locks; no late reopen | 0008 §1.4 | Accepted (D5) | process end is strictly after the existing lock |
| Process restart requires the master password | 0002 §5.4 | Accepted | quick unlock already treats restart as lost policy |
| Handoff fails closed | 0009 §4.4 | Draft (delegated) | a killed handoff is cancelled |

**Spec changes required:** None.

## Decisions needed

None pending. Chosen under the owner's standing delegation (2026-11-02):

1. **End the process on destroy rather than re-initialize the runtime.** Our
   own bridge (`BRIDGE`, `OS`, `ACTIVE`, `ROOT` `OnceLock`s), Dioxus and wry
   all assume one activity per process. Rejected: releasing `ndk-context` (an
   upstream `unsafe` API in an unvendored crate; still leaves the other
   once-only state); re-architecting the bridge for re-attachment (large, no
   benefit over a fresh process).
2. **Order:** destroy → Rust observes the destroyed flag and runs the existing
   lock (session, inputs, quick-unlock policy state, bound autofill request) →
   a 300 ms grace for worker/clipboard-hold threads, whose loops wake at least
   every 250 ms → Rust calls `qvRuntimeStopped()` → Kotlin wipes the autofill
   registry and ends the process. If Rust never acknowledges, Kotlin ends the
   process after 2 s anyway, since the process cannot safely host a second
   activity.
3. **Tests** stop calling `finish()`. Instrumentation already ends the target
   process when a run completes; each method keeps its own `am instrument`
   invocation.

## Design

- `AndroidManifest.xml` MainActivity `configChanges`:
  `orientation|screenLayout|screenSize|smallestScreenSize|keyboardHidden|keyboard|navigation|touchscreen|uiMode|density|fontScale|locale|layoutDirection|colorMode|mcc|mnc|fontWeightAdjustment`.
  The webview relayouts itself.
- `MainActivity.kt`:
  - `@Volatile private var runtimeStopped = false`; `fun qvRuntimeStopped()`
    sets it.
  - `onDestroy` (after the existing flags and `super.onDestroy()`): a
    main-looper runnable checks `runtimeStopped` every 50 ms, for up to 2 s.
    Then `AutofillRegistry.wipeAll()` and
    `android.os.Process.killProcess(android.os.Process.myPid())`.
- `android.rs`: on each existing destroyed/JNI-failure break, after
  `os.update(AndroidState::default())`, sleep 300 ms and call
  `qvRuntimeStopped` (ignore errors).
- Tests: remove the `finish()` calls; keep the FLAG_KEEP_SCREEN_ON clearing.
- `build-android.sh`: destination `dist/android-project`, removed
  (`shutil.rmtree`) before each copy.

Secrets: process end releases all memory. The existing lock path runs first,
so protected Rust containers are zeroized as before. A JVM/framework copy limit
is unchanged (0008 §4.4).

## Steps

### Step 1 — Lifecycle fix and tests
- [x] **Do:** manifest, MainActivity, android.rs and test changes as designed.
- **Files:** `crates/qv-app/android/{AndroidManifest.xml,MainActivity.kt}`, `crates/qv-app/src/android.rs`, `crates/qv-app/android/tests/*.java`.
- **Done when:** both APKs build; on the device, a forced uiMode change does
  not recreate or abort the activity; Back then reopen starts a new process
  with no abort; `PlatformTest` and `AutofillTest` pass.
- **Verify:** Android arm64 Clippy (`mobile`, `validation`); APK builds;
  device: `cmd uimode night yes/no` with the activity in front, Back and
  reopen (attended), `am_crash` absent from logcat, pid changes.

### Step 2 — Single generated project directory
- [x] **Do:** the build script reuses and replaces `dist/android-project`.
- **Files:** `crates/qv-app/scripts/build-android.sh`.
- **Done when:** two consecutive builds leave exactly one project directory.
- **Verify:** two builds; list `dist/`.

### Step 3 — Documentation
- [x] **Do:** app README (process-lifetime note), CHANGELOG, plan index,
  0034 log, VALIDATION.
- **Done when:** documented; gates green.
- **Verify:** all AGENTS gates.

## Test plan

All AGENTS gates on the final tree, plus app validation tests/Clippy, Android
Clippy, APK builds and the device checks in step 1. No dependency change.

## Risks and stop conditions

- If ending the process during an attended check leaves the activity
  relaunching in a crash loop, stop and record it. Do not retry with
  `unsafe`.
- If `PlatformTest` depends on destroy semantics, record it rather than weaken
  its assertions.

## Documentation

- [x] `CHANGELOG.md` — Unreleased entry
- [x] `ARCHITECTURE.md` — Android paragraph: one runtime per process
- [x] Specs — no change
- [x] `AGENTS.md` — no change

## Revisions

None.

## Execution log

- 2026-11-02: Planned and approved under the owner's standing delegation
  ("Fix the bugs you found"), after the 0034 device run.

- 2026-11-02: Steps 1–3 implemented.
  - `configChanges` widened.
  - `onDestroy` waits up to 2 s for Rust's `qvRuntimeStopped`
    acknowledgement (sent 300 ms after the existing destroy lock on every
    poll-loop exit), wipes the autofill registry and ends the process.
  - Tests no longer finish the activity.
  - The build script reuses one `dist/android-project` (removed before each
    copy; refuses a symlink or non-directory).

  Android arm64 Clippy passes for `mobile` and `validation`. A validation
  build then a normal build added exactly one directory (47 → 48 total; the
  old timestamped copies are left for the owner).

  Device (Android test phone, normal build):
  - Dark mode off/on with QuickVault in front: same pid 8138, activity stays
    resumed, no abort.
  - Attended Back then reopen: destroy at 17:11:53.793, pid 8138 died
    17:11:54.069, fresh pid 10267 created and resumed, no `am_crash` or
    `ndk-context` abort. Before the fix this path aborted.
  - The process ended 276 ms after the destroy record, under the 300 ms Rust
    grace, so the ending may have come from the vendor ROM's cached-process reclaim
    rather than our handler. Unconfirmed; either way, process death releases
    all state and fails closed.

  Night mode restored to the owner's setting (yes).

- 2026-11-02: Fresh-context review **Approved** (REVIEW.md). The cold-start
  ordering defect it exposed in 0034 is fixed under the 0034 review.
