# Validation — Plan 0034: Android autofill

Implementation and build evidence. This is not release approval or a security
proof. No device fingerprint or browser is enabled: `AutofillGate`'s
fingerprint set and `qv_platform::autofill::TRUSTED_BROWSERS` are both empty.
Normal builds answer every fill request with no response.

## Environment and artifacts

Host Alpine/musl, pinned Rust 1.98.1 with the `aarch64-linux-android` target
(installed for this session), SDK 35/build-tools 35.0.0, NDK 27.3, JDK 21,
Dioxus CLI 0.7.10 from the ignored `crates/qv-app/dist/validation-0033/tools/`.
There is no dependency or lockfile change.

Build commands, after sourcing `scripts/setup-android.sh --print-env`:

`JAVA_HOME=/usr/lib/jvm/java-21-openjdk QV_DX=$PWD/crates/qv-app/dist/validation-0033/tools/bin/dx sh crates/qv-app/scripts/build-android.sh`

The same command with `QV_APP_DEVICE_VALIDATION=1` builds the marked
validation variant.

| Artifact | SHA-256 |
|----------|---------|
| `quickvault-debug.apk` (gate closed) | `e106d3554bae3d8b8fce4a1945b4519bbc32631c3f49b85b0a24295397397b1b` |
| `quickvault-tests.apk` | `dab1e31e170bdcf8a808041e476f48d2850dba020fbf2d1e4154efd54004727e` |
| `quickvault-validation-debug.apk` (gate open, fixture-restricted) | `7a0eab9baf9f13ca0d6b25026c34b754441b53a9e731371eb7f88b08f039ab4d` |
| `quickvault-validation-tests.apk` | `dab1e31e170bdcf8a808041e476f48d2850dba020fbf2d1e4154efd54004727e` |

The build script's checks pass:
- permission allowlist unchanged (INTERNET loopback, USE_BIOMETRIC, generated
  receiver permission; no `QUERY_ALL_PACKAGES`);
- non-exported `AutofillAuthActivity`;
- `QvAutofillService` bindable only with `BIND_AUTOFILL_SERVICE`;
- `MainActivity` is `singleTask`.

The generated normal project has `VALIDATION = false`; the validation project
has `true`.

## Host evidence

| Check | Result |
|-------|--------|
| `qv-platform` autofill (5) | pass: exact origin; subdomain/parent/`bank.example.evil.test`/`evilbank.example`/userinfo refused; custom, `intent:`, `android-app:` and `javascript:` schemes never parse; IDN/percent/IPv6/trailing-dot hosts refused; signer subset/superset/other key refused; untrusted WebView origin claims become app requests; bounds |
| `qv-core` autofill (3) | pass: titles/URL substrings never match; values only for the chosen head of a conflicted entry; stale head refused; trash excluded; link idempotent, refused on conflicted/locked sessions |
| `qv-platform` quick (3) | pass, including the 0033 review carry-over: readiness answers during a blocked prompt; re-enroll/invalidate during a prompt discards its result |
| `qv-app` autofill (3) | pass: request waits through lock and binds on unlock; label spoof lists nothing; link needs confirmation and then an explicit Fill; lock cancels a bound request; late Fill refused; expiry; explicit cancel; untrusted origin claims list nothing; trusted exact origin fills |
| Android arm64 Clippy (`mobile` and `validation`, app + platform) | pass |
| Normal and validation APK + instrumentation builds | pass (hashes above) |
| Final workspace gates | see PLAN.md execution log |

## Device evidence (2026-11-02)

The test device was the Android test phone, Android 15 (API 35), build
fingerprint
omitted
(the 0033 device). APKs were installed with `-r`, so app data was kept.
`AutofillTest` used only the fixture's `validation-current` root. The normal
build was reinstalled afterwards. The rebuilt validation artifacts differ from
the hashes above only in the test assertion and launch changes described below.

- **`AutofillTest` passed** (status 0), with all seven stages in order:
  1. vault created;
  2. an entry titled after the requester (`com.android.shell Shell`) saved;
  3. the request waited on the lock screen (banner shown);
  4. after unlock, the label spoof was refused (no candidates, "No entry
     matches this verified identity.");
  5. the verified link needed its confirmation dialog, and nothing was filled
     until an explicit choice;
  6. the explicit fill completed with the chosen username and password from
     the native registry;
  7. a lock after binding cancelled a second request, which then yielded no
     result.

  A wrong token and a replayed token were refused before each offer. The
  requester's signer set was read through PackageManager without
  `QUERY_ALL_PACKAGES`. Log:
  `scratchpad/device/autofill-5.log` (session scratch).
- **`PlatformTest` passed** on the normal build with `MainActivity`
  `singleTask`: OK (1 test), 64.697 s. The existing platform regression is
  unaffected by the launch-mode change.
- Harness fixes during the run, with no product change:
  - `js()` returns JSON, so the candidate-count assertion now compares a
    boolean. The real count was 0 (correct).
  - The vendor ROM refuses an app's own activity start while another app is on top
    (a vendor app-op that aborts background activity starts), so `startActivitySync`
    hung. The test now waits for the activity and the runner starts QuickVault
    from adb shell. That vendor app-op was temporarily allowed and then restored to
    `ignore`. The production handoff is unaffected: the handoff activity is
    foreground when it starts QuickVault.
- Running the whole `AutofillTest` class also runs the inherited `PlatformTest`
  method in the same process. That aborts in `ndk-context`
  (`previous.is_none()`, `WryActivity_create`): the Rust/Dioxus runtime can be
  created only once per process. Run each method in its own `am instrument`
  invocation, as 0033 already did. This is a pre-existing limitation, recorded
  as a follow-up in PLAN.md.

| Requirement | Evidence needed | Status |
|-------------|-----------------|--------|
| In-process handoff: registry → Rust poll → shared UI → explicit choice → result; wrong/replayed token refused; lock cancels bound request | `AutofillTest` (validation build) | **pass** (Android test phone) |
| Requester signer read under API 30+ package visibility without `QUERY_ALL_PACKAGES` | signer read for `com.android.shell` | **pass** for that system package; a third-party requester is covered by the round-trip row |
| `singleTask` keeps existing instrumentation green | `PlatformTest` on the normal build | **pass**, 64.697 s |
| Framework round trip from a foreign app: generic auth entry, handoff, dataset filled only into the requested fields | attended run with QuickVault selected as the autofill service (`adb shell settings put secure autofill_service org.quickvault.app/dev.dioxus.main.QvAutofillService`) and any login app | pending (attended) |
| Label spoof: an app labelled like the service with no link gets no candidate | attended run with a sideloaded test app | UI/matcher pass in `AutofillTest`; framework path pending |
| WebView origin claims from an untrusted app never match web entries | attended WebView page with `loadDataWithBaseURL("https://bank.example/", …)` | pending (host covered) |
| Trusted-browser exact origin | requires recording a browser's signer digests from the device and adding an allowlist entry | not started; allowlist empty by design |
| Cold-start handoff: request claimed before MainActivity/Rust start waits for the controller and unlock (review finding 1) | `AutofillTest#testColdStartRequestWaitsForControllerAndUnlock` (validation build) | **pass** (Android test phone, 2026-11-02, 6.1 s); the same test **fails** on a build with the pre-review poll order ("Request survives controller startup") |
| Reopening QuickVault in a still-cached process (e.g. a second handoff after backing out) | plan 0035 fix; attended Back/reopen and dark-mode toggle | **pass** after plan 0035 (fresh process on reopen, no abort) |

Run after connecting the phone:

```sh
adb install -r crates/qv-app/dist/quickvault-validation-debug.apk
adb install -r crates/qv-app/dist/quickvault-validation-tests.apk
# One method per invocation. On the test phone's vendor ROM, keep QuickVault in front from the shell
# while the test runs, e.g. a loop of
#   adb shell am start -n org.quickvault.app/dev.dioxus.main.MainActivity
# whenever another activity is resumed.
adb shell am instrument -w -e class org.quickvault.app.AutofillTest#testAutofillHandoffNeedsVerifiedLinkExplicitChoiceAndLockCancels org.quickvault.app.test/android.test.InstrumentationTestRunner
adb shell am instrument -w -e class org.quickvault.app.AutofillTest#testColdStartRequestWaitsForControllerAndUnlock org.quickvault.app.test/android.test.InstrumentationTestRunner
```

Restore the normal build afterwards (`quickvault-debug.apk`). Only after the
rows above pass on a named device may its exact fingerprint be added to
`AutofillGate`. Browser allowlist entries need digests read on that device and
recorded here.

## Device evidence after the 0034 review (2026-11-02)

Same Android test phone (build fingerprint above), with plan 0036 included (libcrux
linked). The process was force-stopped before each method, and each method
ran in its own `am instrument` invocation, with the shell starting
MainActivity because of the vendor ROM.

| Run | Build (APK SHA-256) | Result |
|-----|---------------------|--------|
| `AutofillTest#testColdStartRequestWaitsForControllerAndUnlock` | validation `e94b39035451cf674f0edd69db82097939a2458801e71fa70be2e92fcc88d2c1` | OK (1 test), 6.125 s; the request survived controller startup, was bound after unlock, and cancel abandoned it with no result |
| same method, pre-review poll order (diagnostic build, not kept) | validation, `android.rs` temporarily reverted | **FAILURES**: `Request survives controller startup`. The test catches the defect |
| `AutofillTest#testAutofillHandoffNeedsVerifiedLinkExplicitChoiceAndLockCancels` | validation `e94b3903…` | OK (1 test), 9.868 s, all stages |
| `PlatformTest` (`test-android.sh`) | normal `99ae40a0b4eae906636aacc4be72967f21bd9df0816fecd3fa64d695ce8acba5`, tests `3e4c0d5f…` | OK (1 test), 62.607 s |

The crash buffer and the `am_crash`/`ndk-context`/`FATAL` greps were empty
for the autofill runs. Rebuilding from the restored tree reproduced both APK
hashes byte for byte. The normal build is reinstalled, and the device's
autofill service setting was not changed
(`com.google.android.gms/.autofill.service.AutofillService`).

Still pending (attended, would change the owner's autofill-service setting):
- the framework round trip from a foreign app;
- the WebView origin-claim rows.

The trusted-browser row is not started. No device or browser is enabled.
