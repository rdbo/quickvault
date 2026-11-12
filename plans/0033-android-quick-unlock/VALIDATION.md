# Validation — Plan 0033: Android quick unlock

Implementation/build evidence, not release approval or a security proof.
Phase 2.6 implementation is complete by owner decision on 2026-11-02.
No device fingerprint is enabled. Physical validation is incomplete; the device gate remains closed.
Current retained host logs: `crates/qv-app/dist/validation-0033/` (ignored).

## Environment and artifacts

Host Alpine/musl, pinned Rust 1.98.1. SDK 35/build-tools 35.0.0, NDK 27.3,
JDK 21, Dioxus CLI 0.7.10 (retained under the ignored
`crates/qv-app/dist/validation-0033/tools/` directory). No product
external dependency or lockfile change. Final build command:

`JAVA_HOME=/usr/lib/jvm/java-21-openjdk QV_DX=$PWD/crates/qv-app/dist/validation-0033/tools/bin/dx sh crates/qv-app/scripts/build-android.sh`
(after sourcing the SDK environment with the setup script).

| Artifact | SHA-256 |
|----------|---------|
| `crates/qv-app/dist/quickvault-debug.apk` | `138c6706ddfa0593c0b960787103926fef1f0f7e335065329a3bce29ab59a573` |
| `crates/qv-app/dist/quickvault-tests.apk` | `23e446eb801a264313b0497e41036a6d553964b58a69ea032b0070fcade3d439` |

The explicit isolated validation artifacts for the app-flow retry are:

| Artifact | SHA-256 |
|----------|---------|
| `quickvault-validation-debug.apk` | `6a4b1039f8de6c4fd5ef7734c847f1f44c6a6e4356c372eef9fbe351df734e41` |
| `quickvault-validation-tests.apk` | `23e446eb801a264313b0497e41036a6d553964b58a69ea032b0070fcade3d439` |

APK signature verification passes. minSdk 29/target 35; backups disabled;
permissions are INTERNET (renderer loopback), USE_BIOMETRIC and generated
signature-level receiver permission. Optional quick unlock requires API 30+.
The Android test phone is now connected. The current artifacts include the
device-discovered protocol metadata fix and an awake interactive test window;
installation preserves app data. No production lock or key policy was weakened.

## Host evidence

| Check | Result |
|-------|--------|
| qv-platform quick policy tests | pass (2): permanent native loss destroys the slot immediately; no state, binding mismatch, 7-day age, 3 failures, cancellation, deletion, unbound operations refused |
| qv-core quick integration test | pass: real vault reauth/open, password-change invalidation, externally changed password slot rejected despite unchanged VK, missing anchor rejected |
| App library | 24 passed, including weak-password candidate/deadline, generator option persistence and unavailable quick unlock/no fallback |
| Final qv-app validation suite | 25 unit + 3 real-WebKit tests passed: edit/history restore, archive round trip, attachment success on safe ancestors or explicit path refusal, lock during save, prior CSP/IPC checks |
| Workspace Clippy | pass |
| Android arm64 Clippy (app + platform, mobile) | pass; final repeat recorded in log |
| Native Kotlin + app/instrumentation APKs | build pass, both final artifacts above |
| Full workspace/SPDX/fixtures/matrix/fmt/Clippy/deny/vet | pass: 747 workspace tests, 0 failed, 2 existing ignored; vet 93 fully/11 partially audited, 421 exempted |

Initial Android check found the Rust target missing; installed it and reran.
Initial expanded GUI run caught a test synchronization issue: the history
version and restored entry share the title, so a title wait completed before
restore. It now requires the restore completion notice before proceeding; the
full strengthened flows pass. No assertion was removed to obtain a pass.

JNI arrays are bounded before Rust copying; temporary JNI/JVM/provider copies
have best-effort cleanup limits. The Rust result is promptly copied to protected
storage; no secret enters logs/errors/argv or a frontend event. Host tests use
an explicitly injected fake wrapping backend; they do not validate hardware.

## Physical device session (2026-11-02)

Android test phone, Android 15, build fingerprint
omitted,
security patch 2024-12-01, WebView 156.0.8078.47.

- Original phase artifacts (`dcd86b1f…75d8e`, test APK `e24cfe59…6dff6`):
  `PlatformTest` passed, OK (1 test), 62.241 s. This includes the added edit,
  history restore, Back/destination cleanup and prior synthetic file/clipboard
  checks. Full output: `/tmp/qv-android-tests-m9ef3d8f/instrumentation.log`.
- Initial interactive startup exposed a real protocol/renderer RefCell panic
  at vendor edits.rs:136, outside key operations. CSP/bootstrap getters now
  read the independent immutable view ID/shared server location. The focused
  regression holds an active mutable render borrow while reading metadata and
  refreshing the shared port. Six vendor hardened tests pass; updated WebKit
  suite passes 28 tests. No auth check, input bound or test assertion removed.
- With that fix, the quick test no longer crashes. KeyInfo reports level=2
  (StrongBox), size=256, auth=2 (Class3), auth timeout=0,
  hardwareAuth=true, invalidates=true. These are observed configuration values;
  they are not a successful authenticated encryption/decryption result.
- The operation timed out without completing authentication. A further retry
  failed its foreground/unlocked prerequisite (qvStatus=12). Android currently
  reports Dozing. Requested that the owner unlock the phone, foreground
  QuickVault and signal readiness before another interactive attempt.
- Test-only FLAG_KEEP_SCREEN_ON now keeps that window awake once foreground,
  matching the existing PlatformTest pattern. It neither unlocks keyguard nor
  changes production screen-off/manual locking. Fixed stage/key-policy metadata
  is reported to instrumentation; no aliases, keys, IVs, plaintext or raw
  exception messages are logged. Latest test APK installed; no active prompt.

- Attended Class3 round trip and authenticated wrong-AAD rejection now pass,
  **13.340 s**, after moving identical AAD streaming into the authentication
  success callback before doFinal. The initial encryption error is resolved.
  Log: `crates/qv-app/dist/validation-0033/class3.log`.
- Separate device-credential round trip and authenticated wrong-AAD rejection
  pass, **22.221 s**. KeyInfo: StrongBox, AES-256, credential auth type 1,
  duration 0, hardware authentication enforced. Log:
  `crates/qv-app/dist/validation-0033/credential-attended.log`.
- Native expiry/lost-state refusal passes, **8.548 s**. The test backdates
  only its synthetic process-local birth timestamp, then removes that state;
  no OS clock adjustment. Log: `crates/qv-app/dist/validation-0033/expiry-run.log`.
- The biometric-enrollment settings window elapsed without a completed check.
  This row remains **unverified**. Existing adapter tests do not establish the
  app workflow. An explicit marked validation build now isolates the app root
  under `validation-current` and restricts foundation opens to its synthetic
  vault. Only that build injects availability for this unallowlisted device;
  native cryptographic/authentication checks are unchanged. Normal mobile
  builds keep all device fingerprints disabled.
- Actual-app Class3 runs reached successful synthetic-vault creation, Settings
  enrollment, lock-screen quick unlock, and password-change revocation. These
  are completed checkpoints in runs that subsequently failed instrumentation
  cancellation assertions; they are not claimed as complete passing suites.
  Logs: `app-class3-retry.log` and `app-class3-final.log` in the retained log
  directory. The later cancellation harness fixes are documented in PLAN.md.
- The focused actual-app Class3 cancellation case passes **15.195 s**:
  native cancellation category verified for each attempt, vault remains locked,
  quick action retained after attempts 1/2 and removed after 3, and the master
  password still opens the vault. Log: `app-class3-cancellations-final.log`.
  The subsequent validation-root correction isolates native staging cleanup as
  well as vault/anchor storage; Android rebuild/Clippy pass on that correction.

## Device-enablement follow-up, without redundant reruns

Do not require the owner to repeat the complete Class3 workflow solely because
it was split into smaller test methods after those checkpoints were observed.
The prepared four-case bulk run has **not** run and is not a new security gate.
Preserve its cases for future regression use. Remaining physical evidence is:

- Device-credential app UI workflow (native adapter round trip already passes).
- Biometric-enrollment invalidation (settings window elapsed; unverified).
- Actual process-restart/reboot password requirement.
- Screen-off/manual-lock during an in-flight prompt, including late-result refusal.

Host policy tests cover expiry, attempt counting, binding and credential/rotation
invalidation; physical results cover only the observed paths above. The owner
closed the implementation phase on 2026-11-02. These missing physical checks
remain requirements for device enablement; the normal device gate stays closed.
Fresh-context implementation review is still due and is not claimed here. Repeated harness races
are not additional product requirements. No new six-authentication bulk run is
needed merely to reconcile the existing evidence.

## Device matrix — incomplete

| Requirement | Evidence needed | Status |
|-------------|-----------------|--------|
| AES-256-GCM, nonexportable generated key, TEE/StrongBox and hardware auth enforcement | native KeyInfo checks + successful auth-bound wrap/unwrap on named hardware | pass: StrongBox key checks and authenticated Class3/credential round trips |
| Every operation needs Class 3 auth; wrong AAD fails | interactive Class3 test | pass: 13.340 s; wrong AAD reaches authenticated doFinal and AEADBadTagException |
| New biometric enrollment invalidates | interactive enrollment test; decryption initialization must fail before prompting/fallback | pending |
| Separate device credential policy, reduced label, no biometric fallback | separate interactive credential test | adapter pass: 22.221 s; app workflow pending |
| Reboot/process death requires password | restart/real reboot and app status; no in-process binding restored | pending |
| Age including suspend, three failed attempts | host state machine; native elapsedRealtime age and lost-state refusal; app attempts | native age/lost-state pass: 8.548 s; Class3 app three-cancellation limit and password fallback pass: 15.195 s |
| Password change/rotation revoke handles and exports/backup exclude them | host binding/invalidation tests; on-device workflow and package inspection | partial: host/package and actual-app password-change revocation checkpoint; device rotation not exercised |
| Screen-off/manual lock cancels an in-flight prompt; no late session | on-device prompt/lock race | pending |

After connection, run the ordinary synthetic app regression:

`sh crates/qv-app/scripts/test-android.sh`

Run each hardware case explicitly (each operation requires the human's native
biometric/PIN authentication; do not replace it with injected UI success):

```sh
adb shell am instrument -w -e class 'org.quickvault.app.QuickUnlockTest#testClass3RoundTripAndWrongVaultAAD' org.quickvault.app.test/android.test.InstrumentationTestRunner
adb shell am instrument -w -e class 'org.quickvault.app.QuickUnlockTest#testReducedDeviceCredentialRoundTripAndWrongVaultAAD' org.quickvault.app.test/android.test.InstrumentationTestRunner
adb shell am instrument -w -e class 'org.quickvault.app.QuickUnlockTest#testBiometricEnrollmentInvalidatesTheHardwareKey' org.quickvault.app.test/android.test.InstrumentationTestRunner
```

The last case opens system security settings and needs a new biometric added
by the owner, then a return to QuickVault; it does not modify enrolled
biometrics itself. Record actual model/build/WebView, results and hardware key
level, plus the manual rows above. Only then consider adding the exact device
fingerprint to the native gate; validate both exposed policies before enabling
the fingerprint. A failing/unsupported policy stays disabled. No allowlist
entry is inferred from the earlier 0031 phone observations.

## Design references

Android's [keystore guidance](https://developer.android.com/privacy-and-security/keystore)
and [KeyInfo API](https://developer.android.com/reference/android/security/keystore/KeyInfo)
identify hardware custody and hardware-enforced authentication as separate
checks. The [biometric prompt guidance](https://developer.android.com/identity/sign-in/biometric-auth)
binds authentication to a CryptoObject for per-operation keys. The code checks
these properties; only actual device results establish the tested backend's
observed behavior.
