# Physical-target validation

2026-11-09. **Qualification in progress.** Initially `adb devices -l` returned
only the header. The owner then connected the phone and identified it for this
run: the owner's Android test phone, arm64-v8a, Android 15 / API 35,
WebView 156.0.8078.47. Device serial is omitted from shared artifacts.
The Linux development host supplies headless test and benchmark evidence;
the complete supported-device list and independent reviewer remain undecided.

## Reproduction and identity

Use the [app README](../../crates/qv-app/README.md) and the tracked
`crates/qv-app/scripts/build-android.sh` / `test-android.sh` procedures. The
runner requires one authorized unlocked phone and uses synthetic private
fixtures. Read the current runner options before invoking device-specific
tests. Rebuild against the current baseline before counting a device result.
Use existing private synthetic directories, never the owner's personal vaults.

For each target record model, OS/API/build, architecture, application commit,
build profile/features, APK/binary digest, backend capabilities, test date and
operator. Record KDF parameters and dataset identity; keep the production
SQLite flags and crypto/storage limits. Device IDs and screenshots must not
expose personal credentials or identifiers in shared artifacts.

## Required attended matrix

Every row below is **pending actual target execution**, not a passing result.
Run the relevant enrollment/sync rows with Android and Linux each acting as A
(the offering device) and B (the joining/initiating device).

| Scenario | Required observation |
|----------|----------------------|
| Create, password unlock, full paged search, lock/reopen | Correct complete results and input cleanup on ordinary and large/conflicted synthetic vaults; lock removes readable state |
| Password enrollment | Password on both devices, comparison confirmation, complete transfer, verified publication, shared-password reopen and a subsequent durable edit |
| Recovery-phrase enrollment | Independent recovery input; preserve shared password; no password-method grant; verified publication and writable reopen |
| Existing-copy sync in both directions | Convergent offline edits; explicit initiation only; no stored device link, automatic reconnect or remote state advancement |
| Biometric-unlocked offering device | Real platform authentication and normal source approval policy; wrong/cancelled prompts fail without a grant |
| Background, screen lock, navigation and cancel | Native lifecycle reaches Rust cancellation; inputs and spent codes clear; no late session appears |
| Grant sealing boundary | Distinguish cancellation before authorization from possible disclosure after sealing, including loss of delivery/receipt |
| Publication/anchor boundary | Distinguish complete receipt from created file and anchor completion; cancellation after publication keeps the file and returns no unlocked session |
| Wrong password/phrase, code reuse and second connection | Failure releases no unauthorized data; spent admission stays closed; fresh explicit window needed |
| Interrupted/slow network and endpoint retry | Absolute deadline includes prompts/KDF; no background restart; no partial merge; truthful durable-outcome report |
| No Internet/account/server | Real Android↔Linux LAN exchange with Internet unavailable, without disabling the LAN itself |
| Large and conflicted vaults | Record actual row/head/ciphertext counts, complete search coverage and process RSS; no assumption that cache size bounds process memory |
| Near-1-GiB vault | Transfer/verify/open/search/lock on an actually populated dataset, separately from arithmetic-boundary tests |
| Final-dependency KDF | Repeated real-device latency and peak memory at the fixed parameters; no lowered-cost substitute |

Host loopback tests, synthetic Android keystores, cross-compilation and the
populated host P3 benchmark remain useful separate evidence. They do not fill
these physical/lifecycle/interoperability rows. No latency/RSS acceptance target
is invented here; target selection remains an owner decision.

## This session's actual results

Physical-phone core benchmarks completed all four existing profiles, including
50,000 records and the actually populated near-1-GiB attachment vault. See
[commands, raw data and limits](LARGE-VAULT-VALIDATION.md). These run under the
shell UID, not the app. Additional on-device 67.5/135 MiB synthetic fixtures
pass complete paged traversal/search and integrity checks; 135 MiB search takes
70.895 s. App process memory and large/conflicted GUI searches remain separate
evidence.

Pinned Dioxus 0.7.10, JDK 21.0.12, Rust 1.98.1, Android arm64/API29 link target,
SDK/build-tools35 and NDK27.3.13750724 rebuilt both package variants. The default
host `dx` was an incompatible 0.8 alpha; it was not used for the final build.
The missing Rust Android standard library was installed without changing the
toolchain pin. Normal and validation manifest/build inspection passed.

| APK | SHA-256 |
|-----|---------|
| Normal app | `dcc18217d62effa38a6357d20458f0dd1056a1dd711056b753a7c068e65fadcd` |
| Normal instrumentation | `83170e60a4ba1746e75a7a9b1918b88ea7b2f590409f0d50ffe1990a7729e4a0` |
| Validation baseline | `1a00124f2ef82ce0a7e87f94eab9dfb7bbd58dde248c0791a36ea26d6bfdcd30` |
| Separate-UID validation app | `343e2f913bb3e3bc7effa2596f2bbfcfa13233df3f76bd09fb334373a881a5b9` |
| Separate-UID focused instrumentation | `1bd093aae5e6e99353a08b8d6a61be6bc03c811ed8dee6d08e0aeb79193ef1ae` |

### Full UI run: failed; isolation defect in the test procedure

`sh crates/qv-app/scripts/test-android.sh` installed the current normal APKs
with `-r`, preserving app data. `PlatformTest` failed at its switch to Create:
automatic fingerprint unlock opened the selected regular vault before the
test entered its synthetic flow. The failure happened before fixture creation
or its entry mutations. It is **not a passing app workflow/lifecycle result**.
Failure context containing existing workspace labels was removed from the
retained log; [the redacted failure](evidence/android-platform.log) preserves
the assertion and stack. The regular app remains on the rebuilt normal APK.

The test's claim that it never selects an existing vault is insufficient when
the product automatically selects/prompts for the remembered vault. Further UI
tests on this populated device require separate app identity, storage and
keystore ownership, not just a different fixture path. A marked validation
build alone still uses the normal application ID; do not install it over the
regular app for this run.

`package-isolated-android.py` (removed 2026-11-14, in git history; the
maintained, generic packager is `crates/qv-app/scripts/package-isolated-android.py`)
packaged the already
built validation library as `org.quickvault.validation48`. Namespace, JNI
class names and native library bytes are preserved; the script checks `.so`
hash equality with the validation baseline. The resulting separate Android
UID owns its own data and keystore. It changes only generated test Intent
targets and adds a focused empty-app boundary method. The original full-flow
test remains present and its failure remains open. Package generation passes;
native digests are in [the evidence](evidence/android-validation-native-hashes.json).

Initial installation of the separate app was rejected with
`INSTALL_FAILED_USER_RESTRICTED: Install canceled by user`. No bypass was
attempted. The owner later reported not watching the prompt and attended the
next attempt: both isolated packages installed successfully, without modifying
the regular application's storage or keystore. The focused boundary method
**passes** (2.932 s): FLAG_SECURE, real WebView restrictions/CSP, synthetic
password input and pause/resume clearing, without creating/opening a vault.
It does not replace the failed full flow or claim biometric/LAN coverage.

After the owner reported the phone was back on, retried the same verified APK
once. It again returned INSTALL_FAILED_USER_RESTRICTED before instrumentation.
Read-only device status showed the screen on, keyguard not showing and input
unrestricted; the phone was connected and unlocked. Asked whether any install
approval prompt appeared. Do not infer that the owner deliberately rejected it
from Android's generic "canceled by user" error, or bypass the installation
restriction. Retry log: `isolated-app-install-retry.log` in the evidence directory.

The subsequent attended installation and passing test are recorded in
`isolated-{app,test}-install-attended.log` and
`android-isolated-boundary-attended.log`. The selected existing
`QrTest#testStrideBoundsAndNoImplicitCameraSession` also **passes** (1.880 s),
covering native frame stride/size bounds, stale request handling and no startup
camera session. This run uses neither live-camera nor optical-scan options;
those checks remain separate.

### Owner-observed fingerprint flicker

The owner reported the app flickering behind the fingerprint prompt during
the full UI attempt. `PlatformTest` deliberately calls `callActivityOnPause`
and `callActivityOnResume` before its synthetic flow; native lifecycle
generations invalidate forms, and `app.js` covers/uncover the page on visibility
changes. Automatic fingerprint prompting can overlap that sequence. This is
a plausible test-induced trigger, not a confirmed root cause for sustained
flickering. Asked whether it was continuous or one/two flashes; clarification
and isolated reproduction remain pending. No production lifecycle, cleanup or
biometric policy was altered to suppress the observation.

On the attended repeat, the owner reports **no flicker** behind the three
fingerprint prompts. The selected existing
`QuickUnlockTest#testClass3RoundTripAndWrongVaultAAD` passes in 19.665 s:
hardware-authenticated seal/open round trip and wrong-vault AAD rejection after
authentication. This test does not force the earlier pause/resume sequence.
It does not reproduce the original flicker or establish its root cause.

The immediately preceding run **failed** (49.809 s) during its first seal:
the callback reached stage70 (cipher finalization/output check), then returned
native failure state2. Metadata reports level2, 256-bit key, per-use hardware
authentication, tagRejected=false and invalidatedKey=false. The exception type
is not retained by this adapter, so the cause is unresolved. Keep that failed
run beside the passing repeat; do not declare unconditional device qualification
or weaken key/authentication requirements to make the result pass. Logs:
`android-isolated-biometric.log` and `android-isolated-biometric-repeat.log`.

### Owner-observed vault-path field

The owner saw a vault-file path input in the isolated validation app. Source
trace: `ui/mod.rs` sets `typed_path = fixture`; all four path controls render
only under that condition. Validation deliberately exposes them to the test
driver. The regular Android app does not enable that fixture flag.

Using `package-isolated-android.py --normal-ui`, packaged the exact prebuilt
regular native library under the separate synthetic UID and asserted that the
regular Create UI has no `#vault-path` or "Vault file (full path)" label. This
**passes on-device** (3.037 s), along with secure-window, CSP, input and lifecycle
assertions. The final APK's native libraries match the regular baseline's bytes.
This verifies the existing production UI; no product UX change was needed.
The temporary test app/packages are removed after the run and regular QuickVault
is brought to the foreground without inspecting or changing its vault data.

| Regular-UI test artifact | SHA-256 |
|--------------------------|---------|
| Separate synthetic app | `45578dea8e0b2120e9812f72c1a1fdbc9c9b610d57260546c73884cf00547185` |
| Instrumentation | `0f31d20d19da4c5dea246439b0ef702d1ddd65ff264329849ba1c7d0cb81f9c3` |

Log: `android-isolated-normal-ui.log`. These focused passes do not close the
failed full-flow test, unresolved first hardware failure or remaining physical
LAN/lifecycle/publication/biometric-source rows.

The owner's follow-up question exposed a separate missing flow: regular
Android currently has no "Open a vault file" picker entry. `ui/mod.rs` gates
both that menu item and the welcome action on `can_pick`, which is Linux-only;
its `pick_vault` callback is also compiled only for Linux. Android's existing
SAF document adapter serves attachments/archives, not external vault opening.
App-local listed vaults and LAN enrollment remain available. The successful
no-path-input check does not establish external-file opening. Found, not fixed:
adding Android vault-file selection needs a scoped plan, including how the
existing 0009 §1.8 import-in-place contract applies to provider-backed files.
