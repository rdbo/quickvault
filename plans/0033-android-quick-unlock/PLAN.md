# Plan 0033 — Android quick unlock (roadmap 2.6)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-11-02 | 2026-11-02 | 0002 §5; 0008 §1, §3–4; 0009 §1.6; 0012 §1, §3 |

## Intent

Implement opt-in Android hardware-backed quick unlock, with a separately named
reduced-protection device-credential mode. Keep it disabled on devices without
recorded validation, and preserve full password unlock as the prerequisite
following reboot, lost policy state, expiry, three failures or credential changes.

## Scope

Platform policy/backend, core enrollment/unlock/invalidation, Android keystore
and prompt glue, app controls, tests and documentation. No vault format change,
new primitive, dependency, unsafe, server, autofill or Linux quick unlock.
The prerequisite 0031 repairs remain in that plan's revision/log. Complete the
0032 review before handoff. Owner explicitly requests continued work on the
staged current tree; preserve staging and never commit/push/branch.

## Spec basis

0002 §5 is Accepted and defines the complete wrapping/authentication policy.
0008 §1/§3 are owner-authorized via D5; §4 and shared app work via D13 and the
2026-11-02 continuation. 0012 requires actual device evidence and disabled
unvalidated optional features. Specs/statuses need no amendment.

## Decisions needed

None pending. Owner delegated choices and approval on 2026-11-02 and explicitly
requested continuing through the phase. Resolved choices:

- Policy state and envelopes live only in process memory. Process restart is
  treated as loss of trusted policy state and requires the password, in addition
  to reboot/7-day monotonic expiry/three failures. No persistent failure counter
  or rollback-sensitive local policy file. Keystore handles are removed on
  invalidation and stale QuickVault-prefixed handles removed on native startup.
- Wrap the canonical 24-word phrase (a bounded reversible representation of VK)
  through Android AES-GCM; use existing store phrase/header/manifest/anchor
  verification. No new raw-key API or alternate store acceptance path.
- API 30+ only for this optional backend, so authenticator types and per-operation
  authentication can be inspected exactly. Android 10 remains supported with
  quick unlock unavailable. Prefer StrongBox; TEE is permitted with identical
  authentication policy. Software keys and silent authenticator fallback refused.
- Device-credential mode is a separate explicit reduced-protection action, never
  fallback from Class 3. Both modes require per-operation auth and hardware key
  custody/auth enforcement. Unvalidated devices remain disabled.

## Design

`qv-platform::quick_unlock` defines QuickBinding (vault ID 16 bytes,
nonzero generation u32, authenticated password-slot version 16 bytes),
QuickPolicy (Class3/DeviceCredential), a small injected Android backend and a
mutex-serialized AndroidKeystore policy manager. Existing generic Keystore
unbound wrap/unwrap remain unavailable on this backend; bound methods default
unavailable for unsupported platforms. AndroidPlatform injects it explicitly.

Manager interfaces: enroll(binding, policy, protected phrase, cancellation),
binding(), unlock(binding, cancellation), invalidate(). Native backend exposes
validated(), seal(binding, policy, phrase, cancellation), open(binding, policy,
envelope, cancellation), delete(envelope). Envelope <= 1536 bytes, plaintext
<= 1024; zero/oversize/unknown versions reject. Policy uses Instant, at most
seven days, three failed/cancelled unwrap attempts, binding equality and no
secret-bearing Debug/Display. Expiry/invalidation drops envelopes and deletes
handles. Missing/lost state refuses. Native failures are fixed categories.

Native envelope bytes: version 1 u8, algorithm 1 u8 (Android AES-256-GCM),
policy u8, random per-process device ID 16 bytes, random key handle 16 bytes,
provider nonce 12 bytes, ciphertext with 16-byte tag. The AAD is ASCII
`qv/android-quick/v1` followed by fixed-width binding (vault 16, generation
big-endian 4, slot version 16) and envelope header through key handle (35).
Provider generates the encryption nonce; no hand-rolled encryption or nonce
counter. Full header/device/handle/policy checked before decrypt/authenticate.

Kotlin owns AndroidKeyStore AES keys, aliases in a QuickVault-only namespace,
KeyInfo validation and BiometricPrompt.CryptoObject. Use auth timeout 0,
AUTH_BIOMETRIC_STRONG, invalidatedByBiometricEnrollment(true); credential mode
explicitly AUTH_DEVICE_CREDENTIAL. Check nonexportability, origin generated,
256-bit size, AES/GCM/NoPadding, hardware security level and hardware auth
requirement enforcement. Prefer StrongBox; retry generation in TEE only on
StrongBoxUnavailableException, preserving all policy. CryptoObject's cipher
must be the operation authorized; doFinal only in successful callback. One
failed match ends an attempt. A bounded JNI request/poll/result/cancel channel
with a 60-second deadline carries at most 1024 plaintext/1536 envelope bytes;
Rust checks Java array length before copying into protected storage, and JVM
buffers are cleared best effort. Lost foreground/screen protection cancels.

Core Session::enroll_quick reauthenticates the master password and derives the
binding inside the serialized session read; cancellation checks bracket native
work. Core::unlock_quick obtains the manager's binding, authenticates the
phrase through the existing store open and verifies vault/generation/slot
binding and anchors before binding a session/automatic snapshots. Password
change and rotation invalidate handles before writing/consuming the session;
password-slot changes received through merge are caught by binding comparison
before any quick-unlocked session is returned. No token enters exports/sync.
Core sessions retain injected services for enrollment/invalidation, without
frontend access to store or crypto internals.

App exposes availability/disabled reason, opt-in Class3 and separate labelled
credential action after password reauth, disable, and explicit quick-unlock on
the lock screen. Worker generation/epoch checks drop late results. Native prompt
background interaction may defer only background expiry via the established
foreground guard; screen-off/protection loss/manual lock cancel immediately.
No automatic fallback to password or device credentials.

## Steps

### Step 1 — Bound platform interfaces and tested policy manager
- [x] Do: interfaces, bounds, expiry/failure/invalidation state machine.
- Files: qv-platform/src/{lib,android,quick_unlock}.rs; core platform reexports.
- Done when: injected tests cover binding mismatch, state loss, 7-day expiry,
  three failures, cancellation, rejected bounds and deletion; Linux unavailable.
- Verify: `cargo test --locked -p qv-platform quick`.

### Step 2 — Core integration and invalidation
- [x] Do: enrollment after reauth, authenticated quick open, credential/rotation
  invalidation and cancellation/lifecycle checks.
- Files: qv-core/src/{lib,platform,session,setup,credentials,rotation,quick_unlock}.rs.
- Done when: wrong password/anchor/slot/generation refused, real vault round
  trip works through injected backend; lock race cannot return a session.
- Verify: `cargo test --locked -p qv-core quick`.

### Step 3 — Native keystore and prompt adapter
- [x] Do: Kotlin implementation/JNI backend, permission and bounded channel.
- Files: qv-app/src/android.rs; android/{MainActivity,QuickUnlock}.kt,
  AndroidManifest.xml; build script permission allowlist.
- Done when: Android compilation passes, exact auth/KeyInfo checks precede use,
  metadata formats/zeroization documented, unvalidated devices disabled.
- Verify: Android arm64 check/Clippy and APK/instrumentation build.

### Step 4 — App actions and regressions
- [x] Do: enrollment/unlock/disable controls and epoch/cancellation handling.
- Files: qv-app/src/{controller,workspace,ops,ui/mod,ui/workspace,workspace_tests}.rs.
- Done when: disabled/unavailable flow and late-result rejection tested; UI
  states reduced-credential policy explicitly; backend unavailable on Linux.
- Verify: app library and validation/engine tests, validation Clippy.

### Step 5 — Device evidence and documentation
- [x] Do: deliver native/app instrumentation and the device-validation record,
  with observed passes and unverified rows stated separately; keep unsupported
  devices disabled. Owner closes implementation delivery on 2026-11-02; remaining
  physical checks are follow-up requirements for enabling a device.
- Files: Android instrumentation; plan VALIDATION.md; app README;
  ARCHITECTURE §3; CHANGELOG; plans index/roadmap and prior review resolution.
- Done when: real-device results recorded or explicitly pending. Completion of
  this documentation/delivery step does not mark missing matrix evidence passed.
  No equivalent-security or release claim from host tests.
- Verify: all AGENTS gates, app real-engine and vendor focus tests; device runner.

## Test plan

Full SPDX/fixtures/matrix/fmt/workspace Clippy/locked suite on final source;
focused platform/core/app tests during development; Android build/Clippy;
real-engine tests and vendor hardened tests; deny/vet (no intended dependency
change). 0012 rows: Biometric enrollment bypass, Hardware assumptions. Host
policy tests do not establish hardware behavior. Reboot/physical enrollment
and per-operation prompts need an authorized physical device.

## Risks and stop conditions

Never enable unvalidated hardware or weaken auth/security-level checks to get
working prompts. Missing physical hardware leaves device evidence incomplete;
continue all independent implementation/build/host evidence and report exact
remaining device steps. Do not invent hardware evidence. No unresolved design
choice currently needs owner input; approval delegation covers this plan.

## Documentation

Update architecture component responsibilities, Unreleased, app limits/quick
policy, plan index, roadmap phase entry/log and VALIDATION.md. No spec status
promotion, no AGENTS workflow changes.

## Revisions

2026-11-02 (owner phase closure): owner explicitly states “so phase 2.6 is
finished.” Mark implementation delivery Implemented and the roadmap phase done.
Outstanding physical integration checks stay unverified in VALIDATION.md and
remain requirements for device enablement, rather than further implementation
phase blockers. No normative behavior, device allowlist, hardware-validation
requirement or spec status changes. Fresh-context implementation review remains
the next session's prerequisite; no Reviewed status is claimed.

2026-11-02 (device continuation): the initial quick-test startup reproduced an
Android protocol/renderer RefCell borrow panic at vendor edits.rs:136. Extend
scope to the already-authorized dioxus-desktop edits patch: keep the immutable
webview ID/shared mutex-protected server location outside the mutable edit
queue; both CSP/bootstrap metadata accessors use that independent clone. A
focused test holds the edit queue mutably borrowed while reading both metadata
accessors and verifies server location refresh is still observed. No format,
unsafe, dependency or behavior relaxation. Update third-party README, run vendor
focus + real-engine/app Clippy + Android rebuild/check. Also expose bounded,
fixed key-policy stage/evidence metadata to instrumentation; never raw exceptions,
aliases, IVs, keys, plaintext or input. Owner continuation/delegation applies.

2026-11-02: Native age additionally checks Android elapsedRealtime (includes
deep sleep), with a process-local handle creation map. Rust Instant alone
excludes suspend time on Linux/Android. Enrollment releases the session mutex
before native prompting, then rechecks the binding/cancellation, because dropping
a background-deferral guard can synchronously run lifecycle callbacks.

2026-11-02: Existing model VersionId is 16 bytes; use that exact width in
QuickBinding/AAD (36-byte encoding), rather than the initial 32-byte sketch.

## Execution log

- 2026-11-02: Approved under owner delegation/explicit continuation. Same
  staged tree as prerequisite review records; staging preserved. Architect
  inspected existing keystore/core/store interfaces and Android official
  KeyInfo/BiometricPrompt guidance. No new dependency or primitive. Proceed
  as developer with host verification while device evidence remains gated.

- 2026-11-02: Steps 1–4 implemented. Focused platform policy test and real-core
  quick round trip pass; core additionally rejects a changed password slot and
  a missing anchor, destroying the handle. App unavailable/reduced-consent test
  passes. Native and instrumentation APK build passes with pinned dx 0.7.10,
  JDK 21, SDK 35/NDK 27.3; Android arm64 Clippy passes. No new dependency/unsafe.
  Exact artifact identities and device matrix are in VALIDATION.md. All device
  fingerprints remain disabled. An asynchronous request to connect/unlock the
  test phone was issued after artifacts were ready; adb currently has no device.
  Continue host gates/documentation while awaiting hardware. Do not tick phase
  2.6 or step 5 without actual device results.

- 2026-11-02: Final host/build gates pass on the implemented source: SPDX,
  SPDX rejection fixtures, offline matrix, fmt; workspace Clippy; locked suite
  **746 passed, 0 failed, 2 existing ignored** with private Xvfb; qv-app
  validation **28 passed** and validation Clippy; vendor hardened **5 passed**;
  Android arm64 app/platform Clippy; final app + instrumentation APK build and
  signature verification; deny/vet (93 fully/11 partially audited, 421 exempted).
  Full logs: `/tmp/qv-next-phase/phase-*.log`, Android logs and artifact hashes
  in VALIDATION.md. No dependency/lockfile changes. Self-check verified native
  AAD/policy/key-info checks, cancellation without holding the session mutex,
  generation/slot/anchor revalidation, bounded JNI intermediates, and no raw
  crypto or frontend bypass. This is not an independent security review.
  `adb devices` is still empty after the connection request. Step 5's physical
  rows remain pending; phase unticked, status In progress and all devices
  disabled. All authorized independent implementation and verification is
  complete. The next action is the prepared synthetic device/hardware tests
  once the phone is connected, followed by ordinary fresh-context review.
  Original staged index preserved; no commit/push/branch.

- 2026-11-02 (phone connected): POCO X7 Pro 2412DPC0AG, Android 15,
  fingerprint `POCO/rodin_global/rodin:15/AP3A.240905.015.A2/OS2.0.7.0.VOJMIXM:user/release-keys`,
  WebView 156.0.8078.47. Installed APKs without clearing app data. Extended
  PlatformTest passes, OK (1 test), 62.241 s. Initial quick-test startup crashed
  in vendor CSP's edits_path while the render RefCell was mutably borrowed;
  applied the scoped revision and its regression (six vendor tests pass).
  Updated app validation passes (28 tests) and Clippy passes. Device retry no
  longer crashes and reports generated AES-256 StrongBox key metadata:
  level=2, auth=2 (Class3), timeout=0, hardwareAuth=true, invalidates=true.
  Authentication did not complete before the test deadline; not a wrapping pass.
  Further retry found qvStatus=12 (locked/background), so failed before use.
  Interactive test now keeps only its test window awake, as PlatformTest does,
  without changing production lock/screen protection. Requested phone unlock
  and readiness; continue independent checks while waiting. No device enabled.

- 2026-11-02 (attended retry): owner confirmed they had missed the earlier
  prompts, then authenticated the next attempt. It reached the success callback
  but encryption failed at doFinal (stage 70). Architect/developer local revision:
  keep AAD bytes identical, but feed them after CryptoObject authentication and
  before payload processing. AOSP AndroidKeyStoreCipherSpiBase caches AAD-stream
  errors until doFinal, so pre-auth streaming is the suspected cause; confirm
  on device rather than claiming a pass from source inspection. No parameter,
  algorithm, key policy, bound, fallback or normative behavior change.

- 2026-11-02: Moving AAD streaming after authentication resolves the observed
  encryption failure: attended Class3 encryption passes. The next prompt did
  not complete. Instrumentation now waits one second after completed prompt
  cleanup before starting another, preserving per-operation authentication.
  Strengthened negative checks: wrong AAD must reach authenticated doFinal and
  throw AEADBadTagException; enrollment invalidation must report permanent key
  invalidation, not cancellation/missing policy. Added a native expiry/lost-
  state test that backdates only its synthetic in-memory birth map via test
  reflection, never the OS clock and without a production override API.

- 2026-11-02 (app-flow validation revision, owner asks to distinguish platform
  from app testing): Class3 and separate credential authenticated round trips
  and strict wrong-AAD tag failures pass; native expiry/lost-state passes.
  Enrollment settings window elapsed and remains unverified. Add an explicit
  QV_APP_DEVICE_VALIDATION build (existing validation feature) with a visibly
  marked isolated `validation-current` root, foundation opens restricted to its
  fixed synthetic vault path. Only this build injects a fixture adapter that
  bypasses the recorded-device availability gate; every actual hardware/auth/
  binding check remains unchanged. Normal mobile build keeps the empty gate.
  Separate validation APK names prevent replacing production artifacts. Add
  actual shared-UI enrollment/lock/unlock, credential invalidation and three
  native authentication cancellations through core; later process/reboot probe.
  No real vault may open in this fixture. Reuse existing instrumented DOM helpers.
  Also distinguish transient authentication cancellation from permanently lost/
  invalid backend state: Unavailable invalidates the slot immediately; three
  Cancelled/other transient failures retain the existing attempt limit. Native
  result consumption waits for the foreground observation before releasing its
  background guard, as the existing document-picker path does. Add policy tests
  for permanent invalidation and repeat affected/full gates on the final source.

- 2026-11-02 (first actual-app device run): the isolated UI build creates a
  real synthetic vault, enrolls Class3 through Settings, and quick-unlocks it
  through the shared lock screen. The run then fails password-change validation
  before completing the remaining assertions (49.443 s overall, not a suite
  pass). The driver did not wait for the password-pane fields and ignored null
  evaluateJavascript results. It now waits for both controls and asserts each
  synthetic input was delivered; fixed stage-only progress identifies the
  completed boundaries without printing input. Added an outside-fixture path
  refusal probe and one-second cancellation dismissal waits. Retry pending.
  Permanent native unavailability policy regression passes (two policy tests
  total). Workspace Clippy, app validation (28), vendor hardened (six), static
  gates and focused Android validation Clippy pass; full suite still running.
  The initial broad cross-target Clippy command also linted unchanged qv-store
  dependencies and exposed an existing Android-only unnecessary u64 cast in
  location.rs:154. The intended app/platform --no-deps target check passes;
  the complete host workspace Clippy gate also passes. No lint allowance added.

- 2026-11-02 (second app run): isolated path refusal, vault creation, Settings
  enrollment, actual quick unlock and password-change revocation all pass.
  The first cancellation returns to the locked form without an error paragraph;
  the test incorrectly requires that paragraph (51.841 s overall, not a suite
  pass). A lifecycle lock may legitimately clear the error. Replace that
  incidental message expectation with stronger relevant checks: native failure
  category must be authentication cancellation, the worker completes, no
  workspace/session appears, the quick action persists only for attempts 1/2,
  disappears after 3, and the changed password still opens the vault. Fixed
  per-attempt progress records those assertions. Extend the existing foreground
  deferral fix to cancelled native results too, since both success and failure
  callbacks can precede observed OS-credential dismissal. No prompt, key policy
  or authentication requirement relaxed. Correct the lock screen's protection
  details so it reports availability rather than always saying unavailable.
  Rebuild and rerun affected app/Android checks and the actual device workflow.

- 2026-11-02: Repeated full workspace suite passes **747 tests, 0 failed,
  2 existing ignored**, retained log `crates/qv-app/dist/validation-0033/workspace-tests.log`.
  Updated real-app validation passes **28 tests**; vendor hardened remains six
  passed on unchanged vendor source. Final static gates, host workspace/app
  Clippy and focused Android validation Clippy pass. The marked test build is
  installed for a further attended retry; normal build artifacts are refreshed
  separately and will be restored after interactive testing. No device enabled,
  missing enrollment/reboot/race evidence remains unverified, and no independent
  fresh-context implementation review is claimed.

- 2026-11-02 (third app run): creation/enrollment/quick unlock/password-change
  revocation again pass; cancellation 1 is correctly categorized and leaves
  the vault locked with quick unlock retained. Cancellation 2 returns a
  non-authentication failure (31.603 s overall). The instrumentation cancels a
  signal after stage 50, which is published immediately before authenticate();
  cancellation can therefore race SDK prompt submission. Serialize cancellation
  on the main thread after authenticate() returns, as a user-visible prompt
  cancellation would occur. Keep the strict native category/three-attempt/no-
  session assertions. Split the app cases into enrollment/unlock/password change
  (two prompts) and cancellation limit (one prompt) for each policy, reducing
  human authentication during focused retries without dropping coverage.

- 2026-11-02 (focused cancellation run): native authentication cancellations
  1 and 2 pass strict category and locked-state checks. Attempt 3's immediate
  quick-action assertion sees the old DOM (11.775 s overall, not a suite pass).
  Fast cancellation can finish between 200 ms render polls, so checking only
  the old form's enabled controls does not acknowledge the Rust action. Capture
  the form epoch before dispatch and require a different rendered epoch plus
  completed locked controls before each policy assertion. Keep all three
  category/attempt-limit/password checks. This is a test synchronization change,
  not a relaxed attempt limit; rerun the actual app cases.

- 2026-11-02: Actual-app Class3 cancellation case passes **15.195 s**, with
  strict native cancellation category, acknowledged Rust form epoch, locked
  state for all three attempts, quick action retained for 1/2 and removed for 3,
  and master-password reopening. Retained log:
  `crates/qv-app/dist/validation-0033/app-class3-cancellations-final.log`.
  During isolation audit, move the validation root selection before native ROOT
  publication/staging cleanup, so all native staging also stays inside the
  fixture. Previously only Controller's vault/anchor root was isolated. No test
  opened an existing vault; no document workflow runs in these test cases.
  Rebuild/recheck Android and use the corrected root for subsequent app cases.

- 2026-11-02 (owner challenges repeated completion delays): reconciled durable
  logs instead of asking for another bulk authentication run. Credit successful
  actual-app Class3 creation/enrollment/quick unlock/password-change revocation
  checkpoints separately from their later harness failures; the focused
  cancellation/password-fallback case is an actual complete pass. The proposed
  four-case/six-authentication bulk rerun is not a new completion requirement.
  Keep those regression cases, but do not make their reorganization erase prior
  observations. Remaining actual evidence: credential app UI, new-biometric
  invalidation, restart/reboot, and prompt/lock races; fresh-context review also
  remains due. No phase completion or device enablement is claimed. The earlier
  completion update failed to distinguish repeated harness debugging from these
  specific missing physical checks, unnecessarily burdening the owner.

- 2026-11-02: Owner explicitly closes phase 2.6 after distinguishing app
  implementation from outstanding Android/device validation. Marked plan
  Implemented, delivery step complete and roadmap phase done; updated plan
  index, validation disposition and changelog. Missing physical rows remain
  unverified and normal-build quick unlock stays disabled on unvalidated devices.
  Next fresh session reviews this implementation before planning phase 2.7.
  Documentation-only closure; prior passing code gates have unchanged inputs
  (747 workspace tests, 28 app validation checks, host/Android Clippy and builds).
  Recheck SPDX/fmt for the final documentation tree. Staging preserved; no
  commit, push or branch.
