# Plan 0039 — LAN QR display and camera scanning (roadmap 2.10b)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-11-03 | 2026-11-03 | 0013 §1.4, §4.2, §8.2, §8.5; 0009 §1.6/§1.7; 0008 §1/§4; 0012 §1/§3 |

Implementation and automated verification are complete (steps 1–5).
Combined device validation has native-camera and optical Join passes; real-peer
pairing/sync and remaining step 6 rows are pending and carried to roadmap 2.11;
the fresh-context review approved the implementation on 2026-11-04 (REVIEW.md).
This status does not close step 6 or enable the ordinary-package camera gate.

## Intent

Display pairing and address-only receive QR codes in the shared app and scan
both with the Android camera. Owner explicitly requested implementation now,
with the remaining attended 2.10 testing moved to the end of this phase.
Preserve all staged 0038 review work; no intermediate commit/session question.

## Scope

In scope: binary QR encoding and bounded grayscale decoding; strict core payload
inspection; shared SVG display and form filling; native Android Camera2 preview
in the existing activity, JNI polling, lifecycle/epoch cancellation and runtime
permission; automated tests, fuzz target, Android instrumentation/build; final
combined device checklist including outstanding 2.10 evidence.

Out of scope: DNS-SD, automatic synchronization, visual redesign, desktop camera,
image files/gallery imports, external scanner apps or cloud/Play Services. CLI
keeps its text fallback; the Linux app provides the desktop QR display. No new
crate, format, protocol, cryptographic algorithm or unsafe product code.

## Spec basis

| Behaviour | Spec | Status | Notes |
|-----------|------|--------|-------|
| Canonical binary pairing/address payloads, endpoint hints | 0013 §1.4/§4.2/§8.5 | Accepted | byte mode, no URL/text/base64 envelope |
| Explicit initiation, windows/lock | 0013 §8; 0009 §1.5 | Accepted / owner-approved Draft | scanning only fills a form; Join/Link/Sync remains explicit |
| Native camera adapter | 0009 §1.6/new §1.7 | Draft, owner-delegated | amendment first, exact profile below |
| Protected buffers and best-effort framework cleanup | 0008 §1/§4 | roadmap/owner-approved Draft | decoder and OS intermediates documented |
| Allocation/work bounds, hostile QR rejection | 0012 §1 | Accepted | discovery remains a hint |
| Device gates | 0012 §3 | Accepted | deferred to final combined checklist; no release claim |

Spec changes: add 0009 §1.7 camera permission/lifecycle/cleanup profile, changelog
and index note. Owner's architectural delegation authorizes this amendment and
dependencies. No Open Question needs a new decision.

## Decisions needed

None pending. Owner direction in this conversation authorizes the scope and
continuation on the staged tree. Standing approval, roadmap 0002, supplemented
by explicit delegated architectural choices for this phase:

- Render in the shared app, with a white four-module quiet zone and black modules.
  Pairing codes are secrets; store symbols in protected memory, clear on close.
- Native Camera2 + TextureView/ImageReader dialog in MainActivity: keeps one Rust
  runtime, avoids an external camera app and image files, and leaves webview
  camera permissions denied. Request CAMERA only after Scan. Camera is optional.
- Use `qrcodegen-no-heap =1.8.1` (MIT) for caller-owned protected encoding buffers,
  and `quircs =0.10.3` (MIT, Rust quirc port) for grayscale detection/binary decode.
  Alternatives: heap-owning qrcodegen; rqrr (hidden image buffers and g2p/lru
  dependencies); ZXing/ML Kit (additional JVM graph or service dependency).
  No independent audit claimed for either selected library. Review exact added
  transitives, pin lockfiles, run deny/vet and record any explicit audit debt.
- Camera remains unavailable in ordinary Android packages until device validation.
  The existing explicit validation packaging mode enables its independent test
  gate. Implementation and synthetic tests can finish now; no phone is required
  in this session. Shared QR display remains usable.

## Design

Components: qv-app owns QR graphics/decoding and minimal native camera glue;
qv-sync validates the existing key-free QR encoding; qv-core exposes inspection
to frontends. Frontends never depend on crypto/store/protocol directly.

Interfaces:
- qv-sync / qv-core `LanQrKind::{Pairing, Address}`, `LanQrInfo { kind,
  endpoints: Vec<SocketAddr> }`, `inspect_lan_qr(&[u8]) -> Result<LanQrInfo, …>`.
  Exact canonical codec, supported profile, at most 1024 bytes; endpoints apply
  the existing production policy and exclude link-local/scope-less IPv6. Reject
  unusable nonempty sets; pairing QR may contain zero endpoints (typed fallback).
- qv-app `qr::Symbol` (redacted Debug; protected row-major modules, size <=177),
  `encode(&[u8])`, `decode(width,height,&[u8]) -> Result<Option<SecretBytes>, AppError>`.
  Byte mode only, <=1024-byte payload. Four-module quiet zone in SVG, no raw HTML.
- `QrTarget::{NewDevice, Link, Sync}`; `Controller::accept_qr(epoch,target,payload)`
  validates through core then fills protected input. Pairing bytes stay binary
  in existing LanCode input and are parsed with JoinCode::from_qr; typed codes
  still use from_manual. All QR endpoints are retained, never remembered beyond
  the form. Address QR fills workspace endpoint candidates; manual endpoint
  edits and navigation clear them. Scan never opens a network connection.
- Android `qvQrAvailable()`, `qvQrStart() -> request_id`, `qvQrFrame(id) -> byte[]?`,
  `qvQrState(id) -> 0 running / 1 stopped / 2 failed`, `qvQrFinish(id)`.
  Frame: private in-process 8-byte little-endian width/height + tightly packed Y.
  This is adapter IPC, not a persisted/wire format. Bounds checked before copy.

Camera and decode bounds: one pending frame, <=1024 per axis, <=786432 pixels,
at most two offered frames per second, <=30 s scan and <=60 decode attempts.
Camera callback respects row/pixel stride. JNI validates Java array length before
allocating and promptly protects/wipes its copy. Decoder bounds precede library
allocation, rejects multiple grids, non-byte/ECI QR and payload >1024; no partial
payload is used on failure. Quircs pixel/cell/payload buffers are promptly wiped;
its internal temporary stack/geometry and OS/JVM/camera copies are best-effort
limits, not guaranteed erasure. No image file, log, argv, restored state or URL.
Encoding scratch and resulting modules use protected Rust storage.

Scan starts only for the correct current form when no worker is busy. Use the
existing worker permit, state cancellation token, epoch and lock generation;
checks before applying results. Lock, pause, cancellation, permission denial,
30 s expiry, camera failure and activity destruction close the native session
and erase pending frames. Camera dialog is FLAG_SECURE. No background deferral
for scanning, no new activity, no OS capture intent. Existing vault write/anchor
path is unchanged.

Errors are existing redacted InvalidInput/Unavailable/Cancelled/Busy categories;
no decoder text or camera details reach UI/logs. A malformed complete QR is
refused; an image without a decodable QR can be retried within the action bound.

## Steps

### Step 1 — Requirements and deferred validation

- [x] Do: amend 0009 §1.7, index/changelog; revise roadmap/0038 records so
  attended 2.10 testing is carried by the final 2.10b step and no longer blocks
  implementation. Keep the 2.10/2.10b device evidence explicitly pending.
- Files: specs/0009-clients-and-platforms.md, specs/README.md, plans/0002-roadmap/PLAN.md,
  plans/0038-lan-exchange/{PLAN,REVIEW}.md, plans/README.md, CHANGELOG.md.
- Done when: owner's continuation/deferred-testing direction is recorded.
- Verify: targeted doc inspection, `git diff --check`.

### Step 2 — Bounded QR engine and strict core inspection

- [x] Do: add exact dependencies, encoder/decoder, core inspection, rejection
  and round-trip tests. Include both real protocol payloads, rotations, scaled
  camera-like frames, multi-code refusal, oversize/dimension/profile/address
  rejection and redacted Debug. Retain lockfiles and supply-chain records.
- Files: Cargo.toml/lock, crates/qv-app/{Cargo.toml,src/qr.rs,src/lib.rs},
  crates/qv-sync/src/lan/{mod.rs,qr.rs}, crates/qv-core/src/{lan.rs,lib.rs},
  supply-chain/config.toml, plans/0039-lan-qr/DEPENDENCIES.md.
- Done when: generated binary QR decodes byte-identically and hostile inputs
  cannot bypass existing core profiles/endpoints.
- Verify: `cargo test --locked -p qv-app qr`; `cargo test --locked -p qv-sync qr`.

### Step 3 — Shared display and scanned forms

- [x] Do: preserve protected symbols alongside LanRun, copy to LanView, clear
  on expiry/finish/cancel/lock. Shared SVG component for both window kinds;
  typed fallback remains. Add form/worker/epoch scan acceptance and endpoint
  lifecycle; no implicit network action. Add camera availability/scan controls
  for new-device Join, existing-copy Link and Sync on Android. Headless and
  WebKit coverage for QR display/cleanup and form acceptance.
- Files: crates/qv-app/src/{lan.rs,lan_tests.rs,controller.rs,workspace.rs,
  ui/mod.rs,ui/workspace.rs,bin/flow.js,qr.rs}, local CSS assets as needed.
- Done when: both QR kinds render, scanned form input is current/bounded,
  manual edits override it, and late results cannot repopulate a locked form.
- Verify: focused qv-app QR tests; app library and validation engine tests.

### Step 4 — Native camera and Android packaging

- [x] Do: Camera2 dialog and bounded Y frames via JNI, runtime permission only
  at Scan; token/id/epoch cleanup on every exit. Independent validation gate,
  CAMERA uses-feature required=false, packaging allowlist, instrumented
  permission/lifecycle/stride/stale-request checks. Build both Android feature
  sets and validation APK; do not install or request a phone now.
- Files: crates/qv-app/src/{android.rs,qr.rs,controller.rs},
  android/{MainActivity.kt,AndroidManifest.xml,tests/QrTest.java},
  scripts/{build-android.sh,test-android.sh}, crates/qv-app/README.md.
- Done when: native code builds and tests can exercise cleanup/denial/stale
  frames; product camera remains gated pending actual platform validation.
- Verify: Android arm64 Clippy for mobile and mobile,validation; APK build.

### Step 5 — Fuzzing, final gates and records

- [x] Do: fuzz bounded grayscale decoding and payload inspection; wire into
  CI smoke/extended lists. Run focused fuzz smoke and final required gates
  once, plus dependency checks. Update architecture component descriptions,
  changelog, README, index and execution log; record implementation separately
  from deferred attended evidence. No self-approval of production review.
- Files: fuzz/{Cargo.toml,Cargo.lock,fuzz_targets/lan_qr.rs},
  .github/workflows/{ci.yml,fuzz-extended.yml}, ARCHITECTURE.md, CHANGELOG.md,
  crates/qv-app/README.md, plan/index/roadmap, supply-chain records.
- Done when: automated evidence and artifacts are recorded; no hidden skips.
- Verify: SPDX, matrix, fmt, workspace Clippy, `cargo test --locked`, deny/vet,
  validation engine tests; 60 s new-target fuzz smoke. No repeated full suites
  while iterating; required final suite after code is settled.

### Step 6 — Combined attended validation (owner deferred)

- [ ] Do: on Linux + supported physical Android device, with Internet blocked
  and no account/server, pair from QR, compare SAS, new-device initialize and
  link existing copies; scan address QR and sync in both directions. Verify
  frame/permission denial, cancellation/back, screen lock/background, timeout,
  camera availability, no image files, code/DOM cleanup and stale-result
  rejection. Include every outstanding attended 0038 / 2.10 check; test typed
  fallback and interruption/retry at transfer/commit/ack boundaries. Record
  device/OS/WebView, artifact hashes and observed results, then evaluate camera
  gate enabling in a reviewed follow-up. D12 release review remains separate.
- Files: plans/0039-lan-qr/DEVICE-VALIDATION.md and phase records.
- Done when: actual results are recorded; pending is never called passed.
- Verify: Android instrumentation `QrTest` plus attended checklist. Explicitly
  deferred by owner; does not block steps 1–5 or require another prompt now.

## Test plan

Steps above use focused checks. Final AGENTS gates run once on settled product
code, with isolated Xvfb; serialized workspace execution retains the known
instance-lock test isolation workaround. 0012 rows: LAN discovery mistaken for
trust, Webview exposure, Ambiguous trust boundary, Unrequested synchronization,
plus carried Account-dependent LAN sync and LAN partial acceptance device rows.
No tests/spec are claimed to prove security. No dependency audits are invented.

## Risks and stop conditions

Bound Camera2 and Rust work before allocation; preserve the existing lifecycle
lock path. Do not weaken window or SAS checks or enable unvalidated camera in
ordinary packages. Record concrete problems and repair within the delegated
architecture; stop only for unsafe/destructive work or an unresolved security
issue that cannot be resolved within these requirements. No commit/push/branch.

## Documentation

- [x] CHANGELOG.md — implementation and owner-deferred validation
- [x] ARCHITECTURE.md — existing app/core/platform component responsibilities
- [x] Specs — 0009 camera profile and index note; statuses unchanged
- [x] AGENTS.md — no workflow/layout change; no edit needed
- [x] DEVICE-VALIDATION.md — combined final 2.10 + 2.10b checklist

## Revisions

### 2026-11-04 — Wrap-up direction

The owner reconnected the phone, then explicitly requested wrapping up and
finishing as much as possible. A proposed private instrumentation/CLI driver
for real-peer testing was not completed or run. Removed its unbuilt prototype
and packaging entry; no new test-control bridge, dependency or product code is
retained. Keep successful native/optical evidence and finish the existing
ordinary-package camera gate check on the final prepared artifacts. Real-peer
pairing, sync and Internet-isolation/interruption rows remain pending in step 6;
they do not block handoff of the implemented phase under the owner's direction.

## Execution log

- 2026-11-03: Architect plan under explicit owner continuation and architectural
  delegation; standing approval, roadmap 0002. Owner moved remaining 2.10
  attended testing to the end of 2.10b and has no time for device work now.
  Existing staged 0038 review changes preserved. Switch to developer for steps
  1–5; step 6 remains pending without asking for approval or a phone.

- 2026-11-03: Step 1 done. Camera profile amended before implementation; owner-deferred validation is recorded in 0038, roadmap and index.

- 2026-11-03: Steps 2–4 implemented. Added qrcodegen-no-heap 1.8.1,
  quircs 0.10.3 and num-derive 0.4.2; existing product dependency versions
  unchanged. Targeted source/debt record is DEPENDENCIES.md. Deny passes;
  vet passes with the three explicitly recorded development exemptions
  (94 fully audited, 11 partially audited, 460 exempted overall). No claim
  that a new package received an independent audit.

  Strict core inspection rejects unsupported profiles, unknown/malformed QR
  labels and any unusable endpoint (including loopback, link-local and mapped
  IPv6 hints). App encoding keeps scratch/modules protected; decoding bounds
  before the library and wipes exposed pixel/bitmap/payload buffers. Shared SVG
  has black/white modules and a four-module quiet zone; path allocation reserves
  once. Both QR kinds clear on expiry, completion, cancel and lock. Scan input
  fills only the selected current form, preserves all pairing QR candidates,
  and retains no endpoint between LAN actions. Manual address/code edits and
  navigation clear address hints; new LAN actions consume codes/hints.

  Android uses a same-activity Camera2 dialog with FLAG_SECURE, action-only
  permission, bounded stride-aware Y frames, one pending frame, 2 Hz offering,
  30 s/60-attempt bound, request ids and epoch/token cancellation. JNI checks
  lengths before allocation and clears returned JVM arrays in chunks. Pause,
  screen-off, destruction, cancel and expiry close capture. Ordinary packages
  keep the independent camera gate false; marked validation packaging enables
  it. Hardware camera/any/autofocus remain optional. QrTest covers synthetic
  strides/bounds, startup/stale-frame behaviour and the production gate; actual
  instrumentation/optics/permission/lifecycle evidence is deferred to step 6.

  Focused results: 4 QR engine/form tests and strict sync inspection test pass;
  new scanned-payload end-to-end test passes new-device join, existing-copy
  link and address sync, with real cores over a host LAN address. Existing
  manual tests remain. The test loopback toggle now changes only while holding
  the shared fixture mutex to prevent parallel tests changing a live fixture.
  All three real-engine WebKit flows pass, including SVG quiet-zone presence,
  cleanup and pairing approval. Desktop/workspace and Android mobile and
  mobile,validation Clippy pass. Both APK variants build; final metadata-only
  packaging refresh follows optional-hardware assertions. No device install.

  New lan_qr fuzz target and CI smoke/extended entries compile. Local smoke
  (`cargo +nightly fuzz run -s none lan_qr -- -max_total_time=60 -max_len=65536 -use_cmp=0`)
  passes 35,775 runs in 61 s, 48 MiB reported RSS. This uses the available
  1.101.0-nightly (2026-11-02), without ASan on musl; CI retains its pinned
  nightly and sanitizer configuration. No unchanged campaign was repeated.

  Final workspace test suite is running once on settled Rust sources, with
  RUST_TEST_THREADS=1 and isolated Xvfb; no source changes are planned while
  it runs. Static/format/matrix/SPDX and final dependency/fuzz checks are in
  /tmp/qv-0039-*.log. Step 6 and fresh-context production review remain pending;
  no approval/phone request, commit, branch, push or staging change.

- 2026-11-03: Final Android cleanup refinement: publish pause/screen/destroy
  generation metadata before potentially slow camera resource closure; attempt
  each resource close even if an earlier close fails, reporting native failure
  status on cleanup exceptions. Catch asynchronous session-creation failures
  and verify the dialog's FLAG_SECURE before opening preview. These enforce
  the planned lifecycle/failure contract. No Rust source changed after the
  final Rust gates began; only affected APK packaging was refreshed.

  Roadmap 2.10 is ticked for its reviewed implementation now that the owner
  moved its remaining attended criterion into this plan's step 6. Pending
  device evidence is retained explicitly; 2.10b acceptance stays unticked.


- 2026-11-03: Step 5 complete; status Implemented for code and automated
  verification. Step 6 remains owner-deferred, and fresh-context production
  review is still required. No review approval or device result is inferred.

  Final required gates on the settled Rust tree:
  - `sh scripts/check-spdx.sh`, `sh scripts/check-matrix.sh`,
    `cargo fmt --check`, fuzz workspace formatting and `git diff --check` pass.
  - `cargo clippy --all-targets --locked -- -D warnings` passes, as do validation
    and Android arm64 mobile/mobile,validation Clippy checks.
  - `RUST_TEST_THREADS=1 QV_TEST_XVFB=/tmp/qv-0038-review-xvfb/root/usr/bin/Xvfb cargo test --locked`
    passes: 876 passed, zero failed, two pre-existing ignored, 48 completed test
    binaries including doc tests. Serialization keeps all assertions while
    avoiding the known parallel platform instance-lock fixture interference.
    This full suite ran once, with unchanged Rust inputs through handoff.
  - All three real-engine WebKit flows pass; the new QR core/form/real-core
    join/link/sync tests pass. The new fuzz target compiles and its recorded
    60 s smoke passes; the full extended campaign was not run locally.
  - `cargo deny check`, `cargo vet --locked` and fuzz-workspace dependency deny
    checks pass with the development audit debt documented above.

  Evidence logs: `/tmp/qv-0039-workspace-tests.log`,
  `/tmp/qv-0039-final-clippy.log`, `/tmp/qv-0039-final-validation-clippy.log`,
  `/tmp/qv-0039-final-android-{mobile,validation}.log`,
  `/tmp/qv-0039-engine-tests.log`, `/tmp/qv-0039-qr-final-focused.log`,
  `/tmp/qv-0039-core-qr-tests.log`, `/tmp/qv-0039-qr-e2e.log`,
  `/tmp/qv-0039-deny-final.log`, `/tmp/qv-0039-vet-final.log`,
  `/tmp/qv-0039-fuzz-deny.log` and `/tmp/qv-0039-fuzz-smoke.log`.

  Product and marked validation APK builds both pass after the final Kotlin
  cleanup refinements; their current identities are recorded in
  DEVICE-VALIDATION.md. Packaging validates manifest/signature and optional
  hardware features. QrTest is compiled into the test APK, but no Android
  instrumentation or physical scan was executed. Logs:
  `/tmp/qv-0039-handoff-{product,validation}-apk.log`.

  Documentation-only handoff edits follow these build/test results; cheap
  formatting/header/matrix/diff and packaging-script syntax checks are rerun
  in `/tmp/qv-0039-handoff-checks.log`. No extra long suite is needed for those
  records. No install, release, commit, branch, push or staging change.


- 2026-11-03: Owner connected the phone, authorizing resumption of step 6.
  Installed the prepared marked validation app/test APKs without clearing data;
  both installed hashes match. Focused QrTest started but timed out at 210 s
  while the phone was screen-off/keyguard locked; exit 1, no passing result.
  Requested unlock; shell input injection is denied by the device, and no lock
  or debugging security setting was changed. Stopped the timed-out run and
  relaunched the validation activity. Separate synthetic Linux app state is
  ready. DEVICE-VALIDATION.md records model/platform, artifacts, log paths and
  current LAN/Internet state. Combined attended rows and fresh review remain
  pending; do not repeat long checks while awaiting the physical unlock.
  Product code and test inputs are unchanged; previous automated evidence
  remains applicable. No staging, commit, push or branch changes.


- 2026-11-03: Owner confirmed continuation after unlocking. The focused QR
  runner still waits during startup with the phone unlocked and QuickVault
  foreground. Stop this attempt rather than consume another 210 s timeout.
  The existing AutofillTest already handles this vendor-ROM singleTask startup using
  an explicit ActivityMonitor and shell foreground launch. Apply that same
  bounded monitor pattern to QrTest, add a fixed startup stage and test-window
  keep-awake with cleanup; no product behaviour or assertions removed. Rebuild
  only the instrumentation APK from the existing validation project and rerun
  the focused device check. Unchanged Rust/full-suite evidence stays current.


- 2026-11-03: Bounded QrTest now passes on the physical phone (0.578 s);
  ordinary-package gate check also passes (0.653 s). Extend this same explicit
  test with an opt-in validation-only live-camera mode, selected through
  QV_ANDROID_QR_CAMERA=1. It checks real bounded Y frames, stale request
  isolation, finish, pause cleanup and the 30 s native timeout, without
  persisting/logging pixels. Grant CAMERA with adb for this adapter check and
  restore its initially denied state afterward; do not count that as runtime
  permission-dialog evidence or optical QR decoding. Add mode documentation,
  keep defaults unchanged, rebuild only tests and run this focused hardware
  check. This is step 6 verification, not a new product capability.


- 2026-11-03: Device policy denies GRANT_RUNTIME_PERMISSIONS to adb as well as
  input injection. No permission state changed. Adjust the opt-in camera check
  to invoke the actual Scan permission action and wait up to 60 s for the
  owner's grant, then explicitly retry after the permission activity returns.
  Requested that physical tap; no debugging/security setting is changed.


- 2026-11-03: Live camera check passes (37.859 s), including the actual
  permission prompt (owner selected one-time access), real bounded sensor
  frames, stale completion/frame isolation, finish, pause cleanup and native
  timeout. Add a separate opt-in optical test through the actual Join Scan
  button, JNI, Rust decoder and core form insertion. A known synthetic QR
  constant from qr.rs is displayed using a temporary signed-package qrcode
  8.2 encoder (cross-implementation fixture); it has no endpoint/live peer.
  Only booleans/fixed stages reach instrumentation output, no frame/payload.
  Check scanned input stays out of DOM, does not submit Join, and clears on
  navigation. This supplements, but cannot replace, real pairing/offline sync.


- 2026-11-03: Physical native camera check passes (37.859 s) after the owner's
  one-time permission grant: real bounded Y frames, stale ids/completions,
  finish, pause cleanup and native timeout. The ordinary gate check also
  passes (0.653 s), and the validation synthetic adapter check passes (0.578 s).
  The separate optical fixture attempt returned no accepted scan in 75 s;
  permission UI was observed and permission snapshots remained denied before
  and after. Record incomplete, not a decoder/core regression or passing optics.
  Added an explicit permission prerequisite assertion so future optical failures
  distinguish missing permission from decode/form failure. No repeated optical
  attempt until the owner confirms physical readiness. README and validation
  record document the two explicit test modes and current artifact identities.
  Only instrumentation, its runner and documentation changed; product code,
  locked dependencies and Rust gates/full-suite inputs are unchanged.


- 2026-11-03: Owner requested the optical retry and granted one-time camera
  permission. Permission UI pauses the activity; State::invalidate deliberately
  resets Join to Unlock. The optical helper's first retry incorrectly assumed
  the Join form survived that lock. Preserve the product lock contract and
  explicitly reselect Join in the validation driver before its one Scan retry.
  No lifecycle/epoch checks are weakened. Add this bounded fixture correction
  before the next ready attempt; keep prior results tied to their artifacts.


- 2026-11-03: Corrected optical retry passes in 5.471 s on the physical phone:
  camera -> JNI -> Rust decode -> canonical core inspection -> current Join
  form; no secret prefill or implicit Join, navigation clears scanned state.
  Logs and current app/test hashes are in DEVICE-VALIDATION.md. After the run,
  native camera has no active client and one-time permission is denied again.
  Native and optical fixture evidence is now recorded separately from still
  pending real-peer pairing, address sync, offline and interruption rows.
  Asked only for the missing isolated-LAN setup, not implementation approval.
  Full Rust suite/Clippy/fuzz/dependency inputs did not change; only Java tests,
  their runner and documentation changed. Recheck current default adapter/gate
  with the final instrumentation APK, plus affected cheap repository checks.


- 2026-11-03: Additional ordinary-package gate pass: 0.649 s on unchanged
  product bytes, test APK e67a3b0e… before the optical-only retry correction.
  Final optical test APK 7fd5d374… passes the validation adapter assertions
  and full optical/form path together. Then ADB lists no connected phone;
  an attempted final ordinary rerun exits at preflight, with no install or test.
  Record that limitation rather than repeat waiting tests. Last installed app
  remains the marked validation build. Isolated-LAN availability was requested
  for remaining actual pairing/sync/offline work. Device disconnection and
  missing offline setup leave step 6 pending; implementation status unchanged.


  Handoff checks pass: SPDX, matrix, cargo fmt, git diff whitespace, shell
  runner syntax and embedded Python AST. Full output/exit statuses are in
  `/tmp/qv-0039-device-handoff-checks.log`. Final Java instrumentation compiles;
  no additional product-source or dependency changes, staging or commits.


- 2026-11-04: Owner reconnected the same unlocked Android phone. Wi-Fi was off;
  enabled it for LAN verification and it rejoined 192.168.1.2/24, with host
  192.168.1.7. Mobile data remains enabled. Host has no network-admin capability;
  an isolated user/network namespace cannot be created (ENOSPC). No system
  limits, global firewall, VPN or Internet routes changed. Architect revised
  only step 6 fixture detail above; switch to developer. No approval question
  or new phase, production change, staging operation or repeated long suite.


- 2026-11-04: Owner explicitly requested wrapping up rather than further test
  setup. Stopped the proposed cross-device driver work and removed its unbuilt
  prototype/packaging line. No host synthetic vault or phone vault was created,
  and no new fixture bridge or executable remains. Continue only the existing
  ordinary-package QrTest that was previously prevented by disconnection;
  leave the ordinary app installed and restore Wi-Fi to its initial off state.
  Preserve successful physical camera/optical evidence, with actual live-peer
  pairing/sync/offline/interruption rows pending. No implementation approval,
  release, fresh review or device result is inferred.


  Wrap-up attempt: ADB again listed no device, so the focused runner exited at
  preflight without an install or test (`/tmp/qv-0039-device-qr-wrap-product.log`).
  The ordinary-package replacement and Wi-Fi restoration could not be applied.
  Last installed app is still the marked validation APK; Wi-Fi had been enabled
  for the LAN setup (initially off). Do not infer a final gate rerun or cleanup
  that did not happen. No further device waiting/retry under the owner's wrap-up
  direction. Keep implementation status Implemented, with review and remaining
  step 6 evidence explicit.


- 2026-11-04: Fresh-context review (REVIEW.md): **Approved with minor fixes**,
  status Reviewed. Reviewer added a non-byte-mode refusal test and fixed a
  flaky 2.10 qv-sync test-harness race (test-only). Two low findings are
  recorded: the permission prompt locks the vault, and a foreign
  QR in view ends the scan. Step 6 attended checks are carried to roadmap 2.11
  (owner-delegated, Revisions 2026-11-04) and have not passed. The camera gate
  stays closed in ordinary packages.
