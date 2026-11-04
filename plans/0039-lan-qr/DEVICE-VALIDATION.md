# Final combined validation — phases 2.10 and 2.10b

**Status: pending; device validation resumed on 2026-11-03 after the owner connected the phone.**
Implementation and automated checks may complete without this step. Do not mark
these rows passed, enable ordinary-package camera support, tick the device-gated
roadmap boxes or claim a LAN release until actual results are recorded. This
list carries all remaining attended phase 2.10 work into the end of 2.10b.
D12 independent protocol review remains a separate release gate.

## Record before running

- [ ] Linux OS/app or CLI revision, phone model/Android/WebView versions, package
  variant and app/test APK SHA-256; supported Android baseline: arm64/API 29+.
- [ ] Use newly created synthetic vaults, with no account/server configured.
  Preserve existing vaults and app data. Both devices share a local network.
- [ ] Block Internet access on both devices while retaining their local route,
  and record the method (router uplink disconnected, or equivalent controlled
  firewall). Phone airplane mode + Wi-Fi alone does not establish that the
  Linux host or Wi-Fi uplink cannot reach the Internet.

## Android camera adapter and lifecycle

- [x] Build the explicitly marked validation app/test APKs with
  `QV_APP_DEVICE_VALIDATION=1 sh crates/qv-app/scripts/build-android.sh`.
  Its QR gate is independent of the production-default false setting.
- [x] Run the targeted synthetic instrumentation (compares installed hashes;
  never clears app data):
  `QV_APP_DEVICE_VALIDATION=1 QV_ANDROID_TEST_CLASS=org.quickvault.app.QrTest sh crates/qv-app/scripts/test-android.sh`.
- [x] Focused ordinary-package check confirms the camera gate stays closed.
- [x] Optical Join form check through the real Scan button, camera, JNI, Rust
  decoder and core, with no payload prefill/implicit Join and navigation cleanup.
  This uses a known synthetic QR chart, not a live peer; see the retry record.
- [x] Opt-in real-camera adapter check (`QV_ANDROID_QR_CAMERA=1`): runtime
  permission grant, bounded Y frames, stale request/frame isolation, finish,
  pause cleanup and the 30-second native deadline. See the result record below;
  this narrower pass does not close the remaining lifecycle/optics rows.
- [ ] Before Scan, confirm no camera permission request or capture. Deny the
  permission at Scan: close without a connection or retained image. Grant on
  an explicit later attempt; no restart is required. Permission UI/pause
  cancels a scan on platforms that report backgrounding; retry explicitly.
- [ ] Scan opens the in-app FLAG_SECURE preview, no external camera app or image
  file. Test back/cancel, timeout (30 s), camera unavailable/in use, screen lock,
  pause/background, activity destruction and permission revocation. Listener
  windows/other pending LAN work must still obey the existing lock contract.
- [ ] Confirm late frame/permission callbacks and stale request ids do not
  reopen the camera or refill a locked/different form. Partial/ambiguous/foreign
  QR codes and unsupported profile/address/size are refused. Test rotation,
  glare, tilted codes, a second code in view and both camera orientations.
- [ ] Inspect app-private/cache/gallery locations before/after: no captured
  image files or persisted pairing payload. Record framework/OS cleanup limits;
  no physical-erasure claim. Inspect logs/errors for synthetic canaries.

## Pairing and initialization — carried 2.10 gate plus QR

- [ ] Linux app shows its pairing QR and typed fallback; phone scans from Join.
  Scan fills the form only. Select Join explicitly, compare the six-digit code
  on both devices, approve, confirm the received vault and password-check it.
- [ ] Reverse direction: phone displays a pairing QR; Linux types the fallback
  code/address. Confirm both screens and durable new-device creation. Camera
  scanning is a phone capability; Linux camera support is out of scope.
- [ ] Link existing unlocked copies by scanning a pairing QR. Confirm the same
  SAS; the follow-up exchange keeps concurrent edits and reports both local
  acceptance and peer receipt. Reject a mismatched SAS and stale/observed code.
- [ ] Window expiry/cancel/lock removes both manual and graphical codes. New
  pending questions retain inactivity locking; none outlives its operation.
- [ ] QR without endpoint hints requires a typed endpoint; incorrect or absent
  route does not establish trust. Typing remains usable when camera is disabled.

## Offline exchange in both directions — remaining 2.10 evidence

- [ ] Make different edits on each device. Open a receive window on Linux;
  phone scans the address-only QR, chooses the intended existing link and Sync.
  Scan alone sends nothing. Verify convergence, conflicts and separate local
  acceptance/peer-receipt reporting, with Internet still unavailable.
- [ ] Open Receive on the phone and sync from Linux using the typed address.
  Repeat with Linux app/CLI as appropriate; neither device is a primary.
- [ ] Repeat unchanged rounds; no new local commit. Add concurrent edits and
  verify none are overwritten. No account/server contact or background retry.
- [ ] Interrupt transfer (manifest/object), commit and acknowledgement turns:
  retain prior local edits, reject partial candidates, preserve a completed
  commit and report an unconfirmed receipt if Done is lost. Retry explicitly
  and check convergence/anchor-consistent reopen on both devices.
- [ ] Exercise lock/cancel and receive-window expiry during an active round and
  an unanswered comparison/password prompt. Preserve durable-commit reports
  and completion errors, and verify the listener closes.
- [ ] Remove a link and verify it no longer authenticates; a scanned address
  never restores trust. Manual endpoint edits supersede scanned address hints.
  Endpoints are not remembered between actions.

## Completion record

For each row record the observed outcome, device/revision/artifact identity,
command/log or screenshot reference and any failure. Keep unrun rows pending.
After the device gate passes, separately review enabling production camera;
ordinary packages remain gated until then. Update plans 0038/0039, roadmap
2.10/2.10b and release evidence with the actual results. D12 remains separate.


## Prepared artifacts — 2026-11-03

Product APKs were built after the final Kotlin lifecycle/cleanup changes;
test APKs were subsequently rebuilt for the device launcher and opt-in checks
described below. Paths are under `crates/qv-app/dist/`. These identities
supersede earlier packaging iterations; rebuilds require recording new hashes.

| Artifact | SHA-256 |
|----------|---------|
| quickvault-debug.apk (ordinary camera gate closed) | `39e8cc2f4d54e9cf491210490ed67cc5315d26bce5b945facae34e9045ac98c0` |
| quickvault-tests.apk | `7fd5d374eca61187eb86e230cd8a7ec1901d4a3a20997b424763b52c560e2f8f` |
| quickvault-validation-debug.apk (explicit validation gate) | `eb2af6599215921912a7c5756d03d6c3e2adb1cfd42754c570f9079a3d4b7ea8` |
| quickvault-validation-tests.apk | `7fd5d374eca61187eb86e230cd8a7ec1901d4a3a20997b424763b52c560e2f8f` |

The test APK bytes are identical across these two variants. The build validates
manifest/signature metadata; that evidence does not cover camera optics,
permission UI, lifecycle behaviour or offline two-device operation.


## Connected-device attempt — 2026-11-03

Owner connected one authorized device and resumed step 6. Observed model
2412DPC0AG (`rodin_global`), Android 15/API 35, arm64-v8a, WebView
com.google.android.webview 156.0.8078.47. Host: Linux 7.3.1-0-sigma;
base revision `138bdde` plus the staged 0038/0039 implementation. Phone
192.168.15.2 and host 192.168.15.7 share the LAN. Internet isolation has not
been established; airplane mode was off, mobile data and Wi-Fi were enabled.

The marked validation app and test APKs installed with `adb install -r`, without
clearing app data. Installed SHA-256 values match the prepared validation
artifacts above. Existing private vault/state directories were preserved.

Focused command:
`QV_APP_DEVICE_VALIDATION=1 QV_ANDROID_TEST_CLASS=org.quickvault.app.QrTest sh crates/qv-app/scripts/test-android.sh`.
The runner reached `org.quickvault.app.QrTest:` but produced no completed result
and timed out at its 210 s bound (exit 1). During the wait, native window policy
reported screen off, sleeping and keyguard showing. The phone rejected shell
input injection with INJECT_EVENTS permission denial. An unlock was requested;
no credential, lock-setting or ADB security-setting change was attempted.
This is an incomplete run, not passing instrumentation or physical-camera
evidence. Logs: `/tmp/qv-0039-device-qr-run.log` and
`/tmp/qv-android-tests-cczgx5a_/instrumentation.log`.
The timed-out app was stopped and its validation activity relaunched for the
next unlocked attempt; do not repeat the timeout while the phone is locked.

A separate Linux app instance was launched using
`XDG_STATE_HOME=/tmp/qv-0039-device-host-j8dhjg6n/state`, leaving the owner's
normal app state untouched. Its empty welcome screen is ready for a fresh
synthetic vault. No pairing, scan, sync or offline/interruption row above has
passed yet. Unlock and keep the phone awake before resuming the focused test.


## Unlocked-device verification — 2026-11-03

The owner unlocked the phone and continued. QrTest still waited during activity
startup with keyguard off, screen on and QuickVault foreground. This invalidates
an assumption that the earlier timeout was explained solely by the lock screen.
The test now uses the existing AutofillTest pattern: an ActivityMonitor with a
30 s bound plus the runner's explicit shell foreground launch. No production
behaviour or prior assertion was removed. Only the instrumentation APK was
rebuilt from the existing validation Gradle project (5–8 s incremental builds).
Rust/full-workspace inputs remain unchanged.

Results before the opt-in optical extension:

| Check | Result | Evidence |
|-------|--------|----------|
| Validation adapter: strides/bounds, no startup capture, stale frame | PASS, 0.578 s | `/tmp/qv-0039-device-qr-monitor.log`, `/tmp/qv-android-tests-kxv7tzvp/instrumentation.log` |
| Ordinary APK: same checks plus camera unavailable/start refused | PASS, 0.653 s | `/tmp/qv-0039-device-qr-product.log`, `/tmp/qv-android-tests-s21cf06g/instrumentation.log` |
| Explicit validation live camera: actual permission grant, real bounded luminance frames, finish, stale frame/completion isolation, pause cleanup, 30 s timeout | PASS, 37.859 s | `/tmp/qv-0039-device-qr-permission.log`, `/tmp/qv-android-tests-gps58rhh/instrumentation.log` |
| Shared Join optical path | INCOMPLETE: no scan accepted within 75 s; permission prompt observed, permission denied in snapshots before/after | `/tmp/qv-0039-device-qr-optics.log`, `/tmp/qv-android-tests-l_e5fsn_/instrumentation.log` |

The successful live-camera check used test APK SHA-256
`a792378a638c0e3cdda89c5a15a11f3246323899eb30681ba3db3b0941c18a62`
and the unchanged marked validation app above. Native live-frame checks remain
unchanged by the later optical-only extension. The owner chose one-time camera
permission; it expired before the separate optical attempt. An attempted adb
permission grant was rejected by device policy (GRANT_RUNTIME_PERMISSIONS);
no permission or debugging-security setting was changed through adb.

Repeatable focused modes (both require the marked validation package and
`QV_ANDROID_TEST_CLASS=org.quickvault.app.QrTest`):

- `QV_ANDROID_QR_CAMERA=1`: explicit permission action if needed, then real
  frame bounds/length, stale request/completion, finish, pause and timeout.
  No captured frame is persisted or logged. Only the test window stays awake.
- `QV_ANDROID_QR_OPTICS=1`: shared Join Scan button through JNI, Rust decoder
  and core; assert protected pairing data does not prefill DOM controls, no
  implicit Join, and navigation clears the form. Requires the owner to grant
  permission and aim at a pairing QR. The test reports a missing permission
  prerequisite separately from failure to decode; wait for physical readiness
  before retrying.

The displayed `/tmp/qv-0039-optics-fixture.png` is a public, known synthetic
constant from `crates/qv-app/src/qr.rs::TEST_PAIR`, encoded as QR byte mode by
qrcode 8.2 from a signature-verified temporary Alpine package. It has no live
peer or endpoint. It is an independently encoded test chart, not a captured
image or a real pairing secret; accepting it fills only Join. Window title:
“QuickVault QR validation fixture”. Neither it nor an optical pass would close
real Linux/phone pairing, address sync or Internet-isolation checks.

No existing vault was opened, cleared or removed. Device/LAN acceptance rows
remain pending. Ordinary camera enablement, fresh-context production review
and D12 release review are unchanged requirements.


### Optical retry and final fixtures

Owner requested a retry and granted one-time camera access. The initial driver
assumed Join survived the permission activity's pause; the product correctly
locks, expires the old epoch and returns to Unlock. That attempt was stopped
before its outer timeout. Corrected only the validation driver: explicitly
select Join again, then click Scan once permission returns. Product lifecycle,
lock and stale-result rules remain unchanged.

With that correction the optical check **passes, 5.471 s**, through the actual
Join Scan control, camera, JNI, Rust decoder and core. It observes the fixed
“Pairing code scanned” status, empty renderer code/endpoint inputs, no implicit
Join and cleanup after navigating back to Unlock. Evidence:
`/tmp/qv-0039-device-qr-optics-epoch.log` and
`/tmp/qv-android-tests-atv9uw2s/instrumentation.log`.
App SHA-256 remains the prepared validation hash; test APK is
`7fd5d374eca61187eb86e230cd8a7ec1901d4a3a20997b424763b52c560e2f8f`.
Native camera service reports no active clients after completion. One-time
permission is again denied after the test process ends, as expected on this
phone. No persistent permission grant or debugging-setting change was made.

The final test APK includes the bounded launcher and both opt-in modes; both
prepared test APK paths now have the hash above, superseding earlier test
artifacts. Production app bytes and Rust/full-workspace inputs are unchanged.
The marked-package default adapter assertions also pass as part of the final
optical run. A final ordinary-package rerun could not start: ADB listed no
device at the preflight, so no install or instrumentation occurred. The prior
ordinary-package gate passes (0.653 s and 0.649 s) used unchanged production
app bytes; their test artifacts preceded the last optical-only driver fix.
No full Rust suite or unchanged fuzz/dependency campaign is repeated for
Java/script/docs.

Real Linux/phone new-device pairing with a live code and comparison approval,
existing-copy link, address scanning followed by both-direction sync, Internet
isolation, transfer/commit/ack interruption, denial/back, screen lock/destruction,
camera unavailable/in-use and file/log inspection still require their own
results. Native/optical fixture passes do not close those broader rows.


### Handoff after device disconnect

`/tmp/qv-0039-device-qr-product-final.log` records an additional ordinary-package
pass, 0.649 s, with the preceding test APK
`e67a3b0e7bcb2c3d6ea335e18590b4220c97a6e1f9387dbadd938dc201bf6948`.
After the final successful optical run, `adb devices -l` became empty. The
attempt to repeat the ordinary check with the final optical-only fixture
correction stopped immediately at the runner's device preflight (exit 1):
`/tmp/qv-0039-device-qr-handoff-product.log`. No test result is inferred from
that refused run. Last installed app is the marked validation APK; the final
optical run confirms its test APK and real Scan path. No subsequent package
replacement occurred after disconnection.

Asked the owner whether an isolated LAN is available for the remaining offline
work. Do not change global networking or mark Internet isolation from app/core
fixture passes. Reconnect the phone for remaining device checks. No product
camera gate is enabled and no fresh-context review has been claimed.


## Wrap-up — 2026-11-04

Owner reconnected the unlocked phone and then requested wrapping up, finishing
as much as possible. Previously successful native camera and optical Join
results above remain the device evidence. No long suite or unchanged camera
campaign was repeated.

Wi-Fi was initially off; enabled it for LAN setup, and it rejoined
192.168.15.2 with Linux at 192.168.15.7. Mobile data stayed enabled. Linux has
no network-admin capability; a trial isolated user/network namespace failed
with ENOSPC. No system limits, firewall, VPN or Internet routes were changed.
Internet isolation was never established and no live-peer round was started.

A proposed test-only physical-LAN driver was stopped during wrap-up. Its unbuilt
prototype and packaging entry were removed; no new command/control bridge,
dependency, host synthetic vault or phone vault remains from that work.

Attempted the already-prepared ordinary-package camera gate check, but ADB again
listed no device. The runner exited at preflight without installing or testing:
`/tmp/qv-0039-device-qr-wrap-product.log`. The attempted ordinary-APK replacement
and restoration of initially-off Wi-Fi could not be performed. Last installed
app remains the marked validation APK; Wi-Fi was enabled during this session.
Existing app/vault data was preserved.

Implementation is complete. Fresh-context review and the unchecked real-peer,
offline/interruption and remaining lifecycle rows are explicitly pending.
Owner's wrap-up instruction ends this testing session; no release/device gate
is inferred from the incomplete attempts.
