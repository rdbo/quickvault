# Phase 1.9 — Dioxus Linux/Android feasibility report

The shared Dioxus fixture app works on Linux and the physical Android phone,
using qv-core for offline create/list/edit/save/lock/reopen. The owner selected
standard webview input (D8 resolved). This completes feasibility evidence, not
production frontend or security validation. Release and adapter gaps are below.

## Runtime evidence (2026-10-27)

| Exercise | Linux | Physical Android | Evidence/limit |
|----------|-------|------------------|----------------|
| Shared form/create/list | observed | owner confirmed | Real core and full password-kdf/1; dummy fixture only |
| Edit/save/lock/unlock | changed title persisted | owner confirmed changed title persisted | Core tests also verify protected-value persistence; stored protected values never rendered |
| Input cleanup | empty controls after Save/lock | owner reported workflow worked | Whole article remounted by form generation; framework copies remain best effort |
| Escaped text | script-like title remained literal | not separately exercised | Not an exhaustive active-content audit |
| Home/background lock | desktop screen-lock integration deferred | owner confirmed reopening is locked | Native lifecycle flags plus 50 ms Rust watcher; not a measured latency guarantee |
| Screenshot protection | no desktop claim | owner confirmed expected blocking | FLAG_SECURE on this app only; no device screenshot collected |
| API-availability button | explicitly reports adapters deferred | owner confirmed it worked | Exact returned booleans not retained; no full adapter claim |
| Late input/session, idle | 2 controller tests pass | same controller code | Real core, bounds/wrong password, stale callbacks/results; not exhaustive device race testing |

Private app metadata confirms the encrypted fixture is mode 0600, with a separate
0600 anchor and 0700 dedicated parent directories under noBackupFilesDir. No
fixture contents were copied from the phone. The owner used only dummy data.

## Unlock timing and process memory

One warmup followed by five sequential full core unlocks; each session is locked.
Full password-kdf/1 unchanged. Timings include core verification, not only KDF.
Linux uses a host debug build with Argon2/BLAKE2 dev optimization and software
rendering. Android uses a native arm64 release build in a debug-signed package.

| Platform | Sample | Unlock ms | RSS before KiB | Peak KiB | RSS after KiB |
|----------|--------|-----------|----------------|----------|---------------|
| Linux | 1 | 408 | 166504 | 428732 | 166464 |
| Linux | 2 | 406 | 166464 | 428732 | 166464 |
| Linux | 3 | 402 | 166464 | 428732 | 166464 |
| Linux | 4 | 408 | 166464 | 428732 | 166464 |
| Linux | 5 | 410 | 166464 | 428732 | 166464 |
| Android | 1 | 852 | 355716 | 617860 | 355836 |
| Android | 2 | 865 | 355836 | 617980 | 351116 |
| Android | 3 | 861 | 351116 | 613260 | 351116 |
| Android | 4 | 866 | 351116 | 613260 | 351112 |
| Android | 5 | 881 | 351112 | 613256 | 351108 |

Linux median **408 ms**, range 402–410 ms; Android median **865 ms**, range
852–881 ms. Android's sampled peak is 617980 KiB (about 604 MiB), versus
428732 KiB (about 419 MiB) on Linux. Numeric raw samples are retained in
[evidence/linux-unlock.csv](evidence/linux-unlock.csv) and
[evidence/android-unlock.csv](evidence/android-unlock.csv).

RSS samples every 25 ms cover the Rust/UI process only, excluding separate
WebView renderer processes, and may miss brief peaks. These are not total app
memory budgets. The phone is API 35, arm64, about 11 GiB physical RAM, meeting
the supported baseline but not representing its 4 GiB low end. The observed
sub-second unlock does not validate all supported-device KDF budgets. No profile
change is proposed from this one-device feasibility measurement.

## Build and packaging

- Linux: pinned stable Rust; GTK 3.24.52, WebKitGTK 2.48.1, owner-installed
  libxdo. Default GUI-linked build/tests and the real window run successfully.
- Android: dx 0.7.3 built from source (installed 0.8 alpha not used), NDK
  27.3.13750724, JDK 21, Gradle compile SDK 33/build-tools 34.0.0. The build-only
  wrapper copies the generated project and enforces minSdk 29 because dx's
  template hardcodes 24 despite its native compiler API setting.
- Inspected app ID `org.quickvault.feasibility`, label QuickVault feasibility,
  minSdk 29, targetSdk 33, arm64-v8a, backups disabled, signature valid.
- Android INTERNET permission is needed for Dioxus's loopback TCP/WebSocket
  transport. It grants broader network capability than loopback; the spike
  implements no remote feature. Its only other request is its own AndroidX
  signature permission. No personal-data permission is requested.
- Packaged network policy denies remote cleartext and allows only 127.0.0.1
  cleartext for the local UI socket. This does not prevent encrypted remote
  connections allowed by INTERNET. No global cleartext or CSP exception added.
- Native imports are Android system libraries; no bundled OpenSSL library.

Final normal APK SHA-256:
`57e68b1417efc9622f212e7552783741e856ec5517de3d0b908adfe2970e7e60`.
Rebuild with `spikes/ui-feasibility/scripts/build-android.sh` after selecting
pinned dx and the documented SDK/JDK environment. It never installs an app.

## Device findings fixed during the spike

1. Dioxus failed to bind its loopback listener without INTERNET permission.
   Restored the standard framework socket permission.
2. The custom manifest omitted Dioxus's loopback network-security policy,
   leaving a white screen even after the listener worked. Restored the reference
   with an explicit remote-cleartext denial and 127.0.0.1-only exception.
3. Create returned a redacted I/O error. Temporary static-stage/numeric-code
   tracing identified SQLite extended code 1550 (CANTOPEN_SYMLINK) at open.
   The Android adapter now canonicalizes the existing OS-provided app directory
   before adding the fixture root. SQLite NOFOLLOW, ownership and mode checks
   remain enabled. Owner confirmed the normal build then worked.

The diagnostic build printed no path, password, title, SQL or payload. Its patch
is retained in [evidence/android-storage-trace.patch](evidence/android-storage-trace.patch).
Original qv-store source was restored exactly; the final installed APK contains
no diagnostic tracing. No core API/format or storage-policy change was needed.

Two initial installs were rejected by the phone's installation restriction.
The owner resolved that setting and later independently uninstalled the test
app before requesting a fresh install. Agent actions used only the existing
localhost adb server and this inspected package, its private files and PID-scoped
diagnostics. No phone settings, provider activation, personal-data access,
rooting, agent uninstall/data-clear, or reboot occurred. The app and its dummy
fixture remain installed; nothing was removed without the owner's action.

## Adapter evidence and follow-ups

The Android availability button calls the existing Wry context to load
AndroidKeyStore, query biometric/autofill feature flags and obtain ClipboardManager.
The owner confirmed it ran; exact booleans are not retained. No keys were
created/enumerated, no biometric authentication invoked, and no clipboard
content read or written. These mechanisms compile and execute, but production
key wrapping/authentication and sensitive clipboard ownership/expiry still need
implementation and validation. Linux keyring/biometric/clipboard adapters and
logind/screen-lock integration are explicitly deferred.

The packaged inert autofill class is guarded by BIND_AUTOFILL_SERVICE. It never
inspects requesting apps or fills/saves data, has no provider metadata, and is
not enabled. This proves class/entry-point packaging only; functioning provider
metadata, verified-identity matching and end-to-end service binding remain gaps.
Quick unlock and autofill remain disabled. No native secret-input adapter,
framework fork or custom engine was added.

## Preliminary source-review risks (not runtime results)

Inspection of dioxus-desktop 0.7.3 source identified these release-hardening
items; the approved disposable-data workflow does not establish compliance:

- `src/protocol.rs:130–179` unconditionally injects an inline module bootstrap
  and an evaluation module, even with a custom index. This conflicts with a
  literal no-inline executable-script policy unless an approved integration
  can replace the bootstrap; no unsafe-inline/eval exception is authorized.
- `src/webview.rs:303–312` deserializes the IPC String without an application
  size check before queuing it. Caller-side application validation alone is
  not evidence of a bounded framework message-ingestion path.
- `src/protocol.rs:67–76` exposes a framework file-dialog endpoint in addition
  to app-defined actions; it must be evaluated against the allowlisted-bridge
  requirement. Its presence is not a claim of arbitrary file-read exploitation.
- `src/webview.rs:364–384` blocks later internal navigations but opens external
  http/https/mailto URLs through webbrowser. Application link rendering and
  explicit-action constraints need validation; no stored link has been opened.

These are source observations in the stock framework, not evidence that a
QuickVault exploit ran or that no integration can meet the contract. These remain production release-hardening gaps. The approved plan permits
this disposable synthetic-data spike while retaining the release requirements;
no framework patch or CSP exception was introduced.

## Dependency and verification evidence

Four explicitly owner-approved advisory exceptions and version-scoped license
exceptions apply only to the isolated spike. Its retained vet store reports
89 fully audited, 47 partially audited, 356 exempted. Exemptions are an initial
baseline, not independent audits. Root policy, lockfile and audit store remain
unchanged (27 fully audited, 6 partially audited, 75 exempted).
See [DEPENDENCIES.md](DEPENDENCIES.md) for IDs, reasons and limits.

Required root/spike gates passed before the final documentation handoff:
SPDX, fmt, all-target Clippy with -D warnings, locked tests, deny and vet.
Root tests: 456 passed, 2 ignored; spike: 2 passed. Final checks passed and their results are recorded in PLAN.md. Passing checks do not establish security.

Build/inspection logs: `/tmp/qv-ui-android-package-canonical.log`,
`/tmp/qv-ui-apk-{manifest,signature,network}-canonical.log`.
Final gate logs: `/tmp/qv-final19-{spdx,fmt,clippy,test,deny,vet}.log` and
`/tmp/qv-final19-spike-{fmt,clippy,test,deny,vet}.log`. Temporary logs support the session; retained
numeric CSVs and the observations above are the durable feasibility evidence.

## Feasibility conclusion

The selected Dioxus UI can share real-core offline vault workflows across Linux
and Android. This phase found and fixed concrete packaging/path integration
issues and measured one physical phone without changing KDF parameters. The
prototype remains isolated and non-production. Production active-content,
OS-adapter, broader-device performance and lifecycle/race validation remain
follow-up work; D8 is settled and needs no repeated framework-choice approval.
