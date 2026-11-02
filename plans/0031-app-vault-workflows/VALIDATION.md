# Validation — Plan 0031: App vault workflows (roadmap 2.5)

Evidence for the implemented scope. Passing tests do not prove security and
do not authorize a release (0012). Automated results, real-engine runs and
owner observations are kept separate.

## Environment

- Host: Alpine Linux (musl), Rust 1.98.1 (pinned), sandboxed session.
- Real engine: WebKitGTK through the hardened Dioxus 0.7.10 integration, on a
  private Xvfb 21.1.25. The xvfb and misc-font packages were unpacked into the
  session scratchpad without a system install; `QV_TEST_XVFB` names a wrapper
  that adds the font path.
- This host's `/` is owned by `nobody`. The 0011 §4 ancestor-owner rule
  therefore refuses every absolute path here, which is correct behaviour. Linux
  attachment round trips through absolute paths run on hosts with a root-owned
  `/` (CI).

## Automated

| Check | Scope | Result |
|-------|-------|--------|
| `cargo test --locked` | whole workspace (headless) | 740 passed, 2 existing ignored |
| SPDX, SPDX fixtures, matrix, fmt, workspace and qv-app validation Clippy | final tree | pass |
| `cargo deny check`, `cargo vet --locked` | unchanged graph | pass (93 fully / 11 partially audited, 404 exempted; recorded debt) |
| `cargo test --locked -p qv-app --features validation` | 22 unit + 3 real-WebKit tests (final tree: 25 passed) | pass |
| `cargo test --locked -p qv-platform files` / `android` | moved file helpers; Android clipboard hold, background deferral guard | 3 + 3 pass |
| vendored `dioxus-desktop` focused tests | ingress, navigation, bounded handshake, dropped-batch outcome, resolved batch not re-read | 5 pass |
| `qv-flow-harness` with fixture platform | full shared-screen flow, clipboard unavailable path | pass |
| `qv-flow-harness` with real Linux services | same flow; real X11 clipboard on Xvfb shows the copy toast | pass |
| `qv-boundary-harness` | active-content refusals; exactly 3 refused native IPC messages | pass |
| Android arm64 `cargo check` and Clippy (`--no-deps`, qv-app + qv-platform) | NDK 27.3 clang, `--features mobile` | pass |

The real-engine flow covers:
- create with phrase confirmation;
- a new entry with a generated, never-prefilled protected value;
- a hostile HTML title rendered as text, with no element and no script run;
- a masked value, reveal and hide;
- copy (toast when a clipboard exists, fixed error otherwise);
- delete and trash restore;
- the generator's 30 s display;
- lock with reveal and phrase nodes cleared, then wrong password refused with
  the input cleared;
- unlock showing the entry again;
- phrase recovery with the optional new-password prompt.

## Visual (private Xvfb)

Frames captured from the real flow at 1180 px and 400 px widths were checked:
- desktop sidebar navigation, entry fields with masked values, generator;
- phone width: bottom navigation bar, 44 px targets, stacked field actions.

## Android

Built with the pinned recipe: SDK 35, build-tools 35.0.0, NDK 27.3.13750724,
JDK 21, Dioxus CLI 0.7.10 (installed in the scratchpad, dynamically linked
on musl) and `--locked`.

| Artifact | SHA-256 |
|----------|---------|
| `crates/qv-app/dist/quickvault-debug.apk` | `d36f3f12cddb1a36ac2ceac9c91569b50989cb32a77cbcb9d963856eb07f2d3f` |
| `crates/qv-app/dist/quickvault-tests.apk` | `8f2ac283ab3761990134dad164fca187083433a881d53446bd6b1d9946a35cf1` |

Inspected:
- minSdk 29, targetSdk 35; `allowBackup=false`, `fullBackupContent=false`;
  network security config present;
- permissions: `INTERNET` (loopback renderer) and the generated
  `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`;
- v2 signature verifies with the recorded debug certificate `9bd6ccea…cd9e39`.

### Physical device (2026-11-01/02)

POCO X7 Pro (model 2412DPC0AG, `rodin_global`), Android 15 (SDK 35, build
AP3A.240905.015.A2, HyperOS OS2.0.7.0.VOJMIXM), WebView provider
`com.google.android.webview` 156.0.8078.47. Installed over USB with
`sh crates/qv-app/scripts/test-android.sh`; synthetic vaults only.

Final result: `OK (1 test)` twice in a row (60 s each) on the hashes above.
The suite covers the 2.4 checks (FLAG_SECURE, WebView settings, CSP, input
clearing after background) and:
- create with phrase confirmation; entry create, reveal and hide;
- a copy labelled QuickVault and marked `EXTRA_IS_SENSITIVE`, cleared at expiry
  while owned;
- background during a foreground hold keeps the workspace, then locks when the
  hold ends; unlock again;
- attachment add through the picker path and a byte-exact save;
- archive export to a picked document and merge-back through private staging,
  with no staged ciphertext left.

Failures found on the device, in order, each fixed and verified by the next run
(details in the plan's execution log):
1. The app closed right after start: a resolved edit batch was re-read as
   dropped (vendored `edits.rs`).
2. Android pause locked through tao's `Suspended`, bypassing decision 1.
3. A memoized screen rendered while the worker was finishing stayed empty.
4. The system picker backgrounded the activity, so every pick locked the vault.
5. A finished pick did not re-render the path control.
6. A pick outlived navigation, so an archive export overwrote the attachment's
   earlier destination (test race exposed a real hazard).
7. Archive merge failed: the descriptor-pinned source walk opened ancestors
   `O_RDONLY`, but `/data` and `/data/data` are search-only (`--x`) for apps
   (confirmed with `run-as`). Ancestors now use `O_PATH`.
8. Test-only: row-button matching, exact chosen-name waits, a screen-heading
   wait, and the merge report wording for an own fresh export.

Owner observations on the phone are not recorded here; they belong to the
owner's UI review.

## Not covered here

- Finishing an interrupted rotation: implemented on the lock screen, but
  producing an interrupted journal needs core-internal fault injection.
- Wayland-native clipboard: out of scope; copy needs X11 or XWayland.
