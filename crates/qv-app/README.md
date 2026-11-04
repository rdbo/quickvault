# QuickVault shared app foundation

The shared Android/Linux Dioxus UI provides the CLI's offline feature set:
- create, phrase confirmation or recorded skip, password/phrase unlock,
  snapshot-backed anchor recovery and lock;
- browsing, search, entry view and edit, groups, move, trash;
- reveal (30 s) and copy (Rust → OS clipboard, 20 s), TOTP codes, generator;
- history, conflicts, snapshots, archive export/merge, attachments;
- settings, password change, phrase redisplay, key rotation (including
  finishing an interrupted one), verify and vault information.

Validation: [2.4](../../plans/0030-app-foundation/VALIDATION.md),
[2.5](../../plans/0031-app-vault-workflows/VALIDATION.md),
[2.7](../../plans/0034-android-autofill/VALIDATION.md).

Android autofill (plan 0034, 0009 §4.4) is implemented behind its own
device-validation gate; no device or browser is enabled yet. The service only
hands off: it returns a generic "Unlock QuickVault to fill" entry. The shared
app then shows the requester, needs unlock and an explicit choice (each
conflicting version is listed separately), and returns only the chosen
username/password. Matching is exact. Native apps match only entries linked
through the confirmed "Link this app" action on the autofill screen, which stores
`androidapp://<package>#sha256=<signer digests>`. Websites match exact
`http(s)` origins, and only when reported by an allowlisted browser (the
allowlist is empty until device-validated digests are recorded). Titles,
labels and URL substrings never match. Digital Asset Links are not used, since
they would need a network fetch. A lock after unlocking cancels the request.
The chosen values pass through JNI/JVM arrays (zeroed after use),
`AutofillValue` strings and the target app's own fields: best-effort framework
copies, as for the other Android adapters. On an enabled device, Settings →
Password → Autofill opens Android's autofill-service chooser.

Android quick unlock (plan 0033) is implemented behind a device-validation gate.
No device is enabled yet. Unsupported/unvalidated devices keep password unlock.
On a validated API 30+ device, Settings → Password offers password-reauthenticated
Class 3 enrollment and a separate **device credential · reduced protection**
action. The latter makes the device PIN/pattern/password a vault credential;
biometric unlock never silently falls back to it. Each operation needs native
OS authentication. Hardware policy is checked before use (StrongBox preferred,
TEE permitted; software keys refused).

Quick unlock lasts only for the current app process. Restart/reboot, lost state,
seven days (including deep sleep), three failed/cancelled attempts, password
change or rotation require the master password again. Its encrypted envelope and
trusted counter are held in memory; aliases are deleted on invalidation and stale
QuickVault aliases cleaned on startup. Nothing enters vault exports, sync or backup.
JNI/provider/JVM intermediates have bounded best-effort cleanup, like the other
Android adapters. Physical validation and interactive commands are recorded in
[plan 0033](../../plans/0033-android-quick-unlock/VALIDATION.md).

Android process lifetime (plan 0035): the Rust runtime starts once per process.
Configuration changes (rotation, dark mode, font size, locale) are handled in
place. When the activity is destroyed, for example by Back, the vault locks
and the process ends; the next launch is a fresh process, so quick unlock and
any pending autofill request need the master password or a new request.

App limits (plan 0031):
- Single-line inputs accept 1 KiB and multi-line notes or protected values
  8 KiB, below the 64 KiB native IPC bound. Larger existing values can be
  viewed, revealed and copied, and are edited with the CLI.
- Protected values are never prefilled into inputs; leaving a protected value
  blank keeps it unchanged.
- A recovery phrase on screen allows 5 minutes of inactivity; other screens
  lock after 60 seconds.
- Linux files are chosen by absolute path and opened through the CLI's
  no-follow owner rules. Linux copy uses the X11 clipboard (XWayland on
  Wayland sessions); without an X server, copy is unavailable and says so.
- Android uses the system document picker. Attachments stream in bounded
  chunks with no plaintext temporary file; ciphertext archives are staged in
  private no-backup storage and removed afterwards. Copied text and
  attachment chunks briefly exist as JVM objects. A chosen document belongs
  to the current screen: it is forgotten on navigation, on lock and after a
  save into it, so a later save never overwrites it silently.
- Android marks clips sensitive (API 33+) and clears them at expiry or lock
  only when it can verify the clip is still its own. While another app has
  focus, Android may hide that, so the clip is left for the system to expire.
- Background locking is immediate on Android, except for two app-started OS
  interactions begun in the foreground: a copy keeps the vault open until its
  20 s hold ends, so it can be pasted, and the system document picker (which
  always backgrounds the app) keeps it open until the app is back with a
  choice or cancellation. Screen-off, lost protection and the 60 s inactivity
  lock still apply.

On Linux, install GTK 3, WebKitGTK 4.1, libxdo and the AppIndicator development
libraries, then run:

```sh
cargo run --locked -p qv-app --features desktop --bin quickvault
```

The app requires private owner-only state storage. Linux OS screen-lock/sleep
monitoring uses logind when available; sessions without it can use vaults after
acknowledging the displayed reduced protection. Manual lock and the 60-second
inactivity timeout remain active. Linux uses `$XDG_STATE_HOME/quickvault`, or
`$HOME/.local/state/quickvault`, with separate vaults, anchors and snapshots.
A second instance refuses startup. A blank vault path
selects the app vault. Persistent use requires acknowledging the displayed
protection limits. Inactivity locks after 60 seconds; background locks immediately
on Android (except during a foreground clipboard hold or document pick, above). Resume never unlocks.

Startup failures identify the missing prerequisite:

- **Private storage unavailable:** the private state root or instance-lock
  file could not be established with the required ownership and permissions.
- **QuickVault is already running:** another instance owns the same private
  state directory. Switch to that window or close it before restarting.

Messages are fixed categories and never include paths or raw OS errors.
On Linux, a visible warning reports unavailable automatic screen-lock/sleep
locking. Losing an installed monitor locks the current session and clears the
form; an explicit retry can proceed after reviewing the reduced protection.
Android's lifecycle and secure-window requirements remain mandatory.

For visual review without opening or creating vaults:

```sh
cargo run --locked -p qv-app --features validation --bin qv-ui-preview
```

This is a read-only synthetic preview. Use synthetic input only. The separate
`qv-flow-harness` exercises real core operations in a newly created private
temporary directory, then removes only that fixture directory. These harnesses
are excluded from ordinary desktop/mobile builds.

Run protected-controller tests with `cargo test --locked -p qv-app`. Run actual
WebKit boundary and shared-screen flow tests with:

```sh
cargo test --locked -p qv-app --features validation
```

These tests require Xvfb (`QV_TEST_XVFB` can select its executable). They start
private X servers and use synthetic values. No graphical display is required by
default workspace tests.

Android arm64/API 29+ packaging uses the repository's pinned SDK/NDK recipe,
JDK 21 and Dioxus CLI 0.7.10:

```sh
sh scripts/setup-android.sh --accept-licenses
eval "$(sh scripts/setup-android.sh --print-env)"
# Set JAVA_HOME to JDK 21 and install/select dx 0.7.10.
sh crates/qv-app/scripts/build-android.sh
```

`QV_DX` selects the CLI. The script writes ignored app/test APKs and tooling
caches under `dist/`; it does not install or contact a device. APKs are debug
signed, intended for synthetic validation. Device instructions and artifact
identities are in the validation record. After building, the repeatable runner
compares installed package hashes, installs changed packages without clearing
app data, and tests separate synthetic
vaults:

```sh
sh crates/qv-app/scripts/test-android.sh
```

It requires exactly one authorized, unlocked phone. `QV_ADB` selects a working
ADB client/server; the runner never replaces that server. Only the test window
stays awake during the run. Test fixtures use a newly created private directory
and never open the existing app vault. Logs and failure status are retained in
a temporary directory printed by the runner. Android uses canonical noBackupFilesDir,
backup disabled and FLAG_SECURE. Hardware quick unlock and autofill remain
disabled on unvalidated devices.

`QV_APP_DEVICE_VALIDATION=1` selects an explicit synthetic app build and writes
`quickvault-validation-debug.apk` and `quickvault-validation-tests.apk`.
It displays a validation banner, uses a separate `validation-current` private
root, and restricts foundation opens to its fixed synthetic vault. Only this
build injects hardware-backend availability for device testing; real native
key-policy checks and authentication remain required. The explicit
`QuickUnlockUiTest` methods exercise enrollment, lock/unlock, password-change
invalidation and three cancelled prompts through the shared app UI and core.
Install the normal build again after device testing. Record results in plan
0033's validation record; this build does not validate or enable a device.

Rust forms use protected containers, bounded input and epoch cancellation.
Compiled local scripts explicitly clear DOM inputs on submit, cancel, lock and
visibility changes. Framework, WebKit and OS input/renderer copies have
best-effort cleanup, not deterministic erasure. Linux automatic OS monitoring
is an optional reported capability. Manual and
inactivity locking work without it; Android requires its native lifecycle
monitoring and secure window. The maintained renderer
integration and dependency patch scope are documented in
[third-party](../../third-party/README.md).


LAN QR codes (plan 0039) are displayed by the shared Devices screen for pairing
and Receive. They carry the exact binary 0013 payload, with a four-module quiet
zone; the typed code/address fallback remains available. Scanning only fills
Join, Link or Sync; the user must still explicitly connect and approve the SAS.
A manually edited endpoint supersedes scanned address hints. Lock/navigation
clear pending scanned secrets and hints, and each LAN action consumes them.

Android uses an in-app Camera2 preview, asks CAMERA permission only at Scan,
keeps one bounded luminance frame in memory and closes on cancel, timeout,
lock/pause or destruction. No captured image file or external camera/scanner
app is used. Camera/autofocus hardware are optional. Rust encoder scratch,
modules and retained payloads are protected; exposed decoder/JVM buffers wipe.
Camera/provider/JVM/decoder stack and renderer copies still have best-effort
cleanup limits (0008); do not claim complete erasure.

The ordinary APK's QR camera gate remains closed pending physical validation.
Build a marked validation APK with `QV_APP_DEVICE_VALIDATION=1`; then select
that same variant when running its focused adapter instrumentation:

```sh
QV_APP_DEVICE_VALIDATION=1 QV_ANDROID_TEST_CLASS=org.quickvault.app.QrTest sh crates/qv-app/scripts/test-android.sh
```

Add `QV_ANDROID_QR_CAMERA=1` for the explicit live-camera adapter check:
grant permission on the phone when requested, then it checks bounded sensor
frames, stale requests, cancellation, pause cleanup and the 30-second timeout.
Only its test window stays awake; it saves no frame. This mode requires the
marked validation package. `QV_ANDROID_QR_OPTICS=1` instead checks the shared
Join Scan button through the camera, JNI, Rust decoder and core form insertion;
aim the phone at a known synthetic pairing QR displayed on Linux. It checks
that no pairing payload prefills DOM controls and that navigation clears the
form. Neither mode pairs a real peer or establishes offline sync evidence.

The runner supports just the named PlatformTest/QrTest classes and verifies
installed hashes. It does not clear app data. Physical camera permission,
optics/lifecycle and the deferred phase 2.10 offline-LAN test are the final
combined step in [DEVICE-VALIDATION.md](../../plans/0039-lan-qr/DEVICE-VALIDATION.md).
Validation has resumed on the connected phone; results and remaining rows
are recorded separately from cross-build and synthetic evidence. [DEPENDENCIES.md](../../plans/0039-lan-qr/DEPENDENCIES.md)
records the new library pins, targeted source inspection and unaudited debt.
