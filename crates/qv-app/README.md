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
[2.5](../../plans/0031-app-vault-workflows/VALIDATION.md).

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
backup disabled and FLAG_SECURE; clipboard, keystore, quick unlock and autofill
remain unavailable.

Rust forms use protected containers, bounded input and epoch cancellation.
Compiled local scripts explicitly clear DOM inputs on submit, cancel, lock and
visibility changes. Framework, WebKit and OS input/renderer copies have
best-effort cleanup, not deterministic erasure. Linux automatic OS monitoring
is an optional reported capability. Manual and
inactivity locking work without it; Android requires its native lifecycle
monitoring and secure window. The maintained renderer
integration and dependency patch scope are documented in
[third-party](../../third-party/README.md).
