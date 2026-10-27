# Dioxus feasibility spike — not a production password manager

Plan: [0013](../../plans/0013-ui-feasibility/PLAN.md).
Status/evidence: [REPORT.md](../../plans/0013-ui-feasibility/REPORT.md).

The owner selected normal Dioxus webview input. This prototype demonstrates the
shared source/controller structure. Create/edit/reopen and bounded unlock
measurements work on Linux and Android. The phone also passed background locking
and screenshot blocking. See the report for measured results and integration gaps.
Use only disposable credentials and data. It cannot open an existing user vault.
No network sync, autofill provider, quick unlock or external-link feature exists.
The root workspace excludes this crate; it has its own lockfile and deny policy.

The controller uses the real core and full password-kdf/1. It keeps Rust password
input in MasterPassword/SecretText, wipes owned intermediates and drops inputs
and metadata on lock. Dioxus/engine/OS copies are outside deterministic wiping
claims. Lock invalidates late operation results. Initial creation records the
explicit recovery-confirmation skip; this is not a complete recovery/setup UI.
A cancelled creation can leave a valid encrypted fixture file; it is never deleted
automatically. A failed post-create seed can require inspecting/reopening that
fixture; there is no automatic destructive reset.

```sh
# Default shared UI checks:
cargo check --manifest-path spikes/ui-feasibility/Cargo.toml --locked
cargo clippy --manifest-path spikes/ui-feasibility/Cargo.toml --all-targets --locked -- -D warnings

# Real-core controller tests, without linking the platform GUI libraries:
cargo test --manifest-path spikes/ui-feasibility/Cargo.toml --locked --no-default-features --lib
```

Full desktop linking needs Dioxus/Wry's native platform dependencies, including
libxdo development files. The host prerequisites are now installed and the app builds/runs here. Four
advisory exceptions apply only to the spike; see DEPENDENCIES.md in plan 0013. The `ui` feature is on by default; disabling it isolates controller
tests and does not replace required full UI/device validation.

`cargo run --manifest-path spikes/ui-feasibility/Cargo.toml --locked`
uses a fresh per-process private fixture directory under the temporary directory.
`QV_SPIKE_DIR` can name a dedicated reusable fixture directory for restart tests;
it is a fixture root, not a path to a user vault. The app always uses its own
`active/fixture.qvault` and separate `anchors/` paths. Use a private directory.

Android source uses Wry's framework context for its own no-backup directory and
FLAG_SECURE. A pinned dx 0.7.3 arm64 build and package inspection pass.
Build without deploying using `sh spikes/ui-feasibility/scripts/build-android.sh`
after loading the Android SDK environment and selecting JDK 21. `QV_DX` selects
the 0.7.3 CLI; `DX_HOME`, `ANDROID_USER_HOME` and `GRADLE_USER_HOME` can select
writable tool caches. The wrapper copies the generated Gradle project and enforces
minSdk 29 because the CLI template hardcodes 24. Output is
`dist/qv-ui-feasibility-debug.apk` (native release build, debug-signed package).
Before device deployment, inspect the distinct application ID,
manifest and permissions against plan 0013's boundaries. Android INTERNET
permission is required for Dioxus's loopback TCP UI transport; this permission
also grants broader network capability despite no remote feature in the spike.
The build copies the checked-in network-security resource: only 127.0.0.1
permits cleartext (for that WebSocket); remote cleartext is disabled. Do not change phone
security settings, enable an autofill provider, read personal data, clear data,
root, reboot or uninstall any app. Existing authorized adb access is sufficient.

The prototype does not yet satisfy production CSP/bridge/navigation requirements.
Known source-review questions are in REPORT.md. No production release or stronger
memory-protection claim follows from choosing Dioxus or these controller tests.

To measure, create a dummy fixture, lock it, enter its dummy password again and
press “Run 5 unlock samples.” This performs one warmup plus five full-profile
unlocks. Numeric CSV files are saved privately under the fixture root; the UI also
shows the results. RSS samples cover only the Rust/UI process every 25 ms, not
all renderer processes; zero means the counter was unavailable. Optional OS
features remain disabled. The availability probe never reads/writes clipboard
contents, generates keys or invokes biometric authentication. The inert autofill
service checks packaging only; it is not a functioning provider.
