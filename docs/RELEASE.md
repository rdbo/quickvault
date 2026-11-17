# Releasing QuickVault

The procedure for a tagged release. What must be true before 1.0, and who
does what, is in [plan 0056](../plans/0056-release-1-0/PLAN.md); this file
is the mechanical part. Nothing here waives a 0012 §3 gate: a feature whose
gate has not passed is disabled or left out of the release.

## Before tagging

1. The tree is clean and `master` CI is green on every job (`gates`,
   `app-boundary`, `windows`, `android-app-build`, `supply-chain`, `fuzz`).
2. All `AGENTS.md` gates pass locally on the release commit, plus
   `RUST_TEST_THREADS=1 cargo test --locked -p qv-app --features validation`.
3. `cargo deny check` and `cargo vet --locked` pass (workspace and
   `fuzz/`).
4. Every plan that changed code is `Reviewed` (`plans/README.md`), and the
   per-platform attended checklists for the platforms being released have
   recorded results.
5. Set the workspace version in `Cargo.toml` (`[workspace.package]
   version`), run `cargo update --workspace --offline` so `Cargo.lock`
   follows (also `fuzz/Cargo.toml` and `fuzz/Cargo.lock`), move the
   `CHANGELOG.md` "Unreleased" entries under the new version with the date,
   and write the release notes (below).

## Artifacts

Pushing a tag `v<version>` (matching `Cargo.toml`) runs
`.github/workflows/release.yml`, which builds everything from the tagged
commit with `--locked` and publishes a GitHub Release. Pushes and pull
requests (`ci.yml`) only test; they publish nothing.

| Asset | Built on | Install |
|-------|----------|---------|
| `quickvault-<v>-android-arm64.apk` | Ubuntu, `build-android.sh` with `QV_APP_RELEASE=1` | Open the file on the phone (allow installs from this source) |
| `quickvault-<v>-windows-x86_64.exe`, `qv-<v>-windows-x86_64.exe` | Windows (MSVC) | Run; the app needs the WebView2 runtime that Windows 10 and 11 ship |
| `quickvault_<v>_amd64.deb` | Debian 12 container, `package-deb.sh` | `sudo apt install ./quickvault_<v>_amd64.deb` (Debian 12+, Ubuntu 24.04+) |
| `quickvault-<v>-r0-alpine-3.22-x86_64.apk` | Alpine 3.22 container, `package-alpine.sh 3.22` | `apk add --allow-untrusted ./quickvault-<v>-r0-alpine-3.22-x86_64.apk` |
| `quickvault-<v>-r0-alpine-edge-x86_64.apk` | Alpine Edge container, `package-alpine.sh edge` | `apk add --allow-untrusted ./quickvault-<v>-r0-alpine-edge-x86_64.apk` |
| `SHA256SUMS` | the last job | `sha256sum -c SHA256SUMS` |

The release starts as a draft and is published only when every asset is
uploaded. A tag that does not match the workspace version stops at once.
`package-linux.sh` (tarball) and `package-windows.ps1` (zip) remain for
local builds.

Choose the Alpine package matching your repositories: `alpine-3.22` for
Alpine 3.22 and `alpine-edge` for Edge. Stable and Edge can provide different
library ABIs (for example, libxdo.so.3 versus libxdo.so.4). Each release build
installs its APK in a clean matching container and checks both binaries'
dynamic libraries before uploading it. Edge builds target the repository
state at build time; a later Edge ABI change can require a rebuild.
The original 1.0.0 stable asset used the shorter `alpine-x86_64` filename;
it targets 3.22 and does not provide an Edge build.

The APK's `versionName` is the workspace version and its `versionCode` is
`major·10000 + minor·100 + patch` (1.1.0 → 10100; the build refuses a minor
or patch above 99). Android installs an update only with a higher code, so
never re-release a version number. 1.0.0 and 1.1.0 were published with code
1; every later release updates over them.

Without `QV_APP_RELEASE=1`, `build-android.sh` builds the development APK
(`android:debuggable="true"`, debug key); never publish it. The release
build refuses validation features and refuses an APK that is still
debuggable.

## Signing and checksums

Artifacts are unsigned (owner decision, 0012 §3); `SHA256SUMS` lists every
asset.

- **Android** refuses unsigned APKs and installs an update only over an APK
  from the same signer. The release APK is therefore signed with one stable
  project key, kept as GitHub Actions secrets. It attests continuity between
  releases, not identity. Create it once (keep a copy offline: losing it
  means users must uninstall, and lose app data, to install the next
  release):

  ```sh
  keytool -genkeypair -keystore quickvault-release.jks -alias quickvault \
      -keyalg RSA -keysize 4096 -validity 36500 -dname "CN=QuickVault"
  base64 -w0 quickvault-release.jks > quickvault-release.b64
  ```

  Then, on GitHub: the repository's **Settings → Secrets and variables →
  Actions → New repository secret**, twice: `QV_ANDROID_KEYSTORE_B64` with the
  contents of `quickvault-release.b64`, and `QV_ANDROID_KS_PASSWORD` with the
  keystore password. Delete `quickvault-release.b64`; keep the `.jks` and the
  password outside the repository. (The release workflow's own `gh` runs on
  GitHub's machines; nothing needs installing locally.)

- **Alpine** packages are always signed by `abuild`; each build signs with a
  throwaway key it discards, so installs use `--allow-untrusted`.
- **Debian** packages are not signed (only apt repositories are).

## Release notes

Write them in `docs/release-notes/<version>.md` before tagging; the release
workflow uses that file as the release body. Record (0012 §3):
- the commit, tag and toolchain (`rust-toolchain.toml`);
- pinned dependencies (`Cargo.lock`) and the `cargo deny`/`cargo vet`
  results, with the audit status of the security-critical crates
  (crypto, CBOR, SQLite bindings), stating plainly where none exists;
- known limitations: framework and OS memory copies (0008 §1.1/§4.4),
  clipboard residuals per platform, unvalidated devices, disabled features;
- test results and the attended evidence actually recorded;
- the reproducible-build status: the Linux tarball uses fixed archive
  metadata, but the binaries are not yet verified as reproducible.
