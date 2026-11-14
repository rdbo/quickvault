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
   follows, and move the `CHANGELOG.md` "Unreleased" entries under the new
   version with the date.

## Artifacts

All artifacts are built from the tagged commit with `--locked`.

| Platform | Command | Output |
|----------|---------|--------|
| Linux x86_64 | `sh crates/qv-app/scripts/package-linux.sh` | `target/dist/quickvault-<v>-linux-x86_64.tar.gz` and `.sha256` |
| Windows x86_64 | `crates/qv-app/scripts/package-windows.ps1` (on Windows, MSVC) | `target/dist/quickvault-<v>-windows-x86_64.zip` and `.sha256` |
| Android arm64 | `QV_APP_RELEASE=1 QV_ANDROID_KEYSTORE=<owner keystore> QV_ANDROID_KEY_ALIAS=<alias> sh crates/qv-app/scripts/build-android.sh` (after the usual Android environment; apksigner prompts for the password) | `crates/qv-app/dist/quickvault-release.apk` (with its v4 `.idsig`) and `dist/apk-certs.txt` |

Without `QV_APP_RELEASE=1`, `build-android.sh` builds the development APK
(`android:debuggable="true"`, debug key); never publish it. The release
build refuses validation features and refuses an APK that is still
debuggable. Build the Linux tarball on a glibc distribution no newer than
the oldest one you support: the binaries link the system GTK and
WebKitGTK.

## Signing and checksums

- Each archive contains `SHA256SUMS` for its files, and each archive has its
  own `.sha256`.
- Sign the archives (and the Android APK, through its own signing scheme)
  with the owner's release key, which never enters the repository or an
  agent session. Publish the public key and the detached signatures with the
  release.

## Release notes

Record with each release (0012 §3):
- the commit, tag and toolchain (`rust-toolchain.toml`);
- pinned dependencies (`Cargo.lock`) and the `cargo deny`/`cargo vet`
  results, with the audit status of the security-critical crates
  (crypto, CBOR, SQLite bindings), stating plainly where none exists;
- known limitations: framework and OS memory copies (0008 §1.1/§4.4),
  clipboard residuals per platform, unvalidated devices, disabled features;
- test results and the attended evidence actually recorded;
- the reproducible-build status: the Linux tarball uses fixed archive
  metadata, but the binaries are not yet verified as reproducible.
