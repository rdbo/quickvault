# Maintained third-party source

Owner-approved packages: x11rb 0.13.2 (plan 0015, D1/D2), plus the five
exact app-foundation snapshots listed below (plan 0030). The owner also
authorized necessary correctness fixes within the clipboard implementation.
The retained package is excluded from the product workspace and selected by an
explicit local Cargo patch. Product adapter code retains ordinary AGPL SPDX
headers and workspace lints; upstream files retain upstream licensing/lints.

## Provenance

Upstream archive: <https://crates.io/api/v1/crates/x11rb/0.13.2/download>.
SHA-256: `9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414`.
`x11rb/UPSTREAM.sha256` records this hash. Upstream copyright/license files are
retained unchanged. Registry VCS metadata is omitted. The upstream archive's
Cargo.lock is replaced by a lockfile for the maintained package's focused CI
tests, separate from the product Cargo.lock.

The SPDX checker validates the exact package name/version and provenance
metadata before allowing upstream headers. This is not a source-content check
or an audit. Compare the retained source against the hashed archive when
reviewing/updating. Only the following upstream files have local changes:

- `Cargo.toml`: existing qv-crypto path dependency for protected memory, exact
  protocol version 0.13.2, local MSRV 1.98.1 and publication disabled.
- `src/rust_connection/write_buffer.rs`: fixed SecretBytes ring replaces the
  ordinary payload VecDeque; consumed slots and fatal errors wipe it. Borrowed
  vectored writes and FD ordering remain. Added partial/write/backpressure,
  wrap, redaction and FD-order regression tests.
- `src/rust_connection/packet_reader.rs`: a fixed header guard checks reply and
  GenericEvent lengths before the upstream protocol reader can resize; maximum
  packet is 1 MiB. Buffered/fragmented header paths are covered, including an
  advertised maximum under a subprocess memory limit. The read path uses the
  existing 4 KiB staging buffer, rather than bypassing header checks with direct
  reads into a large protocol buffer.

The shared qv-platform clipboard Stream (also used by the CLI) separately caps lifetime input at 4 MiB, rejects
received FDs, and bounds nonblocking I/O with deadlines/cancellation. This limit
also bounds the library's eager queue accumulation. These guards do not replace
upstream decoding or claim complete dependency security. Copied plaintext uses
borrowed ChangeProperty serialization and DefaultStream vectored I/O; the
protected ring is the only library-owned outgoing payload copy on that path.
Tracing/extra-traits/XCB/unsafe features are not enabled.

## Verification and maintenance

- `sh scripts/test-check-spdx.sh` and `sh scripts/check-spdx.sh`.
- `cargo test --manifest-path third-party/x11rb/Cargo.toml --locked --lib rust_connection`.
- `rustfmt --edition 2021 --check third-party/x11rb/src/rust_connection/write_buffer.rs third-party/x11rb/src/rust_connection/packet_reader.rs`.
- Product gates and deny/vet, including isolated-Xvfb clipboard tests. Install
  Xvfb, or set `QV_TEST_XVFB` to its path; missing Xvfb is a test failure.

No package outside the approved list below is exempt. Record any baseline/patch change, preserve
licenses, trace payload copies and allocation bounds again, and review local
patches as maintained application code. Vet exemptions are not audits. Never
update a mutable git reference or download source during the build.


## App foundation additions (plan 0030)

Owner delegated dependency/integration decisions on 2026-11-01. These are plain
published-source snapshots, not Git submodules/history. Upstream licenses,
headers and lints are retained; product code keeps workspace rules. Provenance
is checked by scripts/check-spdx.sh. Cargo patches select these exact packages.

| Package | Version | Upstream archive SHA-256 |
|---------|---------|-------------------------|
| dioxus-desktop | 0.7.10 | `236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d` |
| glib | 0.18.5 | `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5` |
| glib-macros | 0.18.5 | `0bb0228f477c0900c880fd78c8759b95c7636dbd7842707f49e132378aa2acdc` |
| gtk3-macros | 0.18.2 | `52ff3c5b21f14f0736fed6dcfc0bfb4225ebf5725f3c0209edeec181e4d73e9d` |
| selectors | 0.24.0 | `0c37578180969d00692904465fb7f6b3d50b9a2b952b87c23d0e2e5cb5013416` |

Archives: `https://crates.io/api/v1/crates/<package>/<version>/download`.
All five Cargo manifests set publish=false. New hardened.rs uses QuickVault's
AGPL SPDX header; desktop's aggregate license expression includes that alongside
its original upstream license choices. Upstream license files are unchanged.
Exact maintained changes:

- dioxus-desktop: PNG-only image dependency; hardened opt-in integration in
  config/protocol/webview/ipc/app/desktop_context/edits and new hardened.rs,
  plus focused boundary/transport tests. No replacement
  renderer, no input-dialog workaround and no new crypto construction.
- glib: variant_iter.rs backports gtk-rs-core#1343's mutable output pointer
  (RUSTSEC-2024-0429). Existing iterator tests exercise forward/backward/nth/last;
  run them with optimizations to catch the original optimizer-sensitive defect.
- glib-macros/gtk3-macros: Cargo and source diagnostic imports select maintained
  proc-macro-error3 3.1.1. Both the original helper and proc-macro-error2 are
  unmaintained; no advisory ignore is used.
- selectors: Cargo replaces fxhash with rustc-hash 2.1.1 and updates paired
  phf/phf_codegen to 0.11.3, dropping the old rand 0.7 chain.

Focused checks use the isolated `third-party/Cargo.toml` test workspace:
`cargo test --manifest-path third-party/Cargo.toml --locked -p glib --lib variant_iter`,
the corresponding selectors library and macro package compile/integration tests,
and desktop `--no-default-features --features tokio_runtime --lib hardened`.
Its test profile optimizes GLib to exercise the optimizer-sensitive regression. Full application
feature/runtime tests remain required. Unmodified upstream unsafe is retained;
product code adds none. Track exact patches as application maintenance, not
as upstream audits. License allowances and vet debt are recorded in plan 0030.
