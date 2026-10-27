# Maintained third-party source

Owner-approved exception: x11rb 0.13.2 only (plan 0015, D1/D2). The owner also
authorized necessary correctness fixes within this clipboard implementation.
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

The CLI's private Stream separately caps lifetime input at 4 MiB, rejects
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

No other vendor package is exempt. Record any baseline/patch change, preserve
licenses, trace payload copies and allocation bounds again, and review local
patches as maintained application code. Vet exemptions are not audits. Never
update a mutable git reference or download source during the build.
