# Current-tree checks

2026-11-09; product baseline `ee0cafdd56af1b9593445cb632f0f1be3e7e101a`.
Production source, dependencies, formats and security policies are unchanged.
The diff contains evidence, documentation and disposable measurement/packaging
tools. All 110 baseline source/evidence hashes still match.

| Command / scope | Result |
|-----------------|--------|
| `sh scripts/check-spdx.sh` | pass, including new untracked sources |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 978 tests, 2 existing ignored tests, all doctests |
| `sh scripts/check-matrix.sh` | pass |
| `rustfmt --edition 2024 --check plans/0048-security-release-validation/capacity-harness.rs` | pass |
| Measurement runner baseline/instrumented release builds and focused Clippy | pass; all selected registry versions/checksums match product lock |
| Original and instrumented capacity operations | all 30/90/180-row search/preparation/batch/recursive runs pass; integrity, counts and commit count checked |
| `cargo test --release --locked -p qv-core large_vault_stock -- --nocapture` | pass; complete final-dependency 67.5 MiB lifecycle |
| P0–P3 host and physical-phone benchmarks | every final sample passes, including populated near-1-GiB verification/edit |
| Android normal/validation app, instrumentation and isolated packaging | builds/manifest inspection pass; isolated native `.so` hashes equal validation baseline |
| Normal Android `PlatformTest` | **failed** before synthetic creation; automatic regular-vault unlock raced test mode selection |
| Isolated current-UI native boundary test | pass, 2.932 s, after owner-attended installation; failed earlier installs retained |
| Isolated existing native QR boundary test | pass, 1.880 s; live camera/optics not selected |
| Isolated Class3 hardware round trip / wrong-vault AAD | repeat passes, 19.665 s; first seal run failed at stage70 and remains unresolved |
| Exact regular native UI in synthetic UID | pass, 3.037 s; Create UI has no raw vault-path field, CSP/input/lifecycle assertions retained |
| cargo-deny 0.20.2 / cargo-vet 0.10.3 | pass with existing explicit exceptions/development debt; see DEPENDENCY-REVIEW.md |
| Python runner syntax, source inventory and `git diff --check` | pass |

Full gate logs are `/tmp/qv-0048-evidence/`: `spdx-final.log`, `fmt-final.log`,
`clippy.log`, `test-xvfb.log`, `matrix-final.log`, `harness-fmt-final.log`,
`deny-writable-cache.log`, `vet.log`. Short shared evidence lives in `evidence/`;
verbose logs stay temporary. Existing ignored tests were not added/changed.

The initial full test run failed because Xvfb was absent. Downloaded Alpine
Xvfb21.1.25 and its dependencies into a temporary tool directory; the final
run uses `QV_TEST_XVFB=/tmp/qv-0048-xorg/Xvfb`, without changing tests or global
device settings. Full workspace Clippy/tests use these temporary build settings
to retain meaningful assertions while avoiding oversized debug artifacts:

```sh
export QV_TEST_KDF_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true
export CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true
cargo clippy --all-targets --locked -- -D warnings
QV_TEST_XVFB=/tmp/qv-0048-xorg/Xvfb cargo test --locked
```

Benchmark executables use the ordinary release profile, not these test settings.
The new source has no unsafe code, new primitive, policy exception, dependency
or new production API. Synthetic passwords are protected Rust containers and
never arguments; measurement logs contain only counters/timings/fixed errors.
The original UI failure log's workspace labels were redacted.

Other retained failures: initial deny read-only cache, Android target missing
and unpinned default `dx`, rejected broad ADB-pushed file modes, initial harness
borrow errors, guarded rejection of transitive dependency drift, and the first
disposable manifest's incorrect inherited MSRV replacement. Local tooling fixes
precede the successful runs; none is presented as a pass. No production limit,
assertion or protocol check was weakened. No commit, branch or push was made.

This is the implementing agent's validation record, not a fresh-context
independent security audit. D12, genuine dependency review and the outstanding
physical app/LAN rows remain open. No release approval is implied.

Commit-readiness follow-up: normalized redundant blank EOFs in shared logs and
rendered the identical preparation trace with zero context. The updated
measurement runner's instrumented build-only path and focused Clippy pass;
`git apply --check --unidiff-zero` validates its retained patch. Current SPDX,
fmt, matrix, Python syntax, production-baseline hashes and working-tree
`git diff HEAD --check` pass. Production Rust/dependency inputs to the earlier
full workspace Clippy/tests are unchanged. The owner's index was preserved;
restage cleanup/new plan0049 before committing, since its old snapshot still
contains the original evidence whitespace.
