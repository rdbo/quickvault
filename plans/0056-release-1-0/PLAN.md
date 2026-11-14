# Plan 0056 — Release 1.0: readiness checklist and pre-release work

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| In progress — agent pre-release work done 2026-11-14; owner actions and gated steps open | 2026-11-14 | 2026-11-14 (owner request "Prepare for 1.0"; details owner-delegated, standing 2026-11-02) | 0012 §1–3; 0009 §2, §5; 0002 §1.3; 0004 §4 |

## Intent

The owner (2026-11-14): "Prepare for 1.0 … 1.0 means: fully usable on
desktop and mobile, stable, secure and reliable." Also: clean up and
reorganize the repository, make the test suite fast, review what matters
since the last reviews (not everything), and mark the remote server as not
planned. This plan is the single list of what stands between the current
tree and a 1.0 release, split into what an agent can do and what only the
owner can do.

## Scope

**In scope (1.0):**
- The offline vault, the `qv` CLI and the shared app on Linux, Android and
  Windows.
- Direct LAN sync (specs 0013/0014) and archive exchange.
- The 0012 §3 gates for an offline release, a LAN release and each
  GUI/mobile platform; supply-chain and release-artifact requirements.

**Out of scope:**
- The remote server (roadmap milestone 4): not planned (owner, 2026-11-14).
  Its specs stay Draft design records; no 1.0 gate depends on them.
- The "Later" row of `ARCHITECTURE.md` §7 (automatic sync, import from other
  managers, iOS/macOS, extensions, BSD).
- New features. 1.0 work fixes, hardens, validates and packages.

## Spec basis

| Requirement | Spec | Status | 1.0 meaning |
|-------------|------|--------|-------------|
| Offline release: format freeze, golden vectors (incl. worst-case manifest), KDF/budget benchmarks on supported targets, crash/permission/disk-full/malformed-input tests | 0012 §3 ¶1 | Accepted | Freeze is step 7, after the owner's user testing (owner decision 2026-10-30) |
| LAN release: byte-level vectors for every message/transcript/error, independent composition review (D12), hostile-peer and crash tests, LAN-only operation | 0012 §3 ¶2 | Accepted | D12 is owner-only; attended LAN checks in 0039 DEVICE-VALIDATION |
| GUI/mobile release per platform: input cleanup limits, CSP/IPC, OS wrapping, lifecycle, autofill, clipboard on that platform | 0012 §3 ¶6 | Accepted | Attended checklists per platform |
| Release records: pinned dependencies, audits, known limitations, test results; signed artifacts, checksums, reproducible-build status | 0012 §3 ¶9 | Accepted | Step 8 |
| Supported Android baseline (arm64, API 29+, ≥ 4 GB) | 0009 §2 | Draft | KDF benchmark target |
| Windows profile | 0009 §5.1 | Draft | WINDOWS-GATES.md |

**Spec changes required:** none by this plan. Step 7 (the freeze) will amend
0004/0002/0012 statuses and texts when the owner starts it.

## Decisions needed

1. **D12 — independent protocol reviewer** (roadmap D12). Only the owner can
   choose and engage one. The package to send is
   `plans/0048-security-release-validation/REVIEW-PACKAGE.md`.
   Blocks: the LAN part of the 1.0 release (step 9), not development.
   Resolution: pending (owner).
2. **Freeze go-ahead.** The owner decided on 2026-10-30 that formats stay
   volatile until they have user-tested the app and say it is ready.
   Blocks: step 7. Resolution: pending (owner).
3. **Android release signing key.** A release APK must be signed with a key
   the owner controls; agents never create or hold it. Recommendation: an
   offline keystore kept by the owner, passed to the build through
   environment variables (step 6 adds the hook). Blocks: step 8 for Android.
   Resolution: pending (owner).
4. **Code signing for Windows and Linux artifacts.** Options: (A) ship
   unsigned binaries with SHA256SUMS and a detached signature by an owner
   key (minisign or OpenPGP); (B) buy an Authenticode certificate for
   Windows. Recommendation: A for 1.0 (0012 §3 asks for signed artifacts and
   checksums; it does not require Authenticode); B later if SmartScreen
   friction matters. Blocks: step 8. Resolution: pending (owner).

All other choices in this plan are owner-delegated (standing, 2026-11-02).

## Design

No product design change. The work is evidence, review, packaging and a
deliberate freeze. Current state, from `plans/README.md` on 2026-11-14:

| Area | State | What 1.0 still needs |
|------|-------|----------------------|
| Offline core, CLI (M1) | Reviewed | Freeze and golden vectors (step 7); phone KDF/budget numbers (step 5) |
| Shared app, LAN, conflicts (M2: 0040–0045, 0051, 0054) | Implemented; fresh reviews pending | UI/UX plans are low security risk: one combined review (step 3) and owner acceptance |
| Security assessment (0046–0050) | 0046/0047 Reviewed; 0048 Blocked; 0049/0050 In progress | Phone qualification (0049 picker, 0050 media), 0048 hardware/LAN evidence, D12 |
| Performance (0053) | Reviewed 2026-11-14 (this session) | Phone run |
| Wayland clipboard (0055) | Reviewed 2026-11-14 (this session) | Owner's Wayland check |
| Windows (0052) | Implemented; qv-win clipboard partially reviewed 2026-11-14 | First green CI `windows` run, the attended WINDOWS-GATES.md list, the rest of the fresh review |
| Packaging | Windows zip and Linux tarball (unsigned, SHA256SUMS); Android signed non-debuggable release build path (2026-11-14) | Owner signing keys and artifact signatures (Decisions 3–4, step 8) |

## Steps

### Step 1 — Repository cleanup and organization

- [x] **Do:** remove the phase 1.9 UI spike (`spikes/ui-feasibility/`,
  superseded by qv-app) and plan-local one-off harnesses; consolidate the
  three near-identical Android isolated-UID packagers into
  `crates/qv-app/scripts/package-isolated-android.py`; move the plan 0053
  performance harness to `scripts/perf/`; move the logo files to
  `docs/logo/`; move the 0012 offline matrix list from the otherwise empty
  `tests/` to `scripts/matrix-offline.txt`; drop stale ignore entries.
- **Done when:** no tracked file references a removed path except dated
  history notes; all gates pass.

### Step 2 — Fast test suite

- [x] **Do:** memoize full-profile Argon2id results by (password, salt,
  profile) in test builds only (`test-kdf-limit`), so copies of a fixture
  vault run the real KDF once per test binary instead of once per unlock.
  Measure before/after per test binary.
- **Done when:** `cargo test --locked` passes unchanged assertions and is
  substantially faster; the measurement is in the execution log.

### Step 3 — Focused fresh reviews of the riskiest unreviewed code

- [x] 0053 (unlock sink, cache tiers, match sets, bulk staging): REVIEW.md.
- [x] 0055 (own Wayland wire client, GTK clipboard): REVIEW.md.
- [x] Partial reviews, low-severity findings only:
  - 0052 qv-win clipboard FFI (secret-bearing global memory);
  - 0045 persistent quick-unlock policy (`qv-platform`/`qv-core`
    `quick_unlock.rs`);
  - 0049 store import path (`qv-store/src/vault_import.rs`).
  Each plan's REVIEW.md lists what was and was not covered.
- [ ] Remaining, in priority order, each in a fresh session:
  - 0050 source repairs (storage leases, recovery-copy authorization,
    media capability);
  - 0052 rest (`fs.rs`, `security.rs`, `session.rs`, `console.rs`), with a
    Windows run for its clipboard hardening findings;
  - 0045 Kotlin keystore glue and app offer/auto-prompt, 0049 core/app;
  - this plan's own code changes (test KDF memo, packagers);
  - one combined UI review of 0040–0044, 0051, 0054.
- **Done when:** every plan in `plans/README.md` that changed code is
  `Reviewed`.

### Step 4 — CI on real Windows (owner)

- [ ] **Owner:** push the tree; check that the `windows`, `gates`,
  `app-boundary`, `android-app-build`, `supply-chain` and `fuzz` jobs pass.
  Then run the attended items of
  `plans/0052-windows-platform/WINDOWS-GATES.md` on a real Windows 10 22H2 or
  11 machine.

### Step 5 — Device evidence (owner with an agent session)

- [ ] **Owner + agent:** with the phone connected, in one session:
  - 0039 `DEVICE-VALIDATION.md`: real two-device LAN sync and new-device
    join, Internet blocked, interruption at transfer/commit/acknowledgement;
  - 0049 picker and 0050 media qualification under an isolated UID
    (`package-isolated-android.py`);
  - 0053 phone performance run and the 0002 §1.3 KDF benchmark on the
    supported baseline (`budget_bench`);
  - 0045/0033/0034 quick unlock and autofill device checks;
  - the owner's Wayland check of plan 0055 step 5 (app copy and `qv copy`).

### Step 6 — Release packaging

- [x] **Do (agent):**
  - Linux: a release tarball script (app + `qv`, `.desktop` entry, icon,
    LICENSE, README, SHA256SUMS), mirroring `package-windows.ps1`.
  - Android: a **non-debuggable** release variant (Gradle `assembleRelease`)
    signed with an owner-supplied keystore, refusing to run without one;
    never a generated key. Before this step the only APK,
    `quickvault-debug.apk`, had `android:debuggable="true"`: with USB
    debugging, `adb shell run-as` reads the app's private files (vaults,
    anchors, quick-unlock state) and a debugger can attach to the process.
    Fine for development; never for a published artifact.
  - `docs/RELEASE.md`: version bump, tag, artifacts, checksums,
    signatures, release notes (written 2026-11-14).
- **Done when:** the scripts build artifacts locally (Android with a
  throwaway test key, never published) and checksums verify.

### Step 7 — Format freeze (gated on Decision 2)

- [ ] **Do:** only after the owner says the app is user-tested and ready:
  freeze the DDL, CBOR registry, profile IDs/parameters, archive and journal
  formats; replace development format values with release values; publish
  golden file vectors including the worst-case manifest at maximum budgets;
  set the KDF parameters from the step 5 benchmark (never below the 64 MiB
  floor). Architect → developer → reviewer (storage/crypto formats).

### Step 8 — Release records and artifacts

- [ ] **Do:** release notes with pinned dependencies (`Cargo.lock`),
  `cargo deny`/`cargo vet` results, audit status of security-critical crates
  (record honestly that ML-KEM/X-Wing/OPAQUE crates may be unaudited),
  known limitations (framework memory copies, Windows clipboard residuals,
  unvalidated devices), test results, signatures and checksums, and the
  reproducible-build status. Bump the workspace version to `1.0.0`.

### Step 9 — Release decision (owner)

- [ ] **Owner:** with steps 3–8 done and the D12 result folded in (or the
  LAN feature disabled for 1.0), decide the release. A failed gate blocks
  its feature, never permits weakening it (0012 §3).

## Test plan

- Every step that changes code runs all `AGENTS.md` gates on the final tree.
- Steps 5 and 9 are attended; their evidence goes in the named validation
  files, never as passed until actually run.

## Risks and stop conditions

- Do not start step 7 without the owner's explicit go-ahead.
- Do not generate, store or commit release signing keys.
- Do not mark a device or CI row passed from development evidence (Wine,
  cross-compilation, synthetic tests).
- A review that finds a security issue in crypto, storage or protocol code
  stops that area's release work until it is re-planned.

## Documentation

- [x] `CHANGELOG.md` — Unreleased entries for the cleanup, test speedup, reviews and server status
- [x] `ARCHITECTURE.md` — §7 (milestone 4 not planned, 1.0 pointer), §3 spike paragraph
- [x] Specs — 0006 and 0009 §1.4 "not planned" notes; `specs/README.md`
- [x] `AGENTS.md` — matrix list path; `.agents/README.md` layout
- [x] `plans/README.md` — index row

## Revisions

None.

## Execution log

- 2026-11-14: Plan written at the owner's request; owner unavailable, so
  every choice is owner-delegated (standing 2026-11-02) and owner-only items
  are listed as Decisions 1–4 and steps 4, 5 and 9.
- 2026-11-14: Step 1 done. Removed `spikes/ui-feasibility/` (plan 0013
  keeps the findings), the plan-local
  `capacity-harness.rs`/`measure-capacity.py` (0048, superseded by the 0053
  harness) and the 0048/0049/0050 Android packagers (merged into
  `crates/qv-app/scripts/package-isolated-android.py`, which also rewrites
  the historical `validationNN` IDs pinned in the test classes so one
  isolated UID runs every instrumentation class). Moved `perf-harness.rs`
  and `measure-perf.py` to `scripts/perf/` (path logic unchanged:
  `parents[1]` is still the repository root), the logos to `docs/logo/`, and
  `tests/matrix-offline.txt` to `scripts/matrix-offline.txt`. Updated every
  live reference (README, qv-app README and comments, Android resource
  comments, AGENTS.md, `.agents/README.md`, `.gitignore`, ARCHITECTURE.md,
  plan validation docs); dated history notes keep the old names.
- 2026-11-14: Step 2 done. Cause of the slow suite: every unlock in tests
  runs the full password-kdf/1 Argon2id (256 MiB, t=3, single-threaded),
  serialized one at a time (`QV_TEST_KDF_JOBS=1`, owner 2026-11-13), and
  most unlocks re-derive the same fixture password and salt. Fix:
  `qv_crypto::password::memo` (test builds only, `cfg(any(test, feature =
  "test-kdf-limit"))`) caches results by SHA-256 of a label, profile ID,
  salt and password, rechecked after taking the KDF slot; qv-store's
  dev-dependency now enables the feature. No production code path changes
  (the feature is enabled only from dev-dependencies), no assertion changed,
  no Cargo.lock change. Measured per test target, same tree and build
  before/after (`cargo test --locked -p <crate> <target>`):

  | Target | Before | After |
  |--------|--------|-------|
  | qv-store unit tests | 335 s | 52 s |
  | qv-core unit tests | 168 s | 37 s |
  | qv-app unit tests (libtest time) | 44 s | 31 s |
  | qv-cli credentials | 49 s | 14 s |
  | All test execution (sum) | ≈ 980 s | ≈ 330 s |

  Full `cargo test --locked` after the change, including a 3 min rebuild:
  514 s wall, 1040 passed, 0 failed, 7 ignored. The remaining time is mostly
  distinct derivations (fresh vaults, password changes, rotations) and the
  CLI tests' child `qv` processes, each of which runs its own KDF; a
  cross-process cache would put key material on disk and was rejected.
  Residual, documented in the code: binaries compiled by a test build (for
  example `target/debug/qv` after `cargo test`) also carry the memo, as they
  already carry `test-eager-views`; they must never be used with a real
  vault. Release packaging builds without dev-dependencies.
- 2026-11-14: Step 3 (this session's part) done: REVIEW.md for 0053 and
  0055 (Approved), partial reviews for 0052, 0045 and 0049; see each file.
  The test memo and packagers written in this session need their own fresh
  review (listed in step 3).
- 2026-11-14: Step 6 done for the agent part.
  - Linux: `crates/qv-app/scripts/package-linux.sh` and
    `crates/qv-app/linux/org.quickvault.QuickVault.desktop`. A local run
    built the tarball; extracted, its `SHA256SUMS` verify and `qv --version`
    runs.
  - Android: `QV_APP_RELEASE=1` in `build-android.sh` builds
    `assembleRelease` with R8 off and `isDebuggable`/`isJniDebuggable`
    false, zipaligns, signs with `apksigner` from `QV_ANDROID_KEYSTORE`/
    `QV_ANDROID_KEY_ALIAS` (password prompted, or `QV_ANDROID_KS_PASS` as an
    apksigner source), verifies the certificates and refuses a debuggable
    result or validation features. A local run with a throwaway key (then
    deleted with its APK) built and signed it; the badging has no
    `application-debuggable`. Not run on a phone: a release APK cannot be
    installed over the debug-signed app, and its JNI paths without R8 are
    the same as the debug build's. Device run of the release APK is step 5.
  - `docs/RELEASE.md` written.
- 2026-11-14: Final-tree gates, all exit 0: `sh scripts/check-spdx.sh`,
  `sh scripts/test-check-spdx.sh`, `sh scripts/check-matrix.sh`,
  `cargo fmt --check`, `git diff --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, qv-app Clippy with
  `--features desktop` and `--features validation`;
  `cargo test --locked`: 1040 passed, 0 failed, 7 ignored (462 s wall
  including the rebuild); `RUST_TEST_THREADS=1 cargo test --locked -p qv-app
  --features validation`: 104 unit tests and the 3 real-engine flows pass.
  No `Cargo.lock` or `fuzz/Cargo.lock` change (`cargo tree --locked
  --offline` on the fuzz manifest passes), so `cargo deny`/`cargo vet` were
  not required. Not run: the Windows cross Clippy (no Windows code changed).
  No commit, push or branch.
