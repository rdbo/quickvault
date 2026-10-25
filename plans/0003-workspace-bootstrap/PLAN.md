# Plan 0003 — Workspace bootstrap and protected memory

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-25 | 2026-10-25 | 0008 §1, 0002 §7.1, 0012 §3 |

## Intent

Roadmap 0002 phase 1.1. Set up the Cargo workspace, toolchain pin, lints,
supply-chain tooling, CI and SPDX checks. Then create `qv-crypto` with its
first real interface: protected memory (zeroizing, locked, unprintable,
non-cloneable secret buffers, plus visible reduced-protection status),
process hardening (core dumps and debugger attach) and a fail-closed OS RNG.

## Scope

**In scope:**
- Virtual workspace, `rust-toolchain.toml` (1.98.1, D1), workspace lints, `clippy.toml`.
- `deny.toml`, `cargo vet` initialisation (`supply-chain/`).
- GitHub Actions workflow (D2) and SPDX header check (D3).
- `crates/qv-crypto` (D4 layout): `memory`, `process` and `rng` modules.

**Out of scope:**
- Guard-page / no-access allocations (0008 §1.2 "prefer"). These need `unsafe`
  allocation code. This plan records the gap as a known limitation; a later plan
  may propose it with an `unsafe` review.
- Encrypting idle protected values, wiping metadata views and lock-time
  cancellation (0008 §1.2 and §1.4). These belong to qv-core in phase 1.8.
- Swap/hibernation/disk-encryption detection (0008 §1.3). This needs platform
  adapters (phase 2.3) and core policy (1.8).
- Secret strings and NFC password handling (phase 1.3). Constant-time
  comparison (`subtle`) is added in 1.3 only if a direct comparison is needed.
- Windows/macOS process hardening. On other OSes it reports `Unsupported`.
- Fuzzing: this phase has no parser, so the fuzz harness starts in 1.2.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Zeroizing secret buffers, redacted Debug, no implicit clone | 0008 §1.1 | Draft (D5 go-ahead) | |
| Disable core dumps and debugger attach before secrets, report unsupported | 0008 §1.1 | Draft (D5) | Linux/Android here |
| Lock buffers before filling; lock failure surfaced as reduced protection | 0008 §1.2 | Draft (D5) | |
| Don't claim zeroizing erases swap | 0008 §1.2 | Draft (D5) | Doc comments must not claim it |
| OS CSPRNG; RNG failure aborts operations | 0002 §7.1 | Accepted | |
| No secrets in logs/errors/panics | 0008 §3 | Draft (D5) | Error types carry no secret data |
| `Cargo.lock`, `--locked`, `cargo deny`, `cargo vet` | 0012 §3 | Accepted | |

**Spec changes required:** None.

## Decisions needed

None. D1–D5 were resolved on 2026-10-25 (roadmap 0002). Every dependency below
is in the roadmap's candidate table, and the design needs no `unsafe`.

## Design

**Components touched:** workspace root (tooling); `qv-crypto`, which is in the
trusted client and has no dependencies on other qv crates or on frontends.

**Interfaces:**

```rust
// crates/qv-crypto/src/memory.rs
/// Heap secret of fixed length. Not Clone/Copy, no Display, redacted Debug
/// (`SecretBytes(<redacted>)`, length not shown). Zeroized on drop. The
/// allocation is never resized.
pub struct SecretBytes { buf: Box<[u8]>, locked: bool }
impl SecretBytes {
    /// Allocates zeroed memory and locks its pages, then returns it. Callers fill it afterwards.
    pub fn zeroed(len: usize) -> Self;
    /// zeroed + lock, then `init` fills it in place. On Err the buffer is wiped and dropped.
    pub fn try_init<E>(len: usize, init: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<Self, E>;
    /// Copies `src` into a new locked buffer, then zeroizes `src`.
    pub fn take_from(src: &mut [u8]) -> Self;
    /// zeroed + lock + OS RNG fill (fails closed).
    pub fn random(len: usize) -> Result<Self, RngError>;
    pub fn expose_secret(&self) -> &[u8];
    pub fn expose_secret_mut(&mut self) -> &mut [u8];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    /// false if locking failed for this buffer (reduced protection).
    pub fn is_locked(&self) -> bool;
}
impl zeroize::ZeroizeOnDrop for SecretBytes {}

/// Fixed-size secret (keys). Same properties; backed by Box<[u8; N]>.
pub struct SecretArray<const N: usize> { buf: Box<[u8; N]>, locked: bool }
impl<const N: usize> SecretArray<N> {
    pub fn zeroed() -> Self;
    pub fn try_init<E>(init: impl FnOnce(&mut [u8; N]) -> Result<(), E>) -> Result<Self, E>;
    pub fn random() -> Result<Self, RngError>;
    pub fn expose_secret(&self) -> &[u8; N];
    pub fn expose_secret_mut(&mut self) -> &mut [u8; N];
    pub fn is_locked(&self) -> bool;
}

/// Process-wide memory-lock status since start. Sticky: once reduced, it stays reduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryProtection { pub lock_failures: u64 }
impl MemoryProtection { pub fn is_reduced(&self) -> bool; }
pub fn memory_protection() -> MemoryProtection;

// crates/qv-crypto/src/process.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hardening { Applied, Unsupported, Failed }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessHardening { pub core_dumps: Hardening, pub debugger_attach: Hardening }
impl ProcessHardening { pub fn is_reduced(&self) -> bool; } // anything but Applied
/// Call before reading any secret. Idempotent. Never panics.
pub fn harden_process() -> ProcessHardening;

// crates/qv-crypto/src/rng.rs
/// Opaque. Debug = "RngError", Display = "operating system random number generator failed".
#[derive(Debug)] pub struct RngError(());
impl std::error::Error for RngError {}
/// Fills from the OS CSPRNG. On failure, zeroes `buf` and returns Err.
pub fn fill_random(buf: &mut [u8]) -> Result<(), RngError>;
/// Non-secret random values (nonces, salts, IDs).
pub fn random_array<const N: usize>() -> Result<[u8; N], RngError>;
```

`lib.rs` re-exports `memory::{SecretBytes, SecretArray, MemoryProtection, memory_protection}`,
`process::{harden_process, ProcessHardening, Hardening}` and
`rng::{fill_random, random_array, RngError}`.

**Page locking (the core of the memory module).** `region::lock` rounds the
range to whole pages, and `munlock` does not nest. If each buffer held its
own `LockGuard`, dropping one buffer would unlock a page that a live neighbour
buffer still shares. So `memory` keeps a private registry instead:
`static PAGES: Mutex<BTreeMap<usize /*page addr*/, (u32 /*refcount*/, region::LockGuard)>>`.

- **On allocate:** for each page the buffer spans, increment the page's
  refcount. If the page is new, call `region::lock(page_ptr, page_size)` and
  store the guard. If any page fails to lock, release the pages already taken
  (decrement), set `locked = false` and increment the global
  `AtomicU64 LOCK_FAILURES`. This happens **before** the constructor returns,
  so callers fill only locked memory. `len == 0` counts as locked and touches
  no pages.
- **On drop** (`impl Drop`): zeroize first (`zeroize::Zeroize` on the slice),
  then decrement each page. A page whose count reaches 0 is removed, which
  drops its guard and unlocks it.
- **Mutex poisoning:** recover with `into_inner()`. Never `unwrap`. The
  registry's invariants hold across a panic because each map update is a
  single insert, increment or remove.
- **Page addresses:** compute with provenance-preserving pointer methods
  (`ptr.wrapping_byte_sub(ptr.addr() % page)`), with `region::page::size()`.
- **No `unsafe`:** `region::lock` and `LockGuard` drop are safe APIs
  (`region::unlock` is `unsafe` and must not be used). `LockGuard` is
  `Send + Sync`, so the static `Mutex` is sound.
- **Test-only failure injection:** a `#[cfg(test)]` thread-local flag makes
  the lock attempt fail before it reaches the registry, so the
  reduced-protection path is unit-testable. The flag must not exist in
  non-test builds.

**Process hardening (Linux/Android, via `rustix`):**
- `core_dumps`: `setrlimit(Resource::Core, 0/0)`.
- `debugger_attach`: `prctl(PR_SET_DUMPABLE, 0)` via
  `rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)`.
  Non-dumpable also blocks same-uid `ptrace` attach and core dumps under the
  default `suid_dumpable=0`.
- Each field is `Applied` if its call succeeded, `Failed` on error, and
  `Unsupported` on other OSes (`cfg`).
- Doc comments must state honestly that this is best effort: privileged
  debuggers, `suid_dumpable=2` and piped `core_pattern` handlers can still
  capture memory.

**RNG:** `getrandom::fill`. `fill_random` delegates to a private
`fill_from(source, buf)`, so a unit test can inject a failing source and check
that the buffer is zeroed and an error returned. `SecretBytes::random` uses
`try_init`, so a failure leaves no partially filled secret behind.

**Secrets and hostile input:** `SecretBytes` and `SecretArray` are the only
secret holders. They have no `Clone`, `Copy`, `Display`, `PartialEq`,
`Serialize` or `Deref`, so `expose_secret*` is the greppable access point.
Debug output never shows contents or length. No hostile input is parsed in this phase.

**Errors:** only `RngError` (opaque; carries nothing). Lock and hardening
failures are not errors. They are reported as status values, so callers
(qv-core in 1.8) must surface them to the user (0008 §1.2: never only in logs).

**Workspace settings:**
- `Cargo.toml` (virtual): `resolver = "3"`, `members = ["crates/*"]`.
- `[workspace.package]`: `edition = "2024"`, `rust-version = "1.98.1"`,
  `license = "AGPL-3.0-or-later"`, `repository = "https://github.com/rdbo/quickvault"`,
  `publish = false`.
- `[workspace.dependencies]`: exact versions, `=x.y.z`.
- `[workspace.lints.rust]`: `unsafe_code = "forbid"`, `missing_docs = "warn"`.
- `[workspace.lints.clippy]`: `unwrap_used`, `expect_used`, `panic`,
  `dbg_macro`, `todo`, `unimplemented`, all `"deny"`.
- `clippy.toml`: `allow-unwrap-in-tests = true`, `allow-expect-in-tests = true`,
  `allow-panic-in-tests = true`.
- Crates opt in with `[lints] workspace = true`.
- `rust-toolchain.toml`: `channel = "1.98.1"`, `components = ["rustfmt", "clippy"]`,
  `profile = "minimal"`.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| `zeroize` 1.9 (no default features beyond `alloc`/`std`; no `derive`) | Wiping that the compiler won't optimize away | Hand-written volatile writes (that would be a home-made primitive) | RustCrypto, very widely used; check `cargo vet` imports |
| `getrandom` 0.4 (default features) | OS CSPRNG, explicit error | `rand`/`OsRng` (more surface, wraps getrandom anyway) | rust-random; audited by imports from several orgs (check) |
| `region` 4.0 | Safe `mlock`/`VirtualLock` with a guard; portable to Android, Linux, Windows and macOS | `memsec` (all `unsafe` fns), raw `libc` (needs `unsafe`), `rustix::mm::mlock` (`unsafe fn`) | Small, maintained; likely no third-party audit, so record an exemption |
| `rustix` 1.1 (`default-features = false`, `features = ["std", "process"]`), Linux/Android target only | Safe `setrlimit` and `prctl(PR_SET_DUMPABLE)` | `libc` (needs `unsafe`) | Bytecode Alliance; check `cargo vet` imports. In the roadmap table (1.10 row); used earlier here |

## Steps

### Step 1 — Workspace skeleton and toolchain

- [x] **Do:** Create the virtual workspace, `rust-toolchain.toml` and
  `clippy.toml` as in *Design*. Create `crates/qv-crypto` (lib) with
  `[lints] workspace = true` and a `lib.rs` that has the SPDX header and crate
  docs (purpose, trust boundary, honest memory caveats). No dependencies yet.
  Run `cargo generate-lockfile` and commit-ready `Cargo.lock`.
- **Files:** `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `clippy.toml`, `crates/qv-crypto/Cargo.toml`, `crates/qv-crypto/src/lib.rs`.
- **Done when:** the pinned toolchain is picked up (`cargo --version` shows 1.98.1) and the gates pass on the empty crate.
- **Verify:** `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked`

### Step 2 — RNG module

- [x] **Do:** Add `getrandom` and write `rng.rs` as designed, with the private
  `fill_from` for injection. Unit tests: two `random_array::<32>()` calls
  differ; `fill_random` on an empty slice is Ok; an injected failure zeroes a
  pre-filled buffer and returns `RngError`; Display/Debug of `RngError` are
  the fixed strings.
- **Files:** `crates/qv-crypto/Cargo.toml`, `crates/qv-crypto/src/rng.rs`, `lib.rs`, `Cargo.lock`.
- **Done when:** the tests pass and nothing in the module panics or unwraps.
- **Verify:** `cargo test --locked -p qv-crypto rng`

### Step 3 — Secret buffers and page-lock registry

- [x] **Do:** Add `zeroize` and `region`. Implement `memory.rs`:
  `SecretBytes`, `SecretArray<N>`, the page registry, `memory_protection()`
  and test-only failure injection, exactly as designed.
  - **Unit tests:**
    - Debug output is `SecretBytes(<redacted>)` / `SecretArray(<redacted>)`
      and contains neither the content bytes nor the length.
    - `take_from` zeroizes its source.
    - `try_init` passes through Err.
    - Several small buffers sharing a page: dropping one keeps the page's
      refcount > 0, and the registry is empty after all are dropped. Expose
      a `#[cfg(test)] fn registered_pages() -> usize`.
    - `len == 0` is locked and touches no pages.
    - Injected lock failure: `is_locked() == false`, `lock_failures` increased,
      and the registry is left unchanged.
  - **Doctests:** add `compile_fail` doctests for `.clone()`, `Copy` use
    after move, `format!("{}", s)` and `==` on both types. Pair each with a
    passing doctest of the same snippet minus the forbidden operation, so a
    `compile_fail` can't pass for an unrelated reason.
  - **Assertions:** unit tests must **not** assert the global
    `memory_protection()` value is unreduced; injection makes it sticky in
    that process.
- **Files:** `crates/qv-crypto/src/memory.rs`, `lib.rs`, `Cargo.toml`, `Cargo.lock`.
- **Done when:** all tests and doctests pass. `grep -n unsafe crates/` finds
  only the `forbid` lint and docs. Doc comments say that zeroizing does not
  erase swap or copies made before the secret was wrapped.
- **Verify:** `cargo test --locked -p qv-crypto memory && cargo test --locked -p qv-crypto --doc`

### Step 4 — Lock-failure integration test (real OS limit)

- [x] **Do:** Add `crates/qv-crypto/tests/memory_lock_limit.rs` (its own
  process, a single test). The test:
  1. Asserts `memory_protection()` is unreduced after one small allocation.
  2. Sets `RLIMIT_MEMLOCK` to 0 via `rustix` (Linux/Android only; a
     dev-dependency is not needed because `rustix` is already a target
     dependency, but a dev-dependency entry with the same version is fine
     if required).
  3. Allocates a buffer larger than one page, then asserts
     `!is_locked()` and `memory_protection().is_reduced()`.

  If the allocation still locks (the process has `CAP_IPC_LOCK`, e.g. root),
  the test prints a skip notice with `eprintln!` and returns. It must not
  fail, and it must not pretend to pass the check.
- **Files:** `crates/qv-crypto/tests/memory_lock_limit.rs`, `crates/qv-crypto/Cargo.toml`.
- **Done when:** the test passes as a non-root user (this environment and GitHub runners).
- **Verify:** `cargo test --locked -p qv-crypto --test memory_lock_limit -- --nocapture`

### Step 5 — Process hardening

- [x] **Do:** Add the `rustix` target dependency and write `process.rs` as
  designed. Add the integration test `crates/qv-crypto/tests/process_hardening.rs`
  (its own process). It calls `harden_process()` twice (idempotent) and
  asserts both fields are `Applied` on Linux/Android. It then confirms through
  `rustix::process::getrlimit(Resource::Core)` (both limits 0) and
  `dumpable_behavior()` (`NotDumpable`). A `cfg(not(any(linux, android)))`
  branch asserts `Unsupported`.
- **Files:** `crates/qv-crypto/src/process.rs`, `lib.rs`, `Cargo.toml`, `Cargo.lock`, `crates/qv-crypto/tests/process_hardening.rs`.
- **Done when:** the test passes and `is_reduced()` is false on this machine.
- **Verify:** `cargo test --locked -p qv-crypto --test process_hardening`

### Step 6 — Supply chain: cargo deny and cargo vet

- [x] **Do:**
  1. Install the tools (`cargo install --locked cargo-deny cargo-vet`) and
     record their versions in the execution log.
  2. Write `deny.toml`:
     - `[graph]` all targets.
     - Advisories: deny vulnerabilities, unmaintained and yanked.
     - Licenses: an allow-list containing only what the current tree needs
       (expected: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception), with
       `private.ignore = true` for our `publish = false` crates.
     - Bans: `multiple-versions = "warn"`, `wildcards = "deny"`.
     - Sources: crates.io only; unknown registries and git sources denied.
  3. Run `cargo vet init`. Then `cargo vet import` the well-known audit sets
     from the cargo-vet registry (bytecodealliance, google, mozilla, isrg,
     zcash, embark where available), then `cargo vet prune`.
  4. Keep the remaining exemptions. Do not write fake audits. List each
     exempted crate in the execution log.
- **Files:** `deny.toml`, `supply-chain/config.toml`, `supply-chain/audits.toml`, `supply-chain/imports.lock`.
- **Done when:** `cargo deny check` and `cargo vet` both pass.
- **Verify:** `cargo deny check && cargo vet --locked`

### Step 7 — SPDX check and CI workflow

- [x] **Do:**
  - Write `scripts/check-spdx.sh` (POSIX sh, with its own SPDX header on
    line 2). It reads `git ls-files '*.rs' '*.sh'` and fails, listing the
    offending files, if a `.rs` file's first line, or a `.sh` file's first
    or second line, is not the exact SPDX header.
  - Write `.github/workflows/ci.yml`:
    - Triggers: `push` and `pull_request`. Workflow-level
      `permissions: contents: read`.
    - Job `gates` (ubuntu-latest): checkout pinned by full commit SHA
      (with the tag in a comment) and `persist-credentials: false`; then
      `scripts/check-spdx.sh`, then fmt, clippy and test exactly as the
      standard gates. The toolchain comes from `rust-toolchain.toml` via
      the runner's rustup.
    - Job `supply-chain`: checkout (same pin); install `cargo-deny` and
      `cargo-vet` with `cargo install --locked --version <exact>`, using
      the versions from Step 6; then run `cargo deny check` and
      `cargo vet --locked`.
  - No third-party actions besides `actions/checkout`. Get the SHA with
    `git ls-remote https://github.com/actions/checkout refs/tags/<latest v-tag>`.
- **Files:** `scripts/check-spdx.sh`, `.github/workflows/ci.yml`.
- **Done when:** every `run:` command in the workflow passes locally. A
  deliberately header-less temp `.rs` file makes the SPDX script fail; remove
  it afterwards.
- **Verify:** `sh scripts/check-spdx.sh` plus each workflow command in order.

### Step 8 — Documentation

- [x] **Do:** Update the files in *Documentation*. Set this plan to
  `Implemented`. Specs stay unchanged: 0008 is not fully implemented.
- **Files:** see *Documentation*.
- **Done when:** the docs match the tree.
- **Verify:** `git status --short` lists only the intended files; the full gate set passes once more.

## Test plan

- **Unit and property tests:**
  - RNG: output, empty input and injected failure.
  - Memory: redaction, wipe-on-take, init errors, page refcounting and
    injected lock failure.
- **Rejection, malformed-input and crash-path tests:**
  - Compile-fail doctests for Clone, Copy, Display and equality.
  - RNG failure path: buffer zeroed, no secret constructed.
  - Lock failure under a real `RLIMIT_MEMLOCK=0`.
- **Vectors:** None (no formats yet).
- **0012 §1 matrix rows addressed:** the memory and side-channel rows that
  cover secret handling, redaction and reduced-protection reporting. This is
  partial: OS-leak, lifecycle and swap rows come later.

## Risks and stop conditions

- If any step appears to need `unsafe` (for example a crate API turns out to
  be `unsafe fn`, or guard pages look necessary), stop and ask. Do not add
  `#[allow(unsafe_code)]`.
- If a dependency or feature resolves to a crate outside the candidate table,
  stop and ask. This covers a heavy transitive tree, and `getrandom` pulling
  in `rand_core` through a feature. Platform shims such as `libc`,
  `linux-raw-sys`, `bitflags`, `cfg-if`, `errno` and `windows-*` are expected.
- If `cargo deny` flags an advisory or license problem that has no clean fix,
  stop. Do not add an `ignore` entry without asking.
- If the pinned toolchain cannot be installed in this environment, stop; do
  not fall back to an unpinned toolchain.
- If the process-hardening test cannot reach `Applied` here (for example in a
  sandbox that forbids `prctl`), record the actual result. Do not weaken the
  assertion silently. Ask whether to gate it.

## Documentation

- [x] `CHANGELOG.md` — Unreleased/Added: workspace, tooling, CI, qv-crypto protected memory/RNG/process hardening
- [x] `ARCHITECTURE.md` — §3: note that `qv-crypto` exists (protected memory, RNG, process hardening); §6: rows for toolchain (Rust 1.98.1 pinned) and CI (GitHub Actions, SHA-pinned)
- [x] Specs — no change (0008 stays Draft; record the guard-page gap as a known limitation in this plan's log)
- [x] `AGENTS.md` — *Current state* (code exists now), layout table (`crates/`, `supply-chain/`, `deny.toml`, `scripts/`, `.github/`), gates list adds `sh scripts/check-spdx.sh`
- [x] `plans/README.md` — index row; `plans/0002-roadmap/PLAN.md` tick 1.1 and log entry (done by the session, step 6 of the protocol)

## Revisions

None.

## Execution log

- 2026-10-25: Approved (standing approval, roadmap 0002): no open decisions, no spec amendment, dependencies from the candidate table only, no `unsafe`, matches phase 1.1.
- 2026-10-25: Steps 1–5 done. The pinned 1.98.1 toolchain was auto-installed
  by rustup. Exact versions: getrandom 0.4.3, zeroize 1.9.1 (`alloc` only, no
  `derive`), region 4.0.1, rustix 1.1.5 (`std`, `process`; Linux/Android only).
  Transitive crates are platform shims only (libc, cfg-if, bitflags,
  linux-raw-sys, errno, r-efi, mach2, windows-sys, windows-link); no `rand_core`.
  `region::lock` and `LockGuard` are safe APIs, so the crate has no `unsafe`.
  Deviation (strengthening): the `compile_fail` doctests name their expected
  error codes (E0599 clone, E0382 use after move, E0277 Display, E0369 `==`),
  so none can pass for an unrelated error. Added (not in the plan, test only):
  a Linux test that checks `VmLck` in `/proc/self/status` rises while a 64 KiB
  secret is alive, which is kernel-level evidence that pages are locked. The
  `RLIMIT_MEMLOCK=0` test exercised the real failure path here (not skipped).
  The memory unit tests share a `Mutex`, so exact registry counts can be asserted.
- 2026-10-25: Step 6 done. cargo-deny 0.20.2 and cargo-vet 0.10.3. This sandbox
  has a read-only `~/.cargo/bin` and `~/.cargo/advisory-dbs`, so the tools were
  installed under the session scratchpad and run with `CARGO_HOME` pointing
  there (registry symlinked). The repo config doesn't depend on that. The
  license allow-list is `Apache-2.0` and `MIT` only. `cargo vet` imports:
  bytecode-alliance, google, mozilla, isrg, zcash, embark-studios. Also tried
  `ariel-os`, then removed it (not in the plan, no audits used). Result:
  3 fully audited (zeroize, errno, windows-link via imports), 10 exempted:
  bitflags 2.13.2, cfg-if 1.0.5, getrandom 0.4.3, libc 0.2.191,
  linux-raw-sys 0.12.1, mach2 0.7.0, r-efi 6.0.0, region 4.0.1, rustix 1.1.5,
  windows-sys 0.61.2. No audits written by us.
- 2026-10-25: Step 7 done. `actions/checkout` pinned to
  3d3c42e5aac5ba805825da76410c181273ba90b1 (v7.0.1, lightweight tag). Deviation:
  `check-spdx.sh` lists tracked **and** untracked non-ignored files
  (`git ls-files --cached --others --exclude-standard`). Tracked-only would
  pass vacuously before the owner's first commit. Negative test: a header-less
  `.rs` and `.sh` made it exit 1 and name both files; removed afterwards.
  Every other workflow command passed locally. The exception is
  `rustup toolchain install`, which failed only because of this sandbox's
  read-only `~/.cargo/bin`; the toolchain was already installed. The first
  hosted run needs confirming after the owner pushes.
- 2026-10-25: Step 8 done. Final gates: SPDX ok; fmt ok; clippy `-D warnings`
  clean; `cargo test --locked`: 14 unit, 2 integration, 16 doctests (8
  `compile_fail` + 8 paired positives), all passing; `cargo deny check` ok;
  `cargo vet --locked` ok. Specs unchanged; 0008 stays Draft.
  Known limitations (by design for this phase): no guard pages / no-access
  allocations (0008 §1.2 "prefer", needs `unsafe`); no swap/hibernation
  reporting (§1.3); process hardening only on Linux/Android; zeroizing cannot
  erase copies made before wrapping or swapped pages.
  Found, not fixed: `AGENTS.md` still says "`unsafe` only when a plan allows
  it", while the workspace lint is `forbid`. A plan that allows `unsafe` must
  also relax the lint for that crate (`forbid` can't be overridden by
  `#[allow]`). Left for the plan that first needs it.
