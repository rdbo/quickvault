# Plan 0024 — Offline hardening evidence (roadmap 1.16)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-30 | 2026-10-30 (standing approval, roadmap 0002) | 0012 §1 (offline rows), §3 (offline gate); 0002 §1.3, OQ1; 0004 §4, OQ1; 0008 §5; 0011 §3 |

## Intent

Collect the offline release-gate evidence that the format freeze depends on:
- every offline row of the 0012 matrix tied to a named, passing test;
- extended fuzz campaigns;
- KDF and budget benchmarks on Linux and on the owner's Android phone;
- permission, disk-full and redacted-error audits;
- the dependency audit status.

Phase 1.16b then freezes the formats from this evidence. The KDF profile
may change only *before* the freeze (roadmap risks).

## Scope

**In scope:**
- A row tag convention for tests, plus a checker script (run in CI) that
  fails when a listed offline row has no tagged test.
- Tags on existing tests. New tests only where a listed offline row has none.
- CLI audit tests:
  - file and directory modes under `umask 000`;
  - write failures from a file-size limit (the disk-full path) at each
    write path;
  - canary secrets absent from all output of failing commands.
- The networking-blocked CLI test turns from "skip" into a required pass
  where CI enables namespaces.
- Extended local fuzz campaigns of every existing target, plus a scheduled
  longer CI campaign.
- A benchmark example (no new dependency): generation on the host, then
  measurement on Linux and Android.
- `REPORT.md`, with the matrix map, fuzz results, benchmarks, audit
  findings, the dependency audit status and known limitations.

**Out of scope (1.16b, its own plan, owner approval needed because it
amends specs):**
- the freeze: the physical DDL, CBOR registry, profile IDs/parameters and
  archive format recorded in 0002/0003/0004/0007;
- final release values for the development format numbers;
- golden vectors in `tests/vectors/`, including the worst-case manifest;
- closing 0002 OQ1 and 0004 OQ1;
- spec statuses set to `Implemented`.

Also out of scope:
- Any change to a KDF parameter or budget. This plan only measures and
  reports; a miss becomes a 1.16b decision.
- Behaviour changes for the known limitations: they are recorded, not
  decided.
- LAN, server and GUI rows of 0012.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Offline rows have named, passing tests | 0012 §1, §2 | Accepted | Row list below |
| Offline gate: crash points, permissions, disk-full, malformed SQLite/CBOR, redacted errors; KDF and resource benchmarks on supported targets | 0012 §3 | Accepted | Freeze itself is 1.16b |
| KDF target (~1 s mid-range, ≤ 2 s low-end Android, 64 MiB floor) | 0002 §1.3, OQ1 | Accepted | D7: one supported arm64 Android 10+, ≥ 4 GB device serves |
| Resource budgets; worst-case manifest | 0004 §4.1–4.2, OQ1 | Accepted | Measured; vector frozen in 1.16b |
| Owner-only files, no-follow | 0008 §5 | Draft, D5 | Audited by test |
| No secrets in argv, errors or output | 0011 §3; 0008 §1–3 | Accepted; Draft, D5 | Canary test |
| Supply chain status recorded with the release | 0012 §3 | Accepted | Report only |

**Offline rows** (the 0012 §1 rows that apply to the offline Linux CLI
release, with their offline part): Implicit server prerequisite;
Old-date concurrent edits; Order-dependent merges; Whole-file rollback; Live
SQLite copying; Swap/hibernation leaks (Linux CLI hardening status);
Unpinned crypto (offline profiles); Hostile SQLite/CBOR; Deleted-entry
resurrection (local merge); Self-referential/incomplete commitments;
Rotation/purge ambiguity (interrupted rotation, partial purge); Migration
coupling; Mixed credentials (local merge); Snapshot disk growth (mandatory
recovery copy with a full disk); Impossible generator; Ambiguous trust
boundary (plaintext allocation review, recorded); Hostile files from sync
folders (archive reading); Exchange-file password guessing;
Password-slot partitioning oracle; Anchor crash windows; CLI argument
leakage; Budget inconsistency; Supply chain (report).

Parts of these rows that need file exchange (2.2), LAN (2.x), the server
(3.x) or the GUI (2.4+) belong to those releases' gates. Every other row is
not offline.

**Spec changes required:** None in this plan.

## Decisions needed

None blocking. Recorded as sane defaults (owner: "use sane defaults"):
- **Offline row scope** as listed above. The owner can narrow or widen it
  at approval. Each row's non-offline part moves to the release that adds
  that transport.
- **Fuzz length:** 30 minutes per target locally (four in parallel, musl:
  `-s none`, `-use_cmp=0`). Plus a weekly scheduled CI job: 30 minutes
  per target with AddressSanitizer on glibc. Any crash stops the phase.
- **Benchmark profiles** P0–P3 below, five measured samples after one
  warm-up, release build, median and range reported.

Raised for 1.16b, not decided here:
- whether the measured KDF time keeps password-kdf/1;
- the final format version numbers;
- the known limitations from 1.15c: `info` shows no rotation hint; a
  generation ≥ 2 vault without its inventory has reduced snapshot
  protection; a rollback before commit needs the new password.

## Design

**Components touched** (no new crate, trust boundary or dependency):
- `scripts/check-matrix.sh` (new) and `tests/matrix-offline.txt` (new):
  the row list and the checker.
- `crates/*/src/**` and `crates/*/tests/**`: tag comments on existing
  tests only.
- `crates/qv-cli/tests/audit.rs` (new): modes, disk-full and canary tests.
- `crates/qv-cli/tests/offline.rs`: `QV_REQUIRE_NETNS=1` turns the skip into
  a failure.
- `crates/qv-core/examples/budget_bench.rs` (new): the benchmark example.
- `.github/workflows/ci.yml`: the matrix check, namespaces for the
  networking test, and a scheduled `fuzz-extended` job (actions pinned by
  SHA, tools by version).
- `plans/0024-offline-release-evidence/REPORT.md` and `evidence/` (numeric
  CSV and fuzz summaries only).

**Row tags.** A line `// 0012 §1: <exact row name>` directly above a
test function's attributes (`#[test]` or a `proptest!` item). One test may
carry several tags. `tests/matrix-offline.txt` has one row name per line,
in 0012 order, plus `#` comments.

`scripts/check-matrix.sh` (POSIX sh, SPDX header after the shebang):
- reads the list;
- scans `git ls-files 'crates/*.rs'`;
- prints each row with its count of tagged tests;
- exits 1 when a row has none, or when a tag names a row that is not in
  0012 §1 (it checks against the table rows of
  `specs/0012-security-validation.md`).

It does not run tests: `cargo test` is the "passing" half. CI runs it in
the gates job. "Supply chain" and "Ambiguous trust boundary" are
review/report rows: their tag is on the closest automated check
(`offline_cli_dependencies_are_fixed` and a redaction test), and the report
holds the review.

**Audit tests** (`crates/qv-cli/tests/audit.rs`, existing PTY/`Home`
harness, private Xvfb not needed):
1. *Modes.* Run a full workflow under `sh -c 'umask 000; exec "$0" "$@"'`:
   `init`, `add`, `attach add`, `snapshot`, `passwd`, `recovery rotate`.
   Then walk the vault directory and the XDG state, config and data
   directories. Every regular file QuickVault created is `0600`, every
   directory it created is `0700`, and there are no symlinks.
2. *Write failure.* Run each write path under
   `sh -c 'trap "" XFSZ; ulimit -f <blocks>; exec "$0" "$@"'`, with the
   limit just above the existing file size (measured in the test; POSIX
   `ulimit -f` blocks are 512 bytes, so check the shell's unit once and
   assert it). The paths: `init`, `add` (vault growth), `attach add`,
   `snapshot`, `recovery rotate`. Each must:
   - exit nonzero with the documented code for `LimitExceeded`/`Io`
     (0011 §6);
   - print no panic;
   - leave the previous vault openable with its anchor `Verified` and its
     content unchanged;
   - leave no published partial file: for rotation, no marker, or a marker
     that `recovery rotate` resolves;
   - for a mandatory recovery copy, follow the existing over-budget/refusal
     path, matching the 0012 "Snapshot disk growth" offline part.

   EFBIG maps to `LimitExceeded`, like ENOSPC (`errno_err`). A real
   full-disk test needs root or a tmpfs mount, which this environment
   lacks; the report says so.
3. *Canaries.* Distinct canary strings for the master password, the new
   password, a protected note, a field value and a phrase word. Drive
   failing commands: a wrong password, an over-limit field, a cancelled
   rotation, a corrupt vault (Integrity), a refused restore, and `--json`
   errors. Assert that no canary appears in stdout, stderr, the argv of
   spawned helpers, or any file outside the encrypted vault and archives.

**Networking-blocked evidence.** In `offline_with_networking_blocked`,
if `QV_REQUIRE_NETNS=1` and `unshare -rn true` fails, panic instead of
skipping. In CI's gates job:
- set `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
  (Ubuntu 24.04 restricts unprivileged user namespaces);
- set `QV_REQUIRE_NETNS=1` on the Test step.

This environment still cannot run it. The owner reads the CI result; the
report records that the local result is a skip, not a pass.

**Benchmark example** (`crates/qv-core/examples/budget_bench.rs`; uses only
qv-core and its existing dependencies; lints and SPDX as product code; no
`unsafe`):

```text
budget_bench generate <dir> <profile>   # host only; writes v.qvault, anchors/, password file 0600
budget_bench measure  <dir> [samples]   # Linux and Android
```

- `generate` builds the vault through `qv_store`'s public `Write` API in
  batches of ≤ 1,000 records per commit (development password read from
  `<dir>/password`, never argv). Then a full `verify_all`.
- `measure` runs one warm-up plus `samples` (default 5) runs of:
  `Core::unlock` (KDF, header MAC, unlock verification, anchor, views),
  then `Session::verify`, then lock. It prints one CSV row per sample:
  `profile,unlock_ms,verify_ms,peak_rss_kib,file_bytes`. Peak RSS is
  `VmHWM` from `/proc/self/status`, read after each sample in a fresh
  child process, so every sample has its own peak. No secret is printed.

| Profile | Content | Purpose |
|---------|---------|---------|
| P0 | empty vault | KDF-dominated unlock (0002 §1.3) |
| P1 | 1,000 entries, 3 history versions each, 20 attachments of 1 MiB | typical vault |
| P2 | 50,000 records (max record IDs), 4 retained versions each (≈ 250,000 objects, within the clock budget) | record/object/manifest budgets (0004 §4.1) |
| P3 | 100 attachments of 10 MiB (≈ 1 GiB referenced ciphertext) | ciphertext budget and streaming |

If generating P2 or P3 hits a budget error, that is a finding: report it
and stop, rather than shrinking the profile. Android:
- build with the NDK from `scripts/setup-android.sh --print-env` for
  `aarch64-linux-android` (release);
- push the binary and the generated directories to `/data/local/tmp/qv-bench/`
  over the owner-started adb server only;
- run `measure`; collect only the CSV; remove the directory afterwards.

The 1 GiB P3 push is optional when the phone lacks space; the report says
so.

**Fuzz campaigns:**
- Local: each of the 7 targets for 30 minutes on the pinned nightly, with
  the corpus from the CI 60 s runs as seed. Record runs, `cov`/`ft`, peak
  RSS and crashes in `evidence/fuzz-<target>.txt` (summary lines only).
- CI: `.github/workflows/fuzz-extended.yml`, `on: schedule` (weekly) and
  `workflow_dispatch`, ubuntu-latest, pinned nightly and cargo-fuzz
  0.13.2, `-max_total_time=1800`, the same `-max_len` values as ci.yml,
  ASan (the cargo-fuzz default). Upload no artifacts with vault data.

**Secrets and hostile input:**
- The benchmark password is a development constant read from a 0600 file.
  Generated vaults are disposable and never contain user data.
- Canaries are synthetic.
- Fuzz inputs never touch the user's files.

**Errors:** existing types only. Any audit failure is a finding in
REPORT.md. It is fixed in this plan only when local and obvious
(developer stop conditions); otherwise the phase stops.

**Dependencies:** None.

## Steps

### Step 1 — Row list, tags and checker

- [x] **Do:**
  - Write `tests/matrix-offline.txt` (the rows above).
  - Write `scripts/check-matrix.sh`.
  - Tag the existing tests that exercise each row, reading each test before
    tagging it. A row whose offline part has no test is recorded as a gap
    for steps 2–4, or as a new focused test in this step if it is small.
  - Add the CI step.
- **Files:** `tests/matrix-offline.txt`, `scripts/check-matrix.sh`,
  `crates/**` (comments only), `.github/workflows/ci.yml`.
- **Done when:** `sh scripts/check-matrix.sh` lists every row with ≥ 1
  tagged test, or exits 1 naming only the rows that steps 2–4 cover. A
  deliberately misspelled tag in a scratch copy makes it exit 1.
- **Verify:** `sh scripts/check-matrix.sh`; `sh scripts/check-spdx.sh`.

### Step 2 — Mode audit

- [x] **Do:** `audit.rs` test 1.
- **Files:** `crates/qv-cli/tests/audit.rs`.
- **Done when:** it passes; a scratch run that `chmod 0644`s one created
  file makes it fail (then reverted).
- **Verify:** `cargo test --locked -p qv-cli --test audit modes`.

### Step 3 — Write-failure audit

- [x] **Do:** `audit.rs` test 2 for the five paths.
- **Files:** `crates/qv-cli/tests/audit.rs`; product code only for a
  local, obvious fix (logged).
- **Done when:** every path fails closed as specified.
- **Verify:** `cargo test --locked -p qv-cli --test audit write_failure`.

### Step 4 — Redaction audit

- [x] **Do:** `audit.rs` test 3. Review the `Debug` impls of
  secret-bearing types in qv-crypto, qv-store and qv-core; list them in
  the report.
- **Files:** `crates/qv-cli/tests/audit.rs`.
- **Done when:** no canary leaks; the review list is in the report.
- **Verify:** `cargo test --locked -p qv-cli --test audit canary`.

### Step 5 — Networking-blocked requirement

- [x] **Do:** `QV_REQUIRE_NETNS` in `offline.rs`; CI sysctl and
  environment.
- **Files:** `crates/qv-cli/tests/offline.rs`, `.github/workflows/ci.yml`.
- **Done when:** locally, with `QV_REQUIRE_NETNS=1`, the test fails with
  the unavailability message; without it, it skips as before.
- **Verify:** `cargo test --locked -p qv-cli --test offline`.

### Step 6 — Fuzz campaigns

- [x] **Do:** run the local campaigns (in the background while steps 2–5
  proceed). Add `fuzz-extended.yml`.
- **Files:** `.github/workflows/fuzz-extended.yml`,
  `plans/0024-offline-release-evidence/evidence/fuzz-*.txt`.
- **Done when:** seven 30-minute runs end with no crash, timeout or OOM.
  A crash stops the phase with its minimized input kept outside the repo.
- **Verify:** the summaries; `cargo fmt --check --manifest-path fuzz/Cargo.toml`.

### Step 7 — Benchmark example and Linux numbers

- [x] **Do:** the example; generate P0–P3 in the scratchpad; measure on
  the host (release).
- **Files:** `crates/qv-core/examples/budget_bench.rs`,
  `evidence/linux-*.csv`.
- **Done when:** the CSVs have the exact header and 5 rows per profile;
  `cargo clippy --all-targets` is clean on the example.
- **Verify:** `cargo build --locked --release -p qv-core --example budget_bench`.

### Step 8 — Android numbers (owner's phone) — deferred (Revisions, 2026-10-30)

- [ ] **Do:** ask the owner to connect the phone through the adb server
  they start. Cross-build, push, measure, collect the CSVs, clean up.
- **Files:** `evidence/android-*.csv`.
- **Done when:** P0–P2 (P3 if space allows) have 5 samples each. If the
  phone is unavailable, the step stays open: 1.16b cannot freeze without
  it, and the report says so.
- **Verify:** the CSV header and row checks.

### Step 9 — Report, docs and gates

- [x] **Do:** write `REPORT.md`:
  - the matrix map (row → tests);
  - fuzz results;
  - benchmarks against 0002 §1.3 and the 0004 budgets;
  - the audit results and limits (no tmpfs/root, no netns locally);
  - the dependency audit status (`cargo vet` exemptions and audited
    crates, unaudited security-critical crates named);
  - the known limitations;
  - the decisions raised for 1.16b.

  Also update `CHANGELOG.md`, `ARCHITECTURE.md` §7 (1.16a), the roadmap
  (1.16 split revision, tick and log), `plans/README.md` and this plan.
  Run all gates.
- **Files:** as listed.
- **Done when:** the plan is Implemented and all gates are green.
- **Verify:** all `AGENTS.md` gates, `sh scripts/check-matrix.sh`,
  `git diff --check`.

## Test plan

- Final verification: all `AGENTS.md` gates (with private Xvfb), plus
  `sh scripts/check-matrix.sh`. No dependency change, so deny/vet are not
  required. They are still run once for the report's supply-chain status.
- New tests: modes, write failure and canaries (CLI). The networking test
  is required where CI enables it.
- Rejection and crash paths: existing suites, now tagged. The write-failure
  test adds real write errors.
- Fuzz: 7 × 30 minutes locally; weekly in CI.
- Vectors: none new (golden vectors are 1.16b).
- 0012 §1 rows: every offline row listed above.

## Risks and stop conditions

Stop and report if:
- a fuzz run finds a crash, hang or OOM;
- a benchmark misses 0002 §1.3 (more than ~1 s on the phone treated as
  mid-range, or more than 2 s), or a profile cannot be generated within
  the 0004 budgets. That is a 1.16b decision; never change parameters or
  budgets here;
- an audit finds a secret in output, a file outside owner-only modes, or a
  write failure that loses or corrupts prior state, and the fix is not
  local and obvious;
- a row's offline part needs behaviour that does not exist yet;
- anything needs a dependency, `unsafe`, a spec amendment or a format
  change.

The phone is touched only through the owner-started adb server: no
global settings, no app install, only `/data/local/tmp/qv-bench/`, removed
afterwards.

## Documentation

- [x] `CHANGELOG.md`: Unreleased: offline release evidence (matrix
  checker, audits, fuzz, benchmarks).
- [x] `ARCHITECTURE.md`: §7: 1.16 evidence and the no-freeze decision.
- [x] Specs: no change (benchmarks are recorded in the specs by the 1.16b
  freeze).
- [x] `AGENTS.md`: the row tag convention, in *Engineering and
  verification* (one line), and `.agents/README.md` if it lists scripts.
- [x] Plans: this plan and REPORT.md; the roadmap revision, tick and log;
  `plans/README.md` row.

## Revisions

- 2026-10-30 (owner decision, during step 6): pre-1.0, everything stays
  volatile, and there is no format freeze until the owner declares the
  product ready and has user-tested it. The roadmap drops 1.16b, so this
  plan is all of 1.16.
  - **Step 8 (Android benchmarks) is deferred** to the unscheduled pre-1.0
    release step. Its only purpose was KDF/budget tuning before a freeze.
    The phase-1.9 phone number (865 ms median unlock) stays the reference.
  - **Step 6:** the local campaigns already running are completed and
    reported. No further long local campaigns; ongoing fuzzing is the
    per-push and weekly CI jobs.
  - Mentions of "1.16b" and "the freeze" below now refer to that release
    step.

## Execution log

2026-10-30: Same session as the fresh-context review of 0023 (Approved
with minor fixes; the owner had committed 1.15c as `c7b6c1d`). Phase 1.16
is split under the session-size rule: 1.16a (this plan, evidence) and 1.16b
(the freeze, which amends specs and so needs the owner's approval). This
plan has no open decision, spec amendment, dependency, `unsafe` or
crate/order deviation: standing approval, roadmap 0002. Developer starts at
step 1.

2026-10-30: Steps 1–5 done.
- **Matrix.** `tests/matrix-offline.txt` (23 rows, 0012 order) and
  `scripts/check-matrix.sh`. 69 tags on existing tests, each read by name
  and body or doc comment before tagging (the new audit tests add 4 more).
  Every row has ≥ 1 tagged test, so the rows needed no new focused test.
  Negative runs: a misspelled tag (unknown row) and a tag on a non-test
  item both exit 1. A CI step runs it in the gates job.
- **Modes** (`audit_modes_owner_only_under_umask_000`): `init`, `add`,
  `attach add`, `rm`, `trash empty`, `snapshot ls`, `passwd` and
  `recovery rotate` under `umask 000`. Every file under the home is 0600,
  every directory 0700, and there are no symlinks (the test's own input
  file is excluded). A scratch `chmod 0644` of the vault made it fail
  (420 vs 384); reverted.
- **Write failure** (`audit_write_failure_fails_closed_at_every_write_path`),
  under `prlimit --fsize` with `SIGXFSZ` ignored:
  - the automatic snapshot fails as a warning (exit 0) with no archive
    left;
  - `add` (vault growth) and `attach add` exit 1/9 with the vault, anchor
    and directory byte-identical and still unlocking;
  - `trash empty` refuses before deleting (entry still in trash,
    snapshots unchanged);
  - `recovery rotate` publishes nothing (no marker, no "partly applied",
    old password works);
  - `init` publishes nothing at the target.

  Differences from the plan:
  - `prlimit --fsize` (byte-exact) instead of `ulimit -f`, whose block
    unit differs between shells (512 bytes in busybox and dash, 1024 in
    bash).
  - The rotation case cannot choose between failing at the recovery copy
    and failing at the replacement: their sizes are too close to separate
    with one limit. The store's pre-journal failure paths are covered by
    the 0022/0023 tests.
- **Canaries** (`audit_canary_secrets_never_reach_output_or_files`): four
  canaries (master password, a wrong password, a historical and a current
  protected field). Eight failing piped commands (wrong password, also
  `--json`; missing entry; protected field without `--reveal`; an
  over-limit attachment, exit 9; unknown snapshot; missing history,
  `--json`; corrupt vault) and a cancelled PTY rotation. No canary appears
  in their output, and none in any file under the home: vault pages,
  journals, anchors, archives.
  - Differences from the plan: a field over 256 KiB cannot be passed in
    argv (Linux caps one argument at 128 KiB), so the over-limit case is an
    attachment of 10 MiB + 1. None of these commands spawns a helper, so
    there is no helper argv to check; argv leakage stays covered by the
    tagged "CLI argument leakage" tests.
  - Investigated, not a finding: the first version flipped one byte at the
    file's midpoint, and the copy still opened. The byte was in the
    unallocated gap of an index page (`sqlite_autoindex_object_1`, page 5,
    offset 2048), which is never read. QuickVault authenticates content,
    not page slack. The test now clobbers the SQLite magic instead.
  - Debug review: every secret container in qv-crypto, qv-model, qv-store
    and qv-core has a hand-written redacted Debug. Derived Debug appears
    only on settings, IDs, profiles and errors (listed in REPORT.md).
- **Networking-blocked requirement.** `QV_REQUIRE_NETNS=1` turns the skip
  into a failure. Locally: a skip without it (3 passed), and a failure with
  it ("unshare failed: No space left on device"). CI sets the AppArmor
  sysctl and the variable on the Test step. The hosted result is for the
  owner to check (no `gh` here).

  `cargo test --locked -p qv-cli --test audit`: 3 passed.
  `--test offline`: 3 passed.

2026-10-30: Steps 6, 7 and 9 done; step 8 deferred by the owner; plan
Implemented.
- **Fuzz.** Eight 30-minute local runs, all clean (no crash, timeout,
  OOM or leak): the 7 targets, plus `vault_open` seeded with two real vault
  files (coverage 663 against 277 unseeded). Summaries are in
  `evidence/fuzz-*.txt`. `fuzz-extended.yml` runs weekly and on demand,
  30 minutes per target with ASan.
  - Found, not fixed (recommended): build a real-vault seed into
    `vault_open`, as `archive_read` does.
  - The nightly warns that `fetch_update` is deprecated; stable is
    unaffected.
- **Owner decision during step 6:** no freeze before 1.0 (see Revisions).
  Step 8 deferred; the roadmap no longer has 1.16b. The owner also judged
  long campaigns too heavy for this stage; the report says so.
- **Benchmarks.** `budget_bench` (generate/measure/sample, a child process
  per sample). Differences from the plan:
  - P2 holds 49,997 entries, because the three control records count
    toward the 50,000 cap.
  - P3 holds 99 attachments, because padded chunks make 100 × 10 MiB
    exceed the 1 GiB ciphertext budget.

    Both first attempts were refused cleanly (LimitExceeded) with the vault
    intact. These were profile errors, not budget inconsistencies.
  - Added a `write_ms` column (one core edit per sample) and 0.1 ms
    resolution.

  Linux medians, unlock / verify / edit ms:
  - P0: 332.6 / 0.1 / 0.3
  - P1: 375.9 / 116.3 / 47.2
  - P2: 2388.9 / 2619.7 / 2551.3
  - P3: 488.4 / 3592.4 / 13.2

  Peak RSS is about 260 MiB throughout (the Argon2id buffer). The Android
  cross-build of the example works (scratchpad rustup home), but was not
  run.
- **Supply chain.** `cargo deny check` ok; `cargo vet --locked` ok (27
  fully audited, 6 partially, 79 exempted, including most
  security-critical crates). Recorded in the report.
- **Docs:** REPORT.md, `CHANGELOG.md`, `ARCHITECTURE.md` §7, `AGENTS.md`
  (row tags, no freeze), `.agents/README.md`, the roadmap and
  `plans/README.md`.
- **Final gates** on the final tree (logs: session scratchpad `final24/`):
  SPDX, `check-matrix.sh`, fmt (workspace and fuzz), Clippy and
  `cargo test --locked` with private Xvfb all pass: **649 passed, 0
  failed, 2 pre-existing ignored**, 36 groups. `git diff --check` is
  clean. No dependency, `Cargo.lock`, `unsafe`, format or spec change.
  Network isolation is unavailable here and not counted as a pass.
- The same-session check is not an independent review. The next fresh
  session reviews 0024. Changes are uncommitted.

2026-10-30: The owner said "whatever you feel is best" about the open items.
- **Done:** `fuzz/fuzz_targets/vault_open.rs` now builds a real vault
  (`VaultFile::create`) once per process. The first input byte picks the
  mode: even inputs are raw bytes as before; odd ones are `(offset, byte)`
  patches plus a truncate/extend selector applied to that vault, the
  `archive_read` scheme.
  - Fuzz-harness only; no dependency (qv-crypto and qv-store were already
    fuzz dependencies).
  - `cargo fmt --check --manifest-path fuzz/Cargo.toml` passes.
  - A 2-minute run from an empty corpus was clean (1,139,278 runs, cov
    2297, ft 3043; that coverage includes the one-time creation).
  - The workspace is unchanged, so the earlier workspace gates still apply.
- **Left:** the known limitations (REPORT §7). The rollback credentials and
  the cleanup of a damaged `-old-` copy are security trade-offs; the rest
  belong to the pre-1.0 release step. The owner commits as usual.

2026-10-30: Fresh-context review (REVIEW.md): **Approved with minor
fixes**. The offline CLI flow now also runs `recover` under the
networking-blocked wrapper (the 0012 row names recovery). The canary
audit gained the planned new-password canary. REPORT.md was updated to
match. Status Reviewed.
