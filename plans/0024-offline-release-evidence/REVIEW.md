# Review — Plan 0024: Offline hardening evidence (roadmap 1.16)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-30 | `git show 210c86c` ("phase 1.16"), plus the uncommitted reviewer fixes below |

## Summary

Phase 1.16 adds the offline evidence that does not depend on a frozen
format:
- matrix row tags and `scripts/check-matrix.sh`, run in CI;
- CLI audits of file modes, write failures and canary redaction;
- a networking-blocked test that CI must pass;
- the weekly extended fuzz workflow and a seeded `vault_open` target;
- the `budget_bench` example with Linux numbers;
- the supply-chain status in REPORT.md.

The work matches the plan as revised by the owner's no-freeze decision.
Step 8 (Android) is deferred, as logged. Two claims went further than the
tests: one matrix row was missing a required action, and one planned
canary was missing. Both are fixed with small test additions. Nothing
needs re-planning.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 Row list, tags, checker | yes | 23 rows. The reviewer checked in a scratch copy: a misspelled tag and a tag on a non-test item each exit 1; the restored copy exits 0. |
| 2 Mode audit | yes | `init`, `add`, `attach add`, `rm`, `trash empty`, `snapshot ls`, `passwd`, `recovery rotate` under `umask 000`. |
| 3 Write-failure audit | yes | `prlimit --fsize` deviation logged and justified. Rotation fails only at its recovery copy (finding 3). |
| 4 Redaction audit | yes, after fix | The planned new-password canary was missing (finding 2). |
| 5 Networking-blocked requirement | yes | Local result is a skip, not a pass. CI sets the sysctl and `QV_REQUIRE_NETNS=1`. |
| 6 Fuzz campaigns | yes | Eight clean 30-minute runs without ASan (musl); the weekly workflow uses ASan. |
| 7 Benchmark example | yes | P2/P3 profile corrections logged. |
| 8 Android numbers | deferred | Owner decision 2026-10-30 (plan *Revisions*). |
| 9 Report, docs, gates | yes | |

Out-of-scope changes: the commit also carries the 0023 review fixes. The
main one moves the journal directory fsync after the rename, so a failure
there is reported as "published". The reviewer re-read the change in
`crates/qv-store/src/rotation_install.rs`; it is correct and covered by the
0023 tests.

## Findings

1. **[medium] "Implicit server prerequisite" evidence lacked recovery** —
   `crates/qv-cli/tests/offline.rs`. The 0012 §1 row requires
   create/unlock/edit/**recover** with no account or server and with
   networking blocked. The tagged CLI flow never ran `recover`, so the
   claim "every offline row has a tagged passing test" was incomplete for
   this row. Action: fixed by reviewer. `flow()` now reads the phrase from
   `init`'s display, runs `recover` through the same (optionally
   `unshare -rn`) wrapper, and unlocks with the new password.
2. **[low] Canary audit dropped the planned new-password canary without
   logging it** — `crates/qv-cli/tests/audit.rs`. Step 4 named canaries for
   the new password and a phrase word; the test had four canaries and
   neither of those. Action: fixed by reviewer. Added
   `CANARY_NEW` and a `passwd` run that types it, mismatches the repeat
   and is cancelled with Ctrl-C (exit 1). Phrase words are random
   dictionary words and cannot serve as distinct canaries; REPORT.md now
   says so.
3. **[low] The rotation write-failure case only fails at the recovery
   copy** — `crates/qv-cli/tests/audit.rs` (`limited(…, 1024)`). With a
   1 KiB limit, the rotation's pinned snapshot fails first, so the CLI
   audit never reaches the replacement's write error. This is logged and
   bounded by the store's pre-journal failure tests (0022/0023).
   Action: none. Note for the pre-1.0 release audit: a store-level
   injected write error at the replacement build would make this explicit.
4. **[low] Fuzz patch offsets mostly miss the seed file** —
   `fuzz/fuzz_targets/vault_open.rs` `mutate` (the same scheme as
   `archive_read`). A uniform `u32` offset falls inside a seed file of tens
   of KiB only by chance, and `-use_cmp=0` on musl limits libFuzzer's
   guidance. Taking `offset % len` would make far more patches land.
   Coverage still rose (277 → 663), so this is efficiency, not
   correctness. Action: recommended only (harness change; no product
   impact).
5. **[info] Tag fit.** `audit_modes_owner_only_under_umask_000` carries the
   "Ambiguous trust boundary" tag, which is a plaintext-allocation review
   row. The modes are 0008 §5 evidence, and the row's substance is the
   REPORT §5 review plus the redaction tests. This is acceptable for a
   review row; no change.
6. **[info] P2 is below the object budget.** It holds 199,991 objects, not
   the ≈ 250,000 the plan estimated. Manifest worst-case evidence comes
   from `manifest_worst_case_fits_the_limit`, so the "Budget
   inconsistency" row is unaffected.
7. **[info] Extended fuzz keeps no crash artifact.** `fuzz-extended.yml`
   uploads nothing, so a crash input survives only in the job log.
   Fuzz inputs hold no vault data, so uploading `fuzz/artifacts/` on
   failure would be safe. Owner's choice.

No security issue was found in the diff:
- the benchmark's development password is a 0600 file and a compiled-in
  constant, never argv;
- the audits use synthetic secrets;
- no `unsafe`, dependency or format change.

## Fixes applied by reviewer

- `crates/qv-cli/tests/offline.rs`: phrase capture from `init` and a
  `recover` step, plus an unlock with the new password, inside the
  networking-blocked flow (finding 1). Test-only.
- `crates/qv-cli/tests/audit.rs`: the `CANARY_NEW` canary and a cancelled
  `passwd` with a mismatched new password (finding 2). Test-only.
- `plans/0024-offline-release-evidence/REPORT.md`:
  - §1: the flow now covers recovery;
  - §2: five canaries, and why phrase words cannot be canaries;
  - first-person wording removed.

## Gates

The committed tree `210c86c` passed every gate before the fixes:
- SPDX, `check-matrix.sh`, fmt (workspace and fuzz) and Clippy;
- `cargo test --locked` with private Xvfb: 649 passed, 0 failed,
  2 pre-existing ignored, 36 groups.

After the fixes, `cargo test --locked -p qv-cli --test audit --test offline`
gave 3 + 3 passed. Final results on the reviewed tree are below. Logs are in
the session scratchpad (`rev24/`, `rev24final/`).

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass (23 rows, each ≥ 1 tag) |
| `cargo fmt --check` | pass (workspace; fuzz fmt passed on the committed tree, harness unchanged) |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass with private Xvfb: 649 passed, 0 failed, 2 pre-existing ignored, 36 groups (the fixes extend existing tests); `git diff --check` clean |
| `cargo deny check` / `cargo vet --locked` | n/a (no dependency change) |

The private Xvfb comes from Alpine packages extracted into the scratchpad
and is used through `QV_TEST_XVFB`. `unshare -rn` is unavailable here, so
`offline_with_networking_blocked` skips locally and is **not** counted as a
pass. The owner should confirm the hosted CI run, where it is required.
This review is not a proof of security.

## Documentation

- [x] CHANGELOG.md (1.16 entry present; review entry added)
- [x] ARCHITECTURE.md §7 (1.16 evidence and the no-freeze decision; no structural change)
- [x] Spec statuses and Changelogs (no normative change; no `Implemented` promotion, per the owner's decision)
- [x] Plan ticks, execution log, plans/README.md row (now Reviewed)

## Escalations for the owner

None blocking. For the owner:
- check that the hosted CI's networking-blocked test passes;
- the known limitations stay recorded, not decided (REPORT §7);
- findings 3, 4 and 7 are optional improvements.
