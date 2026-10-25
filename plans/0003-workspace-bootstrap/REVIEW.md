# Review — Plan 0003: Workspace bootstrap and protected memory

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-25 | commit `08161e3` ("phase 1.1") |

## Summary

The workspace, toolchain pin, lints, `cargo deny`/`cargo vet` setup, SPDX check,
CI workflow and `qv-crypto` (protected memory, process hardening, fail-closed
RNG) match the plan's design and steps. The page-lock registry is correct: pages
are locked before constructors return, a partial lock failure rolls back cleanly,
the refcounts never underflow, and drop zeroizes before it unlocks. The code has
no `unsafe` and no `unwrap` on fallible paths. Its doc comments are honest about
the limits (swap, earlier copies, best-effort hardening). The tests are real:
the compile-fail doctests carry error codes, the `RLIMIT_MEMLOCK=0` failure path
runs for real, and `VmLck` gives kernel-level evidence that pages are locked.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Virtual workspace, resolver 3, edition 2024, lints, `clippy.toml`, toolchain 1.98.1 |
| 2 | yes | `fill_from` injection; failure zeroes buffer; fixed Debug/Display strings |
| 3 | yes | Registry as designed; test-only injection is `#[cfg(test)]`; 8 `compile_fail` + 8 paired positives |
| 4 | yes | The real-limit path ran here (not skipped) |
| 5 | yes | `RLIMIT_CORE` 0/0 and `PR_SET_DUMPABLE 0`, checked by reading them back |
| 6 | yes | 3 audited via imports, 10 exempted, no audits written by us |
| 7 | yes | Checkout pinned by SHA, `persist-credentials: false`, `contents: read` |
| 8 | yes | Docs match the tree |

Out-of-scope changes: none. The two logged deviations (error-coded
`compile_fail` doctests; SPDX script also covers untracked files) make the work
stronger, and both are justified.

## Findings

1. **[low] Unit tests require working `mlock` on the host** —
   `crates/qv-crypto/src/memory.rs:573` (also `:525`, `:553`).
   `memory_pages_are_locked_by_the_kernel` locks 64 KiB (17 pages unaligned),
   and other tests assert `is_locked()`. On a host with a lower
   `RLIMIT_MEMLOCK` (64 KiB was the kernel default before 5.16, and some
   container runtimes still use it), `cargo test` fails instead of skipping.
   Failing loudly is defensible for a security crate, and both this environment
   (8 MiB) and GitHub runners have enough headroom. Revisit if the CI matrix
   gains constrained runners (phases 1.16, 2.3). Action: noted, no change.
2. **[low] `AGENTS.md` wording vs the `forbid` lint** — `AGENTS.md`
   (*Engineering conventions*, "`unsafe` only when a plan allows it"). The
   developer already logged this. `forbid` can't be relaxed per item, so the
   first plan that needs `unsafe` must also change how that crate opts into the
   workspace lints. Action: left for that plan, as the developer proposed.
3. **[info] Hosted CI not confirmed** — `master` is in sync with `origin`, but
   `gh` isn't installed in this environment, so the first Actions run could not
   be checked. Action: owner to confirm on GitHub.

## Fixes applied by reviewer

None.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (14 unit, 2 integration, 16 doctests) |
| `cargo deny check` | pass (cargo-deny 0.20.2) |
| `cargo vet --locked` | pass (3 fully audited, 10 exempted; cargo-vet 0.10.3) |

`cargo deny`/`cargo vet` ran from a scratch `CARGO_HOME`, because
`~/.cargo` is read-only in this sandbox.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 note, §6 rows)
- [x] Spec statuses and Changelogs (no change; 0008 stays Draft)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None blocking. Please confirm that the first hosted CI run on `master` passed.
