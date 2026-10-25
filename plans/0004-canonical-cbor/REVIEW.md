# Review — Plan 0004: Bounded deterministic CBOR (`qv-encoding`)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-25 | commit `cb37791` ("phase 1.2") |

## Summary

The plan built `qv-encoding`, a strict codec for the spec 0004 §3.1 profile.
It has an allocation-free iterative validator, a borrowing pull decoder,
`RawValue` for unknown entries, a canonical-only zeroizing encoder and
`encode_array`. It also adds a 60 s `cbor_decode` fuzz job in CI. The code
matches the plan's interface sketch and profile table. The deviations are
logged, and each one keeps behaviour the same or makes it stricter. The tests
are real. Each rejection test asserts its exact error. The proptest oracle
re-encodes valid input through the sorting encoder, so a validator that wrongly
accepted misordered or duplicate keys would fail it. One small CI hardening fix
was applied.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Head boundaries at every width; Appendix A bytes; non-shortest/reserved/indefinite/truncated rejections |
| 2 | yes | Every case listed in the plan is present with its exact variant; `validate.rs` has no `Vec`/`Box`/`String` |
| 3 | yes | Typed reads, `OutOfRange`, `try_null`, `raw_item`/`skip` sub-slices, `Unconsumed`, redacted `Debug`, `compile_fail` doctests (E0599, E0369) with paired positives |
| 4 | yes | Growth via own `reserve` (new Vec, copy, wipe old) with a debug assertion; sorting, duplicates, item counts, depth 32/33, raw depth, growth, `encode_array` bytes; `unknown_keys.rs` |
| 5 | yes | 4 properties at 256 cases; `proptest =1.12.0` dev-only; 4 `safe-to-run` exemptions, no audits, no publisher trust |
| 6 | yes | `fuzz/` outside the workspace with its own lock; CI job with pinned nightly and cargo-fuzz; musl workaround logged, not put in CI |
| 7 | yes | Docs as listed |

Out-of-scope changes: none. (The commit also contains the phase 1.1 review,
`plans/0003-workspace-bootstrap/REVIEW.md`, which was written in this phase's
session per the roadmap protocol.)

## Findings

1. **[low] CI did not enforce `fuzz/Cargo.lock`** — `.github/workflows/ci.yml` (fuzz job)
   The developer logged that `cargo fuzz run` has no `--locked` flag, so a
   stale fuzz lockfile would be re-resolved silently in CI (0012 §3: locked
   builds). Added a `cargo fetch --locked --manifest-path fuzz/Cargo.toml`
   step before the run. Verified locally: it passes on the committed lock, and
   on a copy with an extra dependency it refuses to update the lock.
   Action: fixed by reviewer.
2. **[low] Encoder nesting is checked after the closures return** — `crates/qv-encoding/src/encode.rs:148`
   `Encoder::array`/`map` compute depth bottom-up, so a caller that nests
   closures 1,000 deep recurses 1,000 deep before getting `DepthExceeded`. The
   plan says encoder recursion is "bounded by `MAX_DEPTH`". That holds for
   values decoded from validated input (depth ≤ 32), but not for an arbitrary
   trusted caller. No hostile input reaches this path, so it is not a
   vulnerability. Phase 1.5's typed writers should keep record nesting fixed
   by their schema, not driven by data. Action: noted, no change.
3. **[low] Oracle blind spot for keys outside `i64`** — `crates/qv-encoding/tests/roundtrip.rs:150`, `fuzz/fuzz_targets/cbor_decode.rs:48`
   A map with a key outside `i64` is copied verbatim, so the oracle does not
   cross-check the key order of such maps. `tests/reject.rs`
   (`key_order_is_bytewise_not_length_first`) does pin `u64::MAX` before `-1`.
   Random inputs rarely produce such keys anyway. Action: noted, no change.

Checked and fine: depth semantics (empty containers at depth 32 are
rejected), counts bounded before use (`2·n` for maps, `checked_mul`), no
arithmetic overflow paths (`frame.remaining` is only decremented on frames
pushed with ≥ 1 item), `int()` at `i64::MIN`/`-2⁶⁴`, error-path zeroization
(child encoders and map entries drop and wipe on `?`), `finish` hands over the
buffer without leaving a copy, errors carry no data, and no `Debug` on
`Decoder`/`Encoder`/`MapEncoder`. Key order is bytewise (RFC 8949 §4.2.1), as
0004 §3.1 requires ("core deterministic"). `sort_by` scratch copies hold only
encoded keys and `Vec` headers, never value bytes.

## Fixes applied by reviewer

- `.github/workflows/ci.yml` (fuzz job): new step "Check fuzz lockfile"
  (`cargo fetch --locked --manifest-path fuzz/Cargo.toml`). It is local, adds
  no dependency, changes no code or format, and it was verified here.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` (root and `fuzz/`) | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (75 tests across all crates, incl. doctests) |
| `cargo deny check` (deps changed) | pass (`advisories ok, bans ok, licenses ok, sources ok`; fuzz crate: advisories, bans, sources ok) |
| `cargo vet --locked` | pass (10 fully audited, 14 exempted) |
| Fuzz | Not re-run by the reviewer; the developer's local 60 s run (musl, `-use_cmp=0`) is logged. The first hosted run is pending the owner's push |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 row and "Implemented so far"; the diagram names no crates)
- [x] Spec statuses and Changelogs (no change; 0004 stays Accepted, not fully implemented)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None blocking. Carried over from the execution log, all owner-side:
(1) confirm the first hosted CI run, including the new `fuzz` job;
(2) whether to add `cargo vet` publisher trust entries (cuviper, BurntSushi)
in place of exemptions. That is a policy choice.
