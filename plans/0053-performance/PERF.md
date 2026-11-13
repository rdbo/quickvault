# Plan 0053 performance evidence

2026-11-13. Linux development host, stable 1.98.1, release profile. These are
development timings, not a release threshold. Phone measurements are pending
(see the end).

## Reproduce

```sh
# Current tree:
python3 plans/0053-performance/measure-perf.py --label after
# Baseline: a pristine export of the commit before this plan.
mkdir -m 700 /var/tmp/qv-0053-baseline
git archive 0c838e4 crates Cargo.toml Cargo.lock .cargo rust-toolchain.toml third-party \
  | tar -x -C /var/tmp/qv-0053-baseline
python3 plans/0053-performance/measure-perf.py --source-root /var/tmp/qv-0053-baseline --label baseline
# Unlock benchmark (plan 0024), P1 and P2, three samples each:
cargo run --release --locked -p qv-core --example budget_bench -- generate <new dir> P2
cargo run --release --locked -p qv-core --example budget_bench -- measure <dir> 3
```

The harness is derived from plan 0048's, keeping its safeguards: an owner-only
temporary directory, product-lockfile versions only, the product SQLite flags,
synthetic data only. Fixtures are 30, 90 or 180 entries with three 256 KiB
searchable values each (22.5, 67.5 and 135 MiB), authored through core and
fully verified. Every sample is a fresh process with a fresh password unlock.
It measures `unlock`, then a complete paged `traverse`, then one operation:

- `search`: complete paged search for "bulk", which matches every title;
- `fieldsearch`: a query that matches no title, so every field is examined;
- `refine`: the first page of "b", "bu" and "bul", then all pages of "bulk";
- `kinds`: the sidebar type counts;
- `batch`: set an icon on all entries in one call;
- `recursive`: trash the group and its entries in one call.

`growth` is the sampled peak RSS minus the RSS before the stage (2 ms sampling;
short transients can be missed). Stage times also have about 2 ms of
granularity: the sampler thread's sleep is joined at the end. That is why a
sub-millisecond stage reads 0.1 ms in one run and 2.1 ms in another. Unlock
growth includes the 256 MiB Argon2id run. Raw summaries are in `evidence/`.

## Results (medians of three samples; unlock and traverse of 18)

| Rows | Stage | Baseline | After | Change |
|------|-------|----------|-------|--------|
| 180 | unlock | 1,901 ms | 1,319 ms | −31% |
| 180 | traverse | 16,342 ms | 347 ms | 47× faster |
| 180 | search | 16,091 ms | 404 ms | 40× faster |
| 180 | refine | 16,918 ms | 403 ms | 42× faster |
| 180 | fieldsearch | 217 ms | 196 ms | −9% |
| 180 | kinds | 180 ms | 2.2 ms | 82× faster |
| 180 | batch | 1,552 ms, +146,256 KiB | 1,560 ms, +4,164 KiB | memory −97% |
| 180 | recursive | 1,555 ms, +145,476 KiB | 1,541 ms, +4,188 KiB | memory −97% |
| 90 | unlock | 1,143 ms | 844 ms | −26% |
| 90 | traverse | 531 ms | 44 ms | 12× faster |
| 90 | search | 532 ms | 44 ms | 12× faster |
| 90 | refine | 566 ms | 46 ms | 12× faster |
| 90 | fieldsearch | 33 ms | 19 ms | −44% |
| 90 | kinds | 12.6 ms | 2.2 ms | sampler granularity |
| 90 | batch | 788 ms, +73,892 KiB | 779 ms, +4,064 KiB | memory −95% |
| 90 | recursive | 777 ms, +73,932 KiB | 776 ms, +4,084 KiB | memory −94% |
| 30 | unlock | 626 ms | 522 ms | −17% |
| 30 | traverse | 8.4 ms | 8.4 ms | same |
| 30 | search | 8.4 ms | 8.4 ms | same |
| 30 | refine | 10.4 ms | 10.4 ms | same |
| 30 | fieldsearch | 6.3 ms | 2.2 ms | −65% |
| 30 | kinds | 0.1 ms | 2.1 ms | sampler granularity (see above) |
| 30 | batch | 266 ms, +26,700 KiB | 262 ms, +3,996 KiB | memory −85% |
| 30 | recursive | 264 ms, +26,244 KiB | 260 ms, +4,004 KiB | memory −85% |

`budget_bench` (plan 0024 profiles; medians of three):

| Profile | Metric | Baseline | After |
|---------|--------|----------|-------|
| P1 (1,000 records, attachments) | unlock | 429 ms | 398 ms |
| P1 | peak RSS | 267,828 KiB | 267,924 KiB |
| P2 (49,997 entries, 4 versions) | unlock | 3,593 ms | 1,660 ms |
| P2 | peak RSS | 272,488 KiB | 288,960 KiB |
| P2 | verify / one edit | 2,467 / 2,460 ms | 2,522 / 2,610 ms |

## Targets (decision 1)

| Target | Result |
|--------|--------|
| Host complete search, 180 rows ≤ 2 s | **Met:** 0.40 s |
| Phone complete search, 180 rows ≤ 7 s | Pending: phone run |
| Phone complete traversal, 180 rows ≤ 3 s | Pending: phone run |
| Batch/recursive growth at 180 rows ≤ 32 MiB | **Met:** about 4 MiB |
| No 30/90-row stage more than 10% slower | **Met**, except stages under 3 ms, whose 2 ms differences are the sampler's granularity |

Phone expectation, not evidence: the 0048 phone run was 3.7× slower than this
host's baseline for the same search. The same ratio would put the phone at
about 1.5 s.

## Why

Code reading and the deterministic read counters in the tests:

- Every page rescanned every record. The cache evicted in record-ID order,
  which is also the scan order, so beyond the cache size every read missed. A
  complete traversal decrypted about pages × records views. In the new count
  test, forcing match sets off gives 209 reads for 14 hits, against a bound of
  54 with them on.
- Every page lowercased every examined field again.
- Unlock decrypted each single-head record three times: verification, the
  index summary, then the representative.
- Bulk changes kept every decoded record until the commit.

## Found, not fixed

- **One ordinary edit at P2 takes about 2.5 s,** unchanged by this plan
  (manifest/head work grows with the record count). Worth its own plan if
  50,000-record vaults matter.
- **P2 peak RSS rose by about 16 MiB:** labels for about 50,000 records, plus
  the cache tiers' map nodes. Label text is charged to the 64 MiB budget; map
  overhead is structural memory, as 0004 §7.1 allows.
- **`fieldsearch` with no hits** still examines all field text on one page:
  that is the minimum without an index. Above the cache size it decrypts every
  record once per new query, then refinement narrows it.

## Phone run

Pending. Repeat 0048's method (LARGE-VAULT-VALIDATION.md, "Separate
mutation costs"):
1. Cross-build `perf-harness.rs` release/locked for `aarch64-linux-android`.
2. Push it to a disposable directory under the private shell UID.
3. Run `generate` and `sample … traverse|search|refine` for 90 and 180 rows.
4. Remove the subtree afterwards.

No app package is installed, and the owner's app data is never touched.
