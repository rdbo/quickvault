# Large-vault evidence — 0047

Development evidence on2026-11-09, not device qualification or security proof.
There is no aggregate searchable-text eligibility cap. The existing1 GiB
referenced-ciphertext limit and all per-object/model limits remain.

## Stock-budget fixture

`crates/qv-core/src/large_vault_tests.rs` authors90 entries through ordinary
save APIs. Each has three searchable256 KiB values: **70,778,880 bytes
(67.5 MiB)** of values alone, excluding titles and field names. No cache constant
or validity limit is raised. Whole returned rows fit the ordinary2 MiB page
budget two at a time, across45 pages. Every traversal checks all90 hits and
owned cache/query charging at or below64 MiB.

The expanded fixture covers password reopen, an edit, complete search,
streamed archive export/import, recovery snapshot restore, phrase unlock,
generation rotation, verification and search after rotation. It also exercises
both authenticated LAN enrollment routes, reopens the received files with the
shared password and traverses every hit. Synthetic quick unlock uses the
existing mock Android keystore services on the Linux test host; it is not a
physical biometric or Android lifecycle measurement.

Tiny-cache, Unicode, protected-field exclusion, maximum-row, backwards cursor,
stale query/session/scope, cancellation and concurrent-edit cases are separate
paging_tests.rs tests. Compact/full projection equivalence has generated cases
and a retained regression seed. Exact1 GiB reference-budget boundary and +1
rejection use synthetic manifest arithmetic, not a physically populated vault.

## Commands and measurements

Rust1.98.1, x86_64-unknown-linux-musl development host:

```sh
export CARGO_TARGET_DIR=/tmp/qv-0047-build
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export QV_TEST_KDF_JOBS=2
cargo test --locked -p qv-core large_vault_stock -- --nocapture
/usr/bin/time -v cargo test --release --locked -p qv-core large_vault_stock -- --nocapture
```

The pre-SQLite-upgrade ordinary debug core suite passes all136 tests, including
the expanded lifecycle, in1141.94s. After upgrading SQLite, the complete workspace
run also passes with opt-level1, debug assertions and overflow checks enabled;
its core suite takes115.32s. This is a whole-suite duration, not an isolated
fixture timing. The original smaller lifecycle, before adding LAN/quick unlock, passed debug in
665.96s and optimized in16.96s. These are historical results, not timings for
the expanded fixture. The pre-SQLite-upgrade optimized fixture passed in28.55s (after an83s rebuild):

| Operation | Time |
|-----------|------|
| Author90 entries |0.487s |
| Password open with ordinary snapshot policy |1.761s |
| Complete45-page search |0.537s |
| Password LAN enrollment, reopen and search |5.149s |
| Phrase/key LAN enrollment, reopen and search |3.822s |
| Synthetic quick open and complete search |1.349s |
| Complete expanded lifecycle |28.55s |

At completed-search checkpoints, structural counters were93 records,93 heads,
94 referenced objects (95 after rotation),73,058,176 referenced ciphertext bytes
(73,058,432 after rotation), and66,850,387 bytes of owned cache/query text.
The filtered test process reported peak RSS340,084 KiB (about332.1 MiB);
search checkpoints reported current RSS roughly75–141 MiB. This includes KDF,
SQLite, allocator and other process costs, not just cache text. The final `/usr/bin/time` invocation includes compilation and therefore reports
589,328 KiB for the command and descendants; that is not the vault process's
peak. Its `/proc/self/status` high-water mark above isolates the running test.
The earlier no-rebuild checkpoint reported339,628 KiB in both measurements.
Logs retain the exact counters.

These are individual homogeneous ASCII fixtures on a warm development host,
not latency targets, statistical benchmarks, representative conflicted datasets,
phone measurements or1 GiB performance claims. The first final repeat failed at archive merge with Store(Io) while concurrent
native/debug work nearly exhausted temporary disk. The failure is recorded,
not counted as success. Reclaimed this session's generated release/incremental
artifacts and abandoned interrupted-test fixtures; the final repeat above then
passed with adequate temporary space. Final workspace/native/release results are recorded
in REVIEW.md and the plan execution log.

## Memory contract and remaining qualification

- Cache, normalization/selection keys and cursor sort text share64 MiB of
  owned text capacity. Evicted readers remain charged until their text drops;
  cloned cursors share immutable state. A smaller cache test target does not
  shrink the fixed working-text budget or make a valid record ineligible.
- Structural record/head/tree metadata is separately bounded by existing
  manifest/record/object/clock limits, with no full titles or field values.
  One decoded head and serialization scratch have separate model bounds;
  uncacheable valid rows bypass residency rather than failing vault open.
- A returned core page has at most32 rows and2 MiB owned display text. The app
  has three replaceable page lanes without retained history; selected detail,
  active query and framework copies are additional. CLI traversal retains one
  page plus ancestor IDs and streams path names/JSON.
- Argon2 uses256 MiB working scratch. Engine/library, SQLite, allocator,
  GUI/WebKit and OS copies are additional. The measured RSS is a test-process
  observation, **not a total application memory ceiling**.
- Bulk mutation preparation can retain many decoded payloads (for example a
  recursive deletion or large batch edit). Its existing record/ciphertext/batch
  bounds are separate from the view cache; tighter mutation working memory
  requires separate work. There is no promise that every operation fits64 MiB.

Recorded RSS/isolated timings precede the final SQLite upgrade; the final
upgraded dependency tree passes functional lifecycle tests. Updated device/
representative measurements are follow-up0048, not an additional0047 run.

Physical Android/Linux interactive read/search/lock checks, large/conflicted
real-world workloads, supported-device peak memory/KDF latency and actual1 GiB
vault benchmarking remain release/qualification evidence gaps. Neither the
synthetic keystore nor the arithmetic boundary fixture closes those gates.
