# Review — Plan 0009: Objects, manifests, local head, anchor and the write path

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-26 | `e4a6d30` (phase 1.7); plan 0008 follow-up `5044abc` (`fs.rs`, sidecar tests) re-checked |

## Summary

Phase 1.7 gives `qv-store` the objects, the encrypted manifest, the MAC'd
local head, per-replica external anchors, writer state in the `replica` row
and the single mutation transaction, all as planned. Unlock follows the
planned order and fails closed. The crash harness covers every ordering
point with the planned outcome, and the rollback, tamper and linkage suites
test real failure paths with exact error variants. I found one bug:
`adopt_baseline` skipped the pending-anchor retry that every other write
does. It was local, the plan states the requirement exactly, and I fixed it
with a test. Nothing is escalated.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | 0004 §2 `replica` row, §4.1 budget, §4.2 sentence, Changelog line; matches D-A/D-B |
| 2 | yes | `LocalState` is a `MacKey`; key-separation test; public `Clock` codec |
| 3 | yes | Envelope bound before parsing and copying; AAD as 0004 §3.2; role match after AEAD |
| 4 | yes | Counts checked before `with_capacity`; one `validate` shared by decode and seal; streamed envelope hash tested against the full encoding |
| 5 | yes | Table in `compare` matches 0005 §5.4, including the generation step; anchor read is `O_NOFOLLOW`, owner-only, 256-byte bound |
| 6 | yes | Schema 2 DDL and autoindex rows pinned; validation and row reads in one read transaction (0008 review finding 3) |
| 7 | yes | Create writes the anchor before the rename; unlock = `unlock_for_recovery` + fail-closed mapping |
| 8 | yes | `put_local` checks before any write; head and replica re-read inside `BEGIN IMMEDIATE` |
| 9 | yes | All 8 mutation and 2 create points; spilled hot journal rolled back; rollback and linkage suites; fuzz target + CI step |
| 10 | yes | Worst case 52,428,816 sealed bytes of 67,108,864; docs updated |

Out-of-scope changes: none. `Manifest::encode`/`decode` became public for
the fuzz target (logged in step 7).

## Findings

1. **[medium] `adopt_baseline` could put the DB two commits ahead of its
   anchor** — `crates/qv-store/src/write.rs:125`.
   `write()` retries a pending anchor update before it begins, but
   `adopt_baseline` called `begin` directly. After a commit whose anchor
   write failed (gate `AnchorPending`, DB at N+1, anchor at N), a recovery
   committed N+2. If its anchor write failed too, the next open saw a head
   two ahead and returned `Rollback`. That contradicts the plan's reading
   ("the DB can never get two steps ahead of the anchor") and 0005 §5.4.
   The result was a false refusal, not acceptance of a wrong state.
   Action: fixed by reviewer (shared `finish_pending_anchor`, new test
   `write_adopt_baseline_retries_pending_anchor`, which failed before the
   fix with seq 3).

2. **[low] The anchor directory may be the vault's own directory** —
   `crates/qv-store/src/anchor.rs:31`, `crates/qv-store/src/vault.rs:500`.
   The docs say the anchor must not sit next to the vault or in a sync
   folder (an anchor that rolls back with the vault detects nothing), but
   `create`/`unlock` accept any private directory. The Linux default is
   correct. Phase 1.10, which picks the directory for `--vault` paths, should
   refuse or warn when the anchor directory equals or contains the vault's
   directory.
   Action: noted for 1.10.

3. **[low] `Manifest`, `RecordEntry`, `VersionRef` derive `Debug`** —
   `crates/qv-store/src/manifest.rs:80`, `:126`, `:213`.
   They hold no secrets, but they map records to object IDs, which is the
   linkage 0004 §2.2 hides, and 0004 §5.1 calls metadata confidential. A
   `{:?}` in a future log line would leak it. Phase 1.8 (`qv-core`, the first
   consumer) should either redact these impls or make sure nothing logs
   them.
   Action: noted for 1.8.

4. **[info] The crash harness copies the live vault through a second
   descriptor** — `crates/qv-store/src/crash.rs:113`.
   `std::fs::copy` opens and closes the vault file, which drops the
   process's POSIX locks on it (the hazard `fs.rs` documents). This affects
   tests only, and the operation fails right after the copy, so no result
   depends on it. Keep it in mind if later write paths (1.12–1.15) reuse
   the harness and keep going after a snapshot.
   Action: none.

**Plan 0008 follow-up (fresh look):** `check_parent` matches 0004 §1.1 (no
other-write, no sticky exception, group write only for Android's own
UID/GID directory). `check_sidecars` runs before every SQLite open of the
vault and of the temp file, after the parent check, so only the owner or
root can race it. The tests cover a planted 0666 journal, a symlinked
journal, a real WAL, a `-shm`, a sticky shared parent, and our own hot
journal restoring a torn page. No further findings. The Android
`own_group_dir` branch is still uncompiled here.

**Checked and fine:** the record and manifest AADs and the configuration
digest against 0004 §3.2/§3.4; head MAC before parsing; manifest hash
recomputed from the stored columns and compared with the row key and the
head; history verified by length, SHA-256, then AEAD; every reference to
exactly one role, history dominated and not floor-suppressed, heads
pairwise concurrent, clocks unique per record; control kinds only on the
control IDs; the anchor table; counters reserved in the using transaction;
no `unsafe`; no `unwrap`/`expect` outside tests; redacted `Debug` on vault,
write and envelope types.

## Fixes applied by reviewer

- `crates/qv-store/src/write.rs:99-116`, `:125` — `write()` and
  `adopt_baseline` share `finish_pending_anchor`; test
  `write_adopt_baseline_retries_pending_anchor`. It is local, it changes no
  API or format, and the plan states the exact rule.
- `CHANGELOG.md` — *Fixed* entry for the above.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (before and after the fix; see the plan log) |
| `cargo deny check` / `cargo vet` | n/a (no dependency change; `Cargo.lock` untouched) |

## Documentation

- [x] CHANGELOG.md (plus the reviewer's *Fixed* entry)
- [x] ARCHITECTURE.md §3 and §6
- [x] Spec statuses and Changelogs (0004 amended, stays Accepted)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None. Findings 2 and 3 are carried into phases 1.10 and 1.8.
