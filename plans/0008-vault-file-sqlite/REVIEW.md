# Review — Plan 0008: Vault file: hardened SQLite, schema, header and keyslots

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved (after the owner-directed fix of finding 1) | 2026-10-26 | commit `b270ecf` ("phase 1.6"), then the uncommitted finding-1 fix |

## Summary

The new crate `qv-store` matches the plan. It has the file-safety
primitives, the hardened connection with every setting read back, the exact
schema and independent row checks, the header and slot codecs, the header
MAC, atomic `create`, `open` → `unlock` with a separate wrong-password result,
the tamper and second-process lock suites, and the `vault_open` fuzz target.
The plan 0007 finding is fixed in `qv-model`. The code is careful and the
tests are real. There is one security problem: before any of our checks run,
SQLite rolls back a hot `-journal` file that sits next to the vault. The
plan's parent-directory rule, which is looser than the spec, lets another
user plant that file. A crafted 512-byte journal, written without any
knowledge of the vault, destroys it on open. Fixing this needs the owner to
choose the directory rule, so the plan stays `Implemented`.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | v4 checks in `Payload::check`; public `Keyslot::{encode, decode}` |
| 2 | yes | `rusqlite =0.40.2`, transitive pins ≤ 2026-10-12, 5 vet exemptions; `-DSQLITE_USE_URI=0` dropped (logged, justified) |
| 3 | yes | `O_NONBLOCK` added against a FIFO swap (logged) |
| 4 | yes | Attach create/write also off (logged); load-extension covered by the compile option, as planned |
| 5 | yes | `octet_length` instead of `length` (logged, justified) |
| 6 | yes | Missing parent → `NotFound` (logged) |
| 7 | yes | Roadmap *Done when* items mapped to named tests in the log |
| 8 | yes | Seeds built with Python's `sqlite3` instead of `create` (logged; equivalent) |
| 9 | yes | Docs updated |

Out-of-scope changes: none. The `qv-model` change and `.cargo/config.toml`
are justified in the approval entry.

## Findings

1. **[high] A hot `-journal` planted by another user rewrites or truncates
   the vault before validation** — `crates/qv-store/src/fs.rs:99`,
   `crates/qv-store/src/vault.rs:117-120`.
   SQLite rolls back a hot journal at `<path>-journal` the first time it
   reads the file, which happens inside `harden` (the `journal_mode` pragma),
   before `quick_check`, the schema check or the MAC. The journal has no
   cryptographic binding to the vault, so anyone who can create that name can
   make SQLite write arbitrary pages or truncate the file. I confirmed this
   with a temporary probe test, since deleted. I created a vault (12,288
   bytes), wrote a hand-made 512-byte journal header with `nRec = 0` and an
   original size of one page, mode 0666, and called `VaultFile::open`. The
   vault was truncated to 4,096 bytes and the open returned `Integrity`. The
   data is lost for good. SQLite only refuses a journal that it cannot open
   read-write, so another user's 0666 journal is accepted.
   Who can plant the file: anyone who can create entries in the parent
   directory. The plan's *Decisions needed* reading accepts a sticky,
   world-writable parent (`/tmp`) and a group-writable parent whose group is
   the effective GID. The second case is a shared group on systems whose
   primary group is shared, such as `users`. Spec 0004 §1.1 says "owner-only
   file permissions (0600, private 0700 directory on Unix)", so the plan's
   reading is looser than the spec text, and the spec was not amended. This is
   also a 0008 §5 issue: a path planted next to the vault redirects writes to
   it. The tamper suite's "a refused open leaves the file byte-identical"
   claim does not cover sidecar files.
   Directions (the owner chooses; they can be combined):
   (a) make the parent rule match the spec: no other-write bit even with the
   sticky bit, and either no group-write bit or only Android's own-UID/GID
   `0771` case. Read permission stays allowed, so `~/Documents` (0755) still
   works.
   (b) before SQLite opens the file, check `<path>-journal` if it exists
   (`lstat`/`O_NOFOLLOW`: regular file, owned by the effective UID, no group or
   other bits; otherwise `UnsafeFile`) and keep SQLite's rollback for our own
   journals, which phase 1.7's crash recovery needs. This still has a check
   then use race unless (a) also holds.
   My recommendation is both, with a tamper test for each journal case
   (another owner, mode 0666, symlink, our own valid hot journal still
   rolled back).
   Action: escalated; the owner chose both (a) and (b); fixed (see
   *Follow-up*).

2. **[low] A full disk is reported as a vault size limit** —
   `crates/qv-store/src/error.rs:118`, `:134`.
   `SQLITE_FULL`, `ENOSPC` and `EFBIG` map to `LimitExceeded` (CLI exit 9,
   "vault size limit exceeded"). The plan specifies this mapping, and
   `SQLITE_FULL` is also what `max_page_count` returns, so it is not a bug
   in this phase. Phase 1.7 (the first real writes) or 1.10 (CLI messages)
   should consider telling a full disk (`Io`) apart from the budget.
   Action: noted for 1.7/1.10.

3. **[low] Row checks and value reads are separate autocommit statements** —
   `crates/qv-store/src/schema.rs:215`.
   `read_rows` checks the types and lengths, then reads the values in later
   statements with no enclosing read transaction. Another process that
   ignores our `flock` could change the rows in between. Only the same user
   can do that, which is out of scope, and SQLite's `LENGTH` limit (64 MiB)
   still bounds each value. Phase 1.7 could run validation inside one read
   transaction anyway.
   Action: noted for 1.7.

4. **[low] `create` can fail after the vault is in place** —
   `crates/qv-store/src/vault.rs:201`.
   If `sync_dir` or the reopen fails after the rename, `create` returns an
   error, but a complete, valid vault exists at the path. This is not a
   corruption, but the CLI's `init` (1.10) should not tell the user that
   nothing was created.
   Action: noted for 1.10.

## Fixes applied by reviewer

None. A temporary probe test (`crates/qv-store/tests/zz_probe_hot_journal.rs`)
was written to confirm finding 1 and then deleted; the tree has no review
changes besides this file and the status lines below.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (all suites; qv-store unit tests 50 passed in 3.5 s) |
| `cargo deny check` / `cargo vet` | not re-run: dependencies unchanged since the developer's green run in the same commit |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 "Implemented so far", §6 local-storage row)
- [x] Spec statuses and Changelogs (no change; 0004 stays Accepted, not fully implemented)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

1. **Finding 1 (high): choose the parent-directory rule.** Option (a) matches
   0004 §1.1 as written ("private 0700 directory"; I read it as "no one else
   can write", keeping read permission allowed). Keeping the plan's looser
   reading instead needs a 0004 §1.1 amendment and still requires (b). Once
   you decide, the fix fits within plan 0008: a developer change to
   `check_parent`, a journal check before `open_connection`, and new tamper
   tests, with a *Revisions* entry in the plan. Phase 1.7 should not start
   until this is fixed, because it adds the real write path and the
   crash-recovery journal handling builds on it.

## Follow-up (2026-10-26)

The owner chose both remedies for finding 1. The fix was made within plan 0008
(*Revisions* entry) and checked in the same session:

- The parent rule now follows 0004 §1.1: no other-write bit (no sticky
  exception), no group-write bit except Android's own-UID/GID `0771`
  directory. Read bits stay allowed.
- `check_sidecars` runs before every SQLite open of the vault or its temp
  file: an existing `-journal` must be owner-only, and any `-wal` or `-shm` is
  refused. A probe showed that a planted WAL is replayed and written into the
  vault even in rollback-journal mode (`open` succeeded and the header MAC on
  disk was zeroed), so WAL files are refused outright, not only journals.
- Tests: planted 0666 and symlinked journals, a real WAL and a `-shm`, each
  refused with the vault byte-identical; a sticky shared parent is refused;
  our own synced hot journal still restores a torn page (crash recovery
  intact). With the check removed, the planted-journal test fails.
- Gates: SPDX, fmt, clippy `-D warnings`, `cargo test --locked` (319 passed,
  0 failed, 2 ignored) all pass.

Verdict after the fix: **Approved**. The fix was written and checked by the
same session that found the bug, so the review of phase 1.7 should look at
`fs.rs` and the sidecar tests again with fresh eyes. The Android branch of
`own_group_dir` has not been compiled yet (no Android target here).
