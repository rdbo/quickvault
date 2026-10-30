# Review — Plan 0023: Rotation installation, restart and `recovery rotate`

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-30 | `git show c7b6c1d` (phase 1.15c), plus the reviewer fixes below |

## Summary

Phase 1.15c publishes the verified replacement through the 0021 journal. It
covers the I0–I9 sequence with no-replace renames and one anchor generation
step, restart and rollback, removal of pre-journal leftovers,
inventory-aware snapshot budgets, the core `Rotation` lifecycle and
`qvault recovery rotate`. It matches the plan. The logged deviations
(the extra `RollbackPending` state, `NeededPasswords` instead of a single
boolean, an old-generation restore being exit 7 rather than 4) are sound and
justified. Restart authenticates every copy it relies on with its own
password and checks head, digest, sequence, replica and that side's journal
MAC before it acts. The crash matrix reaches every installation, completion
and rollback point. One error-classification edge in the journal
publication step, three hostile cases named in step 3 but not tested, and a
stale doc comment were fixed.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 Primitives, crash harness | yes | `FileRole::Transition` skips only the name/marker test and is refused by every write path (`refuse_candidate` now refuses any non-ordinary role) and by `finish_unlock`. `read_bounded` checks the size by fstat before reading. The flock stays with the descriptor that `into_file` returns. |
| 2 Installation | yes, after fix 1 | I0 re-checks identity, anchor and inventory scope. Cancellation is polled only up to I3. A cleanup failure after I6 is `cleanup_pending`. |
| 3 Restart | partial → yes after fix 2 | The state table matches. Rollback of Committed and Complete of RollbackPending are refused before any change. Missing before the fix: "swapped suffix", "another vault's journal" and "a stale old copy". The developer log did not list them as omitted. |
| 4 Crash matrix | yes | 11 installation points; 8 completion and 5 rollback points after a restart. Each ends with exactly one generation openable, its anchor verified and its logical state equal. Content equality follows from the head digest that restart checks against the journal, and from plan 0022's comparison. |
| 5 Inventory policy | yes | Rows count and age out; removal goes through `remove_inventoried` only; a mismatch stops pruning with a failed report. Without an inventory at generation ≥ 2 there is no ordinary copy and no pruning, and a recovery copy needs consent. Listing subtracts exactly the present inventoried files from `unreadable`. |
| 6 Core | yes | Refusals before the snapshot keep the session. `take_open` locks it afterwards. Install needs three distinct confirmed words. |
| 7–8 CLI | yes | Typed `rotate`, `complete` and `rollback` ignore `--yes`. The usage refusals come before any prompt. A real interrupted install (anchor directory 0500) completes on one copy and rolls back on another. |
| 9 Docs, gates | yes | |

Out-of-scope changes: none.

## Findings

1. **[low] A journal published with a failed directory fsync was reported as
   unpublished** — `crates/qv-store/src/rotation_install.rs`,
   `publish_marker`. `sync_dir` ran inside `publish_marker` after
   `rename_noreplace` had succeeded. A failure there took the
   "before publication" path: `journal_published = false`, the g+1
   inventory was removed, and the `Unpublished` guard deleted the candidate
   that the on-disk journal names. The data stayed safe: the old vault was
   still active, and restart would classify the state as RollbackPending
   and roll back with the old password. But the CLI omitted the "partly
   applied" line, and the next command failed with exit 7. The plan
   (I3: "from its rename on, the transition exists"; "an error from I3 on
   returns `journal_published = true`") states the exact requirement.
   Action: fixed by the reviewer. `publish_marker` stops at the rename, and
   `install` syncs the directory after it hands the candidate to the
   journal, mapping a failure to `journal_published = true`. A directory
   fsync failure cannot be injected without a new hook, so no test was
   added; the existing crash matrix covers both sides of the point.
2. **[low] Three planned hostile restart cases missing** —
   `crates/qv-store/src/rotation_install_tests.rs`. Action: fixed by the
   reviewer with `rotation_resume_refuses_swapped_suffix_foreign_journal_and_stale_old_copy`:
   - a forged suffix with the siblings renamed to match (the journal still
     decodes; MAC refusal);
   - another vault's journal (vault-ID refusal);
   - the same vault one commit earlier at the `-old-` name (head
     refusal).

   Each case is Integrity with byte-identical evidence.
3. **[low] Stale doc comment** — `crates/qv-store/src/rotation.rs`
   (`PreparedRotation`): "Installing it … is roadmap 1.15c". Action: fixed
   (it now points to `PreparedRotation::install`).
4. **[note] Recovery snapshot before the freeze** —
   `crates/qv-core/src/rotation.rs` (`begin_rotation`). 0002 §3.5.1 lists
   "freeze ordinary writes … and take a local recovery snapshot". Core takes
   the snapshot under the session lock, releases it, then takes the open
   state out. A concurrent frontend could commit a write in that gap. The
   write would be in the rotated vault but not in the recovery copy, so
   nothing is lost; the copy is just one write older. The CLI is
   single-threaded. This is the same pattern as the other destructive
   operations. Revisit when a multi-threaded frontend arrives (2.4/2.5).
   No action.
5. **[note] Rolling back CandidateReady/ActiveRetired/AnchorPending needs the
   new password too** (plan *Decisions needed*: every copy that takes part
   is authenticated before any rename or removal). A user who forgets the
   new password straight after an interrupted rotation cannot roll back
   through the tool; ordinary opens stay refused while the marker exists.
   This follows the reviewed 0021/0023 rule and fails safe. It is a
   usability point for the 1.16 offline audit, not decided here.
6. **[note] Committed cleanup opens the `-old-` header before reclassifying.**
   In the `(active, old)` layout, restart opens the old sibling's header
   before the anchor shows Committed. A damaged or locked `-old-` file then
   blocks cleanup (fail closed; manual removal needed). Only a hostile or
   damaged directory reaches this. No action.

No security finding in cryptographic, secret-handling, parsing or storage
code beyond finding 1. Checked:
- secrets stay in protected containers;
- `InterruptedRotation`, `Rotation` and the error types redact Debug or
  carry no data;
- the journal holds no key or path;
- marker reads are bounded before allocation;
- names come only from the vault path and the authenticated suffix;
- every rename is `RENAME_NOREPLACE` with identity checks before and after;
- no file is renamed or removed on unauthenticated evidence, except the
  designed Committed cleanup of the journal-named `-old-` file (regular
  files only);
- MAC comparisons go through the existing constant-time verifiers;
- no `unsafe`, dependency, schema, profile or spec change.

## Fixes applied by reviewer

- `crates/qv-store/src/rotation_install.rs`: the directory fsync of the
  journal moved from `publish_marker` to `install`, after the candidate is
  handed to the journal; its error maps to `journal_published = true`. The
  error path of `publish_marker` is now `inspect_err` (finding 1).
- `crates/qv-store/src/rotation_install_tests.rs`: the `suffix_of` helper
  and the three hostile cases (finding 2). Test-only.
- `crates/qv-store/src/rotation.rs`: the `PreparedRotation` doc comment
  (finding 3).

## Gates

The committed tree `c7b6c1d` passed every gate before the fixes: SPDX, fmt,
Clippy, and `cargo test --locked` with private Xvfb: 645 passed, 0 failed,
2 pre-existing ignored, 35 groups. After the fixes,
`cargo test --locked -p qv-store rotation_` gave 37 passed. Final results on
the reviewed tree are below. Logs are in the session scratchpad `rev23/`.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass with private Xvfb: 646 passed, 0 failed, 2 pre-existing ignored, 35 groups (645 plus the new hostile test); `git diff --check` clean |
| `cargo deny check` / `cargo vet --locked` | n/a (no dependency change) |

The private Xvfb comes from Alpine packages extracted into the scratchpad,
used through `QV_TEST_XVFB`. Network namespace isolation is not available
here and is not counted as a pass.

## Documentation

- [x] CHANGELOG.md (1.15c entry present; review entry added)
- [x] ARCHITECTURE.md §3 rotation paragraph and §7 status (updated to reviewed)
- [x] Spec statuses and Changelogs (no normative change; 0002 stays Accepted until 1.16)
- [x] Plan ticks, execution log, plans/README.md row (now Reviewed)

## Escalations for the owner

None blocking. Notes 4–6 are for the 1.16 offline audit or the first
concurrent frontend.
