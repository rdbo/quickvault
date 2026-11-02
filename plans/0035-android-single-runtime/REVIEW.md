# Review — Plan 0035: Android one Rust runtime per process

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-11-02 | `54e9764..87f1267` (0035 parts of the phase 2.7 commit) |

## Summary

The fix matches the plan. MainActivity handles the recreating configurations
in place. After destroy, Rust runs the existing destroy lock
(`os.update(AndroidState::default())`) and waits 300 ms for the worker and
clipboard threads, then acknowledges. Kotlin then wipes the autofill registry
and ends the process; it ends it anyway after 2 s. Each Android build reuses
one generated project directory and refuses a symlink there. Device evidence
for in-place dark mode and fresh-process reopen is in the plan log. The plan
itself notes that the observed process end may have come from MIUI reclaim.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | `configChanges` widened; `stopped()` on every poll-loop exit (destroy flag and JNI failures); `onDestroy` handler; tests no longer `finish()`. |
| 2 | yes | `dist/android-project` removed and recopied; symlink/non-directory refused. Confirmed again by this review's two builds. |
| 3 | yes | README, CHANGELOG, ARCHITECTURE, 0034 log and VALIDATION. |

Out-of-scope changes: none.

## Findings

None blocking. Notes:
- Plan 0035 made cold handoffs the common case. That exposed a 0034 ordering
  bug, fixed in the 0034 review (finding 1).
- A configuration that is still unhandled, or a system destroy while
  QuickVault is in the background, now ends the process. It also ends a
  waiting autofill handoff activity, because that activity runs in the same
  process. Both fail closed: locked state, cancelled request.

## Fixes applied by reviewer

None in 0035 files.

## Gates

Shared with the 0034 review (same tree); see plans/0034-android-autofill/REVIEW.md.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (Android paragraph)
- [x] Specs: no change
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None.
