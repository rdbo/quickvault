# Review — Plan 0052: Windows platform and release (partial)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Partial — not a verdict on the whole plan | 2026-11-14 | `crates/qv-win/src/clipboard.rs` and its callers; `fs.rs` opening helpers spot-checked |

## Summary

Plan 0056 (1.0 preparation) asked for focused reviews of the riskiest
unreviewed code, not a full review of every plan. Of 0052 this covers the
Win32 clipboard FFI, which handles secret-bearing global memory. The rest
of qv-win (`fs.rs`, `security.rs`, `session.rs`, `console.rs`, `dialog.rs`,
`sync.rs`), the store/platform Windows paths and packaging still need a
fresh review; the plan stays `Implemented`.

## Plan conformance

Not assessed for the whole plan.

## Findings

Checked in `clipboard.rs`: one operation per `unsafe` block with a SAFETY
note (Clippy-enforced); balanced `GlobalLock`/`GlobalUnlock`; a block is
freed by us only when `SetClipboardData` did not take it; text is NUL-free
UTF-16 with an even length and a terminating NUL inside the allocation;
the clipboard is closed on every path; clearing requires both the recorded
sequence number and our window as owner, so a successor's content is never
cleared (0008 §3, 0009 §5.1).

1. **[low] Replaced content is not zeroed by us** —
   `crates/qv-win/src/clipboard.rs` (`window_proc`). When another
   application empties the clipboard, our `CF_UNICODETEXT` block is freed
   without our `zero_global`; only our own `clear_if` path zeroes first.
   This is best effort either way: Windows NT keeps the clipboard data in
   its own (win32k) copy made by `SetClipboardData`, which we cannot wipe,
   and the module header already disclaims system copies. Possible
   improvement: keep the published `HGLOBAL` per owner thread and zero it on
   `WM_DESTROYCLIPBOARD`, if a Windows run confirms the handle is still
   valid then. Action: recorded for the remaining 0052 review (plan 0056
   step 3); no code change without a Windows run.
2. **[low] A failed exclusion format leaves the text briefly visible** —
   `clipboard.rs` `set_text`. If `RegisterClipboardFormatW` or a later
   `SetClipboardData` fails after `CF_UNICODETEXT` was set, the clipboard is
   closed (which lets history/monitors see it) before `clear_if` removes it.
   Suggested direction: `EmptyClipboard` before `CloseClipboard` on that
   error path. Rare (format registration failure). Action: recorded with
   finding 1.
3. **[info] Synthesized formats** — the system may synthesize `CF_TEXT`/
   `CF_OEMTEXT` copies on request; documented in the module header as
   outside our control. Action: none.

## Fixes applied by reviewer

None (Windows `unsafe` changes need a Windows run, not Wine alone).

## Gates

See plan 0056's execution log for the 2026-11-14 tree. The Windows CI job
result is plan 0056 step 4.

## Documentation

Not assessed.

## Escalations for the owner

None blocking. Findings 1–2 are small hardening items for the remaining
0052 review, which needs a real Windows run (plan 0056 steps 3–4).
