# Review — Plan 0055: Clipboard on Wayland

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-11-14 | commit `bcf16e7` ("polishing"): `crates/qv-platform/src/clipboard/wayland.rs`, `src/clipboard.rs`, `src/linux/gtk_clipboard.rs`, `src/linux/mod.rs`, the qv-app/qv-cli call sites and manifests |

## Summary

The desktop app on a Wayland display owns the clipboard through GTK; the
CLI (and the app without GTK) speaks the `ext`/`zwlr` data-control protocol
through a small hand-written client on rustix, falling back to X11 when the
compositor lacks it. Ownership, the 20 s clear-if-still-ours rule and
replacement reporting match 0008 §3 as amended. No new crate. Reviewed in a
fresh context for plan 0056; there is still no real-compositor evidence
(the owner's step 5 check).

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 0008 §3 amendment | yes | Plus 0011 §3.6 for the CLI revision |
| 2 GTK adapter | yes | |
| 3 LinuxPlatform wiring | yes | |
| 4 Docs | yes | |
| 5 Gates and owner check | partial | Gates pass; the owner's Wayland check is pending |

Out-of-scope changes: `crates/qv-app/assets/app.css`, `ui/items.rs` and
`workspace.rs` UI polish in the same commit (plan 0054's log covers them).

## Findings

Wire client (`clipboard/wayland.rs`), checked as hostile-ish input:

- Message size must be 8–4096 and a multiple of 4 before any body slice;
  string lengths are checked against the body with checked arithmetic and a
  required NUL; total reads are capped at 4 MiB per hold; at most 8 queued
  descriptors (more is an error; excess `SCM_RIGHTS` beyond the control
  buffer are truncated by the kernel); every wait has a deadline.
- Opcodes match both protocol XMLs (manager: create_source 0,
  get_device 1, destroy 2; source: offer 0, destroy 1, events send 0 /
  cancelled 1; device: set_selection 0, destroy 1, event finished 2).
- Only a whole-value write to a text-type `send` counts as delivery; the
  hint answers `secret`. Cleanup destroys the source, which the compositor
  applies only while it is still the selection (0008 §3 successor rule).

GTK adapter: the provider's `Release` guard marks loss exactly when GTK
frees the closure; clearing happens after a display round trip and an idle
callback, and only while not lost; a late start after the 5 s timeout is
`abandoned` and its value dropped, so a stale owner can serve nothing.

1. **[low] Expiry can overshoot by up to one paste transfer** —
   `wayland.rs` `serve`/`write_all`. A requester that reads slowly holds the
   loop for up to `TRANSFER` (5 s) per request before expiry is rechecked.
   Each request still gets the bounded write, and the next iteration ends
   the hold, so the overshoot is bounded per request. A local client that
   keeps requesting can only extend it by repeated bounded writes while it
   could read the value anyway. Action: none; recorded.
2. **[low] Offers from other clients are never destroyed** — `wayland.rs`
   `handle`. `data_offer` objects created by the compositor for other
   clients' selections are ignored until the connection closes at the end of
   the hold. Harmless server-side residue for ≤ 300 s. Action: none.

No critical, high or medium findings.

## Fixes applied by reviewer

None.

## Gates

Run on the final 2026-11-14 tree (plan 0056 execution log).

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (fake-compositor tests included) |
| `cargo deny check` / `cargo vet --locked` | n/a (no new package; two lockfile edges only) |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 qv-platform)
- [x] Spec Changelogs (0008, 0011)
- [x] Plan log, plans/README.md row

## Escalations for the owner

None. The owner's Wayland check (step 5: copy in the app and with `qv copy`,
wait 20 s, copy elsewhere during the countdown) moves to plan 0056 step 5;
the plan is marked Reviewed for its implementation.
