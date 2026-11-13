# Plan 0055 — Clipboard on Wayland: GTK in the app, data-control in the CLI

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — owner Wayland check and fresh review pending | 2026-11-13 | 2026-11-13 (owner bug report; design delegated by the owner, standing 2026-11-02) | 0008 §3 (amended), 0009 §1.6 |

## Intent

The owner, on a Wayland session (MangoWC, wlroots-based), reports that copying
in the app puts nothing on the clipboard. Make app copies work on Wayland
compositors with the same ownership, expiry and replacement rules as X11.

## Diagnosis

Linux uses only `qv_platform::clipboard::X11Clipboard`. On Wayland it talks to
XWayland (`DISPLAY=:0`). A throwaway diagnostic using that adapter on the
owner's session held a test string for its full timeout with `Ok(())`: the X
selection was owned. Whether the compositor bridges an X selection to Wayland
clients is compositor policy; this one did not, so Wayland apps saw nothing,
and the app showed "Copied" without an error because the X11 hold succeeded.

## Scope

**In scope:**
- A GTK clipboard adapter in `qv-platform` behind an opt-in `gtk` feature
  that only the desktop app enables. `LinuxPlatform` uses it when GTK is
  initialized in the process and its display is Wayland; X11 sessions, the
  CLI and processes without GTK keep `X11Clipboard`.
- Status reporting: clipboard available on a Wayland session.
- 0008 §3 amendment: what counts as delivery with the GTK backend.

**Out of scope:**
- The CLI on GNOME Wayland: mutter offers no data-control protocol, so the
  CLI keeps X11 there (see Revisions).
- GNOME/KDE-specific clipboard-manager integration beyond the existing
  `x-kde-passwordManagerHint` target.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Sensitive hint, 20 s expiry, clear only if still owned | 0008 §3 | Draft (implemented profile) | Unchanged |
| Replacement before delivery is `ClipboardReplaced` | 0008 §3 | Draft (implemented profile) | GTK delivery rule added |
| Cleanup never clears a successor's selection | 0008 §3 | Draft (implemented profile) | Ownership is tracked on the GTK thread (below) |
| Clipboard integration isolated in qv-platform; framework APIs may implement it | 0009 §1.6 | Accepted | Adapter in qv-platform, feature-gated |

**Spec changes required:** 0008 §3: after the X11 delivery sentence, add:
"With the GTK backend (the desktop app on Wayland), count a text-target request
answered through GTK as delivery; GTK does not report whether the requester
read the data." Changelog line; owner-delegated.

## Decisions needed

None open. Delegated by the owner (standing, 2026-11-02):

1. **Backend: GTK clipboard (chosen)** vs a `data-control` protocol client.
   GTK works on every Wayland compositor (wlroots, GNOME, KDE) because the app
   window holds the input serial, and adds no crate (gtk 0.18.2 is already
   locked through the vendored dioxus-desktop). `data-control` would also
   serve the CLI but needs `wayland-client`, `wayland-protocols(-wlr)`,
   `wayland-backend`, `wayland-scanner` and `quick-xml`, and GNOME does not
   implement it. Rejected for now; revisit for the CLI.
2. **X11 sessions keep `X11Clipboard`** (reviewed; serves from protected
   memory without GTK copies). GTK is used only when the GDK display is
   Wayland.

## Design

**Components touched:** `qv-platform` (`src/linux/gtk_clipboard.rs`, feature
`gtk`; `LinuxPlatform`), `qv-app` manifest only (enables the feature with
`desktop`). No `qv-core` change; the CLI does not enable the feature.

**Interfaces:**

```rust
// crates/qv-platform/src/linux/gtk_clipboard.rs, cfg(feature = "gtk")
pub struct GtkClipboard;          // impl Clipboard
pub(crate) fn wayland_session() -> bool;   // WAYLAND_DISPLAY set
```

With the feature, `LinuxPlatform::clipboard()` returns `&GtkClipboard`, whose
`hold` falls back to `X11Clipboard` when GTK is not initialized
(`gtk::is_initialized()`, an atomic check) or the GDK display is not Wayland.
`status().clipboard` is `true` on a Wayland session, else the X11 probe.

**Control flow of `GtkClipboard::hold`** (on the `qv-app-clipboard` worker
thread; never on the GTK thread):

1. Validate before any backend work, like `X11Clipboard`: at most 256 KiB,
   UTF-8, timeout 1–300 s, not cancelled.
2. Put the value in `Arc<Mutex<Shared>>` (`value: Option<SecretBytes>`,
   `delivered`, `lost`, `releasing`).
3. If GTK is not initialized, use `X11Clipboard`. Otherwise
   `glib::MainContext::default().invoke` a closure on the GTK thread: if the
   default GDK display is not `GdkWaylandDisplay`, answer `UseX11`; otherwise
   `Clipboard::get(SELECTION_CLIPBOARD).set_with_data(targets, provider)` and
   answer `Owned` or `Unavailable`. Targets: `UTF8_STRING`,
   `text/plain;charset=utf-8`, `STRING`, `TEXT`, `text/plain` (info 0) and
   `x-kde-passwordManagerHint` (info 1). The worker waits on a channel with a
   5 s bound. `UseX11` → hand the value to `X11Clipboard.hold` unchanged.
4. The provider closure owns a `Release` guard. GTK frees the closure exactly
   when it gives up ownership (another owner, or our clear); the guard's
   `Drop` sets `lost` unless `releasing` is set. Info 1 answers `secret`;
   info 0 answers the text via `SelectionData::set_text` and sets `delivered`.
5. The worker polls every 100 ms: cancellation, expiry, `lost`, progress
   seconds (never the value). `lost` → `Ok` if `delivered`, else
   `ClipboardReplaced`.
6. Expiry or cancellation: invoke on the GTK thread: `gdk::Display::sync`
   (a Wayland round trip, so a pending `cancelled` event is read), then an
   idle callback (below event priority, so that event is handled first) that
   clears only if `lost` is still false, setting `releasing` first. The
   worker waits for it (5 s bound), then drops the value.

**Secrets and hostile input:** the value stays in `SecretBytes` and is
zeroized when the shared state drops. `set_text` copies it into GTK memory
for each request, and GTK writes it to the requester's pipe: a framework
copy, best-effort per 0008 §4.4, like x11rb's send buffer. Requests carry no
untrusted input we parse beyond GTK's target info number.

**Successor safety (0008 §3):** ownership loss is observed on the GTK thread
before any clear (round trip plus idle). A compositor also rejects a
`set_selection` whose serial is older than the current selection's
(wlroots and mutter both check this), so a clear racing a newer copy from
another app is refused there.

**Errors:** unchanged mapping: `Unavailable` (GTK refused ownership or the
GTK thread did not answer), `ClipboardReplaced`, `Cancelled`, validation
errors. The app shows its existing clipboard error.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| gtk =0.18.2 (qv-platform, Linux, optional feature `gtk`) | GTK clipboard, `gdk`/`glib` reexports | Wayland data-control crates (5 new crates; no GNOME) | Already locked and vetted through dioxus-desktop; no new package in `Cargo.lock` |

## Steps

- [x] 1. 0008 §3 amendment and Changelog.
- [x] 2. `qv-platform` feature `gtk`; `linux/gtk_clipboard.rs` with pure
  helpers (validation, outcome mapping, target info) and unit tests.
- [x] 3. `LinuxPlatform` uses it under the feature; `qv-app` enables it with
  `desktop` (Linux).
- [x] 4. `ARCHITECTURE.md` §3/§6 (qv-app Linux clipboard on Wayland),
  `CHANGELOG.md`, plan index.
- [ ] 5. Gates (done; see log) and the owner check: SPDX, fmt, workspace and qv-app (`validation`, `desktop`)
  Clippy, qv-app unit tests; owner check on the Wayland session (copy in
  the app, paste into a Wayland app; wait 20 s; copy elsewhere during the
  countdown and confirm it is not cleared).

## Test plan

- Unit: validation rejects oversize, non-UTF-8, out-of-range timeout and
  cancellation before any GTK call; outcome mapping (`lost` with and without
  delivery, expiry, cancel); the hint target never yields the value.
- No automated Wayland test: CI and the dev sandbox have no compositor. The
  owner's manual check in step 5 is the evidence; X11 behaviour is unchanged
  and keeps its Xvfb tests.

## Revisions

### 2026-11-13 — The CLI on Wayland

The owner asked for CLI copies to work on Wayland too ("no problem"). The
CLI has no window, so it needs a data-control protocol. Design delegated:

- **No Wayland crates.** `wayland-client` and its protocol crates would add
  about eight packages. The needed subset (registry, `wl_seat` bind, the
  data-control manager, source, device; `wl_display.sync`; received pipe
  descriptors) is small, and the repo already keeps its own bounded X11
  transport, so `qv-platform/src/clipboard/wayland.rs` speaks the wire
  format directly on rustix (already locked, features unchanged).
- **Protocols:** `ext_data_control_manager_v1` (staging), else
  `zwlr_data_control_manager_v1`; both share opcodes. Bound at version 1.
- **Bounds:** 4096-byte messages (the protocol limit; size must be 8–4096
  and a multiple of 4), checked string lengths and NUL terminators, a 4 MiB
  lifetime read budget, at most 8 queued received descriptors, 5 s
  round trips and per-paste writes, `MSG_NOSIGNAL` on the socket.
- **Ownership and cleanup:** `set_selection(source)`; `source.cancelled` is
  the loss signal; cleanup destroys the source, which the compositor turns
  into a cleared selection only while that source is still current, so a
  successor's copy is never cleared (0008 §3).
- **Delivery:** a text-type `send` whose whole value was written to the
  requester's descriptor (0008 §3 amended); the hint answers `secret` and
  never counts; other types get nothing.
- **Selection:** `SessionClipboard` (Linux) tries data-control on a
  Wayland session and falls back to `X11Clipboard` if the compositor lacks
  it or the start fails before ownership (closing the socket releases
  anything partial). The CLI, `LinuxPlatform` without `gtk`, and
  `GtkClipboard` when GTK is not running use it.
- **Specs:** 0011 §3.6 (foreground serving also on Wayland) and 0008 §3
  (data-control delivery rule), with Changelog lines.

## Execution log

- 2026-11-13: Plan written; delegated approval (standing 2026-11-02).
- 2026-11-13: Steps 1–4 done. Differences from the first draft: the adapter
  lives in `qv-platform` (0009 §1.6 isolates clipboard integration there),
  behind an opt-in `gtk` feature that `qv-app` enables with `desktop`
  through a Linux-only direct dependency on `qv-platform`. `Cargo.lock`
  gains only the two edges (`qv-app` → `qv-platform`, `qv-platform` →
  `gtk`); no new package or version, so `cargo deny`/`cargo vet` inputs are
  unchanged and were not rerun. `LinuxPlatform::clipboard` returns
  `GtkClipboard`, which falls back to `X11Clipboard` without GTK in the
  process or on a non-Wayland display. If a workspace build unifies the
  feature into the CLI, the CLI still uses X11 (GTK is never initialized
  there).
- 2026-11-13: Gates on the final tree: `check-spdx.sh`, `check-matrix.sh`,
  `cargo fmt --check`, workspace Clippy, qv-platform Clippy with and without
  `gtk`, qv-app Clippy (`validation`, `desktop`) pass. Tests: qv-platform
  37 passed (and the 5 GTK unit tests with `gtk`), qv-app `validation` lib
  104 passed. Not run: the full workspace test suite (owner asked to keep
  the machine responsive; unaffected crates unchanged), the Windows cross
  Clippy (Linux-only change), and any Wayland automation (none possible
  here). Pending: the owner's step 5 check and a fresh-context review.
- 2026-11-13: CLI revision implemented (`clipboard/wayland.rs`,
  `SessionClipboard`, shared `validate`, qv-core reexport, CLI backend and
  message). Fake-compositor tests over a socket pair cover text and hint
  serving with descriptor passing, delivery versus replacement, ext over
  wlr preference, no data-control global, expiry destroying the source,
  protocol errors and message/string bounds. Gates: `check-spdx.sh`,
  `check-matrix.sh`, `cargo fmt --check`, workspace Clippy, qv-platform
  Clippy with and without `gtk`, qv-app Clippy (`validation`, `desktop`)
  pass. Tests: qv-platform clipboard tests 12 passed; qv-cli
  `tests/clipboard.rs` 3 passed against a private Xvfb (X11 path
  unchanged; the test harness clears `WAYLAND_DISPLAY`). No real compositor
  is reachable from the dev sandbox: the owner's Wayland check covers the
  app and `qv copy`.
- 2026-11-13: `cargo test -p qv-app --features validation` with a private
  Xvfb and `RUST_TEST_THREADS=1`: 104 unit tests and the 3 real-engine
  flows pass, including `real_linux_services_run_the_shared_local_flows`
  (the real `LinuxPlatform` with `gtk`: GTK running on an X11 display takes
  the X11 path).
