# Plan 0032 — Remove vendored forks except dioxus-desktop

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-11-02 | 2026-11-02 | 0008 §3, §4.4; 0012 §3 |

## Intent

The owner does not want to maintain third-party source. Remove the vendored
glib, glib-macros, gtk3-macros, selectors and x11rb packages and use the
published crates.io releases of the same versions. Keep only the hardened
dioxus-desktop fork (owner, 2026-11-02: "removing everything except
dioxus-desktop, for now", made a priority).

## Context

- Four forks exist only so `cargo deny` reports no advisories without ignores
  (plan 0030): `fxhash` and `proc-macro-error` are unmaintained (no
  vulnerability); glib 0.18's `Variant::array_iter_str` is unsound
  (RUSTSEC-2024-0429) with no 0.18 fix, and the GTK3 webview stack pins glib
  0.18. Neither QuickVault code nor any GTK/WebKit/tao/wry/muda crate in the
  build calls `array_iter_str` (checked 2026-11-02 in the registry sources).
- x11rb 0.13.2 (plan 0015) has two patches: a zeroizing write ring for copied
  plaintext, and a framing guard that refuses reply/GenericEvent lengths over
  1 MiB before the protocol reader allocates.

## Decisions (owner-approved direction, 2026-11-02)

1. Unmaintained/unsound advisories that the removed forks fixed become
   explicit, justified `deny.toml` ignores, revisited when tao/wry leave GTK3.
2. The x11rb framing guard moves into QuickVault's own `BoundedStream`
   (`qv-platform/src/clipboard/transport.rs`), which sees every byte before
   x11rb does: setup reply (8-byte header, length in bytes 6..8), then 32-byte
   packets; type 1 (reply) and GenericEvent (`type & 0x7f == 35`) add
   `u32 length * 4` bytes; a packet over 1 MiB is refused. Same cap as before.
3. The zeroizing write ring is dropped: x11rb's ordinary send buffer briefly
   holds the copied value, documented as a best-effort library intermediate
   (0008 §4.4), like WebKit and JVM copies.

## Steps

### Step 1 — Framing guard in our transport
- [x] **Do:** add the framing state to `BoundedStream::read`, checked before
  bytes are returned to x11rb. Tests: oversized reply and GenericEvent refused;
  fragmented setup + normal packets accepted; oversized setup impossible (u16).
- **Verify:** `cargo test --locked -p qv-platform clipboard`.

### Step 2 — Remove the forks
- [x] **Do:** drop the five `[patch.crates-io]` entries and workspace excludes;
  delete `third-party/{glib,glib-macros,gtk3-macros,selectors,x11rb}`; update
  `third-party/Cargo.toml`, `Cargo.lock` (same versions from crates.io),
  `deny.toml` ignores, `supply-chain/` (vet), `scripts/check-spdx.sh`, CI.
- **Verify:** all gates, `cargo deny check`, `cargo vet --locked`, real
  Xvfb clipboard tests, vendored dioxus-desktop tests, app real-engine tests.

### Step 3 — Documentation
- [x] **Do:** `third-party/README.md`, `AGENTS.md` vendored list,
  `ARCHITECTURE.md` (§3 line and technology table), qv-cli doc comment,
  `CHANGELOG.md`, plans index, roadmap revisions.

## Risks / stop conditions

- Stop if `cargo deny` reports a vulnerability (not unmaintained/unsound
  already analysed) in the restored crates.
- Stop if removing a fork changes resolved versions of unrelated crates beyond
  the forks' own dependency chains.

## Revisions

None.

## Execution log

- 2026-11-02: Planned and approved on the owner's explicit direction. Same
  working tree as the uncommitted phases 2.4/2.5 (owner priority).
- 2026-11-02: Implemented.
  - Step 1: `Framing` state in `BoundedStream::read` checks every byte before
    x11rb sees it (setup reply, then packets; reply/GenericEvent over 1 MiB
    refused). Upstream x11rb's direct large-read path is now used again, but
    only after our check bounded the advertised length. Test
    `clipboard_framing_refuses_oversized_packets_before_x11rb_sees_them`
    (fragmented setup + packets accepted, cap accepted, cap+1 and oversized
    GenericEvent refused, refused through the real stream).
  - Step 2: patches and excludes removed; five directories deleted (260
    tracked files). `cargo update -w` changed only the forks' chains: same
    glib/glib-macros/gtk3-macros/selectors/x11rb versions from crates.io, plus
    fxhash, proc-macro-error(+attr), phf 0.8 family, rand 0.7 family,
    getrandom 0.1, wasi 0.9; proc-macro-error3(+attr3) removed. `cargo deny`
    reported exactly the analysed findings: RUSTSEC-2024-0429 (glib, uncalled),
    RUSTSEC-2024-0370 and RUSTSEC-2025-0057 (unmaintained), RUSTSEC-2026-0097
    (rand 0.7: build-dependency of selectors' phf codegen only, `log` feature
    off; `cargo tree -e normal` shows no runtime edge), and selectors' MPL-2.0
    licence (previously skipped as a private crate). All four ignored with
    reasons; per-version MPL-2.0 exception. Vet: five `audit-as-crates-io =
    false` policies removed, 19 exemptions added as recorded debt, two stale
    exemptions removed. SPDX checker, its fixture test (removed packages now
    rejected even with their former hashes), CI and the isolated
    `third-party/Cargo.toml` workspace updated.
  - Gates on the final tree: SPDX, SPDX fixtures, matrix, fmt, Clippy
    (workspace, qv-app validation, Android arm64 qv-app + qv-platform) pass;
    `cargo test --locked` 741 passed (2 existing ignored), including the
    real-Xvfb clipboard tests; qv-app validation 25 passed; vendored
    dioxus-desktop 5 passed; `cargo deny check` ok; `cargo vet --locked` ok
    (93 fully / 11 partially audited, 421 exempted).
  - Step 3: third-party README, AGENTS.md, skills, `.agents/README.md`,
    ARCHITECTURE (§3 CLI paragraph, technology table), qv-cli docs, CHANGELOG,
    plans index and roadmap revision. Historical plans 0015/0030 left as
    records. Needs a fresh-context review (touches the clipboard transport).
