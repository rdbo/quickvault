# Maintained third-party source

One owner-approved package remains: the hardened dioxus-desktop 0.7.10
snapshot (plan 0030, owner delegation 2026-11-01). Plan 0032 (owner,
2026-11-02) removed the former x11rb, glib, glib-macros, gtk3-macros and
selectors forks; the product now uses their published crates.io releases, with
justified advisory and licence exceptions in `deny.toml` and QuickVault's own
X11 framing check in `qv-platform/src/clipboard/transport.rs`.

The package is a plain published-source snapshot, not a Git submodule or
history. It is excluded from the product workspace and selected by an explicit
`[patch.crates-io]` entry. Upstream licenses, headers and lints are retained;
product adapter code keeps ordinary AGPL SPDX headers and workspace lints.

## Provenance

| Package | Version | Upstream archive SHA-256 |
|---------|---------|-------------------------|
| dioxus-desktop | 0.7.10 | `236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d` |

Archive: `https://crates.io/api/v1/crates/dioxus-desktop/0.7.10/download`.
`dioxus-desktop/UPSTREAM.sha256` records the hash; `scripts/check-spdx.sh`
validates the exact package name, version and hash before allowing upstream
headers. That is not a source-content check or an audit: compare the retained
source against the hashed archive when reviewing or updating. The manifest sets
`publish = false`. New `hardened.rs` uses QuickVault's AGPL SPDX header; the
aggregate license expression includes that alongside the upstream choices.
Upstream license files are unchanged.

## Exact maintained changes

- PNG-only image dependency.
- Hardened opt-in integration in config/protocol/webview/ipc/app/
  desktop_context/edits and the new `hardened.rs`: only the bundled document
  under a strict CSP, a single initial navigation, bounded and duplicate-key
  rejecting native IPC with a queue limit, a bounded websocket handshake with a
  connection cap, and focused boundary/transport tests. No replacement
  renderer, no input-dialog workaround and no new crypto construction.
- Plan 0031, in edits.rs/webview.rs/hardened.rs: an edit batch that the
  bounded transport drops (full queue/channel, over 8 MiB, lost connection)
  resolves as not applied, and hardened rendering closes the window instead of
  treating it as flushed (a resolved batch is forgotten so a later wake-up is
  not misread as a drop); plus a metadata-only counter of refused native IPC
  messages used by the real-engine boundary harness.

Unmodified upstream unsafe is retained; product code adds none.

- Plan 0044 (owner feedback), in hardened.rs/protocol.rs: the native event
  allow-list also admits `contextmenu` (mouse data like `click`; hover,
  pointer, drag, wheel and media events stay refused); an optional in-memory
  `preview` provider answers `/preview/…` routes (GET only, same document
  base, no query/body, single `bytes=` range → 206 with `Content-Range`,
  `no-store`, `nosniff`, provider-chosen exact MIME; unknown → 404); the CSP
  adds `media-src 'self'` (no `data:`/`blob:`). Tests
  `hardened_events_are_an_allow_list`, `hardened_preview_ranges_and_csp`.

- Plan 0045 (device bug), in edits.rs: the hardened 3 s read/write bounds
  now cover the unauthenticated handshake only and are cleared once the page
  has proven the key. The page acknowledges an edit batch on its next
  animation frame, which Android pauses in the background; the old timeout
  dropped the connection, the late acknowledgement went to the reconnecting
  socket and was lost, and the renderer waited forever. Test
  `hardened_authenticated_connection_waits_for_a_late_acknowledgement`
  (acknowledges after 3.5 s; fails without the change).

- Plan 0033 device follow-up: edits.rs stores protocol connection metadata
  independently of the renderer's RefCell. CSP/bootstrap metadata reads no
  longer borrow the mutable render queue on Android request threads; the same
  Arc/Mutex server location still supplies refreshed ports/keys. Regression
  holds a live render borrow while reading/updating protocol metadata.

## Verification and maintenance

- `sh scripts/test-check-spdx.sh` and `sh scripts/check-spdx.sh`.
- `cargo test --manifest-path third-party/Cargo.toml --locked -p dioxus-desktop --no-default-features --features tokio_runtime --lib hardened`
  (isolated focused-test workspace, separate lockfile).
- Product gates, deny/vet and the app's real-engine tests.

Review local patches as maintained application code and record any baseline
or patch change here. Vet exemptions are not audits. Never update a mutable
git reference or download source during the build. No other package is
exempt from the product rules.
