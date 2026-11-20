# Plan 0070 — Move the app UI to Tauri 2 and Leptos, with nothing listening

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Phase A: Linux done, phone checklist pending (owner); phases B–G carried out by plan 0071 | 2026-11-17 | 2026-11-17 (owner: "Sounds good") | 0009 §6, §1.8; 0008 §1.1, §1.4, §4; 0003 §6.4; 0012 §1, §3 |

## Intent

The owner rejects the client/server shape of Dioxus's desktop and mobile
renderer. Screen updates travel over a loopback websocket that drops and
reconnects when Android pauses the app, which caused the freezes in plans 0045
and 0069 and still costs seconds on return. The app must run fully in
process: **no servers, no listening sockets, no loopback ports**, for screen
updates and for audio/video previews alike. Audio and video previews keep
working; in-process buffering is acceptable (owner, 2026-11-17).

Owner decision, 2026-11-17: replace the Dioxus desktop/mobile renderer with
**Tauri 2** and a **Leptos** frontend (client-side rendering, compiled to
WebAssembly). The web UI built so far (CSS, `player.js`, screen structure) is
kept. egui, Slint and a native UI per platform were considered and rejected
(effort, Android text input, media; see *Revisions*). Dioxus web inside Tauri
was considered and rejected by the owner ("feels unconnected").

## Scope

**In scope (this plan):**
- Phase A: a go/no-go prototype on the owner's Android test phone and the
  Linux desktop, in a workspace outside the product (steps A1–A8).
- The migration outline (phases B–G) with its delivery boundaries,
  the command-boundary design and security rules the later phases must follow.
- Recording the owner decision in 0009 §6 and `ARCHITECTURE.md` §6.

**Out of scope:**
- Implementing phases B–G. Each gets its own plan (0071 onward), written when
  it starts, from this plan's design and phase A's results.
- Any visual redesign: screens keep today's layout and CSS.
- Formats (frozen at 1.0, spec 0015), qv-core behaviour, the CLI, LAN sync.
- iOS/macOS.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Shared UI framework selection | 0009 §6 | Accepted | "A framework replacement requires a new owner decision": given 2026-11-17; recorded in step A0 |
| Webview contract: bundled assets, CSP, navigation, allowlisted typed bounded bridge, reveal expiry, copy from Rust | 0008 §4.1–4.3 | Accepted | Kept; the bridge changes from Dioxus IPC to one Tauri command (design below). Amended in phase B |
| Secret input through standard webview controls | 0008 §1.1, §4.4 | Accepted | Kept; "Dioxus" wording becomes framework-neutral in phase B |
| Lifecycle locking, background expiry | 0008 §1.4, 0009 §1.8 | Accepted | Unchanged behaviour; owned by Rust |
| Preview transport (protected per-range buffers, revocation) | 0003 §6.4, 0008 §4 | Accepted | Loopback listener replaced by an in-process scheme handler; amended in phase E |
| Validation and supply chain | 0012 §1, §3 | Accepted | New dependencies reviewed in phase B before entering the product workspace |

**Spec changes required:** A0 records the owner decision in 0009 §6 (the
shipped UI stays Dioxus until phase G). Behavioural amendments (0008 §4/§4.4
transport and document URLs, 0003 §6.4 media transport, 0009 §1.8 wording)
are the first steps of the phases that change behaviour (B and E).

## Decisions needed

None open. Choices below were delegated (standing owner delegation,
2026-11-02) and are recorded as such:

1. **Prototype location** — a separate Cargo workspace,
   `prototypes/tauri-leptos/`, excluded from the product workspace with its
   own lockfile, like `third-party/`. Delegated: keeps 300+ unreviewed crates
   out of `Cargo.lock`, deny and vet until phase B reviews them. Its code is
   written to become phase B's skeleton, not thrown away.
2. **Separate Android identity for the prototype** — application ID
   `org.quickvault.prototype`, debug key. Delegated: it installs beside the
   real app and cannot touch its data, signer or update path.
3. **Version pins** — the newest stable release at least 14 days old when A1
   starts: currently tauri 2.12.5, tauri-build 2.7.4, tauri-cli 2.12.4,
   leptos 0.8.23, trunk 0.22.1 (wasm-bindgen as Leptos resolves, with
   `wasm-bindgen-cli` at the identical version). Delegated.
4. **Build tool** — Trunk with its tool downloads disabled, using the pinned
   local `wasm-bindgen-cli`. If Trunk cannot run without downloading, use a
   short script around `cargo build --target wasm32-unknown-unknown` and
   `wasm-bindgen` instead. Delegated: no build may fetch tools or source
   (third-party/README.md rule).
5. **Media fallback** — mode A (`<video src>` on the scheme) where it passes;
   otherwise mode B (`player.js` fetching chunks: MP4 through MediaSource,
   other formats as an in-memory blob capped at 256 MiB, as Linux does today).
   Linux uses mode B regardless (WEBKIT.md W1) unless A7's descriptor check
   proves mode A writes nothing to disk. Delegated within the owner's
   "buffer it in the process" allowance.
6. **Release number** — the finished migration ships as 1.2.0; formats are
   unchanged. Delegated.

## Design

### Shape

```
Rust process (Tauri)                               WebView
┌───────────────────────────────┐                  ┌─────────────────────────────┐
│ qv-app: Tauri builder, one    │ ◀── invoke "qv" ─│ qv-ui: Leptos (wasm32),     │
│ command, events, qvmedia      │ ─── reply ──────▶│ existing CSS, player.js     │
│ scheme; controller/workspace/ │ ─── events ─────▶│ ("locked", "notice", …)     │
│ ops/views/lan (unchanged);    │ ◀─ qvmedia range │                             │
│ Android JNI glue (unchanged)  │ ── 206 chunk ───▶│                             │
└───────────────────────────────┘                  └─────────────────────────────┘
       in process: Tauri IPC (custom protocol / Android postMessage), no port
```

Crates after phase B (names final unless phase B finds a conflict):

- `qv-ui-api` — shared request, reply and event types (serde). No I/O, no
  secrets in `Debug`. Compiles for the host and `wasm32-unknown-unknown`.
- `qv-ui` — the Leptos frontend, `wasm32-unknown-unknown` only. Depends on
  `qv-ui-api`, leptos, wasm-bindgen, web-sys; **never** on qv-core, qv-crypto
  or qv-platform.
- `qv-app` — keeps its name, binary and packaging. Becomes the Tauri backend:
  the controller and everything Dioxus-free stays; `src/ui/` and the
  `dioxus`/`dioxus-desktop` dependencies go in phase G.

ARCHITECTURE §3 gains the renderer/backend boundary in phase B: the page is
inside the trusted client (0008 §4.1) but is where untrusted media is parsed,
so the backend checks every request as if a compromised page sent it.

### The bridge: one command

```rust
// qv-ui-api
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "op")]
pub enum Request { Unlock { vault: VaultRef, password: Secret }, Page { view: ViewRef, page: u32 }, Reveal { field: FieldRef }, Copy { field: FieldRef }, /* … */ }

#[derive(Serialize, Deserialize)]
pub enum Reply { Ok, Page(PageView), Revealed { field: FieldRef, value: Secret, expires_ms: u32 }, Error(UiError), /* … */ }

#[derive(Serialize, Deserialize)]
pub enum Event { Locked { generation: u64 }, Notice(Notice), RevealExpired { field: FieldRef }, /* … */ }

/// Opaque per-session reference: 128 random bits, issued by the backend.
pub struct FieldRef([u8; 16]); // likewise VaultRef, ViewRef, EntryRef, GroupRef
```

- **One Tauri command**, `qv`, taking the raw request body
  (`tauri::ipc::Request`, `InvokeBody::Raw`). The backend checks the length
  first (64 KiB cap; unlock and password-bearing requests far below it), then
  decodes with `serde_json` (`deny_unknown_fields`, default recursion limit).
  Oversized, malformed or unknown requests fail closed with a fixed error and
  no echo of the input. Tauri's per-command argument deserialization is not
  used, so the bound is ours, matching the hardened IPC bounds today.
- **Capabilities**: the app's single window gets only the `qv` command and
  the core event listener. No Tauri plugins with fs, shell, http, dialog or
  opener rights; no `tauri-plugin-localhost` ever.
- **References, not handles**: Rust handles (`EntryHandle`, `GroupHandle`,
  …) never leave Rust. The page gets random 128-bit references from a
  per-session table; a lock clears the table, so a stale reference fails
  (0008 §4.1). References carry no vault data.
- **Secrets in requests** (`Secret`): a newtype whose `Deserialize` writes
  straight into `Zeroizing<String>`/`SecretBytes` and whose `Debug` prints
  `Secret(..)`. The raw body buffer is zeroized after decoding. The page
  clears the input on submit, cancel and lock (0008 §4.4).
- **Reveal**: the reply carries the value and its expiry. The page drops it
  after 30 s or on `RevealExpired`/`Locked`, whichever comes first (0008 §4.3).
- **Copy and autofill** take a reference and go Rust → OS; the page never
  sends a value to copy.
- **Locking**: idle, screen lock, background expiry and LAN cancellation stay
  in Rust. The backend emits `Locked { generation }`; the page drops every
  vault-derived signal, clears inputs and shows the lock screen. Replies and
  events from an older generation are discarded (0008 §4.4).
- **Activity**: every `qv` request counts as activity. The page also reports
  pointer/key/scroll activity as `Request::Active`, at most once per second,
  so the idle timer behaves as today.
- **No flicker**: pending reads keep showing the current content (Leptos
  `<Transition>`, the `use_last` rule); there is no revision bump at
  operation start (owner preference).

### Webview hardening (0008 §4.2), Tauri equivalents

- Bundled frontend only (`frontendDist`), no `devUrl` in release; devtools
  off in release builds.
- CSP set in `tauri.conf.json`: `default-src 'self'`; `script-src 'self'
  'wasm-unsafe-eval'`; `style-src 'self'`; `img-src 'self'`; `media-src` and
  `connect-src` limited to `ipc:` and `qvmedia:` (and `blob:` for mode B);
  no `unsafe-inline`, no remote origins. Exact per-platform scheme spellings
  are recorded in A3 (Tauri maps custom schemes to `http://<scheme>.localhost`
  on Windows and Android).
- `on_navigation` admits only the app document; new windows are refused;
  external links go through the existing parsed http/https rule.
- Release builds disable Tauri features not used (minimal feature set listed
  in phase B's dependency review).

### Media: the `qvmedia` scheme

`register_asynchronous_uri_scheme_protocol("qvmedia", …)`. Opening a preview
issues a random 128-bit token bound to the attachment and the session (weak
binding as today, 0003 §6.4). Each request: token, single `Range`, GET or
HEAD. The handler decrypts one ≤64 KiB range off the main thread into a
protected buffer and answers `206` with `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff` and the fixed MIME; malformed or multiple
ranges get `416`; unknown or revoked tokens `404`. Closing the preview, a
navigation or a lock revokes tokens. The `preview.rs` range reads and the
`hardened_media.rs` rules are reused; the socket is not. Copies handed to wry
and the engine are outside our control (0008 §4.4, documented).

### Android

Tauri's Android activity derives from `WryActivity`, as `MainActivity` does
today, so the Kotlin glue (QR camera, quick unlock, autofill, picker,
clipboard, lifecycle, FLAG_SECURE, back) carries over. Fixed for the real app
(phase B): application ID `org.quickvault.app`, the project signing key, the
version-code formula (plan 0069), and the **autofill service component name**,
which the OS stores in the user's settings; renaming it silently turns
autofill off for existing users.

### Secrets and hostile input

Covered above: bounded raw bridge, typed decode, references, `Secret`
newtype, reveal expiry, generation discard, scheme bounds. The renderer holds
whatever a screen shows, as today; wasm and JS copies are best effort.

### Errors

`UiError` is a closed enum of user-facing messages (the controller's current
`Error` texts). No debug strings, paths or values cross the bridge.

### Dependencies

Prototype only (phase A, excluded workspace; no product lockfile change):

| Crate / tool | Why | Alternatives | Review / audit status |
|--------------|-----|--------------|-----------------------|
| tauri 2.12.5, tauri-build 2.7.4 | App shell, IPC, scheme handler, Android host | Keep vendored dioxus-desktop (owner rejected) | Apache-2.0 OR MIT; Tauri has had independent audits (verify reports in phase B); `cargo deny check licenses` against the repo `deny.toml` in A1 |
| leptos 0.8.23 | Frontend | Dioxus web (owner rejected), Sycamore, Yew | MIT; pre-1.0, pinned |
| wasm-bindgen (+ cli, same version), web-sys | wasm glue, MediaSource/DOM | none practical | MIT OR Apache-2.0; wasm-bindgen 0.2.129 already in `Cargo.lock` |
| trunk 0.22.1 (tool) | wasm build and asset hashing | script around wasm-bindgen (fallback, decision 4) | Tool only, not shipped; scratch `CARGO_HOME` |
| tauri-cli 2.12.4 (tool) | Android project generation and build | hand-written Gradle like `build-android.sh` (phase B may switch) | Tool only, scratch `CARGO_HOME` |

Full `cargo deny check` and `cargo vet --locked` happen in phase B, before
any of these enter the product workspace, with the 0012 §3 review and
exemptions recorded. Removing dioxus-desktop in phase G retires its vendored
patch and, if no longer reachable, the gtk-rs advisory exceptions.

## Steps (phase A — prototype, go/no-go)

### Step A0 — Record the owner decision

- [x] **Do:** amend 0009 §6 with a dated paragraph: owner selected Tauri 2 +
  Leptos on 2026-11-17 to replace the Dioxus renderer, no listening sockets;
  Dioxus remains the shipped UI until plan 0070's phase G; the same
  validation criteria apply. Add the 0009 Changelog line, the specs/README
  note, the ARCHITECTURE §6 note, the CHANGELOG Unreleased entry and the
  plans/README row.
- **Files:** `specs/0009-*.md`, `specs/README.md`, `ARCHITECTURE.md`,
  `CHANGELOG.md`, `plans/README.md`.
- **Done when:** the decision is findable from each file; no behaviour text changed.
- **Verify:** `sh scripts/check-spdx.sh`.

### Step A1 — Prototype workspace and dependency check

- [x] **Do:** create `prototypes/tauri-leptos/` (own `Cargo.toml`
  workspace, `Cargo.lock`, `rust-toolchain.toml` symlink or copy pinned to
  1.98.1) with members `app` (Tauri), `ui` (Leptos), `api` (shared types);
  path-depend on `qv-core` for unlock. Add it to the product workspace
  `exclude`. Pins per decision 3. SPDX headers on every source. Install
  `wasm32-unknown-unknown`, `wasm-bindgen-cli`, `trunk`, `tauri-cli` into a
  scratch `CARGO_HOME` with `--locked`.
- **Files:** `prototypes/tauri-leptos/**`, root `Cargo.toml` (`exclude` only).
- **Done when:** both crates build for the host and wasm32; `cargo deny
  --manifest-path prototypes/tauri-leptos/Cargo.toml check licenses` passes
  against the repo `deny.toml`, or every failure is listed in the log.
- **Verify:** `cargo metadata --locked` for the product workspace is
  unchanged; `nice -n 19 ionice -c3 cargo build -j 2 --locked` in the
  prototype; `git diff --stat Cargo.lock` is empty.

### Step A2 — Bridge and lock screen

- [x] **Do:** implement the one-command bridge (raw body, 64 KiB cap,
  `deny_unknown_fields`, `Secret` newtype, references), the `Locked` event
  with generations, and the Leptos lock screen using the existing `app.css`.
  Unlock opens a copied fixture vault through qv-core, then shows one group
  list, one entry with Reveal (30 s expiry) and Copy (Rust → OS), a plain
  text field and a notes textarea for typing and paste.
- **Files:** `prototypes/tauri-leptos/{api,app,ui}/src/**`, `ui/index.html`, `ui/Trunk.toml`.
- **Done when:** unit tests reject an oversized body, unknown fields, an
  unknown op, a stale reference after lock and a reply from an old
  generation; the screens run on Linux.
- **Verify:** `cargo test --locked` in the prototype; manual run under Xvfb
  with a screenshot.

### Step A3 — Hardening checks

- [x] **Do:** set the CSP, navigation guard, no new windows, devtools off in
  release, minimal capabilities. Record the exact document and scheme URLs
  per platform. Confirm with `ss -ltnp`/`/proc/<pid>/net/tcp*` that the
  running app (and its WebKit processes) hold **no listening sockets**.
- **Done when:** a test page script that tries `fetch` to a remote URL,
  `eval`, an inline script and a navigation is blocked; no listener exists.
- **Verify:** prototype tests; `ss -ltnp` output recorded in the log
  (without addresses beyond loopback/none).

### Step A4 — Lifecycle and idle

- [ ] **Do:** the 5-minute idle lock, `Request::Active` throttling, and on
  Android the existing `qvBackgroundMillis`/screen-generation glue copied
  into the prototype's activity, with FLAG_SECURE.
- **Done when:** idle lock fires without page activity, and is deferred by
  activity reports; on Android, leaving and returning keeps the vault, screen
  lock locks.
- **Verify:** prototype tests with a short test limit; phone checklist.

### Step A5 — Android build and JNI

- [ ] **Do:** `tauri android init` into the prototype, application ID
  `org.quickvault.prototype`; call one Kotlin method from Rust (clipboard copy
  through `qvCopy`) to prove the JNI bridge; build a debug arm64 APK.
- **Done when:** the APK installs beside the real app and copies through Kotlin.
- **Verify:** `aapt2 dump badging` shows the prototype ID; install on the
  phone when reachable, otherwise list it as an owner action.

### Step A6 — Media scheme

- [x] **Do:** the `qvmedia` handler serving ranges from the repo's fixture
  MP4s (`crates/qv-app/tests/fixtures/preview-long*.mp4`) and a generated WAV,
  through the token/range/revocation rules. Page tests mode A (`<video src>`)
  and mode B (`player.js` copied unchanged, fetching chunks).
- **Done when:** on Linux both modes play and seek; `416`/`404`/revoked
  cases are tested; closing the preview revokes.
- **Verify:** prototype tests; Linux real-window run.

### Step A7 — Measurements and descriptor check

- [x] **Do:** on Linux, sample `/proc/<pid>/fd` of the app and WebKit
  processes during mode-A playback for `WebKit-Media-*` or other media files
  (as `run-media.py --check-media-files` does). Measure APK size, startup to
  lock screen, and RSS (app + WebKit processes) against the current app.
- **Done when:** results are in the execution log.

### Step A8 — Go/no-go

- [x] **Do:** fill in `VALIDATION.md` (this directory) with automated
  results and the phone checklist; give the owner the APK and the checklist.
- **Done when:** every must-pass row has a result, or is listed as an owner
  phone action.

### Phone checklist (must pass)

1. Unlock by typing with Gboard (including suggestions) in the password field.
2. Paste into the text field and the notes textarea (long press → Paste).
3. The keyboard does not cover the focused field.
4. Leave and return 20 times quickly, including during an unlock: no freeze,
   no reconnect delay, the vault stays open within the inactivity time.
5. Screen lock locks at once; the screenshot block holds (recents thumbnail blank).
6. Copy reaches the clipboard through Kotlin and is cleared as today.
7. Play and seek the MP4 video and the MP4 audio; play the WAV; mode used is recorded.
8. Back button: closes the open panel, leaves at the root.

Nice to have: TalkBack reads the lock screen; startup and memory no worse than 1.1.1.

**Go** when 1–8 pass on the phone and A2–A7 pass on Linux. **No-go** stops
the migration; the owner chooses the next step (stop condition below).

## Later phases (each its own plan, after phase A's go)

| Phase | Delivers | Boundary |
|-------|----------|----------|
| B | Spec amendments (0008 §4/§4.4, 0009 §1.8), dependency review (deny, vet, 0012 §3), `qv-ui-api`/`qv-ui` crates in the product workspace, Tauri backend in `qv-app` beside the Dioxus UI behind a feature, build scripts for Linux, Windows and Android (fixed app ID, signer, version code, autofill component name), CI | Owner commit + fresh review |
| C | The full command set and events over the controller; reference tables; generation discard; tests for every rejection | Owner commit + fresh review |
| D | Screens: shell, vault picker, unlock, browse, search, entry, editor, move, trash, history, conflicts, generator, snapshots, settings, LAN, import, QR, autofill (may split at a screen-group boundary, with the reason stated) | Owner commit + fresh review |
| E | Media: 0003 §6.4 amendment, `qvmedia` handler on real attachments, player modes per platform; WEBKIT.md entries rechecked | Owner commit + fresh review |
| F | Tests: real-window UI tests on Linux, Android instrumentation tests adapted, Windows CI | Owner commit + fresh review |
| G | Switch the shipped app; delete `src/ui/`, Dioxus dependencies and `third-party/dioxus-desktop`; update `third-party/README.md`, `deny.toml`, ARCHITECTURE §3/§6, WEBKIT.md; release 1.2.0 | Owner commit + fresh review |

Until G the shipped app stays Dioxus, so a failed phase never strands users.

## Test plan

- Final verification: all `AGENTS.md` gates on the product tree (phase A
  changes only docs and the workspace `exclude`), plus `cargo test --locked`
  and `cargo clippy --all-targets --locked -- -D warnings` inside the
  prototype workspace.
- Unit tests: bridge bounds, decode rejections, reference expiry on lock,
  generation discard, reveal expiry, activity throttling, scheme token/range
  rules (A2, A4, A6).
- Rejection tests: oversized body, unknown field and op, stale reference,
  revoked/unknown token, malformed and multiple ranges.
- Vectors: none (no formats touched).
- 0012 §1 rows: none changed in phase A; phase B maps the webview-boundary
  rows to the new tests.

## Risks and stop conditions

- **Stop and report** if any phone must-pass row fails and no Tauri-level fix
  exists: the owner decides between staying on Dioxus (with the in-process
  transport) or another framework.
- **Stop** if Tauri cannot take a raw, length-checked command body: an
  unbounded per-command decode does not meet 0008 §4.3.
- **Stop** if anything would need a listening socket (a Tauri plugin, a dev
  server in release, a media helper). No exceptions.
- **Stop** if a required crate's licence is outside `deny.toml`'s allow-list.
- Never install the prototype under the real application ID or signing key.
- Never write device details, addresses or session specifics into repo files.
- Heavy builds: `nice -n 19 ionice -c3`, `-j 2`, one heavy job at a time.

## Documentation

- [x] `CHANGELOG.md` — Unreleased: owner decision and plan 0070 (A0); the prototype (A1–A8)
- [x] `ARCHITECTURE.md` — §6 note on the decision (A0); §3/§6 rewritten in phases B and G
- [x] Specs — 0009 §6 decision paragraph + Changelog (A0); behaviour amendments in B and E; `specs/README.md` note
- [x] `AGENTS.md` — no change in phase A; phase G replaces the Dioxus vendoring rule
- [x] `plans/README.md` — row 0070
- [x] `crates/qv-app/WEBKIT.md` — W13 (media elements cannot load a custom scheme), found in A6; the rest rechecked in E

## Revisions

- 2026-11-17: Alternatives discussed with the owner before this plan:
  an in-process transport inside the vendored dioxus-desktop (rejected:
  "patching a hole with duct tape"); egui (rejected: effort, weak Android
  text input, no media); Slint and native per-platform UIs (not pursued);
  Dioxus web inside Tauri (owner: "feels unconnected"); Sycamore and Yew
  (Leptos chosen: fine-grained updates, the most active Rust option).

## Execution log

- 2026-11-17: Plan written; owner approved the direction ("Sounds good").
  Step A0 done: 0009 §6 paragraph and Changelog line, specs/README note,
  ARCHITECTURE §6 note, CHANGELOG Unreleased entry, plans/README row.
  `sh scripts/check-spdx.sh` passes. Steps A1–A8 not started: they are
  heavy builds and wait for the owner's go on timing.
- 2026-11-17: Owner go ("Yes you can begin"); status In progress. Linux part
  of A1–A3 and A6 done (details in `VALIDATION.md` when A8 writes it):
  workspace `prototypes/tauri-leptos/` (api, app, ui) with its own lockfile,
  seeded from the product `Cargo.lock` so shared crates keep reviewed
  versions; product `Cargo.toml` `exclude` gains `prototypes`; a local
  `.gitignore` for build output. Bridge, references, generations, idle and
  reveal timers, `qvmedia` handler, Leptos lock screen and browse screens
  build and run under Xvfb; 17 prototype tests pass.
- 2026-11-17: A1–A3, A6–A8 done on Linux; A4 and A5 done except their phone
  parts. Results, deviations and phase B findings: `VALIDATION.md`. Summary:
  - A1: `cargo deny check licenses` (repo `deny.toml`) rejects 8 permissive
    crates (MPL-2.0, Zlib from tauri-utils; BSL-1.0 xxhash-rust and CC0-1.0
    base16 from Leptos, not optional). Not a stop: the plan's A1 lists them;
    the stop condition applies when they enter the product (phase B adds
    exact exceptions; BSL-1.0 and CC0-1.0 are new licence kinds).
  - A2/A3: real-window probe shows eval, inline/remote scripts, remote and
    loopback fetch, frames, popups, navigation and ungranted Tauri commands
    refused; no listening socket from the app or its WebKit processes
    (namespace before/after comparison with a positive control; the app is
    non-dumpable, so its own descriptors cannot be listed).
  - A4: idle lock and activity deferral pass in tests and the real window.
    Android lifecycle (screen lock, background expiry) is phone check 4–5.
  - A5: `tauri android init`; prototype `MainActivity.kt` adapted from the
    app's (FLAG_SECURE, lifecycle and clipboard methods, Back as Escape,
    insets); debug arm64 APK built, `aapt2 dump badging` shows
    `org.quickvault.prototype`, min SDK 29, target 35. No phone attached:
    install and the `qvCopy` proof are owner actions (checklist 6).
  - A6: mode B plays and seeks every sample on Linux; mode A fails on
    WebKitGTK for custom schemes (new WEBKIT.md W13). `player.js` copy in
    the prototype fetches in 64 KiB ranges.
  - A7: start to lock screen 0.7–0.8 s, unlock 0.43 s, RSS app 207 MB +
    WebKit 131/248 MB (debug); no media file in WebKit descriptors. Not
    compared side by side with 1.1.1 (a second full build).
  - Deviations (delegated, details in `VALIDATION.md`): externally tagged
    enums and byte-array secrets (serde's internal tagging buffers secrets);
    a script instead of Trunk (Trunk's inline bootstrap breaks the CSP);
    synthetic vault created at first run; `tone.m4a` fixture; direct
    `getrandom` and Android `jni` dependencies (both already locked); AGP
    8.7.0/Gradle 9.1.0/SDK 35 (the template's AGP 9 needs build tools 36,
    which sdkmanager could not fetch here).
  - Disk: the prototype target reached 11 GB (a separate optimized test
    profile doubled every dependency) and briefly filled the disk; the
    prototype now shares the dev build for tests, builds without
    incremental caches, and its host build output was removed after the
    runs (about 0.9 GB left: Android artifacts and the page).
  - Found, not fixed (phase B): Tauri's Android `postMessage` IPC parses its
    JSON envelope before our length check; Tauri hashes bundled scripts into
    the CSP; Tauri owns unwiped request/reply buffers; Android WebView
    settings and chrome client differences.
  - Remaining: the owner's phone checklist (VALIDATION.md); then go/no-go.
- 2026-11-18: Phases B–G were carried out in one plan, 0071 (owner
  continuation request, 2026-11-17), which ships the migration as 1.2.0.
  The phase A phone checklist still applies to the product build.
