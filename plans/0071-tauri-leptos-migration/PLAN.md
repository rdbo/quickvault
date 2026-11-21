# Plan 0071 — Tauri 2 + Leptos migration (plan 0070 phases B–G)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — gates pass; phone check and fresh-context review pending | 2026-11-17 | 2026-11-17 (owner: "Do as many phases as you can, try not to stop. I'll test it out afterwards") | 0008 §1.1, §4; 0003 §6.4; 0009 §1.8, §4, §6; 0012 §1, §3 |

## Intent

Carry out plan 0070's phases B–G: the shipped app moves from the vendored
Dioxus desktop/mobile renderer (screen updates over a loopback websocket) to
Tauri 2 with a Leptos page, fully in process, with the same screens, CSS,
`app.js`, `player.js`, controller and Kotlin glue.

Owner decision, 2026-11-17: continue through the phases without waiting for
the phase A phone checklist or per-phase commits; the owner tests the result.
Plan 0070's rule "each phase its own plan, owner commit + fresh review at each
boundary" is therefore replaced by this one plan with the phases as sections,
one owner commit and one fresh-context review at the end (recorded deviation,
owner continuation request, AGENTS.md "Explicit owner continuation requests
override the named intermediate commit/session boundary").

## Scope

In: spec amendments; dependency review; crates `qv-ui-api` (types) and
`qv-ui` (Leptos, wasm32); the Tauri backend in `qv-app` (bridge, frames,
references, `qvmedia` scheme, window controls); every screen of the Dioxus UI;
Android on Tauri (same application ID, signer, version code, autofill
component); build and packaging scripts; CI; tests adapted; Dioxus and the
vendored dioxus-desktop removed; release notes for 1.2.0 prepared.

Out: visual redesign; formats (frozen, 0015); qv-core behaviour; CLI; iOS and
macOS; tagging or publishing a release (owner).

## Spec basis

| Behaviour | Spec | Status | Change |
|-----------|------|--------|--------|
| Shared UI framework | 0009 §6, client table | Accepted | Tauri 2 + Leptos replaces Dioxus (owner 2026-11-17) |
| Webview contract (document URLs, bridge, navigation, media origins) | 0008 §4 | Draft (owner-approved sections implemented) | Amended in B1 for the Tauri document URLs, one bounded command, in-process media scheme |
| Framework input copies | 0008 §1.1, keyboard row, §4.4 | as above | "Dioxus" wording becomes framework-neutral |
| Preview transport | 0003 §6.4, 0009 §1.8 | Accepted | Loopback listener → in-process scheme, ≤ 64 KiB per response |
| Validation, supply chain | 0012 §1, §3 | Accepted | New dependencies reviewed in B2 |

## Decisions (delegated, owner standing delegation 2026-11-02)

1. **Bridge shape.** The page never sees Rust handles. It renders *frames*:
   serialized view models built in the backend by the same controller reads
   the Dioxus components make, with handles replaced by random 128-bit
   references from a per-session table that a lock clears. Actions are a
   typed `Act` enum carrying references and the controller's form epoch,
   which the controller already checks (stale epochs are ignored).
2. **Frame delivery by long poll, not Tauri events.** The page asks
   `Frame { after }`; the backend answers raw bytes when a newer frame exists
   (or after 20 s with the same one). Tauri events are delivered by `eval` of
   JavaScript source, which would put revealed values into script text; raw
   command replies do not.
3. **Hooks in the backend.** Dioxus `use_page` owners and `use_last` caches
   become backend hook slots keyed by component path; slots not used while
   building a frame are released, like an unmount, and all are cleared on
   lock.
4. **Features.** `qv-app` gains `ui` (shared non-renderer code, enabled by
   both renderers while both exist) and `tauri`. At the switch (G) the
   Dioxus features go and `desktop`/`mobile`/`validation` name the Tauri
   build again, so build commands keep working.
5. **Android.** The Tauri Android project lives in `crates/qv-app/gen/android`
   (Tauri layout), application ID `org.quickvault.app`, `MainActivity`
   extending `TauriActivity`; all Kotlin classes move to the
   `org.quickvault.app` package (owner decision 2026-11-18, replacing the
   original choice to keep the `dev.dioxus.main` component names: users
   select the autofill service again once after updating); the version
   code formula moves to the Tauri build script; AGP 8.7.0 / Gradle 9.1.0 /
   SDK 35 as phase A.
6. **Page build.** `crates/qv-ui/build.sh` (cargo wasm32, wasm-bindgen
   0.2.129, the app's assets) as phase A, output in `crates/qv-app/dist/ui`
   (git-ignored), embedded by Tauri at compile time.
7. **Media.** Mode B (player.js chunks) on Linux, mode A (`src` on the
   scheme) on Android and Windows, as today's split; `player.js` fetches in
   64 KiB ranges everywhere it fetches.
8. **Window chrome.** No OS decorations on desktop (0009 §1.8); drag,
   resize, minimize, maximize, close and full screen are `Act::Window`
   requests run in Rust; the page has no Tauri window permission.

## Design

### Protocol (`qv-ui-api`)

`Envelope { generation, request }` with `generation` the frame epoch the page
last rendered. `Request`: `Frame { after }`, `Act { act }`, `Input { field,
value: Secret }`, `Key { key, ctrl, shift }`, `Activity`, `PageTurn { slot,
serial, forward }`, `Window(WindowOp)`. `Reply`: `Ok`, `Frame(Frame)`,
`Error(UiError)`. 64 KiB body cap, `deny_unknown_fields`, externally tagged
(phase A). Secrets as byte arrays into zeroizing buffers.

`Frame { seq, epoch, theme, platform, body, title }` where `body` is
`Failed`, `Locked(LockedFrame)` or `Unlocked(ShellFrame)`; each screen has a
DTO mirroring what its Dioxus component read (strings, flags, counts,
references), with display decisions computed in Rust where the Dioxus code
did. Page-local state (open menus, sheets, palette, popovers, selection
anchor) stays in Leptos signals as it was in Dioxus signals.

### Backend (`qv-app/src/bridge/`)

- `refs.rs`: handle ↔ reference table per session (entry, group, item,
  field, attachment, history/version keys stay strings as today).
- `frame/` (one module per screen group): build the frame.
- `hooks.rs`: page owners and last-good caches per slot.
- `hub.rs`: latest frame bytes, sequence, condvar for the long poll; a
  render thread runs the Dioxus poll loop (`wait_ui`, `pump`, rebuild on
  change) and after every request.
- `dispatch.rs`: `Act` → controller calls, references resolved, unknown or
  stale references refused.
- `media.rs`: the `qvmedia` scheme over `preview.rs`'s provider.
- window operations in `mod.rs` (`window_op`, desktop only); `webkit.rs`:
  the Linux WebKitGTK hardening (added in F1).

### Page (`qv-ui`)

Leptos components mirroring `src/ui/*` one to one with the same DOM ids,
classes and ARIA, reading memoized slices of the frame signal (PartialEq) so
unchanged parts are not rebuilt; inputs are uncontrolled, and controlled
ones replace their value only when Rust's value differs from what was typed
(the Dioxus `Echo` rule).

## Steps

### Phase B — specs, dependencies, skeleton
- [x] B1 Spec amendments (0008 §1.1/§4, keyboard row; 0003 §6.4; 0009 table,
  §1.8 preview, §4.1/§4.3, §6) with changelogs and `specs/README.md`.
- [x] B2 Dependencies in the product workspace: tauri, tauri-build, leptos,
  wasm-bindgen(-futures), js-sys, web-sys, jni (Android); `cargo deny check`
  with exact licence exceptions; `cargo vet` exemptions; justification in
  `DEPENDENCIES.md`.
- [x] B3 `qv-ui-api`, `qv-ui` crates; `qv-app` features `ui` and `tauri`;
  `cfg(feature = "desktop")` in shared modules becomes `ui`.
- [x] B4 Tauri backend skeleton: builder, command, long poll, hub, refs,
  window ops, CSP, capabilities, navigation guard, `tauri.conf.json`.

### Phase C — commands and events
- [x] C1 `Act`/`Input`/`Key` dispatch for every Dioxus handler.
- [x] C2 Hooks (page slots, last-good caches), lock clearing.
- [x] C3 Rejection tests (body bounds, unknown references, stale epoch,
  references after lock).

### Phase D — screens
- [x] D1 Root, title bar, locked screens (welcome, unlock, create, phrase,
  recover, import, join, recovery, rotation, resume), protection sheet.
- [x] D2 Shell: sidebar, list pane, selection, tabs, toasts, palette,
  confirmations, vault switcher and cards.
- [x] D3 Entry, move, history, version, attachments; editor (start, form,
  generator popover, adder), group editor.
- [x] D4 Pages: generator, sync and LAN panel/receipt, trash, conflicts and
  compare, snapshots, archives, settings panes, autofill.

### Phase E — media
- [x] E1 `qvmedia` handler on `preview.rs` sources; token per preview,
  revoked on close, lock, hide; 64 KiB ranges; Origin rules.
- [x] E2 Viewer component; `player.js` range fetching; WEBKIT.md entries rechecked.

### Phase F — tests and platforms
- [x] F1 Real-window Linux checks adapted (probe, flows); unit tests.
- [x] F2 Android: `android.rs` without Dioxus, Tauri project, build and test
  scripts, version code, signing.
- [x] F3 Windows: clippy for `x86_64-pc-windows-gnu`; CI.

### Phase G — switch
- [x] G1 Features renamed; Dioxus code, dependencies and
  `third-party/dioxus-desktop` removed; `deny.toml`, `third-party/README.md`,
  AGENTS.md vendoring rule, ARCHITECTURE §3/§6, WEBKIT.md, packaging.
- [x] G2 Version 1.2.0 and release notes; all gates.

## Test plan

All AGENTS.md gates on the final tree; `qv-app` clippy with the app features
for Linux, Android and Windows (gnu); `qv-ui` clippy for wasm32; bridge unit
tests (bounds, rejections, references after lock, stale epoch, media ranges
and revocation); real-window Linux checks under Xvfb (unlock, browse, entry,
reveal, copy, edit and save, lock, media); Android APK build. 0012 §1 rows
that named the Dioxus bridge are remapped in F1.

## Risks and stop conditions

- Stop on anything that would need a listening socket.
- Stop if a secret would have to cross the bridge outside `Secret` or a
  frame field shown on screen.
- Disk: build artefacts are large; check `df` between heavy builds.

## Documentation

- [x] Specs (B1), `specs/README.md`
- [x] ARCHITECTURE §3 (renderer/backend boundary, crates) and §6 (G1)
- [x] CHANGELOG Unreleased
- [x] AGENTS.md (vendoring rule; app feature names unchanged)
- [x] `crates/qv-app/README.md`, WEBKIT.md, `third-party/README.md`
- [x] `plans/README.md` row; plan 0070 status

## Execution log

- 2026-11-17: Plan written after reading the whole Dioxus UI (6,500 lines)
  and the controller surface. Owner freed disk space (112 GB free).
- 2026-11-17: B1 done (0008, 0003, 0009 amendments, changelogs, specs
  README). `qv-ui-api` crate written and tested (6 tests). Deviation from
  decision 4: Dioxus and Tauri cannot share one lockfile (wry 0.53 pins
  `webkit2gtk =2.0.1`, wry 0.57 `=2.0.2`, one native library), so there is
  no side-by-side stage: the working tree moves to Tauri now with the final
  feature names (`desktop`, `mobile`, `validation` are the Tauri build;
  `ui` and `fixture` name the shared code). The Dioxus sources stay on disk,
  uncompiled, as the porting reference until G1 deletes them. Nothing is
  committed before the owner commits, so the shipped 1.1.1 is unaffected.
- 2026-11-17/18: C–E. Backend (`bridge/`: frames for every screen, dispatch
  of every Dioxus handler, hooks, references, hub, render loop, `qvmedia`)
  and the Leptos page (`qv-ui`: locked screens, shell, list, entry, move,
  history, version, attachments, viewer, editor, group editor, every page)
  written against the Dioxus sources, same DOM, classes and ids. `player.js`
  reads the scheme in 64 KiB ranges. wasm32 Clippy clean; page 3.1 MB wasm.
- 2026-11-18: F1. Under Xvfb the boundary harness, the full flow (create,
  phrase, generated password, reveal/copy, edit, history restore,
  attachments, archives, LAN window, lock, unlock, recover), the real-Linux
  flow and the media flow (playback, seek, revocation) pass. Fixed on the
  way: the validation scripts use top-level `await`, so they are wrapped in
  an async function. Parity gaps found against the hardened Dioxus webview
  and closed: incognito, devtools off, downloads refused; WebKitGTK
  settings and handlers (`bridge/webkit.rs`: editing-only context menu,
  no permission/file/auth prompts, no web storage, page cache, hyperlink
  auditing, developer extras or element full screen; checked by
  right-clicking under Xvfb); Tauri's default webview data folder in the
  user's home replaced by the app's private state folder, or a private
  temporary one for previews and harnesses (the engine tests failed on a
  read-only home before). Rejection tests added (unknown references, page
  slots, oversized keys, bad names). Observation, not changed: the preview
  controller (Dioxus and Tauri alike) creates empty `anchors`, `imports`,
  `snapshots`, `vaults` folders in the working directory.
- 2026-11-18: F3. Windows clippy (`x86_64-pc-windows-gnu`, desktop, all
  targets) passes with a gcc-preprocessed `llvm-windres` (no mingw here);
  Tauri needs an `.ico` (`assets/icon.ico`, from icon-256.png). WebView2's
  accelerator keys cannot be turned off without `unsafe` COM calls outside
  `qv-win`, so the page swallows browser shortcuts (reload, find, print,
  caret browsing, devtools); WebView2 general autofill is off.
- 2026-11-18: F2. Deviation from decision 5: `MainActivity` stays in
  `dev.dioxus.main` and extends the generated `org.quickvault.app.TauriActivity`,
  so the launcher activity, autofill service and handoff, the tests and
  `test-android.sh` keep their component names. Android project generated
  with tauri-cli 2.12.4 into `gen/android` and kept in the tree with phase
  A's toolchain edits; the old manifest, network config (no cleartext at
  all now), launcher icon, Kotlin and instrumentation tests moved in. Tauri
  hooks: `handleBackNavigation = false` (Back stays the app's Escape),
  webview hardening in `onWebViewCreate`, our chrome client re-set after
  Wry installs its own. `qv-app` gains `crate-type = ["cdylib", "rlib"]`
  and a `mobile_entry_point`; `launch` returns on Android (Tauri's run
  returns after setup there). The QR camera switch is a Gradle property
  (`BuildConfig.QR_CAMERA`). `build-android.sh` builds the page, passes the
  workspace version and version code through `--config`, builds with
  optimized Rust for debug, and keeps every manifest/badging check; the
  debug APK (10101 for 1.1.1, arm64 `libqv_app.so`, allowed permissions
  only) and the test APK build; `package-isolated-android.py` builds the
  isolated pair with byte-identical native code. Not installed: the phone
  is the owner's.
- 2026-11-18: G1. Removed `src/ui/`, `src/runtime.rs`, `Dioxus.toml`, the
  old `harness.js` and `third-party/`; the SPDX checker rejects vendored
  sources (its tests cover the former dioxus-desktop identity). CI and the
  release workflow build the page, lint it for wasm32, run the engine tests
  serially and package Android with tauri-cli; the Debian, Alpine, Linux and
  Windows packaging scripts build the page; `build.rs` refuses a release
  build without it. Supply chain: `DEPENDENCIES.md` (licence exceptions,
  advisories, 204 vet exemptions, Gradle wrapper provenance, Gradle 9.1.0
  checksum pinned); `cargo deny check`, `cargo vet --locked` and
  `check-supply-chain.py` pass. Docs: AGENTS.md and skills (no vendoring),
  ARCHITECTURE §3/§6 and diagram, READMEs, WEBKIT.md, 0009/0012/specs
  README.
- 2026-11-18: G2. Version 1.2.0 (workspace, lockfiles, fuzz manifest),
  CHANGELOG, `docs/release-notes/1.2.0.md`. Final gate results are in the
  release notes.
- 2026-11-18: Owner decision: no Dioxus leftovers, so the F2 deviation is
  reversed. `MainActivity`, the autofill service and handoff, the QR camera
  and quick unlock now live in `org.quickvault.app`
  (`gen/android/app/src/main/java/org/quickvault/app/MainActivity.kt`);
  manifest, instrumentation tests, `build-android.sh` and `test-android.sh`
  follow. The changed autofill component name means Android turns the
  QuickVault autofill service off on the update from 1.1.1; users select it
  again once (CHANGELOG, release notes). Older plans' validation records
  keep the old names as history.
  `build-android.sh` rebuilt both APKs (version code 10200); the final
  manifest names `org.quickvault.app.MainActivity`, `AutofillAuthActivity`
  and `QvAutofillService`. The script now deletes Gradle's previous APK
  outputs first: debug packaging is incremental and left replaced entries
  as dead space (a 68 MB APK holding 41 MB of entries).
- 2026-11-19: First phone run of the Tauri build: the isolated validation
  pair (`package-isolated-android.py --baseline validation`) on the owner's
  Android test phone. `PlatformTest` passes: secure window and hardening,
  create, phrase, lock, unlock, recover, wrong password, items, history,
  attachments, clipboard, archive export and merge, background expiry,
  cancelled worker and phrase skip. Most failures before that were test
  drift, much of it older than 1.2.0, fixed in the instrumentation sources:
  the first-run Welcome screen, the two-step create, the `.err` class, the
  `vaults/` folder rule for validation vaults (2026-11-06), the staging path
  under `validation-current/`, hidden desktop-only twins of phone buttons,
  phone navigation and Lock through the tab bar and vault chip, attachment
  markup and archive picker labels. `flows.js` keeps a short step trace and
  failure messages summarize the page (headings and button labels only, no
  values). The short-background step now asserts that the form keeps its
  session (same node, same epoch): app.js clears typed controls whenever the
  page is hidden, and Tauri's webview reports an instrumentation pause as
  hidden.
  Finding, not fixed: an unlock started about half a second after a lock
  sometimes fails with the generic operation error; a temporary diagnostic
  (removed) showed `Store(Locked)`, the vault's process lock still held by
  the previous session. With a 5 s wait the run passed; the test keeps the
  0.5 s wait so it still catches the race. It touches the store's lock and
  lease lifetime, so it needs its own plan (architect → developer →
  reviewer); it has not been seen on Linux.
  `AutofillTest`: the first-run screen fix is in; the label-spoof check read
  the page as soon as "Fill a login" appeared, before the candidate search
  ended, and now waits for the search to finish before asserting that no
  candidate is offered (the assertion is unchanged). Not yet re-run, nor
  `QrTest`, `MediaTest`, `VaultImportTest` or the fingerprint tests
  (`QuickUnlockTest`, `QuickUnlockUiTest`).
  Device note for future runs: some vendor ROMs refuse an app's own
  background activity starts unless the tester allows it once per install
  (an app-ops setting); the run hangs at `startActivitySync` otherwise, and
  also when the phone is locked.
- 2026-11-21 (owner report, release workflow): the release APK failed in
  `:app:lintVitalAnalyzeUniversalRelease`, a pass only release builds run:
  androidx.lifecycle 2.10.0's `NonNullableMutableLiveDataDetector` throws
  `IncompatibleClassChangeError` (`KaCallableMemberCall`) under AGP 8.7.0's
  lint. Reproduced locally with `QV_APP_RELEASE=1` and a throwaway key.
  Fix: `lint { disable += "NullSafeMutableLiveData" }` in
  `gen/android/app/build.gradle.kts` (no LiveData in the app). The local
  release build then passes; release lint reports no issues. The throwaway
  key and APK were deleted.
