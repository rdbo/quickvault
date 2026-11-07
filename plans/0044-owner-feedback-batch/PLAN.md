# Plan 0044 — Owner feedback batch: list selection, sync receipt, conflict compare, in-app previews, Android shell

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — fresh review and device check pending | 2026-11-07 | 2026-11-07 (owner request; design owner-delegated, standing 2026-11-02) | 0003 §6.3 (amended); 0008 §1.1, §4.4; 0009 §1.7–1.8 (amended); 0013 §7; 0005 §6.5 |

## Intent

Nine owner notes (2026-11-07) after using the phone and desktop builds:

1. Remove the "Vault file (full path)" field on the locked screen (`dump.png`).
2. Act on items straight from the list: a right-click menu (trash without
   opening the item) and multi-select with batch actions (trash, color,
   move). UI/UX delegated.
3. Android: the app draws under the status bar; reserve the space cleanly.
4. The post-sync modal says "Syncing" after the sync, shows "N conflicts"
   without a way to resolve them, needs "Dismiss" even after a clean sync, and
   looks poor. Redesign it, unbiased by the current design.
5. Preview attachments in the app (images, audio, text, …) without saving
   them. Decrypted content never touches the disk unless the user saves a copy.
   A pleasant, innovative viewer.
6. Android Back closes the app from anywhere. It should go back one level,
   and close the app only from the top level, after a second Back.
7. A white border appears after submitting the password on Android.
8. Conflict resolution shows the same content on several cards, as if they
   were unrelated.
9. The "reduced protection" chip still shows on Android.

## Scope

**In scope:** the nine notes; the specs, core batch operations, vendored
webview route and Android activity code they need; tests and docs.

**Out of scope:**
- Typed-path fallbacks inside the unlocked workspace (attachments, export,
  snapshot restore on a Linux desktop without a file-chooser portal): unchanged.
- Field-by-field merge in conflict resolution (the core resolves by choosing
  one complete version, 0005 §2.5; composing a new version is a later feature).
- Previewing PDF, SVG, HTML, office documents or archives.
- Thumbnails decrypted automatically when an item opens (preview is always an
  explicit action).
- Android autofill and quick-unlock device gates (asked separately).

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Locked screen, vault list, files without typed paths | 0009 §1.8 | Draft (approved profile) | Amended: no typed vault path on the locked screen |
| Protection acknowledgement | 0009 §1.8, 0008 §1.3–1.4 | Draft / Accepted | Fingerprint comparison made robust; behaviour unchanged |
| Item list actions, multi-select | 0009 §1.8 | Draft | Amended (new bullet) |
| Trash, restore, move, color | 0007 §2.1, 0003 §4, §5.5 | Accepted | Batch forms of existing operations, one transaction each |
| Sync result | 0005 §6.5, 0013 §7, 0014 §6 | Accepted / Accepted / Accepted | Same facts (local acceptance, conflicts, peer receipt), presented as a receipt; adds a read-only change summary |
| Conflict resolution | 0005 §2.5 | Accepted | Same "choose one complete version"; comparison view |
| Attachment preview | 0003 §6.3 | Accepted | Amended: explicit, memory-only, sniffed allow-list |
| Webview copies of previewed content | 0008 §1.1, §4.4 | Accepted | Best-effort cleanup limits documented, no new claim |
| Android window, back navigation | 0009 §1.8 | Draft | Amended (Android shell bullet) |

**Spec changes required:** Step 1 amends 0003 §6.3 (preview) and 0009 §1.8
(locked screen path, list actions, sync receipt, previews, Android shell),
with Changelog lines and the specs index. Owner request; wording delegated.

## Decisions needed

None open. Choices made under the owner's standing delegation (2026-11-02),
with rejected options:

1. **Path field (note 1).** Remove the typed vault path from every locked-screen
   mode except validation fixtures. A failed system picker shows an error
   naming the missing portal instead of turning on path fields. Android hides
   the internal folder line under the vault name. Rejected: keeping the field
   when the portal fails (the vault list and default folder already cover
   create/unlock; a raw path is what the owner rejected).
2. **List actions (note 2).** Desktop right-click on a row opens a context
   menu: Open, Copy username, Copy password, Color ▸ (swatches), Move to…,
   Select, Move to trash. Multi-select: Ctrl/⌘-click toggles, Shift-click
   selects a range, a "Select" button in the list header enters selection
   mode on every platform (Android disables long-press natively, so the
   phone uses this button). In selection mode rows show check circles, the
   header becomes a selection bar ("3 selected", Select all, Color, Move,
   Trash, ✕), Escape/Back leaves it. Batch trash shows "Moved N items to the
   trash · Undo". Batch operations are one core transaction each. Groups are
   not selectable (they are chips, and group deletion needs its own recursive
   confirmation). Rejected: per-row checkboxes always visible (noisy);
   swipe-to-delete (destructive gesture, no undo surface on desktop).
3. **Safe area (note 3).** The Android activity pads its content by the
   system-bar, display-cutout and keyboard insets and paints the padding with
   the theme's background; status-bar icons follow the theme (Rust reports the
   theme to the activity). Rejected: CSS `env(safe-area-inset-*)` (unreliable
   in Android WebView, needs page changes per screen); opting out of
   edge-to-edge (removed for targetSdk 35+).
4. **Back (note 6).** The activity's back callback sends Escape to the webview,
   so Back does exactly what Escape does (close a popover/sheet, leave
   selection, cancel a form, answer "no", go up one screen; on the locked
   screen leave Create/Recover/Join). Only when nothing handles it does Rust
   call the activity, which shows "Press back again to close QuickVault" and
   closes on a second Back within 2 seconds. Rejected: a Rust navigation
   stack (duplicates the Escape logic and misses local popovers).
5. **Sync receipt (note 4).** See Design. The modal becomes a *live card*: a
   progress view with a step track while running; when done it turns into a
   non-modal receipt docked at the bottom. A clean result ("Up to date",
   "Received 3 changes") closes itself after 6 seconds with a visible
   countdown ring (a click or focus on it keeps it; the bridge forwards no
   hover events). Conflicts keep it open with
   "Resolve 2 items" leading straight to the comparison. Failures keep it
   open with the error. No "Dismiss": a ✕ closes it early.
6. **Conflict comparison (note 8).** One view per conflicted record: version
   columns (A, B, …) with their time and state, one row per property; equal
   values are shown once and greyed ("Same in both"), differing ones side by
   side and highlighted. Protected values are compared in Rust and shown as
   "Same"/"Different" with per-version reveal. Color, group, type and expiry
   are rows too, so versions that only differ there no longer look identical.
   If nothing visible differs: "These versions have the same content" and one
   button keeps version A. A sticky bar holds "Keep A" / "Keep B".
7. **Preview (note 5).** See Design: the attachment *shelf* on the item page
   (always shown for a live entry, with an Add tile), and a full-window
   *viewer* (images with fit/actual size and panning, audio and video with a
   player card, text in a reader). Content is sniffed from its bytes against
   an allow-list; SVG/HTML/PDF/scripts are never rendered. Bytes are
   decrypted into a protected buffer and served to the webview only from
   memory, from a one-time random route on the app's own origin. Rejected:
   `data:` URIs (the plaintext becomes a DOM string in base64 and needs CSP
   `data:`); temporary files (the owner's rule).
8. **Protection chip (note 9).** On Android the current build's locked screen
   shows no chip after the owner's acknowledgement (checked on the device,
   2026-11-07), so the reported chip is most likely the earlier build or a
   transient status. Make the comparison robust: where lifecycle monitoring
   is mandatory (every platform except Linux), the lifecycle bit is not part
   of the compared fingerprint (the app cannot run without monitoring; losing
   it locks and ends the process). Saved fingerprints with `l0`/`l1` match.
   Ask the owner where the chip still appears.

## Design

**Components touched:** `qv-core` (batch item operations; core trust
boundary, write path), `qv-app` (UI, controller, LAN result, preview
registry), `third-party/dioxus-desktop` (hardened handler: preview route and
CSP, maintained vendored code), `crates/qv-app/android/MainActivity.kt`
(insets, theme, back), `crates/qv-app/assets/app.css`/`app.js`.
No crypto, storage-format, wire-format or protocol change.

**Interfaces:**

```rust
// qv-core/src/edit.rs — one mutate() transaction each; at most
// MAX_BATCH (4096) handles, else CoreError::Limit; an empty slice is Ok(()).
pub const MAX_BATCH: usize = 4096;
impl Session {
    /// Trash live entries (0007 §2.1). Any non-live/foreign handle fails the
    /// whole call (NotAllowed / StaleHandle) before anything is written.
    pub fn delete_entries(&self, entries: &[EntryHandle]) -> Result<(), CoreError>;
    /// Restore trashed entries (the single-item restore, batched).
    pub fn restore_entries(&self, entries: &[EntryHandle]) -> Result<(), CoreError>;
    /// Move live entries into a live group; one new version per entry.
    pub fn move_entries(&self, entries: &[EntryHandle], to: GroupHandle) -> Result<(), CoreError>;
    /// Set (Some) or clear (None) the icon/colour token of live entries
    /// (0003 §5.5); entries already holding it are left unchanged.
    pub fn set_entry_icons(&self, entries: &[EntryHandle], icon: Option<&Text>) -> Result<(), CoreError>;
}

// qv-app/src/workspace.rs
WsAction::TrashMany(Vec<EntryHandle>),
WsAction::RestoreMany(Vec<EntryHandle>),           // the batch Undo
WsAction::MoveMany(Vec<EntryHandle>, GroupHandle),
WsAction::ColourMany(Vec<EntryHandle>, Option<u8>),
WsAction::Preview(AttachmentHandle),               // open the viewer
WsAction::PreviewStep(i8),                         // previous/next attachment
WsAction::ClosePreview,
// ws.undo becomes an enum: Undo::Item(ItemHandle) | Undo::Entries(Vec<EntryHandle>)

// qv-app/src/lan.rs
pub struct Change { pub entry: Option<EntryHandle>, pub title: Z }
pub enum Outcome { UpToDate, Received, Sent, Failed }
pub struct LanDone {
    pub outcome: Outcome,
    pub added: Vec<Change>, pub updated: Vec<Change>, pub trashed: Vec<Change>, // ≤ 50 listed each
    pub added_n: usize, pub updated_n: usize, pub trashed_n: usize,
    pub conflicts: usize,
    pub peer_confirmed: bool,
    pub error: Option<AppError>,
    pub lines: Vec<String>,   // join/new-device texts kept
    pub at: Instant,          // receipt time, for the 6 s auto-close
}

// qv-app/src/views.rs
pub struct CompareView { pub name: Z, pub kind: &'static str,
    pub versions: Vec<CompareHead>, pub rows: Vec<CompareRow>,
    pub identical: bool, pub needs_password: bool }
pub struct CompareHead { pub version: String, pub label: char, pub modified: String, pub state: &'static str }
pub enum Cell { Text(Z), Masked { field: FieldId }, Missing }
pub struct CompareRow { pub label: Z, pub same: bool, pub cells: Vec<Cell> }
pub fn conflict_compare(s: &Session, record: &str) -> Result<CompareView, CoreError>;

// qv-app/src/preview.rs (new, feature "desktop")
pub enum Kind { Image, Audio, Video, Text, Unsupported }
pub fn sniff(bytes: &[u8]) -> (Kind, &'static str /* exact MIME */);
pub struct Preview { token: [u8; 16], mime: &'static str, kind: Kind, bytes: SecretBytes,
                     name: Z, handle: AttachmentHandle }
pub(crate) fn open(...) -> Result<PreviewView, AppError>;   // decrypt + register
pub(crate) fn close();                                       // zeroize + unregister
pub(crate) fn serve(path: &str, range: Option<&str>) -> Option<Served>; // for the webview route

// third-party/dioxus-desktop/src/hardened.rs
pub struct Served { pub mime: &'static str, pub total: u64, pub start: u64, pub body: Vec<u8> }
pub struct HardenedWebview { pub assets: ..., pub preview: Option<Arc<dyn Fn(&str, Option<&str>) -> Option<Served> + Send + Sync>> }
// csp(): adds media-src 'self'.

// Android bridge (Rust → Kotlin), crates/qv-app/src/android.rs
pub(crate) fn set_theme(mode: u8);   // 0 dark, 1 light, 2 system → qvTheme(I)V
pub(crate) fn back_at_root();        // → qvBackAtRoot()V
```

**Data and control flow:**
- *Batch operations:* each core call validates every handle first (own
  session, kind, live/trashed state, target group live), then applies all
  changes inside the same `mutate` closure (`set_deleted` with the full list
  for trash/restore; `save_entry_in` per entry for move/icon), so the store's
  single transaction commits all or nothing (0004 §5). Crash before commit:
  nothing changed; after: everything.
- *Sync receipt:* the LAN worker reads entry summaries (record id →
  modified time, conflict flag, title) before the round and again after a
  `Committed` round, under the same session, outside the protocol. The diff
  yields added/updated/trashed lists (bounded). `Unchanged` → "Up to date".
  The controller's polled snapshot clears a clean receipt 6 s after `at`
  unless the UI reported a hold (`lan_hold(epoch, bool)` from pointer/focus).
- *Preview:* `WsAction::Preview(h)` → read the summary size (≤ 10 MiB,
  0003 §6.3) → allocate `SecretBytes` of that size → `save_attachment` into a
  bounded writer that refuses overflow → accept only on `Ok` (content hash
  verified by the store) → sniff → register `{token, bytes}` as the single
  active preview (replacing and wiping any previous one) → the viewer renders
  `<img|audio|video src="/preview/<hex token>">` or, for text, the decoded
  text in a `pre`. The vendored handler calls the provider for paths under
  `/preview/`; the provider answers only the exact current token, with a copy
  of the requested range, `Cache-Control: no-store` and `nosniff`.
  Closed on ✕/Escape/Back, navigation away from the item, lock, epoch change,
  hiding the window (Android pause) — each wipes the buffer and token.
- *Back:* `OnBackPressedCallback` → `KeyEvent(KEYCODE_ESCAPE)` down/up to the
  webview → existing handlers. The root key handler, on Android, calls
  `back_at_root()` when Escape was not handled (no shortcut, palette closed).
- *Theme:* the root component calls `android::set_theme` when the effective
  theme preference changes (cached; no JNI per render).

**Secrets and hostile input:**
- Batch handles are session-scoped; foreign/stale handles fail closed before
  writes. Counts bounded by `MAX_BATCH`.
- Preview plaintext lives in `SecretBytes` (zeroized on close). Copies the
  framework makes — the response body handed to wry, the webview's decoded
  image/audio frames, the DOM text for text previews — follow 0008 §1.1/§4.4
  best-effort limits and are documented, not claimed erased. No temporary
  files; the webview cache is disabled on Android (`LOAD_NO_CACHE`) and
  responses carry `no-store`.
- The attachment content is untrusted (0003 §6.3), even from an
  authenticated device: the type comes from magic bytes only (MIME metadata is
  ignored for rendering); allow-list: PNG, JPEG, GIF, WebP; MP3, Ogg, WAV,
  FLAC, M4A/AAC (MP4 audio brands); MP4/WebM video; UTF-8 text without NUL in
  its first 8 KiB, at most 2 MiB decoded (larger text shows its first 1 MiB
  with a note). Everything else shows "No preview for this kind of file" with
  Save a copy. CSP keeps `script-src 'self'`; images and media load only from
  `'self'`. Names are shown as text. Residual risk: webview image/media
  decoders parse hostile bytes; recorded in 0003 §6.3's amendment.
- The route token is 128 random bits (`getrandom` via existing `qv_crypto`
  RNG helper), compared in constant time; one live token at a time.
- Text previews are inserted as text nodes (Dioxus escapes), never as HTML.

**Errors:** existing `AppError`s; new `AppError::PreviewUnavailable`
("This file can't be previewed. Save a copy to open it elsewhere.") for a
failed decrypt/verify; batch failures report the first error and change
nothing. The picker failure message names the portal.

**Dependencies:** None new. (RNG and constant-time compare from crates already
used by `qv-app`/`qv-crypto`.)

## Steps

### Step 1 — Spec amendments

- [x] **Do:** 0003 §6.3: in-app preview on explicit action, sniffed
  allow-list, memory only, no disk unless saved, residual decoder risk.
  0009 §1.8: "Files without typed paths" — the locked screen never shows a
  typed vault path (validation fixtures excepted); new bullets *Item list
  actions*, *Sync receipt*, *Attachment previews*, *Android shell* (insets,
  theme-colored system bars, Back = Escape, double-Back exit). Changelogs and
  `specs/README.md`.
- **Files:** `specs/0003-data-model.md`, `specs/0009-clients-and-platforms.md`, `specs/README.md`
- **Done when:** text matches Design; changelog lines dated 2026-11-07.
- **Verify:** `sh scripts/check-spdx.sh`

### Step 2 — Locked screen, focus ring, acknowledgement

- [x] **Do:** `fallback` = fixture only for the four locked-screen path
  inputs; picker failure sets an error naming the portal instead of the
  fallback; hide the folder line on Android; `.qv:focus,.qv:focus-visible
  {outline:none}`; `prefs::fingerprint` gains a `lifecycle_required: bool`
  (true off Linux) that normalizes `l` to `l1` on both sides of the
  comparison (saved values keep working).
- **Files:** `crates/qv-app/src/ui/mod.rs`, `crates/qv-app/src/documents.rs`,
  `crates/qv-app/src/prefs.rs`, `crates/qv-app/src/controller.rs`, `crates/qv-app/assets/app.css`
- **Done when:** tests: fingerprint equality ignores lifecycle when required;
  Linux still distinguishes it.
- **Verify:** `cargo test --locked -p qv-app prefs` and `--features desktop`

### Step 3 — Android shell: insets, theme, Back

- [x] **Do:** `MainActivity.kt`: inset padding listener on the content view
  (systemBars | displayCutout | ime), window background and system-bar icon
  appearance from `qvTheme(mode)`; `OnBackPressedCallback` dispatching Escape;
  `qvBackAtRoot()` with Toast and 2 s double-press `finish()`. Rust:
  `android::set_theme`, `android::back_at_root`; root key handler calls it on
  unhandled Escape (Android only); locked screen Escape returns to Unlock mode.
- **Files:** `crates/qv-app/android/MainActivity.kt`, `crates/qv-app/src/android.rs`, `crates/qv-app/src/ui/mod.rs`
- **Done when:** APK builds; on the phone the title clears the status bar,
  Back from an item returns to the list, Back at the list shows the toast and
  a second Back closes.
- **Verify:** `cargo clippy -p qv-app --features mobile --target aarch64-linux-android -- -D warnings`; `sh crates/qv-app/scripts/build-android.sh`

### Step 4 — Core batch operations

- [x] **Do:** the four `Session` methods and `MAX_BATCH`.
- **Files:** `crates/qv-core/src/edit.rs` (+ its tests module)
- **Done when:** tests: all-or-nothing on a bad handle (trashed entry in a
  delete list; foreign session; deleted target group), one generation step per
  call, empty list is a no-op, over-limit refused, icons unchanged where equal,
  restore after batch delete returns every entry.
- **Verify:** `cargo test --locked -p qv-core batch`

### Step 5 — List context menu and multi-select

- [x] **Do:** `ListPane`: `oncontextmenu` row menu (desktop), selection
  signal (record ids), Ctrl/⌘/Shift handling, "Select" header button,
  selection bar with Select all / Color / Move / Trash / ✕, Escape leaves
  selection. New `WsAction`s with `Undo::Entries`.
- **Files:** `crates/qv-app/src/ui/items.rs`, `crates/qv-app/src/workspace.rs`,
  `crates/qv-app/src/ops.rs`, `crates/qv-app/src/ui/shell.rs` (undo text),
  `crates/qv-app/assets/app.css`, `crates/qv-app/src/workspace_tests.rs`
- **Done when:** tests: TrashMany + Undo restores all; MoveMany; ColourMany;
  stale epoch refused; a UI test renders `ListPane` in selection mode.
- **Verify:** `cargo test --locked -p qv-app --features desktop`

### Step 6 — Sync receipt

- [x] **Do:** `LanDone` restructure, summary diff in the sync paths
  (initiator and served), 6 s auto-close with hold, receipt UI (progress step
  track while running; docked receipt when done; Resolve → Conflicts or the
  single record), join/new-device texts kept.
- **Files:** `crates/qv-app/src/lan.rs`, `crates/qv-app/src/controller.rs`,
  `crates/qv-app/src/ui/pages.rs`, `crates/qv-app/assets/app.css`, `crates/qv-app/src/lan_tests.rs`
- **Done when:** tests: diff classification (added/updated/trashed/bounded),
  Unchanged → UpToDate, conflicts keep it open, clean receipt expires, hold
  defers expiry; existing LAN tests pass.
- **Verify:** `cargo test --locked -p qv-app lan`

### Step 7 — Conflict comparison

- [x] **Do:** `views::conflict_compare`, `ConflictRecord` rewritten as the
  comparison with sticky Keep bar; protected equality via `ct_eq`.
- **Files:** `crates/qv-app/src/views.rs`, `crates/qv-app/src/ui/pages.rs`, `crates/qv-app/assets/app.css`, tests
- **Done when:** tests: equal fields marked same, differing fields side by
  side, colour-only difference shows a row, identical versions flagged,
  protected values never in the view.
- **Verify:** `cargo test --locked -p qv-app --features desktop conflict`

### Step 8 — Vendored preview route

- [x] **Do:** `HardenedWebview::preview`, `/preview/` dispatch in
  `hardened_handler` (GET only, same base, no query/body; single `bytes=a-b`
  range → 206 + `Content-Range`, else 200), `media-src 'self'` in `csp()`;
  focused tests; `third-party/README.md` "Exact maintained changes".
- **Files:** `third-party/dioxus-desktop/src/{hardened.rs,protocol.rs}`, `third-party/README.md`
- **Done when:** tests: unknown token 404, wrong method 403, range math and
  bounds, headers present, CSP string.
- **Verify:** `cargo test --locked --manifest-path third-party/dioxus-desktop/Cargo.toml hardened`

### Step 9 — In-app preview and attachment shelf

- [x] **Do:** `preview.rs` (sniff, bounded secret writer, registry, serve,
  close hooks on lock/epoch/navigation/pause), `WsAction`s, entry-page shelf
  (Add tile, type-colored tiles), full-window viewer (image fit/actual/pan,
  audio/video player card, text reader with wrap toggle, ‹ › and arrow keys,
  "2 of 5", Save a copy…, ✕), styles.
- **Files:** `crates/qv-app/src/preview.rs`, `crates/qv-app/src/lib.rs`,
  `crates/qv-app/src/runtime.rs`, `crates/qv-app/src/workspace.rs`, `crates/qv-app/src/ops.rs`,
  `crates/qv-app/src/ui/items.rs`, `crates/qv-app/assets/app.css`, tests
- **Done when:** tests: sniff allow-list and refusals (SVG, HTML, PDF,
  truncated headers, NUL text), size bound, token mismatch → None, close
  wipes and unregisters, lock closes, a corrupted attachment yields
  `PreviewUnavailable` with nothing registered.
- **Verify:** `cargo test --locked -p qv-app --features desktop preview`

### Step 10 — Docs, gates, device build

- [x] **Do:** docs below; all gates; APK build and owner install.
- **Verify:** see Test plan.

### Step 11 — Linux picker helper process

- [x] **Do:** `qv-app/src/picker.rs` (protocol, `helper()`, `pick()`),
  `runtime::run` calls `helper()` first, `documents::pick_path` uses
  `picker::pick`; opt-in live test `portal_pick_answers_on_a_live_bus` in
  `qv-platform` (skipped unless `QV_TEST_PORTAL_BUS` is set); spec 0009
  §1.8, CHANGELOG, ARCHITECTURE.
- **Files:** `crates/qv-app/src/{picker.rs,lib.rs,runtime.rs,documents.rs}`,
  `crates/qv-platform/src/linux/portal.rs`, docs.
- **Done when:** protocol tests pass; the built binary in helper mode,
  started by a non-dumpable parent, gets answers from the real portal.
- **Verify:** `cargo test --locked -p qv-app --features desktop picker`.

## Test plan

- Final verification: all `AGENTS.md` gates, plus `cargo clippy -p qv-app
  --all-targets --features validation -- -D warnings`, `cargo test -p qv-app
  --features desktop`, vendored `hardened` tests and the Android clippy/APK
  build. Step checks are focused.
- Unit and property tests: batch operations; diff classification; compare
  view; sniffing; registry lifecycle; fingerprint normalization.
- Rejection, malformed-input and crash-path tests: batch all-or-nothing and
  limit; foreign handles; preview overflow, failed verification, unsupported
  types; route refusals.
- Vectors: magic-byte samples for each allowed and refused type.
- 0012 §1 matrix rows addressed: none new (no row covers these UI paths).

## Risks and stop conditions

- Stop if a batch operation cannot stay in one store transaction.
- Stop if the webview route would need to relax `script-src`, add `data:` or
  `blob:` to the CSP, or write the plaintext anywhere outside memory.
- Stop if Android WebView refuses media from the intercepted route; fall back
  to images/text only on that platform and record it, rather than adding a
  temporary file.
- Escape on Android must not exit while an input method or popover is open.

## Documentation

- [ ] `CHANGELOG.md` — Unreleased entries
- [ ] `ARCHITECTURE.md` — §3 qv-app row: in-memory attachment preview route;
  vendored changes line
- [ ] Specs — Step 1
- [ ] `third-party/README.md` — preview route and CSP media-src
- [ ] `crates/qv-app/README.md` — Android Back and insets
- [ ] `AGENTS.md` — no change

## Revisions

- 2026-11-07: Step 11 added (owner report: "no file manager is opening"
  although `gdbus … FileChooser.OpenFile` works). Cause, reproduced with the
  real xdg-desktop-portal 1.22.1 on a private bus and a mock FileChooser
  backend: a caller with `PR_SET_DUMPABLE = 0` (the app, 0008 §1.1) gets
  `AccessDenied: Portal operation not allowed: Unable to open
  /proc/<pid>/root`; a dumpable caller is served. Design (owner-delegated):
  keep the hardening; re-execute `/proc/self/exe --qv-portal-picker` as a
  helper (dumpable after `execve`, no vault data, exits before hardening,
  the instance lock or any vault access). Request over stdin (kind byte,
  title, NUL, suggested name; ≤ 8 KiB), answer over stdout (`P`+path ≤
  `MAX_PICKED`, `C`, `U`), never argv. Rejected: toggling dumpable around
  the call (opens a same-user ptrace window while secrets may be in
  memory); an in-process GTK dialog (changes the 0009 portal rule and adds
  GTK UI code to the product).

## Execution log

- 2026-11-07: Plan written and approved under the standing delegation.
  Device check: the phone's current build shows no protection chip on the
  locked screen after the owner's acknowledgement (`protection=suwuhul1c1p0`
  in the app's preferences).
- 2026-11-07: Step 1: 0003 §6.4 (new) and 0009 §1.8 amended as designed,
  changelogs and index. SPDX check passes.
- 2026-11-07: Step 2: typed vault path only for fixtures (`typed_path`);
  `NoFilePicker` now names the portal; Android hides the vault-place line
  and the create "Saves in" banner; `.qv:focus{,-visible}` outline removed;
  `prefs::acknowledged` normalizes `l0`/`l1` off Linux. Test
  `acknowledgement_ignores_lifecycle_only_where_it_is_required` (includes
  the phone's saved value). `cargo test -p qv-app --features desktop prefs`:
  4 passed.
- 2026-11-07: Step 3: Kotlin inset padding (systemBars | displayCutout |
  ime, `CONSUMED`), `qvTheme`/`applyTheme` (decor and content background
  from app.css `--bg`, bar icon appearance; pre-35 bar colours),
  `OnBackPressedCallback` → Escape to the webview, `qvBackAtRoot` (Toast,
  2 s). Rust `android::sync_theme` (atomic, JNI only on change),
  `android::back_at_root` from the root key handler on unhandled Escape;
  the locked screen's Escape returns Create/Recover/Join to Unlock. Clippy
  (`--features validation`, and Android `mobile` target) clean; the APK
  builds (Kotlin compiles). Device behaviour not yet observed.
- 2026-11-07: Step 4: `delete_entries`, `restore_entries`, `move_entries`,
  `set_entry_icons` (takes `Option<&str>`, since `Text` has neither `Clone`
  nor `PartialEq`; validated before the transaction), `MAX_BATCH`
  re-exported. Each validates all handles, then builds every change and
  calls `commit` once (each `commit` is its own store transaction, so the
  single-item helpers were not looped). Test
  `batch_entry_operations_are_all_or_nothing`: 1 passed.
- 2026-11-07: Step 5: `ListPane` row menu (`oncontextmenu`, anchored to
  the row because the CSP forbids inline positioning styles), selection
  mode (Ctrl/⌘ toggle, Shift range from the last clicked row, header and
  phone "Select" buttons, check tiles), selection bar (select all/clear,
  colour and move popovers, trash), Escape/Back leaves menu → popover →
  selection, Ctrl-A selects all shown. `WsAction::{TrashMany, RestoreMany,
  MoveMany, ColourMany}`, `workspace::Undo` (batch Undo). Automatic colour
  clears only colour tokens (as `pick_colour`). `editor::group_choices`
  made `pub(crate)`. **Deviation (vendored, Step 8 scope pulled forward):**
  the hardened bridge forwarded only click/input/change/key/focus events,
  so `contextmenu` was added to `hardened::event`'s allow-list (mouse data
  like click), with test `hardened_events_are_an_allow_list` (hover,
  pointer, drag, media and wheel stay refused). Test
  `selected_entries_are_trashed_restored_moved_and_coloured_together`.
- 2026-11-07: Step 6: `LanDone` gains `round` (received, conflicts, peer
  confirmation, `Changes`), `at`, `kept`, manual `Debug` without titles;
  `summary`/`changes` diff live entries (id → modified, conflict, title;
  `ItemRow.modified` added) before and after a committed round, lists
  bounded at 50; `finish` clears the stale "Syncing…" info. Auto-close in
  `Controller::snapshot` (6 s, `View.receipt` drives the ring); `lan_keep`
  on click/focus (no hover events cross the bridge, spec wording adjusted).
  Receipt UI docked at the bottom with tone, chips, openable items,
  "and N more", "Resolve now" (opens the only conflict's comparison, else
  the list), close ✕ with countdown ring; running state shows a two-device
  pulse instead of the bar. Tests: extended
  `lan_app_new_device_join_then_sync_with_a_typed_code`, new
  `lan_receipt_lists_changes_and_closes_only_when_clean`. `cargo test -p
  qv-app lan`: 9 passed.
- 2026-11-07: Step 7: `views::conflict_compare` (heads A/B/…, rows for
  title, type, group, colour, expiry, notes and fields by stable field ID;
  protected values revealed in the view function only to compare with
  `ct_eq`, cells stay `Masked`), `CompareView::identical`; `ConflictRecord`
  rewritten (differences grid, "Same in every version" summary, sticky Keep
  bar, per-cell reveal; `cols-N` classes because the CSP forbids inline
  styles). Assertions added to
  `records_history_snapshot_restore_archive_merge_conflict_resolve_verify`
  (title differs, password same and masked, no secret in any cell).
  **Found, not covered:** no separate test for identical or colour-only
  versions (building such a conflict needs the full branch/merge setup);
  the row logic is the same generic per-row equality.
- 2026-11-07: Step 8: `HardenedWebview::preview` provider, `Served`,
  `byte_range`, `/preview/` dispatch with 206/`Content-Range` and
  `Accept-Ranges`, `media-src 'self'`. Test
  `hardened_preview_ranges_and_csp`; vendored hardened tests 8 passed.
  **Not covered:** handler-level 404/403 tests (need a wry responder); the
  provider's own refusals are tested in `preview.rs`.
- 2026-11-07: Step 9: `preview.rs` (allow-list sniffing incl. a strict MP3
  frame header and control-character-free text; documents/archives
  refused; `Bounded` writer; one active preview; constant-time token match;
  `serve` for the provider), `WsAction::{Preview, PreviewStep,
  ClosePreview}`; content is registered when the result is applied, so a
  lock in between drops and wipes it; `clear_transient` and `invalidate`
  close it. `views::attachments` now sorts by name (stable shelf and steps).
  Shelf on the item page (Add tile for editable entries), Preview button on
  the Attachments screen, full-window `Viewer` mounted by the shell (image
  fit/1:1 with scrolling, audio card, video, text reader with wrap, ‹ ›,
  arrow keys, dots, Save a copy via portal or the files screen). Text is
  not selectable (it would bypass the managed clipboard). Tests:
  `preview::tests` (3), `attachments_preview_from_memory_and_close_with_their_screen`.
- 2026-11-07: Step 10: docs (CHANGELOG, ARCHITECTURE §3, app README,
  third-party README). Final tree: `cargo fmt --check`, SPDX,
  `check-matrix.sh` clean; clippy `-D warnings` clean for the workspace,
  `-p qv-app --features validation` and Android `mobile`
  (aarch64-linux-android); `cargo test -p qv-app --features desktop` 83
  passed; vendored hardened 8 passed; `cargo test --locked --no-fail-fast`
  913 passed, 2 ignored, 3 failed: the two Xvfb clipboard tests (Xvfb not
  installed; not a pass) and `qv-cli` `exit_codes_for_vault_states`
  (`Store(Locked)`), which passed 3/3 when its test file was rerun alone.
  **Found, not fixed:** that test's vault-lock contention under the full
  parallel run (unrelated to this plan). APK builds (`QR camera: on`, SHA-256
  `340c74f0…f9dd`, same debug signer); the phone was not connected, so it
  was not installed and no device behaviour (insets, Back, previews, media
  from the intercepted route) has been observed. Visual mock rendering was
  attempted with headless Chromium/Firefox and failed in this environment
  (browser crash); the new screens have not been seen rendered.
- 2026-11-07: Step 11 implemented. Tests
  `picker_requests_round_trip_and_refuse_malformed_input`,
  `picker_responses_carry_only_absolute_local_paths`. End-to-end on a
  private bus with the real xdg-desktop-portal 1.22.1 and a mock GTK-less
  FileChooser backend: a direct non-dumpable call is refused
  (`Unable to open /proc/<pid>/root`); `target/debug/quickvault
  --qv-portal-picker` started from a non-dumpable parent returns the path
  for Open, Save (backend received `current_name`) and Folder (`directory`);
  a malformed request answers `U`. The QuickVault client alone also answered
  three picks against a mock portal (`portal_pick_answers_on_a_live_bus`).
  Not yet observed on the owner's desktop.
- 2026-11-07: Owner follow-ups after trying the build (dump.png, dump2.png,
  dump3.png):
  1. Preview: a click on the dark stage closes it; image, players, text,
     the "no preview" card and the arrows stop the click.
  2. Row menu drawn under later rows and not closing on an outside click.
     Cause: the older `.row>*:not(.open){position:relative;z-index:1}` is
     more specific than `.row-menu`/`.row .pop-scrim`, so the menu was
     in-flow at z-index 1 and the scrim a small relative box. Now
     `.row>.row-menu` (absolute, z 40) and `.row>.pop-scrim` (fixed,
     full window, z 39); a right click on the scrim closes the menu instead
     of bubbling to its row and reopening it.
  3. Selection bar overflowed the list column (trash cut off): "Select all"
     is an icon button (Icon::All), tighter gaps, the count ellipsizes. The
     check icon is always rendered and shown with opacity on `.on`, centred
     by flex (it was off-centre when inserted conditionally).
  4. Escape did not leave the selection: it lived in `ListPane` signals and
     Escape reached the list only with focus inside it (WebKit does not
     focus buttons on click). The selection moved to `Workspace::selection`
     (`Controller::{selection, set_selection}`); the root Escape shortcut
     (and so Android Back) ends it before going back; `clear_transient`
     ends it on navigation. Test `escape_ends_the_list_selection_before_going_back`.
- 2026-11-07: Owner: changing an item's colour re-rendered the whole
  screen; the zoom cursor showed above/below the previewed image. Causes:
  every workspace operation set `busy` at once, which disables navigation
  and rows, hides the FAB and shows the "Working…" toast, then a "Color
  changed." toast followed — a full-window flash for a ~20 ms operation; the
  stage itself had `cursor: zoom-out`. Fix: `View::busy_shown` (unlocked UI
  only) turns on after `BUSY_SHOWN_AFTER` (300 ms, `State::op_started` set
  in `run_op`); `busy` keeps its meaning (tests and the locked screens use
  it); a `Busy` refusal while the busy state is not shown yet is dropped
  quietly in `act`; `ColourMany` sets no notice; the stage cursor is the
  default. Test `quick_operations_do_not_show_as_busy`.
- 2026-11-07: Owner: clicks near the edges of the dark area did not close
  the preview. The handler was on `.v-stage` only; the title strip, dots
  and footer are the same backdrop. The close handler moved to the viewer
  root; the zoom, wrap and save buttons (and, as before, the content and
  arrows) stop propagation. fmt, clippy (validation, Android) clean;
  `cargo test -p qv-app --features desktop` 87 passed.
- 2026-11-07: Owner: a colour change (and closing a preview) still
  re-rendered the whole screen. Cause: `Controller::read` refuses reads while
  an operation owns the vault (so a long one cannot freeze the UI on the
  session lock), and `run_op` bumped the revision at the start, so the shell
  redrew exactly then: the list read as empty, the item page as "Loading…",
  and both rebuilt (fade-in replayed) when the result landed. The 300 ms
  busy delay did not cover this. Fix: `run_op` no longer bumps the revision
  at the start (one redraw when the result lands; slow operations still
  show via `busy_shown`); `ui::use_last` keeps each screen's last successful
  read (shell items, overview, groups, recovered count; the list's group
  listing; the item page's entry and attachments) while reads are refused,
  so screens that redraw during a slow operation keep their content.
  Closing a preview runs no operation; the only full-window change is
  removing the viewer, whose `backdrop-filter` blur layer is now a plain
  near-opaque backdrop (a blur layer's teardown can repaint the page under
  it in WebKit) — not confirmed on the owner's machine. Test
  `screens_keep_their_last_data_while_reads_are_refused` (no edits while a
  read is refused; in-place text update after).
- 2026-11-07: Owner: the title-bar vault name still flickered (shifting the
  command bar). The root component's overview read was not cached. Now
  `use_last` also covers the title-bar name, the sidebar's root group and
  the list's recovered-items count; the only uncached unlocked read left is
  the command palette's search, rendered only while the palette is open.
