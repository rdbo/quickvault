# Plan 0031 — App vault workflows (roadmap 2.5)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-11-01 | 2026-11-01 | 0009 §1, §5; 0008 §1.4, §3, §4; 0007 §1–3; 0010; 0002 §3.4–3.5, §4.2; 0011 §4 (feature parity reference); 0005 §4; 0004 §6 |

## Intent

Make the CLI's offline feature set reachable from the one shared Android/Linux
app. This covers browsing and search, entry view and edit, reveal and copy,
generator, trash, history, conflicts, snapshots, archives, attachments,
settings and credential flows. Layouts must fit touch and desktop, and every
operation must stay safe when a lock races it. The phase also closes the
phase-2.4 review follow-ups (plan 0030 REVIEW findings 1–4).

## Scope

**In scope:**
- Unlocked workspace in `qv-app`: navigation, screens and controller
  operations for every CLI offline command family (table under *Design*).
- Reveal that expires after 30 s, copy from Rust to the OS (Linux X11 adapter,
  new Android adapter), and clipboard expiry or clear-on-lock when still owned.
- Linux file input/output through the CLI's existing no-follow helpers, moved
  into `qv-platform`. Android document import/export through the Storage
  Access Framework (SAF), with no plaintext temporary files.
- Responsive navigation: sidebar on desktop, bottom bar on touch.
- Plan 0030 follow-ups:
  - phrase-screen inactivity policy;
  - over-budget consent for every recovery-snapshot operation;
  - fail-closed edit-batch drops in the hardened desktop patch;
  - engine-level refused-IPC assertions.
- Automated tests, real-WebKit flow harness extension, Android instrumentation
  extension, and manual checklists on both platforms.

**Out of scope:**
- LAN sync (2.8–2.10), quick unlock (2.6), autofill (2.7), remote sync.
- Third-party import/export (needs its own spec, 0011 §4 "later").
- A native Linux file dialog or portal dependency, and Wayland-native clipboard.
- Raising the hardened IPC 64 KiB ingress bound.
- Format, storage, crypto or protocol changes: the app only calls existing
  `qv-core` APIs.
- Release approval or spec status promotion.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Shared client, core-only vault access, local-first | 0009 §1.1–1.2, §1.6 | Draft | D13 go-ahead (2.4) for 0009 §1.6/0008 §4. Owner on 2026-11-01: no further approval checkpoints until the UI is ready for major review. 2.5 continues the same app scope. |
| Desktop single instance, lock behaviour | 0009 §5; 0008 §1.4 | Draft (owner-amended 2026-11-01) | Linux monitoring optional, as in 2.4 |
| Clipboard/screenshot/keyboard/log/temp-file rules | 0008 §3 | Draft, D5 go-ahead | Clipboard 20 s, only if still owned; plaintext export only to an explicit user-selected destination |
| Reveal 30 s, typed checked bridge, Rust→OS copy | 0008 §4.2–4.4 | Draft, D13 go-ahead | Escaped text only |
| History, suppression, purge, trash, snapshots | 0007 §1–3 | Accepted | Mandatory recovery snapshots and budget consent as in the CLI |
| Generator options and suggestion | 0010 | Accepted | |
| Password change, rotation, phrase redisplay after reauth | 0002 §3.4–3.5, §4.2 | Accepted | Core APIs exist |
| Archive export/merge, conflicts | 0005 §4; 0004 §6; 0011 §4 archive contracts | 0005 §4 Draft, D5 go-ahead (2.2); others Accepted | Same core calls as CLI |
| Feature parity reference | 0011 §4 | Accepted | CLI behaviour is the semantic reference, not its I/O syntax |

**Spec changes required:** None. The choices below fit within the existing
requirements: 0008 §1.4 leaves "mobile background expiry" and the inactivity
duration unspecified, and 0008 §3 permits documenting OS clipboard limits.

## Decisions needed

All items were chosen under the owner's 2026-11-01 delegation of phase
choices/tradeoffs ("no further approval checkpoints until the UI is ready for
major review"). Each is recorded with the rejected options. The owner can
override any of them at the post-phase UI review. None amends a spec.

1. **Android copy versus immediate background lock.** Immediate background
   lock clears an owned clipboard before the user can paste in another app.
   Options:
   - (A) keep immediate background lock, except that a clipboard hold started
     in the foreground defers the background-expiry lock until the hold ends
     (≤ 20 s). Screen-off/keyguard and activity destruction still lock at once.
   - (B) a general 30 s background grace period.
   - (C) Android copy unavailable.

   Resolution: A, delegated 2026-11-01. It keeps the owner-validated immediate
   lock for every other case. B weakens the common case; C fails the phase goal.

2. **Android clipboard ownership in the background.** Android 10+ hides
   clipboard data and descriptions from unfocused apps, so ownership may be
   unverifiable at expiry. Options:
   - (A) clear only when ownership is verified (label + timestamp match). When
     unverifiable, leave the clipboard and disclose before each first copy
     that expiry is best effort on this device.
   - (B) clear unconditionally.

   Resolution: A, delegated. B contradicts 0008 §3 "only if still owned".
   Set `ClipDescription.EXTRA_IS_SENSITIVE` on API 33+. Real-device results
   decide which path occurs; record them.

3. **Linux file selection.** Options:
   - (A) bounded absolute-path text input checked in Rust, reusing the CLI's
     no-follow helpers.
   - (B) a native/portal dialog dependency.

   Resolution: A, delegated. No new dependency; matches plan 0030's "bounded
   local path input handled in Rust".

4. **App edit bounds under the 64 KiB IPC ingress limit.** Bounds are 1 KiB per
   single-line input and 8 KiB per multi-line notes/protected value. That stays
   below 64 KiB even with 6× JSON control-character escaping. Existing larger
   values are viewable, revealable and copyable, but are edited through the CLI
   (shown as a fixed hint). Search query: 256 bytes. Resolution: delegated;
   alternative (raise ingress bound) rejected as out-of-scope boundary change.

5. **Phrase-screen inactivity (0030 finding 1).** Options:
   - (A) 5-minute inactivity limit while the creation or redisplay phrase
     screen is shown. OS lock, background expiry and manual lock still apply
     immediately. If it expires before confirmation or skip, the lock status
     says so and points to *Settings → Show recovery phrase* (reauth
     redisplay, 0002 §4.2), which offers the same three-word confirmation.
   - (B) a durable "confirmation pending" vault marker (format change).
   - (C) keep 60 s.

   Resolution: A, delegated. B changes the vault metadata format; C makes
   writing down 24 words impractical.

## Design

**Components touched** (no new crate, dependency or trust boundary):
- `crates/qv-app`: workspace controller, screens, assets, Android glue.
  Trusted client.
- `crates/qv-platform`:
  - `files` module (unix), moved from `qv-cli/src/attachment_files.rs`, with
    `PlatformError` errors;
  - Android clipboard hold logic over an injected backend trait;
  - `AndroidPlatform::with_clipboard`.
- `crates/qv-cli`: uses the moved file helpers; behaviour and exit codes
  unchanged.
- `crates/qv-core`: reexport the file helpers only if the app cannot reach
  them via `qv_core::platform`, matching the existing reexport pattern. No
  behaviour change.
- `third-party/dioxus-desktop` (approved patch areas `edits.rs`,
  `hardened.rs`): fail-closed batch drops and a metadata-only refused-IPC
  counter. Record both in `third-party/README.md`.
- Android packaging: `MainActivity.kt` clipboard and SAF methods,
  instrumentation tests.

**Feature map** (CLI → app; every row is a controller operation plus a screen):

| CLI | App |
|-----|-----|
| `ls`, `info --full` | Vault browser (groups/entries, recovered items), vault overview |
| `info` (header) | Settings → About this vault (`Core::inspect` fields, unverified label) |
| `search` | Search box (non-protected data, 0011) |
| `show`, `totp` | Entry screen: non-protected values, reveal per protected field, TOTP code + seconds |
| `add`, `edit`, `mv`, `mkdir`, `rm` | Entry editor, group create/rename, move picker, delete (recursive confirm) |
| `trash ls/restore/empty` + expired | Trash screen; purge/empty with confirmation + recovery snapshot |
| `copy`, `generate [--copy]` | Copy buttons; Generator screen (all 0010 options, entropy) |
| `attach add/ls/save/rm` | Entry attachments panel |
| `history`, `history show`, `restore`, `history purge` | History screen per entry |
| `conflicts`, `resolve` | Conflicts screen (all record kinds) |
| `snapshot ls/restore/export`, `merge` | Snapshots and Archives screens |
| `passwd`, `recovery show`, `recovery rotate`, `recover` | Settings → Security; post-phrase-unlock "set new password" prompt (skippable) |
| `verify` | Settings → Verify integrity (fixed-label report) |

Semantics follow the CLI implementation of each command, which is the reference
for core call order, conflict refusals, confirmations and snapshot/budget
handling. The relevant files are under `crates/qv-cli/src/cmd/`. The app
reproduces those semantics, not CLI syntax or output.

**Interfaces** (crate-private unless noted):

```rust
// qv-app/src/workspace.rs — unlocked state owned by Controller's State.
pub enum Screen { Browse(GroupHandle), Recovered, Search, Entry(EntryHandle),
    EditEntry, EditGroup, Trash, History(EntryHandle), HistoryVersion,
    Conflicts, ConflictRecord, Attachments(EntryHandle), Generator,
    Snapshots, Archives, Settings(SettingsPane) }
pub enum SettingsPane { General, Password, Phrase, Rotation, Verify, About }
struct Workspace {
    screen: Screen, back: Vec<Screen>,          // back stack ≤ 32
    query: Zeroizing<String>,                   // ≤ 256 bytes
    draft: Option<EntryForm>,                   // see below
    reveal: Option<Reveal>,                     // at most one
    pending: Option<Confirm>,                   // typed confirmation dialog
    report: Option<Report>,                     // fixed-label result
}
struct Reveal { target: RevealTarget, value: SecretBytes, until: Instant } // 30 s
enum RevealTarget { Field(FieldHandle), History(HistoryHandle, FieldId),
    Conflict(ConflictVersionHandle, FieldId), Totp(FieldHandle) }
enum Confirm { Delete{recursive}, Purge, EmptyTrash, HistoryPurge,
    RemoveAttachment, SaveAttachmentPlaintext, OverBudget{needed: u64, op: Retry},
    SelfContainedExport, Resolve, Rotate }
struct EntryForm { title, type_hint, plain: Vec<(name, kind, value)>,
    protected: Vec<(name, kind, replacement: Option<SecretBytes>)>, notes,
    removed: Vec<FieldId>, protect_toggles }   // all text ≤ bounds below
// Controller additions (all take FormEpoch; stale epoch => InvalidInput, no effect)
fn navigate(&self, e: FormEpoch, to: Screen);
fn ws_input(&self, e: FormEpoch, target: WsField, value: &mut String); // bound, protect, zeroize
fn ws_action(&self, e: FormEpoch, action: WsAction, consent: bool) -> Result<(), AppError>;
fn workspace_view(&self, e: FormEpoch) -> Option<WorkspaceView>; // escaped-text data only
fn revealed(&self, e: FormEpoch) -> Option<SecretBytes>; // copy while unexpired
// qv-platform
pub mod files { pub struct Input; pub struct Output; } // moved, PlatformError
pub trait AndroidClipboardBackend: Send + Sync {
    fn set(&self, value: &[u8], sensitive: bool) -> Result<ClipToken, PlatformError>;
    fn owned(&self, token: ClipToken) -> Option<bool>; // None = unverifiable
    fn clear(&self) -> Result<(), PlatformError>;
}
impl AndroidPlatform { pub fn with_clipboard(self, b: Arc<dyn AndroidClipboardBackend>) -> Self; }
```

- `WorkspaceView` holds displayable vault text as `Zeroizing<String>`. It
  derives neither `Debug` nor `Display`. Protected values never appear in it.
  `revealed()` is the only path to the renderer for protected values,
  mirroring 2.4's `phrase()`.
- Core handles stay in Rust; event closures capture them with the epoch. The
  webview can only target listeners that already exist. Rust re-checks epoch,
  screen and allowed action before every core call.

**Data and control flow:**
- Writes are core transactions (existing transaction → anchor → report
  ordering; no second write path). Long operations run on the single existing
  worker permit:
  - save; delete/restore/purge;
  - history restore/purge;
  - resolve; merge/export; snapshot restore;
  - attachment add/save; password change; rotation; verify.
- Busy screens refuse a new action. Lock cancels the worker token, advances
  the epoch and drops the workspace. The controller discards late results;
  the UI reports "an operation was in progress when the vault locked; it may
  have completed" for writes.
- Clipboard hold uses its own single slot, not the worker permit. A new copy
  cancels and replaces the previous hold. Lock cancels the hold, which clears
  the clipboard if still owned. Progress feeds a remaining-seconds counter
  shown in a toast; the value never reaches progress.
- Copy sources:
  - Field: `session.reveal`, refused when `entry_versions > 1`, as in CLI copy.
  - TOTP: `session.totp`.
  - Generator: `services.clipboard().hold`, which needs no session.
- Destructive operations (purge, empty trash, history purge, baseline adopt,
  merge, rotation, snapshot-backed paths) call `begin_destructive(false, …)`.
  `SnapshotOverBudget { needed }` opens `Confirm::OverBudget`. Consent retries
  with `allow_over_budget = true`; refusal aborts with nothing changed. This
  mirrors `qv-cli` `recovery_copy`/trash/merge. `finish_destructive` failure is
  reported as "recovery snapshot cleanup incomplete" and never as failure of
  the committed change.
- Rotation: begin → show new phrase → confirm three words (`confirm_word`) →
  install. On unlock, `rotation_pending(path)` routes to a resume screen
  (`rotation_passwords` → `resume_rotation` → `finish_rotation(choice)`),
  following `qv-cli/src/cmd/credentials.rs`.
- Android documents. Kotlin starts `ACTION_OPEN_DOCUMENT` or
  `ACTION_CREATE_DOCUMENT` on a Rust request and stores the result Uri. Rust
  polls through the existing 100 ms status thread pattern; JNI uses
  `dioxus_desktop::wry::prelude::jni`, so no new dependency. Then:
  - Attachments stream in ≤ 64 KiB `byte[]` chunks over JNI, both ways.
    Plaintext never goes to a temp file. Java `byte[]`/`String` copies are
    documented best-effort intermediates (0008 §4.4).
  - Archives (ciphertext) are copied from the document into a private
    `noBackupFilesDir/quickvault/staging/` file, stopping at the archive bound
    + 1 byte, then `merge_archive(staging)`. Export writes into staging, then
    copies out. Staging files are removed on completion, failure and next
    startup.
  - Snapshot restore on Android targets `vaults/<name>.qvault` in the private
    root (name ≤ 255 bytes, `[A-Za-z0-9 _-]`).
- Linux paths: absolute, ≤ 4096 bytes, passed to the moved `files::Input` or
  `files::Output` (no-follow, owner checks, exclusive 0600 create, never
  overwrite), or to core APIs that take paths.

**Secrets and hostile input:**
- Every input is bounded before conversion (decision 4; paths 4096; names
  1024). The framework `String` is zeroized after conversion, as in 2.4
  `input()`.
- Protected replacements live in `SecretBytes`. Existing protected values are
  never prefilled into inputs: a blank replacement means unchanged.
  "Generate" fills a protected replacement without displaying it.
- Reveal: one value at a time, 30 s, cleared on navigation, lock, and
  visibility hidden (app.js clears `.revealed`).
- Displayed vault text is escaped `rsx!` text only. No `dangerous_inner_html`.
  URLs are shown as text, never links; external links stay out of scope
  (0008 §4.2).
- No vault text, path or value appears in logs, errors, `Debug` or panics.
  `AppError` stays data-free; new variants: `Conflict`, `OverBudget`,
  `ClipboardUnavailable`, `TooLargeForApp`.
- Android JNI receives metadata or chunks only. Uris stay inside Kotlin.
  Rust sees a numeric request id and status.

**Errors:** fixed messages per `AppError` variant; core categories keep 2.4
messages (wrong password, integrity, anchor). Partial plaintext output at a
user-chosen destination is reported as incomplete, never as success (0011
attachment rules).

**Dependencies:** None added. `jni` is reached through wry's prelude
reexport; `rustix` `fs` is already a qv-platform feature. If implementation
proves either assumption false, stop: adding a direct dependency needs a
dated revision under roadmap step 4.

## Steps

### Step 1 — Shared secure file helpers

- [x] **Do:** move `qv-cli/src/attachment_files.rs` `Input`/`Output` into
  `qv-platform::files` (unix), returning `PlatformError`, and map the errors in
  the CLI to the same exit codes. Preserve every check: no-follow traversal,
  owner/permission rules, exclusive 0600 create and identity re-check.
- **Files:** `crates/qv-platform/src/files.rs`, `src/lib.rs`, `Cargo.toml` (only
  if a rustix feature is missing); `crates/qv-cli/src/attachment_files.rs`
  (remove or wrap), `crates/qv-cli/src/cmd/attach.rs`; core reexport if needed.
- **Done when:** CLI attachment tests unchanged and passing. Moved-module unit
  tests cover symlink components, `..`, foreign-writable ancestors, existing
  output and non-regular input.
- **Verify:** `cargo test --locked -p qv-platform files`,
  `cargo test --locked -p qv-cli attach`.

### Step 2 — Workspace controller core: navigation, views, reveal, epoch races

- [x] **Do:** add `workspace.rs` with the `Screen` state, back stack,
  browse/search/entry/recovered/overview views, and reveal (30 s, single) and
  TOTP. Move to the workspace after unlock, confirm or skip. Lock drops it.
  Apply decision 5 (5-minute phrase-screen limit plus the explanatory locked
  status), and route post-phrase-unlock to an optional "set new password"
  prompt. Split `controller.rs` only along these lines; keep the 2.4 public
  behaviour.
- **Files:** `crates/qv-app/src/workspace.rs`, `controller.rs`, `lib.rs`.
- **Done when:** headless tests show the following:
  - stale-epoch navigation, input and action are ignored;
  - reveal expires at 30 s and clears on navigate/lock;
  - search bound is enforced;
  - lock mid-operation drops late results;
  - the phrase screen survives 61 s idle and locks at 5 min with the fixed status.
- **Verify:** `cargo test --locked -p qv-app workspace`.

### Step 3 — Editing: entries, groups, move, delete, trash

- [x] **Do:** `EntryForm` with bounds (decision 4). Cover blank-means-unchanged
  protected replacement, generated replacement, add/remove field,
  protect/unprotect, type hint, and save via `edit_entry`/`new_entry`/`save_entry`.
  Add group create/rename, move picker, delete with recursive confirmation,
  trash restore/purge/empty and expired listing. Over-budget consent applies
  to purge and empty. Conflicted entries follow core/CLI refusals.
- **Files:** `crates/qv-app/src/workspace.rs` (+ `edit.rs` if it grows),
  controller tests.
- **Done when:** tests create, edit and reopen through core, and show:
  - oversize and NUL inputs refused and the form cleared;
  - existing protected value unchanged on blank replacement;
  - purge and empty refuse without confirmation;
  - over-budget path aborts without consent, succeeds with it.
- **Verify:** `cargo test --locked -p qv-app edit`, `… trash`.

### Step 4 — History, conflicts, snapshots, archives, verify, info

- [x] **Do:**
  - history list/show (reveal via `reveal_history`)/restore/purge with
    confirmation and snapshot;
  - conflicts list/inspect/resolve, with a password prompt where core requires it;
  - snapshot list and restore to a new vault;
  - archive export (self-contained warning) and merge, with over-budget consent;
  - verify report and About (`Core::inspect`, labelled unverified).
  Linux paths go through decision 3 and `files`.
- **Files:** `crates/qv-app/src/workspace.rs` (+ `records.rs` if split), tests.
- **Done when:** tests cover:
  - restore as a new causal edit;
  - purge confirmation;
  - resolve after a merged conflicting archive;
  - snapshot restore opening only with the new-baseline rule;
  - merge of an untrusted archive path rejected before core when the
    path/bounds fail;
  - verify report labels only.
- **Verify:** `cargo test --locked -p qv-app records`.

### Step 5 — Attachments and generator

- [x] **Do:** attachments list/add/save/remove with conflict refusals and
  `SaveAttachmentPlaintext` confirmation. Linux uses `files`; Android goes
  through Step 8. Partial output is reported as incomplete. Generator screen
  covers every 0010 option with bounds identical to CLI validation, entropy
  estimate, 30 s display and save-as-vault-defaults.
- **Files:** `crates/qv-app/src/workspace.rs` (+ `attach.rs`), tests.
- **Done when:** tests cover a 10 MiB + 1 refusal, existing-output refusal,
  conflicted-attachment refusal, a save/verify round trip, impossible generator
  settings refused with a fixed error (0012 "Impossible generator"), and
  defaults persisted.
- **Verify:** `cargo test --locked -p qv-app attach`, `… generator`.

### Step 6 — Settings and credentials

- [x] **Do:** general settings (name, description, history depth, trash
  retention, generator defaults) via `edit_settings`/`save_settings`. Password
  change: new password twice, strength/weak-confirmation semantics from 2.4,
  `change_password`. Phrase redisplay after reauth (`recovery_phrase(password)`)
  with optional three-word confirmation. Rotation: begin, confirm, install,
  with resume on unlock. Baseline adoption gains over-budget consent.
- **Files:** `crates/qv-app/src/workspace.rs` (+ `security.rs`), `controller.rs`, tests.
- **Done when:** tests cover:
  - the old password fails and the new one opens after change;
  - wrong reauth password refuses redisplay;
  - rotation completes, and an interrupted rotation is detected and resumed;
  - over-budget baseline consent;
  - lock during a password change drops the late result.
- **Verify:** `cargo test --locked -p qv-app security`.

### Step 7 — Clipboard on Linux and shared copy flow

- [x] **Do:** the clipboard slot. Copy field/TOTP/generated value through
  `session.hold_clipboard` or `services.clipboard().hold`, with a 20 s timeout,
  replace-on-new-copy, lock cancel, and a remaining-seconds toast. If the
  clipboard is unavailable (no X server/XWayland), disable copy with a fixed
  disclosure. Copy refuses conflicted entries.
- **Files:** `crates/qv-app/src/workspace.rs` (+ `clipboard.rs`), tests.
- **Done when:** tests cover:
  - a fake clipboard sees exactly one hold per copy;
  - replacement cancels the old hold;
  - lock cancels the active hold;
  - the value never passes through the progress callback;
  - real X11 clipboard tests under private Xvfb (existing CLI fixture pattern)
    show owned content expiring.
- **Verify:** `cargo test --locked -p qv-app clipboard` (Xvfb via `QV_TEST_XVFB`).

### Step 8 — Android clipboard, background deferral and documents

- [x] **Do:**
  - qv-platform: `AndroidClipboardBackend`, hold logic (set → poll ownership →
    clear if owned at expiry or cancel), `with_clipboard`, and status
    `clipboard: true` only with a backend.
  - Decision 1: while a foreground-started hold is active, `update()` defers
    `BackgroundExpired` until the hold ends; ScreenLocked/ProtectionLost stay
    immediate.
  - Kotlin `qvCopy`/`qvClipOwned`/`qvClipClear` (label + timestamp,
    IS_SENSITIVE API 33+).
  - SAF open/create, chunked read/write, archive staging and cleanup.
  - JNI glue in `qv-app/src/android.rs` with no secret-bearing callbacks
    beyond the chunk payloads documented above.
- **Files:** `crates/qv-platform/src/android.rs`, `crates/qv-app/src/android.rs`,
  `crates/qv-app/android/MainActivity.kt`, `crates/qv-app/android/tests/*`,
  `scripts/test-android.sh` if needed.
- **Done when:**
  - qv-platform unit tests: deferral ends at hold expiry, screen-off during
    hold locks immediately, unverifiable ownership leaves the clip and
    reports it, owned clip cleared on cancel;
  - Android arm64 build passes;
  - instrumentation exercises copy, document import/export and attachment
    round trip on synthetic data.
- **Verify:** `cargo test --locked -p qv-platform android`; Android build and
  instrumentation via `crates/qv-app/scripts/build-android.sh` and
  `test-android.sh`. Device results are recorded in VALIDATION.md; the owner is
  asked to connect the phone only when the APKs are ready.

### Step 9 — Shared screens and responsive layout

- [x] **Do:** `ui.rs` split into components per screen. Navigation is a
  sidebar at ≥ 900 px and a bottom bar with 44 px targets below that. Build
  confirmation dialogs (typed, epoch-checked), toasts, busy states and an
  escaped-text rendering audit. `app.js` clears `.revealed` and `.phrase` on
  visibility hidden and keeps the copy/cut block. CSS stays packaged locally.
- **Files:** `crates/qv-app/src/ui.rs` (+ `ui/` modules), `assets/app.css`,
  `assets/app.js`.
- **Done when:** every feature-map row is reachable on both layouts in the
  preview binary; no inline script or style is needed under CSP; vault strings
  containing `<img onerror>`/`javascript:` render as text.
- **Verify:** `cargo clippy --locked -p qv-app --all-targets --features validation -- -D warnings`;
  preview screenshots at desktop and mobile widths recorded in the log.

### Step 10 — Hardened transport follow-ups (0030 findings 2–3)

- [x] **Do:** in hardened mode, a batch that cannot be queued (full pending
  queue, full channel or > 8 MiB) closes that webview's transport and sends a
  window-close request. The app's `CloseRequested` handler locks first. Add
  `hardened::refused_ipc()` (AtomicUsize, metadata only). The boundary
  harness asserts it increased by exactly the three posted forbidden messages.
  Update `third-party/README.md` patch list.
- **Files:** `third-party/dioxus-desktop/src/edits.rs`, `src/hardened.rs`,
  `third-party/README.md`, `crates/qv-app/src/bin/harness.js`,
  `boundary_harness.rs`.
- **Done when:** vendor unit test shows a dropped batch closes the connection
  rather than resolving as flushed; the engine test fails if forbidden IPC is
  accepted.
- **Verify:** `cargo test --manifest-path third-party/Cargo.toml --locked -p dioxus-desktop --no-default-features --features tokio_runtime --lib hardened`;
  `cargo test --locked -p qv-app --features validation --test engine`.

### Step 11 — Real-engine flows and manual checklists

- [x] **Do:** extend `flow.js`/flow harness for:
  - create → add entry with a generated password → reveal → expiry → copy;
  - edit, delete, trash restore, history restore;
  - archive export + merge, attachment add/save;
  - lock during save.
  Extend Android instrumentation equivalently. Run the manual checklist on
  Linux (Xvfb/real desktop) and the phone, keeping owner observations separate.
- **Files:** `crates/qv-app/src/bin/flow.js`, `src/runtime.rs` fixture,
  `tests/engine.rs`, `android/tests/*`, `plans/0031-app-vault-workflows/VALIDATION.md`.
- **Done when:** engine flows pass; device results list actual device, OS and
  WebView; failures are recorded, never shown as passes.
- **Verify:** `cargo test --locked -p qv-app --features validation`; Android runner.

### Step 12 — Documentation and final gates

- [x] **Do:** ARCHITECTURE §3 (qv-platform files/Android clipboard, app
  workspace), CHANGELOG, `.agents/README.md` app navigation, qv-app README
  limits (bounds, Android clipboard, Linux X11 clipboard/Wayland, SAF copies),
  VALIDATION.md, roadmap tick and execution log.
- **Done when:** all gates in the test plan pass on the final tree.
- **Verify:** test plan below.

## Test plan

- Final gates:
  - `sh scripts/check-spdx.sh`, `sh scripts/test-check-spdx.sh`,
    `sh scripts/check-matrix.sh`;
  - `cargo fmt --check`;
  - `cargo clippy --all-targets --locked -- -D warnings`, plus the qv-app
    validation Clippy;
  - `cargo test --locked`, `cargo test --locked -p qv-app --features validation`
    (Xvfb);
  - vendor focused tests (`third-party/README.md`), Android arm64 build;
  - `cargo deny check` and `cargo vet --locked` (expected unchanged; run
    because Cargo.lock may move with the file-module refactor).
- Unit tests: every controller operation, its refusal paths and epoch
  staleness; the Android hold/deferral state machine; the moved file helpers.
- Rejection / crash paths:
  - oversize, NUL and invalid paths; conflicted entries and attachments;
  - unconfirmed destructive actions; over-budget refusal;
  - lock during every long operation class;
  - partial attachment output reported incomplete;
  - staging cleanup after a failed merge.
- 0012 §1 rows (tag tests):
  - Webview exposure;
  - Ambiguous trust boundary;
  - Snapshot disk growth (over-budget consent);
  - Impossible generator;
  - Deleted-entry resurrection (trash restore via app reopens through core);
  - Rotation/purge ambiguity (app rotation/purge flows).

  Do not claim release coverage from tags.

## Risks and stop conditions

- Stop if `jni` cannot be reached through wry's prelude or rustix needs a new
  feature set outside qv-platform's current graph. Either is a dependency change
  under roadmap step 4.
- Stop if any feature needs `unsafe` (e.g. fd passing). The plan uses
  JNI byte chunks to avoid it.
- Stop if an operation needs a core behaviour change beyond reexports, or a
  format/storage change.
- Android ownership verification behaving differently from decision 2 on
  device is recorded, not worked around with unconditional clearing.
- Missing physical hardware leaves Step 8/11 evidence incomplete. Keep the
  phase In progress; no suffix.
- Any 0008 requirement that cannot be met by the selected integration: stop
  before handling real secrets.

## Documentation

- [x] CHANGELOG.md — workflows, limits, follow-ups closed
- [x] ARCHITECTURE.md — §3 qv-platform files/Android clipboard; app workspace
- [x] Specs — no change
- [x] third-party/README.md — dioxus-desktop patch additions
- [x] .agents/README.md — app screen/module navigation
- [x] crates/qv-app/README.md — limits and platform notes
- [ ] plans/README.md row; roadmap 2.5 tick + execution log

## Revisions

- 2026-11-02 (device evidence, owner delegation 2026-11-01): decision 1's
  rule extended to the system document picker, which always backgrounds the
  activity, so every pick locked the vault and lost the pick. A pick started in
  the foreground defers only background expiry, through the new
  `AndroidPlatform::defer_background()` guard that the clipboard hold also
  uses, until the poller sees the activity back with an outcome or the pick
  forgotten. Screen lock, protection loss and the 60 s inactivity lock still
  apply. Picks are screen-scoped (forgotten on navigation, lock and after a
  write). Rejected: locking and keeping the pick across unlock (the form is
  lost and a stale grant crosses sessions). Also outside the listed files:
  `qv-store/src/incoming_path.rs` walks ancestors with `O_PATH` (search
  permission only) because Android's `/data` is `--x` for apps; `O_DIRECTORY |
  O_NOFOLLOW` still refuses symlinks at every component. Both for the 0031
  fresh-context review; the owner may veto the picker choice at the UI review.

## Execution log

- 2026-11-01: Planned after the 0030 fresh-context review (Approved with minor
  fixes). Decisions 1–5 chosen under the owner's 2026-11-01 delegation. No
  spec amendment, dependency, unsafe or phase-scope change. Touching
  qv-platform/qv-cli/vendor patch is required by the phase's Rust→OS copy and
  file features and is recorded in the roadmap revisions. Standing approval,
  roadmap 0002.

- 2026-11-01: Step 1 done. `qv-platform::files` (Linux) holds the moved
  no-follow Input/Output with injected cancellation and an explicit size bound;
  qv-core reexports it beside the other Linux adapters; qv-cli keeps a thin
  wrapper with the same messages/exit codes and signal cancellation. Tests:
  `cargo test -p qv-platform files` 3 passed (changed input/replaced output,
  unsafe paths/size/existing output/0600/cancellation, absolute path vs actual
  ancestor ownership); `cargo test -p qv-cli --test attachments` 2 passed;
  Clippy for platform/cli/core clean. Found: this sandbox's `/` is owned by
  `nobody`, so the unchanged ancestor-owner rule refuses every absolute path
  here; CLI e2e tests use relative paths and pass. Unit tests use a private
  working directory and assert absolute-path results against real ancestor
  ownership. Not changed: the rule itself (0011 §4).

- 2026-11-01: Steps 2–7 controller work (shared parts). New modules:
  - `workspace.rs`: screens, bounded protected inputs, typed actions,
    confirmations, over-budget retry, worker, reveal, clipboard slot;
  - `ops.rs`: operations mirroring the CLI command semantics;
  - `documents.rs`: Linux path files plus Android document seams;
  - `views.rs`: escaped display data; Debug-free except variant names;
  - `workspace_tests.rs`.

  Controller: lock generation for late results, a workspace per unlock,
  5-minute phrase-screen limit with an explanatory locked status, an optional
  new-password prompt after phrase unlock, and over-budget consent for
  baseline adoption.

  Deviations, all within the approved design intent:
  1. Snapshot restore uses the open session's `restore_snapshot` instead of
     a reauthenticated second unlock. The second unlock contends for the
     vault's exclusive lock (observed `Store(Locked)`), and a pruned snapshot
     fails closed.
  2. Core's `begin_rotation` consumes and locks the session once its recovery
     snapshot exists, so a prepared rotation moves to a controller
     `Phase::Rotation`: phrase confirmation, install or cancel. During that
     worker the app does not treat the expected self-lock as an OS lock;
     manual and OS locks still cancel. Cancel changes nothing (journal
     unpublished).
  3. Interrupted rotations are detected before unlock (`rotation_pending`)
     and finished from the lock screen (complete/rollback, with the passwords
     core requests). Not covered by an app test: producing an interrupted
     journal needs core-internal fault injection.
  4. `history purge` takes no recovery snapshot, matching the CLI.

  Tests: `cargo test -p qv-app --lib` 20 passed (10 new workspace tests plus
  existing controller/runtime/views). Coverage includes stale epochs, reveal
  expiry, search bound, late result after lock, phrase idle, edit bounds and
  blank replacement, groups/move/delete/restore, trash confirmation and
  snapshot, synthetic over-budget refusal/consent, history
  reveal/restore/purge, snapshot restore into a branch, archive merge
  creating real conflicts, copy/edit refusal on conflicts, conflict resolve,
  self-contained export confirmation, verify, generator expiry/impossible
  settings/defaults, fake clipboard replace/lock-cancel/unavailable,
  settings, password change with weak confirmation, phrase redisplay with
  reauth, and rotation cancel/confirm/install.

  Found: in this sandbox the attachment round trip stops at the correct
  absolute-path refusal (`/` owned by `nobody`); CI hosts with a root-owned
  `/` run the full round trip.

- 2026-11-01: Steps 3–7, 9 and 10 completed for shared and Linux scope; step 8
  code is complete and step 11 is partly done.

  UI: `ui/workspace.rs` provides the responsive shell (sidebar at ≥ 900 px,
  bottom bar below), a typed confirmation dialog, fixed-label reports, one
  component per screen, stable input ids and a keyed remount per form epoch.
  Vault text renders as escaped `as_str()` text only. `Zeroizing<String>`
  deliberately has no `Display`.

  Changes:
  - `app.js` skips controlled inputs when clearing and also wipes `.revealed`
    and `.phrase` on hide.
  - Leaf components take the revision. A memoized field line did not
    re-render after a reveal; the real-engine flow found this.
  - Vendor: dropped edit batches resolve as not applied, and hardened
    rendering closes the window (the app's close handler locks). A refused
    native IPC counter feeds the boundary harness, which now requires exactly
    3 refusals. `third-party/README.md` updated.
  - Android: the qv-platform clipboard hold clears only verifiably owned clips
    and defers background expiry during a foreground hold (decisions 1–2). The
    JNI backend and SAF streams live in `android.rs` and `MainActivity.kt`.
    Uris stay in Kotlin, attachments move in 64 KiB chunks, archives are
    staged privately and removed (also at startup), and picks are forgotten
    on lock. Pause and screen-off now use separate generation counters: the
    2.4 poller turned any missed pause into a synthetic screen lock, which
    would defeat decision 1. Screen-off stays immediate.
  - qv-core reexports `MAX_ARCHIVE_TOTAL_LENGTH` and the Android clipboard
    types (facade only).
  - Real-engine flow extended (stage-numbered failures); harness deadlines
    raised to 150/160 s for the longer debug flow.

  Results:
  - Gates on this tree: workspace `cargo test` 738 passed, 2 ignored; qv-app
    validation 21 unit + 3 engine; Clippy workspace and qv-app validation
    clean; Android arm64 check and `--no-deps` Clippy clean; vendor desktop
    focused 4 passed.
  - Visual check of captured frames at desktop and phone widths: see
    VALIDATION.md.

  Found, not fixed: `qv-store/src/location.rs:154`'s `f_type as u64` is an
  unnecessary cast only on aarch64-android under Clippy. It is pre-existing,
  outside this plan's files, and not run in CI.

  Remaining: APK build (pinned dx 0.7.10 is being built; the host dx is
  0.8.0-alpha), the device run, final gates and documentation.

- 2026-11-01: The pinned dx 0.7.10 was installed in the scratchpad (the host
  binary is 0.8.0-alpha; musl needed dynamic linking). App and
  instrumentation APKs were built and inspected: API 29/target 35, backups
  off, INTERNET plus the generated receiver permission, recorded debug
  certificate. Hashes are in VALIDATION.md (app APK rebuilt after removing an
  unused method).

  Added: About now captures the unverified header before unlock, because
  `Core::inspect` cannot open the file while the session holds it; a test
  found this. A freshly created vault shows that details appear after the
  next unlock.

  Final gates: SPDX, fixtures, matrix and fmt pass; workspace and qv-app
  validation Clippy clean; `cargo test --locked` 738 passed, 2 ignored; qv-app
  validation 24 passed; vendor desktop 4 and x11rb 13 passed; deny and vet
  pass with an unchanged graph; Android arm64 `--no-deps` Clippy clean.

  No device was attached (`adb devices` empty). Step 8's device evidence and
  step 11's phone checklist are pending, so the plan stays In progress. Steps
  1–7, 9, 10 and 12 documentation are done.

- 2026-11-01 (device session, POCO X7 Pro 2412DPC0AG, Android 15 / HyperOS
  OS2.0.7.0.VOJMIXM, WebView 156.0.8078.47). The first device run found and
  fixed, each verified by the next run:
  1. Vendored `poll_edits_flushed` re-polled a resolved oneshot (`Canceled`),
     so the 0031 "close on dropped batch" closed the app on the first wake-up
     after a flush (FORTIFY abort at exit). The resolved receiver is now
     forgotten; test `hardened_applied_batch_stays_applied_on_later_polls`.
  2. tao's `Suspended` (Android pause) locked directly, defeating decision 1.
     On Android, pause now goes only through the native poller (deferrable).
  3. Releasing the worker permit did not advance the view revision, so a
     memoized screen rendered while busy stayed empty (race). An atomic
     release counter is part of the revision; test
     `releasing_the_worker_advances_the_revision_so_refused_reads_rerender`.
  4. Design gap: the system document picker always backgrounds the activity,
     so every pick locked the vault (and forgot the pick). Extended decision 1:
     `AndroidPlatform::defer_background()` guard (clipboard hold reuses it); a
     foreground-started pick defers only background expiry until the poller
     sees the activity back with an outcome, or the pick forgotten. Screen
     lock, protection loss and the 60 s inactivity lock still apply. Test
     `android_document_pick_deferral_is_foreground_only_and_fires_on_release`.
  5. A finished pick did not re-render `PathInput` (now takes `revision`;
     the poller calls `Controller::touch`). Missing display name falls back to
     the Uri's last segment, then "unnamed document".
  6. Hazard: a pick outlived navigation and writes, so an archive export
     overwrote the attachment's earlier destination. Picks are now forgotten
     on navigation and after a destination is written.
  Test-only fixes: row-button matching, exact "Chosen: <name>" waits, screen
  heading wait, bounded failure summary.
  Device result now: create, reveal/hide, sensitive copy and owned clear at
  expiry, background deferral during a hold then lock, attachment add and
  byte-exact save, archive export all pass. **Open:** archive merge-back
  fails with the generic core-operation error ("The vault operation could not
  be completed…"); not yet diagnosed. Full host gates were not rerun after
  these edits. Plan stays In progress.

- 2026-11-02: Device follow-up. Diagnosed the open merge failure: the
  incoming-archive walk opened `/data` with `O_RDONLY`; `run-as` confirmed
  `/data` and `/data/data` are `--x` for the app. Fixed with `O_PATH` ancestors
  (see Revisions); the acceptance traversal test now covers a search-only
  ancestor and fails without the fix. The merge test now accepts either merge
  report for an own fresh export, and requires no app error. Device suite: `OK
  (1 test)` twice (60 s) on app `d36f3f12…3f2d3f`, tests `8f2ac283…a35cf1`.
  Final tree: SPDX, SPDX fixtures, matrix, fmt, Clippy (workspace and qv-app
  validation), Android arm64 Clippy (qv-app + qv-platform) pass; `cargo test
  --locked` 740 passed (2 existing ignored); qv-app validation 25 passed;
  vendored dioxus-desktop 5 passed. No dependency changed, so deny/vet were not
  rerun. Steps 8 and 11 ticked; owner phone observations stay separate (UI
  review). Status Implemented.
