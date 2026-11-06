# Plan 0040 — App design: application look and feel (roadmap 2.10a)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — fresh review, phone instrumentation and owner acceptance pending | 2026-11-04 | 2026-11-04 (step 1: standing approval, roadmap 0002; steps 2–8: owner delegated D1) | 0009 §1.6; 0008 §4 (unchanged) |

## Intent

The owner finds that the shared app looks and feels like a website, on desktop
and on the phone (2026-11-02). Restyle and restructure the shared Dioxus
screens so they feel like an application on Linux and Android, with one
codebase and no change to security behaviour or functionality. The owner
approves the visual direction before any code (roadmap 2.10a).

## Scope

**In scope:**
- Design brief and mockups ([DESIGN.md](DESIGN.md), canvas linked there), then
  a stop for the owner's approval (D1).
- After approval: new `app.css` design tokens (light/dark from the OS), the app
  shell, responsive desktop/tablet/phone layouts over one DOM, own stroke icons
  as rsx SVG, the locked/onboarding screens, the workspace shell (toolbar,
  sidebar, list + detail panes, status bar, phone app bar, bottom tabs, a
  phone-only More screen), dialogs/sheets/toasts, restyling every remaining
  screen, keyboard shortcuts for existing desktop actions, and updated
  real-engine/Android test selectors with the same assertions.

**Out of scope:**
- Any new vault, sync, security or settings feature; an in-app theme toggle
  (needs persisted settings); custom window decorations; bundled or remote
  fonts; third-party icon packs; Windows/macOS; changes to the 0008 §4 input,
  reveal, clipboard and lock behaviour; changes to the webview policy or CSP.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Shared app, layouts adapted for touch and desktop | 0009 §1.6 | Draft (owner-approved for the app, D13) | No new requirement; this phase only changes presentation |
| Input cleanup, reveal, clipboard, lock, webview policy | 0008 §1.1, §4 | Draft (D5/D13 go-ahead) | Unchanged; see DESIGN.md *Invariants* |
| Explicit LAN initiation, QR display | 0009 §1.5, §1.7; 0013 §4.2, §8.5 | Draft / Accepted | Restyle only |
| Local save status separate from sync | 0009 §1.3 | Draft | Status bar shows existing state only |

**Spec changes required:** None.

## Decisions needed

1. **D1 — Visual direction.** Approve "quiet native" as shown in the canvas
   and DESIGN.md: native window title bar, three panes on desktop, app bar plus
   bottom tabs and sheets on the phone, system fonts, neutral greys with one
   green accent, light/dark from the OS, and own stroke icons. Options:
   A. Approve as shown.
   B. Approve with changes (name them; comments on the canvas also work).
   C. Ask for a different direction.
   Recommendation: A. The owner reserved this decision in the roadmap entry,
   so the standing delegation (2026-11-02) is not applied to it. If the owner
   delegates it ("whatever you think is best"), proceed with A.
   Blocks: steps 2–8. Resolution: owner delegated on 2026-11-04 ("Do whatever
   is the best thing OK? I'm trusting you on this one"); option A chosen as shown.

Choices already made under the standing delegation (owner, 2026-11-02),
recorded here with their rejected alternatives in DESIGN.md: follow the OS
theme with no toggle; native decorations; system fonts; own icons; one DOM
with CSS breakpoints.

## Design

**Components touched:** `crates/qv-app` only: `assets/app.css`,
`src/ui/{mod.rs,workspace.rs}`, a new `src/ui/icons.rs`, `src/workspace.rs`
(navigation helpers only), the Android activity theme if the WebView needs it
to report `prefers-color-scheme`, and the real-engine/Android test scripts. No
trust boundary moves. Frontend → qv-core is unchanged, and qv-core and crypto
are untouched.

**Interfaces:**

```rust
// src/ui/icons.rs — fixed paths authored here; no strings reach the DOM as HTML.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Icon { Lock, Search, Plus, Folder, List, Generator, Trash,
    Conflicts, Snapshots, Archives, Devices, Settings, Edit, History, Attach,
    Copy, Eye, EyeOff, Back, Chevron, More, Shield, Phone, Laptop, Close }
#[component] pub(crate) fn Svg(icon: Icon, label: Option<&'static str>) -> Element;

// src/workspace.rs
impl Workspace {
    /// The nearest list screen (Browse/Search/Recovered) at or below the
    /// current screen in the back stack; the list pane shows it next to a
    /// detail screen. Read-only; adds no state.
    pub(crate) fn list_context(&self) -> Screen;
}
impl Controller {
    /// Select a sibling from the list pane: replaces the current detail
    /// screen instead of pushing it (Back still returns to the list).
    pub fn select(&self, epoch: FormEpoch, to: Screen);
}
// Screen gains `More` (phone-only section list). Debug stays variant-only.
```

**Layout:** one DOM. Root classes `layout-wide|layout-mid|layout-narrow` come
from CSS media queries only (no Rust width state). The sidebar and bottom tabs
are both rendered and hidden by CSS. In a narrow layout, a detail screen hides
the list pane (`.has-detail`), and the app bar's back arrow calls the existing
`back()`. The desktop toolbar search field navigates to `Screen::Search` on
focus or Ctrl F, *before* typing. Navigation bumps the epoch, and `app.js`
clears uncontrolled inputs. The Search screen's existing controlled `Query`
input then takes focus.

**Keyboard:** a root `onkeydown` in Rust maps Ctrl F, Ctrl N, Ctrl L, Ctrl S
and Esc to existing controller actions. Esc cancels a pending confirmation
first, then goes back. Shortcuts are ignored while `busy`. No new JS.

**Secrets and hostile input:** unchanged. Keep `data-qv-epoch`,
`data-qv-clear`, `data-qv-controlled`, `.phrase` and `.revealed`, input bounds
and attributes, reveal and clipboard flows, and `value: None` for secret
inputs. Icons are rsx elements with constant paths. User text renders only as
text nodes. Never use `dangerous_inner_html`. A redesigned list or detail
shows no field that the current screens hide.

**Errors:** unchanged categories and messages. Errors stay inline with
`role=alert`; transient notices may move into toasts or the status bar.

**Dependencies:** none.

## Steps

### Step 1 — Design brief and mockups (stop for owner approval)

- [x] **Do:** write DESIGN.md; publish the mockup canvas (desktop: vault, edit
  entry light, unlock, devices with pairing dialog; phone: unlock, list, entry
  with copy toast, confirm sheet, More light); stop for D1.
- **Files:** `plans/0040-app-design/{PLAN.md,DESIGN.md}`, roadmap, index.
- **Done when:** the owner has the brief and canvas; D1 is recorded.
- **Verify:** document inspection; `git diff --check`.

### Step 2 — Tokens, shell CSS and icons

- [x] **Do:** replace `app.css` with token-based light/dark custom
  properties (`prefers-color-scheme`); add the app-shell rules from DESIGN.md
  (no document scroll, system fonts, default cursor, `:focus-visible`,
  `user-select` on chrome, `overscroll-behavior`, reduced motion,
  `pointer: coarse` metrics). Add `ui/icons.rs` and replace the Unicode glyphs.
  On Android, confirm that the WebView reports the system scheme; if not, set
  a DayNight activity theme (no WebView force-dark).
- **Files:** `crates/qv-app/assets/app.css`, `src/ui/icons.rs`,
  `src/ui/{mod.rs,workspace.rs}`, `android/AndroidManifest.xml` (only if needed).
- **Done when:** both themes render on Linux and the Android APK builds; no
  glyph icons remain.
- **Verify:** `cargo clippy -p qv-app --all-targets --locked -- -D warnings`;
  `cargo test --locked -p qv-app`.

### Step 3 — Locked and onboarding screens

- [x] **Do:** a compact centred panel, the Unlock/Create/Recover/Join
  segmented control, vault-file row, protection line; restyle weak-password,
  phrase display/confirm, recovery/baseline, rotation and opening states.
  Remove the intro, principles and footer. Keep every control, consent and
  message.
- **Files:** `src/ui/mod.rs`, `assets/app.css`.
- **Done when:** every phase renders in both layouts and all locked-screen
  tests pass.
- **Verify:** `cargo test --locked -p qv-app`; validation flows (step 7 command).

### Step 4 — Workspace shell, panes and navigation

- [x] **Do:** toolbar, sidebar with top-level groups and sections, list
  and detail panes using `list_context()`, status bar, phone app bar with back,
  bottom tabs, `Screen::More`, `Controller::select`. Breakpoints at 1000 and
  720 px.
- **Files:** `src/ui/workspace.rs`, `src/workspace.rs`, `assets/app.css`,
  `src/workspace_tests.rs`.
- **Done when:** navigation, Back and More work in every layout; lock and
  epoch behaviour are unchanged.
- **Verify:** new headless tests: list context from the back stack, `select`
  replaces rather than pushes, More is reachable only through navigation, and
  lock clears it like any screen. Plus `cargo test --locked -p qv-app`.

### Step 5 — Dialogs, sheets, toasts and busy states

- [x] **Do:** Confirm becomes a modal dialog or sheet with an inert
  background and Esc cancel. Restyle the LAN panel, QR card and scan panel as
  dialogs, toasts for clipboard and notices, and the busy overlay. Keep ids
  (`lan-qr`, `lan-codes-match`, …) and roles.
- **Files:** `src/ui/workspace.rs`, `src/ui/mod.rs`, `assets/app.css`.
- **Done when:** every pending confirmation and LAN question still needs the
  same explicit action; QR quiet zone and cleanup tests still pass.
- **Verify:** `cargo test --locked -p qv-app`; validation flows.

### Step 6 — Remaining screens and keyboard

- [x] **Do:** restyle entry detail/edit, history/version, attachments, trash,
  conflicts and record, move, snapshots, archives, devices, generator, settings
  panes and autofill in the new components. Add the shortcuts.
- **Files:** `src/ui/workspace.rs`, `assets/app.css`.
- **Done when:** no screen still uses the old card/page styles; shortcuts
  invoke only existing actions and do nothing while busy or locked.
- **Verify:** headless shortcut tests (busy/locked no-ops; Esc ordering);
  `cargo test --locked -p qv-app`.

### Step 7 — Validation, screenshots and owner review

- [ ] **Do:** update the selectors in `src/bin/flow.js`, `src/bin/harness.js`,
  `android/tests/flows.js` and the instrumentation tests to the new markup
  (prefer ids and roles). Keep every assertion. Capture screenshots at
  1280×800, 900×700 and 390×844 in light and dark, on Linux through the
  preview binary under Xvfb. Run the Android build and instrumentation when
  the owner connects the phone, and ask the owner to review on Linux and the
  phone.
- **Files:** test scripts above; screenshots under `plans/0040-app-design/`.
- **Done when:** all suites pass with unchanged assertion counts; the owner
  accepts the result on both platforms, which is the phase's *Done when*.
- **Verify:** `cargo test --locked -p qv-app --features validation`;
  `sh crates/qv-app/scripts/build-android.sh`;
  `sh crates/qv-app/scripts/test-android.sh` (attended).

### Step 8 — Documentation

- [x] **Do:** CHANGELOG, `crates/qv-app/README.md` (layout and screenshots),
  roadmap tick and log, index row.
- **Files:** as named.
- **Done when:** records match what was delivered and what is still pending.
- **Verify:** `git diff --check`; SPDX and matrix scripts.

## Test plan

- Final verification: all `AGENTS.md` gates on the final tree; steps above are
  focused.
- Unit tests: list context, `select`, More and shortcut mapping (step 4 and 6).
- Rejection paths: shortcuts while busy/locked/pending; Esc never confirms;
  late results after lock still dropped (existing tests).
- Real-engine flows: unchanged assertions with new selectors; the hostile
  markup, protected-value and reveal checks in `flow.js` must stay.
- 0012 §1 rows: none new. Existing GUI rows (Webview exposure, clipboard,
  reveal, lock) keep their evidence and must keep passing.

## Risks and stop conditions

- Stop if a layout needs a new persisted setting, a new JS capability, a CSP or
  webview-policy change, or shows a value that is hidden today.
- Android WebView may ignore `prefers-color-scheme` without a DayNight theme.
  Use the theme, not force-dark, and record it if the WebView still does not
  follow.
- Selector churn in the real-engine flows: update hooks, never drop an
  assertion. If a check cannot be expressed, stop and record it.
- The owner may reject parts at step 7. Iterate within this plan, since D1
  covers the direction.

## Documentation

- [ ] `CHANGELOG.md`: redesign entry (step 8)
- [ ] `ARCHITECTURE.md`: no component change expected; confirm at step 8
- [ ] Specs: none
- [ ] `crates/qv-app/README.md`: layouts and screenshots
- [x] `plans/README.md`: index row
- [ ] `AGENTS.md`: no workflow change

## Revisions

### 2026-11-05 — Owner rejected the "quiet native" result

The owner reviewed the implemented direction and rejected it:
- the GTK title bar is unwanted: the app needs its own title bar or none;
- it still feels like filling in web forms rather than using an app;
- there is no in-app dark/light toggle (the earlier look was dark);
- several flows are poor UX, for example typing a full vault file path.

The owner asked for a new, unbiased design and allows large breaking UI
changes. The implemented restyle stays in the tree only until a replacement
is approved. A new clickable prototype was published for feedback before any
product code: https://claude.ai/artifact/GYYz8oLLeAo4nefahGccp6

Its main parts:
- a frameless window with its own title bar;
- an app-managed vault switcher and system file pickers instead of path
  fields;
- click-to-copy fields, inline editing and a command bar;
- a generator with sliders and switches;
- grouped settings with a theme toggle;
- step-by-step pairing and onboarding flows;
- phone tabs and sheets from the same UI.

A revised plan follows the owner's feedback on it. Spec-affecting choices it
raises are recorded there before implementation:
- a one-time reduced-protection acknowledgement (0008 §1.3);
- a persisted app theme preference;
- portal file pickers on Linux.

### 2026-11-05b — Prototype approved; rebuild the app UI from it

The owner approved the prototype at
https://claude.ai/artifact/GYYz8oLLeAo4nefahGccp6 ("THATS what I'm talking
about"). Under the standing delegation (2026-11-02), the shared app UI is
rebuilt from it, replacing steps 2–7's restyle. Steps 1–8 above are history.
Steps 9–16 below are the new contract. No vault, crypto, storage-format,
protocol or sync behaviour changes.

Decisions (owner-delegated, 2026-11-05):

- **R1 Frameless desktop window.** On Linux the window has no OS decorations.
  The app's title bar:
  - drags the window (`DesktopService::drag`) and maximizes on double click;
  - has minimize, maximize and close buttons;
  - has 6 px edge and corner handles that use tao `drag_resize_window`.

  Android draws no title bar. Rejected alternatives: keeping the GTK bar
  (owner refused) and GTK client-side headerbars (not reachable through
  tao/wry).
- **R2 App preferences file** `preferences` in the app's private state
  directory, holding non-secret data only:
  - `theme=dark|light|system` (default `dark`);
  - `protection=<status fingerprint>` (the acknowledged reduced-protection
    status).

  Format: UTF-8 `key=value` lines, at most 256 bytes. Unknown or malformed
  keys are ignored. Writes go to a temporary file with mode 0600 and are
  renamed into place; a read refuses a non-regular file. A parse or I/O
  failure falls back to the defaults and is never fatal. This is app
  configuration, not a vault format.
- **R3 One-time reduced-protection acknowledgement** (0008 §1.3, 0009 §5).
  - The app computes a fingerprint of the protection status:
    - process/memory hardening reduced;
    - storage, swap and hibernation evidence;
    - lifecycle monitoring;
    - clipboard.
  - If protection is complete, no acknowledgement is needed.
  - If it is reduced and the fingerprint differs from the stored one, the
    locked screen shows the reduced protection. Create, unlock and recover
    stay refused (`AppError::Consent`) until the user acknowledges it in an
    explicit sheet; the sheet stores the fingerprint.
  - Any change in status asks again. Settings → Security shows the mode.
  - `Controller::submit`'s consent argument is replaced by this stored state.
    Tests pass consent through the same path.
- **R4 No typed paths.**
  - The default vault lives in the app's own storage (no path).
  - "Open a vault file…", attachments, archives and snapshot restore use the
    system picker: the Android Storage Access Framework (existing), and on
    Linux the xdg-desktop-portal FileChooser over the existing zbus (async
    API, `futures_lite::future::block_on`, as logind already does).
  - The portal returns `file://` URIs. Only absolute local paths are
    accepted; non-`file` URIs are refused. The chosen path goes into the
    existing protected path input, and the existing no-follow and ownership
    rules still apply.
  - If the portal is unavailable, an in-app fallback path field appears with
    an explanation (0011 §4 path rules unchanged).
  - No dependency or feature changes.
- **R5 Vault choice.** The unlock screen shows this device's vault. Its menu
  offers:
  - "Open a vault file…" (picker, Linux);
  - "Create a new vault";
  - "Join from another device";
  - "Recover with recovery phrase".

  No vault name is shown before unlock: names are encrypted metadata
  (0008 §1.2), so the screen says "Your vault · this device" or the file
  name. With no app vault yet, a first-run welcome replaces the unlock card.
- **R6 Items view.**
  - "All items" and type filters (from the existing `type_hint`) are built
    from existing core listings walked recursively by the app. Groups come
    from top-level groups.
  - The list shows a monogram tile, title and subtitle. Quick copy (first
    non-protected field, first protected field) reuses the existing Copy
    action with handles read at click time.
  - Detail: click a field to copy; reveal keeps the existing 30 s rule with a
    countdown ring; TOTP keeps "Show code"; notes; attachments; history.
  - Editing happens in place in the detail pane, with the same form
    semantics (protected values never prefilled).
  - Delete offers Undo through the existing Restore action.
- **R7 Command bar** (Ctrl K): items via the existing search plus commands for
  existing actions only.
- **R8 Idle ring.** The lock button shows the remaining time of the existing
  60 s inactivity lock (`Live::idle`). The display only; the lock policy is
  unchanged.
- **R9 Spec.** 0009 (Draft, owner-approved for the app) gains §1.8, the app
  shell and preferences profile (R1–R4), with a Changelog line.

Kept invariants are as in Design → Secrets: cleanup hooks (`data-qv-*`,
`.phrase`, `.revealed`), input bounds, reveal and clipboard timers, lock
triggers, FLAG_SECURE, the webview policy, and no raw HTML.

### Step 9 — Spec 0009 §1.8 and plan records
- [x] Do: amend 0009 with R1–R4; Changelog; index note.
- Done when: the text matches R1–R4. Verify: `git diff --check`.

### Step 10 — Preferences, protection acknowledgement and idle display
- [x] Do: `src/prefs.rs` (R2); `Controller::{theme, set_theme,
  protection_ack_needed, acknowledge_protection}`; route `submit` through the
  stored acknowledgement (R3); `Live::idle`. Tests: bounds, malformed input,
  symlink refusal, fingerprint change asks again, refused unlock until
  acknowledged.
- Verify: `cargo test --locked -p qv-app prefs`, `... protection`.

### Step 11 — File picking without typed paths
- [x] Do: `qv-platform` `linux::portal::pick(kind, save)` (R4), and a
  `documents::pick` that fills the protected path input for vault, attachment,
  archive and restore targets; Android keeps SAF. Tests: URI decoding,
  refusal of non-file URIs, unavailable portal maps to the fallback.
- Verify: `cargo test --locked -p qv-platform portal`; `-p qv-app documents`.

### Step 12 — Views and navigation support
- [x] Do: `views::all_items` (type and group), quick-copy handle lookup, Undo
  state for delete, and `Screen` filters for type/group lists. Tests for each.
- Verify: `cargo test --locked -p qv-app workspace`.

### Step 13 — Window and shell
- [x] Do: frameless Linux window with title bar, drag, resize and controls
  (R1); sidebar, list and detail, phone tabs, sheets, toasts, command bar;
  theme applied from preferences; new CSS from the prototype tokens.
- Verify: `cargo clippy -p qv-app --features validation --all-targets`;
  validation flows.

### Step 14 — Screens
- [x] Do: rebuild unlock and first-run, onboarding (create, phrase,
  confirm), recover, join, items (detail, inline edit, history, attachments,
  move), generator, devices and pairing, trash, conflicts, settings (theme,
  security, password, phrase, rotation, snapshots, archives, verify, about)
  and autofill, from the prototype.
- Verify: `cargo test --locked -p qv-app --features validation`.

### Step 15 — Tests, screenshots and Android
- [ ] Do: update `flow.js`, Android `flows.js` and the instrumentation tests
  to the new UI, keeping every assertion. Take screenshots in light and dark
  at desktop, mid and phone widths. Build the Android APKs. Run the phone
  instrumentation when attended.
- Verify: full gates; APK builds.

### Step 16 — Documentation
- [x] Do: CHANGELOG, qv-app README, ARCHITECTURE §3 if structure changed,
  roadmap, index.

### 2026-11-05c — Item editor rebuilt from its prototype; item colours

The owner approved the item-editor prototype at
https://claude.ai/artifact/4Zxts5aHzHwLgXkFWp7T5s ("Yeah this is way better.
Let's go with that"). It replaces the entry form of step 14. The owner's
earlier request for user-chosen colours ("can i not change the group
color?") is part of it: the prototype's tile opens a colour picker. The
vault-list redesign (memory: name-only create, remembered vaults) is still
queued and is not part of this revision. Decisions below are
owner-delegated (2026-11-02 standing delegation; "be innovative") unless
marked otherwise.

- **E1 Start step.** A new item opens "What are you saving?" with one input
  and type tiles (Login, Card, Wi‑Fi, Note, Something else).
  - The input is a protected workspace input (`WsField::Start`,
    uncontrolled, `LINE_MAX`), because people paste card numbers into it.
  - The guess runs in Rust on the device (`views::guess`): 12–19 digits
    (spaces and dashes allowed) are a card; a host name or URL is a login
    for that site; Wi‑Fi words (wi-fi, wifi, wlan, ssid, router, network)
    are a Wi‑Fi network; anything else is a login with that title.
  - For a card, the screen shows only the brand, the last four digits and
    whether the Luhn check passes, never the whole number. Accepting moves
    the number into the protected "Card number" replacement.
  - Enter or a click accepts the guess; "Or save it as …" and the tiles
    choose explicitly. Nothing is looked up online.
- **E2 Types and templates.** Type hints stay the existing strings
  (`login`, `card`, `wifi`, `note`; "Something else" is `custom`, the
  0003 §5.1 name for unknown hints). Templates:
  - login: Username (text), Password (secret), Website (url);
  - card: Name on card (text), Card number (secret), Expires (text,
    MM/YY), Security code (secret);
  - wifi: Network name (text), Password (secret), Security (text, "WPA2");
  - note and custom: no fields; a note opens its notes as the page.

  Changing the type on the type chip keeps every field with a value (or a
  saved or replaced protected value). A template field reuses a kept field
  with the same name (case-insensitive). Empty fields that the new template
  does not have are dropped. The notice says how many filled fields were kept.
  An unknown existing hint is shown as is and changes only when the user picks.
- **E3 Title.** The title is the big input. If it is empty on save, the
  title comes from the website's host name (login), the network name
  (Wi‑Fi), or the card's brand and last four digits (card). It is shown as the
  placeholder with "Title from …". Otherwise saving still says
  `NameRequired`.
- **E4 Derived displays of protected values.** Only these leave Rust,
  computed from the protected value in place:
  - a card number's brand, last four digits and Luhn validity;
  - whether a protected field has a saved value (one bit), for "Saved · Change".

  The last four digits are also in the automatic card title; the user can
  change it. This matches common card practice ("ending 4242").
- **E5 Field rows.**
  - Each field has a label column and a real input box. The name changes only
    through ⋯ → Rename.
  - The ⋯ menu also has "Hide the value" / "Show the value normally"
    (`ToggleProtect`; not for one-time codes), Move up/down and Remove (Undo
    shown in place).
  - A saved protected value shows "•••••••• Saved · Change". Change opens the
    replacement input, and × keeps the saved value (clears the replacement).
  - The eye in a protected input uses the existing 30 s replacement reveal and
    switches the control to plain text. Its value is already in that control,
    and no value is sent to the DOM.
  - A generated replacement shows "•••••••• Generated" with the same eye (a
    30 s reveal pill) and Change.
- **E6 Generator popover.** The dice on a password row opens a popover over
  the workspace generator form. It has:
  - the value, shown as on the Generator page;
  - length (characters) or word count;
  - a words switch and a symbols switch;
  - Again and "Use it".

  "Use it" moves the generated value into that row's replacement in Rust
  (`UseGenerated`), never through the DOM. The strength line shows the
  exact entropy of the generator settings (`qv_core::estimate`).
  Typed values get no meter. Rejected: zxcvbn per keystroke (it leaves
  unzeroized copies, `strength.rs`) and a hand-made estimator (it misleads).
  *Deviation from the prototype*, recorded here.
- **E7 Add a field.** One "Add a field" button opens a name box. The kind is
  inferred from the name (`views::kind_for`: OTP/2FA/authenticator → one-time
  code; password/PIN/CVV/secret/token/API key/private/seed → hidden;
  recovery/backup codes → multi-line hidden; mail → email;
  url/site/web/link/domain → website; address/notes/memo → multi-line;
  otherwise text). A kind pill shows and overrides it, and each type has a
  few common names. Protection follows the kind default (0003 §5.3).
- **E8 Wi‑Fi.**
  - A Wi‑Fi item's "Security" field is chosen with WPA3 / WPA2 / WEP / Open
    network buttons; the stored values are `WPA3`, `WPA2`, `WEP` and `None`.
  - The editor shows a join card with the network name and security.
  - The item page has "Show join code": a 30 s reveal (`RevealKey::WifiJoin`)
    of a `WIFI:T:…;S:…;P:…;;` QR built in Rust (escaping `\ ; , : "`) with
    the existing encoder. The QR carries the password, like any reveal, and
    is refused (`TooLargeForApp`) above `qr::MAX_PAYLOAD`.
- **E9 Card visual.**
  - The editor and the item page show a card face with the brand,
    `•••• •••• •••• 4242`, the name on the card and the expiry.
  - The expiry shows "N yr/mo left", "Expired" or "Month 01–12", from the
    device clock.
- **E10 Colours** (0003 §4, §5 amendment). The `icon` text of an entry or
  group may hold `hue:<n>`, n 0–11, the app's colour token.
  - Any other value (absent, a built-in icon name, or unknown) shows the
    automatic colour from the record ID. It is kept unchanged unless the
    user picks a colour.
  - "Automatic" clears only a `hue:` value. The colour syncs as part of the
    record.
  - The swatches open from the tile in the entry and group editors.
- **E11 Group chip.**
  - The entry editor's group chip lists the vault root ("No group") and
    the top-level groups. If the entry is in a nested group, that group is
    listed too.
  - Choosing one sets the draft's group, which is a move on save (core
    already checks the group is live).
  - `qv-core` gains `EntryDraft::{group, set_group}` (handle-checked).
- **E12 Spec.** 0009 §1.8 gains the item-editor bullet (E1, E4, E6, E8),
  and 0003 §4/§5 the icon note (E10), each with a Changelog line.

Kept invariants: protected values are never prefilled; replacements stay
separate until save; 0008 §4 reveal and clipboard timers; input bounds;
`data-qv-*` hooks; no inline styles (the CSP); no raw HTML.

### Step 17 — Specs and plan records
- [x] Do: 0009 §1.8 item-editor bullet; 0003 §4/§5 icon note (§5.5); Changelogs.
- Verify: `git diff --check`.

### Step 18 — Core and workspace support
- [x] Do: `EntryDraft::{group, set_group}` with tests (foreign session
  refused). Workspace: `WsField::Start`; `EntryForm::{start, removed}`;
  actions `StartAs`, `SetType`, `SetGroup`, `SetHue`, `AddField(Option<_>)`,
  `AddNamedField`, `MoveField`, `UndoRemoveField`, `UseGenerated`,
  `RevealKey::WifiJoin`. Views: `guess`, `kind_for`, `auto_title`, the card,
  expiry and Wi‑Fi views, `colour` on rows. Tests: guess cases including a
  bad Luhn and no full number in the view; type change keeping filled fields
  and remapping replacements; move/remove/undo index remapping; auto title on
  save; `hue:` parsing and Automatic keeping foreign icons; UseGenerated
  never prefilled; Wi‑Fi payload escaping and bound.
- Verify: `cargo test --locked -p qv-core edit`, `-p qv-app`.

### Step 19 — Editor UI and CSS
- [x] Do: rebuild `EditEntry` (start step, head, rows, menus, adder, notes,
  card and Wi‑Fi visuals, generator popover, save bar) and `EditGroup`
  swatches; colours on every tile and dot; card face and join code on the
  item page; phone menus as bottom sheets (CSS).
- Verify: validation Clippy; real-input check under Xvfb.

### Step 20 — Flows, gates and docs
- [x] Do: update `flow.js` and Android `flows.js` to the start step, the
  generator popover and the collapsed notes, keeping every assertion;
  CHANGELOG; log.
- Verify: all `AGENTS.md` gates plus Android Clippy.

## Execution log

- 2026-11-04: Architect plan in the next-phase session after the 0039 review.
  Step 1 done: the brief and a nine-board canvas. The roadmap entry reserves
  the owner's approval of the direction, so steps 2–8 wait for D1.

- 2026-11-04: Owner delegated D1 ("Do whatever is the best thing OK? I'm
  trusting you on this one"). Chose option A, the direction as shown in
  DESIGN.md and the canvas. Status In progress. Continuing on the uncommitted
  review tree under this explicit continuation, without a separate commit
  boundary. Steps 2–8 are developer work; this implementation still needs its
  own fresh-context review.

- 2026-11-04: Steps 2–6 implemented.
  - **CSS:** new token-based `app.css` with light/dark from
    `prefers-color-scheme`, `pointer: coarse` touch metrics, a no-scroll app
    shell, system fonts, default cursor, `:focus-visible`, reduced motion, and
    breakpoints at 1000 and 720 px.
  - **Icons:** `ui/icons.rs` holds constant stroke paths rendered as SVG
    elements; two unused variants were removed for Clippy.
  - **Locked screens:** the intro, principles and footer are removed; a
    compact panel with a brand row keeps every control, consent and message.
    The weak-password buttons are restyled (same actions).
  - **Shell:** toolbar (search launcher button, New entry, Lock), sidebar with
    Vault, top-level groups and sections, a messages strip, list and detail
    panes, status bar, and phone app bar with Back, bottom tabs and the new
    `Screen::More`. Confirm, LAN and scan panels are modal (`inert`
    background, sheets on phones).
  - **Navigation:** `Screen::{is_list, is_vault_detail, is_form}`,
    `Workspace::{select, list_context}`, `Controller::{select, list_context,
    shortcut}` and `Shortcut::from_key`. List rows are disabled while an entry
    or group form is open.
  - **Copy:** group actions are relabelled "Rename/Move/Delete group" to tell
    them apart from entry actions.
  - **Kept:** class names, ids, headings and button texts that the cleanup
    script and the tests rely on (`.tabs`, `.primary`, `.lock-button`,
    `.nav-item`/`.nav-label`, `.row-button`, `.notice`, `.phrase`,
    `.revealed`, `data-qv-*`).
- 2026-11-04: Step 7 in progress.
  - **Selectors:** two history-row selectors were scoped to
    `.detail-pane .row-button` (`src/bin/flow.js`,
    `android/tests/PlatformTest.java`), because the list pane now precedes the
    detail. Assertions are unchanged; all other hooks are unaffected.
  - **Android theme:** `build-android.sh` patches the generated AppTheme from
    `Theme.AppCompat.Light.NoActionBar` to DayNight, asserting exactly one
    occurrence, so the WebView follows the system scheme. No force-dark.
  - **Screenshot hook:** validation builds accept `QV_UI_SIZE=WxH`. Ordinary
    builds use 1200×800, with a new 360×480 minimum.
  - **Screenshots:** the synthetic flow harness under Xvfb was captured at
    1200/1280×800, 900×700 and 390×844, light and dark (GTK theme), and saved
    under `screenshots/`. They contain synthetic data only, with no revealed
    values or local paths.
  - **Fixes from the screenshots:** the floating New button is hidden on
    narrow detail screens, and the narrow list text is padded.
  - **Results:** `cargo test --locked -p qv-app --features validation` passed
    before the final tweaks (39 library tests plus the 3 real-engine flows);
    the two new headless tests pass. Android arm64 Clippy passes for mobile
    and mobile,validation.
  - **Still pending:** the final gates, the APK build, phone instrumentation
    and the owner's review.
  - **Cleaned up:** a synthetic `.qv-ui-flow-*` fixture directory left by a
    killed screenshot run.
  - Step 8 documentation done: the qv-app README layout section and CHANGELOG.
    ARCHITECTURE needs no change (no component, boundary or technology change).

- 2026-11-05: Implementation complete; status Implemented.
  - **Still pending:** step 7's attended parts. No phone is connected (`adb
    devices` is empty), so Android instrumentation did not run on a device.
    The owner's acceptance on Linux and the phone, which is the phase's *Done
    when*, is also outstanding. Roadmap 2.10a stays unticked until both happen.
  - **APKs:** both the ordinary and the marked validation APK build with the
    pinned dx 0.7.10, and the DayNight patch assertion passes. SHA-256:
    product `8b0976d5b469449bb1ec7fd8955452134c7506c8b091f7d57504493da4448c8e`,
    validation `96c43cdbbbc80fb2046b3c39cb074dbc5fde7e9553adc95b5d4ba75c9d22200c`.
    Nothing was installed.
  - **Final gates on the final tree:**
    - SPDX, matrix, `cargo fmt --check` and `git diff --check` pass.
    - `cargo clippy --all-targets --locked -- -D warnings` passes, as does
      Android arm64 Clippy for mobile and mobile,validation.
    - `RUST_TEST_THREADS=1 cargo test --locked --no-fail-fast` with a private
      Xvfb: 879 passed, 0 failed, 2 pre-existing ignored, 48 result lines.
    - `cargo test --locked -p qv-app --features validation`: 44 passed,
      including the 3 real-engine WebKit flows.
    - No dependency changed, so deny/vet were not rerun for this plan; the
      0039 review run covered the same lockfile.
  - **Load flakes:** an earlier full run overlapped the release APK build. Two
    timing-sensitive tests failed in it, both untouched by this plan: the
    clipboard hold order and a fixed 300 ms LAN window sleep. Each passed 8 of
    8 runs alone, and the idle full rerun above passes. Found, not fixed:
    those two tests assume an unloaded machine.
  - **Review:** this implementation still needs the fresh-context review.

- 2026-11-05 (rebuild, partial): Steps 9–12 done, and the code for steps 13–14
  is written and compiles (`cargo check -p qv-app --features validation
  --all-targets` passes with 3 warnings to fix). Steps 13–16 are not ticked.
  - **Spec:** 0009 §1.8 added.
  - **Preferences and consent:** `prefs.rs` (theme, acknowledged protection
    fingerprint), the controller's theme/consent/acknowledgement API,
    `View::{idle_left, theme, ack_needed}` and `Live::reveal_left`.
  - **File picker:** the Linux portal picker (`qv-platform`
    `linux::portal`), re-exported through core, with
    `documents::pick_path` and its follow-up action.
  - **Views and navigation:** `views::{all_items, top_groups,
    quick_fields}`, `Screen::Kind`, `Pane::Overview`, `WsField::Command`
    and Undo after delete.
  - **New UI** from the approved prototype: `ui/{mod,shell,items,pages,icons}.rs`
    and a new `app.css`.

  Not done yet:
  - Clippy, fmt, and the full and validation test suites have not run on the
    new UI.
  - `flow.js`, Android `flows.js` and the instrumentation selectors still
    target the old UI and must be rewritten. The real-engine flows will fail
    until then.
  - No screenshots, APK build or documentation (CHANGELOG, README) yet.
  - Fix-ups to make: zeroize the phrase words passed to `PhraseGrid`, and a
    `.busy-dot` style.

- 2026-11-05 (rebuild complete): Steps 10–14 and 16 done. Step 15 is done
  except the attended phone run.
  - **Inline styles:** the webview policy (`style-src 'self'`) blocks them, so
    hue, width, spacing and menu-anchor styles became CSS classes. The policy
    is unchanged.
  - **Event handling:** form-submit handlers did not reach Rust in this
    webview, so Unlock and the command bar use a button and Enter instead.
  - **File picker in fixtures:** validation fixtures force the typed-path
    fallback (`documents::force_no_picker`), so no real desktop dialog can
    block an automated run. They also show the vault path field, so Android
    fixtures can keep their private vault path.
  - **Real-engine driver:** `src/bin/flow.js` was rewritten with every stage
    and check kept. It passes with both the synthetic and the real Linux
    services.
  - **Android drivers:** `android/tests/flows.js` maps the old screen names
    onto the new screens, with idempotent steppers the Java side polls.
    PlatformTest, QuickUnlockUiTest, AutofillTest and QrTest were updated to
    use them and the new labels. They compile into the test APK but have not
    run on a device: no phone is attached.
  - **Screenshots:** under `screenshots/` (synthetic data only), replacing the
    first redesign's.
  - **Final gates on the final tree:**
    - SPDX, matrix, `cargo fmt --check` and `git diff --check` pass.
    - Workspace Clippy and validation Clippy pass, as does Android arm64
      Clippy for mobile and mobile,validation (after marking the Linux-only
      picker target and the desktop-only window icons as platform-specific).
    - The full serialized suite has 885 passed, 0 failed and 2 pre-existing
      ignored.
    - `cargo test --locked -p qv-app --features validation` has 48 passed,
      including the 3 real-engine flows.
    - Both APKs build. SHA-256: product
      `037c5fcc1698874050922f95933d09c871a7d6afe7dff06f3cf61920b47f084d`,
      validation
      `86848ec053fc65720f87245dfc58fb2631bf5fbff6342674581268ea70571b14`.
    - No dependency changed (zbus features unchanged), so deny/vet were not
      rerun.
  - **Still pending:** Android instrumentation on the phone, the
    fresh-context review, and the owner's acceptance on Linux and the phone.

- 2026-11-05 (owner acceptance, "can't create a vault"): Reproduced on the
  real desktop binary under a private Xvfb with a fresh profile, then fixed:
  - **Silent failure with an existing vault:** with the device vault present
    and no file chosen, Create targeted the existing file and failed; the
    wizard returned to step one and the error sat on the hidden step. Step
    one now asks "Choose where to save…" (or, with the typed fallback,
    disables Continue until a path is typed). Errors show on the visible
    step.
  - **Locked screens did not redraw on input:** `Locked` was keyed on the
    workspace revision, not the snapshot change counter, so typed paths and
    cleared errors never reached the screen. It now takes the change counter,
    and path/password inputs advance the revision.
  - **Consent did not continue:** "I understand, continue" now runs the
    action that opened the sheet.
  - **Mismatched repeat:** `Controller::repeat_mismatch` (constant-time,
    returns one bit) disables Create with a hint, so a typo no longer
    submits and wipes the form. Submit still checks both values.
  - **Messages and focus:** a missing file dialog reports
    `AppError::NoFilePicker` instead of the generic protection message; the
    vault name field is focused.
  - **Gates:** fmt, SPDX, matrix, `git diff --check`; workspace, validation
    and Android arm64 (mobile, mobile,validation) Clippy pass;
    `cargo test -p qv-app` 45 passed; with `validation` 46 plus the 3
    real-engine flows passed. Full suite: see the next entry.

- 2026-11-05 (owner acceptance, round 2: "can't click anything after
  unlocking", GTK bar still present, "Create anyway" hover). The previous
  entry's full-suite run passed on its tree. Reproduced with real X input
  (xdotool) on the desktop binary, then fixed:
  - **Shell unclickable:** `inert: pending.is_some()` rendered
    `inert="false"` on the shell and tab bar whenever Dioxus wrote the false
    value (it is not a Dioxus boolean attribute; timing-dependent, so it
    showed up intermittently). Any `inert` attribute disables the subtree. A
    temporary on-screen probe showed `DIV.shell=false, NAV.tabbar=false`
    with clicks dead; with the attribute omitted when false, three repeat
    runs showed none and clicks worked. The probe was removed.
  - **OS title bar:** the window never disabled decorations;
    `with_decorations(false)` is now set. Under Xvfb `_MOTIF_WM_HINTS`
    reads `0x2, 0x0` (no decorations); a desktop with a window manager is
    needed to see it.
  - **Danger hover:** `.btn:hover:enabled` outranked `.btn.danger`, so
    "Create anyway" turned dark on dark; it now keeps its colour.
  - **Typed text dropped or reordered:** Dioxus treats `value` as volatile
    and writes it every render, so a render racing newer keystrokes
    overwrote them. Controlled inputs (`items::Input`, the command bar) now
    render `initial_value`, keep what was typed, and remount only for a value
    the user did not type (`items::Echo`).
  - **Autofocus never worked:** HTML `autofocus` applies only at page load,
    and Dioxus `set_focus` runs through `new AsyncFunction`, which the CSP
    forbids. `app.js` now focuses inserted `[autofocus]` controls and the
    app root when nothing is focused (keyboard shortcuts need it); the dead
    `set_focus` call was removed. (The previous entry's "vault name field is
    focused" was not true until this change.)
  - **Smaller:** a new entry starts with an empty title (placeholder
    "Title"); saving without a title or field name says so
    (`AppError::NameRequired`); "+ Kind" field buttons work without a typed
    name (lowercase kind name); toasts sit above the edit save bar.
  - **Why the tests missed it:** the real-engine driver used `el.click()`,
    which reaches inert and covered controls. `flow.js` now clicks only after
    `reachable()` holds (enabled, not inside `[inert]`, has a box, topmost at
    its centre), and the Android `flows.js` steppers use the same check.
    Found, not fixed: with the shell bug reintroduced, the engine flow still
    passed, because the false value was not written in that run; the check
    catches it whenever the attribute is present, not deterministically.
    Real pointer and keyboard input under Xvfb (xdotool) found every bug
    above; it is not automated yet.

- 2026-11-05 (owner acceptance, round 3: "why does the group color change as
  I type a new name?"). Tile and dot colours hashed the name. They now come
  from the record ID (`icons::id_hue`), so a rename keeps the colour and
  synced devices agree. New drafts already have their random ID, so
  `qv-core` gains `EntryDraft::id_hex` and `GroupDraft::id_hex`, matching the
  handles' existing `id_hex` ("IDs are metadata, not secrets"). Owner-delegated
  choice over freezing the colour only while editing. Name hashing remains
  only for LAN device tiles, which have no record. Verified with real input:
  the new-group tile kept one colour across each keystroke of "Work", and the
  saved sidebar dot matched. Test: `id_hue_depends_only_on_the_record_id`;
  the empty-title save test now expects `NameRequired`, and the field test
  covers a "+ Kind" button with no typed name. Previous tree's full suite
  (round 2): 886 passed, 0 failed, 2 ignored; validation 49 passed.

- 2026-11-05 (owner request, not started): user-chosen group/item colours.
  Proposed: keep the colour in the existing synced `icon` text field
  (0003 §4/§5; wording amendment, no new format), with a 12-colour row plus
  "Automatic" in the edit forms. The owner will batch it with findings from
  further testing into a larger change.

- 2026-11-05 (owner acceptance, round 4: dump3/dump4). The large icon class
  `l` collided with the `.dev .l` / `.opt .l` / `.set-row .l` text column
  (`flex:1; min-width:140px`), so the "No linked devices yet" icon stretched
  over its title; it is now `ico lg`. The GROUPS "+" button's hover was a
  cramped 20 px square; it now matches the other icon buttons (26 px,
  radius 8, 14 px glyph, aligned with the counts). Both checked under Xvfb.
  Also: the command bar label sat about 1.5 px above the magnifier's visual
  centre (dump2); it is lowered 1 px (CSS only).
- 2026-11-05 (owner request: "this form smells", be innovative): a new item
  editor was prototyped before any app change, at
  https://claude.ai/artifact/4Zxts5aHzHwLgXkFWp7T5s. It has a one-box start
  that recognises sites, card numbers and names on the device; forms shaped by
  type (live payment card, Wi‑Fi join card, note page); field tools only on
  hover; one "Add a field" that infers the kind from the name; saved
  protected values shown as "Saved · Change"; and a tile colour picker. It
  awaits the owner's review and joins the batched follow-up.
- 2026-11-05 (owner approved the item-editor prototype: "Yeah this is way
  better. Let's go with that"). Revision 2026-11-05c, steps 17–20:
  - **Specs:**
    - 0009 §1.8 gains the item-editor bullet: on-device guess, protected start
      box, the limited derived displays, generated-only strength, and the
      Wi‑Fi join QR as a timed reveal.
    - 0003 gains §5.5 and the icon-row notes: the `hue:<0–11>` colour token in
      the existing `icon` text.
  - **Core:** `EntryDraft::{group, set_group}`. Handles from another session
    are refused (`StaleHandle`), and save still checks the group is live.
    Test: `draft_group_moves_on_save_and_refuses_foreign_handles`.
  - **App:**
    - `src/editor.rs` holds the rules: types and templates, guess, kind
      inference, card info, expiry, Wi‑Fi payload, colour token, and the
      type-change, move, remove and undo index remapping.
    - `src/ui/editor.rs` holds the screen.
    - New workspace input `Start`; actions `StartAs`, `SetType`, `SetGroup`,
      `SetHue`, `AddField(Option<_>)`, `AddNamedField`, `MoveField`,
      `UndoRemoveField`, `UseGenerated`; `RevealKey::WifiJoin`.
    - A typed-replacement reveal now follows further typing for its 30 s
      instead of being cleared.
    - The card number from the start box is marked `filled` and shown as
      dots, because it is not in the control.
  - **Deviations from the prototype:**
    - No strength meter for typed passwords (E6). Generated values show the
      generator's exact entropy.
    - The editor's Wi‑Fi card has no QR code. The real code is on the item
      page behind "Show join code" (30 s), because it carries the password.
    - The card number is masked while typing: it is a protected field.
    - The automatic colour stays derived from the record ID, as before, not
      from the type.
  - **Tests:**
    - 7 unit tests in `editor.rs`;
    - 7 controller tests in `editor_tests.rs` covering: the card number never
      reaching the view; sites and networks; type change with replacements;
      move, remove and undo; kind inference; `UseGenerated` never in the form,
      and the stored bit; colours and groups;
    - one icon colour test.
    - Existing tests changed only for the new start step and the capitalised
      template names (case-insensitive matching); no assertion was dropped.
  - **Flows:** `flow.js` chooses Login in the start step, uses the generator
    popover and opens the collapsed notes. It now also asserts that the
    generated value is in no input and not in the page text. Android
    `flows.js` and `PlatformTest`/`AutofillTest` were updated the same way;
    not run, no phone.
  - **Found while testing with real input under Xvfb, fixed:**
    - The popover's `row` class matched the list's global `.row` rule (which
      turns off pointer events for children), so "Use it" was dead. Editor
      classes are now `ie-`-prefixed; `.brand` was renamed too.
    - The title lost its size to `.qv input`.
    - Inner focus outlines showed.
    - Nothing was focused after the start step: the first empty field now
      takes focus.
    - `MMYY` typed without a slash was not read.
    - Phone sheets sat under the tab bar.

    Checked by real pointer and keyboard: card (start guess, face, expiry
    hint, item page), login (title from site, generator popover in both
    modes, "Generated" state), Wi‑Fi (security buttons, join QR shown with
    its countdown), field menu, colour picker, phone layout and sheets.
  - **Found, not fixed:**
    - Trash rows and autofill candidates keep the automatic colour (their core
      summaries carry no `icon`).
    - Under bare Xvfb a frameless window does not relayout when shrunk, so
      phone checks use `QV_UI_SIZE`.
    - Editor errors persist until the next input or Dismiss (existing
      behaviour).
  - **Gates on the final tree:** fmt, SPDX, matrix and `git diff --check`
    pass. Clippy passes for the workspace, for `qv-app --features validation`
    and on Android arm64 (`mobile`, `mobile,validation`). Tests:
    `-p qv-app --features validation` 65 passed (the 3 real-engine flows
    included); full suite 901 passed, 0 failed, 2 ignored. Android
    instrumentation not run (no phone).
  - **Docs:** CHANGELOG, `crates/qv-app/README.md`, specs and index.
- 2026-11-06 (owner: the automatic-locking banner "never goes away"; tool
  switches feel ~500 ms slow):
  - **Lag:** the UI redrew only when a background thread polled the
    controller every 200 ms. Each switch waited 0–200 ms, then faded in over
    260 ms.
    - The root now redraws right after any bubbled click, input or key event
      (`Redraw` context; handlers change the controller synchronously). The
      poll still covers background work and timers.
    - The fade is 120 ms.
    - Measured with an `import`-based probe whose own floor is about 120 ms.
      Before: the first change appeared 120–250 ms after the click, settling
      at about 460 ms. After: it was there at the first sample on every
      switch.
  - **Banner:** 0008 §1.4 requires the limitation "before persistent use and
    while unlocked", not a banner. The presentation is owner-delegated and
    recorded in 0009 §1.8:
    - the acknowledgement and the locked-screen protection chip;
    - while unlocked, a lasting amber mark on the lock button and its label;
    - Settings → Auto-lock "Idle only".

    Both banners were removed.
  - **Fixed:** Settings → Auto-lock claimed screen-lock/sleep locking even
    when unavailable (contrary to 0008 §1.4). The flow now checks that the
    lock mark and the Settings row agree and that no banner is shown
    (stage 82).
  - **Found, not fixed (needs the owner's system):** logind detection fails
    when `GetSessionByPID` finds no session for the app's process. That is
    common when desktop apps run in systemd user scopes. A possible fallback
    is `GetSession("auto")` (the user's display session). It is a
    lifecycle-security change, so it waits for the owner's diagnostic output
    and its own review.
  - Narrow Linux windows hide the title bar, so there the mark is missing;
    Settings still shows it.
- 2026-11-06 (owner bug: in group 1, + highlighted group 2, but the item was
  saved in group 1):
  - **Cause:** opening a form (`NewEntry`, `EditEntry`, `NewGroup`,
    `RenameGroup`) replaced the current screen without pushing it onto the
    back stack. The sidebar and the list beside the form use
    `list_context()`, the nearest list in that stack, so they showed an
    earlier list. The draft was always in the right group; Cancel also
    returned to the wrong list.
  - **Fix:** `Workspace::open_form` pushes the current screen. Saves go
    through `Workspace::land`, so editing from an entry or renaming from a
    group does not stack that screen twice.
  - **Test:** `forms_keep_the_list_they_were_opened_from` fails without the
    fix (checked by reverting it) and passes with it.
  - **Also fixed:** sidebar group dots and command-bar results still used the
    automatic colour (missed in step 19); they now show chosen colours.
- 2026-11-06 (owner: entry ⋯ menu too far away; card number unintuitive
  while typing; locked out while moving the mouse):
  - **Menus:** the entry menu (`anchor-detail`) and the group menu
    (`anchor-list`) used fixed positions. Both now open under their button
    with the editor's popover (`pop-anchor`, `menu pop end`, `pop-scrim`;
    renamed from `ie-…` as they are shared), and become bottom sheets on
    phones.
  - **Card number:**
    - The input is plain text, grouped while typing by `app.js`
      (`data-qv-format="card"`, numeric keyboard, caret kept). Rust ignores
      the spaces, and the value is still a protected replacement.
    - `CardInfo::valid` waits for the brand's full length (Amex 15, else 16).
      The start box still checks a pasted number at any length.
    - The digits now really render monospace (a broader input rule overrode
      `.mono`).
  - **Inactivity:**
    - Root handlers for mousemove and wheel never fired: the hardened bridge
      (`third-party/dioxus-desktop/src/hardened.rs`) forwards only click,
      input, change, keydown, keyup, focus and blur, by design.
    - Rather than widen it, `app.js` reports pointermove, wheel, scroll and
      touchstart as an empty input event on the hidden `#qv-activity`, at
      most once a second and without positions. It calls
      `Controller::activity`, which updates the idle clock only for the
      current epoch. Clicks and keys anywhere count too.
    - Real input under Xvfb: 75 s of mouse movement alone stayed unlocked,
      and 65 s idle then locked.
    - Test: `moving_the_pointer_postpones_the_inactivity_lock`. Spec 0009
      §1.8 gains the Inactivity bullet.
  - **Found, not fixed (same allowlist):**
    - The title bar's drag (`onmousedown`) and double-click maximize
      (`ondoubleclick`) and the editor's rename-on-focus-out (`onfocusout`)
      use events the bridge drops. Drag and maximize cannot be checked
      without a window manager.
    - Rename still closes on Enter/Esc.
