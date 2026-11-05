# Plan 0040 — App design: application look and feel (roadmap 2.10a)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — owner review and phone instrumentation pending | 2026-11-04 | 2026-11-04 (step 1: standing approval, roadmap 0002; steps 2–8: owner delegated D1) | 0009 §1.6; 0008 §4 (unchanged) |

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

None.

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
