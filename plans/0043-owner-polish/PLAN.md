# Plan 0043 — Page fade, title-bar icon, protection chip, `qv` binary, logo

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — fresh review and owner acceptance pending | 2026-11-06 | 2026-11-06 (owner request; details owner-delegated, standing 2026-11-02) | 0009 §1.8 (amended); 0011 §1.1 (amended) |

## Intent

Four owner notes (2026-11-06):

1. "Fade in not working": only the Generator faded in; other section tabs
   did not. Behaviour should be consistent.
2. Poor contrast of the title-bar icon (`dump.png`).
3. Rename the `qvault` command to `qv` (changing the 2026-10-14 decision).
4. The "reduced protection" chip on the locked screen shows all the time.
   Show it at an appropriate time or hide it.

## Spec basis

| Behaviour | Spec | Notes |
|-----------|------|-------|
| Binary name | 0011 §1.1 (Accepted) | Amended to `qv` at the owner's request |
| Locked-screen protection chip | 0009 §1.8 (Draft, approved profile) | Amended: shown only while an acknowledgement is pending |
| Acknowledgement before use, mode in settings | 0008 §1.3–1.4, 0009 §1.8 | Unchanged |

## Design

1. **Fade.** `pages::Page` keyed its `.page-inner.fade-in` wrapper by the
   form epoch, which is constant for an unlocked session. A switch between
   two section pages reused the element, so the animation did not replay;
   only a switch from the vault view (a new element) faded. The token now
   includes the screen (and the Settings pane), and the wrapper is
   `ui::Remount`, a one-item keyed list (see the 2026-11-07 log: a key on a
   lone element is ignored by Dioxus), so every page switch rebuilds it. Devices' local dialog state already reset on a
   switch (different component).
2. **Icon.** `.brand .ico{color:var(--text3)}` overrode the tile's
   `color:var(--ink)`, painting a grey glyph on the accent tile. Replaced by
   `.dial .ico` (size and a slightly heavier stroke only), so the glyph uses
   the ink colour: about 10:1 in the dark theme, 4.2:1 (white on
   `#0f8f66`) in the light one.
3. **`qv`.** `[[bin]] name`, the clap command name, the `qv:` message prefix,
   hints, docs and tests. Unchanged (owner-delegated): `QVAULT_PATH`, the
   config path, the `.qvault` vault extension and the `qv/…` labels. Dated
   plan logs, spec changelog lines and earlier CHANGELOG entries keep the
   old name as history.
4. **Chip.** The locked screen renders the chip only while
   `ack_needed` (a reduced status not yet acknowledged, or a changed one).
   The gate still opens the status before create/unlock/recover; the
   acknowledged mode stays in Settings → Security → Device protection, and
   the Linux idle-only mark on the lock button is unchanged. The desktop
   flow script taps the chip only when shown and otherwise accepts either
   copy outcome.

No new dependency; no format, protocol or crypto change.

## Steps

- [x] Spec 0011 §1.1 and 0009 §1.8 amendments, changelogs, index.
- [x] Rename in `qv-cli` (code and tests), `qv-crypto` doc comment, specs
  0004/0011/0014, `ARCHITECTURE.md`, roadmap phases 3.6–3.7.
- [x] App: page key, `.dial .ico`, chip condition, `flow.js`.
- [x] `CHANGELOG.md`.
- [x] Gates; app validation flow.

## Revisions

### 2026-11-07 — Official logo

The owner added `LOGO.svg`/`LOGO.png` (AGPL header in the SVG) and asked
for it "in certain areas of the app". Placement owner-delegated:

- **Desktop window icon** (taskbar, window switcher):
  `assets/icon-256.png`, rendered from `LOGO.svg` with `rsvg-convert -w 256
  -h 256`, decoded by the vendored `dioxus_desktop::icon_from_memory` (its
  existing `image`/png dependency; no new crate). A decode failure keeps the
  framework default.
- **Android launcher icon:** the manifest names `@mipmap/ic_launcher` (it
  named none, so Android drew a generic icon). `android/res/` holds the
  adaptive icon: charcoal background, the mark scaled 0.14 about its centre
  into the 66dp safe circle, and the same mark as the monochrome layer.
  `build-android.sh` copies them over the template's three adaptive-icon
  files and refuses a changed template layout. minSdk 29 always uses the
  adaptive icon, so the template's density WebPs are unused.
- **Title bar:** `Logo` (inline SVG, `ui/icons.rs`) replaces the accent tile
  with the lock glyph from item 2. In the dark theme the tile equals
  `--bg`, so only the mark shows; in the light theme it is a charcoal tile.
- **Welcome (first run):** the logo replaces the safe dial. The unlock card
  keeps the animated dial, which doubles as "opening" feedback.
- **Settings → About:** logo, name and version above the licence line.

Not changed: the unlock card, phone layout chrome (Android has no title
bar) and any spec text; the logo is presentation, not behaviour.

## Execution log

- 2026-11-06: Implemented all four items as designed. One sed slip
  (`select.rs` test helper parameter tied to `QVAULT_PATH`) reverted.
  Gates: SPDX, `cargo fmt --check`, clippy `-D warnings` and
  `check-matrix.sh` pass. `cargo test --locked --no-fail-fast`: 904 passed,
  2 ignored, 2 failed — `qv-cli` `clipboard_binary_lifecycle_and_key_drop`
  and `clipboard_incr_refusals_limits_and_expiry`, which panic spawning
  `Xvfb` (not installed in this session); not a pass, environment only.
  The `--features validation` real-window flow (including the edited
  `flow.js`) needs Xvfb too and was **not run**; the next session with
  Xvfb runs `cargo test --locked -p qv-app --features validation` and the
  two clipboard tests. Not reviewed yet.
- 2026-11-07: Logo revision implemented. The APK build caught a borrow
  error in item 1's page key (computed after `screen` moved into the body
  match; the desktop check had not reported it): the key is now computed
  first. Mock screenshots of the title bar, welcome and About markup with
  `app.css` in both themes (headless Chromium) and of the adaptive icon
  under circle and squircle masks were checked. Gates below.

- 2026-11-07: Final tree gates: SPDX, fmt, clippy `-D warnings`,
  `check-matrix.sh` pass; `cargo test --locked --no-fail-fast` 904 passed,
  2 ignored, 2 failed (the same two Xvfb-dependent clipboard tests; Xvfb is
  not installed — not a pass). `build-android.sh` (dx 0.7.10, JDK 21)
  builds; `aapt2` shows `icon='res/mipmap-anydpi-v26/ic_launcher.xml'` and
  the new foreground. The APK was not installed on a phone, and the
  `--features validation` desktop flow still needs an Xvfb session.
- 2026-11-07: Owner: the fade still played only on the first switch to the
  Generator. Cause: Dioxus applies keys only inside keyed lists, so the
  lone keyed `div` was diffed in place — a probe test showed a key change
  produced no DOM edits at all (`[]`). Fix: `ui::Remount { token, class }`
  renders the wrapper in a one-item keyed list (the idiom the inputs
  already use with `for g in [generation]`). New test
  `ui::tests::remount_rebuilds_only_when_the_token_changes` (fails with the
  lone-key version, passes now). Earlier "clippy passes" lines for UI code
  were with default features, which do not compile `ui`; the
  feature-enabled checks (as in CI) now run: `cargo clippy -p qv-app
  --all-targets --features validation` clean, `cargo test -p qv-app
  --features desktop` 72 passed. Not fixed, reported to the owner: the
  same ignored lone key on `locked-body` (`key: "locked-{epoch.0}"`) and on
  `Editor { key }` in `ui/editor.rs`.
- 2026-11-07: Owner: "fix everything". The two other ignored lone keys:
  - `locked-body` now uses `Remount` with token `locked-<epoch>`. The epoch
    changes only on explicit actions (submit, lock, mode changes, the
    invalid-input clear), never per keystroke or tick, so a new epoch
    rebuilds the locked form and its DOM inputs in step with the cleared
    protected inputs, as the key intended.
  - `EditEntry` renders `Editor` in a one-item keyed list on the draft's
    record ID, so opening another entry's draft resets the editor's local
    popover, rename, add-field and notes state.
  New test `ui::tests::keyed_component_gets_fresh_state_only_for_a_new_key`
  (one mount with a lone keyed component, two with the list; checked both
  ways). Checks: fmt, SPDX, `clippy -p qv-app --all-targets --features
  validation` and default clippy clean; `cargo test -p qv-app --features
  desktop` 73 passed, default 68 passed. Default-feature workspace code is
  unchanged since the full run above (UI code compiles only with
  `desktop`). Real-window validation still needs Xvfb.
- 2026-11-07: Owner (screenshot): the group form's colour block looked
  unstyled, and asked for a "change color" entry. Cause: the shared
  `swatches` markup's label, divider and "Automatic" row are styled only
  under `.menu` (the item editor's popover); in the group form's
  `.card.ie-colours` they fell back to browser defaults. The `.menu .mi`,
  `.sub`, `hr` and `.label` rules now also cover `.ie-colours`. The group
  actions menu gains "Change colour" (opens the same group form), the form
  title reads "Edit group" for an existing group, and the swatches are a
  labelled `group` (not `menu`) outside a popover. Mock render with
  `app.css` checked in both themes. fmt, SPDX, clippy (default and
  `--features validation`) clean; `cargo test -p qv-app --features
  desktop` 73 passed.
- 2026-11-07: Owner: visible text should be American English. Changed the
  app's "Colour"/"COLOUR"/"Change colour"/"Choose a colour" to "color" and
  "Recognised" to "Recognized". "Cancelled" is kept (accepted US usage).
  Internal names (DOM ids, CSS classes, the `colour` field of 0003 §5.5)
  and project docs are unchanged.

- 2026-11-07: Owner: "Color" was uppercase beside the sentence-case "Name".
  In a form card the label now reads "Color" in the `.ed label` style;
  the item editor popover keeps its "COLOR" menu heading.
