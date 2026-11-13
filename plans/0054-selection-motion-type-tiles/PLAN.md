# Plan 0054 — Selection motion, type tiles, quieter file cards, stable selection rows

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — fresh review and owner acceptance pending | 2026-11-13 | 2026-11-13 (owner request; details owner-delegated, standing 2026-11-02) | none (visual only) |

## Intent

Four owner notes (2026-11-13):

1. Choosing groups, item types and similar feels bland, not "app-like";
   perhaps the lack of animation.
2. The circle inside the attachment cards is too much (`dump.png`).
3. Idea: show an item's type in its tile (a network symbol, a login
   symbol, …) instead of the title's initial.
4. Entering list selection makes every row taller; rows should keep their
   size.

## Spec basis

Visual presentation only. No spec names the list tile's content (plan 0040
step notes called it a monogram); no behaviour, format, protocol or crypto
change and no new dependency.

## Design

1. **Motion on choice** (CSS only; the global `prefers-reduced-motion`
   rule already disables all of it):
   - Sidebar `.nav`: background and colour transitions, so the old choice
     fades out while the new one fades in; an accent bar at the left edge
     springs in on the chosen item; its icon (or group dot) pops once;
     a slight press scale.
   - Phone tab bar: the active pill grows in from the centre and the icon
     pops, as in Material 3 navigation bars.
   - Chips, segmented controls, list rows and the editor's type cards:
     background/border transitions and a press scale.
   - Selection: the row tick pops in when selection starts, and a picked
     row's background transitions.
   No remount or list animation is added: list swaps keep the plan 0051
   no-flicker behaviour, and typing a filter does not animate rows.
2. **File cards:** the hard-edged 72 px disc becomes a soft radial glow in
   the top-right corner, drawn under the content (`::before`), slightly
   brighter on hover.
3. **Type tiles:** list rows, the entry header and the command bar show the
   type glyph already used by the sidebar and the editor's colour tile
   (login key, note, card, Wi-Fi). Items of type *Other* keep the
   monogram (owner-delegated): one generic glyph on every custom item says
   nothing, while the letter still tells them apart. `EntryRow` carries the
   type bucket (`&'static str`, one of `TYPE_BUCKETS`) instead of
   `ItemRow` carrying a copy of the lowercased hint; the list's subtitle
   fallback reads the bucket as before.
4. **Selection row height:** the selection tick used the class `check`,
   which is also the generic checkbox-label class (`margin:12px 0`,
   `line-height:1.5`), so each row grew by 24 px. The tick is now
   `tile tick`.

## Steps

- [x] `views::EntryRow::kind` (bucket); drop `ItemRow::kind`; rows, entry
  header and command bar use `icons::entry_glyph`.
- [x] Rename the selection tick class; CSS motion, glow and tile glyph sizes.
- [x] `CHANGELOG.md`, plan index.
- [x] Gates.

## Revisions

### 2026-11-13 — New logo

The owner asked for a new logo ("be creative, make it nice and
recognizable"). Explored with the owner over five rounds on a comparison
page; design details owner-delegated.

- **Chosen mark:** a vault door with two hinges. Its combination dial is
  cut out of the door and turned 42°, so the ring and a short rounded tail
  crossing it form a Q; the dial hub is the Q's centre. Same charcoal tile
  (`#0E1113`) and mint (`#43D4A4`) as before.
- **Owner refinements:** the dial was the owner's idea (turn it until the
  cut reads as a Q); the tail is the owner's "rounded, reaching inside the
  inner circle", the same thickness as the ring; the owner dropped the
  dial's index mark as visual overload.
- **Ruled out:** a first install, a vault handle wheel, read as a ship's
  helm. Rounded stick tails read as a magnifying glass; a pointed door as a
  chat bubble; a bolt as a power app; a plain padlock had no identity. A
  padlock Q and refinements of the original logo stayed as options.
- **Small cut** (`LOGO-small.svg`): at 32 px and below the ring, tail and
  hub are heavier so the tail survives at 16 px. The title-bar logo (26 px)
  uses it.
- **Geometry:** the ring-and-tail cut is computed as an exact outline
  (circle and stadium intersections), so the door is one even-odd path and
  needs no SVG mask; Android vector drawables have none, and the launcher
  foreground doubles as the monochrome layer. Rendered against the masked
  design: the full mark differs by 3 anti-aliased pixels at 512 px.
- **Files:** `LOGO.svg`, `LOGO-small.svg`, `LOGO.png` (2048 px),
  `assets/icon-256.png`, the `Logo` component (`ui/icons.rs`) and the
  Android adaptive foreground (scale 0.16; the farthest point is 31.3dp
  from the centre, inside the 33dp safe circle).

No behaviour, spec or dependency change.

## Execution log

- 2026-11-13: Implemented as designed, except the row press scale: a
  transform on `.row` would make it the containing block of its fixed menu
  scrim, so rows only transition their background.
- 2026-11-13: First handoff was wrong: the workspace gates do not build
  `qv-app`'s `desktop` feature, so the UI never compiled (a leftover tuple
  pattern in `items.rs` and a stray doc comment). The owner caught it; both
  fixed.
- 2026-11-13: Gates on the final tree: `check-spdx.sh`, `check-matrix.sh`,
  `cargo fmt --check`, workspace Clippy, and qv-app Clippy with
  `--features validation` and `--features desktop` pass. `cargo test -p
  qv-app --features validation`: 104 unit tests pass; the 3 real-engine
  flows (`tests/engine.rs`) did not run. Full workspace tests were stopped
  at the owner's request and not repeated. CI rerun and the owner's visual
  check are pending.
- 2026-11-13 (owner note, `dump.png`): **Key icon.** Its closing arc (radius
  3) could not reach its end point, about 6.9 units away, so renderers
  enlarged it: a lumpy, off-centre head with the shaft and teeth folded
  over each other. Redrawn: a radius-3 ring, a 45° shaft and two teeth.
  The other 43 icons were rendered and checked; none has the fault.
  `cargo fmt --check` and qv-app `desktop` Clippy pass.
- 2026-11-13: New logo installed (see Revisions): first the vault wheel,
  then, after the owner's critique, the vault door Q. `check-spdx.sh`,
  `cargo fmt --check` and qv-app Clippy (`validation`, `desktop`) pass on
  the final logo. Rendered at 256, 96, 48, 32, 24 and 16 px. Not run:
  tests and an Android build; the launcher icon awaits the next phone
  build.
- 2026-11-13 (owner note): **Selection bar height.** On desktop, starting a
  selection pushed the rows down 4 px: the list head is 54 px (14 + 30 +
  10) but the selection bar was 58 px (8 + 6 + 30 + 6 + 8 margins and
  padding). Its bottom margin is now 4 px, so it is 54 px with its buttons
  centred at the same 29 px as the head's. CSS only; the phone layout,
  where the bar floats, is unchanged.
- 2026-11-13 (owner note): **Tick flash.** Starting a selection briefly
  flashed every row's tile: the tick tiles entered with `pop`, which fades
  from opacity 0, so their border and fill blended with the row background
  as they appeared. They now enter with `tickIn`, a scale-only grow
  (0.88 to 1) at full opacity. CSS only.
- 2026-11-13 (owner note, frame capture): **Tick flash, actual cause.** The
  flash frame showed each tick still in its item's hue with a light border.
  Dioxus reused the item tile's `span` for the tick (same tag, class
  changed), so the tick's `background`/`border-color` transitions animated
  from the hue and `currentColor` to the tick's grey. The scale-only entry
  above helped only slightly. The tick is now an `i`, so the node is
  replaced and has no previous colour; leaving selection is fixed the same
  way.
- 2026-11-13 (owner note, `dump.png`): **Command bar label.** In a narrow
  window the title bar's "Search or run a command" wrapped onto three lines
  and overflowed the bar. The label now stays on one line and truncates
  with an ellipsis, the shortcut badge keeps its size, and below 760 px of
  app width the badge is hidden to give the label room. CSS only.
- 2026-11-13 (owner note): **Tile grows on hover.** The open row's tile
  grew only once opened, so a click visibly moved it. On hover-capable
  devices the hovered row's tile now grows too, so opening keeps its size.
  CSS only.
- 2026-11-13 (owner notes): **Preview, back link, copy notice.**
  - The viewer root had class `v-{tone}`, so an image preview's root was
    also `.v-img`, the image wrapper's class: the full-screen backdrop got
    the wrapper's `imgIn` zoom (owner: "the dark background zooms in") and
    its sizing rules, and scaling a full-window layer is the likely cause
    of the UI-wide flash on open. The root now uses `tone-*`; the backdrop
    only fades in (`viewerIn`), and the image keeps its own small zoom.
  - Desktop has no phone bar, so Attachments, History and a history version
    had no way back. They now start with a desktop-only "Back" link.
  - Copying set a notice ("The clipboard clears when the countdown ends")
    next to the countdown toast; the notice and its cleanup are removed.
- 2026-11-13: The app's real-engine validation flows (3) and 104 unit tests
  pass on the final tree under a private Xvfb.
- 2026-11-13 (owner note): **UI-wide text flash on opening a preview.** The
  backdrop fix did not cover it. Cause: opening a preview runs an operation,
  the shell disables every action at once (`ShellView::busy`, by design),
  and `.qv button:disabled{opacity:.45}` dimmed them all immediately, so
  the sidebar, title bar and list blinked for any quick operation. Disabled
  controls now dim with a 300 ms transition delay (`BUSY_SHOWN_AFTER`):
  quick operations re-enable them first, long ones dim as before, and
  controls rendered disabled are dim from the start. CSS only; the
  reduced-motion rule disables the delay (and so keeps the old behaviour)
  for those users.
