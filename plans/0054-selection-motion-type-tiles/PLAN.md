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
