# Design brief — QuickVault app look and feel (roadmap 2.10a)

Mockups: [QuickVault App Design canvas](https://claude.ai/artifact/P1HNszVqTZFf1TWzGiJY2f)
(private to the owner). It has nine boards: four desktop windows at 1280×800
and five phone screens at 390×844. Every board has a light/dark switch in Tweaks.

## Goal

The owner's direction (2026-11-02) is that the app should feel like an
application on desktop and on the phone, not a website in a browser. Keep one
shared Dioxus codebase (0009 §1.6). Change no security behaviour or
functionality (0008 §4: input cleanup, reveal, clipboard and lock stay as they are).

## What makes it feel like a website today

- The locked screen is a landing page: hero headline in a serif display font,
  marketing "principles", radial-gradient background and a footer.
- The whole document scrolls, like a page. Chrome text can be selected, buttons
  show the pointer cursor, and there are hover effects for a mouse.
- Spacing and type sizes are page-like: large headings, wide gaps, centred cards.
- There is one layout for every size. The sidebar just stacks on a phone. There
  is no app bar, back button, bottom navigation or sheet.
- Icons are Unicode glyphs, and the colours lean on one green-on-green palette
  with no light theme.

## Direction: "quiet native"

A calm, dense, system-styled utility. It follows what users already know from
password managers and file managers on GNOME/KDE and Android.

**Window and shell**
- Desktop keeps the OS-native title bar and window controls. No custom
  client-side decorations.
- The app fills the window and never scrolls as a whole. Only panes and lists
  scroll (`overflow` on the panes; `overscroll-behavior: none`).
- Desktop ≥ 1000 px: three panes. A sidebar holds the groups and sections, then
  the entry list, then the entry detail. Above them a toolbar (vault name,
  search field, New entry, Lock); below them a thin status bar (save state,
  idle-lock note, "nothing syncs until you choose").
- 720–999 px: the sidebar narrows to icons. The list and the detail share the
  remaining width.
- < 720 px (phone, or a narrow desktop window): one pane at a time. A top app
  bar with a back arrow, the title and icon actions. A bottom tab bar with
  Vault, Generator, Devices and More; More lists the remaining sections and
  settings panes. New entry is a floating button.
- The layout comes from CSS breakpoints over one DOM. Metrics come from the
  input type (`pointer: coarse` → 48 px targets, 16 px text), so a touch
  laptop also gets touch sizes.

**Controls**
- Text is the system UI font (`system-ui`: Cantarell/Noto on Linux, Roboto on
  Android). No bundled or remote fonts, and no serif display type.
- Desktop: 13 px base, 30 px controls, 6 px radius. Default cursor everywhere
  except text fields. Focus rings only for keyboard use (`:focus-visible`).
- Phone: 16 px base, 48–52 px targets, pill-shaped primary buttons, list rows
  of 64–68 px.
- Segmented control for Unlock / Create / Recover / Join. Grouped list cards
  for fields and settings. Icon buttons with labels for assistive technology.
- Confirmations: a modal dialog on desktop, a bottom sheet on the phone. Same
  markup; the background is inert while one is open.
- Toasts for transient status (copied, clears in N s). Errors stay inline next
  to the action (`role=alert`).
- Icons: a small set of 16-unit stroke icons drawn for QuickVault, rendered as
  rsx SVG elements. No icon font, no third-party icon pack, no raw HTML.

**Colour and theme**
- The theme follows the OS (`prefers-color-scheme`), in light and dark. No
  in-app theme setting in this phase: that would need persisted settings and is
  a later feature request.
- Neutral greys with a single green accent, kept from the current brand mark.
  Selection uses an accent tint. Body text and secondary text meet 4.5:1 in
  both themes, and the danger colour is used only for destructive buttons.
- Token sets are in the mockups' `t-dark` / `t-light` blocks. The developer
  moves them into `app.css` custom properties.

**Motion**
- Phone push and pop: 160 ms slide and fade. Sheets: 200 ms rise. Desktop
  pane changes: none, or an 80 ms fade.
- No animation under `prefers-reduced-motion`.

**Keyboard (desktop)**
- Ctrl F focuses search, Ctrl N opens a new entry, Ctrl L locks, Ctrl S saves
  the open form, and Esc cancels or goes back. These are shortcuts for actions
  the app already has. Nothing new is reachable.

## Invariants (must not change)

- `data-qv-epoch`, `data-qv-clear`, `data-qv-controlled`, and the `.phrase` /
  `.revealed` classes that `app.js` cleanup depends on.
- Input bounds, `autocomplete=off`, `spellcheck=false`, protected-input
  conversion and the clearing behaviour. Reveal timers, clipboard ownership,
  lock triggers, FLAG_SECURE and the hardened webview policy and CSP. No new
  assets other than `app.css`/`app.js`, no remote loads, no
  `dangerous_inner_html`.
- The redesign never shows a secret that is hidden today (lists and
  three-pane detail show the same fields as the current entry screen).

## Alternatives considered

- **Material 3 on both platforms.** Native on Android, but foreign on a Linux
  desktop. Rejected: the owner wants an app feel everywhere.
- **Libadwaita or GNOME look on both.** Native on GNOME, but odd on Android
  and on KDE. Rejected for the same reason.
- **Custom client-side title bar.** It needs window-drag and resize hit areas
  and breaks with tiling window managers. Rejected: native decorations already
  feel like an app.
- **Separate desktop and phone UIs.** Violates 0009 §1.6 and the owner's
  "same UI everywhere" preference. Rejected.
