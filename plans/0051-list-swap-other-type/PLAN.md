# Plan 0051 — No list flicker on filter change; fixed item types with Other

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — fresh review pending | 2026-11-11 | 2026-11-11 (owner request; design owner-delegated, standing 2026-11-02) | 0003 §5.1 (amended); 0009 §1.8 (amended) |

## Intent

Two owner notes (2026-11-11) after the 0046–0050 security work:

1. Choosing a type (Logins, Notes, Cards) or a group in the sidebar flickers,
   "as if loading from a web server". It should swap smoothly.
2. Add an "Other" item type, since items need not be one of the standard
   types, and make Wi-Fi a visible type too ("Other" and "Wi-Fi").

## Cause of the flicker

0047 moved every list to bounded page reads (`page_read.rs`). A new request
(other filter, other query, or a new vault revision after an edit) calls
`Slot::request`, which drops the ready page. Until the worker returns, the
list pane shows the "Loading items…" empty state with a zero count, and
`PageNav` inserts a "Previous · Loading… · Next" bar because it is shown
whenever `loading` is set. Both disappear a few milliseconds later: a
blank-and-shift on every click. The sidebar's TYPES heading also exists only
once the kinds page has arrived, so its rows can pop in.

## Design (owner-delegated, standing 2026-11-02)

- **Keep the last page until the next one is ready.** When a page slot
  gets a new request (other filter, query, cursor or vault revision), its
  ready page moves to `held` instead of being dropped, and reads return it
  marked `stale` while the request loads. The result (or an error) drops it;
  lock, owner change and release clear it with the slot. It takes `ready`'s
  place, so each lane still holds one page (0009 §7). Holding it in the UI
  hook instead was rejected: it would keep a fourth page resident.
- **Swap the whole list at once.** The list pane keeps the screen that
  produced the held page, so its title, count, group header and rows change
  together when the new page lands, while the sidebar highlights the new
  choice at once. If a load takes over 250 ms the held rows dim and stop
  taking clicks (pure CSS delay, so quick loads show no transition at all).
- **No transient page bar.** `PageNav` shows only when the page has a
  previous or next page; "Loading…" appears in it only while turning pages.
- **Delayed first-load text.** The first mount's "Loading items…" fades in
  only after 250 ms.
- **Fixed types.** The sidebar always lists the five types of the new-item
  picker, in its order: Logins, Cards, Wi-Fi, Notes, Other, each with its
  exact count (zero included), so the section never changes shape. "Other"
  holds every entry whose lowercased type hint is not `login`, `card`,
  `wifi` or `note`, including an empty hint (0003 §5.1: unknown hints show as
  one bucket). The new-item picker's "Something else" becomes "Other"; it
  still stores `custom`.
- **Core buckets.** `kinds_page` returns these five buckets (`login`,
  `note`, `card`, `wifi`, `other`) with exact counts instead of every
  distinct hint, and `ItemFilter::kind == "other"` selects the Other bucket.
  The app cannot compute an exact Other count from paged distinct hints
  without accumulating pages, which 0009 §7 forbids.

- **Popovers off the list's and sidebar's lanes.** The command bar used
  the main lane, and the group pickers (selection "Move to", editor, Move
  screen) used the groups lane, so each preempted the list or the sidebar's
  groups: they blanked while it was open and reloaded when it closed. They
  now read in the third lane (renamed `Overlay`, which the autofill link
  search already used this way). The sidebar's type counts share it and
  survive preemption because the shell keeps just the five numbers, no page
  text. Still three page slots.

Rejected: a timer that shows a spinner after a delay (adds re-renders and a
new transient state); keeping zero-count types hidden (the section would
still change shape and Wi-Fi/Other would stay undiscoverable); bucketing in
the app (needs every kinds page).

No storage, wire, crypto or secret-handling change. Held rows are the same
display summaries already on screen, dropped with the component or on lock.

## Steps

1. Spec amendments: 0003 §5.1, 0009 §1.8 list text.
2. Core: bucket `Scope::Types` and the kind filter; update paging tests.
3. App: held page in the slot, stale swap in the list pane, `PageNav`,
   fixed sidebar types, "Other" naming, CSS delays.
4. Tests and gates; CHANGELOG, plans index.

## Execution log

- 2026-11-11: steps 1–4 implemented. Gates on the final tree: SPDX, matrix,
  `cargo fmt --check` and `cargo clippy --all-targets --locked -- -D warnings`
  pass; `cargo test --locked --no-fail-fast`: 1010 passed, 2 failed. The two
  failures are `qv-cli` X11 clipboard tests that need Xvfb, which this
  machine lacks; they don't touch this change. New tests: core bucket counts
  and the `other` filter (`paging_tests.rs`), and held page/stale/lock
  clearing (`page_read.rs`). Not yet run in the real app window or on a phone.
- 2026-11-11 (owner: "fix this stuff as well"): popovers moved to the
  overlay lane; type counts kept as numbers; test that an overlay read leaves
  the list's page alone. The X11 clipboard tests ran with an Xvfb unpacked
  into the session scratchpad (`QV_TEST_XVFB`). Final tree: SPDX, matrix,
  fmt and clippy pass; `cargo test --locked --no-fail-fast`: 1012 passed,
  0 failed. Real app window and phone not yet checked.
- 2026-11-12 (owner's phone, owner present): built the ordinary APK with
  pinned dx 0.7.10 (APK SHA-256 `0730853d…a8ac`); same package and signer
  as installed, so `test-android.sh` updated `org.quickvault.app` in place.
  `PlatformTest` failed at "mode 1": the app's leftover `test` vault
  (owner: no real vault on the phone) offered fingerprint unlock first, as
  recorded in 0048. Re-run in the isolated `org.quickvault.validation49` UID
  (0049 packager): the vendor ROM blocked the instrumentation's activity start until
  That vendor app-op was allowed for that package; then it failed at "initial
  password form ready" because a fresh app opens on "Welcome to QuickVault"
  with no password field. `PlatformTest` (last changed 2026-11-07) predates
  that first-run screen, so neither run reached this plan's screens. This is
  not a pass. Isolated pair uninstalled. The ordinary app on the phone runs
  this build for the owner's manual check.
