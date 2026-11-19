# Plan 0072 — Owner feedback batch: group color, join code, continuous list, password meter, toasts, scan to join, video seek, large images

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — gates pass; phone check and fresh-context review pending | 2026-11-19 | 2026-11-19 (owner feedback list: "do all of it"; design delegated, standing 2026-11-02) | 0003 §6.4, 0004 §7.4, 0009 §1.8 and list residency, 0010 §4.2, 0014 §6.3–§6.4; 0009 §1.8 one quick-unlock enrollment (item 10) |

## Intent

Owner feedback collected over several builds (some may predate 1.2.0), to be
fixed in one batch:

1. The group shown when creating an item has the wrong color: it must be
   the group's own color.
2. The sync/join code field needs a way to see what was typed.
3. Lists page with "Previous"/"Next". The user wants to see all entries;
   paging only as a fallback for enormous vaults. Why was it done?
4. Question: what happens when vault A is open and the user syncs vault B?
5. Show the master password's strength while typing, not only after
   submitting. The weak-password confirmation stays.
6. Toasts and similar cards should fade out instead of vanishing.
7. Scanning a join code should join; the confirmations after it are the
   point where the user can still back out.
8. Desktop video: after the end, back to the start, then a jump to the
   unbuffered end flickers until it recovers. Is the player's special
   handling still needed without Dioxus?
9. An 85 KB `LOGO.png` already in the vault opens to an empty viewer.

## Findings

1. `bridge/frame/editor.rs` colors the editor's group chip with
   `convert::id_hue(group id)`, the automatic color, ignoring the group's
   chosen color (kept in its icon text and decoded by `editor::colour`).
   The sidebar and the group picker use `item_hue(colour, id)`, so the chip
   disagrees with them whenever a group has a chosen color.
2. `lan-join-code` (locked Join screen) and the Sync screen's code field are
   masked secret inputs with no way to check them. 0014 §6.4 calls the
   field a "secret input". The typed value already lives in the input's
   DOM value; showing it changes only what is drawn.
3. 0004 §7.4 / 0009 bound the app's list residency to "current plus
   adjacent pages, at most three" of 0004's 32-row pages; the
   implementation keeps one page per lane (`page_read.rs`). The reasons:
   decrypted titles and usernames that reach the webview cannot be wiped
   reliably (0008 §1.1/§4.4), the vault may hold up to the record limit,
   and `qv-core` reads views in bounded batches without accumulating all
   plaintext (0004 §7.3). The bound itself is a sound default; Previous and
   Next were the simplest UI for it, not a requirement.
4. Answer (no change): a sync session is bound to one vault. Sync mode
   checks the vault ID and key generation (0013 §7, 0014 §2.2); another
   vault fails with `vault_mismatch` before any exchange: "The other device
   has a different vault or key generation." Nothing merges. Joining
   (new-device mode) copies the offering device's vault as a new vault
   file next to the existing ones; it never mixes vaults either.
5. The creation form rates the password only on submit (`ops.rs`
   `strength_consent`, locked create). `qv_core::password_strength` runs
   `zxcvbn`, which copies the password into ordinary `String`s that are
   freed but not zeroized; `strength.rs` documents that it runs once per
   typed master password. A live meter multiplies those copies.
6. `.toasts` children (busy, copy, error, notice) and the receipt cards
   are removed from the DOM as soon as Rust clears them; only an entry
   animation exists (`rise`, `receiptIn`).
7. `Controller::start_scanned` joins at once when the QR carries endpoints,
   except when the protection status needs acknowledgement: then it stops
   at "Code scanned. Choose Join to continue." A device being joined is
   usually a new install whose status was never acknowledged, so the
   common case stops. The pause adds nothing: Join itself would show the
   same review.
8. The special player is still needed. It exists for WebKitGTK, not
   Dioxus: playing HTTP media is buffered to an unlinked file in `/var/tmp`
   (WEBKIT W1), and since plan 0071 media elements cannot load the
   `qvmedia` scheme at all (W13). Linux therefore plays from renderer
   memory (MSE for MP4). The seek glitch needs a reproduction under the
   real engine first (step 8).
9. The `qvmedia` scheme answers each request with at most 64 KiB (0003
   §6.4); a request without `Range` gets `206` for the first 64 KiB. Media
   elements and `player.js` ask again for the rest, an `<img>` does not, so
   every image over 64 KiB is truncated and draws nothing. The validation
   image samples were smaller than 64 KiB.
10. (Owner report during the phone check, 2026-11-19.) "Joined vault"'s
   Settings said fingerprint unlock was on, but its locked screen never
   asked. The phone keeps one enrollment, bound to a vault ID and key
   generation, and it belonged to the other vault on the test copy
   (checked against both vault headers). Settings read only "is there an
   enrollment", and the post-unlock offer skips any vault while one exists
   (so it never moves another vault's silently), although 0009 §1.8 said
   "no enrollment for that vault". Older than 1.2.0 (plan 0068).

## Decisions (owner-delegated, standing 2026-11-02)

- D1 (item 2): a Show/Hide toggle on the manual code fields (join and
  sync). It flips only the input's type. The code is masked again on
  submit, scan, lock, hide and leaving the screen. No other secret field
  changes in this plan.
- D2 (item 3): one continuous, scrollable list for items, trash and
  conflicts. The main lane keeps a window of consecutive pages instead of
  one page; it loads the next page when the list's end comes into view. The
  window holds at most 32 pages (1,024 rows) and at most 8 MiB of row text.
  Vaults within it show every row, with no buttons. A full window is not
  trimmed as it scrolls, because WebKitGTK has no scroll anchoring and
  removing rows above the viewport would make the list jump. Instead "Show
  more" replaces it with the next window and "Back to the start" returns:
  the owner's fallback for enormous vaults. A vault change reloads the
  window as far as it was read before showing it, so an edit keeps the
  user's rows and place. No core API change: the window uses the existing
  cursors. Spec 0004 §7.4 and 0009 change "at most three pages" to this
  window. Groups, pickers, autofill candidates and the other lanes keep one
  page.
- D3 (item 5): a live meter under the new-password field on create, change
  and recovery (label, bits, bar). It is computed in Rust by the same
  `password_strength` after typing pauses (400 ms debounce), never per
  keystroke, and the page receives only the label and bits. The Fair
  warning shows inline live. Weak still blocks on submit with the 5-second
  confirmation. The zxcvbn copies stay a documented best-effort limit, now
  per pause instead of per submit (0008, `strength.rs`, 0010).
- D4 (item 6): toasts and receipts leave with a short fade (≈ 180 ms). The
  page keeps the leaving element's last text for that time only. A lock or
  hide removes them at once.
- D5 (item 7): when a scanned join needs the protection review, the review
  opens immediately and the join starts as soon as it is acknowledged.
  Dismissing the review leaves the filled form ("Choose Join").
- D6 (item 9): images use the same path as Linux media. The page fetches
  the route in 64 KiB ranges, under the existing own-origin CORS grant,
  into a `Blob` and shows it from a `blob:` URL. It revokes the URL and
  drops the buffer on close, navigation, lock and hide. The CSP gains
  `blob:` in img-src only. An image over 64 MiB of file bytes is not
  fetched (the 64 MiB decode-consent bound still applies first). No
  response grows beyond 64 KiB. 0003 §6.4 and 0008 §4 are amended.
- D7 (item 10): keep one enrollment per device and keep the offer
  device-wide; amend 0009 §1.8 to say so. `Session::quick_enrolled`
  compares the live binding with the open vault (vault ID and key
  generation, as the locked screen judges a closed vault). Settings shows
  "on" only in that vault; elsewhere it says off for this vault, names the
  holder and offers to enroll this vault instead, which ends the other
  vault's enrollment (the existing enroll replaces the slot). The vault
  sheet's "open vault has quick unlock" uses the same check instead of
  "no other listed vault has it".

## Steps

1. Group chip color (item 1): `item_hue(editor::colour(icon), id)`; test
   in `editor_tests.rs` with a colored group.
2. Specs: amend 0003 §6.4 (images via range fetch into a blob), 0004 §7.4
   and 0009 (list window), 0008 §1.1/§4 (img-src blob:, live strength copies),
   0010 §4.2 (live meter), 0014 §6.3–§6.4 (review then join; show toggle),
   with changelogs.
3. Join/sync code toggle (D1).
4. Scan to join through the review (D5); controller test.
5. Toast and receipt fade (D4).
6. Large images (D6): `player.js`/page image loader, CSP, Linux/Windows/
   Android; validation sample over 64 KiB.
7. Live password meter (D3): workspace and locked inputs, debounce, frame
   fields, page meter; tests for debounce, the label and cleanup on
   lock.
8. Video seek after the end (item 8): reproduce with `run-media.py` under
   the real engine, fix in `player.js` within W1/W4/W5, and record what was
   found in WEBKIT.md.
9. Continuous list (D2): page reader window, frame, page scroll triggers;
   tests for the bounds, the drop at both ends, a revision change keeping the
   position, and lock clearing.
10. CHANGELOG, gates, execution log.

## Test plan

Workspace gates, page Clippy for wasm32, app Clippy with `desktop` and
`validation`, app validation tests (real WebKitGTK) for the image and list
flows, Android Clippy, and a phone check of items 2, 3, 5, 7 and 9 by the
owner.

## Risks and stop conditions

- D2 and D6 move more decrypted text into the renderer than before. Both
  stay bounded and are recorded in 0008 as best-effort limits. Changes to
  preview transport and secret inputs need the fresh-context review before
  release.
- Stop if the video glitch turns out to be an engine fault that cannot be
  fixed: record it in WEBKIT.md instead of working around it.

## Execution log

- 2026-11-19: Findings 1–9 from code and spec reading. Item 4 answered.
- 2026-11-19: Steps 1–7. (1) `views::group_chip` gives the editor chip
  the group's own color; asserted in `colours_and_groups_are_saved_with_the_item`.
  (2) Specs 0003 §6.4, 0004 §7.4, 0009, 0010 §4.2 and *Security
  Considerations*, 0014 §6.3–§6.4 amended. (3) `SecretInput`/`Input` take
  `reveal`: Show/Hide flips the input type and masks again on
  `visibilitychange` to hidden and when the form turns busy; the join and
  sync code fields use it. (4) `View::join_review` (status `QR_READY`)
  reaches the page as `join_review`; the locked screen opens the review
  with Join queued behind it. (5) `shell::fading` keeps a leaving toast or
  receipt for 180 ms (`toastOut`, `receiptOut`); the copy toast keeps one
  element while its seconds count down instead of being rebuilt each
  second. (6) The viewer gives images `data-qv-src`; `player.js`
  `loadImage` reads them in 64 KiB ranges into a blob (≤ 64 MiB, larger
  ones get "too large to preview"), `stopMedia` drops the blob, CSP
  img-src adds `blob:`. The media flow (`run-media.py --private-runtime`,
  `qv-flow-harness`) now also loads the 67,549-byte 5000×4000 fixture
  after consent and checks it decodes from a `blob:` and loses its source on
  close: pass. Without the private audio session the flow stops at
  stage 6 (video cannot play without a sink), an environment limit.
  (7) `meter.rs` (`Rating`): the page sends `RatePassword` 400 ms after
  the last keystroke of the new password (create, change, rotation); Rust
  rates only if the input changed and the page receives label and bits.
  This also removes a per-keystroke `zxcvbn` run that the workspace's
  Fair warning did before. Tests: `meter` unit tests,
  `create_rates_the_new_password_only_when_asked_and_drops_it_on_lock`,
  the password-change workspace test.
- 2026-11-19: Step 8. Reproduced under Xvfb (private PipeWire session,
  compositing) by recording the display with `ffmpeg x11grab` and
  measuring the video area's mean luma per frame. A seek outside the
  buffered data rebuilt the MediaSource (`restart` → `loadBlob`), which
  reloads the element (`emptied`) and can blank the picture for 50–100 ms
  before the target's first frame; the owner's case (after the end, back to
  the start, then a paused jump to the unbuffered end) goes through it.
  `restart` now moves the read position to the fragment before the target
  and appends there in the same MediaSource (a turn counter discards a
  window that was loading during the seek; a seek before any data updates
  the pending start). Old data is removed only after the new data is in, so
  the buffer is never emptied (W5). The media flow counts `emptied` across
  a forward jump to 70 s and a paused jump back to 10 s (stage 95) and
  requires none, plus the chosen frame before Play and moving frames
  after. Recordings: the old player blanked on the paused far jump in one
  of two runs, the new one in neither. The replay-after-end rebuild (W4)
  still shows a one-frame blank; recorded in WEBKIT.md as a limit, not
  masked. Note for later runs: `player.js`, `app.js` and `app.css` reach
  the binary only through `crates/qv-ui/build.sh` (`dist/ui`); editing
  `assets/` alone tests the old copy. Media flow with this change: 4/4
  compositing-free runs plus 1 compositing run passed in the final series;
  across all runs of the change 6 of 8 software-mode runs passed, the two
  failures at stages it does not touch (a stage 5 open timeout and stage
  74, the long-GOP replay); the unchanged player passed 3 of 3 in the same
  setting.
- 2026-11-19: Step 9. `page_read.rs`: the main lane's slot keeps the
  window's pages (`parts`) and shows their merged view; `page_turn` on a
  windowed list (items, trash, conflicts) appends the next page while
  there is room (32 pages, 8 MiB of row text), replaces a full window with
  the next one ("Show more"), and Back returns to the start. A revision
  change reloads the same list up to the pages it had (`fill`), keeping the
  old rows on screen undimmed until the whole window is back; a failed
  refill shows what it has. Other lists keep page-by-page turning.
  `PageNav` gains `window` and `more`; `PageNavBar` renders a
  `[data-qv-more]` sentinel ("Loading more…") that `app.js` presses when
  it comes within 800 px of the viewport (on scroll, resize and DOM
  changes), or the two fallback buttons. Tests: window growth, refill after
  an edit, stale callbacks and lock clearing
  (`the_item_window_grows_as_the_list_scrolls_and_keeps_its_rows_across_an_edit`),
  the fallback with a one-page bound
  (`a_full_window_is_replaced_by_the_next_and_back_returns_to_the_start`),
  the page and text bounds (`the_window_is_bounded_by_pages_and_by_row_text`);
  the old replace test now runs on a groups list. Real engine: the media
  fixture holds 41 rows and its flow (stage 60) scrolls the list's end into
  view and requires all 41 rows and no Previous/Next: pass. Follow-up, not
  done: the list re-renders every row when a page arrives (unkeyed, as
  before); keyed rows would make appends cheaper on a phone with a large
  vault.
- 2026-11-19: Step 10, gates on the final tree: `check-spdx.sh`,
  `check-matrix.sh`, `cargo fmt --check` pass; workspace
  `cargo clippy --all-targets --locked -- -D warnings` passes;
  `cargo test --locked` 1,110 passed, 0 failed, 8 ignored. Page Clippy for
  wasm32 and the page build pass. App Clippy with `desktop` and
  `validation` (all targets) passes; `cargo test -p qv-app --features
  validation` 127 unit tests and the 3 real-WebKitGTK runs (boundary
  harness, full flow, real Linux services) pass under Xvfb with
  `RUST_TEST_THREADS=1`; `--features desktop --lib` 126 pass. App Clippy for
  `aarch64-linux-android` (`mobile`, `mobile,validation`) and
  `x86_64-pc-windows-gnu` (`desktop`, all targets) passes. Media flow
  (`run-media.py --private-runtime`): pass, with the list, image and
  far-seek stages. No dependency change (`Cargo.lock` untouched).
  Not done here: the phone check of items 2, 3, 5, 7 and 9 and the
  fresh-context review (preview transport, secret inputs and the list
  window touch 0008 boundaries).
- 2026-11-19 (item 10, D7): 0009 §1.8 amended. `Session::quick_enrolled`
  (qv-core), `Controller::quick_holder`, Settings' line and card
  (`#quick-elsewhere`, `#quick-move`), the vault sheet's open-vault mark.
  Tests: `dismissal_and_another_vault_keep_the_enrollment` (core: the open
  other vault is not enrolled, a locked session names none) and
  `quick_unlock_is_offered_after_a_password_unlock_and_prompts_on_return_only`
  (app: the second vault names the holder, a password unlock offers
  nothing, enrolling from its Settings moves the enrollment).
