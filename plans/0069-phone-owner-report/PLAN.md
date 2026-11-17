# Plan 0069 — Phone owner report: updates, paste, background, groups, copy

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — gates pass; phone check and fresh-context review pending | 2026-11-17 | 2026-11-17 (owner report; "fix these, don't ask"; design delegated, standing 2026-11-02) | 0004 §7.3, 0008 §1.4, §3, 0009 §1.8, §7 |

## Intent

Owner report from daily phone use:

1. Updating 1.0.0 → 1.1.0 from the GitHub APKs fails with "App not
   installed as package conflicts with an existing package".
2. Groups should be ordered by name.
3. Leaving and quickly re-entering the app sometimes leaves a screen that
   neither locks nor reacts to taps.
4. Switching to another app and back must not lock while the inactivity
   time has not run out.
5. Nothing can be pasted into input fields.
6. Copying an empty or missing field reports that the clipboard is
   unavailable.
7. The inactivity lock should be 5 minutes instead of 1.

The owner asks to weigh UX against near-zero security gains, and to fix
anything else found along the way without asking.

## Findings

1. Both published APKs are signed by the same certificate (SHA-256
   `cdc07ce9…49ef1`, v3 scheme) and their manifests are identical apart
   from `versionName`, but both carry `versionCode=1`: Dioxus 0.7.10's
   Gradle template hard-codes `versionCode = 1`, and `build-android.sh`
   never set it. Every release therefore claims to be the same build;
   package installers and update tools need a higher `versionCode` for an
   update, and some installers refuse the same code with this "conflicts"
   message. A copy installed by a development build (debug key) would also
   conflict; that can only be undone by uninstalling once.
2. Paged child listings (`Scope::Children`, `GroupItems`, `Groups(Some)`)
   sort groups by the stored fractional `order` key. No client edits it:
   new groups are appended, so siblings appear in creation order. 0004 §7.3
   pins "group order/ID".
3. (Corrected 2026-11-17: the owner reports the freeze in 1.1.0, so plan
   0068's redraw retry is not the cause; the first version of this finding
   was wrong.) The page renders through the vendored hardened edit
   websocket. Rust sends one batch at a time and does not run the virtual
   DOM again until the page acknowledges it; the page applies a batch and
   acknowledges on its next animation frame, which Android pauses in the
   background. If the socket closes in between, the stock client
   (`dioxus-interpreter-js` `native.ts`) reconnects and later acknowledges
   on whichever socket is then current (throwing while it is still
   connecting, the exception plan 0045 saw over DevTools), while Rust
   resends the unacknowledged batch on the new connection. The page then
   applies the same batch twice, which breaks its element table: later
   edits fail, taps reach Rust but the screen never changes and the lock
   screen never appears. Plan 0045 removed one cause of the socket closing
   (a server timeout); any other close still triggers this. No deadlock
   found: core never calls back into the app while it holds a session
   lock, and lock callbacks run without the platform lock.
4. `AndroidPlatform::update` raises `BackgroundExpired` as soon as the
   activity is not in the foreground (0008 §1.4 "mobile background
   expiry", implemented as zero time).
5. `MainActivity` makes the WebView not long-clickable and consumes its
   long click. That disables Android's text selection and its Paste
   toolbar in every field. No spec or plan records a reason; the page's
   CSS already makes everything except inputs and notes unselectable, rows
   use their own 450 ms hold, and the page cancels copy/cut. On Linux the
   hardened WebKitGTK view suppresses every context menu, so right-click
   Paste is missing there too (Windows keeps WebView2's menu).
6. A copied empty value is sent to the platform; any hold failure,
   including `ClipboardReplaced`, shows "no supported clipboard was found
   on this system". 0008 §3 requires replacement to be reported
   separately from expiry. A row's quick copy with no such field does
   nothing.
7. The 60 s limit is a literal in `Controller::snapshot` and `lan.rs`.

## Design (delegated by the owner, standing 2026-11-02)

1. `build-android.sh` sets `versionName` to the workspace version and
   `versionCode` to `major·10000 + minor·100 + patch` (minor and patch
   below 100; refuse otherwise), checks the template has exactly one of
   each, and verifies both in the badging. 1.1.0 → 10100; 1.0.0 shipped as
   1, so every later release updates over it. `docs/RELEASE.md` says so.
2. Child groups sort by lowercase name, then record ID, like search and
   the all-groups scope; the stored `order` field is unchanged (formats
   frozen, 0015) and leaves the cache label. 0004 §7.3 amended.
3. Numbered batches (vendored `edits.rs`/`protocol.rs`, hardened mode
   only): Rust prefixes each frame with its batch number (u64, little
   endian) and resends an unacknowledged batch with the same number; the
   hardened bootstrap replaces the interpreter's `waitForRequest` so each
   number is queued once, the acknowledgement goes on the connection that
   carried the batch and only while it is open, and a superseded socket
   does not reconnect. Design 4 also removes the lock (and its large edit
   batch) from short app switches.
4. Background expiry becomes a limit: `AndroidState` carries the time the
   activity has been in the background by the boot clock
   (`SystemClock.elapsedRealtime`, which counts deep sleep and frozen
   time), and `AndroidPlatform::with_background_limit(limit)` makes
   `BackgroundExpired` fire only once that time reaches the limit
   (default zero: the old immediate behaviour). The app passes its
   inactivity limit (5 minutes). The app's own inactivity timer keeps
   running in the background, so whichever ends first locks. Screen lock,
   screen off and lost protection still lock at once. A device that slept
   while the app was in the background counts as a screen lock: on resume
   the activity compares the boot clock with uptime since the pause and
   records a screen event when they differ by more than a second, so a
   screen-off broadcast delayed by the cached-app freezer cannot be
   missed. Deferrals (clipboard hold, picker, scan permission) keep
   deferring expiry. Returning to the app is not activity.
   Device tests that used a pause as a lock gain
   `MainActivity.qvExpireBackground()`, which ages the current background
   period past any limit (it can only make a lock happen sooner).
5. The WebView's long click is restored (selection, Paste toolbar). Copy
   and cut stay cancelled by the page. Linux: the hardened WebKitGTK
   context menu is shown only on editable targets, with only Paste, Delete
   and Select All; elsewhere it stays suppressed (vendored
   dioxus-desktop patch, documented in `third-party/README.md`).
6. Copy of an empty or missing value shows the notice "Nothing to copy:
   this field is empty." (notes: "…this item has no notes."), never
   reaching the platform. `ClipboardReplaced` ends the countdown with the
   notice "The clipboard now holds something else, so QuickVault left it
   alone."; other hold failures show "Copying did not work. Try again."
   The "no supported clipboard" error remains for a missing backend.
7. One `workspace::IDLE` (5 minutes) for the controller, LAN waits and
   the Android background limit; the phrase and picker limits stay 5
   minutes (no longer longer than the base). UI copy and README updated.

Rejected: keeping a short separate background grace (the owner asked for
the inactivity time); a native paste button (the system toolbar already
offers it once long click works).

## Spec basis

Owner instruction amends: 0008 §1.4 (background expiry is the inactivity
limit, sleep counts as screen lock), 0009 §1.8 (5-minute inactivity,
background, paste, copy notices), 0009 §7 (LAN prompts clear on background
expiry), 0004 §7.3 (group order by name). No format, protocol or crypto
change; the stored `order` field keeps its meaning.

## Steps

1. [x] Specs: 0004 §7.3, 0008 §1.4, 0009 §1.8/§7, Changelogs, index.
2. [x] Android version code in `build-android.sh`, `docs/RELEASE.md`.
3. [x] qv-core paging: groups by name; tests.
4. [x] qv-platform Android background limit; tests. Kotlin background
   clock, sleep detection, `qvExpireBackground`, long click; Rust poller.
5. [x] qv-app: `IDLE`, background limit wiring, copy notices and errors,
   UI text; tests; device tests updated.
6. [x] Linux editable context menu (vendored dioxus-desktop) and its
   focused test; `third-party/README.md`.
7. [x] Gates; CHANGELOG, README, plans index.
8. [x] Numbered edit batches in the vendored hardened transport (finding
   and design 3, corrected), with a reconnect regression test.

## Test plan

- qv-platform: background below the limit never locks; reaching it locks
  once; screen lock and lost protection stay immediate; a deferral still
  defers; zero limit keeps the old behaviour; watch() at registration
  follows the limit.
- qv-core: siblings listed by name regardless of creation order.
- qv-app: empty field copy and missing field give the notice and start no
  hold; replacement gives its notice; inactivity uses 5 minutes.
- `sh crates/qv-app/scripts/build-android.sh` only if the SDK is present
  (badging check covers the version code); device tests updated for the
  owner's phone run.
- Gates: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked`, qv-app `--features desktop`/`validation` clippy,
  `sh scripts/check-matrix.sh`, the vendored focused tests.

## Risks

- Background expiry is weaker by design (owner decision): an unlocked
  vault stays open in the background up to 5 minutes. Screen lock still
  locks; FLAG_SECURE keeps the recents preview blank.
- A delayed screen-off broadcast after the freezer could show the vault
  for a moment before locking if the device did not sleep; the sleep
  check covers the long case.

## Revisions

- 2026-11-17, during implementation (design delegated): copy and cut are
  allowed in plain (non-password) text fields being edited, so the
  selection toolbar's Copy is not another dead end; shown values and
  password inputs still copy only through the app's clearing clipboard.

- 2026-11-17, owner correction: the owner already ran 1.1.0 (after
  uninstalling it from the main and a second profile) and it still froze.
  Finding 3 and design 3 replaced above; step 8 added.

## Execution log

- 2026-11-17: findings and design above; both release APKs downloaded and
  compared with `apksigner`/`aapt` (same signer, `versionCode=1` in both).
- 2026-11-17: steps 1–7. Specs 0004 §7.3, 0008 §1.4, 0009 §1.8/§7 and
  the index amended. `build-android.sh` derives `versionCode`/`versionName`
  (checked against the generated template: 1.1.0 → 10100) and verifies them
  in the badging; `docs/RELEASE.md` explains. qv-core groups sort by
  lowercase name in every scope; the cache label drops the order key.
  qv-platform `with_background_limit`; the activity reports boot-clock
  background time, counts sleep in the background as a screen event and
  keeps the WebView long click; the poller passes the time; the app uses
  `workspace::IDLE` (5 minutes) for inactivity, LAN waits and the limit.
  Copy: empty/missing values and missing notes give notices; replacement
  gives its notice; other failures `ClipboardFailed`. Linux editing-only
  context menu in the vendored dioxus-desktop. Device tests: pauses that
  stood for a lock now call `qvExpireBackground()`; a short background is
  checked to keep the vault and a typed form.
  Tests that pinned creation order (CLI `ls`, core listing, the golden
  description text and the offline lifecycle) now expect name order; the
  golden vault/archive files are unchanged and their hashes still match.
- 2026-11-17: verification. `cargo fmt --check`, `sh scripts/check-spdx.sh`,
  `sh scripts/check-matrix.sh`: pass. `cargo clippy --all-targets --locked
  -- -D warnings`: pass; qv-app `--features desktop` and `--features
  validation` (all targets): pass; qv-app `--features mobile` for
  `aarch64-linux-android` (lib): pass. `cargo test --locked`: 1098 passed,
  0 failed. Vendored focused tests (`--lib hardened`): 16 passed.
  Not run: the real-window validation tests and the device instrumentation
  tests (owner's phone run).
- 2026-11-17: `build-android.sh` (debug build, pinned dx 0.7.10): pass;
  Kotlin and the instrumentation APK compile; badging shows
  `versionCode='10100' versionName='1.1.0'`. Built only, not installed.
  Found, not fixed: `crates/qv-app/README.md` still says Linux copy uses the
  X11 clipboard, which predates plan 0055's GTK clipboard; left for a
  review against 0055.
- 2026-11-17: step 8. `edits.rs`: `MsgPair.seq` from a per-server
  counter, hardened frames prefixed with it; `protocol.rs`:
  `HARDENED_TRANSPORT_JS` in the hardened bootstrap only. New test
  `hardened_unacknowledged_batch_is_resent_with_its_number_after_reconnect`;
  the late-acknowledgement test now checks the frame prefix. A Node
  simulation of the page code (fake sockets and animation frames: batch
  queued, socket closed, resent on a connecting socket) applied each batch
  once and never sent on a closed or connecting socket. Vendored focused
  tests 17 passed; `RUST_TEST_THREADS=1 cargo test --locked -p qv-app
  --features validation` (real WebKitGTK under private Xvfb): 116 + 3
  passed. Final gates: fmt, SPDX (and its self-test), matrix, clippy
  (workspace and qv-app validation) pass; `cargo test --locked` 1098
  passed, 0 failed. Not verifiable here: the freeze itself on the phone.
