# Plan 0045 — Owner feedback: fingerprint first, protection levels, Android list and Devices polish

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — fresh review and device check pending | 2026-11-07 | 2026-11-07 (owner request; design owner-delegated, standing 2026-11-02) | 0002 §5.4 (amended); 0008 §1.3; 0009 §1.8, §4 (amended) |

## Intent

Seven owner notes (2026-11-07) after testing plan 0044 on the phone:

1. Android: multi-select starts by holding an item, not with a button.
2. Android: it is not clear how to resolve conflicts.
3. Android: after opening an item and pressing Back, the row stays
   highlighted.
4. No fade when returning from the generator (or any tool) to the vault,
   desktop and mobile.
5. Android Devices tab: the buttons are scattered; needs UI/UX work.
6. "Reduced" protection overstates the concern on Android. Use graded levels
   (for example Maximum, High, Medium, Low, Very low).
7. It is unclear how to trigger quick unlock. When enabled it must be the
   first way to unlock; dismissing the fingerprint prompt falls back to the
   master password.

## Scope

**In scope:** the seven notes; the specs, platform policy, core, Android
activity and UI code they need; tests and docs.

**Out of scope:**
- Desktop quick unlock (no validated backend, 0009 §5).
- Browser autofill fingerprints (asked separately).
- Changes to what the acknowledgement gate refuses (0008 §1.3 stays as is;
  only its presentation and Android's evidence change).

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Quick-unlock policy state, expiry, failures | 0002 §5.4 | Accepted | Amended: policy state survives app restarts in private, non-backed-up storage, bound to the boot; "failed attempt" defined |
| Lock screen with quick unlock first | 0009 §1.8 | Draft (approved profile) | Amended (new bullet) |
| Protection levels, Android evidence | 0008 §1.3, 0009 §1.8 | Accepted / Draft | Gate unchanged; 0009 gains the level table and Android's evidence rules |
| Long-press selection | 0009 §1.8 "Item list actions" | Draft | Amended: Android long press, no Select button there |
| Conflict entry points | 0009 §1.8, 0005 §2.5 | Draft / Accepted | Amended: entry banner and list notice open the comparison |
| Devices page, fades, focus | 0009 §1.8 | Draft | Presentation only; no spec text needed beyond the Devices layout line |
| Preferences file | 0009 §1.8 "Preferences" | Draft | Amended: one `quick=off` key |

**Spec changes required:** Step 1 amends 0002 §5.4, 0009 §1.8 and §4
(Android evidence), with Changelog lines and the specs index. Owner request;
wording delegated.

## Decisions needed

None open. Choices made under the owner's standing delegation (2026-11-02),
with rejected options:

1. **Quick unlock survives app restarts (note 7).** Today the policy state
   lives only in process memory (plan 0033), and Android ends the process
   often, so quick unlock is almost never available; one dismissed prompt
   also deletes it (core invalidates on every error). New rule, within 0002
   §5.4 ("keep policy state outside the replaceable vault"): the state is
   kept in one private file in the app's no-backup directory and is valid only
   for the same boot (Android `Settings.Global.BOOT_COUNT` plus the boot clock
   `SystemClock.elapsedRealtime`), seven days from enrollment, under three
   failed attempts, and for the same vault/generation/password slot. A
   reboot, a changed boot count, a clock that went backwards, a corrupt or
   unknown file, or a missing keystore key all mean "password required" and
   delete the file and every QuickVault keystore key. Rejected: process-only
   state (the reported problem); keystore `setUserAuthenticationValidityDuration`
   reuse windows (weaker, no per-use authentication).
2. **What counts as a failed attempt.** A prompt the user dismisses (Cancel,
   Back, touching outside, the system cancelling it when the app goes to the
   background, a timeout) is not a failed attempt: it reveals nothing and the
   biometric hardware rate-limits guesses itself. A non-matching finger is
   not the end of the attempt either: the system prompt lets the user try
   again. A failed attempt is an attempt that ends in a biometric lockout or a
   failed unwrap. Three failed attempts delete the enrollment. The counter is
   written to the state file before the prompt opens (a kill mid-prompt
   counts), and given back on success or dismissal. Rejected: counting
   dismissals (three accidental dismissals would turn the feature off).
3. **Fingerprint first on the locked screen.** When quick unlock is ready for
   the selected vault, the locked screen shows a large "Unlock with
   fingerprint" button first and the password field below it ("or use your
   master password"), without focusing the field (no keyboard under the
   prompt). The system prompt opens by itself when the locked screen appears
   at app start or when the app returns to the foreground; after a manual
   lock in the foreground, it waits for a tap. Dismissing it leaves the
   password field ready. The button shows only when the stored binding's
   vault ID and generation match the selected vault's (unverified) header;
   core refuses a mismatch before prompting and without deleting the
   enrollment. Rejected: hiding the password field until dismissal (an extra
   step when the user wants the password).
4. **Turning it on.** "Features on by default": after a successful
   master-password unlock on a device where quick unlock is available, with
   no enrollment for this vault and the user not having turned it off, the
   app enrolls immediately with the password just used (Class 3 biometric):
   the system prompt says "Turn on fingerprint unlock". Dismissing it just
   skips it until the next password unlock. "Turn off quick unlock" in
   Settings stores `quick=off` in the preferences file and stops the offers;
   enrolling from Settings clears it. The device-credential (PIN/pattern)
   policy stays a separate explicit choice in Settings, never offered
   automatically. Rejected: an in-app "Use fingerprint next time?" card
   (would keep the password in memory while it waits).
5. **Protection levels (note 6).** A level derived from the existing checks;
   the acknowledgement gate keeps using `ProtectionStatus::is_reduced`:

   | Level | When |
   |-------|------|
   | Maximum | Storage, swap and hibernation verified; lock detection, clipboard clearing and process/memory protection all present |
   | High | Storage, swap and hibernation verified; one or more of the others missing |
   | Medium | Storage verified; swap or hibernation not confirmed (no known gap) |
   | Low | Storage not confirmed, or a known swap/hibernation gap |
   | Very low | A known storage gap (unencrypted disk) |

   The chip, the protection sheet and the Settings row show the level and the
   checks behind it; "Reduced protection" disappears from the UI. The
   device-credential option is labelled "Use your screen lock PIN or pattern
   instead (lower protection)". Rejected: a numeric score (false precision).
6. **Android evidence.** Today every Android disk check is "Unknown". New
   rules: storage is verified when `DevicePolicyManager
   .getStorageEncryptionStatus()` is `ENCRYPTION_STATUS_ACTIVE_PER_USER`
   (file-based encryption), a known gap when it reports inactive or
   unsupported, unknown otherwise; swap is verified when storage is verified
   and the device launched with Android 11 or later
   (`ro.product.first_api_level >= 30`, read with `/system/bin/getprop`
   because `Build.VERSION` does not expose it publicly; the Android CDD
   requires metadata encryption there, so any swap on flash is encrypted,
   and zram stays in RAM), unknown otherwise; hibernation is verified because
   Android does not hibernate to storage. On the owner's phone (Android 15,
   FBE, metadata encryption) this gives Maximum. Rejected: reading
   `/proc/swaps` (denied to apps on the phone, checked 2026-11-07).
7. **Long press (note 1).** `app.js` turns a touch held 450 ms on a row (moved
   under 10 px, no scroll) into a Ctrl-click on the row's open button, the
   same input that already starts a selection on desktop, and swallows the
   click that follows the release. Rows disable text selection and the touch
   callout. Android hides the "Select" link; narrow desktop windows keep it.
   In selection mode a tap toggles. Rejected: a Rust long-press timer (the
   bridge forwards no pointer events).
8. **Focus after Back (note 3).** Two causes: Back is a synthetic Escape key,
   which switches the webview to keyboard modality so `:focus-visible`
   outlines the row that keeps focus, and touch leaves `:hover` stuck. On a
   coarse pointer `app.js` blurs a focused button after Escape, and row hover
   styles apply only under `@media (hover: hover)`.
9. **Fade (note 4).** The list pane gets the `fade-in` entry animation, so it
   fades when it mounts again after a tool page; the detail pane already
   fades. No re-render is added (no-flicker rule: only a mount animates).
10. **Conflicts on Android (note 2).** The conflicted-entry banner gains a
    "Compare and resolve" button (opens the comparison for that record), and
    every item list shows a notice above the rows when conflicts exist ("2
    items have conflicting versions · Resolve"), opening Conflicts (or the
    single record). On phones the comparison's sticky bar holds full-width
    "Keep A"/"Keep B" buttons labelled with the version time.
11. **Devices page (note 5).** One hero card (what LAN sync is) and two large
    choice tiles in a column on phones and a row on wide screens: "Show a
    code" (this device shows a QR code) and "Scan a code" (camera, or "Type
    a code" where no camera); the typed-code path stays as a link under the
    tiles. Reuses the `.choice` tile styles of the welcome screen.

## Design

**Components touched:** `qv-platform::quick_unlock` (policy manager:
persistence, boot binding, failure semantics; trust boundary for the
enrollment), `qv-platform::android` (evidence fields), `qv-core::quick_unlock`
(invalidation rules, vault pre-check), `qv-app` (Android backend, prefs,
controller offer/auto-prompt, UI), `MainActivity.kt` (keystore retain,
boot/evidence probes, prompt result kinds), `assets/app.js`, `assets/app.css`.
No vault, sync or wire format change. The quick-unlock state file is a new
device-local format, volatile pre-1.0.

**Interfaces:**

```rust
// qv-platform::quick_unlock
pub enum PlatformError { …, Denied }          // failed attempt (counted)
pub struct BootStamp { pub count: u32, pub uptime_ms: u64 }
pub trait AndroidKeystoreBackend {
    // existing: validated, seal, open, delete
    fn boot(&self) -> Option<BootStamp>;                        // None: no persistence
    fn load(&self) -> Option<Vec<u8>>;                           // ≤ STATE_MAX bytes
    fn save(&self, state: &[u8]) -> Result<(), PlatformError>;   // atomic
    fn clear(&self) -> Result<(), PlatformError>;
    fn retain(&self, keep: Option<(&SecretBytes, u64)>);         // envelope + enrolled uptime; deletes all other QuickVault keys
}
pub const STATE_MAX: usize = 1600;
// Slot.since: Instant -> enrolled: BootStamp; age = now.uptime_ms - enrolled.uptime_ms
impl AndroidKeystore { pub fn policy(&self) -> Option<QuickPolicy>; } // for Settings text
// qv-core
impl Core { pub fn quick_ready_for(&self, path: &Path) -> bool; }   // binding matches header
```

**State file** (`<no_backup>/quickvault/quick-unlock`, 0600, written with
`prefs::write_private`, read with `prefs::read_private` and `STATE_MAX`):
`"QVQU"`, version `1`, policy u8 (1/2), boot count u32 BE, enrolled uptime
ms u64 BE, failures u8 (0..=2), binding 36 bytes, envelope length u16 BE
(63..=1536), envelope. Exact length required; anything else is corrupt.
It holds no plaintext secret: the envelope is AES-GCM ciphertext under a
non-exportable, per-use-authenticated keystore key. No integrity tag: a
party able to write the app's private storage could reset the counter or the
age; documented as residual (biometric hardware lockout and per-use
authentication still apply). Excluded from backup (no-backup directory,
0002 §5.3).

**Control flow:**
- *Load (lazily, once, on first `binding()`):* read the file; require
  `validated()`, a `BootStamp`, equal boot count, `now.uptime ≥ enrolled`,
  age < 7 days, failures < 3 and a well-formed record; then `retain(Some)`
  (Kotlin keeps that alias, deletes every other QuickVault alias, adopts the
  envelope's device ID and enrolment time). Otherwise `clear()` then
  `retain(None)`.
- *Enroll:* destroy the old slot (clear file, then delete key), seal, then
  save the new record before reporting success; a save failure deletes the
  new key and fails.
- *Unlock:* reserve (failures + 1) and save before the prompt; prompt; on
  success or `Cancelled`, give it back (failures − 1) and save; on `Denied`
  keep it (destroy at 3); on `Unavailable` destroy. Core runs the vault
  pre-check (`inspect` header vault ID and generation equal the binding)
  before the prompt and refuses `NotAllowed` without touching the slot; core
  invalidates only when the obtained phrase fails to open the vault or the
  opened binding differs.
- *Destroy order:* clear the file first, then delete the key (a restart then
  never references a deleted key; a leftover key is removed by `retain(None)`).
- *Kotlin result kinds:* `onAuthenticationFailed` (bad finger) no longer ends
  the operation; `onAuthenticationError` with USER_CANCELED, NEGATIVE_BUTTON,
  CANCELED or TIMEOUT → kind 1 (`Cancelled`); LOCKOUT or LOCKOUT_PERMANENT
  → kind 3 (`Denied`); an unwrap failure or invalidated key → kind 2
  (`Unavailable`). Prompt titles: "Unlock QuickVault" / "Turn on fingerprint
  unlock" (biometric), "Unlock QuickVault with your screen lock" (device
  credential).
- *Auto-prompt:* `AndroidPlatform` counts foreground entries
  (`foreground_entries()`); the controller remembers the last count it
  prompted for. When the locked screen is idle, quick unlock is ready for the
  selected vault, the protection acknowledgement is not pending and the count
  changed (including the first one at start), it performs `QuickUnlock` once.
  A manual lock records the current count, so it does not prompt.
- *Offer:* the controller's password `Unlock` keeps the protected password
  until the session opens; if the offer applies (decision 4) it runs
  `enroll_quick(Class3)` as the next workspace operation, then drops the
  password. A failure or dismissal shows nothing (an `Unavailable` failure
  shows the Settings hint once).

**Secrets and hostile input:** the password for the offer stays in its
existing protected container for one extra operation only and is dropped on
lock, cancel or completion. The state file is untrusted input: bounded read,
exact-length parse, no allocation before the length check, fail closed.
Envelope bytes stay in `SecretBytes`. No secret in logs or errors.

**Errors:** `Cancelled` → nothing shown; `Denied` → "Fingerprint unlock
didn't work. Use your master password."; after the third, "Fingerprint unlock
is off until you unlock with your master password."; vault mismatch → no
button.

**Dependencies:** None.

## Steps

### Step 1 — Spec amendments

- [x] **Do:** 0002 §5.4: persistence rule, boot binding, failed-attempt
  definition, dismissal not counted (owner, 2026-11-07, plan 0045) +
  Changelog. 0009 §1.8: "Quick unlock first" bullet (decisions 3–4),
  protection levels (decision 5) in the acknowledgement bullet, long press in
  "Item list actions", conflict entry points in "Conflict comparison",
  Devices layout line, `quick=off` in "Preferences"; 0009 §4 (Android
  autofill section → new "Android protection evidence" bullet under §1.8)
  with decision 6 + Changelog. `specs/README.md` index dates.
- **Files:** `specs/0002-cryptography.md`, `specs/0009-clients-and-platforms.md`, `specs/README.md`
- **Done when:** every decision above is cited by spec text.
- **Verify:** `sh scripts/check-spdx.sh`

### Step 2 — Platform: persistent quick-unlock policy

- [x] **Do:** `BootStamp`, backend methods, `PlatformError::Denied`, state
  encode/decode with bounds, lazy load, enroll/unlock/destroy ordering,
  counter semantics; `qv-core::platform::error` maps `Denied` →
  `NotAllowed`. Update the module docs (no longer process-lifetime).
- **Files:** `crates/qv-platform/src/quick_unlock.rs`, `crates/qv-platform/src/lib.rs`, `crates/qv-core/src/platform.rs`
- **Done when:** unit tests with a fake backend (in-memory file, settable
  boot stamp) cover: restart keeps a valid slot; boot count change, uptime
  regression, 7-day age, failures = 3, corrupt/short/long/unknown-version
  file and missing boot stamp all clear the file and retain nothing;
  dismissal not counted; `Denied` counted and the third destroys; counter
  saved before the prompt (a "killed" prompt counts after reload); save
  failure on enroll deletes the key.
- **Verify:** `cargo test --locked -p qv-platform quick`

### Step 3 — Core: vault pre-check and invalidation

- [x] **Do:** `Core::quick_ready_for(path)`; `unlock_quick` pre-checks the
  header and invalidates only after a phrase/binding failure.
- **Files:** `crates/qv-core/src/quick_unlock.rs`
- **Done when:** tests: cancelled unlock keeps the binding; another vault's
  path refuses with `NotAllowed` and keeps it; wrong phrase still destroys.
- **Verify:** `cargo test --locked -p qv-core quick`

### Step 4 — Android native: persistence, evidence, prompt kinds

- [x] **Do:** Kotlin: `qvBootCount()`, `qvUptime()`, `qvQuickRetain(envelope?, enrolled)`
  (replaces the startup alias sweep), device ID adopted from the retained
  envelope, `born` from Rust, result kinds 1/2/3, bad finger keeps the
  prompt, new titles; `qvProtectionEvidence()` returning storage state and
  initial SDK. Rust `NativeKeystore`: `boot/load/save/clear/retain` against
  `ROOT/quick-unlock`; `qvQuickFailureKind` 3 → `Denied`. `AndroidPlatform`:
  evidence fields in `AndroidState` mapped by decision 6;
  `foreground_entries()`.
- **Files:** `crates/qv-app/android/MainActivity.kt`, `crates/qv-app/src/android.rs`, `crates/qv-platform/src/android.rs`
- **Done when:** qv-platform tests for the evidence mapping and the
  foreground counter pass; the APK builds.
- **Verify:** `cargo test --locked -p qv-platform android`; `sh crates/qv-app/scripts/build-android.sh`

### Step 5 — App: fingerprint first, offer, levels, prefs

- [x] **Do:** `prefs` `quick=off`; controller `quick_ready` for the selected
  vault (cached per path and keystore serial), auto-prompt by foreground
  count, the post-unlock offer, error texts; locked-screen layout (decision
  3); `ProtectionLevel` in `views` or `prefs` with the table, used by the
  chip, sheet and Settings row; Settings quick-unlock card states (on with
  policy / off / unavailable) and the renamed credential option.
- **Files:** `crates/qv-app/src/prefs.rs`, `crates/qv-app/src/controller.rs`, `crates/qv-app/src/ui/mod.rs`, `crates/qv-app/src/ui/pages.rs`, `crates/qv-app/src/ui/shell.rs`, `crates/qv-app/assets/app.css`
- **Done when:** tests: level table (each row and boundary), prefs
  round-trip with `quick=off` and the 256-byte bound, controller: no offer
  when `quick=off`, unavailable, or already enrolled; manual lock does not
  auto-prompt; a new foreground entry does once.
- **Verify:** `cargo test --locked -p qv-app prefs controller views`

### Step 6 — Lists, conflicts, Devices, fade, focus

- [x] **Do:** decisions 7–11 in `app.js`, `app.css`, `items.rs`,
  `pages.rs`, `shell.rs`.
- **Files:** `crates/qv-app/assets/app.js`, `crates/qv-app/assets/app.css`, `crates/qv-app/src/ui/items.rs`, `crates/qv-app/src/ui/pages.rs`
- **Done when:** desktop flow harness passes; the entry banner and list
  notice open the comparison.
- **Verify:** `cargo test --locked -p qv-app`

### Step 7 — Android device tests, docs, gates, device build

- [x] **Do:** update `QuickUnlockUiTest` (dismissals keep quick unlock;
  auto-prompt; restart keeps it) and `QuickUnlockTest` (retain instead of
  sweep). Docs below. All gates; build the APK.
- **Files:** `crates/qv-app/android/tests/QuickUnlockUiTest.java`, `crates/qv-app/android/tests/QuickUnlockTest.java`, docs
- **Done when:** gates pass; APK builds.
- **Verify:** all `AGENTS.md` gates; `sh crates/qv-app/scripts/build-android.sh`

## Test plan

- Final verification: all `AGENTS.md` gates; step checks above are focused.
- Unit tests: state codec, policy manager, level table, prefs, controller
  offer/auto-prompt rules, Android evidence mapping.
- Rejection and crash-path tests: corrupt/oversize/truncated/unknown state
  files; boot change; clock regression; kill during the prompt (counter
  persisted); save failure on enroll; vault mismatch refused before the
  prompt.
- Device: the validation APK's `QuickUnlockUiTest` on the owner's phone when
  the owner runs it; manual check by the owner (fingerprint first,
  restart survives, reboot asks for the password).
- 0012 §1 matrix rows addressed: none (no offline-matrix row covers quick
  unlock); 0012 §3 device evidence stays release evidence.

## Risks and stop conditions

- If Android does not expose `BOOT_COUNT` to the app on the phone, stop
  persisting (quick unlock falls back to process-only) and report it.
- If `getStorageEncryptionStatus` does not report ACTIVE_PER_USER on the
  owner's phone, keep storage Unknown; do not invent other evidence.
- Do not weaken per-use authentication, Class 3, invalidation on new
  biometric enrollment or the non-exportable key checks.
- A fresh-context review is required (secret handling and a persistent
  device-local policy state).

## Documentation

- [ ] `CHANGELOG.md` — Unreleased entry
- [ ] `ARCHITECTURE.md` — §3 qv-platform quick unlock line (persistent
  boot-bound policy), if it says process-lifetime
- [ ] Specs — Step 1
- [ ] `crates/qv-app/README.md` — quick unlock paragraph
- [ ] `plans/README.md` — index row
- [ ] `AGENTS.md` — no change

## Revisions

- 2026-11-08: Step 9 added (owner feedback on the switcher's placement,
  sync vault visibility, the typed-code link, the Devices name; and the
  flaky CLI test found in Step 8).
- 2026-11-07: Step 8 added (owner: no way on Android to change vault once
  one is open; design delegated). The phone gets a vault switcher sheet;
  the Settings row stays.
- 2026-11-07: Decision 6 reads the launch API level through `getprop`
  (`Build.VERSION.DEVICE_INITIAL_SDK_INT` is not public in SDK 35); an
  unreadable value leaves swap unknown (level Medium).

### Step 8 — Phone vault switcher (revision 2026-11-07)

- [x] **Do:** a vault chip (dot, name, ▾) above the phone item list and a
  held Vault tab (`app.js` hold → Ctrl-click, as for rows) open a bottom
  sheet: one card per listed vault (initial tile, name, place; the open one
  marked "Open" with a Lock button; a fingerprint mark on the vault with
  quick unlock), then "Create a new vault" and "Join from another device".
  Choosing a vault uses `switch_vault` (locks first; refused while a form
  has input) and lets the locked screen open its quick-unlock prompt at
  once. Escape/Back closes the sheet. 0009 §1.8 switching bullet amended.
- **Files:** `specs/0009-clients-and-platforms.md`, `crates/qv-app/src/ui/{mod,shell,items}.rs`, `crates/qv-app/src/controller.rs`, `crates/qv-app/assets/{app.js,app.css}`
- **Done when:** a controller test shows a switch to an enrolled vault
  prompts once and a manual lock still does not; gates pass; APK builds.
- **Verify:** `cargo test --locked -p qv-app`; all gates; `sh crates/qv-app/scripts/build-android.sh`

### Step 9 — Sync naming, vault visibility, flaky CLI test (revision 2026-11-08)

- [x] **Do:** owner feedback: (1) the phone vault chip competed with the
  list title, and a phone does not show which vault a sync uses; the vault
  becomes an account-style tile at the top right of the list header, and
  the Sync page, the code window and a running sync name the vault (with
  Change on the page). (2) "Type a code instead" becomes a full-width
  button. (3) Devices is renamed Sync (tab, sidebar, palette, page, join
  text; ids unchanged). (4) The flaky qv-cli test: the `Home::unlock`
  helper retries `Locked` for up to 5 s (fork/exec window of a parallel
  test's `qv` child). Specs 0009 §1.8 and 0014 §6 (rename only) amended.
- **Files:** specs 0009, 0014; `crates/qv-app/src/ui/{shell,items,pages,mod}.rs`, `crates/qv-app/assets/app.css`, `crates/qv-app/src/bin/flow.js`, `crates/qv-cli/tests/common/mod.rs`
- **Done when:** gates pass; APK builds and is installed.
- **Verify:** all gates; `sh crates/qv-app/scripts/build-android.sh`

## Execution log

- 2026-11-07: Plan written and approved under the owner's standing
  delegation (2026-11-02); owner asked for the notes to be addressed.
- 2026-11-07: Steps 1–7 done.
  - Step 1: 0002 §5.4, 0009 §1.8 (quick unlock first, levels, Android
    evidence, long press, conflict links, Devices, `quick=off`) and the specs
    index amended with Changelog lines.
  - Step 2: `qv-platform::quick_unlock` persists a 57-byte header + envelope
    record through new default backend methods (`boot`, `load`, `save`,
    `clear`, `retain`); the `Drop` that deleted the key at process end is
    gone. Without a boot stamp nothing is persisted or touched; a missing
    file still sweeps stale handles. `PlatformError::Denied` added (→
    `CoreError::NotAllowed`). `Keystore::policy` added for Settings.
    Dismissals give the attempt back; every other failure still counts (as
    before); `Unavailable` destroys. 4 new tests.
  - Step 3: `Core::quick_ready_for`; `unlock_quick` refuses another vault
    before prompting and invalidates only on non-cancel failures after the
    keystore step. 1 new test (creates a second vault).
  - Step 4: Kotlin `retain`, boot count/uptime, storage encryption status,
    `getprop` launch level, result kinds (1 dismissed, 3 lockout or other
    authentication error, 2 key/unwrap failure), bad finger keeps the
    prompt, new prompt titles. Deviation: `retain(None)` spares keys this
    process created (`born`), so a late first restore cannot delete a fresh
    enrollment. `AndroidPlatform::with_storage`, `foreground_entries`.
  - Step 5: prefs `quick=off`; `prefs::level`/`Level`; controller `pump`
    (driven by the UI's 200 ms poll), offer after a password `Unlock`
    (only when no vault is enrolled, so another vault's enrollment is never
    replaced silently), `quick_ready` for the selected vault (the header can
    only be read while locked), `QuickFailed`/`QuickEnded` messages, silent
    dismissal; locked screen, chip, sheet, Settings row and quick card.
    1 new controller flow test.
  - Step 6: long press and Back blur in `app.js`; row hover only for
    hover-capable pointers; list `fade-in`; conflict notice and entry
    "Compare and resolve"; Devices hero + choice tiles; Keep buttons show the
    version time.
  - Step 7: `QuickUnlockUiTest` expects dismissals to keep quick unlock and
    uses `#quick-unlock`; enrollment labels/notice updated.
  - Gates on the final tree: `sh scripts/check-spdx.sh` ok;
    `sh scripts/check-matrix.sh` ok; `cargo fmt --check` ok;
    `cargo clippy --all-targets --locked -- -D warnings` ok;
    `QV_TEST_XVFB=<scratch Xvfb> cargo test --locked --no-fail-fast`: 928
    passed, 0 failed (without Xvfb the qv-cli clipboard tests cannot start).
    `cargo test -p qv-app --features validation` lib: 90 passed.
    `sh crates/qv-app/scripts/build-android.sh`: built (APK SHA-256
    0d427ee1…87b72).
  - Found, not fixed: the desktop flow harness (`tests/engine.rs`, two real
    flow tests) fails at HEAD before these changes: stage 64 ("nav enabled
    during a window": nav `disabled` is stale since the no-revision-bump
    change) and stage 67 (the script still expects the pre-0044 sync modal
    with Dismiss). Confirmed by building HEAD from a scratch copy. The
    script needs updating for plan 0044's receipt; out of this plan's scope.
  - Not verified: on-device behaviour (the phone disconnected before the
    final build), `getprop` readability for the app's SELinux domain, a
    process restart keeping quick unlock, and the device UI test run.
- 2026-11-07: Step 8 done. `VaultSheet` signal in `Root` (Escape/Back
  closes it, like the palette); `VaultCards` sheet in `shell.rs`; vault chip
  in the phone list head; a held Vault tab arrives as a Ctrl-click (app.js
  hold extended to `#tab-vault`). `switch_vault` to a listed vault resets the
  prompt markers so `pump` prompts once if that vault is enrolled; the
  sheet's fingerprint mark uses `Controller::quick_ready_for` (the open
  vault's mark is inferred, its header being held). Controller flow test
  extended (switch prompts once; manual lock does not).
  - Gates on the final tree: SPDX, matrix, fmt, clippy ok;
    `QV_TEST_XVFB=… cargo test --locked --no-fail-fast` 928 passed, 0 failed
    (a first run in parallel with the APK build had two load-related
    failures, qv-core `lan_core_sync_converges…` timeout and qv-cli
    `exit_codes_for_vault_states` Store(Locked); both passed alone and in
    the clean rerun). Validation lib tests 90 passed. APK built (SHA-256
    9b3ae4b0…53252) and installed on the owner's phone, hash verified.
- 2026-11-08: Fix found on the phone: `Controller::open_vault` built a
  throwaway list, so the new vault chip and sheet showed a joined vault's
  file name ("Joined vault") instead of its stored name. It now uses the
  real list; `the_vault_name_is_the_stored_one…` asserts it. Gates rerun:
  SPDX, matrix, fmt, clippy ok; full `cargo test` (with `QV_TEST_XVFB`):
  927 passed, 1 failed — qv-cli `exit_codes_for_vault_states` panicked with
  `Store(Locked)` in its first `home.unlock()` (the second time in two full
  runs); it passed 6/6 runs alone. No changed code is on its path (qv-cli
  and the store are untouched). Found, not fixed: the fixture's session (or
  a background step it starts) seems to still hold the vault's file lock
  when the test unlocks it under full-suite load; needs its own look. APK rebuilt (SHA-256 4c04fab1…eb510) and installed, hash verified.
- 2026-11-08: Step 9 done. Gates on the final tree: SPDX, matrix, fmt,
  clippy ok; `QV_TEST_XVFB=… cargo test --locked --no-fail-fast` 928
  passed, 0 failed; validation lib tests 90 passed. APK built (SHA-256
  6175024a…54211) and installed on the owner's phone, hash verified. The
  desktop flow harness's stage-64 title check now expects "Sync"; its
  stale stage 64/67 checks (pre-existing, Step 7 log) remain.
