# Changelog

Repository-level changes: code, tooling, docs and spec milestones. Normative
spec amendments are also recorded in each spec's own *Changelog* section; this
file summarizes them. Loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are ISO 8601. Newest first within each section.

## Unreleased

### Changed

- 2026-11-06: Owner follow-ups (plan 0043):
  - The command-line client is now `qv` instead of `qvault` (spec 0011
    §1.1). `QVAULT_PATH`, the config file and the `.qvault` extension are
    unchanged.
  - App: every section page fades in when you switch to it, not only the
    Generator. Keys on lone elements are ignored by Dioxus, so the page
    wrapper, the locked form (rebuilt on each new form epoch) and the entry
    editor (fresh per draft) now use one-item keyed lists.
  - App: the title bar's lock icon uses the dark ink colour on the green
    tile instead of grey.
  - App: the locked screen shows the protection chip only while a reduced
    protection status awaits acknowledgement; Settings → Security still
    shows the mode (spec 0009 §1.8).
  - App: the group form's color picker is styled like the rest of the
    app (it showed browser-default controls); the group menu has "Change
    color", and the form is titled "Edit group". Visible app text uses
    American spelling ("color", "Recognized").
  - App: while you type a card number, the card preview shows the digits
    in their places instead of pushing them into the last group; when the
    field loses focus it shows only the last four again (spec 0009 §1.8).
  - App: the official logo (`LOGO.svg`) is the desktop window icon, the
    Android launcher icon (adaptive, with a monochrome layer), the title-bar
    mark, the first-run welcome image and the Settings → About header.
- 2026-11-06: LAN sync without device links (spec 0014, accepted by the
  owner; plan 0042):
  - One device shows a one-use code (QR, or the 26-character code and an
    address) for up to 10 minutes. The other device scans or types it and
    syncs once. Both prove they hold this vault and key generation with
    proofs tied to that session; no comparison code is needed and nothing
    about the other device is stored.
  - A new device still compares the six-digit code on both screens before
    the vault key is sent.
  - Removed: linked devices, link names and removal, receive windows, the
    address-only QR and the separate session handshake. The `lan_link`
    table stays in the file format but is cleared at each save, so existing
    vaults keep opening.
  - CLI: `qvault lan open | sync | join` replace `lan pair`, `receive`,
    `links` and `unlink`.
  - App: Devices has "Show a code", "Scan a code" and "Type a code". A
    scanned code that names its address starts the sync or join at once;
    one without an address shows "Code from the QR code" and asks for the
    address. A camera frame without a readable code, or with two codes, is
    skipped instead of ending the scan.
  - Specs 0013, 0002, 0004, 0005, 0009, 0011 and 0012 amended. The new
    composition still needs the independent review before any LAN release.
- 2026-11-06: The lock screen again confirms a scanned pairing code and a
  cancelled key rotation. The 2.10a redesign had stopped showing both
  messages (plan 0040).
- 2026-11-06: Vault list (plan 0041, owner follow-up to 2.10a):
  - Create a vault with just a name. It is saved as `<name>.qvault` in a
    default folder: `~/.local/share/quickvault/vaults` on Linux (changeable),
    or the app's private folder on Android.
  - The lock screen lists every vault by name, with its folder: the ones
    remembered and the ones found in the default folder. The most recent is
    selected.
  - "Open a vault file…" adds a vault where it is, without copying it.
  - A moved or deleted file is reported and can be removed from the list.
  - Settings shows the open vault's file and the folder for new vaults.
  - A vault has one name, the one stored and synced inside it; renaming it
    in Settings renames it everywhere. The lock screen shows a copy kept in
    a bounded private `vault-list` file. Files are never renamed; a vault
    not yet opened on this device shows its file name.
  - An existing vault in the old private folder stays listed in place. It
    shows as "main" until it is next unlocked, then by its name.
  - No vault, crypto, storage-format, protocol or sync change.

- 2026-11-05: New app UI (roadmap 2.10a, plan 0040), built from the
  prototype the owner approved after rejecting the 2026-11-04 restyle. One
  shared UI for desktop and phone:
  - the desktop window draws its own title bar (drag, double-click, window
    buttons, edge resize; no OS decorations);
  - dark by default, with an in-app theme switch (dark, light or system)
    stored in a small non-secret preferences file;
  - first-run welcome, vault menu, step-by-step creation and phrase
    confirmation;
  - "All items", type and group filters, quick copy from list rows,
    click-to-copy fields with reveal countdown rings, and in-place editing;
  - command bar (Ctrl K), Undo after moving an item to the trash;
  - generator with sliders and switches, pairing and sync dialogs, and grouped
    settings;
  - phone layout with large titles, bottom tabs, a floating New button and
    bottom sheets.

  Behaviour changes, specified in 0009 §1.8:
  - The reduced-protection acknowledgement is asked once per protection
    status and remembered, instead of a checkbox on every unlock.
  - Files are chosen through the system picker (Linux xdg-desktop-portal over
    the existing zbus; Android Storage Access Framework) instead of typed
    paths. A typed path remains only when no picker is available.

  Fixed during owner acceptance: the OS title bar was still shown; the shell
  could become unclickable after unlocking (`inert="false"`); fast typing
  dropped characters in edit forms; autofocus never applied; creating a
  second vault failed silently; accepting the protection notice did not
  continue; item and group colours changed while renaming (now from the
  record ID). The real-engine test driver now clicks only controls a real
  pointer could reach.

  New item editor, from a prototype the owner approved:
  - A new item starts from one box, "What are you saving?". It recognises a
    website, a card number or a Wi‑Fi name on the device. A pasted card number
    goes straight into the protected card-number field.
  - Forms follow the type: a live card face for cards, a join card and
    security buttons for Wi‑Fi, and a plain page for notes. Untitled items
    take their title from the website, network name or card.
  - Field tools sit behind ⋯ (rename, hide or show the value, move, remove
    with Undo). One "Add a field" infers the kind from the name.
  - Saved protected values show "Saved · Change". The generator popover moves
    its value into the field without passing it through the page.
  - Wi‑Fi items can show a join QR code for 30 seconds.
  - Items and groups can be given a colour, stored as `hue:<0–11>` in the
    existing `icon` text (0003 §5.5).

  Also from owner testing:
  - Screens switch without the earlier ~0.5 s lag: the UI redraws right
    after each click, input or key press instead of on a 200 ms poll, and
    the fade-in is shorter.
  - The permanent "Automatic locking … unavailable" banner is gone. Where
    screen lock and sleep are not detected, the lock button carries a mark
    and Settings shows "Auto-lock: Idle only" (0009 §1.8).
  - Settings no longer claims that screen lock or sleep lock the vault when
    they don't.
  - Opening a new item, an edit or a group form no longer jumps the sidebar
    and list to an earlier group. Forms now record where they were opened,
    so Cancel and Save return there. Sidebar dots and command-bar results now
    show chosen colours.
  - An item's ⋯ menu and a group's actions menu open under their button
    instead of at a fixed spot.
  - The card number is visible while typed, grouped in fours (Amex 4-6-5).
    It is only called invalid once it is long enough to be complete.
  - Moving the mouse, scrolling or touching the window now counts as
    activity, so the 60-second lock no longer fires while you look around.

  No vault, crypto, storage-format, protocol or sync change (the colour is a
  value convention in an existing field). The webview policy is
  unchanged: the UI uses no inline styles. The real-engine and Android test
  drivers were rewritten for the new screens with the same checks.

- 2026-11-04: Phase 2.10b (plan 0039) passed its fresh-context review, which
  added a test that non-byte-mode QR codes are refused and fixed an
  intermittent qv-sync LAN test-harness race (test-only). Its remaining attended
  pairing/sync, offline and interruption checks move to the milestone-2
  evidence phase 2.11. They have not passed, and the camera stays disabled in
  ordinary packages until then. Phase 2.10a (plan 0040) has started: a design
  brief and mockups for an application look on desktop and phone, waiting for
  the owner's approval.

- 2026-11-03: Android QR device validation uses a bounded MIUI-compatible
  activity launcher. Explicit validation-only modes exercise live camera
  frames/lifecycle/timeout and optical Join form filling. The native camera
  and optical Join checks pass on the connected Android 15 phone; remaining
  live pairing and offline two-device evidence is tracked in plan 0039.

- 2026-11-03: Owner moved remaining attended phase 2.10 testing to the end of
  QR phase 2.10b (plan 0039), authorizing implementation now. Device evidence
  and release gates remain pending. Added the Android QR camera profile in
  0009 §1.7.

- 2026-11-03: Repair phase 2.10 review findings (plan 0038): active LAN
  transfers and CLI pairing prompts respect window expiry; app questions and
  initiated operations retain inactivity locking. Local acceptance reports
  survive a subsequent lock, and app results retain completion errors beside
  committed outcomes. Fresh-context review now approves the repairs; the
  WebKit flow completes pairing through the real approval control and checks
  the joining core peer. The pinned-tool debug APK builds. The attended
  offline Linux/phone test remains pending before phase 2.10b.

### Added

- 2026-11-03: LAN QR display and Android camera scanning (roadmap 2.10b,
  plan 0039). The shared app shows binary pairing and address-only Receive
  codes. Scans fill the appropriate current form through strict core
  validation; Join/Link/Sync and comparison-code approval remain explicit.
  Android Camera2 keeps a bounded preview in memory, with action-only camera
  permission and cleanup on cancellation/expiry/lock/pause. Manual entry works
  without a camera; ordinary packages keep scanning gated until device
  validation, with an explicitly marked validation APK available. Remaining
  2.10 and QR device testing is combined at the end of 0039, owner-deferred.
  Added decoder fuzzing, form/cleanup regressions, synthetic QR pairing/link/
  sync coverage, Android adapter instrumentation and package checks. New exact
  QR dependency pins and their unaudited supply-chain debt are recorded.

- 2026-11-03: LAN sync (roadmap 2.10, plan 0038; spec 0013 §5, §7, §8).
  - Linked devices sync directly on the local network, with no account,
    server or Internet access. One device opens a receive window; the other
    starts a round with the link the user chose. Both merge the other's
    state through the archive acceptance path and commit locally. Local
    acceptance, conflicts and the other device's receipt are reported
    separately. A round with nothing new commits nothing, and retries are
    idempotent. Link-mode pairing now ends with one sync round.
  - **CLI:** `qvault lan pair|join|receive|sync|links|unlink` (0011 *LAN
    command contracts*). The pairing code is typed at a hidden prompt and
    shown only on the alternate screen. New exit code 10: LAN peer
    unavailable.
  - **App:** a Devices screen (links, pairing, link an existing copy,
    receive, sync, remove) and a Join mode on the locked screen for new
    devices. Comparison codes, the vault name and the master password are
    asked while the operation waits. Cancel and lock end every window and
    prompt.
  - This device's addresses come from route probes, with no new
    dependency. DNS-SD discovery stays deferred. Rendering and camera
    scanning of the QR codes move to roadmap 2.10b; until then the code and
    address are typed.
  - Spec amendments: 0013 §8.5 (address-only receive-window code), §5.1
    (one link per attempt), §7.4 (`Want` bounds); 0011 LAN commands and
    exit code 10.
  - **Fixed during the phase:** a cancel or lock took effect only while
    socket I/O blocked, so a fast round could finish after it. It now
    applies before every frame.
  - Development vectors cover the session handshake and the address code.
    The fuzz targets cover the new decoders. No independent protocol review
    yet (D12); no LAN release.
  - The review of phase 2.9 (plan 0037) made new-device join apply the
    platform and anchor-location checks of vault creation before pairing.

- 2026-11-02: LAN pairing (roadmap 2.9, plan 0037; spec 0013 §4, §8–10, §12).
  - An unlocked vault can open a time-limited pairing window that shows a
    QR payload or a 26-character code. A second device then joins:
    - **new device:** receive, fully verify, confirm and password-check the
      vault, then create it at a new path;
    - **link mode:** an existing copy of the same vault.

    Both sides keep a pairwise link key bound to the vault's key generation,
    after comparing a six-digit code.
  - Links are local:
    - each one can be listed and removed;
    - no peer address is remembered (there is no device identity to
      remember it for); each pairing or sync gets the address from a QR or
      the user;
    - rotation, restore and archives carry none;
    - planted-back or modified link rows are detected on open.
  - Windows accept one session at a time and close after 16 failed attempts,
    a second valid hello (the code may have been observed), their time limit,
    a lock or a cancel. Nothing is sent to an unauthenticated peer.
  - Not yet: discovery (DNS-SD), sync sessions, the CLI and the app (roadmap
    2.10). No independent protocol review yet (D12); no LAN release.
  - **Development format change:** vault files move to schema/header
    `0x7FFF0004` (new `lan_link` table, local-head key 8).
    Older development vaults are refused, with no migration (pre-1.0).
  - Spec clarifications (0013 §1.3, §7.1, §8.3; 0004 §2.4), development
    interoperability vectors with an independent Python check, and the new
    `lan_oob` fuzz target. The `lan_message` target covers the typed
    decoders.
  - The review of phase 2.8 (plan 0036) made oversized frames close the
    connection without a wire error code.

- 2026-11-02: LAN protocol foundation (roadmap 2.8, plan 0036).
  - New `qv-protocol` crate: bounded `u32` frames (4096 bytes before the
    session keys, 1,052,672 after), checked before allocation and read without
    read-ahead. It also has the fail-closed `lan / 1` profile, feature and
    error-code registry, and an exact-shape canonical-CBOR message
    reader/writer for the 0013 wire labels.
  - `qv-crypto`: X-Wing draft-11 through `libcrux-kem` 0.0.10, checked against
    all draft-11 test vectors and with tests for missing halves, the ML-KEM
    key check and low-order X25519. It also has the 0013 §6 record layer:
    counter nonces, sequence AAD, poisoning on any failure and the 2³²
    limit.
  - New `lan_message` fuzz target in CI.
  - Supply chain:
    - two narrow `deny.toml` entries for libcrux verification-tooling crates
      that are never compiled (`bindgen` licence, `proc-macro-error2`
      advisory);
    - vet exemptions for the libcrux tree. No audit is claimed.
  - The hybrid signature moves to roadmap 3.3, its first consumer.
  - Review of phase 2.7 (plans 0034 and 0035) fixed four issues:
    - cold-start autofill handoffs were cancelled before the app's
      controller existed;
    - an empty login field failed the whole fill;
    - spec 0009 §4.4 now states the handoff lifetimes;
    - an Android-only Clippy cast lint in qv-store.

- 2026-11-02: Fixed an Android abort when QuickVault's activity was created a
  second time in a live process: after Back and reopen while the process was
  cached (likely with autofill), or on an in-place configuration change such
  as dark mode or font size (plan 0035). The Rust runtime starts once per
  process, so configuration changes are now handled in place. After the
  activity is destroyed, the app locks, Rust acknowledges and the process ends,
  so the next launch is fresh; this also means reopening needs the master
  password again. Android builds now reuse one `dist/android-project` copy
  instead of adding a new ~175 MB directory per build.

- 2026-11-02: Android autofill (roadmap 2.7, plan 0034), behind a device and
  browser validation gate (both allowlists empty). The thin service returns
  only a generic "Unlock QuickVault to fill" entry. A non-exported one-shot
  handoff opens the shared app, which requires unlock and an explicit choice
  (each conflicting version listed separately) and returns only the chosen
  login. Matching is exact: verified package plus full signer set (linked by an
  explicitly confirmed action), or an exact origin reported by an allowlisted
  browser. Titles, labels, URL substrings and custom schemes never match.
  Locking cancels a bound request. Spec 0009 §4.4 added (Draft, owner standing
  delegation); Digital Asset Links deferred. Quick unlock no longer holds its
  policy lock during the native prompt (0033 review finding). Device evidence
  is pending.

- 2026-11-02: Phase 2.6 implementation completed under the owner's closure
  decision (plan 0033). Remaining physical-device checks are recorded separately
  as prerequisites for device enablement; unvalidated hardware stays disabled.
  Fresh-context implementation review remains due.

- 2026-11-02: Physical Android testing found and repaired a CSP/bootstrap
  metadata read that could borrow the renderer's active edit RefCell and abort
  the app. Protocol connection metadata now uses its independent shared server
  location; a focused regression covers reads during rendering, and updated
  host engine tests pass. The earlier extended Android regression passed;
  authenticated Class 3 and device-credential adapter round trips and wrong-AAD
  rejection now pass on the connected phone. An explicit isolated validation
  build adds shared-app quick-unlock workflow tests. Enrollment-change
  invalidation and the remaining device matrix are still unverified.

- 2026-11-02: Android quick-unlock implementation (roadmap 2.6, plan 0033):
  bounded hardware keystore/prompt adapter, Class 3 policy and separate labelled
  device-credential opt-in, core reauthentication/binding and credential-change
  invalidation, process-local age/attempt policy, app enrollment/unlock/disable,
  host regressions and interactive hardware instrumentation. Unvalidated devices
  remain disabled; physical-device evidence is still required. No dependency,
  vault format, server or primitive change.
- 2026-11-02: Repaired phase-2.5 review findings: candidate-bound five-second
  weak-password consent, Fair warning and generated master-password suggestions,
  generator class-constraint preservation/strength warnings, Android Back and
  action-transition document cleanup and stale native picker-result rejection.
  Extended engine/device edit/history/file/lock-race checks; see the review log.

- 2026-11-02: Fresh phase-2.5 review records changes requested for credential
  strength safeguards, Android Back document-choice cleanup, generator
  option/warning parity and incomplete GUI validation. Phase 2.6 remains
  pending the prerequisite review fixes; see plan 0031 REVIEW.md.

- 2026-11-01: App vault workflows (roadmap 2.5, plan 0031). The shared
  Android/Linux app now reaches the CLI's offline feature set:
  - browsing, search, entry view and edit, groups and trash;
  - 30 s reveal and Rust→OS copy, TOTP codes and the generator;
  - history, conflicts, snapshot restore, archive export/merge, attachments;
  - settings, password change, phrase redisplay, key rotation with resume,
    verification and vault information.

  On Android, the system document picker no longer locks the vault when
  started in the foreground (only background expiry is deferred; screen-off
  and inactivity still lock), and a chosen document is forgotten on
  navigation and after a save. Archive import on Android now works: the
  descriptor-pinned source walk opens ancestors with `O_PATH`, because apps
  have only search permission on `/data`. Verified on a physical phone.

  Layouts are responsive (desktop sidebar, touch bottom bar). Every operation
  is epoch-checked; results arriving after a lock are discarded. Destructive
  operations take the mandatory recovery snapshot and ask before it exceeds
  its budget.

  Android adds a clipboard backend (sensitive clips, cleared only when still
  owned) and document-picker streaming with no plaintext temporary files. A
  foreground copy defers Android's background lock until the 20 s hold ends;
  screen-off still locks at once.

  Shared no-follow file helpers moved from qv-cli to qv-platform with no CLI
  behaviour change. The hardened desktop patch now closes the window when the
  bounded edit transport drops a batch, instead of treating it as flushed.
  Plan 0030 review follow-ups are closed: a 5-minute phrase-screen limit with
  guidance, over-budget baseline consent and engine-level refused-IPC
  assertions. No release or security validation claim.

- 2026-11-01: Phase 2.4 review: Linux startup now reports private-storage and
  already-running refusals by category (previously collapsed into "Protection
  unavailable"), with a regression test.

- 2026-11-01: Owner policy amendment makes automatic OS screen-lock/sleep
  monitoring optional on Linux. Missing logind no longer prevents app startup
  or local create/unlock/recovery after reduced-protection acknowledgement.
  A persistent warning states which automatic locking is unavailable; manual
  and 60-second inactivity locking remain active. Received OS events and loss
  of an installed watcher still lock existing state. Android requirements remain
  unchanged. Specs 0008/0009 and the active phase plan record this decision.
  Foundation implementation passes all gates (724 tests) and awaits a fresh-
  context review; no release/security validation claim.

- 2026-11-01: App startup identifies missing lock monitoring, unavailable
  private storage and another running instance instead of collapsing them into
  "Protection unavailable". A failed monitor rearm locks the controller and
  clears protected forms before reporting the failure. No monitoring bypass.

- 2026-11-01: Repeatable Android instrumentation runner installs the local test
  packages without clearing app data and exercises separate synthetic vaults.
  Expanded recovery/error/cancellation/skip suite passes on the physical phone. Owner confirms screenshot blocking alongside
  screen-lock/background locking. Test-only keep-awake does not alter product
  lock behavior. Phase 2.4 remains In progress.

- 2026-11-01: Shared Android/Linux app foundation (roadmap 2.4, plan 0030):
  create with phrase confirmation/recorded skip, password and phrase unlock,
  snapshot-backed anchor recovery, protected bounded forms, lifecycle locking,
  visible protection status and responsive screens. A maintained Dioxus 0.7.10
  integration restricts assets, CSP, native IPC/navigation and loopback transport.
  Android arm64/API29+ app and instrumentation APKs build; Linux real-WebKit
  boundary and full rendered-flow checks pass. Synthetic Android instrumentation also passes on a POCO X7 Pro
  (Android 15); manual device and real-desktop lifecycle validation remain
  pending, so the phase stays In progress. Full
  vault browsing/editing follows in 2.5. Framework cleanup is best effort.
  Five provenance-tracked vendor additions remediate the dependency graph;
  deny passes without advisory ignores. Exact vet exemptions record development
  audit debt rather than audits or release approval.

- 2026-10-31: Linux platform services (roadmap 2.3, plan 0029): injectable OS
  traits, logind lock/sleep monitoring, session-bound clipboard cancellation,
  hardened single-instance ownership and conservative swap/hibernation status.
  The CLI shares its existing X11 engine through core; quick unlock stays
  unavailable. Configured platform flows require explicit reduced-protection
  acknowledgement; missing lifecycle monitoring still refuses the session.
  Real-desktop validation remains unclaimed; private-bus and
  manual procedures are recorded. zbus 6.2.0 replaces the proposed unmaintained
  5.x graph; 24 exact-version vet exemptions record development audit debt.
  CI installs the private D-Bus test server, and matrix checks include untracked
  sources while ignoring deleted paths without changing row/tag requirements.
  Fresh-context phase review is Approved. The owner subsequently approved
  the architecture under D13; plan 0030 describes the app foundation and the
  approved desktop integration. Subsequent implementation and dependency
  remediation are recorded in the 2026-11-01 entry.

- 2026-10-31: Archive export retains and reports its published ID when directory
  sync fails, with an explicit warning that crash durability is unconfirmed.
  Recovery snapshots still require successful publication completion.

- 2026-10-31: Core and CLI conflict resolution and archive exchange (roadmap
  2.2c, plan 0028): all-kind `conflicts`, complete-version `resolve --version`,
  `merge` and immutable `snapshot export`. Resolution preserves protected/TOTP
  and unknown values, rejects stale choices and requires selected-slot password
  proof before adoption. Attachment copying and owned deletion share the atomic
  write path. Imports require serialized recovery copies and view preflight;
  exports are slotless unless warned self-contained consent is explicit. Local
  snapshot recovery preserves keyslot conflicts with the working source slot.
  Agent guidance now keeps steps inside the phase instead of automatically
  splitting phases by step count. Fresh-context review of 0027 is Approved.

- 2026-10-30: Completed both parts of roadmap 2.2b under plan 0027, combined
  at the owner's direction: atomic archive-candidate acceptance and durable
  filename receipts through the existing commit/anchor path, descriptor-pinned
  source traversal and normalized protected paths, idempotent redelivery and
  independent candidate/object/chunk validation. Permanent tombstones now have
  authenticated role markers and survive dominated/floor-covered history,
  purge, later final deletion, restore and rotation. Payload-history listings
  omit those non-restorable metadata roles. Volatile manifest format is
  0x7FFF0002; schema/header stays 0x7FFF0003, without migration. Core/CLI exchange
  and conflict-resolution workflows remain 2.2c.

- 2026-10-30: Roadmap 2.2b1 (plan 0027): bounded confidential archive receipt
  metadata and a sealed local-only SQLite singleton, authenticated by the local
  head and bound to the replica/generation. Ordinary writes preserve it;
  creation, new-path restore and rotation initialize empty receipts. The
  volatile development schema/header is 0x7FFF0003, without old-format migration.
  Parser, tampering, capacity, restart and lifecycle tests plus a CI fuzz target.
  Atomic incoming acceptance and actual filename receipt recording remain
  2.2b2; core/CLI workflows remain 2.2c. Fresh review of 0026 is Approved.

- 2026-10-30: Roadmap 2.2a (plan 0026): authenticated private archive input
  and the shared `qv-sync` merge-candidate engine. Candidates preserve complete
  versions, concurrent deletion/edit, attachment references and monotonic
  suppression floors without accepting state or rewriting ciphertext.
  Rejection/convergence tests include real encrypted archive/store integration.
  Owner-approved 2.2 is split under the session-size rule: atomic acceptance
  and durable filename receipts remain 2.2b; core/CLI conflict resolution and
  archive export remain 2.2c, each after an owner commit and fresh review.

- 2026-10-30: Spec 0013 (direct LAN sync protocol) is **Accepted**, by owner
  delegation. Its amendments are applied:
  - 0001: the LAN advertisement and pairing metadata reference;
  - 0002: the `lan / 1` profile, the `lan-link` purpose key, and
    generation-bound LAN approvals under rotation;
  - 0004: the local-only `lan_link`/`lan_hint` tables and
    `lan_links_digest`;
  - 0005: OQ3–OQ6 resolved, and the local head field.

  No LAN release is authorized: the 0012 §3 gate, including the D12
  independent review, still applies.

- 2026-10-30: Draft spec 0013, the direct LAN sync protocol (roadmap 2.1,
  plan 0025). It proposes the resolution of 0005 OQ3–OQ6, which the owner
  delegated as D10:
  - discovery only during explicit, time-boxed windows;
  - QR or manual-code pairing with a committed comparison code, creating
    pairwise link keys bound to one key generation;
  - an X-Wing session handshake and a counter-nonce record layer;
  - full-manifest exchange through the local commit path;
  - local link removal, with rotation for compromise.

  It is not yet accepted. It lists the amendments to 0001, 0002, 0004 and
  0005 that are applied on acceptance. No code changed.

- 2026-10-30: Fresh-context review of phase 1.16 (plan 0024): Approved with
  minor fixes. The networking-blocked offline CLI test now also recovers the
  vault with its phrase, as the 0012 "Implicit server prerequisite" row
  requires. The canary audit now covers a new master password.

- 2026-10-30: Offline hardening evidence (plan 0024, roadmap 1.16):
  - `scripts/check-matrix.sh` and `tests/matrix-offline.txt`: every offline
    0012 row has a tagged, passing test (CI-checked);
  - CLI audits for owner-only modes under `umask 000`, fail-closed write
    failures under a file-size limit, and canary secrets never reaching
    output or files;
  - the networking-blocked test is required in CI (`QV_REQUIRE_NETNS`);
  - a weekly 30-minute-per-target fuzz workflow with ASan, and a
    `vault_open` fuzz target that now mutates a real vault built per
    process, not only raw bytes;
  - the `budget_bench` example and Linux benchmarks at the record and
    ciphertext caps;
  - a recorded dependency audit status.

  Owner decision: pre-1.0, every format stays volatile. The format freeze,
  golden vectors and supported-device KDF tuning move to a pre-1.0 release
  step after the owner's user testing; roadmap 1.16b is dropped.

- 2026-10-30: Fresh-context review of phase 1.15c (plan 0023): Approved with
  minor fixes. A failed directory fsync after the journal's rename is now
  reported as a published (partly applied) rotation. Added three hostile
  restart tests (swapped suffix, another vault's journal, stale old copy)
  and corrected a stale doc comment.

- 2026-10-30: Offline key rotation is complete (plan 0023, phase 1.15c):
  `qvault recovery rotate`. The command:
  - takes a pinned recovery snapshot;
  - builds and verifies the next generation;
  - shows the new phrase and requires three confirmed words;
  - publishes through the rotation journal with no-replace renames and one
    anchor generation step.

  Restart completes or rolls back an interrupted rotation through the same
  command, with each copy authenticated by its own password; rollback is
  refused once committed. Snapshot budgets now count older generations'
  copies from the authenticated inventory, and a missing inventory fails
  closed. Ordinary opens of an interrupted vault get a `recovery rotate`
  hint (exit 7). Crash injection covers every journal step, for
  installation and both restart choices.

- 2026-10-30: Fresh-context review of phase 1.15b (plan 0022): Approved with
  minor fixes: two replacement tests (anchor mismatch, unknown extension
  fields) and two misplaced doc comments.

- 2026-10-29: Verified rotation replacement (plan 0022, phase 1.15b). The store
  builds a private next-generation database: a new VK, phrase and password
  slot; every object reencrypted under fresh IDs; logical IDs, clocks, history,
  floors and conflicts preserved; and one causal keyslot edit. It verifies the
  database again from the persisted bytes without touching the shared anchor.
  Ordinary opens refuse `.qvrotate` names (exit 7). Adds a MAC'd
  per-generation snapshot inventory with hash-checked removal, an independent
  vector and a fuzz target. Nothing installs it yet: the journal installation,
  restart, core and `recovery rotate` come in phase 1.15c.

- 2026-10-29: Fresh-context review of phase 1.15a (plan 0021): Approved, no
  fixes. Independent required gates pass with private Xvfb.

- 2026-10-29: Rotation foundation (plan 0021, phase 1.15a): bounded canonical
  journal metadata with independent old/new generation MACs, strict rejection
  tests and a journal fuzz target. Existing `.qvrotate` intent markers block
  ordinary open/create/restore and mutation paths without adopting an anchor.
  No production marker writer or `recovery rotate` command yet; replacement,
  durable recovery and snapshot accounting follow in phase 1.15b. Owner-approved
  0002 amendment defers offline recovery public-key derivation until needed.

- 2026-10-29: Fresh-context review of phase 1.14 (plan 0020): Approved with
  minor fixes to its stale plan status. No blocking product finding; independent
  required gates pass with private Xvfb. Network isolation unavailable.

- 2026-10-29: `qvault passwd`, `recovery show` and `recover <existing.qvault>`
  (plan 0020, phase 1.14). Password replacement atomically updates the complete
  slot, encrypted keyslot record and header MAC through the existing transaction
  and anchor path, preserving VK, generation and application object ciphertext.
  Recovery-phrase redisplay reauthenticates and uses the terminal alternate
  screen. Phrase recovery of a missing/mismatched anchor requires explicit
  baseline consent and a verified recovery copy. After a successful password
  change, the CLI names pre-change snapshots and offers deletion only after
  separate confirmation; old slots and independent copies remain effective.
  No new dependency, profile, format or schema. Standalone phrase/archive import
  and generation rotation are not included.

- 2026-10-29: Correct slot-bearing snapshot restore to return integrity exit 7
  as specified, with a production CLI regression preserving source and anchors
  (plan 0019 review remediation). Other unsupported archive features retain
  their existing classification.

- 2026-10-28: Independent review of snapshot restore (plan 0019) requests a
  correction: selected slot-bearing archives are refused with exit 1 instead
  of the specified exit 7. Phase 1.14 awaits correction and review; no product
  behavior change in this review session.

- 2026-10-28: `qvault snapshot restore <id> <new-path>` restores a local archive
  into a new private vault with fresh replica, writer and external anchor
  state (plan 0019, phase 1.13b). It preserves archived records, history,
  suppression floors and attachments, leaves the active vault and its anchor
  unchanged, and uses the password current when the snapshot was made.
  Full or unambiguous six-or-more-hex IDs (optional `@`) are supported;
  existing targets are refused. The explicit recovery baseline does not prove
  global freshness. Automatic pruning waits until restore succeeds, and
  signal cancellation is checked between bounded units of work. No dependency,
  schema or format change.

### Fixed

- 2026-10-28: Authenticate archive records, retained history and attachment
  chunks before publication or delivery to import code. Reject nonce-only
  corruption and contradictory reference digests, and preserve existing
  snapshots when a replacement cannot be verified (plan 0018 review fixes).
  Verification uses bounded seek passes over ciphertext without plaintext
  staging; the archive format is unchanged.

### Added

- 2026-10-28: Local snapshot policy, `qvault snapshot ls`, `qvault verify` and
  the mandatory recovery snapshot of `trash empty` (plan 0018 steps 7–10,
  phase 1.13a; 0007 §3, 0011 §4). With a configured private snapshot
  directory, an unlock may write one ordinary archive per hour and one on the
  first unlock of a UTC day, decided from authenticated archive headers only:
  no marker or settings row and no vault write on a read command. Budgets are
  30 days, 48 ordinary snapshots and 512 MiB, pruned oldest first; a recovery
  copy pinned by an in-progress destructive operation is never pruned and a
  `recover-` file left by a crash is reclassified before pruning. `trash empty`
  writes and verifies a recovery copy before its purge commits: a copy that
  cannot be written aborts the deletion with nothing purged, and exceeding the
  ordinary budget requires explicit approval (exit 9 when declined). `verify`
  is a read-only full re-hash/authentication pass that reports object/record/
  head/history/tombstone counts, the local sequence and the anchor comparison
  (`verified|advanced|missing|mismatch`) as human lines or documented JSON.
  `snapshot ls` authenticates every header with the vault key and lists only
  same-vault, same-generation archives newest first; unauthenticatable files
  are stderr warnings, never rows. Snapshot files carry no password slot, and
  snapshot failures or budget skips are warnings that never fail the command.
  Limits: `verify` never repairs (the remedy is a snapshot restore, 1.13b), a
  failed verify is not proof of erasure, and archives elsewhere on other media
  remain outside application control. No dependency, schema, MSRV or format
  change.

- 2026-10-28: `qv-store` archives and `verify` (0004 §6, §3.6; plan 0018 steps
  3–6): the bounded archive header codec and `u32be` framing, the writer that
  streams only verified objects to a temp file and checks each object's
  profile, length and SHA-256 against its reference first, the publish
  protocol (temp → re-read and verify with the reader → `fsync` →
  `RENAME_NOREPLACE` → directory `fsync`), the 0004 §6.3 reader, the private
  local-snapshot directory, the full `verify` pass and the `archive_read` fuzz
  target with its CI step. No dependency, schema, MSRV or frozen format change.

### Changed

- 2026-11-02: Removed the vendored x11rb, glib, glib-macros, gtk3-macros and
  selectors forks (plan 0032, owner direction). The same versions now come from
  crates.io; only the hardened dioxus-desktop snapshot remains in
  `third-party/`. The X11 framing check (packets over 1 MiB refused before
  x11rb allocates) moved into QuickVault's own clipboard transport. x11rb's
  ordinary send buffer now briefly holds a copied value (documented
  best-effort intermediate). `deny.toml` gains four justified advisory ignores
  (glib's uncalled unsound iterator, two unmaintained crates, build-time-only
  rand 0.7) and an MPL-2.0 exception for selectors.

- 2026-10-28: Owner-approved 0011 snapshot/`verify` contract (plan 0018, owner
  decision D1): `verify` reports counts, anchor status and fixed-label notes and
  never repairs; `snapshot ls` lists only authenticated same-vault,
  same-generation snapshots; archive IDs are scoped and prefix-addressable; and
  `trash empty` must write and verify a recovery snapshot before it commits.

- 2026-10-27: 0007 §3 amended per owner decision D6: a local snapshot carries
  no password slot and opens with the vault key of the same vault ID and
  generation or the recovery phrase; the new §3.5 requires a password change to
  offer (never to claim erasure of) the pre-change snapshots, and OQ1 is
  resolved. No archive format value changes (plan 0018).

- 2026-10-27: Owner-approved history/restore/purge CLI contract added for
  roadmap phase 1.12: scoped historical version IDs, explicit conflict restore
  consent, protected historical display and local suppression limits (plan 0017).

- 2026-10-27: Use the existing reviewed constant-time implementation for
  confidential attachment-content hash comparisons during staging and reading;
  test rejected digests at first, middle and last byte positions (plan 0016
  review remediation). No format or dependency change.

- 2026-10-27: Fresh-context review approved phase 1.10c (plan 0015), including
  independent maintained-transport and private-Xvfb checks. Owner approved
  plan 0016 and its concrete attachment CLI spec amendment.

- 2026-10-27: Fresh-context review approved phase 1.10b (plan 0014), with
  independent gates passing and no code fixes. The owner approved plan 0015's
  clipboard design and incoming-allocation correction, with continuing authority
  for necessary correctness fixes within that implementation.

- 2026-10-27: Fresh-context review approved phase 1.9's disposable Dioxus
  feasibility scope (plan 0013); root/spike gates pass. Prepared plan 0014
  for remaining CLI editing/trash/signals, with an owner decision pending on
  separating clipboard integration because of dependency buffer/ownership gaps.

- 2026-10-26: Owner selected standard Dioxus webview input for the shared UI.
  Specs 0008/0009 now require bounded input and best-effort cleanup, with
  framework/OS copy limits stated; native dialogs, a fork or a custom engine
  are not required solely for deterministic wiping. D8 resolved; plan 0013
  revised and approved. Related 0002/0012 cross-references, architecture and
  agent guidance updated; core secret handling and release controls retained.

- 2026-10-26: Fresh-context review approved the CLI EOF-CR and deep-listing
  fixes (plan 0011); phase 1.10a is Reviewed.

- 2026-10-26: Fixed CLI password input dropping a final carriage return at EOF.
  Deep listings now traverse iteratively, share path components and flush
  output incrementally; listing order and human/JSON formats are preserved.

- 2026-10-26: Agent guidance now loads spec/layout navigation on demand in
  `.agents/README.md` and uses the architecture and plans index for current
  implementation status. Skills describe targeted roadmap reading, focused
  step verification and full final gates with preserved exit status; review
  checks remain independent. Shorter skill descriptions reduce discovery
  context. Spec/security requirements, approval rules and required gates are
  retained; the specs index no longer calls the repository specification-only.

### Added

- 2026-10-27: Entry history, explicit historical display/reveal, restore as a
  fresh causal edit and confirmed local history purge (plan 0017, phase 1.12).
  Retention targets ten versions under monotonic suppression and existing
  budgets; no active head/conflict/tombstone is pruned. New CLI `history`,
  `history show`, `restore` and `history purge` support scoped historical IDs,
  masked output and explicit conflict-restoration consent. Purge keeps current
  heads but suppresses them if later dominated; snapshots, unseen concurrent
  history and independent copies may remain. No secure-erasure claim.

- 2026-10-27: Streaming attachments through qv-core and `qvault attach
  add|ls|save|rm` (plan 0016, phase 1.11). Imports up to 10 MiB use protected
  chunk buffers, authenticated ordered chunks and complete SHA-256/length
  checks within the existing transaction/anchor path. Metadata hashes now
  zeroize on drop and rejected decode. Listing supports JSON; plaintext save
  requires explicit consent and a new owner-only path, with no overwrite,
  symlink traversal, temporary plaintext or automatic file opening. Removal
  confirms permanent causal deletion and prunes by references. Failed/crashed
  exports can leave incomplete plaintext; independent copies are not erased.

- 2026-10-27: CLI `copy`, `totp --copy` and `generate --copy` (plan 0015,
  phase 1.10c). The private X11 adapter uses sensitive hints, a foreground
  timeout/countdown and signal cleanup after dropping vault keys/metadata.
  Window/connection release preserves a newer owner; INCR transfers and I/O
  have explicit budgets. Maintained x11rb source protects outgoing buffers and
  checks incoming lengths before allocation. Provenance/header-checker rules,
  two documented vet exemptions and isolated-Xvfb CI tests accompany it.
  Native Wayland requires XWayland; clipboard managers/recipients may retain
  copies despite hints and timeout. No secure-erasure claim.

- 2026-10-27: CLI entry editing (`add`, `edit`), groups/moves/deletion
  (`mkdir [-p]`, `mv`, `rm [-r]`) and `trash ls|restore|empty` (plan 0014,
  phase 1.10b). Notes and protected fields use bounded no-echo prompts;
  `-i` prompts field values, and stdin/password prompt conflicts fail before
  unlocking. SIGINT/TERM/HUP cancel input/countdowns and restore terminal and
  recovery alternate-screen state. Core drafts preserve untouched data; trash
  empty confirms unless `--yes`. Clipboard commands remain phase 1.10c.


- 2026-10-26: Isolated non-production Dioxus spike source and protected fixture
  controller (plan 0013). Linux create/edit/reopen, input cleanup and five
  full-profile unlock samples validated; arm64 APK built with minimum Android 10, backups off and
  no personal-data permissions. Dioxus loopback IPC requires Android
  INTERNET permission (also capable of remote networking). Device validation
  now passes on the connected phone, including persistence/background lock and
  screenshot blocking; five unlock samples measure 852–881 ms (median 865 ms).
  Fixed required loopback packaging policy and canonical app-private paths while
  retaining storage checks. Four approved spike-only advisory exceptions and an isolated vet baseline retain root policy.

- 2026-10-26: Plan 0013 for phase 1.9 Android/Linux feasibility, with verified
  physical-device prerequisites and explicit phone-operation boundaries.
  The initial native-input proposal was replaced by the owner's Dioxus input
  decision; no spike app has been installed yet.

- 2026-10-26: Withdrew unapproved CLI plan 0012 after the owner corrected
  phase selection to the unfinished Android/Linux feasibility phase 1.9.
  No CLI scope or behavior changed.

- 2026-10-26: `scripts/setup-android.sh`: installs the Android command-line
  tools (checksum-pinned), platform 35, build-tools 35.0.0, NDK r27
  (27.3.13750724) and the Rust Android targets; `--print-env` prints the
  variables for Android builds (minimum API 29). The SDK goes to
  `$HOME/Android/Sdk`, or to the git-ignored `.android-sdk/` when `$HOME` is
  read-only.

- 2026-10-26: Spec 0009 §2: the supported Android baseline (arm64, Android
  10+, at least 4 GB RAM) is the target of the 0002 §1.3 KDF budgets; no named
  benchmark devices (roadmap D7, owner decision).

- 2026-10-26: CLI foundation, vault and read commands (roadmap phase
  1.10a, plan 0011). New crate `qv-cli`, binary `qvault`: `init` (a
  suggested 6-word passphrase, the zxcvbn verdict with the 5-second weak
  password confirmation, the recovery phrase on the alternate screen, a
  three-word check or a recorded skip), `info` (the unverified header without
  a password; `--full` unlocks), `ls`, `search`, `show` (masked unless
  `--reveal`; `--field` for scripts), `totp` and `generate`. Vault selection
  by `--vault`, `QVAULT_PATH` or the config file (a strict TOML subset);
  `--password-stdin`; `--json`; no-echo prompts with the terminal state
  always restored; all vault text escaped (ANSI/OSC, C1, bidi controls) and
  written from zeroizing buffers; exit codes per 0011 §6; PTY end-to-end
  tests. `qv-core` gains the header view, the zxcvbn master-password
  estimate, the recovery-phrase confirmation positions and recorded skip,
  `@id` lookup, and refuses a vault stored inside the anchor directory
  (review of plan 0009). `qv-model` stores the skip at settings key 3, and
  new generator defaults replace an unreadable stored value (review of plan
  0010). Spec 0010 §3.2: a zxcvbn estimate at its 64-bit ceiling counts as
  Strong. New dependencies: `clap` (builder API) and `zxcvbn`.

- 2026-10-26: `qv-core` sessions and vault operations (roadmap phase 1.8,
  plan 0010). New crate `qv-core`, the single entry point for frontends:
  `Core` hardens the process and reports reduced protection, creates vaults
  (returning the recovery phrase once) and unlocks them, including the
  read-only recovery unlock with `adopt_baseline`. A `Session` serializes
  calls, and `lock` cancels running work, drops and zeroizes the vault, keys
  and views, and is final; handles carry a random session tag. The metadata
  index (64 MiB budget) keeps only non-protected metadata; protected values
  and notes are decrypted on demand (`entry`, `reveal`, `totp`, drafts).
  Search covers titles, group names and non-protected text, URL and e-mail
  fields, with no search index. Listings follow the repaired group tree,
  with recovered items. Edits, moves and settings go through drafts that
  carry their base version, as causal versions committed by the store's one
  transaction. Conflicts are shown, and their records refused for changes
  until phase 2.2. The trash: a group is deleted with its contents in one
  transaction and restored with what was deleted with it; final deletion is
  explicit, leaves a tombstone, drops history, advances the floor and
  tombstones the entry's attachments; an expiry report lists what the
  retention period offers and flags clock anomalies. `qv-store`: a final
  tombstone drops the record's history and advances its floor; manifest
  types print a redacted `Debug` (review of plan 0009). `qv-model`: password
  generator defaults in vault settings (key 2).

- 2026-10-26: Objects, manifests, local head, anchor and the write path
  (roadmap phase 1.7, plan 0009). `qv-store` now stores records as
  encrypted immutable objects whose plaintext envelope holds only object ID,
  key generation, profile, nonce and ciphertext; the encrypted manifest
  (heads, history, floors, chunk lists, sorted references, configuration
  digest, the three control records) with its envelope hash and reference
  digest, validated and bounded before allocation; the authenticated local
  head; per-replica external anchors in a private state directory; and
  writer IDs with counter reservations in a local-only `replica` row. `create`
  writes the vault metadata, root group and password-keyslot records;
  `unlock` verifies the head, manifest, every referenced object row and
  every head (0004 §3.6) and compares the head with its anchor (0005 §5.4),
  failing closed on a missing or mismatched anchor, with
  `unlock_for_recovery` + `adopt_baseline` as the explicit recovery. All
  writes go through one mutation transaction (head re-read inside
  `BEGIN IMMEDIATE`, objects, manifest, head, counters, prune, durable
  commit, anchor, report), checked at every ordering point by a test-only
  crash-injection harness. New errors `Rollback`, `NoAnchor`, `Changed`,
  `InvalidEdit`; a full disk is no longer reported as the size budget.
  Development schema 2. New `manifest_decode` fuzz target, run in CI. The
  generated worst-case manifest at every budget is 50.0 MiB, inside the
  64 MiB limit. `qv-crypto`: the `local-state` key MACs; `qv-model`: public
  clock codec. Spec 0004 amended (below).

- 2026-10-26: Vault file: hardened SQLite, schema, header and keyslots
  (roadmap phase 1.6, plan 0008). New crate `qv-store`: owner-only vault
  files (symlinks, nonregular files, unsafe modes and unsafe parent
  directories refused), a `flock` process lock, file-identity tracking and
  sync-folder/network/removable location warnings; SQLite opened with every
  0004 §1.2 setting read back (defensive mode, no triggers/views/extensions,
  limits, an execution-step budget, a 2 GiB size cap), bounded
  `quick_check` and exact-schema validation; the header and the local
  password slot under the header MAC; atomic `create` (temp file and
  no-replace rename) and `open` → `unlock` to VK, with wrong password and
  integrity failures kept distinct. Formats are development values until
  phase 1.16. New dependency `rusqlite` with bundled SQLite 3.53.2, whose
  compile options `.cargo/config.toml` trims (no FTS, R-Tree, dbstat, JSON,
  extension loading or URI filenames; checked by a test); `rustix` gains its
  `fs` feature. New `vault_open` fuzz target, run in CI, plus tamper and
  second-process lock suites. `qv-model` gains a public keyslot-descriptor
  codec.

- 2026-10-26: Data model, version vectors and merge (roadmap phase 1.5,
  plan 0007). New crate `qv-model`: random UUIDv4 IDs (validated on decode),
  the record-version plaintext and the five payload kinds (vault metadata
  with settings, groups, entries with typed fields, attachment metadata, the
  password keyslot) as canonical CBOR with an integer-key registry
  (development values until the 1.16 format freeze), unknown-key
  preservation and 0004 §4.1 budgets checked before allocation; version
  vectors with the sorted-pair wire form, join and edit clocks; the
  maximal-version merge with its integrity checks, head limit, live/trash
  representatives and record status; history floors as data; the
  deterministic group-tree projection with a recovered-items view; and
  `otpauth://totp` parsing with RFC 6238 codes. `qv-crypto` gains `hotp`
  (RFC 4226 over the pinned HMAC crates; RFC 4226 and RFC 6238 vectors) and
  the new dependency `sha1`. Property tests cover merge commutativity,
  associativity and idempotence over generated histories and the 0012 rows
  for old-date edits, mixed credentials and deleted-entry resurrection. New
  `record_decode` fuzz target with a canonical round-trip oracle, run in CI.

- 2026-10-25: Recovery phrase and password generator (roadmap phase 1.4,
  plan 0006). `qv-crypto` encodes VK as 24 BIP-39 English words (entropy
  encoding only, not the wallet seed) and decodes it back with
  constant-time word lookups and checksum checks; `RecoveryPhrase::confirm_word`
  supports confirmation at vault creation. Trezor BIP-39 vectors pass. The
  spec 0010 generator covers random characters, passphrases (EFF large list)
  and PINs. Every setting is validated before any randomness is used,
  selection is unbiased rejection sampling, `require_each_class` regenerates
  whole passwords (at most 10,000 attempts) and never patches them, and
  entropy, strength labels and the 64-bit warning are exact. Deterministic
  chi-square tests cover every sampling path. Both word lists are embedded
  byte for byte, and their SHA-256 is checked at first use and in tests
  (sources and licences in `crates/qv-crypto/data/README.md`; `.gitattributes`
  keeps their line endings). New `CryptoError::WrongPhrase` (exit code 3).
  New direct dependency `ctutils` (already in the build via `hmac`), approved
  by the owner instead of `subtle`, whose `BSD-3-Clause` licence is outside the
  allow-list. `zxcvbn` estimates for typed passwords come with the CLI
  (phase 1.10).

- 2026-10-25: Review fix (plan 0005): other crates could read raw AEAD/MAC
  key bytes through the sealed key-use traits; the accessors now require a
  crate-private token, with compile-fail tests.

- 2026-10-25: Crypto profiles and key hierarchy (roadmap phase 1.3, plan
  0005): `qv-crypto` gains the profile registry (one type per namespace;
  unknown IDs fail closed; explicit transitions), password-kdf/1 (Argon2id
  over the NFC master password), the KEK and its constant-time commitment,
  password slots that report only "wrong password" (with a
  partitioning-oracle test), HKDF-SHA-512 purpose keys for all nine labels
  as purpose-typed keys, per-record and per-attachment keys, stored-data/1
  (XChaCha20-Poly1305 with canonical Padmé framing and budgets checked
  before decryption), MAC/1, object-hash/1 and the redacted `CryptoError`.
  Upstream known-answer vectors: RFC 4231, Wycheproof HKDF-SHA-512, FIPS
  180-4, draft-irtf-cfrg-xchacha-03 and RFC 9106. Development-only
  QuickVault vectors are cross-checked by a stdlib Python script and by
  OpenSSL's Argon2id. New dependencies: `chacha20poly1305`, `argon2`, `hkdf`,
  `hmac`, `sha2` and `unicode-normalization`; `deny.toml` now allows
  `Unicode-3.0` (Unicode data tables), approved by the owner.

- 2026-10-25: Canonical CBOR (roadmap phase 1.2, plan 0004): new crate
  `qv-encoding` implementing the spec 0004 §3.1 profile of RFC 8949
  deterministic CBOR. It validates the whole input without allocating before
  any typed read, and rejects every noncanonical form, tags, floats, other
  simple values, invalid UTF-8, non-integer, duplicate or misordered map keys,
  nesting deeper than 32 and lengths beyond the input. The encoder can only
  emit canonical items (sorted maps, exact counts) and wipes its buffers.
  `RawValue` preserves unknown map entries byte for byte, and `encode_array`
  builds AAD/info/transcripts. Property tests (`proptest`, dev-only) and a
  `cbor_decode` fuzz target (`fuzz/`, cargo-fuzz) with a new CI job.

- 2026-10-25: Cargo workspace and tooling (roadmap phase 1.1, plan 0003):
  pinned Rust 1.98.1, workspace lints (no `unsafe`, no `unwrap`/`expect`
  outside tests), `cargo deny` and `cargo vet` configuration, SPDX header
  check, GitHub Actions CI. New crate `qv-crypto` with zeroizing, page-locked,
  unprintable and non-cloneable secret buffers (`SecretBytes`, `SecretArray`),
  reduced-protection reporting when locking fails, core-dump/debugger-attach
  hardening on Linux/Android, and a fail-closed OS RNG.

- 2026-10-25: Development roadmap (`plans/0002-roadmap/`): 37 phases across
  the four milestones of `ARCHITECTURE.md` §7, one phase per session. Records
  the owner's decisions on toolchain/MSRV, CI, SPDX headers, workspace layout,
  go-ahead for the Draft sections milestone 1 needs, snapshot password slots
  and CLI attachment commands.

- 2026-10-16: Agent workflow. `AGENTS.md` (with `CLAUDE.md` symlink), skills in
  `.agents/skills/` (`quickvault-thinker`, `quickvault-architect`,
  `quickvault-developer`, `quickvault-reviewer`) symlinked from `.claude/skills`,
  the `plans/` directory, this changelog, and search guards (`.ignore`,
  `.gitignore`, `.claude/settings.json`).

### Fixed

- 2026-10-26: `qv-store`'s `adopt_baseline` now retries a pending anchor
  update before it commits, as every other write does (review of plan 0009).
  Before, a recovery after a failed anchor write could leave the database
  two commits ahead of its anchor, so the next open reported a rollback.

- 2026-10-26: `qv-store` no longer lets a file planted next to the vault
  rewrite it before validation (review of plan 0008). SQLite rolled back a
  hot `<vault>-journal` and replayed a `<vault>-wal` before any check ran;
  a crafted 512-byte journal truncated the vault, and a WAL changed it on
  disk. A `-journal` must now be owner-only like the vault, and a `-wal` or
  `-shm` is refused. The parent directory must be writable by no one but
  the owner (0004 §1.1): the sticky-bit exception is gone, and group write
  is allowed only for Android's per-app `0771` directory.

- 2026-10-26: `qv-model` no longer encodes a record whose embedded
  `qv-crypto` ID (root group, group parent, entry group, attachment entry,
  slot ID) lacks the UUIDv4 bits, which decode would reject (review of
  plan 0007).

### Specs

- 2026-10-26: 0004 §4.1/§4.2: an aggregate budget of 1,048,576 clock
  components per manifest, so that the worst-case manifest fits the 64 MiB
  limit (256 writers per clock over 250,000 objects did not); history yields
  to it. 0004 §2: the local-only `replica` row (writer state and the
  anchor's name). Owner-approved with plan 0009.

- 2026-10-24: Prioritize Android alongside Linux before the optional server;
  retain iOS as later work. Specify shared cross-platform app/UI code, isolated
  OS adapters and early Android/Linux framework validation. Preserve Dioxus as
  the planned framework, the open renderer decision and existing security gates.

- 2026-10-24: Follow-up direction: start both LAN and remote sync with manual
  user initiation. Remove automatic unlock/edit/timer triggers, defer background
  scheduling/retries, and align client/CLI requirements and acceptance criteria.

- 2026-10-24: Refocus QuickVault on complete offline use with two independent
  optional sync modes: direct account-free LAN peer sync and account-based
  remote server sync. Align architecture, roadmap, threat model, key rotation,
  storage, history, clients, CLI and separate validation gates; retain existing
  merge/crypto guarantees and record unresolved LAN protocol decisions.
  Document the amendment and review in `plans/0001-offline-first-sync/`.

- 2026-10-14 – 2026-10-15: Initial specs 0001–0012 and `ARCHITECTURE.md`, then
  amendments from a security review. See each spec's *Changelog*.
