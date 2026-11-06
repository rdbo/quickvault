# 0009 — Clients and Platforms

| Status | Created | Depends on |
|--------|---------|------------|
| Draft | 2026-10-14 | 0002, 0008 |

## Summary

Which clients exist, in what order, and how platform-specific features
(autofill, keystore, clipboard) attach to the shared Rust core.

## Specification

### 1. Clients

| Client | Crate | Framework | v1 |
|--------|-------|-----------|----|
| Desktop app | `qv-app` | Dioxus desktop | ✅ |
| Mobile app | `qv-app` | Dioxus mobile | ✅ |
| CLI | `qv-cli` | clap | ✅ |
| Browser extension | — | — | later |
| Auto-type | — | — | not planned yet |

1.1. All clients use `qv-core` as the only way to touch vaults. No client
reads the vault file or calls `qv-crypto` directly.

1.2. Every client is a local vault client first: account creation, login and
network access MUST NOT be prerequisites for local creation, unlock, reads,
edits or recovery. Sync is an optional capability exposed through `qv-core`.

1.3. The two network sync modes are direct LAN peer-to-peer sync (0005 §6)
and account-based remote server sync (0005 §3, 0006). Support neither, either
or both on a vault; enabling LAN MUST NOT require remote account setup. Present
local save status separately from LAN peer receipt and server publication.
Account/session failures must leave local access and approved LAN use available.

1.4. Delivery follows ARCHITECTURE.md §7: develop the shared offline Rust core,
an early Linux CLI and Android/Linux framework feasibility work in phase 1.
Deliver usable offline Android and Linux apps plus manual LAN sync in phase 2;
the optional remote service follows in phase 3. Android work MUST NOT wait for
completion of the full CLI or implementation of the remote server. Each later
platform inherits the independent sync modes subject to its own gates. LAN
discovery/enrollment/session choices remain open in 0005; platform APIs and
permissions must be validated before enabling them.

1.5. Initial LAN and remote sync MUST be initiated by an explicit user action
for the selected mode (0005 §0.5). Unlocking, editing, login, timers and network
availability MUST NOT trigger a round. Pending changes remain local until
the user requests sync; automatic sync and background retries are deferred.

1.6. `qv-app` MUST use a shared cross-platform application and UI codebase for
Android and Linux: reuse screens, navigation, state and vault workflows, with
layouts adapted for touch and desktop. The shared Rust core remains responsible
for vault behavior. Isolate necessary OS-specific key storage,
biometrics, lifecycle, clipboard and autofill integration in `qv-platform` and
minimal packaging/entry-point glue. Framework APIs and reviewed libraries MAY
implement these adapters where they satisfy the security contract. Do not
duplicate the application per OS or claim that cross-platform rendering alone
implements OS security and autofill integration.

1.7. **LAN QR camera input (Android).** The shared app renders the exact binary
QR payloads of 0013 §4.2 and §8.5 with a four-module quiet zone; typing remains
available. Scanning fills a selected Join/Link/Sync form and MUST NOT start a
network operation. Apply the same canonical payload/profile and endpoint policy
as typed input; scanned addresses grant no trust. Reject ambiguous multiple codes.

Request camera permission only after an explicit Scan action, never at startup.
Use an in-app native preview in the existing activity; the webview's camera
permission remains denied. Keep camera frames in memory only, with one pending
bounded luminance frame (at most 1024 pixels per axis and 786432 pixels total),
at most two offered frames per second and a 30-second scan action. No gallery,
external camera app, captured-image file, cloud/service decoder or background
camera is used. A scan closes on cancel, denial, failure, timeout, lock, pause
or destruction; erase pending frames and reject stale request/epoch results.
Camera windows use FLAG_SECURE. Scans do not defer background locking.

Binary pairing payloads and QR modules use protected Rust buffers. Wipe exposed
JVM/native adapter and decoder buffers promptly; OS/camera/JVM/library scratch
copies follow 0008's documented best-effort cleanup limits. No QR payload or
image enters logs, errors, argv, saved state or clipboard. Camera support is
optional and remains disabled in ordinary packages until physical-device
permission/lifecycle/cleanup validation passes (0012 §3); explicitly marked
validation packages may exercise the implemented path.

1.8. **App shell and preferences.**
- **Window.** The desktop app draws its own title bar without OS decorations:
  drag to move, double-click to maximize, minimize/maximize/close buttons and
  edge resize handles. Android has no title bar.
- **Preferences.** The app keeps one non-secret preferences file in its
  private state directory:
  - the theme (dark, light or follow the system);
  - the protection status the user last acknowledged.

  It is bounded (at most 256 bytes), parsed strictly, written to a mode-0600
  temporary file and renamed into place, and never followed through a link.
  Any failure falls back to the defaults. It holds no vault data, name or path.
- **Reduced-protection acknowledgement.** 0008 §1.3–1.4's acknowledgement is
  explicit and remembered per protection status:
  - when protection is reduced, create/unlock/recover are refused until the
    user acknowledges the shown status;
  - a changed status asks again;
  - complete protection asks nothing;
  - the mode stays visible in security settings.
  - On Linux without screen-lock/sleep detection, 0008 §1.4's notice:
    - before use: it is in that acknowledgement and the locked screen's
      protection chip;
    - while unlocked: a lasting mark on the lock button, whose label says
      screen lock and sleep do not lock QuickVault, and an "Idle only"
      auto-lock row in security settings.

    It is not a permanent banner. Nothing claims OS-triggered locking while
    it is unavailable.
- **Files without typed paths.** Vault files, attachments, archives and
  snapshot-restore targets are chosen through the system picker: the Android
  Storage Access Framework, or the Linux xdg-desktop-portal FileChooser.
  - Only local `file:` results are accepted.
  - 0011 §4's no-follow and ownership rules still apply to the chosen path.
  - A path field appears only when no picker is available.
- **Inactivity.** The 60-second inactivity lock counts any use of the window
  as activity: keys, clicks, typing, pointer movement, scrolling and touch.
  Pointer movement and scrolling are reported at most once a second, without
  positions, because the webview bridge forwards only click, input, change,
  key and focus events.
- **Vault list** (plan 0041).
  - **Names (owner, 2026-11-06, refining 2026-11-05):** a vault has one
    name, the one stored (encrypted and synced) in its metadata.
    - Vault names are not secret: the app keeps a plaintext copy in its
      private list, refreshed at each unlock and rename, so the lock screen
      can show it.
    - A vault never opened on this device shows its file name until then.
    - Files are never renamed.
  - **Create:** a vault is created by name in a default folder; its file
    starts as `<name>.qvault`.
    - Linux: `$XDG_DATA_HOME/quickvault/vaults` (absolute only) or
      `~/.local/share/quickvault/vaults`, which the user may change.
    - Android and validation builds: the app's private `vaults/` directory.

    A name is 1–64 characters, without `/`, `\` or control characters, and
    does not start with a dot. An existing file is never replaced.
  - **Import (owner, 2026-11-05):** the system picker references a file
    where it is, without copying it.
  - **The list file:** a separate private file, never the preferences
    file. It is bounded (640 KiB; at most 64 remembered absolute `.qvault`
    paths of at most 4096 bytes, each with a copied name of at most 256
    bytes, and one default folder), parsed strictly
    (malformed lines ignored), never read through a link, and written to a
    0600 temporary file and renamed into place.
  - **What is listed:** the remembered paths, plus regular `.qvault` files
    directly in the default folder (at most 64, links skipped).
  - **Opening:** every listed path still passes 0011 §4's checks when opened.
    The list only removes paths when the user asks, and never deletes files.
- **Item editor.** A new item starts from one box, "What are you saving?".
  - The guess runs on the device. Nothing is looked up online.
  - The box is a protected input, since people paste card numbers into it.
    For a card, only its brand, last four digits and checksum validity are
    shown, and the number moves into the protected card-number field.
  - The card-number input shows what the user types, grouped like the card,
    so it can be checked. The value is still stored protected, and a saved
    or start-box number shows only its last four digits.
  - Values derived from protected fields are limited to:
    - a card number's brand, last four digits and validity;
    - whether a protected field has a saved value.
  - Typed passwords get no strength meter in the item editor. Generated ones
    show the generator's exact entropy, and "Use it" moves the value into
    the field in Rust.
  - A Wi‑Fi item's page can show a `WIFI:` join QR code. It contains the
    password, so it is an explicit 30-second reveal under 0008 §4.
  - Tiles show the colour token of 0003 §5.5.

### 2. Platform priority

Android is the primary mobile target and Linux is its initial desktop companion;
both participate in initial development and the first usable app milestone.
Windows follows. iOS is desirable later, followed by macOS; evaluate BSDs with
the CLI as the likely first target. Initial Android/Linux delivery MUST NOT
depend on iOS packaging or feature parity, and mobile MUST NOT be deferred
behind the remote service.

**Supported Android baseline** (the "supported" devices of 0002 §1.3 and
0004 OQ1): arm64, Android 10 (API 29) or later, at least 4 GB of RAM, which
covers ordinary phones from about 2019 on. One such device is the low-end
target; benchmarks need no named models. Older or smaller devices are not
supported targets.

### 3. CLI (v1)

The full command set is specified in [0011](0011-cli.md).

- **Unlocking (v1):** every command that needs the vault prompts for the
  master password and locks again when it exits. No background agent in v1;
  an `ssh-agent`-style agent MAY be added later.
- Protected values are never printed unless `--reveal` is passed. By default
  `copy` puts them on the clipboard (with auto-clear, 0008 §3) and `show`
  masks them.
- Password prompts read from the TTY, never from arguments or environment
  variables.

### 4. Mobile autofill

The OS controls how password managers plug in:

- **Android:** an `AutofillService` (and Credential Manager provider) is a
  Java/Kotlin class declared in the manifest, which the OS instantiates in the
  app's process when a form needs filling.
- **iOS:** a Credential Provider *Extension*: a separate app extension
  target with its own process and a strict memory limit (~120 MB).

This is a packaging/OS constraint, not a language one: the logic can be Rust.
Plan:

4.1. Dioxus provides the shared UI, including standard webview secret-input
controls under 0008 §1.1/§4.4. Native OS autofill, keystore, biometric and
lifecycle entry points remain platform adapters. No native password dialog
is required solely to avoid framework-managed memory copies.

4.2. Autofill logic (matching, unlock, fill) lives in Rust (`qv-platform`).
The OS-facing entry points are the **thinnest possible glue**: on Android a
minimal class forwarding to Rust via JNI (or pure Rust via `jni` if feasible);
on iOS a minimal extension linking the Rust static library.

4.3. Autofill uses an implemented authenticated platform-wrap backend. If it
is unavailable/expired or a full KDF exceeds extension limits, hand off to the
main app for the Dioxus unlock flow; never weaken the vault KDF. Process separation
uses an authenticated OS-protected channel with short-lived scoped results,
not a shared plaintext key file. Verify app signing identity and web origin using
platform association APIs; never match by app label, substring or unverified
custom scheme. Require choosing an unresolved credential version before filling.

4.4. **Android profile.** Identity matching is exact; no fill ever depends
on titles, labels, activity names or URL substrings.

- *App identity* is the requesting activity's package name as reported by the
  system (`AssistStructure` activity component), plus the SHA-256 digests of
  its complete current signing-certificate set read from the package manager.
  An entry carries an app identity as a `url` field
  `androidapp://<package>#sha256=<hex>[,<hex>…]` (lowercase hex, at most 8
  digests). It matches only when package and digest set are equal. An
  identity without digests, or with a malformed or partial set, never matches.
  Linking an app to an entry is an explicit, confirmed user action that uses
  the OS-verified values and warns that QuickVault cannot confirm the app
  belongs to the service.
- *Web origin* is accepted only from a browser on a built-in allowlist pinned
  by package and exact signing-digest set. Entries are added only from digests
  observed on a validated device; another app's claimed web domain is ignored.
  A stored `https://` or `http://` URL matches only on an equal scheme,
  lowercase ASCII host and port (defaults 443/80). There is no subdomain,
  parent-domain or registrable-domain matching. Userinfo, non-ASCII and
  percent-encoded hosts, IPv6 literals and custom schemes never match.
  Digital Asset Links association is deferred: it needs a network fetch, which
  this offline profile does not perform.
- *Handoff:* the autofill service returns only an authentication entry with a
  generic label. Its immutable explicit intent targets a non-exported activity
  and carries a one-shot random token (at least 128 bits) for a single
  in-process request. The token can be claimed at most 120 seconds after the
  request; a claimed request expires at most 10 minutes after the request,
  after which its result is never delivered and is zeroed. Request identity and
  results never travel in intent extras. The shared app shows the requester,
  requires unlock and an explicit choice (including a version of a conflicted
  entry), and returns only the chosen username/password for the requested
  fields. The handoff activity re-reads the requester's signing digests before
  returning the dataset. A lock after the request is bound to an unlocked
  session cancels it.
- *Gate:* autofill answers no request on devices without recorded
  validation (0012 §3).

### 5. Desktop specifics

- Single-instance; support manual and inactivity locking independently of OS
  notification services. Lock on screen lock/sleep via available OS signals
  (for example logind/D-Bus on Linux, WTS session notifications on Windows).
  On Linux this automatic OS integration is optional: detect and prominently
  disclose its absence, with 0008 §1.3–1.4's reduced-protection acknowledgement,
  while allowing local create/unlock/recovery. Never claim unavailable signals
  are monitored. Failure/loss must not disable manual or inactivity locking.
- Quick unlock: only a validated backend with the authentication and backup
  behavior specified in 0002 §5; unavailable backends remain disabled.

### 6. Early cross-platform framework validation

Dioxus with its standard webview renderer and input controls is the owner's
selected shared UI framework (2026-10-26; 0008 OQ2). Validate integration on
Android and Linux during phase 1, before building the full application.
Demonstrate shared vault-list and entry-editing flows against the same core,
offline persistence, bounded secret-input cleanup and lifecycle
locking/cancellation on an Android device. Check access to keystore/biometrics, clipboard and the autofill service
entry point; identify required adapter/packaging work and benchmark unlock and
memory budgets. A successful empty app build is insufficient evidence of fit.
Feature-specific release gates still apply; this feasibility work does not
require shipping every adapter or implementing iOS first.

Document integration/security gaps and address them in the relevant phase;
do not infer complete framework-memory erasure or require a replacement renderer
merely because internal copies are outside application control. Active-content,
session, OS and release requirements remain in force. A framework replacement
requires a new owner decision; do not create separate Android/Linux app UIs.

The [Dioxus mobile guide](https://dioxuslabs.com/learn/0.7/guides/platforms/mobile/)
describes Android/iOS support with a WebView renderer and experimental rendering
alternatives. Android's [autofill service requirements](https://developer.android.com/identity/autofill/autofill-services)
and Apple's [credential-provider extension requirements](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
remain OS integration work. These sources establish platform mechanisms, not
QuickVault implementation readiness or validation (consulted 2026-10-24).

## Security Considerations

OS entry points and native adapters are part of the trusted client, with bounded
authenticated IPC and session cancellation (0008). Validate packaging, access
groups, backup exclusions and locking on each target. Framework support alone
does not establish input cleanup, keystore enforcement or autofill-origin trust.

## Open Questions

1. CLI agent process (post-v1): design and IPC security.
2. Minimum OS adapter/autofill glue and lifecycle integration per OS.
   Android autofill glue is specified in §4.4 (2026-11-02); other OSes remain open.
3. **Framework choice resolved 2026-10-26 (owner):** use Dioxus and standard
   webview input. Phase 1 (§6) validates integration and records gaps; it does
   not reconsider native input or a custom engine just for memory-copy concerns.

## Changelog

- 2026-11-06: §1.8 vault names: the stored, synced vault name is the only
  name; the lock screen shows a private copy, and files are never renamed
  (owner, refining 2026-11-05).
- 2026-11-06: §1.8 "Vault names" becomes "Vault list" (plan 0041): file names
  are the visible vault names (owner decision 2026-11-05), name-only create in
  a default folder, import in place, a bounded private vault-list file.
- 2026-11-06: §1.8: pointer movement, scrolling and touch count as activity
  for the inactivity lock; the card-number input shows typed digits grouped
  (owner feedback; owner-delegated details).
- 2026-11-06: §1.8: present the missing Linux lock detection as a mark on
  the lock button and an "Idle only" settings row, not a permanent banner
  (owner: the banner "never goes away"; presentation owner-delegated).
- 2026-11-05: §1.8 item editor: on-device start guess with a protected
  start box, limited derived displays of protected values, generated-only
  strength, a Wi‑Fi join QR as a timed reveal, colour tokens (plan 0040,
  owner-approved prototype; details owner-delegated).
- 2026-11-05: Add §1.8, the owner-delegated app shell and preferences profile
  (plan 0040): own title bar, non-secret preferences file, per-status
  reduced-protection acknowledgement, system file pickers instead of typed
  paths, no vault name before unlock.
- 2026-11-03: Add §1.7, the owner-delegated Android LAN QR camera profile
  (plan 0039): binary QR display, bounded in-memory Camera2 capture, action-only
  permission, form-only scan acceptance, lifecycle cleanup and device gate.


- 2026-11-02: §4.4 states the handoff lifetimes as implemented: the token can
  be claimed for up to 120 seconds, and a claimed request lives for up to
  10 minutes (plan 0034 review; owner standing delegation). Still Draft.

- 2026-11-02: Add §4.4 Android autofill profile: exact verified app
  signer/package and allowlisted-browser origin matching, explicit app linking,
  non-exported one-shot handoff, lock cancellation and device gating; Digital
  Asset Links deferred (network). Decided under the owner's standing delegation
  (plan 0034); status remains Draft.

- 2026-11-01: Owner makes Linux automatic OS lock/sleep integration optional.
  Detect/report capability and permit local use when unavailable, retaining
  manual/idle locking and explicit reduced-protection policy (0008 §1.3–1.4).

- 2026-10-26: Owner chose Dioxus and standard webview secret input; resolve the
  renderer choice and update feasibility/autofill handoff wording. Retain
  platform-specific OS adapters and release validation.

- 2026-10-24: Prioritize Android alongside Linux for initial app development,
  ahead of the remote server; defer iOS. Require shared cross-platform app/UI
  code with isolated platform adapters and early Android/Linux framework
  validation, preserving the open renderer choice and security requirements.
- 2026-10-24: Follow-up: initial LAN and remote sync is manually initiated;
  defer automatic triggers and background retries across clients.
- 2026-10-24: Make local use independent of login/network setup; expose LAN and
  remote sync as independent optional modes with separate status, and align LAN
  delivery before the optional remote server.
- 2026-10-14: Initial draft.
- 2026-10-14: CLI v1 prompts per command; `--reveal` required to print secrets.

- 2026-10-15: Require native input, verified autofill origins and main-app handoff
  when extensions cannot perform full unlock; prioritize secure OS integration.
- 2026-10-26: §2: supported Android baseline (arm64, Android 10+, ≥ 4 GB RAM)
  as the target of 0002 §1.3's KDF budgets; no named benchmark devices
  (owner decision, roadmap 0002 D7).
