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

1.4. Delivery follows ARCHITECTURE.md §7: complete offline Linux CLI first,
then LAN sync with Linux desktop in phase 2, then optional remote service in
phase 3. Each later platform inherits these independent modes subject to its
own validation gates. LAN discovery/enrollment/session choices remain open in
0005; platform APIs and permissions must be validated before enabling them.

1.5. Initial LAN and remote sync MUST be initiated by an explicit user action
for the selected mode (0005 §0.5). Unlocking, editing, login, timers and network
availability MUST NOT trigger a round. Pending changes remain local until
the user requests sync; automatic sync and background retries are deferred.

### 2. Platform priority

1. Linux 2. Android 3. Windows 4. iOS 5. macOS 6. BSDs (evaluate; the CLI is
the likely first target there).

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

4.1. Dioxus provides the main UI; native secure input and OS autofill controls
are required security adapters, not optional attempts to eliminate platform glue.

4.2. Autofill logic (matching, unlock, fill) lives in Rust (`qv-platform`).
The OS-facing entry points are the **thinnest possible glue**: on Android a
minimal class forwarding to Rust via JNI (or pure Rust via `jni` if feasible);
on iOS a minimal extension linking the Rust static library.

4.3. Autofill uses an implemented authenticated platform-wrap backend. If it
is unavailable/expired or a full KDF exceeds extension limits, hand off to the
main app for native secure input; never weaken the vault KDF. Process separation
uses an authenticated OS-protected channel with short-lived scoped results,
not a shared plaintext key file. Verify app signing identity and web origin using
platform association APIs; never match by app label, substring or unverified
custom scheme. Require choosing an unresolved credential version before filling.

### 5. Desktop specifics

- Single-instance; lock on screen lock/sleep via OS signals (logind/D-Bus on
  Linux, WTS session notifications on Windows).
- Quick unlock: only a validated backend with the authentication and backup
  behavior specified in 0002 §5; unavailable backends remain disabled.

## Security Considerations

OS entry points and native adapters are part of the trusted client, with bounded
authenticated IPC and session cancellation (0008). Validate packaging, access
groups, backup exclusions and locking on each target. Framework support alone
does not establish secure input, keystore enforcement or autofill-origin trust.

## Open Questions

1. CLI agent process (post-v1): design and IPC security.
2. Minimum native secure-input/autofill glue and lifecycle integration per OS.
3. Dioxus mobile maturity for Android: needs a spike before committing.

## Changelog

- 2026-10-24: Follow-up: initial LAN and remote sync is manually initiated;
  defer automatic triggers and background retries across clients.
- 2026-10-24: Make local use independent of login/network setup; expose LAN and
  remote sync as independent optional modes with separate status, and align LAN
  delivery before the optional remote server.
- 2026-10-14: Initial draft.
- 2026-10-14: CLI v1 prompts per command; `--reveal` required to print secrets.

- 2026-10-15: Require native input, verified autofill origins and main-app handoff
  when extensions cannot perform full unlock; prioritize secure OS integration.
