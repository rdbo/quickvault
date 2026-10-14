# 0001 — Threat Model

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | — |

## Summary

Defines the assets QuickVault protects, the adversaries it considers, and what
is explicitly out of scope. Every other spec's *Security Considerations*
section is judged against this document.

## Assets

| ID | Asset | Notes |
|----|-------|-------|
| A1 | Secret contents of entries (passwords, notes, attachments, TOTP seeds) | Highest value |
| A2 | Vault metadata (titles, usernames, URLs, group structure) | Also confidential |
| A3 | Master password and all derived keys | Compromise ⇒ A1, A2 |
| A4 | Recovery phrase | Equivalent to A3 |
| A5 | Integrity of the vault (no undetected modification, rollback, or deletion) | |
| A6 | Availability of the user's data (history, backups) | |
| A7 | Usage metadata (number of entries, edit times, devices) | Best effort |

## Adversaries in scope

| ID | Adversary | Capabilities |
|----|-----------|-------------|
| T1 | **Device thief** | Physical access to a *locked* or powered-off device; full disk image, including swap, hibernation file, temp files, old SQLite pages. |
| T2 | **Compromised server / malicious operator** | Full read/write access to the server database and code: can read, modify, drop, reorder, replay or withhold any stored data; can serve malicious responses. |
| T3 | **Network attacker** | Passive recording (incl. *harvest now, decrypt later* with a future quantum computer) and active MITM. |
| T4 | **Online guesser** | Talks to the server API, tries passwords, enumerates accounts. |
| T5 | **Malicious sync peer / tampered file** | Supplies a crafted vault file or records via file-sync tools. |
| T6 | **Timing/side-channel observer** | Measures response times of the server or local operations; observes clipboard history, screenshots, recent-apps thumbnails, keyboard learning. |
| T7 | **Future cryptanalysis** | Weakening of one primitive (classical or post-quantum). |

## Out of scope

- Malware running as the user (or with higher privileges) **while the vault is
  unlocked**: keyloggers, memory readers, screen scrapers.
- Compromised operating system, firmware, or hardware.
- An attacker who knows the master password or recovery phrase.
- Physical/electromagnetic side channels (power analysis, EM emanation, cold
  boot beyond what memory hygiene in [0008](0008-memory-and-side-channels.md)
  mitigates).
- Denial of service against the server (handled operationally, not
  cryptographically).

## Security goals

- **SG1 Confidentiality:** T1–T5 learn nothing about A1/A2 beyond sizes
  (padded) and timing.
- **SG2 Integrity:** any modification of stored or transmitted data by T1, T2,
  T3 or T5 is detected; the client never accepts unauthenticated data.
- **SG3 Offline-attack resistance:** T1 and T2 can only attack the master
  password by offline guessing at full Argon2id cost per guess. T4 cannot do
  better than rate-limited online guessing.
- **SG4 Rollback awareness:** a client detects a server or file serving an
  older state than the client has already seen (see [0005](0005-synchronization.md)).
- **SG5 Crypto agility:** any single primitive can be replaced without
  redesign ([0002](0002-cryptography.md)).
- **SG6 Hybrid PQ:** breaking *either* the classical or the post-quantum half
  of an asymmetric construction alone does not compromise A1–A4.
- **SG7 No silent data loss:** sync conflicts and deletions are recoverable
  from history ([0007](0007-history-and-backups.md)).
- **SG8 Intentional unrecoverability:** without the master password or the
  recovery phrase, nobody (including the QuickVault project and server
  operators) can recover the data.
- **SG9 Nothing to brute-force on the server:** the server never stores a
  value that allows offline guessing of the master password
  ([0006](0006-server-authentication.md) §Key custody).

## Accepted leakage

The server learns: account identifiers, number of vaults, number of records
per vault and their padded sizes, timing of syncs and edits, device count, IP
addresses. Reducing this further is a non-goal for v1.

## Changelog

- 2026-10-14: Initial version, agreed in design discussion.
- 2026-10-14: Added SG9.
