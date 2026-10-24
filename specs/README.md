# QuickVault Specifications

QuickVault is developed spec-first. Specs are **normative**: code implements
what they say, and behaviour changes start with a spec change.

## Index

| # | Title | Status |
|---|-------|--------|
| [0001](0001-threat-model.md) | Threat Model | Accepted |
| [0002](0002-cryptography.md) | Cryptography and Key Hierarchy | Accepted |
| [0003](0003-data-model.md) | Data Model | Accepted |
| [0004](0004-local-storage.md) | Local Storage (Vault File) | Accepted |
| [0005](0005-synchronization.md) | Synchronization and Conflict Resolution (LAN and Remote) | Draft |
| [0006](0006-server-authentication.md) | Server Accounts, Authentication and Device Enrollment | Draft |
| [0007](0007-history-and-backups.md) | History and Backups | Accepted |
| [0008](0008-memory-and-side-channels.md) | Memory Hygiene and Side Channels | Draft |
| [0009](0009-clients-and-platforms.md) | Clients and Platforms | Draft |
| [0010](0010-password-generator.md) | Password Generator | Accepted |
| [0011](0011-cli.md) | Command-Line Interface | Accepted |
| [0012](0012-security-validation.md) | Security Validation and Release Gates | Accepted |

The 2026-10-24 direction amendment makes local vault use independent of accounts
and network access, with two optional sync modes: direct account-free LAN sync
and account-based remote server sync. Either mode, both or neither may be used
on a vault. 0005 defines their shared causal merge and separate lifecycle state;
0006 applies only to the remote mode. Archive exchange remains a backup/import/
export utility. Initial LAN and remote sync is manually initiated; automatic
sync and background retries are deferred. LAN discovery, enrollment, sessions,
peer-state persistence, listening lifecycle and peer removal remain explicit
Open Questions; this amendment does not select a wire protocol or promote any
Draft spec to Accepted.

The 2026-10-15 amendments replace HLC/field merging, active-file sync and
unconditional freshness claims. The follow-up security review replaces SQLite
exports with authenticated archives, removes server-visible record linkage,
simplifies anchors and remote acceptance, and hardens pairing and password
slots. Accepted designs still require their applicable
validation gates before release; specification acceptance is not an audit.

This repository is specification-only. Validation scenarios describe acceptance
criteria for future development, not completed implementation tests.

## Process

- **File naming:** `NNNN-short-title.md`, numbers never reused.
- **Status lifecycle:**
  - `Exploratory`: options are being compared; nothing is decided.
  - `Draft`: a concrete proposal; may still change.
  - `Accepted`: agreed; implementation may start. Changes need an amendment
    noted in the spec's *Changelog*.
  - `Implemented`: matches the code.
  - `Superseded by NNNN`: replaced.
- **Normative language:** the key words MUST, MUST NOT, SHOULD, SHOULD NOT and
  MAY are used as described in RFC 2119 / RFC 8174.
- **Every spec has:** a metadata header, Summary, Specification, Security
  Considerations, Open Questions and Changelog.
- **Implementation** of accepted specs is planned and reviewed in
  [plans/](../plans/README.md); see [AGENTS.md](../AGENTS.md).

## Template

```markdown
# NNNN — Title

| Status | Created | Depends on |
|--------|---------|------------|
| Draft  | YYYY-MM-DD | 000X |

## Summary
## Motivation
## Specification
## Security Considerations
## Open Questions
## Changelog
```
