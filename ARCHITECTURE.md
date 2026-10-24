# QuickVault Architecture

QuickVault is an offline-first, end-to-end encrypted password manager with
optional synchronization. The normative specifications are in
[specs/](specs/README.md). This repository currently specifies the design;
it does not yet contain production clients or a server.
Contributor and agent workflow (plans, reviews, documentation duties) is in
[AGENTS.md](AGENTS.md); repository-level changes are in [CHANGELOG.md](CHANGELOG.md).

## 1. Goals and scope

Store generic secrets in nested groups, work fully offline, and provide
recoverable edits and explicit conflicts. A complete local vault requires no
account, server, Internet connection or network enrollment. Synchronization is
optional, with two independent modes:

- **LAN sync:** direct peer-to-peer synchronization between devices on the same
  network, without an account, remote server or Internet access.
- **Remote sync:** synchronization through an untrusted server using an account;
  any enrolled device authorized for a vault may initiate synchronization.

A vault may use neither mode, either mode, or both. Local reads and edits never
wait for a network operation; account/session expiry and server outages do not
disable local vault access or LAN sync. Server-mediated devices need not be
online at the same time; LAN peers must be available together.

Initial LAN and remote synchronization is manual: the user explicitly starts
an exchange. Unlocking, editing, login, timers and connectivity changes do not
trigger synchronization. Pending changes wait for the next explicit sync;
bounded retries may occur within an active operation. Automatic sync and
background retry scheduling are deferred (0005 §0.5).

Linux CLI comes first, followed by desktop and mobile clients. Security includes
metadata confidentiality, hostile-input handling and practical OS integration.

v1 excludes cross-user sharing, a browser extension, auto-type, key files,
hardware-token authentication and hosted open registration. These are separate
future designs, not requirements to prebuild into every subsystem.

## 2. Design decisions

1. **Untrusted storage.** Server data is ciphertext plus the random references,
   liveness, sizes, generations and timing needed to store it; object routing
   data cannot link objects to records or histories. Clients verify
   authenticated manifests; TLS and server authorization are not vault integrity.
2. **Private active DB, immutable archives.** A vault is SQLite with encrypted
   objects. Snapshots, backups and Dropbox/Syncthing exchange use one simple
   archive format, authenticated before parsing; attacker-supplied files never
   reach the SQLite parser. Never synchronize or replace the actively opened DB.
   Exchange archives carry no password slot and open only with VK (another
   device or the recovery phrase); rollback detection also requires a
   separately remembered anchor.
3. **Independent immutable crypto profiles.** KDF, data, wrapping, signatures
   and account authentication evolve separately. Changing KDF cost does not
   require migrating unrelated protocols. Data migration creates a new key
   generation with an explicit resumable transition.
4. **Causal whole-record conflicts.** Merge maximal version-vector heads without
   creating synthetic edits. Preserve concurrent credentials intact and require
   explicit resolution. Dates are display data, not replay protection.
5. **Exact references and honest guarantees.** Manifests cover active versions,
   retained history, chunks and permanent tombstones. A remote state must
   causally contain the remembered one ("the remote never forgets"), and a
   one-step local anchor detects known local regressions. Isolated server forks
   or freezes need independent checkpoint comparison; automatic global freshness
   is not promised.
6. **Minimize plaintext.** qv-core owns session/authorization policy; the trusted
   client includes the Rust subsystems, platform adapters and privileged frontend.
   Protected values stay encrypted when idle, native secure controls collect
   secret input, and clipboard/autofill bypass the webview. Handles reduce copies
   but do not isolate secrets from a compromised authorized UI.
7. **Reviewed building blocks and compositions.** Use reviewed implementations,
   recorded versions/audits and vectors. The pairing/session/migration protocols
   still require independent review. Memory safety and encryption do not replace
   hostile SQLite/CBOR/rendering-input defenses.

## 3. Components and trust boundaries

These are logical subsystems; split physical crates as interfaces stabilize
rather than creating unused workspace scaffolding.

| Component | Responsibility |
|-----------|----------------|
| qv-crypto | Profiles, key hierarchy, encryption, signature verification, protected memory |
| qv-model | Canonical payloads, atomic records, deterministic tree projection |
| qv-store | Hardened SQLite, immutable objects, manifests, transactions, archives |
| qv-protocol | Bounded canonical LAN/server wire types, contexts and version registry |
| qv-sync | Shared causal merge, direct LAN exchange, remote candidate state and publication orchestration |
| qv-core | Session policy, handles, lock cancellation, mutation authorization |
| qv-platform | Native secure input, keystore, clipboard, verified OS autofill |
| qv-cli / qv-app | Explicit user actions and views; no unrestricted crypto/file/SQL bridge |
| qv-server (optional) | Remote-sync accounts, grants, sessions, opaque objects, atomic checkpoint publication |

Frontends call qv-core. Core injects platform traits and orchestrates model,
store, crypto and sync. Crypto/model have no dependency on frontends. Server
uses protocol types and public-key verification libraries; its inability to
decrypt rests on key custody, not a missing Cargo dependency.

```mermaid
flowchart TB
    ui["CLI / local UI + native secure input"] --> core["qv-core: policy and sessions"]
    core --> rust["trusted Rust: model, crypto, store, sync"]
    core --> platform["platform: keystore, clipboard, autofill"]
    rust --> db[("private active SQLite vault")]
    db -->|"build from verified objects"| snapshot["immutable authenticated archives"]
    snapshot <-->|"backup / archive exchange"| files["user-selected file storage"]
    rust <-->|"optional direct authenticated LAN sync"| peer["another QuickVault device"]
    rust <-->|"optional account sync over hybrid TLS"| server["untrusted remote server"]
    anchor[("private external anchor")] <--> core
```

No plaintext or device-bound credentials go into archives. Only an explicitly
self-contained backup carries a password slot, so whoever holds that file can
attempt offline guessing. The native/OS memory conditions of 0008 qualify
locked-device protection.

LAN connectivity and discovery do not establish peer trust. Peers must be
explicitly authorized for the vault; network input remains hostile. LAN sync
does not use server accounts, sessions or grants. Exact discovery, enrollment
and session protocols remain open in 0005 §6 and must be specified and reviewed
before implementation. Snapshot exchange is a backup/interoperability utility,
not a third live network sync mode.

## 4. Key hierarchy and lifecycle

Each vault has a random 256-bit VK, encoded directly as a 24-word recovery
phrase. Argon2id derives a password KEK that wraps VK. Independently derived
purpose keys protect records, attachments, manifests, headers, checkpoints and
local state. Platform quick-unlock envelopes use supported OS algorithms rather
than requiring XChaCha hardware support.

Changing the master password replaces a complete keyslot but does not revoke
a copied old slot or rotate VK. Compromise recovery creates a new VK/generation,
reencrypts retained data, changes recovery verification keys, invalidates old
grants and peer approvals, and requires fresh out-of-band approval of remaining
devices. It cannot
erase secrets already copied. See [0002](specs/0002-cryptography.md).

## 5. Main flows

**Unlock:** harden/validate SQLite and enforce resource/profile limits; unwrap
VK; verify header, complete manifest and external anchor; expose bounded
metadata views and session handles. Protected values are decrypted on demand.

**Edit:** create an immutable causal version; persist objects, manifest, history
suppression, outbox and the next authenticated local head in one transaction.
Advance the external anchor durably before reporting success; a crash between
the two is recovered because the head names the anchor's digest.

**LAN sync:** connect directly to an approved same-network peer while both
vaults are unlocked. Exchange bounded authenticated manifests and immutable
objects, merge complete causal versions, and commit through the normal local
transaction/anchor path. Each device retains its local edits and deletion
knowledge; interrupted exchange is safe to retry. No server checkpoint is
advanced by a LAN exchange.

**Remote sync:** stage and verify the remote state against the remembered remote
base (no lower sequence; every remembered head, tombstone and floor still
covered), excluding unpublished local edits. v1 has one server per vault. Merge
into a candidate, preserve
complete concurrent heads, and publish through atomic idempotent compare-and-swap.
Current reference lists pin data during server garbage collection. Any authorized
enrolled device may start a round; LAN-received edits can subsequently be
published through the same remote protocol.

**File exchange:** publish unique immutable archives; authenticate private
copies of incoming archives and merge same-generation versions. Tombstones never
expire and old files cannot reintroduce suppressed history.

**Server device pairing (0006):** scan a QR with a pairing secret and
approving-key fingerprint.
Both screens show a comparison code; one request per ticket. Use a fresh
ephemeral X-Wing recipient key, encrypt the complete vault-key payload,
authenticate the full transcript, and convey trusted checkpoints. Grant only
explicitly approved vault generations.

**Server revocation:** invalidate existing sessions, grants and pending transfers
atomically; check revocation on every operation and before publication. Rotate
VK if the departed device may hold it. Server revocation does not revoke a
device's LAN access or erase its keys; LAN peer removal requires a separate
policy (0005 Open Questions).

**Server-only recovery:** requires the separate account login plus a matching
vault recovery phrase. Without a trusted checkpoint, freshness starts unverified.
A vault master password alone cannot bootstrap a new device from the server.

## 6. Technology choices

| Concern | Choice |
|---------|--------|
| Language | Stable Rust |
| UI | Dioxus for main UI, native secure-input/OS adapters |
| Optional remote server | Axum/Tokio; SQLite first, Postgres deferred |
| Local storage | rusqlite, encrypted immutable objects and manifests |
| Serialization | Bounded RFC 8949 deterministic CBOR |
| Data encryption | XChaCha20-Poly1305 |
| Password KDF / derivation | Argon2id / HKDF-SHA-512 |
| Server enrollment | Pinned X-Wing draft-11 plus authenticated encryption/transcript |
| Application signatures | Ed25519 + ML-DSA-65, both required |
| Remote transport | TLS 1.3, X25519MLKEM768, pinned application server identity |
| Remote account authentication | Pinned RFC 9807 OPAQUE application profile |
| Direct LAN discovery / enrollment / transport | Not yet selected; requirements and open decisions in 0005 §6 |
| CLI / license | clap / AGPL-3.0-or-later |

OPAQUE and ordinary TLS certificates are explicit classical exceptions.
TLS-bound opaque sessions replace custom per-request HMAC/counter signing.
KDF benchmarks and protocol review are release requirements, not completed work.

## 7. Delivery and validation

| Phase | Deliverable |
|-------|-------------|
| 1 | Offline Linux CLI: encrypted vault, manifests, anchors, bounded history/recovery |
| 2 | Linux desktop, hardened webview/native input, manually initiated direct LAN sync, conflicts and immutable archive exchange; LAN protocol decisions/review required first |
| 3 | Optional closed self-hosted remote server, manually initiated remote sync, accounts, device grants/sessions, server pairing/recovery and remote generation transitions |
| 4 | Android, verified quick unlock and autofill |
| 5 | Windows |
| Later | Automatic sync (separate design), third-party import/export, hosted admission, iOS/macOS, extensions and BSD |

Future implementations must satisfy the acceptance criteria in
[0012 — Security Validation](specs/0012-security-validation.md).
These are specification requirements; no implementation or security validation
has been completed by documenting them.

Remaining implementation work includes KDF/mobile-budget benchmarks, reviewed
platform-wrap backends, native-input lifecycle validation, and independent
protocol review. A witness service is optional future work; v1's documented
fork/freeze limits do not depend on pretending it exists.

Offline release is independent of both network modes. LAN sync must be usable
without deploying phase 3; each sync mode has its own release evidence in 0012.

Open design decisions recorded for the owner (not yet decided):
whether per-device signing identities are worth their complexity
([0006](specs/0006-server-authentication.md) OQ2), webview versus native Rust UI
([0008](specs/0008-memory-and-side-channels.md) OQ2), and password slots in local
snapshots ([0007](specs/0007-history-and-backups.md) OQ1), plus LAN discovery/addressing,
authenticated peer enrollment/session design, local peer-state persistence,
LAN listening lifecycle and peer removal ([0005](specs/0005-synchronization.md)
OQ3–OQ6). No LAN wire protocol has been selected by this direction change.
