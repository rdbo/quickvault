# Plan 0001 — Offline-first sync direction

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-24 | 2026-10-24 (requested spec amendment) | 0001, 0002 §3.5, 0004 §2, 0005, 0006, 0007 §3–4, 0009, 0011 §4, 0012 |

## Intent

Make QuickVault a complete offline password manager with two optional sync
modes: direct peer-to-peer LAN sync and account-based remote server sync.
Remove server prerequisites from local use and LAN sync.

## Scope

**In scope:** amend specifications, architecture, roadmap and validation
requirements; record unresolved LAN protocol choices explicitly.

**Out of scope:** production code, tests, dependencies, byte-level protocol
design, replacing existing crypto profiles, or deciding existing open questions.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Confidentiality, hostile peers, leakage | 0001 | Accepted | Extend explicit LAN coverage |
| Key lifecycle | 0002 §3.5 | Accepted | Account/server steps apply only to server-connected vaults |
| Private local persistence | 0004 §2 | Accepted | Server state is optional; no new DDL |
| Causal merge and server publication | 0005 | Draft | Preserve rules; add LAN requirements and independent modes |
| Accounts and device enrollment | 0006 | Draft | Scope existing protocol to remote sync |
| Snapshots and retention | 0007 §3–4 | Accepted | Both modes use normal merge coalescing; scope server acknowledgements |
| Client delivery and commands | 0009, 0011 §4 | Draft / Accepted | Surface LAN before server delivery |
| Acceptance criteria | 0012 | Accepted | Offline, LAN, remote and mixed-mode scenarios; separate gates |

**Spec changes required:** all rows above, with per-spec Changelogs and index
summary. Keep existing statuses; adding requirements to a Draft does not accept
its unresolved protocol.

## Decisions needed

None block this specification amendment. The owner explicitly requested these
direction changes on 2026-10-24; this records authorization for that document
work, not approval to implement Draft protocols.

LAN discovery/addressing, authenticated pairing/session protocol, persistent
peer metadata, listening lifecycle and peer-removal semantics remain Open
Questions in 0005. Manual initiation for initial delivery was settled by the
owner follow-up recorded under Revisions. Account-login-only key access, if
requested, needs a separate design;
preserve current approved-key-transfer/recovery constraints meanwhile.

## Design

**Components touched:** qv-core and qv-sync orchestrate optional transports;
qv-protocol describes future bounded LAN messages; qv-server is remote-only.
Keep the existing client/server trust boundary and add untrusted LAN input.

**Interfaces:** documentation requirements only. No Rust interfaces, DDL, wire
fields or cryptographic domain labels are introduced by this amendment.

**Data and control flow:** local edits commit without network access. LAN peers
authenticate and exchange verified immutable state, then use existing causal
merge and local transaction/anchor rules. Server sync retains its distinct
verified base, CAS publication and receipts. LAN receipt never acknowledges a
server publication or changes its verified base.

**Secrets and hostile input:** no account or server credential for LAN; explicit
peer approval, protected key transfer, bounded authenticated inputs and no live
SQLite transfer. Leave exact LAN protocol pending owner choice and review.

**Errors:** preserve local data/outbox on network failure, lock, malformed input
and mismatched generations. No new CLI exit codes or error wire encodings.

**Dependencies:** None.

## Steps

### Step 1 — Define independent modes and LAN requirements

- [x] **Do:** Amend goals, components, diagram, flows and roadmap; add 0005
  operating model and LAN requirements without changing causal merge or server CAS.
- **Files:** `ARCHITECTURE.md`, `specs/0005-synchronization.md`.
- **Done when:** offline, LAN-only, server-only and combined use are explicit;
  LAN needs neither an account nor server, and unresolved protocols stay open.
- **Verify:** `git diff -- ARCHITECTURE.md specs/0005-synchronization.md`.

### Step 2 — Remove implicit server prerequisites

- [x] **Do:** Scope account enrollment, rotation server steps, persistence and
  retention to the remote mode; cover hostile LAN peers and metadata leakage.
- **Files:** `specs/0001-threat-model.md`, `specs/0002-cryptography.md`,
  `specs/0004-local-storage.md`, `specs/0006-server-authentication.md`,
  `specs/0007-history-and-backups.md`.
- **Done when:** local/LAN use does not depend on account state, server
  revocation, sequence numbers or server acknowledgements.
- **Verify:** `git diff -- specs/0001-threat-model.md specs/0002-cryptography.md specs/0004-local-storage.md specs/0006-server-authentication.md specs/0007-history-and-backups.md`.

### Step 3 — Align clients, gates and documentation

- [x] **Do:** Add LAN client/CLI scope, separate release gates and mixed-mode
  validation; update spec index and repository changelog.
- **Files:** `specs/0009-clients-and-platforms.md`, `specs/0011-cli.md`,
  `specs/0012-security-validation.md`, `specs/README.md`, `CHANGELOG.md`,
  `plans/README.md`.
- **Done when:** LAN delivery precedes remote service in roadmap/CLI; offline
  release does not depend on either sync backend; statuses remain accurate.
- **Verify:** `git diff --check`; targeted review of changed tables and gates.

### Step 4 — Review amendment consistency

- [x] **Do:** Check the complete diff against intent, existing guarantees and
  unresolved questions; record review and execution results.
- **Files:** this plan, `REVIEW.md`, `plans/README.md`; minor doc fixes as needed.
- **Done when:** no implicit account dependency for LAN, no invented protocol,
  and documentation links/headings/whitespace checks pass.
- **Verify:** `git diff --check`; local Markdown link/heading checks; focused
  searches of touched sections for conflicting server-only wording.

### Step 5 — Start with manual synchronization

- [x] **Do:** Apply the owner's follow-up direction: explicit user initiation
  for both network modes; defer automatic triggers and background retries.
  Record the scheduling decision while leaving LAN listening design open.
- **Files:** `ARCHITECTURE.md`, `specs/0005-synchronization.md`,
  `specs/0009-clients-and-platforms.md`, `specs/0011-cli.md`,
  `specs/0012-security-validation.md`, `specs/README.md`, `CHANGELOG.md`,
  this plan, `REVIEW.md`, `plans/README.md`.
- **Done when:** unlock, edits, login, timers and connectivity changes do not
  start sync; pending work waits for an explicit sync operation; bounded retries
  within that operation remain possible. No discovery or wire design is chosen.
- **Verify:** `git diff --check`; local Markdown checks; targeted search for
  obsolete automatic triggers and review of scheduling acceptance criteria.

## Test plan

- Unit and property tests: not applicable; no implementation exists.
- Rejection, malformed-input and crash-path tests: add future acceptance criteria
  for LAN cancellation, interrupted transfer, invalid peers and mixed-mode state.
- Vectors: require LAN protocol vectors before LAN release; do not create them
  before a protocol is selected.
- 0012 §1 matrix rows addressed: offline independence, LAN peer trust, both-mode
  convergence, lifecycle separation; preserve existing sync/security rows.
- Cargo gates: not applicable; verify no tracked Cargo workspace exists.

## Risks and stop conditions

- Do not choose discovery, pairing crypto, peer authorization storage or
  revocation mechanics; record owner decisions needed before implementation.
- Do not claim server device revocation revokes LAN access or copied VK.
- Do not treat old but authenticated LAN snapshots as authoritative replacements.
- If account login alone must convey VK, stop that redesign and obtain a
  separately scoped key-custody decision.

## Documentation

- [x] `CHANGELOG.md` — Unreleased specification-direction entry.
- [x] `ARCHITECTURE.md` — goals, boundaries, flows, technology scope and phases.
- [x] Specs — amended text, per-spec Changelogs and index; no status promotions.
- [x] `AGENTS.md` — no workflow/layout change; add LAN section to topic map.
- [x] Plan execution log, review and `plans/README.md` index.

## Revisions

- 2026-10-24: Owner follow-up: "I'm thinking about manual sync first also."
  Apply this refinement to both LAN and remote modes. Add step 5 without
  rewriting completed steps; automatic synchronization is deferred. The
  scheduling choice recorded as open in the original amendment is now settled
  for initial delivery; LAN discovery/listening mechanics remain open.

## Execution log

- 2026-10-24: Recorded the user's explicit request to update specs as
  authorization for this document-only amendment. Working tree initially clean.
  Read architecture/index and relevant spec sections. No code or protocol
  implementation is authorized by this plan.
- 2026-10-24: Step 1 complete. Defined independent offline/LAN/remote/combined
  configurations, added direct LAN requirements and OQ3–OQ6, and moved LAN into
  phase 2 ahead of the optional server. Preserved causal merge and server CAS.
- 2026-10-24: Step 2 complete. Scoped server enrollment/state/retention and the
  rotation publication step to remote sync; added LAN threat/leakage and peer
  approval requirements. Rotation journals require a publication operation ID
  only for a server transition. No peer-state schema or wire design was chosen.
- 2026-10-24: Step 3 complete. Added LAN CLI family scope, client independence,
  distinct status reporting and feature-specific acceptance/release gates.
  Updated all amended spec Changelogs, the spec index, repository Changelog and
  AGENTS topic map. Existing Accepted/Draft statuses are unchanged.
- 2026-10-24: Step 4 complete. Reviewed the document diff against intent and
  existing merge/key/anchor guarantees; recorded REVIEW.md. `git diff --check`
  passed. Local Markdown targets, code fences, spec status preservation,
  amendment Changelogs and sync section/Open Question numbering checks passed.
  No tracked Cargo workspace exists, so Cargo gates were not run. No tests,
  dependency changes, commits or network protocol implementation were added.
- 2026-10-24: No response to the optional account-key-access clarification during
  this amendment; preserved the existing approved-device/recovery key-custody
  rule as stated in the question. This does not decide a login-only redesign.
  Remaining LAN protocol choices are documented requirements for future design,
  not unfinished steps of this direction amendment. Review status applies only
  to this specification edit, not protocol acceptance or a security audit.
- 2026-10-24: Step 5 complete following the owner's manual-sync direction.
  Both modes now require explicit initiation; removed remote unlock/edit/timer
  triggers and deferred automatic scheduling/background retries. Bounded retries
  within an active operation remain allowed; pending work otherwise waits for
  the next explicit sync. Updated architecture, clients, CLI, validation matrix,
  release gates, spec index and Changelogs. OQ5 now concerns receiving/listening
  mechanics; discovery and protocol choices remain open. Reviewed these changes
  for consistency; document links/fences/whitespace and targeted trigger checks
  passed, as did `git diff --check`. No Cargo workspace exists; no code/tests
  were added and no Draft status was promoted.
