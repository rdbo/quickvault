# 0005 — Synchronization and Conflict Resolution

| Status | Created | Depends on |
|--------|---------|------------|
| Draft | 2026-10-14 | 0002, 0003, 0004 |

## Summary

Sync exchanges authenticated snapshots of immutable versions. A record is an
atomic unit: concurrent versions remain explicit conflicts until resolved by
the user. Direct LAN sync and optional account-based remote sync use the same
causal merge, also used by archive import/export utilities.
Wall-clock time never proves that an edit has already been seen.

## Specification

### 0. Offline-first operating model

0.1. A local vault MUST support creation, unlock, reads, edits, history and
recovery without an account, server or network access. Local mutations commit
durably before any optional synchronization; they MUST NOT depend on remote
acknowledgement. Sync failure, account expiry or server unavailability MUST NOT
prevent local use of an otherwise valid vault.

0.2. The two network sync modes are:

| Mode | Connection | Requirements |
|------|------------|--------------|
| LAN (§6) | Direct device-to-device on the same network | Explicitly approved peers with access to the same vault/generation; no account, remote server or Internet access |
| Remote (§3, 0006) | Devices exchange encrypted state through a server | Account, enrolled device and grant for the vault/generation |

A vault MAY use neither, either or both modes. Enabling remote sync MUST NOT
be a prerequisite for LAN sync. Every enrolled device with the required grant
MUST be able to initiate remote sync; there is no designated primary device.
Account login alone does not distribute vault keys (0006).

0.3. Both modes preserve the same logical version IDs, clocks, conflicts,
tombstones and history suppression. Receiving a version over one mode and
later another MUST deduplicate it without creating an edit. LAN receipt MUST
NOT advance a server sequence, replace a verified server base or acknowledge
pending server publication. LAN-received changes remain eligible for normal
server publication, and server-received changes for later LAN exchange.

0.4. Archive exchange (§4) remains a backup/import/export interoperability
utility. It is not a third live network sync mode; safe archive handling does
not require building a server or selecting a LAN wire protocol.

0.5. **Manual sync first.** In the initial release of each network mode, a
sync operation MUST start through an explicit user action selecting that mode
(CLI command or client action). Unlocking, editing, account login, discovering
a peer, timer expiry or restored connectivity MUST NOT automatically start a
sync round. Automatic synchronization is deferred to a future amendment.
Bounded retries within the same user-initiated operation are allowed while
unlocked; after completion, failure, cancellation or process exit, pending
changes wait for the next explicit sync operation. Do not schedule background
retries. This does not select LAN discovery or receiver-listening mechanics
(Open Questions 3–5).

### 1. Versions and causality

1.1. A version has a random 128-bit `version_id`, an encrypted payload, and a
version vector `clock: writer_id -> u64`. On the wire encode this logical mapping
as a sorted array of unique [writer_id, positive_counter] pairs, not a CBOR map
with byte-string keys; zero components are omitted. Missing components mean zero.
A writer ID identifies one local replica of a vault, separately from the
account device signing identity. IDs MUST NOT encode wall-clock time.

1.2. An edit joins the clocks of **all locally known heads of that record**
componentwise, then advances the local writer component. With unresolved
conflicts, an edit requires explicit resolution of all heads. Automated
operations MUST preserve conflicts. Receiving data alone MUST NOT create
a synthetic version, new timestamp or new encryption of an existing version.

1.3. Writer IDs and monotonic counter reservations live in private application
state outside archives. Reserve counters durably before use. Import/restore on
another installation creates a new writer ID. If writer state is missing or
rolled back, generate a new ID; never reuse counters. Retired writer components
MUST NOT be removed from live clocks. Counter exhaustion requires a new ID.

1.4. `a < b` means every component of clock `a` is at most the corresponding
component of `b`, and at least one is smaller. Versions are concurrent when
neither dominates the other. Equal clocks with different version IDs or content,
or a version ID reused for different logical content, are integrity errors.

1.5. Dates are display information only; there is no hybrid logical clock.
Future dates warrant a warning, not rejection of a valid concurrent edit.
Neither conflict handling nor causality depends on the receiving device's
wall clock.

### 2. Merge algorithm

2.1. For each record, union the active versions, deduplicate by version ID,
validate identities/clocks, and remove a version from the active set only if
another clock strictly dominates it. Dominated versions become history under
0007. Previously unseen concurrent versions MUST survive regardless of date.

2.2. This maximal-version set is the current state. Union followed by removal
of dominated versions is commutative, associative and idempotent. These
properties concern logical versions; receipt never rewrites their encryption.
If a resource limit is exceeded, abort without changing accepted state; never
discard heads or causal components to fit a budget.

2.3. Multiple heads are an **unresolved conflict**, not prunable history. Show
the conflict and each complete version. No automatic per-field merge is
performed in v1: username, password, URL, TOTP and unknown fields stay together
as written. The deterministic browsing representative is the lexicographically
largest version ID, subject to deletion visibility (§2.5). Copy/autofill requires
choosing a version while a credential is conflicted.

2.4. Resolution is a deliberate new edit covering all known heads (§1.2). A
later unseen version remains concurrent unless the resolution dominates it.
Choosing a version does not prove that unseen edits were considered.

2.5. Soft deletion and final deletion are causal versions. Final tombstones
retain record ID, version ID and clock indefinitely after payload/history
purging. Covered old versions cannot resurrect an entry. Concurrent deletion
and edit remain a conflict in trash; restoration explicitly resolves both.
Tombstones and causal metadata MUST NOT expire by age.

2.6. Groups, vault metadata and the encrypted password keyslot record follow
the same rules. Never automatically adopt or field-merge a conflicted keyslot;
keep the working local slot until explicit resolution. Group repair is a
deterministic display projection (0003), not a synthetic edit. History
suppression frontiers are joined monotonically under 0007.

### 3. Server sync

3.1. This section applies only when remote sync is configured. v1 supports at
most **one server remote per vault**; this limit does not restrict LAN peers.
LAN sync (§6) and file exchange (§4) have no server remote chain. `remote_id`
stays in checkpoints so later versions can add remotes without a format change.
Maintain separate states:

| State | Meaning |
|-------|---------|
| Verified remote base | Last authenticated remote manifest and checkpoint |
| Local working state | Verified local manifest including unpublished edits |
| Candidate | Verified remote state merged with local working state |

Local edits never advance a remote sequence or replace its remembered
checkpoint. A transport cursor is only an optimization.

3.2. A sync round MUST:

1. Fetch a checkpoint, manifest and required immutable objects into bounded
   staging. Resume by object hash without changing accepted data.
2. Verify the checkpoint MAC and the acceptance rule of §5.3 against the
   remembered remote base, then authenticate the remote manifest and all
   references **before merging**. Hash the remote state alone; exclude
   unpublished local edits.
3. Causally merge the verified remote and local states. Persist the candidate,
   outbox and verified-remote metadata transactionally.
4. Prepare publication against the exact verified remote checkpoint ID. Upload
   missing objects, then atomically publish a new manifest/checkpoint using
   compare-and-swap on that predecessor.
5. On `409`, verify the new remote state and repeat. After an ambiguous timeout,
   query by operation ID before retrying. Advance remote checkpoint/cursor only
   after verifying that the publication receipt names the proposed checkpoint.

3.3. Publication uses a random 128-bit `operation_id`. Retain its result for
the life of the checkpoint. Same ID/body returns the same result; same ID with
different body fails. Checkpoint, manifest, reference set, quotas and operation
result become visible in one server transaction. Objects are namespaced by
(vault ID, key generation) and immutable: uploading an existing object ID with
different bytes fails, and clients still verify every hash themselves.
Staging is never visible as vault state; unreferenced staging expires after
24 hours and counts toward quota.

3.4. The server stores opaque objects plus explicit reference lists, not a
last-upload-wins record table. The encrypted manifest authenticates the public
reference list's digest (§5). Compaction MUST retain every current reference,
the current checkpoint and operation results; it need not retain old
checkpoints. Expired cursors return `resync_required` plus the full current
manifest; acceptance is still judged against the remembered base (§5.3).
Upload order cannot determine active versions.

3.5. For a vault with remote sync enabled, server sync runs only while unlocked
and as part of an explicitly user-initiated operation (§0.5). Lock cancels work
and invalidates handles used by staged responses. The durable outbox survives
crashes and remains pending until an accepted remote state covers it. Remote
failures leave local changes
usable and pending; another enrolled device need not be online during this
round. Server revocation is specified in 0006; it does not authorize or revoke
LAN sessions.

### 4. File-based exchange

4.1. The active SQLite database MUST NOT be an automatic file-sync target.
DELETE journaling does not make active-file copying safe. Unexpected external
replacement stops writes, closes the connection and preserves recovery data.
Local locks cannot coordinate arbitrary file-sync tools.

4.2. Exchange files are archives (0004 §6) written from verified local
objects under a **new unique filename** with no replacement of an existing path.
Published archives are immutable and never edited in place. Do not sync
journals or live handles. Exchange archives contain **no password slot**:
every participating device already holds VK, so the file-sync provider gets no
offline master-password guessing target. Only an explicitly self-contained
backup carries a slot, with the warning of 0004 §6.4.

4.3. Incoming archives are hostile read-only inputs. Make a private stable
copy, require the same vault ID and key generation, authenticate it as in
0004 §6.3 (header MAC and manifest before any object is decoded), then merge
using §2. No SQLite file from an exchange location is ever opened. Bound
reads of incomplete files and retry later. A reused filename with different
bytes is an error. Do not automatically
delete archives or interpret file absence as a record deletion.

4.4. Same-generation old backups may be merged without reviving covered
tombstones or suppressed history. Whole-state restore writes a new file and
explicitly establishes a new local baseline; it MUST NOT erase an existing
remote checkpoint. Cross-generation import requires 0002 §3.5.

### 5. Manifests, checkpoints and detection limits

5.1. Every committed local or published remote state has an encrypted manifest
(0004) naming all active versions, retained history, attachment chunks,
tombstones and history suppression frontiers. It is separate from ordinary
records and excludes itself. Check completeness on unlock, import and sync.
Missing referenced data is an integrity/availability failure, not an empty
record. Unreferenced objects are never incorporated implicitly.

5.2. A remote checkpoint contains
`{ vault_id, key_generation, remote_id, sequence, previous_checkpoint_id,
manifest_hash, reference_digest }` plus a MAC under the state-commit key.
Use deterministic CBOR (0004), domain `qv/checkpoint/v1` and the MAC of 0002.
Its ID is SHA-256 of the canonical checkpoint including MAC. Sequence starts
at 1 and increases by exactly one per publication. File archives name
manifest hashes without server sequences.

5.3. **Acceptance rule ("the remote never forgets").** Remember the base's
checkpoint ID, sequence and, per record, its active head clocks, tombstones and
history floor. A new remote state is acceptable only if all of these hold:

1. same vault ID, key generation and remote ID, and a valid MAC;
2. its sequence is not lower than the base's; an equal sequence names the
   identical checkpoint ID; sequence base+1 names the base as
   `previous_checkpoint_id`;
3. every record in the base is present; every base head clock is less than or
   equal to some head clock of that record in the new state (a final tombstone
   counts as a head); and every history floor is componentwise at least the
   base's floor.

Otherwise stop sync and report rollback/fork evidence. Honest evolution only
merges, dominates and prunes below floors, so it always satisfies rule 3; a
replayed old state, a fork that lacks published edits, or a substituted state
does not. This check uses only the remembered base and the new manifest, so it
needs no checkpoint-chain retention or paging of intermediate links, however
long a device was offline. A no-change response names the identical
checkpoint. Referenced data is verified independently (0004 §3.6).

5.4. **Local head and anchor.** Every commit writes one authenticated local head
(0004 `local_head`): `{ vault_id, key_generation, local_seq, previous_digest,
manifest_hash, remote_checkpoint_id?, remote_sequence? }`, MAC'd under the
local-state key. `local_seq` increases by one per commit; `local_digest` is
SHA-256 of the canonical head including its MAC. The external anchor, in private
state outside the DB and archives (keystore-backed where available), stores `{
vault_id, key_generation, local_seq, local_digest }`.

After the DB commit is durable, atomically replace the anchor, then report
success. On open, verify the head MAC and compare:

| Head vs. anchor | Action |
|-----------------|--------|
| identical | normal open |
| `local_seq` = anchor + 1 and `previous_digest` = anchor digest | crash after commit: advance the anchor, then open |
| anything else (older, forked, more than one ahead, other vault) | integrity error; block writes; offer explicit recovery |

A generation change (0002 §3.5) is one such step whose head carries the new
generation and names the old-generation digest as `previous_digest`. Because
the remembered remote checkpoint is inside the authenticated head, the anchor
protects it against DB rollback too. A missing anchor never silently resets an
existing installation's baseline. An anchor stored with the same OS
permissions as the DB detects accidental restores and sync-tool rollback of a
vault at a user-chosen path; an attacker able to replace both files defeats it
(§5.6).

5.5. Server pairing transfers the approving device's verified remote base inside
the protected key transfer (0006). Users may also compare (sequence, checkpoint ID)
pairs between devices. Different IDs at the same sequence are fork evidence.
If the other device reports a higher sequence, sync: a server that still serves
the lower sequence is demonstrably freezing this device, and a higher state
that fails §5.3 is a fork.

5.6. **Limits:** a malicious server can isolate devices on internally valid
forks or freeze a device at its last accepted checkpoint. Detection requires
checkpoint exchange or an independent witness; automatic detection is not
promised. Show last successful sync separately from last independent comparison.
Neither proves global freshness. Recovery without a trusted checkpoint creates
an explicitly unverified baseline. Restoring both DB and external state can
defeat rollback detection. Detection cannot restore data deleted by a server;
independent backups remain necessary.

### 6. Direct LAN sync

6.1. Two devices on the same local network MUST be able to synchronize directly
without contacting a QuickVault server or using server accounts, grants,
registration, OPAQUE or server enrollment tickets. Both participating vaults
MUST be unlocked for the exchange. Neither device is an authoritative primary;
the initiator/receiver distinction MUST NOT affect the logical merge result.

6.2. Same-network presence, discovery advertisements, hostnames and IP addresses
MUST NOT be treated as authentication or permission to receive keys or data.
The user must explicitly approve linking the intended devices for the selected
vault/generation, through an authenticated out-of-band enrollment design.
New-device setup MUST protect VK and bind the intended peers, vault, generation
and protocol profile. Merely logging in to an account MUST NOT authorize a LAN
peer. The exact peer identity, key-transfer and session protocol is undecided;
0006's server-bound transcripts MUST NOT be reused by simply omitting their
account/server fields.

6.3. The LAN session MUST provide peer authentication, confidentiality,
integrity and replay protection under a reviewed protocol consistent with 0002;
VK and plaintext vault contents MUST NOT be sent in cleartext. For approved
peers holding the same vault and generation, the exchange MUST authenticate
a complete manifest and its referenced immutable objects
before merging (§2, §5.1 and 0004 §3.6). Enforce 0004 resource budgets before
allocation and treat even authenticated peer content as hostile. Never send,
open or replace the active SQLite file over LAN. Device-local quick slots,
private signing bundles, session tokens and external anchors are not exchange
data. Unknown required profiles/features fail closed.

6.4. A peer's snapshot is a merge input, not a replacement for local state or
a globally ordered server head. Older snapshots may contribute unseen concurrent
edits; retain locally known heads, permanent tombstones and suppression floors
under §2. The server sequence acceptance test (§5.3) is not a LAN ordering rule.
Different vaults or key generations MUST NOT merge automatically; generation
recovery follows 0002 §3.5. LAN pairing and exchange do not establish a verified
server base; server bootstrap/checkpoint trust remains governed by §5 and 0006.

6.5. Each device commits accepted merged state through the local transaction
and anchor rules (0004 §5, §5.4 above). Network loss, retries, process exit or
lock MUST NOT lose preexisting edits, accept a partial manifest or imply that
the other device committed. Lock cancels work and invalidates staged-response
handles. A complete local commit may survive failure to acknowledge the peer;
repeating the exchange must be idempotent. Report local acceptance separately
from confirmed peer receipt; no distributed atomic commit is promised.

6.6. LAN exchanges do not create server checkpoints or publish to the server.
Already trusted server checkpoints may be independently compared (§5.5), but
such comparison is evidence only and MUST NOT overwrite verified server state
or discharge its outbox. Ordinary LAN merging cannot prove global freshness,
identify every isolated fork or erase a departed peer's copy of VK. Disabling
remote sync or losing account access MUST NOT disable existing LAN use.

6.7. These are product and security requirements, not an implementable wire
specification. Resolve Open Questions 3–6, specify bounded messages, peer-state
durability and failure transitions, and satisfy 0012's LAN gates before shipping
LAN synchronization. No new crypto profile or message layout is selected here.

## Security Considerations

Possession of VK allows forging vault objects and checkpoint MACs. Device
revocation only controls an honest server; it does not revoke LAN access.
Rotate VK after compromise (0002). Local networks are untrusted; discovery is
not authorization, and approved VK holders can forge same-generation content.
Resource budgets and transactional acceptance apply even to authenticated data.

## Testing Requirements

- Permute three or more concurrent edits, duplicates and intermediate merges:
  identical heads; test late edits after explicit resolution.
- Test writer-state restoration, checked counter overflow, old dates and clock
  skew.
- Offline edits must not cause a remote-manifest mismatch.
- Delete/substitute referenced records, history or chunks: reject the candidate.
- Retry lost publication replies and crash at staging/DB/anchor boundaries:
  preserve accepted data and outbox; expose no partial remote publication.
- Isolated valid forks may pass local checks; checkpoint comparison detects
  incompatible histories. An identical frozen checkpoint is not proof of
  freshness.
- §5.3: replayed lower/equal-sequence states, forks missing a published head,
  regressed floors and removed tombstones are rejected; honest merges, history
  pruning and purges after any number of intermediate publications are accepted.
- §5.4: crash between DB commit and anchor update opens; a DB two steps ahead,
  an older DB, or a DB from another installation is an integrity error.
- Import data older than 180 days: covered deletions remain deleted.
- With Internet access blocked and no account/server configuration, create and
  edit a vault, link two LAN devices through the future approved protocol and
  synchronize concurrent edits in both initiation directions.
- Spoof discovery/peer identity and substitute vault/generation/profile: reject
  without releasing keys or changing accepted state. Lock or interrupt at each
  transfer/commit boundary; retry without losing edits or duplicating versions.
- Exercise offline-only, LAN-only, remote-only and combined configurations.
  Deliver the same edit over LAN and server in both orders; converge without
  rewriting versions, acknowledging unpublished server work or resetting the
  verified server base. Server outage/revocation must not disable local/LAN use.
- For each network mode, unlock, edit, log in, discover peers, advance timers
  and restore connectivity without requesting sync: no round starts. Explicit
  sync performs the selected exchange; after failure, cancellation, process exit
  or restart, pending changes wait for another explicit sync. Bounded retries
  within an active user-initiated operation preserve idempotency and stop on lock.

## Open Questions

1. Independent transparency/witness services are deferred; v1 does not promise
   automatic global fork or freeze detection.
2. Every publication uploads the complete encrypted manifest (tens of MiB at
   the maximum budgets). Segmenting the manifest into immutable referenced
   pages would reduce bandwidth for large vaults; deferred until benchmarks show
   typical vaults need it.
3. **LAN discovery and addressing:** manual endpoint entry, local discovery, or
   both? Recommendation: retain a manual path that works without discovery;
   treat every discovered address as untrusted. Not yet selected.
4. **LAN trust and session protocol:** choose authenticated out-of-band peer
   enrollment, hybrid key transfer/session protection, peer identity and durable
   peer-state storage. Specify new-device initialization and crash recovery;
   decide which existing profiles can be safely reused after protocol review.
   Recommendation: reuse reviewed building blocks and the causal data model,
   without depending on the account-bound protocol in 0006. Not yet selected.
5. **LAN listening lifecycle:** initial synchronization is manually initiated
   in both modes (§0.5; owner direction 2026-10-24); automatic scheduling is
   deferred. Decide how an unlocked approved peer becomes available to receive
   a user-initiated exchange, discovery visibility and platform permissions.
   Recommendation: make receiving availability explicit and bounded; do not
   introduce a background service for initial delivery. Listening mechanics
   remain undecided; manual initiation does not choose discovery/addressing.
6. **LAN peer removal and generation transitions:** choose how each replica
   stores/revokes peer approval and how remaining peers learn a removal. Server
   revocation alone cannot enforce it; a VK holder retains same-generation
   decryption/forging ability. Recommendation: distinguish local peer blocking
   from compromise recovery, requiring VK rotation and fresh independent
   approval for the latter (0002 §3.5). Not yet selected.

## Changelog

- 2026-10-24: Follow-up direction: manual initiation first for both LAN and
  remote sync. Remove unlock/edit/timer triggers, defer automatic scheduling
  and background retries, and retain LAN discovery/listening as open decisions.
- 2026-10-24: Make offline use independent of accounts/network access; define
  direct account-free LAN and optional account-based remote sync as the two
  network modes. Preserve shared causal merge and separate server publication
  state; add LAN trust/lifecycle requirements and explicitly open protocol
  decisions. Keep archive exchange as a backup/interoperability utility.
- 2026-10-14: Initial HLC/three-way-merge proposal.
- 2026-10-15: Replace HLC arbitration with causal whole-record conflicts;
  separate remote verification and local edits; define manifests, checkpoint
  chains, external anchors, atomic idempotent publication and immutable exports.
  Correct detection guarantees and retain deletion knowledge indefinitely.
- 2026-10-15: Security review amendment: replace checkpoint-chain retention and
  intermediate-link paging with the local causal acceptance rule (§5.3);
  replace the anchor transition table with a one-step authenticated local head;
  one server remote per vault in v1; drop optional HLCs; exchange via
  authenticated archives without password slots; immutable namespaced objects.
