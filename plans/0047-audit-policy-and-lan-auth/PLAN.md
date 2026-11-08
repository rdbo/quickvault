# Plan 0047 — Large-vault views, filesystem policy and authenticated LAN enrollment

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Proposed | 2026-11-08 | Scope and v4 direction authorized by owner; detailed implementation plan pending review | 0001 SG2/SG3/SG6/SG9, 0002 §1/§3/§4/§6–8, 0003 §2/§4–5, 0004 §1/§4–6, 0005 §2/§5–6, 0008 §1–2/§4–5, 0009 §1, 0011 §2–4, 0012 §1–3, 0013 §1–12, 0014 §1–8 |

## Intent

Resolve the three assessment topics discussed with the owner: support vaults
whose searchable text exceeds 64 MiB, retain ordinary move/copy behavior, and
require cryptographic credential authentication before LAN enrollment releases
the vault key. Prioritize LAN: replace the code-only grant with the owner's
selected v4 flow, with password entry on both devices and ephemeral credentials.

## Scope

**In scope:**

- T3-08: a compact structural index, bounded metadata cache, on-demand search,
  paged views and bounded frontend consumption. Preserve the existing **1 GiB
  total referenced-ciphertext** budget and all per-object/model limits.
- QV-013 disposition: authenticated copies and legitimate moves are valid;
  no persistent directory/inode binding or new ancestor-chain restrictions.
  Preserve current permissions, symlink, open-file identity and write protections.
- QV-005/006 and related QV-009/015 lifecycle work: accept one fully valid
  code-authenticated hello, consume the code, close all listeners, and run one
  independently bounded credential-authenticated session. Remove the competing
  hello detector after admission.
- Password enrollment using v4; key-based sync and phrase-based enrollment;
  final-key confirmation; atomic grant authorization; pre-transfer password-slot
  verification; full staging validation and recovery-capable local publication.
- Explicit public-slot projection so encrypted-record extensions cannot be
  exported into the clear local slot table. V4 adds no persistent auth fields.
- Core, CLI and app integration; adversarial tests, vectors, device evidence and
  accurate disclosure/commit/receipt reporting.

**Out of scope:**

- V3's persistent OPAQUE setup, new credential epochs, file/archive format
  migration, or provisioning credentials during password unlock/change.
- Increasing the ciphertext budget; a persistent plaintext/encrypted search
  index; full-text search of protected fields/notes; manifest pagination.
- Fixing every remaining assessment item. VW-02 general mutation outcomes,
  T3-09 causal capacity, delete-operation IDs, media previews and other open
  items in [0046's ledger](../0046-audit-remediation/FINDINGS.md) stay separate.
  This plan must still report LAN commits and publication truthfully.
- Remote account authentication, device links, Internet discovery or background
  sync. The remote account password and LAN vault password remain distinct.
- Committing, branching, pushing, sending a review request to someone else, or
  declaring a release secure. The owner commits; D12 remains a release gate.

## Spec basis

| Behavior | Spec / status | Required amendment before code |
|----------|---------------|--------------------------------|
| Bounded search and confidential metadata | 0003 §4–5 Accepted; 0004 §4–5 Accepted; 0008 §1 Draft with existing owner-approved implementation scope; 0011 §2/§4 Accepted | Define cache residency rather than aggregate searchable-text eligibility; paging, snapshot invalidation, cancellation, preserved matching/order, frontend bounds |
| Authenticated moved/copied vaults | 0001 SG2/SG4 Accepted; 0004 §1 Accepted; 0008 §5 Draft | Clarify runtime replacement protections versus pre-start path history; copy identity management and known rollback limits |
| One admitted LAN connection | 0013 §4/§8 and 0014 §1–2 Accepted | Replace second-hello monitoring with listener closure; distinguish admission from session lifetime |
| Credential-gated key delivery | 0001 SG3/SG6/SG9, 0002 §1/§3/§6 Accepted; 0013 §4/§6/§10 and 0014 §3 Accepted | New incompatible LAN profile, ephemeral password engine, separate method/intent, exact transcripts, key transition, grant and recovery rules |
| Password/phrase prompts and cleanup | 0002 §4/§8 Accepted; 0008 §1/§4 Draft; 0009 §1 Draft; 0011 §3 Accepted | Offering-device password approval, receiver's pre-transfer prompt, phrase-only enrollment and framework cleanup limits |
| Publishing a new vault | 0004 §5–6 Accepted; 0013 §10 Accepted | Validate before publication; adopt verified descriptor without retaining password through transfer; recovery-capable writable local session with fresh replica/anchor |
| Public slot serialization | 0002 §3.2, 0003 §2.3, 0004 §2/§6 Accepted | Define an allowlisted descriptor projection; compare projections rather than opaque whole-record bytes |
| Evidence | 0012 §1–3 Accepted | Add LAN credential-authentication cases/vectors; retain external composition review and supported-device evidence |

Stage amendments in step 1 with Changelogs and `specs/README.md`. Preserve
overall Draft statuses where only a named section is approved. Accepted-spec
amendments implement this owner-selected direction; exploratory diagrams do not
silently override the normative specs. No code may precede the applicable
amendment and its recorded authorization.

## Decisions needed

**Owner-level choices: resolved for planning.** The owner approved planning all
three topics and explicitly selected **v4: password on both devices** on
2026-11-08. Earlier choices remain: no aggregate searchable-text cap; retain
1 GiB referenced ciphertext; no directory identity policy; close admission after
one valid hello. No further choice between v3/v4 is pending.

**Implementation readiness gates, not requests for policy decisions:**

1. Step 1 must write an exact bounded LAN contract and the paging contract;
   step 2 must verify the pinned engine/adapter/dependency evidence. The reviewer
   checks these before cryptographic implementation (step 4). If a security
   property cannot be met, return to architect rather than inventing a primitive.
2. Parameters are the current **candidate** Argon2id v1.3, 256 MiB, t=3, p=4.
   Target benchmarks remain required; do not reduce cost or promise a duration
   from the diagram. D12 independent composition review gates LAN release.
3. This is an audit follow-up, not a fresh “next phase” session. The initial
   implementation approval in 0046 remains intact; this plan does not replace
   or falsely complete roadmap/release reviews. Planning is authorized now;
   this detailed plan is Proposed until its implementation handoff is approved.

## Design

### A. Components and boundaries

No new product crate. Frontends continue to call `qv-core`.

| Component | Work |
|-----------|------|
| qv-crypto | Pinned password-engine wrapper, ephemeral secret states, final key schedule, separate key-proof/schedule keys, record epochs, constant-time checks |
| qv-protocol | Key-free bounded method/intent/message types, profile/label/error registry; opaque engine bytes, never password-engine key state |
| qv-sync | One admitted connection; driver state machine; expiry/cancellation; handshake/epoch/exchange ordering |
| qv-model | Explicit public-slot projection; bounded metadata summary of authenticated heads with equivalent representative/conflict rules |
| qv-store | Descriptor-only slot installation, source-bound staged objects, credential snapshot reads, pre-publication validation and recovery-capable creation |
| qv-core | Reauthentication and grant policy; password/phrase enrollment; structural index, cache, paging, snapshot-bound capabilities and operation outcomes |
| qv-cli / qv-app | Protected prompts and bounded page consumption; incremental search/All items; cancellation, lifecycle and accurate receipts |

Update `ARCHITECTURE.md` §3/diagram for changed plaintext/trust flows and
§4–6 for the enrollment profile and cache policy. Do not reorganize unrelated
crates or rewrite the existing crypto profiles.

### B. Filesystem policy: close the decision, preserve runtime defenses

Do not add an inode fingerprint, remembered directory hash or ancestor-writable
refusal. A valid authenticated file is not rejected merely because it was
renamed, restored or copied before opening. Distinct copies can diverge; the
product does not determine which pathname the owner intended as “the original.”

Existing owner-only permissions, no-follow/nonregular rejection, tracked file
identity while open, locks, authenticated objects/manifests and external-anchor
checks remain. A valid copy that is older than an intact remembered anchor
still gets the existing rollback result. A hash stored beside a file is not a
replacement for authentication, completeness or remembered freshness.

Document QV-013 as an owner-accepted pre-start identity limitation, not as an
implemented directory-substitution detector. Tests distinguish a legitimate
move/copy before open from path redirection/replacement during an operation.

### C. LAN v4 contract

The baseline is [DESIGN-v4.md](../0046-audit-remediation/diagrams/DESIGN-v4.md),
with the following clarifications made normative in step 1. Do not reintroduce
stored authentication state from the historical v3 design.

**Profile and intent.** Allocate `lan/2` and `lan-pake/1` in their own purpose
namespaces. Keep X-Wing draft-11 for outer session establishment. Authenticate
both `auth_method = password | key` and `intent = enroll | sync` in the hello,
accept and transcript. Permit password/enroll, key/enroll (recovery phrase),
and key/sync. Reject other combinations, old profiles and unknown required
features with no legacy code-only grant fallback. V4's method alone cannot
distinguish a phrase receiver without a local file from an existing-copy sync.

**Admission.** Bound the hello; validate shape/profile/code MAC before KEM
work, then the public key. The first fully valid hello consumes the code and
causes every listening socket and advertisement to close before authentication
continues. The accepted stream remains; no second-hello reader/monitor survives.
The 16-failure budget applies only before acceptance. One remote credential
attempt per accepted code; failure needs a new explicit window/code.

**Time.** Keep the 10-minute maximum: A's active session uses the original
window's remaining absolute time; B's joining operation gets one absolute
10-minute deadline starting before its first connection attempt. Include
candidate attempts, prompts, KDF work, transfer and local pre-publication work;
retain 10-second machine-message and 60-second transfer-idle bounds, shortened
by remaining time. User-wait states use remaining operation time, not the
machine-message timeout. The deadline cancels at the next safe point during an
uninterruptible KDF and is rechecked before sending or publication. Expiry after
a durable local action reports that action accurately; it cannot undo it.
This resolves QV-015 without extending the owner's current window default.

**Password authentication.** B sends the committed-nonce reveal plus KE1.
A verifies the commitment and shows its selected vault name and comparison
code. A's user supplies the vault password and approves the comparison. Local
typos may be corrected while time remains; they never cause an engine reply
or remote retry. Reauthenticate against the working password slot, require one
matching unconflicted control-record head, and capture its exact snapshot.
Construct fresh per-session OPAQUE server setup and registration locally from
that validated password, then wipe A's password and temporary MK/KEK. No client
registration is accepted. Send KE2 only after approval. Engine context binds
the new profile, method, intent and exact outer transcript; fixed distinct
role identities and the fixed credential identifier are part of the contract.

B authenticates KE2 before producing KE3. Bind complete canonical Reveal/KE1,
KE2 and KE3 bytes and T0 into TA. Derive epoch-1 keys from fixed-length
`ss || P || Z`, salt TA, with independent directional labels. KE3 is the last
epoch-0 record; B's FinishedB is the first epoch-1 record, sent in the same
flight but as a separately framed encrypted record. A must verify KE3 before
deriving/switching and opening FinishedB. Epoch-0 records are then invalid.

A verifies FinishedB before any epoch-1 grant. Its grant is its first epoch-1
record and confirms A's composed traffic key to B. There is no FinishedA or
standalone GrantAccepted: B's later exchange-start message acknowledges all
grant checks. This is the owner-selected v4 optimization, preserving A's
explicit confirmation of B's final keys before VK leaves A.

**Grant authorization.** One short core session operation checks the captured
session tag, vault ID/generation, working slot, exact control-record head,
policy, deadline and cancellation/lock flags, constructs the descriptor-only
grant and seals it once. Those reads and sealing use the same session mutex;
never wait on user/network/KDF work under that mutex. Check cancellation again
before returning the frame and before the first send; cancellation drops output
and ends the connection, without counter rewind or grant retry. Treat completed
authorization/sealing as disclosure for revocation/reporting, even if receipt
is unknown. A later password change cannot reliably recall buffered bytes.

**Receiver grant check.** The grant includes VK, vault ID/generation, public
slot descriptor and the selected control-record head identity. Bound and
authenticate it, validate IDs/profiles, unwrap the public slot with B's typed
password, and constant-time compare with VK before bulk transfer. Wipe B's
password/MK/KEK then. Retain only the protected VK and a session-bound proof of
the descriptor/head binding for staging/publication; do not request the
password again merely to build or reopen the file after transfer.

**Key method.** B obtains VK independently from its phrase or unlocked copy.
Derive independent session-specific MAC and key-schedule secrets from VK/T0.
B proves first without requesting vault metadata; A verifies before returning
identity M and its role-bound proof over M. Existing copies compare M with
their known vault/generation; a phrase receiver adopts the authenticated
identity. TA includes both proofs and M. B's exchange State is the first
epoch-1 record; A verifies it before sending its own epoch-1 record or objects.
No VK grant and no second password gate occur. For key/enroll, permit the
authenticated empty receiver state without requiring a password-method grant.

**Epoch/encoding contract.** Keep deterministic bounded CBOR, SHA-256
transcripts, HKDF-SHA-512, MAC/1 and counter-nonce XChaCha20-Poly1305. Use
separate `qv/lan-*/v2` domains for changed handshake/auth/Finished/grant
transcripts; each info/AAD binds profile, method, intent, role/direction,
epoch and transcript as applicable. Never concatenate variable-length inputs.
Counters restart only under distinct keys; no old-key trial-decrypt or fallback.
TA excludes FinishedB and grant to avoid circular derivation. Do not treat a
four-flight diagram as permission to parse two unbounded frames at once.

Step 1 writes the exact registry, array arities, byte lengths, derivation
outputs, message maxima, failure codes and state transitions in 0013 and a
local `LAN-CONTRACT.md` review checklist. Derive engine message lengths from
the pinned suite's serializers; reject all other lengths before decoding and
cap each credential message at 4 KiB. The overall pre/post-key frame limits
remain at least as strict as 0013 §1.3. An unsupported future suite gets a new
profile; no negotiation selects arbitrary KDF parameters.

**Secrets.** Password input has the existing byte bound/NFC behavior. Protect
application-owned state with `SecretBytes`/`SecretArray`; no secret Debug,
errors, logs, argv, files or serialized preferences. Audit dependency-owned
states and scratch buffers separately; wrapping final outputs does not erase
intermediates. OS RNG failure must prevent release of any resulting message;
the adapter may not use application `unwrap`/`expect` or a zero-seed fallback.
Erase ephemeral registration, setup and session states on success, failure,
lock, cancellation and timeout. Dioxus control/bridge copies remain a documented
best-effort boundary. Do not promise 100 ms interruption inside Argon2 itself.

**Publication.** Stream the complete ciphertext exchange into private staging;
verify manifest/object commitments, every record and all model budgets. Bind
the staged unique password record to the earlier public descriptor/head on the
password route. Phrase enrollment preserves the authenticated password record
without asking the phrase holder to know or reset the password. Confirm received
vault name and destination before publication. Build fresh replica/writer/anchor
state; verify and preflight the candidate before fsync/no-replace rename,
then anchor completion, then report. A post-publication failure is never reported
as “nothing created.” Existing-copy sync retains normal merge/snapshot rules
and never advances the remote server base/outbox.

### D. Core/store interfaces to introduce or replace

Names below are sketches; keep these capability and ownership boundaries.

```rust
pub enum LanAuthMethod { Password, Key }
pub enum LanIntent { Enroll, Sync }
// AuthSnapshot fields are private and bound to one unlocked session/head.
// PendingPasswordApproval contains protected password input, never Debug.
// PasswordAuthServer/Client own ephemeral component states; no serialize API.
// AuthenticatedLan owns final keys and cannot be constructed from a code alone.
// EnrollmentProof binds method, VK, identity, descriptor and selected head.

impl Session {
    // Snapshot/check slot under short session reads; KDF outside the mutex;
    // recheck snapshot before using the reauthentication result.
    // grant_for_authenticated_lan(snapshot, final_sealer, cancel) seals once.
}
impl VaultFile {
    // create_from_verified_lan accepts method-bound verification capability,
    // not only PasswordProof; no arbitrary raw VK grants from frontend code.
}
```

Prompt traits return protected password/phrase values or cancellation. Fixed
UI question enums carry comparison/name and prompt purpose but never secrets;
secret answers use protected storage, session/form epochs and immediate cleanup.

### E. Large-vault views without a total text cap

Split `Index` into structural `RecordMeta` and an evictable view cache. Keep
kind, bounded head IDs/status, representative version, group/owner IDs,
timestamps and tree topology in the structural index. Keep confidential titles,
group order/name/icon, type hints and searchable values in the cache or load
them on demand. The structural index is bounded by existing record/object/clock
budgets, not by total string bytes.

Build structural metadata with one authenticated head decoded at a time and
compact head summaries for merge/representative rules; do not retain 256 full
1 MiB head payloads for one conflicted record. Preserve `merge_record`'s kind,
clock, representative and trash/tombstone rules, verified against the current
projection on generated cases. Retain no protected values or notes for search.
Unlock still validates every required object; lazy views do not skip integrity
or schema checks. Cache entries are keyed by record and representative version;
mutation/merge invalidates affected entries and query snapshots.

Use **64 MiB as the cache's owned-text ceiling**, not a vault eligibility
test. Charge actual owned text capacity, normalized/sort-key copies and cursor
buffers, not merely UTF-8 source lengths. Evict/drop zeroizing values before
insertion; records too costly to cache use bounded transient decode instead.
Maintain separately documented bounds for a decoded record, compact index,
returned pages, GUI/framework copies and KDF scratch; 64 MiB is not a claim
about total process RSS. Never spill plaintext to disk/SQLite/temp files.

Introduce page APIs for list/search/all items/recovered/trash/conflicts and
metadata iterators for autofill/addressing where those currently collect all
text. Proposed defaults: at most **32 rows and 2 MiB owned display text per
page**, with one-row fit verified against the model's maximum record and
summary bounds. A page yields as soon as either bound is reached. No silent
truncation of a field, row or result set; a legitimate uncached row remains
readable. Store cursors privately with redacted, zeroizing sort text and bind
them to session tag, local state revision, query/scope and ordering. A changed
revision returns `StateChanged`/stale cursor, not mixed or duplicated pages.

```rust
pub struct ViewCursor { /* private snapshot/scope/order continuation */ }
pub struct ViewPage<T> { pub items: Vec<T>, pub next: Option<ViewCursor> }
pub struct PageLimit { /* validated rows <= 32, bytes <= 2 MiB */ }
// Session::{list_page, search_page, all_items_page, trash_page, conflicts_page}
// take the appropriate scope, optional cursor, limit and cancellation token.
```

Baseline algorithm: scan structural IDs, decode only needed representatives,
match with existing case-insensitive rules, and select the next bounded set
using a bounded top-k heap of sort keys/IDs. Keep the current sort semantics:
group listings by order/ID; entries by lowercased title/ID; search groups then
entries by their current respective order. Account Unicode expansion in the
sort-key budget. Materialize page rows only after selection; cursor advances
only past returned rows. Repeated scans trade CPU/I/O for bounded memory;
benchmark before adding a more complicated index. The 32-row candidate-key
set and one-record decode must fit independently of total matching records.

Scan in small batches (at most 16 records, checking between heads) under short
session reads, releasing the mutex between batches and revalidating the state
revision. Lock/cancel/stale results discard accumulated output. No long-held
snapshot may copy VK out of the session to bypass lock cleanup. Search remains
complete over all matching records, even when cache residency is much smaller.

The app must page/virtualize All items, search, sidebar groups and long lists;
retain only the current and adjacent pages (at most three) plus selected detail.
Evict filtered/stale/locked rows and ignore late worker results by form epoch.
Do not concatenate pages into the current `all_items()` vector. CLI commands
stream pages and paths/JSON, preserving documented ordering and schema without
collecting all rows or group-name text. Resolve path components on demand with
bounded caching; deep paths are emitted in bounded pieces, not copied for
every item. If a snapshot becomes stale after output began, exit with an
explicit failure and never silently restart/duplicate output.

Remove aggregate text preflight from edits/merges, replacing it with compact
projection validation and per-record/model/cache accounting. Exercise password,
phrase and quick unlock, archive restore/import, rotation, and LAN creation;
no path may publish and then discover it cannot open because of cache residency.

### F. Dependencies and review evidence

| Candidate | Why / alternatives | Evidence and integration boundary |
|-----------|--------------------|-----------------------------------|
| `opaque-ke = "=4.0.1"`, defaults off, `ristretto255` + `argon2` only | Existing password-authentication building block; avoids a custom password proof. Raw password-MAC and early password-wrapped VK are rejected offline-oracle designs. No new balanced-PAKE implementation is authorized. | MIT/Apache-2.0; upstream reports a 2021 audit covering older releases, not this composition/current release. Inspect changes and record actual audit scope. Versioned metadata reports Argon2 0.5, digest 0.10 and rand 0.8, whereas workspace profiles use newer families. Keep adapters/aliases inside qv-crypto and preserve existing workspace profiles. |
| Required version-family bridge dependencies | SHA-512 suite type, RNG traits and explicit Argon2 parameters/zeroization for that engine | Resolve and pin the minimal bridge set in step 2; record exact versions/features in DEPENDENCIES.md and Cargo.lock. Enable appropriate zeroization; no new unreviewed production RNG, crypto primitive or broad serde/std feature set. Any materially different engine/version requires plan/spec revision before step 4. |

Research checked 2026-11-08: [versioned package metadata](https://docs.rs/crate/opaque-ke/4.0.1),
[tagged manifest](https://github.com/meta/opaque-ke/blob/v4.0.1/Cargo.toml),
[upstream audit statement](https://github.com/meta/opaque-ke#audit).
Stage 2 verifies advisories, provenance, transitive unsafe footprint, secret
lifetimes, Android/MSRV support and licenses; `cargo deny`/`cargo vet` results
are evidence, not a substitute for security review. No dependency added now.

## Steps

LAN steps 1–10 are the first delivery boundary; they can be reviewed before the
cache work. Steps 11–14 finish large-vault support; step 15 reviews the combined
result. Keep these steps in one plan and resume through its execution log.

### Step 1 — Amend requirements and specify exact contracts

- [ ] **Do:** Record owner choices; amend the specs identified above before
  behavior changes. Write the exact LAN profile/encoding/key/state/error table,
  timeout/deadline semantics and the paged-view contract. Include method versus
  intent, grant disclosure point, descriptor projection and authenticated
  recovery publication. Reconcile v4 with these clarifications; keep v1–v3 and
  reviews as history. Record applicable Draft-section authorization explicitly.
- **Files:** specs/0001–0005 as affected, 0008/0009/0011–0014, specs/README.md;
  this directory/LAN-CONTRACT.md; 0046/diagrams/DESIGN-v4.md and exports only
  if the selected flow changes; architecture and changelog.
- **Done when:** Every new behavior has normative text; no ambiguous transcript,
  intent, epoch or publication rule is left for a coder; spec-only review passes.
- **Verify:** `git diff --check`; local Markdown-link and registry review;
  source-to-contract trace. No Cargo for a documentation-only step.

### Step 2 — Resolve engine/dependency and secret-lifetime evidence

- [ ] **Do:** Inspect pinned sources/features and historic audit scope; assess
  version-family bridges, KDF parameters, zeroization, serialization sizes and
  fallible OS randomness. Record exact suite and direct/bridge versions before
  implementation. Add only the approved minimal dependencies/lockfile entries.
  Review this evidence and step 1's composition before step 4; unresolved
  security issues return to architect. Track external D12 separately.
- **Files:** this directory/DEPENDENCIES.md, LAN-CONTRACT.md; Cargo.toml,
  Cargo.lock, crates/qv-crypto/Cargo.toml; supply-chain/ only with real evidence.
- **Done when:** Selected suite builds on stable/MSRV and Android, license and
  advisory checks pass, exact lengths/profile are fixed, secret cleanup and RNG
  behavior are understood. No invented audit or blanket vet exemption.
- **Verify:** `cargo check --locked -p qv-crypto`;
  `cargo tree --locked -p qv-crypto -e features`; `cargo deny check`;
  `cargo vet --locked`; documented source review.

### Step 3 — Document filesystem decision and isolate public slot encoding

- [ ] **Do:** Close the QV-013 policy discussion with the accepted limitation;
  retain existing runtime protections. Add a defined-field public-descriptor
  projection for restore/LAN/backup boundaries. Compare descriptor projections,
  not whole encrypted-record encodings. Preserve unknown encrypted extensions
  inside the encrypted record; do not rewrite a stored header without its MAC.
- **Files:** crates/qv-model/src/payload/keyslot.rs and tests;
  crates/qv-store/src/{slot,restore,lan_staging,archive,vault,fs}.rs as needed;
  0046/{DECISIONS,FINDINGS}.md and relevant filesystem docs.
- **Done when:** Renames/identical copies remain eligible under normal anchor
  checks; redirection/replacement still rejects. Injected record extensions
  never reach a newly written clear slot; no stored auth state or format bump.
- **Verify:** `cargo test --locked -p qv-model`;
  `cargo test --locked -p qv-store`.

### Step 4 — Implement ephemeral authentication and final-key derivation

- [ ] **Do:** Add qv-crypto wrappers for local ephemeral registration, one-shot
  client/server authentication, exact contexts and KDF settings, independent
  key-method MAC/schedule keys, final directional keys and FinishedB. Maintain
  typed epoch transitions/counters; no state serialization API. Add component
  vectors and mutation tests, not only self-roundtrips.
- **Files:** crates/qv-crypto/src/{lan,profile,lib}.rs; new
  crates/qv-crypto/src/lan_auth.rs; protected wrappers/tests/vectors as needed.
- **Done when:** Wrong passwords, reflected/cross-session/wrong-profile proofs
  and modified engine messages fail before producing usable final channels;
  RNG/KDF errors release no messages; abort/drop cleanup is reviewed.
- **Verify:** `cargo test --locked -p qv-crypto`; compare pinned component
  vectors and independent key-schedule vectors with LAN-CONTRACT.md.

### Step 5 — Add bounded v2 wire messages and explicit record epochs

- [ ] **Do:** Encode/decode new hello method+intent, authentication flights,
  FinishedB and descriptor/head-bound grants. Enforce exact sizes before engine
  parsing; bind AAD and sequence numbers to epochs; reject old-key fallback,
  reordered/duplicated epoch records and counter exhaustion.
- **Files:** crates/qv-protocol/src/{lan,registry,message,error}.rs;
  crates/qv-sync/src/lan/{transport,steps,vectors}.rs; frame tests/fuzz targets.
- **Done when:** Frozen v2 vectors cover every message/transcript and both
  directions; malformed arity/length/profile cannot allocate beyond bounds.
- **Verify:** `cargo test --locked -p qv-protocol`;
  `cargo test --locked -p qv-sync`; execute bounded malformed-frame corpus.

### Step 6 — Close all admission after one valid hello

- [ ] **Do:** Replace Used/second-hello monitoring with a single accepted-stream
  handoff and explicit listener ownership drop; close advertisements too. Keep
  the pre-accept failure budget and absolute expiry. Remove probe-timeout state
  made obsolete by listener closure. Do not keep a hidden clone listening.
- **Files:** crates/qv-sync/src/lan/{window,approver,mod,tests}.rs and serving
  driver lifecycle tests.
- **Done when:** First fully valid hello closes every listening socket;
  already queued/parallel connections are dropped; later junk cannot affect
  the accepted session's auth checks. Invalid hellos consume no credential work.
- **Verify:** `cargo test --locked -p qv-sync`; real loopback tests for queued
  connections, acceptor shutdown, wrong-code floods, expiry and cancellation.

### Step 7 — Integrate credential authentication and atomic grant policy

- [ ] **Do:** Drive v4 on both methods/intents. A reauthenticates outside long
  session critical sections, then revalidates the snapshot before replying.
  Bind its ephemeral state to the exact slot/head. Verify KE3 and FinishedB
  before the atomic grant operation. B verifies its slot before transfer and
  wipes password keys. Add redacted auth/state/cancel outcomes without a new
  reusable password-guessing oracle or retry on a spent code.
- **Files:** crates/qv-core/src/{lan,session,credentials}.rs;
  crates/qv-sync/src/lan/{approver,joiner,exchange}.rs and tests.
- **Done when:** A malicious custom receiver that skips every local prompt
  still cannot obtain a grant without credentials. Password changes/lock before
  authorization reject; post-seal cancellation reports possible disclosure.
- **Verify:** `cargo test --locked -p qv-core lan`;
  `cargo test --locked -p qv-sync`; barrier-driven grant/password-change tests
  covering both orderings, cancellation after sealing and partial writes.

### Step 8 — Publish password/phrase enrollments without another password gate

- [ ] **Do:** Replace the password-only creation capability with method-bound
  verified enrollment proof. Stream and fully validate staging; verify the
  granted descriptor/head against the staged record. Create/reopen the result
  through protected VK without keeping or prompting for B's password again.
  Phrase mode preserves its password records; fresh replica/writer/anchor state
  is local. Preflight candidate validity before destination publication.
- **Files:** crates/qv-store/src/{lan_staging,restore,vault}.rs and tests;
  crates/qv-core/src/{lan,session,setup}.rs.
- **Done when:** Correct password or phrase enrollment publishes a complete,
  openable vault, including a fingerprint-unlocked source; incomplete or
  mismatched staging publishes nothing. Crash/anchor failure reports actual
  publication and never silently resets the shared password or enables biometrics.
- **Verify:** `cargo test --locked -p qv-store`;
  `cargo test --locked -p qv-core lan`; publication/anchor fault injection.

### Step 9 — Implement the two-device prompts and recovery choice

- [ ] **Do:** Add protected A-side password approval and early B-side password
  or phrase input. Show comparison/selected vault meaningfully; retain final
  received-name/destination confirmation. Clear forms/answer buffers and discard
  late responses on cancel, lock, timeout and Android background. Update CLI
  prompts/help, receipts and explicit incompatible-peer guidance.
- **Files:** crates/qv-cli/src/{cli,term,cmd/lan}.rs and tests;
  crates/qv-app/src/{lan,controller,ui}.rs or their actual module files;
  app LAN/UI tests and Android prompt lifecycle tests.
- **Done when:** Both password prompts are required on the password route;
  key sync remains password-free; phrase enrollment has no extra password gate;
  secrets do not reach argv/logs/non-secret UI state; mismatches never publish.
- **Verify:** `cargo test --locked -p qv-cli`;
  `cargo test --locked -p qv-app`; real-window validation with
  `RUST_TEST_THREADS=1 cargo test --locked -p qv-app --features validation`;
  actual Android/Linux prompt and lifecycle evidence per app README.

### Step 10 — Review LAN composition and exercise hostile peers

- [ ] **Do:** Complete the attack matrix below, source-check all key lifetimes
  and v2 vectors, and run both LAN initiation directions without Internet or
  server state. Record a reviewer verdict for the LAN delivery boundary and
  prepare a D12 review package locally; do not send it without authorization.
- **Files:** this directory/{REVIEW,LAN-VALIDATION}.md, LAN-CONTRACT.md, vectors,
  affected tests, 0046 findings ledger.
- **Done when:** Tests show no code-only grant or legacy fallback; intended
  authenticated paths work; reports separate key disclosure, receipt and local
  publication/commit. Unavailable physical/external evidence remains open.
- **Verify:** `cargo test --locked -p qv-crypto -p qv-protocol -p qv-sync -p qv-core`;
  `sh scripts/check-matrix.sh`; LAN/device checks recorded in LAN-VALIDATION.md.

### Step 11 — Replace aggregate-text index eligibility with compact metadata

- [ ] **Do:** Introduce structural summaries and bounded view cache; validate
  heads one at a time while preserving model projection. Migrate structural
  consumers (edits, conflicts, history, settings, autofill, archive/LAN merges,
  all unlock paths) so titles/search values no longer have to remain resident.
  Remove aggregate-text vetoes without removing per-record/model validation.
- **Files:** crates/qv-core/src/{index,session,edit,exchange,lan,views,autofill,
  conflict,history,settings}.rs as affected; qv-model metadata projection and
  tests; focused core fixtures.
- **Done when:** A valid vault beyond 64 MiB searchable text opens/edits/merges
  without a raised constant; cache accounting/eviction is deterministic and
  lock clears retained data; ordinary projection/merge behavior is unchanged.
- **Verify:** `cargo test --locked -p qv-model`;
  `cargo test --locked -p qv-core`; compact/full projection equivalence tests.

### Step 12 — Add complete paged views and cancellation

- [ ] **Do:** Implement snapshot-bound page APIs and bounded top-k selection,
  on-demand searchable-field reads, cursor cleanup and stale-state rejection.
  Cover list/search/All items, trash/conflicts/recovered and metadata consumers;
  preserve Unicode matching, group order, recovered groups and duplicate-title
  tie breaks. Remove or retire eager collection APIs after callers migrate.
- **Files:** crates/qv-core/src/{views,index,session,error,autofill}.rs and tests;
  public exports in lib.rs.
- **Done when:** Traversing all pages equals the current eager result on
  eligible fixtures, with no missing/duplicate hits and no protected searches;
  peak owned text is bounded for match-everything and maximum-size field cases.
- **Verify:** `cargo test --locked -p qv-core`; generated paging/order tests,
  tiny-cache eviction tests, stale cursor and lock/cancel race tests.

### Step 13 — Bound CLI and app consumers end to end

- [ ] **Do:** Replace eager app All items/sidebar/search collections with
  page-driven views and bounded adjacent-page retention. Stream CLI listing,
  recursive paths, search and JSON through page APIs; remove full-text path
  maps and frontend collection fallback. Migrate public API callers in tests.
- **Files:** crates/qv-app/src/{workspace,views,ops,ui} modules and tests;
  crates/qv-cli/src/{address,select,cmd/ls,cmd/search,cmd/trash,cmd/conflicts}.rs
  and other discovered callers; docs/help where required.
- **Done when:** Stock frontends browse/search oversized metadata without
  retaining every row; CLI schema/order remain compatible; UI selection and
  late-response handling remain correct across cache eviction/state changes.
- **Verify:** `cargo test --locked -p qv-cli -p qv-app`; streamed JSON/order
  fixtures; app/controller tests and supported-device large-list evidence.

### Step 14 — Validate large vaults across all creation/acceptance paths

- [ ] **Do:** Add a production-budget fixture with more than 64 MiB searchable
  text, using ordinary authoring APIs after step 11, without patched constants.
  Exercise open/edit/restore/archive merge and v4 LAN join on both credential
  routes. Check 1 GiB reference-budget arithmetic/boundary with streamed or
  synthetic reference fixtures; benchmark a real large vault separately.
- **Files:** core/store/sync integration tests and fixtures;
  this directory/LARGE-VAULT-VALIDATION.md; existing budget benchmark tooling
  if its tracked interface can be reused without unrelated refactoring.
- **Done when:** Oversized searchable metadata remains complete/readable within
  bounded residency; invalid ciphertext/model budgets still reject before
  commit/publication. Record latency, memory categories and target limitations;
  do not claim a full 1 GiB device test from an arithmetic fixture.
- **Verify:** `cargo test --locked -p qv-core -p qv-store -p qv-sync`;
  reproducible large-vault benchmark commands/results recorded in the validation
  document, plus Android/Linux read/search/lock checks.

### Step 15 — Final review, gates and documentation handoff

- [ ] **Do:** Run full final-tree gates; review spec/code/secret-lifetime/crash
  conformance with quickvault-reviewer. Update assessment dispositions only
  where evidence supports closure. Update architecture diagrams, user docs,
  spec statuses/Changelogs and plan indexes. Keep D12/device release gaps honest.
- **Files:** this directory/{PLAN,REVIEW,LAN-VALIDATION,LARGE-VAULT-VALIDATION}.md;
  ARCHITECTURE.md/diagram; CHANGELOG.md; specs/README.md and affected specs;
  plans/README.md; 0046/{DECISIONS,FINDINGS,PLAN}.md and diagram navigation.
- **Done when:** Final implementation is reviewed, gates pass on the final
  tree, every claimed finding has supporting evidence, and unfulfilled release
  gates remain visibly open. No commit, push or branch is made.
- **Verify:** Full test plan below; manual product/doc/spec reconciliation.

## Test plan

Final implementation gates, once on the final tree (repeat affected checks
after later edits):

```sh
sh scripts/check-spdx.sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
sh scripts/check-matrix.sh
cargo deny check
cargo vet --locked
```

Set `QV_TEST_KDF_JOBS=2` or lower if needed; that variable bounds test KDF work,
not production scheduling. Serial real-window tests use `RUST_TEST_THREADS=1`
only for the app validation command in step 9. Keep full command output in
temporary logs with exit status preserved, and report short summaries. Plan-
and spec-only work runs documentation/SPDX checks without Cargo, following the
owner's instruction. Device test/build commands come from the tracked app README;
record exact commands used and distinguish synthetic from actual hardware.

### LAN adversarial matrix

- Stolen code/custom receiver; wrong password; fake emitter; one online guess;
  no public slot/VK/object stream on failure. Verify application behavior by
  observing frames, not by trusting the receiver's own password prompt.
- Relay across distinct T0, reflection, wrong method/intent/profile, vault or
  generation substitution, mutated KEM/auth bytes, bad/noncanonical lengths,
  unexpected messages, malformed keys, replay and exhausted counters.
- Correct KE3 with wrong/missing/replayed FinishedB: A sends no final-key
  grant. Coalesced KE3/FinishedB cannot skip the KE3 verification boundary.
- Key/enroll versus key/sync; wrong phrase/generation; no stable source identity
  before B's proof; A accepts final-key State before its own protected data.
- Concurrent password change/lock versus reauth, KE2, FinishedB, atomic seal
  and first write; both mutex orderings; pending/partial delivery; no claim of
  retracting disclosed VK. One code is never reopened after failure.
- Simultaneous queued connections, invalid MAC floods, every listener closed,
  no background retry/advertisement, absolute deadline across candidates/UI/
  KDF/transfer, bounded cancellation after uninterruptible work.
- Descriptor/head mismatch, conflicted/missing keyslot, unknown encrypted
  extensions, maximum-sized valid slot/record, incomplete staging, disk-full,
  interrupted no-replace publication/anchor, lost Done after local commit.
- Password path wipes both typed passwords before bulk; phrase route requires
  no password/reset; biometric source works with explicit password approval;
  no persistent registration, new file-format fields or account dependence.

### Cache/paging matrix

- Stock >64 MiB text fixture, 1 GiB ciphertext limit retained; maximum fields,
  large/conflicted heads, uncachable row, Unicode lowercase expansion, all
  matches, duplicate sort keys and deeply nested/recovered groups.
- Complete results versus eager reference; cursor query/scope/session/revision
  mismatch; edits/merges during scan; no all-results frontend/path accumulation.
- Password/phrase/quick unlock, edit, merge, restore, rotation and LAN publication
  all share compact validity checks. Cache exhaustion evicts, not rejects data.
- Lock/cancel clears cache, query/sort/cursor/page state and late GUI answers;
  protected fields/notes never enter matching or cache; no plaintext disk spill.

### 0012 §1 traceability

Use exact row comments above tests covering offline rows; update the checked
matrix only when a normative row is added. Primary existing rows:

- `LAN discovery mistaken for trust`, `LAN partial acceptance`,
  `Account-dependent LAN sync`, `Unrequested synchronization`.
- `Unpinned crypto`, `Ambiguous trust boundary`, `Hostile SQLite/CBOR`.
- `Password-slot partitioning oracle`, `Exchange-file password guessing`.
- `Whole-file rollback`, `Live SQLite copying`, `Anchor crash windows`.
- `Mixed credentials`, `Order-dependent merges`, `Budget inconsistency`.

Step 1 adds explicit LAN credential-authentication requirements without
misrepresenting the existing remote-account `Authentication complexity` row
as evidence for this different composition. Passing vectors, tests or specs
does not prove security; D12 and target evidence remain required.

## Risks and stop conditions

- Stop if the password component cannot meet fixed-cost, malicious-peer,
  secret-cleanup, safe-RNG or Android requirements. Do not implement a PAKE,
  silently downgrade to password-MAC or send an early password-wrapped key.
- Stop for any proposal to persist authentication state or change file/archive
  formats: owner chose ephemeral v4; v3 migration is not authorized here.
- Stop if the exact combined-key/record transition admits a replay, downgrade,
  cross-method use, old-key fallback or application data before credential auth.
- Stop if a new recovery API could be called with unverified/raw frontend
  material, skip existing anchor safeguards or silently reset shared credentials.
- Stop before changing the 1 GiB/per-record/manifest/causal budgets, protected
  search scope or directory eligibility policy. No dropped fields, conflicts,
  clocks or partial vaults to make a fixture fit.
- If bounded sorting/scanning is too slow on target devices, record measurements
  and revise the architecture; do not restore a hard aggregate text cap or
  accumulate all plaintext as an unreviewed optimization.
- Existing uncommitted owner work and staged diagrams must remain intact.
  The v4 artifact is owner-selected direction, not an already reviewed protocol.
- Missing device/external evidence blocks only the corresponding release
  claim; record it rather than inventing results or marking a gate complete.

## Documentation

- [ ] CHANGELOG.md — exact behavioral scope and compatibility consequences.
- [ ] ARCHITECTURE.md §3–6/diagram — ephemeral auth and view/cache boundaries;
  no new crate, stored verifier or file/archive format migration.
- [ ] Specs and index — amendments from step 1, exact profile/registry and
  testing requirements, preserve partially implemented/Draft statuses honestly.
- [ ] CLI/app docs — password on both devices, recovery, new-peer-version
  requirement, cache meaning, large-vault latency and truthful partial outcomes.
- [ ] 0046 decisions/findings — supersede historical recommendations, retain
  audit evidence and distinguish owner-accepted limitation from repaired code.
- [ ] This plan/index/validation/review — evidence, remaining steps and D12 gaps.
- [ ] AGENTS.md/skills — no workflow change expected.

## Revisions

- 2026-11-08: Initial plan requested for the three discussed assessment topics.
  Found newly staged v4, asked the concrete product choice, and recorded the
  owner's explicit selection of password entry on both devices. This removes
  v3's persistent-credential migration from implementation scope.

## Execution log

- 2026-11-08: Planning only. Read the relevant architecture/spec requirements,
  actual index/list/search/All items, slot/restore, grant and listener paths,
  v3 reviews and staged v4. Identified separate auth intent for phrase enrollment,
  frontend accumulation, and library version-family integration as explicit
  implementation requirements. No code/spec/dependency/diagram or staging
  changes; no Cargo commands. Documentation checks are recorded at handoff.
- 2026-11-08: Planning handoff checks passed: `sh scripts/check-spdx.sh`,
  `git diff --check HEAD`, 83 local Markdown link targets, and 15 consecutively
  numbered steps with actions/completion criteria/verification. Updated the
  spec index's non-normative planning note and 0046's superseded decision
  ledger; normative spec text, production code, dependencies and staged
  diagram source/exports remain unchanged. No Cargo commands or staging actions.
