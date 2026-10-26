# Plan 0009 — Objects, manifests, local head, anchor and the write path

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-26 | 2026-10-26 | 0004 §2–5; 0005 §1.2–1.4, §5.1, §5.4 (D5); 0002 §3.3, §3.6, §7.2, §8; 0003 §2.3; 0011 §6; 0012 §1 |

## Intent

Roadmap 0002 phase 1.7. Give `qv-store` its real contents: encrypted
immutable objects whose plaintext envelope cannot be linked to records, the
encrypted manifest that defines the vault's state, the authenticated local
head, the external anchor, writer IDs with counter reservations, and the one
mutation transaction (0004 §5.2) that every later write path reuses. Unlock
then verifies all of it (0004 §3.6, 0005 §5.4). A test-only crash-injection
harness shows that a crash at any ordering point leaves the old state or the
new one.

## Scope

**In scope:**
- **Spec amendment (step 1):** an aggregate clock-component budget in 0004
  §4.1/§4.2, so that the worst-case manifest fits 64 MiB (see *Decisions
  needed* D-A), and a `replica` row in the 0004 §2 table (D-B).
- `qv-crypto`: the `local-state` purpose key becomes a `MacKey` (head MAC
  only).
- `qv-model`: a public clock codec (`Clock::encode`/`Clock::decode` into an
  existing encoder/decoder) for the manifest.
- `qv-store`:
  - object rows and the `ObjectEnvelope` codec;
  - record encryption with the canonical AAD (0004 §3.2);
  - the manifest: types, a bounded canonical codec, role and reference
    resolution, configuration digest, reference digest, encryption, the
    envelope and `manifest_hash`;
  - the authenticated local head and the external anchor (file-backed
    `AnchorDir`);
  - the `replica` row with the writer ID and counter reservation;
  - development schema 2: tables `object`, `manifest`, `local_head` and
    `replica`, exact-schema and row checks, all read in one read
    transaction (plan 0008 review, finding 3);
  - `create` writes the three control records (vault metadata, root group,
    password-keyslot record), the first manifest, head 1 and the anchor;
  - `unlock` runs the 0004 §3.6 verification and the 0005 §5.4 anchor
    table; `unlock_for_recovery` + `adopt_baseline` is the explicit recovery;
  - the write path: `UnlockedVault::write` → `Write::reserve_counter` /
    `put_local` → `commit`, with the head re-read inside `BEGIN IMMEDIATE`;
  - on-demand reads: `read_version` (heads: AEAD; history: length, SHA-256,
    then AEAD);
  - a full disk is told apart from the size budget (plan 0008 review,
    finding 2);
  - a test-only crash-injection harness, crash, anchor, rollback, tamper,
    linkage and worst-case-manifest tests;
  - a `manifest_decode` fuzz target and its CI step.

**Out of scope:**
- Bounded metadata/search views and on-demand decryption into views (1.8).
  Unlock decrypts every head once to verify it, keeps only the record kinds,
  and drops the plaintext; 1.8 may fold the view building into that pass.
- Received (non-local) versions, concurrent heads arising from merges, and
  keeping received ciphertext unchanged (2.2, 2.10, 3.6). `put_local` accepts
  only local edits that dominate every head (0005 §1.2).
- History retention depth, floors other than carrying them forward,
  suppression and purge (1.12). In 1.7 every dominated version stays in
  history until a budget is hit.
- Attachment chunk storage, chunk AAD and chunk reads (1.11). The manifest
  format carries chunk lists now (checked against the decrypted
  `attachment_meta` heads); no chunk is written in 1.7.
- Outbox and `sync_state` (server mode, milestone 3), checkpoint fields of the
  head (decoded, never written), LAN peer state (2.9).
- Archives and `verify` (1.13); password change (1.14); rotation (1.15). The
  head and anchor already accept a generation step, but nothing makes one.
- Encrypting with the `local-state` key (sync/outbox state, milestone 3):
  the AEAD-plus-MAC use of one key is still the owner's call then (plan 0005
  note); 1.7 uses it for the MAC only, as 0002 §3.3 says.
- The CLI and its messages (1.10); Android keystore-backed anchors (2.3/2.6).

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Tables `object`, `manifest`, `local_head`; fixed-length and singleton checks independent of SQL | 0004 §2 | Accepted | `sync_state` is server-mode, not created |
| Multi-head records, manifest defines roles; random 128-bit object IDs | 0004 §2.1 | Accepted | |
| Object plaintext limited to ID, generation, profile, nonce, ciphertext | 0004 §2.2 | Accepted | Envelope codec + DB columns; linkage scan test |
| Canonical CBOR; unknown control content fails closed | 0004 §3.1 | Accepted | Manifest, head and anchor reject unknown keys |
| Record encryption, Padmé, AAD `["qv/record/v1", …]`, manifest role is authoritative | 0004 §3.2, 0002 §3.6, §7.2 | Accepted | |
| Manifest contents, AAD `["qv/manifest/v1", …]`, configuration digest | 0004 §3.4 | Accepted | |
| `manifest_hash`, `reference_digest`; manifest excludes itself | 0004 §3.5 | Accepted | |
| Verification points on unlock and on reads | 0004 §3.6 | Accepted | Import/sync/archive points come later |
| Budgets before allocation; mutual consistency | 0004 §4.1–4.2 | Accepted | **Inconsistent as written → step 1 (D-A)** |
| Unlock order; single mutation transaction; no plaintext on disk | 0004 §5.1–5.3 | Accepted | Outbox: none in offline mode |
| Head re-read inside `BEGIN IMMEDIATE`; identity check | 0004 §1.3 | Accepted | |
| Edit joins all heads, then advances the local component | 0005 §1.2 | Draft (D5) | `put_local` requires domination of every head |
| Writer IDs, durable counter reservation, new ID on rollback | 0005 §1.3 | Draft (D5) | Readings in D-B |
| Equal clocks with different versions are integrity errors | 0005 §1.4 | Draft (D5) | Checked over heads and history (plan 0007 review note 2) |
| Manifest completeness on unlock | 0005 §5.1 | Draft (D5) | |
| Local head, anchor, the head-vs-anchor table | 0005 §5.4 | Draft (D5) | |
| `local-state` key MACs the local head | 0002 §3.3 | Accepted | MAC use only |
| Exactly one vault metadata, password-keyslot and root group record; undeletable | 0003 §2.3 | Accepted | |
| Wrong password vs integrity/rollback | 0002 §8, 0011 §6 | Accepted | New `Rollback`, `NoAnchor`, `Changed`, `InvalidEdit` variants |

D5 (roadmap 0002) covers 0005 §0–2, §5.1 and §5.4. No other Draft section is
used.

**Spec changes required:** yes, 0004 (Accepted), step 1:
- §4.1: add "1,048,576 clock components in total across a manifest's heads,
  retained history and history floors" to the initial limits. §4.2: say that
  this aggregate, not the per-clock writer limit times the object count, is
  what bounds the worst case, and that history yields to it like it yields to
  the object budget.
- §2 table: a `replica` row (exactly one row: replica ID naming the external
  anchor, writer ID, next counter; local-only, never in archives or sync).
- Changelog line, `specs/README.md` index unchanged (status stays Accepted).

## Decisions needed

1. **D-A — The 0004 budgets are not mutually consistent** (0004 §4.2,
   0012 row *Budget inconsistency*). Clocks are in the manifest (§3.4), and
   one clock may have 256 writers of up to 27 bytes each (`[bstr16, u64]`).
   With 250,000 referenced objects (each version needs its own object) the
   worst-case manifest has about 1.6 GiB of clocks. One record with 256 heads
   of 256 writers alone needs 1.7 MiB. The 64 MiB manifest limit cannot hold
   that, so §4.2's release gate cannot pass with the §4.1 numbers.
   Options:
   - **A (recommended):** add one aggregate budget: at most **1,048,576
     (2^20) clock components** across all heads, history and floors of a
     manifest. Estimate for the worst case with this plan's encoding: about
     25 MiB without clocks (50,000 records; 250,000 objects at about 40
     bytes of version reference plus 58 bytes of object reference each) plus
     27 MiB of clocks = **about 52 MiB**, plus at most 1 MiB of Padmé
     padding, under 64 MiB with room left. Honest vaults stay far below it:
     1,000 entries × 11 versions × 3 writers is 33,000 components. History
     yields to it (1.12 prunes), and heads, tombstones and floors fail with
     `LimitExceeded` without changing anything (0004 §4.4).
   - B: a per-manifest writer dictionary with clocks as `[index, counter]`.
     That halves the bytes per component but still needs an aggregate limit,
     so it only adds complexity on top of A. It can be added later, before the
     1.16 freeze, if benchmarks want a larger budget.
   - C: lower the per-record limits (heads, writers) or the object count.
     Even 16 writers per clock over 250,000 objects is 103 MiB, so C would
     have to cut the object budget sharply.
   Blocks: steps 1, 4, 10 (and everything that encodes a manifest).
   Resolution: owner accepted the recommendation (A, 2^20 components) on 2026-10-26.
2. **D-B — Where writer state and the anchor key live** (0005 §1.3 says
   "private application state outside archives"; 0005 §5.4 fixes the anchor's
   contents, not how it is found). Recommendation, recorded with the
   amendment so the owner sees it:
   - Writer ID and counter reservation live in a local-only `replica` table
     in the vault DB, updated **in the same SQLite transaction** that uses
     the counters. A counter therefore never appears in a durable version
     without its reservation being durable too, which is what "reserve
     durably before use" protects. The table is outside archives because
     archives are built from verified objects, never from the DB (0004 §5.3,
     which already lists writer identity among the things archives cannot
     contain). A DB rolled back with its writer state fails the anchor
     check; the only way past that is `adopt_baseline`, which always creates
     a new writer ID ("if writer state is … rolled back, generate a new
     ID"). As a second line, `put_local` refuses a counter that does not
     exceed the joined component of the record's heads (`Clock::for_edit`).
   - The anchor is a file named by a random **replica ID** (also in the
     `replica` row), not by the vault ID: 0007 §3.4 restores a snapshot to a
     new path next to the active vault and keeps the active vault's anchor,
     so two DBs with one vault ID must have separate anchors. The `replica`
     row is not authenticated. Changing it can only make the anchor lookup
     fail (`NoAnchor`/`Rollback`), never make a wrong head pass, because
     acceptance needs the anchor's digest to equal the digest of the MAC'd
     head.
   - Anchor directory: `$XDG_STATE_HOME/quickvault/anchors/` (default
     `~/.local/state/quickvault/anchors/`) on Linux, created 0700. The anchor
     must not sit next to the vault or in a sync folder. Android uses
     the app's private storage from 2.3 (keystore-backed where available,
     2.6). qv-store resolves the Linux default; callers may pass another
     directory (tests do).
   The alternative was writer state in a file next to the anchor, reserved
   in batches before each DB transaction. It survives a DB rollback without
   a writer ID change, but it adds a second durable write and a window
   between the reservation and the commit. Rejected for being more complex.
   Blocks: steps 1, 5–8. Resolution: owner accepted the recommendation on 2026-10-26.

Readings that follow from the specs (no decision needed; listed for the
reviewer):
- **Local edits dominate every head.** 0005 §1.2 has an edit join all known
  heads; with a conflict the edit is the explicit resolution. So
  `put_local` requires the new clock to strictly dominate every current head
  of the record, and all old heads move to history. Concurrent heads arrive
  only through received versions (2.x).
- **Tombstones are heads.** A final tombstone is a version (0005 §2.5) with
  its own small object, so the manifest's "permanent tombstones" are the
  heads that decrypt to a tombstone. They never yield to budgets.
- **Exactly one manifest row** in development schema 2: the one the head
  names. Later phases that keep a remote base manifest relax this.
- **The first head has no `previous_digest`** (key absent iff `local_seq` =
  1).
- **Control record IDs are in the manifest.** 0003 §2.3 says the manifest
  names exactly one vault metadata record, one password-keyslot record and one
  root group, and the root is fixed at creation. The manifest therefore
  carries the three record IDs, unchanged by every commit. Unlock checks
  that the heads of those records have the right kinds, that no other record
  has a control kind, that the root heads pass `check_root`, and that the
  vault-metadata heads name the same root.
- **Unknown keys fail closed** in the manifest, head and anchor: they are
  control structures, not records (0004 §3.1).
- **Head ciphertext hashes are not checked on unlock**, only rows and
  lengths plus AEAD (0004 §3.6); history reads check hash, then AEAD.
- **Unlock fails closed on an anchor mismatch** (`Rollback`, or `NoAnchor`
  if the file is missing). Only `unlock_for_recovery` opens such a vault, with
  writes blocked until `adopt_baseline`. A missing anchor never silently
  resets the baseline (0005 §5.4).
- **If the anchor write fails after the DB commit**, `commit` returns `Io`.
  The change is durable and the next open accepts it as "one ahead". Further
  writes in the session first retry the anchor and refuse to start until it
  succeeds, so the DB can never get two steps ahead of the anchor.

## Design

**Components touched:** `qv-store` (trusted; parses the hostile DB only after
hardening and authenticates before trusting), `qv-crypto` (one trait impl),
`qv-model` (two public codec functions), `fuzz/`, CI. No new crate, no new
dependency, no `unsafe`.

**Development format** (unstable until 1.16; integer keys and labels are
development values):

| Item | Value |
|------|-------|
| `user_version` / header `format` | `0x7FFF_0002` (schema 2) |
| Manifest format key | `0x7FFF_0001` |
| Record AAD | `["qv/record/v1", vault_id, key_generation, record_id, version_id, object_id, data_profile]` (0004 §3.2) |
| Manifest AAD | `["qv/manifest/v1", vault_id, key_generation, data_profile]` (0004 §3.4) |
| Configuration digest | SHA-256 of `["qv/config/v1", format, vault_id, key_generation, min_data_profile, min_derivation_profile]` |
| Head MAC | MAC/1(local-state key, `["qv/local-head/v1", head_body]`) |
| `local_digest` | SHA-256 of `[head_body (bstr), mac (bstr32)]` |
| Manifest envelope | `[key_generation, data_profile, nonce (bstr24), ciphertext (bstr)]`; `manifest_hash` = SHA-256 of its canonical encoding |
| Object envelope | `[object_id, key_generation, data_profile, nonce, ciphertext]` |
| Object reference | `[object_id, data_profile, ciphertext_length, sha256(ciphertext)]`; `reference_digest` = SHA-256 of the canonical sorted reference array |

Manifest plaintext (canonical CBOR map; all keys required, unknown keys fail
closed):

| Key | Field | CBOR |
|-----|-------|------|
| 0 | format | uint |
| 1 | config_digest | bstr 32 |
| 2 | control | `[vault_meta_id, keyslot_id, root_group_id]` |
| 3 | records | array of `[record_id, heads, history, floor]`, strictly ascending by record ID; `heads` 1..=256 and `history` ≥ 0 version refs, each strictly ascending by version ID; `floor` a clock (empty = none) |
| 4 | references | array of object references, strictly ascending by object ID |

Version ref: `[version_id, clock, object_id]`, or `[version_id, clock,
object_id, [chunk_object_id, …]]` for an `attachment_meta` version (at most
160 chunks).

Head body (canonical CBOR map; unknown keys fail closed): 0 `vault_id`, 1
`key_generation`, 2 `local_seq` (≥ 1), 3 `previous_digest` (bstr 32, absent
iff `local_seq` = 1), 4 `manifest_hash`, 5 `remote_checkpoint_id` (bstr 32,
optional), 6 `remote_sequence` (uint, present iff 5). 1.7 never writes 5–6.

Anchor file `<anchor dir>/<hex replica_id>.anchor`, 0600, at most 256 bytes:
`{0: format, 1: vault_id, 2: key_generation, 3: local_seq, 4: local_digest}`.

Schema 2 adds (all `STRICT`; the validator expects these DDL strings and the
`sqlite_autoindex_*` rows SQLite creates for the primary keys, with `sql`
NULL):

```sql
CREATE TABLE object (key_generation INTEGER NOT NULL, object_id BLOB NOT NULL CHECK (length(object_id) = 16), data_profile INTEGER NOT NULL, nonce BLOB NOT NULL CHECK (length(nonce) = 24), ciphertext BLOB NOT NULL, PRIMARY KEY (key_generation, object_id)) STRICT
CREATE TABLE manifest (manifest_hash BLOB PRIMARY KEY CHECK (length(manifest_hash) = 32), key_generation INTEGER NOT NULL, data_profile INTEGER NOT NULL, nonce BLOB NOT NULL CHECK (length(nonce) = 24), ciphertext BLOB NOT NULL) STRICT
CREATE TABLE local_head (id INTEGER PRIMARY KEY CHECK (id = 1), body BLOB NOT NULL, mac BLOB NOT NULL) STRICT
CREATE TABLE replica (id INTEGER PRIMARY KEY CHECK (id = 1), replica_id BLOB NOT NULL CHECK (length(replica_id) = 16), writer_id BLOB NOT NULL CHECK (length(writer_id) = 16), next_counter INTEGER NOT NULL) STRICT
```

`object` and `manifest` are rowid tables, because they hold large blobs.
Row checks (types and lengths before values, as in 1.6): exactly one
`local_head` (body ≤ 1 KiB, 32-byte MAC), `manifest` (32-byte hash; ciphertext
≤ `MAX_MANIFEST_CIPHERTEXT`) and `replica` row (`next_counter` in 1..=i64::MAX).
Object rows are checked per reference during verification. Unreferenced
rows are ignored (0004 §3.6).

**Budgets** (`limits.rs`, 0004 §4.1): `MAX_RECORD_CIPHERTEXT` = 1 MiB,
`MAX_MANIFEST_CIPHERTEXT` = 64 MiB (≤ SQLite `LENGTH` 64 MiB + 64 KiB, which
step 4 confirms with a test), `MAX_RECORDS` = 50,000, `MAX_OBJECTS` =
250,000, `MAX_TOTAL_CIPHERTEXT` = 1 GiB (sum of reference lengths),
`MAX_CLOCK_COMPONENTS` = 1,048,576 (D-A), `MAX_CHUNKS` = 160; heads per record
and writers per clock from `qv-model`. Every count is checked against its
budget before allocating from it. Object reference lengths are bounded by
their role: a version object is at most `MAX_RECORD_CIPHERTEXT`, and a chunk
object is exactly `sealed_len(64 KiB)`.

**Interfaces:**

```rust
// qv-crypto: keys.rs
mac_purposes!(HeaderMac, StateCommit, LocalState);   // LocalState gains MacKey

// qv-model: clock.rs (wrappers of the existing pub(crate) codec)
impl Clock {
    pub fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError>;
    pub fn decode(d: &mut Decoder<'_>) -> Result<Clock, ModelError>;
}

// qv-store
pub struct ObjectEnvelope { pub object_id: ObjectId, pub key_generation: KeyGeneration,
    pub data_profile: StoredDataProfile, pub nonce: [u8; 24], pub ciphertext: Vec<u8> }
impl ObjectEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, StoreError>;
    pub fn decode(bytes: &[u8], max_ciphertext: usize) -> Result<Self, StoreError>;
}

/// The decoded, validated manifest. IDs and clocks are not secret (qv-model);
/// the plaintext buffer it came from is zeroizing.
pub struct Manifest { /* control ids, records, references */ }
pub struct RecordEntry { /* record_id, heads, history, floor */ }
pub struct VersionRef { /* version_id, clock, object_id, chunks */ }
pub struct ObjectRef { /* object_id, data_profile, length, sha256 */ }
impl Manifest {
    pub fn vault_meta_id(&self) -> RecordId;
    pub fn keyslot_id(&self) -> RecordId;
    pub fn root_group_id(&self) -> RecordId;
    pub fn records(&self) -> &[RecordEntry];
    pub fn record(&self, id: RecordId) -> Option<&RecordEntry>;
    pub fn references(&self) -> &[ObjectRef];
    pub fn reference_digest(&self) -> Result<[u8; 32], StoreError>;
}
// + read-only getters on RecordEntry, VersionRef, ObjectRef

pub struct AnchorDir { /* checked private directory */ }
impl AnchorDir {
    pub fn open(dir: &Path) -> Result<AnchorDir, StoreError>;   // creates 0700 if missing; parent rule as for vaults
    pub fn default_dir() -> Result<PathBuf, StoreError>;       // Linux XDG rule; Android: Unsupported until 2.3
}

#[non_exhaustive]
pub enum AnchorStatus { Verified, Advanced, Missing, Mismatch }

impl VaultFile {
    pub fn create(path: &Path, password: &MasterPassword, name: &str,
                  anchors: &AnchorDir) -> Result<UnlockedVault, StoreError>;
    pub fn unlock(self, password: &MasterPassword, anchors: &AnchorDir)
        -> Result<UnlockedVault, StoreError>;                      // Missing → NoAnchor, Mismatch → Rollback
    pub fn unlock_for_recovery(self, password: &MasterPassword, anchors: &AnchorDir)
        -> Result<(UnlockedVault, AnchorStatus), StoreError>;      // writes blocked unless Verified/Advanced
}

impl UnlockedVault {
    pub fn manifest(&self) -> &Manifest;
    pub fn record_kind(&self, id: RecordId) -> Option<RecordKind>;
    pub fn writer_id(&self) -> WriterId;
    pub fn local_seq(&self) -> u64;
    pub fn read_version(&self, record: RecordId, version: VersionId)
        -> Result<RecordVersion, StoreError>;
    pub fn write(&mut self) -> Result<Write<'_>, StoreError>;
    /// Explicit recovery (0005 §5.4): new writer ID, head seq+1 naming the
    /// current head, anchor replaced. Only after unlock_for_recovery.
    pub fn adopt_baseline(&mut self) -> Result<(), StoreError>;
}

pub struct Write<'v> { /* holds the IMMEDIATE transaction */ }
impl Write<'_> {
    pub fn reserve_counter(&mut self) -> Result<u64, StoreError>;
    /// Current heads' clocks of `record` (empty for a new record), for Clock::for_edit.
    pub fn head_clocks(&self, record: RecordId) -> Vec<Clock>;
    pub fn put_local(&mut self, record: RecordId, version: RecordVersion) -> Result<(), StoreError>;
    pub fn commit(self) -> Result<(), StoreError>;
    // Dropping a Write rolls the transaction back.
}

// StoreError gains: Rollback (exit 7), NoAnchor (exit 7), Changed (exit 6),
// InvalidEdit (exit 1). Variants stay data-free.
```

`put_local` checks, in order, and returns `InvalidEdit` unless stated
otherwise: the version's clock component for the writer is a counter
reserved by this `Write` and not used yet; a new record is not a control kind
(control records exist only from `create`); an existing record keeps its
kind; the clock strictly dominates every current head (`Clock::compare`); the
version ID is new for the record (heads and history); the root group's
version passes `check_root`; a vault-metadata version names the manifest's
root. The model's own encode checks (undeletable tombstones, payload limits)
also apply. One record takes at most one `put_local` per `Write`.

**Data and control flow.**

*Unlock* (after 1.6's slot and header MAC, all inside one read
transaction): read and check the `local_head`, `manifest` and `replica` rows
→ verify the head MAC (`Integrity` on failure) → head `vault_id`/generation
equal the header's → recompute `manifest_hash` from the stored columns,
hashing the CBOR prefix and then the ciphertext without a second copy; it
must equal the row key and the head's value → AEAD-open the manifest
(`MAX_MANIFEST_CIPHERTEXT`) into a zeroizing buffer → bounded decode and
validation (structure, sort orders, budgets, uniqueness, every role maps to
exactly one reference and every reference to exactly one role, history
strictly dominated by some head and not suppressed by the floor, clocks
unique per record) → configuration digest equals the header's → for every
reference, the object row exists in this generation with that profile and
length → for every head, AEAD-open under the record key with the role's AAD,
decode, and require the same `version_id` and clock as the manifest, one kind
per record, the control-record rules, and chunk lists equal to an
`attachment_meta` payload's (absent otherwise) → compare head and anchor per
0005 §5.4 (an `Advanced` result replaces the anchor before returning). Any
failure before the anchor check is `Integrity` (or `LimitExceeded` /
`Unsupported` where those apply). The step budget is reset per operation.

*Mutation* (`write` … `commit`; `CrashPoint` marks the test hooks):

1. `write()`: refuse if writes are blocked; if an anchor update is pending,
   retry it first; `check_identity()`; `BEGIN IMMEDIATE`; re-read the head
   row, which must equal the in-memory head byte for byte (else `Changed`);
   re-read the `replica` row. — `CrashPoint::Begun`
2. `put_local`: encode the version, seal it under the record key with a new
   random object ID and the record AAD, insert the object row, stage the
   manifest change. — `CrashPoint::ObjectsWritten` (after the first put)
3. `commit()`: build the new manifest (budgets checked, so nothing is
   written past them), seal it, insert the manifest row, delete the old one.
   — `CrashPoint::ManifestWritten`
4. Write the new head (seq + 1, `previous_digest` = old digest, new
   `manifest_hash`, MAC). — `CrashPoint::HeadWritten`
5. Update `replica.next_counter`. Prune: delete the object rows of references
   that the old manifest had and the new one lacks. — `CrashPoint::Pruned`
6. `COMMIT` (`synchronous=FULL`: durable on return). — `CrashPoint::Committed`
7. Replace the anchor: temp file `O_EXCL` 0600, write, `fsync`, rename over
   the old anchor, `fsync` the directory. — `CrashPoint::AnchorTempWritten`
   (before the rename), `CrashPoint::AnchorReplaced` (after the rename,
   before the directory sync)
8. Update the in-memory manifest, head and kinds; return `Ok`.

Expected states after a crash: up to `Pruned`, the old state with the old
anchor (normal open). At `Committed` and `AnchorTempWritten`, the new DB with
the old anchor, so the open sees "one ahead", advances the anchor and shows
the new state. At `AnchorReplaced`, the new state (normal open; the directory
sync only adds durability).

*Create:* build the temp DB (schema, header, slot, `replica`, the three
control records with counters 1–3, manifest, head 1), commit, close, fsync
the temp file — `CrashPoint::CreateBuilt` → write anchor 1 —
`CrashPoint::CreateAnchored` → `rename_noreplace` → sync the directory →
reopen through `open_locked` + `unlock`'s verification (a self-test). Writing
the anchor before the rename means a crash never leaves a vault at the path
without its anchor. A crash before the rename leaves only a temp file and an
orphan anchor under a random replica ID, both harmless. On a failure before
the rename, the temp file, its journal and the new anchor are removed best
effort.

*Recovery:* `adopt_baseline` runs as an ordinary mutation with no records.
It generates a new writer ID (and resets `next_counter` to 1), writes head
seq + 1 naming the current head, commits and replaces the anchor. Then the
vault is writable.

**Crash-injection harness (tests only).** A `#[cfg(test)]` thread-local
`CRASH_AT: Cell<Option<CrashPoint>>`. At the matching point the code copies
the vault file, its `-journal` if present, and the anchor file (each with
its mode) into a fresh snapshot directory, then returns `Internal`, as a
crash would stop there. Dropping the handles rolls back the in-process
transaction; the test opens the **snapshot**. That reproduces what a killed
process leaves on disk: the hot journal is replayed by SQLite (allowed by the
1.6 sidecar rule, since it is ours and 0600), and the anchor is whatever was
renamed into place. Power-loss reordering below the fsync level is out of
scope (SQLite's own guarantees).

**Secrets and hostile input.**
- Record plaintext is encoded into `Zeroizing` buffers (qv-model) and sealed
  from them; decrypted plaintext is `SecretBytes` and decoded straight into
  the model's zeroizing types. Unlock verification drops each head after
  checking it.
- Manifest plaintext is encoded into `Zeroizing<Vec<u8>>` and decrypted into
  `SecretBytes`. The decoded `Manifest` holds IDs and clocks, which qv-model
  treats as non-secret. It has no plaintext field content and lives only
  inside `UnlockedVault`.
- Keys: `DataKey` per record, the manifest and local-state `PurposeKey`s; all
  derived on demand from `VaultKey` and dropped (zeroized) after use; never
  in `Debug`.
- The DB stays hostile until the head MAC verifies; after it does, manifest
  content is still parsed strictly and bounded (any VK holder may author it,
  qv-model trust boundary). The anchor file is unauthenticated and only
  compared, read with `O_NOFOLLOW`, owner/mode checks and a 256-byte bound.
- Nothing plaintext reaches DB pages, journals or temp files: only
  ciphertext, IDs that 0004 §2.2 allows in plaintext (object ID, generation,
  profile, nonce), the MAC'd head (vault ID, sequence, digests), the header
  and slots, and the `replica` row (two random IDs and a counter). The
  linkage test scans the whole DB file for every record, version and
  attachment ID.

**Errors.** New `StoreError` variants: `Rollback` (anchor mismatch: older,
fork, more than one ahead, other vault; exit 7), `NoAnchor` (no anchor for
this replica; exit 7; the CLI offers explicit recovery), `Changed` (the head
changed under us; exit 6), `InvalidEdit` (an edit breaks a vault rule;
exit 1). `SQLITE_FULL` maps to `LimitExceeded` only when the file has reached
`max_page_count`; otherwise it is `Io` (disk full). The plan 0008 review
asked for this; the step-4 tests check both.

**Dependencies:** none new. `rustix` `fs` (already enabled) covers the anchor
file operations.

## Steps

### Step 1 — Spec amendment: aggregate clock budget and the `replica` row

- [x] **Do:** After the owner resolves D-A and D-B, amend 0004 §4.1 (add
  the clock-component budget as resolved), §4.2 (it bounds the worst case;
  history yields to it) and the §2 table (`replica` row, per D-B). Add a
  dated Changelog line. Do not change any other section.
- **Files:** `specs/0004-local-storage.md`.
- **Done when:** the text matches the resolution; the Changelog has the line.
- **Verify:** `grep -n 'clock components\|replica' specs/0004-local-storage.md`.

### Step 2 — `qv-crypto` and `qv-model` hooks

- [x] **Do:** Add `LocalState` to `mac_purposes!`, update its doc ("MACs the
  local head; encryption comes with sync state"), and add a test that a
  local-state MAC differs from a header-MAC MAC over the same message. Add the
  public `Clock::encode`/`Clock::decode` wrappers; round-trip and rejection
  tests (257 writers, a zero counter, unsorted pairs) through the public
  functions.
- **Files:** `crates/qv-crypto/src/keys.rs`, `crates/qv-model/src/clock.rs`.
- **Done when:** both crates' tests pass; no other API change.
- **Verify:** `cargo test --locked -p qv-crypto keys && cargo test --locked -p qv-model clock`.

### Step 3 — Objects and record encryption

- [x] **Do:** `object.rs`: `ObjectEnvelope` codec (exact 5-element array,
  16/24-byte fields, profile known, ciphertext ≤ the caller's bound checked
  from the CBOR length before copying), `record_aad`, `seal_record` (new
  random `ObjectId`; `MAX_RECORD_CIPHERTEXT`) and `open_record` (role from
  the manifest; decrypted `version_id` and clock must equal the role's;
  `Integrity` otherwise). Add the budget constants to `limits.rs`.
- **Files:** `crates/qv-store/src/object.rs`, `limits.rs`, `lib.rs`.
- **Done when:** unit tests: round trip; a wrong record ID, version ID,
  object ID, generation or profile in the AAD → `Integrity`; a version whose
  decrypted clock or ID differs from the role → `Integrity`; the largest
  record plaintext seals at exactly the 1 MiB budget and one byte more is
  `LimitExceeded` (plan 0005 note: 1 MiB − 16 KiB − 4 bytes); envelope
  rejection cases (4 or 6 elements, a 15-byte ID, an unknown profile, an
  over-bound length rejected before allocation).
- **Verify:** `cargo test --locked -p qv-store object`.

### Step 4 — The manifest

- [x] **Do:** `manifest.rs`: the types and getters, the canonical encoder,
  the bounded decoder with every validation in *Data and control flow*
  (each count checked against its budget before `Vec::with_capacity`), the
  configuration digest, `reference_digest`, the manifest AAD, `seal`/`open`
  under the manifest key, the envelope encoding and streamed
  `manifest_hash`. A crate-private `ManifestBuilder` applies staged local
  changes (new record, or new head with old heads moved to history) and
  re-validates. Map `SQLITE_FULL` per *Errors* (`error.rs`, needs the
  connection to read `page_count`/`max_page_count`).
- **Files:** `crates/qv-store/src/manifest.rs`, `error.rs`, `lib.rs`.
- **Done when:** unit tests: round trip and byte-identical re-encoding;
  rejection of each of: unsorted or duplicate record, version or reference;
  a role with no reference; a reference with no role; two roles sharing an
  object; a history version not dominated by a head, or equal to a head
  clock; a history version suppressed by the floor; 0 or 257 heads; a
  control ID with no record; an unknown key; a wrong format; each budget at
  its limit (passes) and one over (`LimitExceeded`), with oversized counts
  rejected before allocation (a 5-byte CBOR header claiming 2^32 elements
  fails fast); a manifest sealed under another vault ID, generation or
  profile → `Integrity`; a test that `MAX_MANIFEST_CIPHERTEXT` ≤ the SQLite
  `LENGTH` limit; `SQLITE_FULL` at `max_page_count` → `LimitExceeded`, below
  it → `Io`.
- **Verify:** `cargo test --locked -p qv-store manifest`.

### Step 5 — Local head and the anchor

- [x] **Do:** `head.rs`: head body codec, MAC, `local_digest`, and the 0005
  §5.4 comparison as a pure function returning `AnchorStatus`. `anchor.rs`:
  `AnchorDir::{open, default_dir}`, anchor codec, bounded read
  (`O_NOFOLLOW`, regular, owner, no group/other bits), atomic replace
  (temp, fsync, rename, directory fsync), and best-effort removal for
  `create`'s failure path. Reuse `fs` helpers.
- **Files:** `crates/qv-store/src/head.rs`, `anchor.rs`, `fs.rs` (small
  shared helpers only), `lib.rs`.
- **Done when:** unit tests: the comparison table, one case each: identical
  → `Verified`; seq + 1 with the right previous digest → `Advanced`; seq + 1
  with a wrong previous digest, seq + 2, seq − 1, equal seq with another
  digest, another vault ID, a generation jump of 2 → `Mismatch`; the
  generation step (+1 seq, +1 generation, naming the old digest) →
  `Advanced`. Head MAC tamper → `Integrity`; unknown head key, `previous_digest`
  present at seq 1 or absent later, `remote_sequence` without
  `remote_checkpoint_id` → rejected. Anchor files: symlink, 0644, another
  owner (where testable), 257 bytes, an unknown key → refused;
  `default_dir` honours an absolute `XDG_STATE_HOME`, ignores a relative one
  and falls back to `$HOME/.local/state`; a group-writable anchor directory
  → `UnsafeFile`.
- **Verify:** `cargo test --locked -p qv-store head anchor`.

### Step 6 — Schema 2

- [x] **Do:** Add the four tables to `schema.rs` (DDL, `install`, the
  expected `sqlite_schema` rows including the two autoindexes), bump
  `FORMAT`/`SCHEMA_VERSION` to `0x7FFF_0002`, and add the row checks for
  `local_head`, `manifest` and `replica`. Run validation and all row reads
  of one open/unlock inside a single read transaction (`BEGIN DEFERRED` …
  `COMMIT`; plan 0008 review, finding 3). Update the module docs.
- **Files:** `crates/qv-store/src/schema.rs`, `header.rs`, `vault.rs`
  (transaction scope only).
- **Done when:** the existing schema tests pass against schema 2, plus
  tamper cases: an index on `object`, a trigger on `local_head`, a missing
  `replica` table, a renamed autoindex, a second `local_head` or `replica`
  row (via tampering), a 31-byte manifest hash, a negative `next_counter`, and
  schema version 1 → `Unsupported`.
- **Verify:** `cargo test --locked -p qv-store schema`.

### Step 7 — Create, unlock, verification and recovery

- [x] **Do:** Rework `vault.rs` per *Data and control flow*: `create` with
  `name` and `AnchorDir`, the three control records (root group named like
  the vault, default settings, the keyslot record holding the same slot
  descriptor as the local slot), the replica row, manifest, head 1, anchor
  before the rename. Add `unlock` and `unlock_for_recovery` with the full
  verification and `AnchorStatus` handling, `manifest()`, `record_kind`,
  `writer_id`, `local_seq`, `read_version` and `adopt_baseline`. Update
  `unsupported.rs` to the same API. Update the existing 1.6 tests to the new
  signatures without weakening them.
- **Files:** `crates/qv-store/src/vault.rs`, `unsupported.rs`, `lib.rs`,
  `tests/lock.rs`, `tests/tamper.rs`, `fuzz/fuzz_targets/vault_open.rs`
  (signature only).
- **Done when:** unit tests: create → unlock shows three records of the
  right kinds, `local_seq` 1, the vault name; `read_version` returns them;
  the root and keyslot records are found by the control IDs. Rejected opens
  (each with the vault byte-identical afterwards, except the documented
  `Advanced` anchor write): a deleted object row, an object row with another
  length, an object swapped with another object of the same vault, a
  manifest row deleted or replaced by an older manifest, a head MAC
  flipped, the configuration digest of another vault → `Integrity`; a
  missing anchor → `NoAnchor`; an anchor from another replica of the same
  vault → `Rollback`. `unlock_for_recovery` + `adopt_baseline` makes a
  missing-anchor vault writable with a new writer ID; without
  `adopt_baseline`, `write()` → `NoAnchor`.
- **Verify:** `cargo test --locked -p qv-store vault && cargo test --locked -p qv-store --test tamper --test lock`.

### Step 8 — The write path

- [x] **Do:** `write.rs`: `Write` per the interface and the mutation order,
  with `CrashPoint` hooks (no-ops outside tests), the pending-anchor rule,
  and the step-budget reset. `put_local` checks per *Interfaces*.
- **Files:** `crates/qv-store/src/write.rs`, `vault.rs`, `lib.rs`.
- **Done when:** unit tests: an entry created, edited twice and soft-deleted
  across four commits; reopen shows one head, three history versions, seq
  5, and `read_version` of each history version verifies hash + AEAD; a
  flipped byte in a history object → `Integrity` on read (unlock still
  succeeds; 0004 §3.6); `put_local` with an unreserved counter, a reused
  counter, a clock not dominating the head, a concurrent clock, a second
  vault-metadata record, a root soft-delete, a kind change, or a duplicate
  version ID → `InvalidEdit`, with nothing written; a dropped `Write` leaves
  seq unchanged; a head row changed behind the session → `Changed`; a
  failing anchor directory (made read-only) → `commit` returns `Io`, the next
  `write()` refuses until the directory is writable again, and a reopen
  accepts the committed change; the prune step deletes exactly the rows that
  lost their reference (checked with a test-only builder hook that drops a
  history entry).
- **Verify:** `cargo test --locked -p qv-store write`.

### Step 9 — Crash, rollback and linkage suites

- [x] **Do:** The crash harness and the tests: for every `CrashPoint` of a
  mutation and of `create`, open the snapshot and assert the expected state
  (old or new manifest, anchor status). Rollback cases: an old DB copy
  with the newer anchor → `Rollback`; a DB two commits ahead of its anchor →
  `Rollback`; a DB from another installation (another replica) →
  `NoAnchor`; two DBs forked from one state, each one commit ahead → the
  other's anchor gives `Rollback`. Linkage: after a create plus edits, scan
  the raw DB file (and any journal) for every record ID, version ID and
  attachment ID bytes → none found; the object table has exactly the five
  envelope columns. Add a `manifest_decode` fuzz target (feeds plaintext to
  the bounded decoder; asserts that accepted input re-encodes byte for byte)
  and its CI step next to the existing ones; run it 60 s locally.
- **Files:** `crates/qv-store/src/write.rs` or `src/crash_tests.rs`
  (`cfg(test)`), `fuzz/fuzz_targets/manifest_decode.rs`, `fuzz/Cargo.toml`,
  `.github/workflows/` (fuzz job).
- **Done when:** every crash point has a test with the expected outcome; the
  rollback and linkage tests pass; the fuzz run is clean.
- **Verify:** `cargo test --locked -p qv-store crash anchor rollback linkage`;
  fuzz command as in the existing CI job (local musl run with `-use_cmp=0`).

### Step 10 — Worst-case manifest, documentation and gates

- [x] **Do:** A test that generates the worst-case manifest at the maximum
  budgets with maximum-length encodings (50,000 records; 250,000 objects
  split between version objects and chunk lists to maximize bytes; exactly
  `MAX_CLOCK_COMPONENTS` components with `u64`-wide counters; maximal
  profile IDs and lengths), checks that the decoder accepts it, and asserts
  `sealed_len(encoded) ≤ MAX_MANIFEST_CIPHERTEXT`. Record the measured size
  in the execution log. If it takes more than about 10 s in the debug test
  profile, keep it in the default run anyway (it is the 0012 release-gate
  row) and log the time. Update the docs (below) and run every gate.
- **Files:** `crates/qv-store/src/manifest.rs` (test), `lib.rs` docs,
  `ARCHITECTURE.md`, `CHANGELOG.md`, `plans/0002-roadmap/PLAN.md`,
  `plans/README.md`, this plan.
- **Done when:** the worst case fits; all gates are green.
- **Verify:** `sh scripts/check-spdx.sh && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked`.

## Test plan

- Unit and property tests: object, manifest, head, anchor codecs (round trip,
  byte-identical re-encode); the anchor table; `put_local` rules; a proptest
  that random sequences of local edits over a few records keep the manifest
  valid, with each record's heads a single version that dominates its
  history, and that reopening yields the same manifest bytes.
- Rejection, malformed-input and crash-path tests: steps 3–9 list them. The
  crash harness covers every ordering point of the mutation and of `create`.
  Every tamper test asserts its exact `StoreError` variant.
- Vectors: none frozen (format unstable until 1.16). Existing qv-crypto KATs
  cover the primitives.
- Fuzzing: new `manifest_decode`; `vault_open` keeps running against schema 2.
- 0012 §1 matrix rows addressed: **Whole-file rollback** (deleted/replaced
  objects, old DB with newer anchor, crash recovery), **Anchor crash
  windows** (crash before/after the anchor write; two ahead; another
  install), **Self-referential/incomplete commitments** (missing history,
  duplicate references, wrong hash/role/configuration; manifest excludes
  itself), **Budget inconsistency** (generated worst case), **Server-visible
  record linkage** (envelope level: object columns and the DB byte scan).

## Risks and stop conditions

- **D-A and D-B are resolved** as recommended. Do not pick another budget
  value, or put writer state elsewhere, without asking.
- **Worst case does not fit:** if the generated worst case at the amended
  budget exceeds `MAX_MANIFEST_CIPHERTEXT`, stop and report the measured
  size. Do not lower budgets or change the encoding on your own.
- **Head and anchor contents:** the head and anchor field lists come from
  0005 §5.4. If the design seems to need another field in either (for
  example writer state in the head), stop. That is a spec change.
- **SQLite surprises:** if the exact-schema check cannot pin the autoindex
  rows reliably, or the hot-journal replay in the crash harness is refused by
  the 1.6 sidecar rule, stop and report. Do not loosen the sidecar rule.
- **Session size:** ten steps. If the session runs short, stop at a green
  step boundary and log where it stopped, rather than leaving a step half done.
- **Test time:** Argon2id runs stay serialized (the 1.6 mutex and fixture).
  Use one shared fixture vault per test binary and copy it, as in 1.6.
- Never weaken a test or turn an exact error variant into `is_err` to make
  it pass. No `unsafe`, no new dependency.

## Documentation

- [x] `CHANGELOG.md` — Unreleased: objects, manifests, head, anchor, write
  path; the 0004 amendment.
- [x] `ARCHITECTURE.md` — §3 "Implemented so far" (qv-store contents); §5
  unlock/write flow if it names steps that changed; the anchor location
  (private state directory) where §3/§5 mention it.
- [x] Specs — 0004 §2, §4.1, §4.2 and Changelog (step 1); status stays
  Accepted (not fully implemented: archives, sync state).
- [x] `crates/qv-store/src/lib.rs` — module table, development format,
  readings, errors, "not in this phase".
- [x] `plans/README.md` — index row; `plans/0002-roadmap/PLAN.md` — tick,
  plan number, *Revisions* (development values to freeze in 1.16: schema 2,
  manifest/head/anchor registries, labels, the anchor location) and
  *Execution log*.
- [x] `AGENTS.md` — "Current state" line for `qv-store`.

## Revisions

- 2026-10-26: Approved by the owner, D-A and D-B as recommended ("I'll trust
  your judgement on these"). The plan amends 0004, so roadmap standing
  approval did not apply.

## Execution log

- 2026-10-26: Approved by the owner (D-A, D-B as recommended); status In progress.
- 2026-10-26: Step 1 done. 0004 §2 gains the `replica` row, §4.1 the 1,048,576 clock-component budget, §4.2 the sentence that it bounds the worst case and that history yields to it; Changelog line. Status stays Accepted.
- 2026-10-26: Step 2 done. `LocalState` is a `MacKey` (doc updated; test: its MAC differs from the header-MAC key's and does not verify a header-MAC tag). `Clock::encode`/`Clock::decode` wrap the existing codec; test embeds a clock in a container and rejects 257 writers, a zero counter and unsorted writers through the public functions. (The decoder validates the whole input first, so the 257-writer case is a complete array, not a bare header.)
- 2026-10-26: Step 3 done. `object.rs`: `ObjectEnvelope` (public, redacted `Debug`, oversized input refused before parsing and before copying), `Scope`, `record_aad`, `seal_record`, `open_record` (role from the manifest; decrypted version ID and clock must match). Budget constants in `limits.rs`, re-exported. Plan correction: at the 1 MiB budget the largest record ciphertext is 1 MiB − 16 KiB + 16 bytes (Padmé's 16 KiB step plus the tag), not 1 MiB; the plaintext ceiling 1 MiB − 16 KiB − 4 from plan 0005 is right, and the test pins both and the one-byte-over rejection, using an entry (a group name is capped at 256 KiB). The profile-in-AAD test seals under a hand-edited AAD, since only V1 exists. `manifest` and `object` carry a temporary `#[allow(dead_code)]` in `lib.rs` until step 8.
- 2026-10-26: Step 4 done. `manifest.rs` per the plan's format table: types with getters, encoder, bounded decoder (every array length checked against its budget before `Vec::with_capacity`, running version and clock-component totals while decoding), `validate` (shared by decode and by sealing, so an invalid manifest is never sealed), configuration digest, `reference_digest`, AAD, `seal_manifest`/`open_manifest`, the streamed `envelope_hash` (tested equal to hashing the full canonical envelope at each byte-string head size), and the crate-private `add_record`/`replace_heads`/`remove_history`. Unknown manifest keys and formats → `Unsupported`, missing keys and structural faults → `Integrity`, budgets → `LimitExceeded`. `sqlite::MAX_LENGTH` is now `pub(crate)` for the length-limit test. `error.rs`: `write_err`/`full_err` map `SQLITE_FULL` to `LimitExceeded` only when the write would reach `max_page_count` (64 pages of slack), else `Io`; a real page-limit test and pure cases. Callers adopt it in steps 7–8.
- 2026-10-26: Step 5 done. `head.rs` (platform-independent): `LocalHead` codec (key 3 absent iff seq 1; keys 5/6 together; unknown keys `Unsupported`), MAC over `["qv/local-head/v1", body]`, `local_digest`, `compare` → `AnchorStatus`; `Anchor` and the public `AnchorStatus` live here so `unsupported.rs` can name them. `anchor.rs` (Linux/Android): `AnchorDir::{open, default_dir}`, codec, bounded `O_NOFOLLOW` read with owner/mode checks, atomic replace (O_EXCL temp, fsync, rename, directory fsync, with the two anchor crash points), best-effort removal. `fs.rs` gains `is_owner_only` and `check_private_dir` (lstat: a symlinked directory is refused). Plan correction: `cargo test -p qv-store head anchor` passes two positional filters, which cargo rejects; the working form is `cargo test -p qv-store -- head anchor` (also for steps 9's verify line). "Another owner" for anchor files is not testable without root; the check is the same `owner_only` as for vault files.
- 2026-10-26: Step 6 done. Schema 2 per the plan's DDL; the exact-schema check expects the two `sqlite_autoindex_*` rows with NULL SQL. `FORMAT`/`user_version` = `0x7FFF_0002`. `read_rows` now also shape-checks the three singleton rows (counts, types, lengths; no values), and `read_state`/`read_head`/`read_replica` read them for unlock and writes; object rows through `ObjectReader` (statements prepared once: rusqlite's statement cache needs a feature that is not enabled, and enabling it would be a dependency change). Open runs schema validation and row reads in one read transaction, unlock runs its whole verification in another (review 0008 finding 3); a cooperating writer cannot change rows between the two because of the `flock`. New unit tamper cases for the new tables. The integration tamper test failed between steps 6 and 7 (create did not write the new rows yet), as expected; step 7 fixed it.
- 2026-10-26: Step 7 done. `vault.rs`: `create(path, password, name, anchors)` builds header, slot, `replica` row (counters 1–3 used by the root group, vault metadata and keyslot record; the keyslot record holds the local slot's descriptor bytes, root group named like the vault), manifest and head 1 in one transaction, fsyncs, writes anchor 1, renames with no-replace, then reopens through the unlock verification (`Verified` required, else `Internal`). On failure before the rename the temp file, its journal and the new anchor are removed. `unlock` = `unlock_for_recovery` with `Missing` → `NoAnchor`, `Mismatch` → `Rollback`; `Advanced` replaces the anchor before returning. `load_state` follows the plan's unlock order (head MAC before parsing; manifest hash from the stored columns; profiles must be accepted by the header minimum, else `Unsupported`; every reference's row profile and length; every head decrypted with its role, one kind per record, chunk lists against `attachment_meta`, root `check_root`, vault metadata naming the root; control kinds exactly on the control IDs). New errors `Rollback`, `NoAnchor` (exit 7), `Changed` (exit 6), `InvalidEdit` (exit 1). A bad vault name is `InvalidEdit`. `unsupported.rs` mirrors the whole API, including uninhabited `AnchorDir` and `Write`. Tests: create/unlock contents, wrong password, header MAC, slots under the MAC, another vault's slot, ten SQL tampers of objects, manifest, head and replica plus an object swap (each `Integrity`, file byte-identical), hostile manifests re-sealed under the right key with a valid head MAC (another vault's configuration digest, control IDs swapped two ways → `Integrity`; the unchanged re-seal → `Rollback`, which shows the failures come from the change), old DB with newer anchor → `Rollback`, no anchor → `NoAnchor`, recovery + `adopt_baseline` (new writer, seq 2, then writable). One fix during testing: the "flip a byte" tamper first set byte 0 to `0x00`, a no-op 1 time in 256; it now always changes the byte. `Manifest::decode`/`encode` became public for the fuzz target (step 9), a small API addition beyond the sketch.
- 2026-10-26: Step 8 done. `write.rs`: `write()` (gate, pending-anchor retry, identity, `BEGIN IMMEDIATE`, head and replica re-read → `Changed`), `reserve_counter`, `head_clocks`, `put_local` (all checks before any write; a failed insert poisons the `Write`), `commit` (seal with budgets, manifest row swap, head, replica writer/counter, prune by reference diff, `COMMIT`, session update, anchor), `adopt_baseline` (a no-edit commit under a new writer ID), `Drop` rolls back. The anchor error after a durable commit is returned as is (the read-only-directory test sees `Io`, as the plan expected). Attachments: `put_local` refuses an `attachment_meta` whose chunks are not already referenced (chunks come in 1.11). Tests: four commits (create, two edits, soft delete) → one head, three history versions, seq 5, counters 4–7, seven objects; a flipped history byte → unlock succeeds, that read `Integrity`; every `put_local` rejection (unreserved counter, non-dominating clock, another writer's clock, second vault metadata, metadata naming another root, root soft-delete, kind change, duplicate version ID, reused counter, second edit of a record) → `InvalidEdit` with nothing written; changed head or counter row → `Changed`; read-only anchor directory → `Io`, next `write()` refused, reopen `Advanced`, later retry in-session succeeds; prune removes exactly the dropped history object; a dropped `Write` and an empty commit. The non-dominating case first passed for the wrong reason (one writer always dominates); its base head now carries a second writer's component.
- 2026-10-26: Step 9 done. `crash.rs` (points; the test hook copies vault, journal and anchor directory, then fails with `Internal`) and `crash_tests.rs`: every mutation point gives the planned state and anchor status, and an ordinary unlock works afterwards; both create points leave no vault at the path (an orphan anchor only after `CreateAnchored`) and clean up. Finding: at the small transactions' pre-commit points the snapshot holds a journal that is not hot (SQLite has not written the vault yet), so SQLite ignores it; the test asserts that, and `crash_spilled_transaction_rolls_back` adds a 4.8 MB transaction that spills the page cache, leaves a hot journal and a changed vault file, and opens to the old state with the journal rolled back. Rollback: two commits ahead → `Rollback`; forked copies → `Rollback`; old copy with newer anchor → `Rollback`; another installation → `NoAnchor`. Linkage: no record or version ID bytes anywhere in the DB file (or journal) during and after a session, the vault ID found as a control; the object table has exactly the five envelope columns. `fuzz/fuzz_targets/manifest_decode.rs` plus its CI step; local runs on musl (`-s none`, `-use_cmp=0`): `manifest_decode` 60 s, 34,787,021 runs, clean; `vault_open` re-run 60 s, 1,540,145 runs, clean. Found, not fixed: without a seed corpus the manifest fuzzer reaches few accepted manifests (coverage 209); a seed corpus is a 1.16 extended-campaign item.
- 2026-10-26: Step 10 done. `manifest_worst_case_fits_the_limit`: 50,000 records × 5 versions = 250,000 version objects (each costs more manifest bytes than a chunk), exactly 1,048,576 clock components with 9-byte counters, 15,000 references of 65,536 bytes and the rest 256 bytes (1,043,200,000 bytes in total): **52,391,657 bytes plaintext, 52,428,816 sealed** against 67,108,864; decodes back; one more component is `LimitExceeded`. 5.5 s in the debug test profile. Added the planned property test (`write_random_edits_round_trip`, 6 cases because each runs Argon2id twice). Docs: `lib.rs` crate docs, `CHANGELOG.md`, `ARCHITECTURE.md` §3 and §6 (anchor location), `AGENTS.md` current state; 0004 stays Accepted (archives and sync state are not implemented). Gates: SPDX, `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (all green, see the final entry). No dependency change (`Cargo.lock` and `fuzz/Cargo.lock` unchanged; `cargo fetch --locked` on the fuzz crate passes), so `cargo deny`/`cargo vet` were not re-run.
  Found, not fixed: (1) Each `write()` clones the in-memory manifest (up to ~50 MB of IDs and clocks at the budgets); 1.8 or 1.16 can make staging incremental if benchmarks need it. (2) Unlock decrypts every head to verify it and drops the plaintext; 1.8 may build its views in the same pass. (3) Stale anchor files of deleted vaults are never removed; harmless, a possible 1.10 nicety. (4) `adopt_baseline` re-seals an unchanged manifest (new nonce, new hash) as an ordinary commit; intended. (5) The `SQLITE_FULL` classification reads the page count after the failure and uses 64 pages of slack: best effort. (6) The Android branch of `check_private_dir` (own-GID directory) is compiled only on Android, which is not installed here.
- 2026-10-26: Reviewed ([REVIEW.md](REVIEW.md)): Approved with minor fixes. `adopt_baseline` now retries a pending anchor update first (the DB could get two commits ahead of its anchor); new test. Two low findings carried into 1.8 (`Debug` on manifest types) and 1.10 (anchor directory next to the vault). Status `Reviewed`.
