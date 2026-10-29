# Plan 0022 — Verified rotation replacement and snapshot inventory (roadmap 1.15b)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-29 | 2026-10-29 (standing approval, roadmap 0002) | 0002 §2.2, §3.2–3.5; 0003 §2, §6; 0004 §1–6; 0005 §1, §5.4 (D5); 0007 §1–3; 0008 §1–3, §5 (D5); 0012 §1 |

## Intent

Continue offline VK rotation after the reviewed foundation (plan 0021). This
phase builds and fully verifies the private replacement database of a new key
generation. It also builds the authenticated inventory that keeps snapshots
of earlier generations under the snapshot budgets. Nothing is installed here.
Publishing the journal, the rename sequence, advancing the anchor, restart
recovery, the core lifecycle and the CLI are roadmap 1.15c.

## Scope

**Revision 2026-10-29 (session-size split):** the remaining 1.15b work from
plan 0021 (replacement, snapshot inventory, installation/restart, core, CLI and
crash evidence at every journal step) needs about 12 steps. That is past the
roadmap's 8–10 step split rule. It is split at the point where something is
first published:

- **1.15b (this plan):** everything that must exist and be verified *before*
  a journal is published. No production caller yet.
- **1.15c (next fresh session, after review of this plan and an owner
  commit):** install with the journal, restart (complete or roll back),
  advance the anchor across generations, release the pin, make snapshot
  policy use the inventory, the core `Rotation` lifecycle, `recovery rotate`,
  crash injection at every journal step, and the whole-rotation *Done when*
  criteria of roadmap 1.15.

**In scope:**
- Reserved rotation file names: ordinary open/create/restore refuse any vault
  path whose file name contains `.qvrotate`. An orphaned replacement or a
  retained old copy can then never be unlocked ordinarily, which would advance
  the shared anchor.
- `UnlockedVault::prepare_rotation` → `PreparedRotation`:
  - check preconditions;
  - generate a new VK, generation, password slot and phrase;
  - reencrypt every retained object under new object IDs while preserving
    logical IDs, clocks and floors;
  - add one causal keyslot edit;
  - write a new head at generation +1 and sequence +1 that names the old head
    digest;
  - commit to a private file with a reserved name;
  - reopen it hardened, unlock its new password slot, verify everything and
    compare it with the source.
- Cancellation and drop cleanup. The source vault file and every anchor stay
  byte-identical.
- `SnapshotInventory`: a bounded canonical codec MAC'd with the new
  generation's local-state key. `SnapshotDir` operations build it from
  earlier generations' snapshots (authenticated with the old VK and the
  previous inventory), publish it, read and verify it, and remove a hashed
  entry. Plus a fuzz target and an independent vector.

**Out of scope:**
- Writing a journal, renames, installation, anchor advancement, restart or
  rollback, and deleting the retained old database (1.15c).
- Taking or pinning the mandatory recovery snapshot (core, 1.15c), and using
  the inventory in snapshot policy (1.15c).
- Any core, CLI, server, LAN or quick-unlock work. Salvaging old-generation
  edits. Compatibility migration of development vaults. Profile changes.
- Cleaning up orphaned replacements left by a crash. They are inert because of
  the reserved-name rule; 1.15c's rotate/resume flow removes them explicitly.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| New VK, generation +1, phrase, password slot; recovery public keys deferred offline | 0002 §3.5.1 (amended 2026-10-29) | Accepted | Seeds are independent derivations of the new VK (§3.3); nothing extra is stored |
| Private replacement: all active versions, conflicts, retained history and chunks, tombstones, floors; reencrypted; IDs and clocks preserved; full manifest verified; replacement-password unlock before publication | 0002 §2.2, §3.5.2 | Accepted | Phrase confirmation is the frontend's job in 1.15c |
| Purpose keys, record/attachment keys, password slot AAD and KEK commitment | 0002 §3.2, §3.3, §3.6 | Accepted | Existing qv-crypto APIs only |
| Head generation step: generation +1, `local_seq` +1, `previous_digest` = old digest | 0005 §5.4 | Draft, D5 | `head::compare` already accepts it; that is why the replacement must never reach an ordinary unlock before installation |
| Causal edit for the keyslot change | 0005 §1.2–1.3 | Draft, D5 | Same rule as `passwd` |
| Storage layout, hardening, budgets, atomic owner-only files | 0004 §1–5 | Accepted | Existing schema; no DDL change |
| Snapshot budgets, recovery copy, ordinary pruning | 0007 §3.1–3.3 | Accepted | Inventory makes old-generation copies countable (consumer in 1.15c) |
| History and floors preserved, no incidental pruning | 0007 §1 | Accepted | |
| Secret containers, files, no secrets in errors or Debug | 0008 §1–3, §5 | Draft, D5 | |
| Matrix rows | 0012 §1 | Accepted | Migration coupling (data part); Rotation/purge ambiguity (replacement part); Hostile SQLite/CBOR (inventory parser); Whole-file rollback (reserved names) |

**Spec changes required:** None. The only normative amendment for rotation
(0002 §3.5.1, plan 0021 D1 A) is already applied. The keyslot edit reading
and the inventory are development formats and behaviour inside the cited
requirements. Phase 1.16 records them for the freeze.

## Decisions needed

None. The design choices are resolved below under existing requirements and
the owner-approved design context in plan 0021 (approved with "use best
judgment"):

- **Keyslot record.** The replacement's keyslot record gets one new causal
  version. It copies the previous head payload with `slot` replaced by the
  new descriptor, its clock is `Clock::for_edit` over the heads with the
  retained writer and next counter, and it has a fresh version ID. This is
  exactly how `passwd` stages it (`Write::stage_password`). The previous head
  becomes history. Plan 0021 retained historical descriptors and did no
  incidental retention pruning; this plan does the same. Every existing
  version keeps its ID, clock and content. Reason: no version ID ever carries
  two payloads, and archives and restores of the new generation read the
  correct descriptor from the keyslot head (`restore.rs`). Historical
  descriptors wrap only the old VK, so they cannot unwrap the new one.
- **Inventory file per generation** (`inventory-<vault id>-<generation>.qvinv`).
  Publishing generation g+1's inventory therefore never replaces generation
  g's, and a 1.15c rollback just removes the new file.
- **No separate `verify_password` call.** `prepare_rotation` itself unlocks
  the persisted replacement slot with the supplied new password, before it
  returns. This meets 0002 §3.5.2 with one KDF run fewer. 1.15c may ask for
  the password again if its CLI contract wants that.

## Design

**Components touched:** `qv-store` only (trusted client; it parses its own
SQLite only after hardening and authentication). New modules:
`rotation.rs` (replacement), `snapshot_inventory.rs` (codec and SnapshotDir
operations), and `creation.rs` (database creation helpers shared by restore
and rotation). `rotation_guard.rs` gains the reserved-name rule. The
`unsupported.rs` stubs gain matching fail-closed items. Also a new fuzz
target and vector. No new crate, dependency, profile, SQL schema or
`unsafe`.

**Interfaces:**

```rust
// qv-store/src/rotation.rs (Linux/Android; `unsupported` fails closed).
/// A verified, unpublished replacement of a new key generation. Owns the
/// still-locked source vault and the locked replacement file. No Clone; Debug
/// is "PreparedRotation(<redacted>)"; nothing returns a key or a path.
/// Dropping it removes the replacement (and its `-journal`) best effort.
/// The source file and every anchor are unchanged.
pub struct PreparedRotation { /* source: UnlockedVault, new_vk: VaultKey,
    replacement: UnlockedVault (role Candidate), suffix: [u8; 16],
    phrase: RecoveryPhrase, temp: PathBuf */ }

impl UnlockedVault {
    /// Consumes the session. On error the source is dropped unchanged; a
    /// caller unlocks again. Runs the password KDF twice (create and
    /// reauthenticate the new slot).
    pub fn prepare_rotation(
        self,
        new_password: &MasterPassword,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PreparedRotation, StoreError>;
}

impl PreparedRotation {
    /// The new generation's phrase (protected memory) for confirmation.
    pub fn phrase(&self) -> &RecoveryPhrase;
    /// The new key generation (old + 1).
    pub fn new_generation(&self) -> KeyGeneration;
    // pub(crate) accessors for 1.15c: source, replacement, new_vk, suffix,
    // old/new local digests and sequences. Not public API.
}

// qv-store/src/snapshot_inventory.rs
pub const MAX_INVENTORY_BYTES: usize = 1024 * 1024;
pub const MAX_INVENTORY_ROWS: usize = 4096;

/// One snapshot of an earlier generation of this vault. Not secret: the
/// archive ID is what `snapshot ls` prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryRow {
    pub archive_id: [u8; 16],
    pub generation: KeyGeneration,   // 1 ≤ generation < inventory generation
    pub created_at: Timestamp,       // from the header authenticated by that generation
    pub size: u64,                   // file size when hashed
    pub sha256: [u8; 32],            // streamed SHA-256 of the whole file
}

/// A verified inventory for one vault ID and generation. Rows sorted by
/// archive ID, unique. Debug prints counts only.
pub struct SnapshotInventory { /* vault_id, generation, rows */ }
impl SnapshotInventory {
    pub fn generation(&self) -> KeyGeneration;
    pub fn rows(&self) -> &[InventoryRow];
    pub(crate) fn sign(..., new_vk: &VaultKey) -> Result<Self, StoreError>;
    pub fn encode(&self) -> Result<Vec<u8>, StoreError>;
    /// Cap before decoding; then the strict structure. Untrusted until `verify`.
    pub fn decode(input: &[u8]) -> Result<UnverifiedInventory, StoreError>;
}
/// Decoded but not yet authenticated. `verify` is its only use.
pub struct UnverifiedInventory { /* ... */ }
impl UnverifiedInventory {
    pub fn verify(self, vault_id: VaultId, generation: KeyGeneration, vk: &VaultKey)
        -> Result<SnapshotInventory, StoreError>;
}

impl SnapshotDir {
    /// Builds the inventory that carries snapshots of generations ≤ g into
    /// g+1 (see the build rules below). Verifies, never writes.
    pub fn prepare_inventory(&self, rotation: &PreparedRotation,
        cancelled: &dyn Fn() -> bool) -> Result<SnapshotInventory, StoreError>;
    /// Publishes atomically under its generation's name. Never replaces an
    /// existing name (`Exists`). Returns the SHA-256 of the file bytes (the
    /// journal's `inventory_digest` in 1.15c).
    pub fn publish_inventory(&self, inventory: &SnapshotInventory)
        -> Result<[u8; 32], StoreError>;
    /// The current generation's inventory: None if absent; Integrity if it
    /// does not verify. Size checked by fstat before reading.
    pub fn inventory(&self, vault: &UnlockedVault)
        -> Result<Option<SnapshotInventory>, StoreError>;
    /// Removes the snapshot file of a verified row only if its streamed
    /// SHA-256 and size match. NotFound if absent; Integrity if different.
    pub fn remove_inventoried(&self, vault: &UnlockedVault, row: &InventoryRow,
        cancelled: &dyn Fn() -> bool) -> Result<(), StoreError>;
    // pub(crate) fn remove_inventory(&self, vault_id, generation) for 1.15c.
}
```

Names may follow local conventions. The contracts, ownership and bounds above
are fixed.

**Reserved names (step 1).** `rotation_guard::check(path)` also refuses a
path whose file name contains `.qvrotate`, as Integrity (exit 7, an
interrupted or partial transition). Because `check` already runs in `open`,
`open_locked`, `create`, `create_from_archive` and `check_identity`, every
ordinary entry point is covered. `create`/restore refuse that name before
any other work. The replacement's `VaultFile` has a crate-private role
`Candidate`, which only `rotation.rs` constructs:
- its `check_identity` skips only the reserved-name test (marker test and
  inode identity remain);
- its `begin()` (so `write`, `adopt_baseline` and credential staging) always
  fails with Integrity;
- it is never passed to `finish_unlock`, which loads and advances anchors.

**Replacement (steps 2–3), in order:**

1. `check_identity`, then `finish_pending_anchor` (an ordinary pending-anchor
   retry). Then require `gate == Open`, else return the blocking error.
   Require `head.remote.is_none()` (else Unsupported: remote rotation is
   phase 3.8). Require exactly one head for each of the three control
   records (else InvalidEdit; 1.15c core maps it to Conflict, exit 8).
2. Check `generation + 1` (u32), `local_seq + 1` and `next_counter < MAX_COUNTER`
   (i64 bound in `write.rs`) for overflow before any KDF or I/O; overflow is
   LimitExceeded.
3. `verify_all(cancelled)` on the source (complete authentication of
   history and attachments). Then `begin_read()`, which re-checks head and
   replica. Every source read below happens inside that one read
   transaction, and it ends before return.
4. Generate: new VK; new header = source header with
   `key_generation = g+1` (same vault ID, profiles and minima); a new
   `SlotId`; `PasswordSlot::create(new_password, new_vk, vault_id, g+1, …,
   V1, V1)` (the profiles of the current registry); the phrase
   `RecoveryPhrase::from_vault_key(&new_vk)`; a random 16-byte suffix.
5. Replacement path: `fs::create_temp(<vault>.qvrotate-new-<32 hex suffix>)`
   (exclusive, no-follow, 0600, locked). The final reserved name is used only
   by 1.15c's install step 1.
6. Object map: walk the source manifest's references in sorted order.
   - Each **record object** has exactly one role, found from the manifest
     versions (heads and history). Read it with `read_role(..., check_hash =
     true)`. If it is an attachment-metadata version, remap its
     `chunk_object_ids`. Reseal it with `seal_record` under the new keys and
     scope (a fresh object ID and nonce).
   - Each **chunk** is opened with the source attachment key of its record
     at its index (`attachment::aad`, `open_chunk`). Hash and length are
     checked as in `read_attachment`. It is resealed with
     `seal_chunk` under the new attachment key and a fresh object ID at the
     same record and index. `Manifest::validate` already requires that every
     reference is used by exactly one role (record object or chunk), so the
     map is a bijection: no chunk is shared between versions.
   - Keep one `BTreeMap<old ObjectId, new ObjectId>` (≤ `MAX_OBJECTS`) and
     check that every new ID is fresh and not present in the old set.
   - Plaintext lives only in `SecretBytes`/zeroizing buffers for one object
     at a time. Check cancellation between objects.
   - Insert every sealed object with `key_generation = g+1` into the
     replacement inside its single creation transaction.
7. Manifest: add a crate-private `Manifest::remapped(&self, header_new,
   map, new_refs)`. It keeps the record order, heads, history, floors,
   version IDs, clocks and conflicts. It replaces every `VersionRef`
   object/chunk ID and the reference list, and recomputes the config digest
   for g+1. It validates: an unmapped ID is Internal. Then the keyslot edit
   with `replace_heads` (old head → history). Then `seal_manifest`; its
   budgets are checked, and exceeding them is LimitExceeded.
8. Head: `{vault_id, g+1, local_seq + 1, previous_digest = Some(source
   digest), manifest_hash, remote: None}`, signed with the new local-state
   key. Replica row: the same `replica_id` and `writer_id`, and
   `next_counter = old + 1`. Header MAC over the new header and the new
   password slot row.
9. Build: extract the shared part of `restore::build` into
   `creation::write_database(conn/temp, header body+tag, slot, replica row,
   objects, sealed manifest, head)`. It uses one `open_connection` +
   `harden` + `page_size` + `schema::install` sequence. Restore and rotation
   both use it, and restore behaviour and its tests stay unchanged. Commit,
   close, fsync the file (the lock's `sync`).
10. Persisted verification: reopen the locked file hardened as role
    `Candidate`, with the same open checks as `open_locked`. Unlock the slot
    with `new_password` (WrongPassword is impossible unless the file is
    damaged: report Integrity). `verify_header` with the slot-unwrapped key.
    Load the state in a read transaction. Run the full `verify_all` on the
    Candidate `UnlockedVault` (gate Blocked(Integrity); `anchors` is the
    source's directory, never touched). Compare:
    - the manifest equals the step 7 manifest exactly;
    - for every source version role, the replacement's decrypted version
      equals the source version, with only `chunk_object_ids` remapped;
    - exactly one extra keyslot version (the edit), and the keyslot head
      payload equals the staged descriptor;
    - every attachment's plaintext streams to the same content hash and
      length (`read_attachment` into a hashing sink, compared in constant
      time with the source's).
    Any difference is Integrity.
11. End the read transaction and return `PreparedRotation`. On any error,
    cancellation (Io) or a crash point, remove the replacement and its
    `-journal` best effort. The source, its sidecars and the anchor
    directory stay byte-identical.

**Inventory (steps 5–6):**

- **Wire** (canonical CBOR map, development values):
  - 0 format = 1;
  - 1 vault ID (bstr 16, UUIDv4);
  - 2 generation (uint, u32, ≥ 2);
  - 3 rows (array ≤ 4096 of 5-arrays `[archive_id bstr16, generation uint,
    created_at int, size uint, sha256 bstr32]`, strictly ascending by
    archive ID);
  - 4 MAC (bstr 32).

  The MAC is MAC/1 with the generation's local-state purpose key over
  canonical `["qv/snapshot-inventory/v1", body]`, where body is the encoded
  map of keys 0–3 (the same construction as `RotationJournal`). Check the
  input cap (1 MiB) before decoding and the row count before allocating.
  Reject unknown keys, format, noncanonical or trailing data, a row
  generation 0 or ≥ the inventory generation, duplicate or unsorted IDs,
  and negative or out-of-range integers. MAC verification is
  constant-time.
- **File:** `inventory-<32 hex vault id>-<8 hex generation>.qvinv` in the
  snapshot directory. It is not a snapshot name, so `entries()` ignores it.
  To publish: `check_private_dir`, `create_temp`, write, fsync, re-read and
  verify, `rename_noreplace`, fsync the directory. To read: open no-follow,
  owner-only regular file, cap by fstat before reading.
- **prepare_inventory build rules** (old generation g, VK_g from the
  prepared source; new VK for the MAC):
  1. If an inventory of g exists, it must verify with VK_g (else Integrity,
     which aborts rotation fail-closed). Carry each of its rows whose file
     (by archive ID, either kind prefix) exists and still has the same
     streamed SHA-256 and size. Drop the others; dropped rows are never a
     reason to delete anything.
  2. Every entry whose header authenticates with
     `ArchiveScope(vault_id, g)` and VK_g (`read_header`) becomes a row
     with generation g, its authenticated `created_at`, its size and its
     streamed SHA-256. Entries that do not authenticate are ignored, as the
     current policy does.
  3. Rows are unique by archive ID. A g-authenticated row supersedes a
     carried row with the same ID. More than 4096 rows is LimitExceeded.
     Hash files in bounded buffers, checking cancellation between buffers
     and files.
  4. Sign with the new VK at generation g+1.
- **remove_inventoried:** find the file by archive ID with either prefix,
  stream its hash and size, compare in constant time, then remove it and
  fsync the directory. The row is only a hint until that match.

**Data and control flow:** nothing in this phase publishes vault state. The
creation transaction is private to an unpublished reserved name. A crash
leaves only that inert file (ordinary open refuses it, and its anchor was
never written) or an inventory temp file. The durability ordering of plan
0009 is unchanged. 1.15c alone publishes, using the reviewed journal.

**Secrets and hostile input:**
- `new_password`, `MasterPassword`, `VaultKey`, `PasswordSlot` internals,
  `RecoveryPhrase` and all plaintext record/chunk buffers stay in
  qv-crypto containers or zeroizing buffers.
- No secret is logged or put in an error. `PreparedRotation`,
  `SnapshotInventory` and `UnverifiedInventory` have redacted or count-only
  Debug.
- The replacement is trusted output, but it is still verified from persisted
  bytes through the hardened reader.
- The inventory is hostile local state: bounded, then MAC-verified, before
  its rows influence anything. Inventory rows never make paths: file names
  are formatted only from the 16-byte ID.

**Errors:** existing `StoreError` only. A reserved name or a marker is
Integrity. Remote state is Unsupported. Control conflicts and staging rule
breaches are InvalidEdit. Overflow and budgets are LimitExceeded. Cancellation
and I/O are Io. A disk full during build is Io or LimitExceeded, as the
existing SQLite mapping reports it.

**Dependencies:** None.

## Steps

### Step 1 — Reserved rotation names

- [x] **Do:** extend `rotation_guard::check` with the reserved-name rule and
  add the crate-private file role. Store tests: open, open_locked, create,
  restore and an existing session's `check_identity` all refuse names
  containing `.qvrotate`. An ordinary `.qvault` still works.
  The CLI credentials test gets one case: opening a `v.qvault.qvrotate-new-…`
  copy of a vault is exit 7, and the anchor files stay byte-identical.
- **Files:** `crates/qv-store/src/{rotation_guard,vault}.rs`;
  `crates/qv-cli/tests/credentials.rs`.
- **Done when:** refusal happens before SQLite, anchor or output work; all
  existing tests pass.
- **Verify:** `cargo test --locked -p qv-store rotation_guard`;
  `cargo test --locked -p qv-cli --test credentials`.

### Step 2 — Shared creation helper and replacement build

- [x] **Do:** add `creation.rs` and move restore's database-writing body
  into it. Implement `rotation.rs` steps 1–9 above: preconditions, overflow
  checks, keys/slot/phrase, the object map with record and chunk
  reencryption, `Manifest::remapped`, the keyslot edit, head and replica, the
  build. Add `unsupported.rs` stubs and lib exports.
- **Files:** `crates/qv-store/src/{creation,rotation,restore,manifest,lib,unsupported}.rs`.
- **Done when:** restore tests are unchanged and green; the replacement builds
  from the shared fixture vault with history, floors, a tombstone and
  multi-chunk attachments. Manifest validation shows no history-count
  limit, so the extra keyslot history version needs no retention run.
- **Verify:** `cargo test --locked -p qv-store restore`;
  `cargo test --locked -p qv-store rotation`.

### Step 3 — Persisted verification and lifecycle

- [x] **Do:** do the Candidate reopen, the slot reauthentication, the full
  verification and the logical comparison (step 10), plus `PreparedRotation`
  accessors, drop cleanup and redacted Debug.
- **Files:** `crates/qv-store/src/{rotation,vault,verify,attachment}.rs` (only
  what is needed to run the existing passes on a Candidate).
- **Done when:** the comparison passes for valid builds. A deliberately
  corrupted test-only build (one wrong object row, a wrong chunk remap) is
  Integrity, and nothing is left behind.
- **Verify:** `cargo test --locked -p qv-store rotation`.

### Step 4 — Replacement evidence

- [x] **Do:** add tests named `rotation_replacement_*`:
  - **preservation:** heads, history, floors, conflicts (a crafted multi-head
    entry), final tombstones, unknown extension fields and attachment
    history versions (one chunk list per version);
    every object ID and nonce is fresh; every object row has generation g+1;
    the head is gen+1, seq+1 and names the old digest; the replica and
    writer IDs are retained; the counter is +1; the keyslot is a dominating
    causal edit; the old head is in keyslot history.
  - **credentials:** the new password unlocks the replacement and the old
    password does not; the new phrase key verifies the header and the old
    phrase does not (crate-internal path).
  - **source and anchors:** the source file, its sidecars and the anchor
    directory stay byte-identical through success, drop, every refusal,
    every cancellation and failure point; the replacement is gone after drop
    and error; an orphaned replacement copied out before drop is refused by
    ordinary open and leaves anchors unchanged.
  - **refusals:** anchor Missing/Mismatch, a pending anchor (retried first),
    a marker, remote state, multi-head control records, generation
    `u32::MAX`, `next_counter` at the maximum, and Changed (head replaced
    between unlock and prepare).
  - **failure injection:** a test-only fault between objects and before
    commit cleans up.
  - **property test:** proptest of random edit/history/attachment/delete
    sequences; the preservation invariants hold.
- **Files:** `crates/qv-store/src/rotation_tests.rs` (test module), and
  fixtures via the existing `verify_tests::setup`.
- **Done when:** every listed case passes and each asserts byte-identical
  source and anchors where it applies.
- **Verify:** `cargo test --locked -p qv-store rotation_replacement`.

### Step 5 — Inventory codec, vector and fuzz target

- [x] **Do:** implement `snapshot_inventory.rs` codec, `sign`, `decode` and
  `verify` with rejection tests:
  - every prefix and every byte mutation;
  - keys 0–4: missing, null, wrong type, unknown;
  - format 2;
  - row bounds: 4096 accepted, 4097 refused;
  - unsorted and duplicate rows; row generation 0 or ≥ the inventory
    generation;
  - over 1 MiB refused before decoding;
  - wrong key, generation and vault;
  - Debug redacted.

  Add `tests/vectors/snapshot_inventory.py` (stdlib CBOR/HKDF/HMAC, public
  BIP-39 vectors) and its `.cbor` fixture, compared by a Rust test. Add the
  fuzz target `snapshot_inventory` (raw bytes plus mutation of a valid seed;
  an accepted input reencodes identically; mutated bytes never verify), its
  Cargo entry and a 60 s CI step.
- **Files:** `crates/qv-store/src/{snapshot_inventory,lib}.rs`,
  `crates/qv-store/tests/vectors/{snapshot_inventory.py,snapshot-inventory.cbor}`,
  `fuzz/Cargo.toml`, `fuzz/fuzz_targets/snapshot_inventory.rs`,
  `.github/workflows/ci.yml`.
- **Done when:** codec tests and the vector pass; fuzz formatting and the
  locked build pass; a local 60 s campaign has no finding.
- **Verify:** `cargo test --locked -p qv-store snapshot_inventory`;
  `python3 -I crates/qv-store/tests/vectors/snapshot_inventory.py`;
  `cargo fmt --check --manifest-path fuzz/Cargo.toml`;
  `cargo build --locked --manifest-path fuzz/Cargo.toml --bin snapshot_inventory`;
  campaign as in plan 0021's log (pinned nightly in CI).

### Step 6 — Inventory directory operations

- [x] **Do:** implement `prepare_inventory` (build rules 1–4),
  `publish_inventory`, `inventory`, `remove_inventoried` and crate-private
  `remove_inventory`. Tests named `snapshot_inventory_dir_*`:
  - generation-g snapshots and carried rows included;
  - another vault's files ignored, as are damaged files and those of other
    generations;
  - changed and missing files dropped from carried rows;
  - a damaged previous inventory is Integrity;
  - 4097 rows is LimitExceeded;
  - publication is atomic, refuses an existing name, never touches snapshot
    files and survives a re-read;
  - publication of g+1 leaves g's file intact;
  - `remove_inventoried` deletes only a matching file; a replaced or
    differently sized file is Integrity and kept; absent is NotFound;
  - symlinks, non-owner-only files and oversized inventory files are refused;
  - cancellation leaves no published file.
- **Files:** `crates/qv-store/src/{snapshot_inventory,archive}.rs`.
- **Done when:** all cases pass; existing snapshot and core snapshot tests
  are unchanged.
- **Verify:** `cargo test --locked -p qv-store snapshot_inventory`;
  `cargo test --locked -p qv-core snapshot`.

### Step 7 — Documentation, roadmap and gates

- [x] **Do:** update the qv-store crate docs (modules table, development
  formats, readings, not-yet-implemented), `ARCHITECTURE.md` §3/§7 and
  `CHANGELOG.md`. Add the roadmap revision with the 1.15b/1.15c split, the
  1.15c checkbox and the execution log. Update `plans/README.md`. Run the
  final gates.
- **Files:** `crates/qv-store/src/lib.rs`, `ARCHITECTURE.md`, `CHANGELOG.md`,
  `plans/0002-roadmap/PLAN.md`, `plans/README.md`, this plan.
- **Done when:** the plan is Implemented, all gates are green, and 1.15c
  remains unticked.
- **Verify:** all `AGENTS.md` gates; `git diff --check`.

## Test plan

- Final verification on the final tree: `sh scripts/check-spdx.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked` (with a private Xvfb via `QV_TEST_XVFB`). Logs go
  under the session scratchpad. No dependency change, so deny/vet are not
  required.
- Unit and property tests: replacement preservation (proptest), codec
  round trips.
- Rejection, malformed-input and crash-path tests: step 4 refusals, faults
  and cleanup; step 5 codec rejection; step 6 directory hostility; reserved
  names (step 1).
- Vectors: an independent inventory MAC/encoding vector (development, not
  frozen).
- Fuzz: `snapshot_inventory` target, a 60 s local campaign, and a CI step.
- 0012 §1 rows, partially addressed:
  - Migration coupling, data part: logical causality preserved under the new
    generation.
  - Rotation/purge ambiguity: the replacement and the inert orphans of an
    interrupted preparation.
  - Hostile SQLite/CBOR: the inventory parser.
  - Whole-file rollback: an orphan or old copy cannot advance the anchor.

  Interrupted installation, restart and the old-generation archive refusal
  remain 1.15c; do not claim the rotation criteria are met.

## Risks and stop conditions

Stop and report if:
- the existing verification rejects a keyslot history that is one version
  above the retention target, or needs retention to run;
- an existing invariant prevents preserving a version's ID or clock, a
  conflict or a floor;
- reusing `verify_all`/`read_attachment` on a Candidate needs anchor
  interaction;
- any schema, profile, dependency or `unsafe` change is needed;
- a secret would reach durable non-encrypted output, an error or Debug.

Never wrap the new VK with the old VK. Never store the new VK or phrase
outside the replacement's password slot. Never write an anchor, journal or
marker. Never rename to an active name, and never claim erasure of the old
generation.

## Documentation

- [x] `CHANGELOG.md` — Unreleased: replacement and inventory foundation, limits.
- [x] `ARCHITECTURE.md` — §3 rotation paragraph; §7 split note.
- [x] Specs — no normative change; statuses unchanged (0002 stays Accepted).
- [x] `AGENTS.md` — no change.
- [x] Plans — this plan's log; roadmap revision, 1.15b/1.15c entries and log;
  `plans/README.md` row.

## Revisions

None.

## Execution log

2026-10-29: Clean tree at `9c25a6a`. Plan 0021 (1.15a) got a fresh-context
review in this session: Approved, see its REVIEW.md. Planned 1.15b and
split it under the roadmap session-size rule (1.15b replacement and
inventory; 1.15c installation, restart, core and CLI). No decision, spec
amendment, dependency, `unsafe` or crate deviation is needed, so this is
standing approval, roadmap 0002. Developer starts at step 1.

2026-10-29: Step 1 done. `rotation_guard::check` refuses file names containing
`.qvrotate` (Integrity) before the marker test. `VaultFile` has a crate-private
`FileRole` (Ordinary/Candidate); `open_locked_as` and `check_identity` apply
the role's guard; `begin` and `finish_pending_anchor` refuse a Candidate.
`rotation_guard` passes 8 tests, including the new reserved-name test
(open/open_locked/create/restore, unchanged anchors and source). The CLI
credentials test passes 8 tests, including the reserved-copy case (exit 7,
anchors byte-identical). Difference from the step text: the check does not
cover "an existing session's `check_identity`", because an ordinary session
cannot have a reserved path. The Candidate role covers the reverse case.

2026-10-29: Steps 2–4 done.
- **Creation helper.** `creation::write_database` now holds restore's
  open/harden/page_size/schema/singleton/manifest/head sequence. Restore uses
  it, and its 6 tests pass unchanged.
- **`rotation.rs`.**
  - Preconditions: pending-anchor retry, gate, remote, control-record heads,
    generation, sequence and counter bounds.
  - Full source `verify_all`, then one read transaction.
  - New VK, phrase and slot; the slot keeps the source's KDF and wrap
    profiles (both V1 today).
  - Record and chunk reencryption with fresh IDs, `Manifest::remapped`, the
    keyslot causal edit, head +1/+1 naming the old digest, replica counter +1.
  - Reopen as Candidate: new-password slot unlock, header MAC under both the
    unwrapped and the generated VK, `finish_candidate` (loads state and never
    touches anchors), equality of manifest, digest, replica and head,
    replacement `verify_all`.
  - Logical comparison of every version by canonical-encoding digest (chunk
    IDs remapped) and of every attachment by content hash, compared in
    constant time.
- **`rotation_tests.rs`.** 8 `rotation_replacement_*` tests pass (29 s):
  - preservation: history, a floor, a tombstone, multi-chunk attachments,
    fresh IDs and nonces, generation g+1 rows, replica/writer retained, the
    keyslot edit;
  - credentials: new password and phrase work; old ones do not; a Candidate
    refuses write and adopt; an orphan copy is refused by ordinary open;
  - drop, cancellation (immediate, after the file exists, late) and faults
    (before the first object, mid-build, before COMMIT);
  - the corrupted chunk remap and keyslot payload are Integrity;
  - refusals before KDF: NoAnchor, marker, remote, a control conflict,
    counter, generation;
  - pending-anchor retry; Changed;
  - a preserved two-head entry conflict;
  - proptest of random edit/purge histories.

  Every case asserts byte-identical vault and anchor directories.
- **Fail-closed stubs** in `unsupported.rs`.

Differences from the plan:
- Chunks cannot be shared (`Manifest::validate` uses each reference
  exactly once), so the map is a bijection. The plan was corrected before
  coding.
- Test-only hooks (`FAIL_AFTER`, `CORRUPT`) and `Manifest::add_head_for_test`
  were added to produce the failure and conflict cases.

2026-10-29: Steps 5–6 done.
- **Codec.** `snapshot_inventory.rs` holds `SnapshotInventory` (sign,
  encode, decode → `UnverifiedInventory` → verify) and `InventoryRow`. The
  1 MiB cap is checked before decoding and the 4096-row bound before
  allocating.
- **Directory operations.** `SnapshotDir::{prepare_inventory, publish_inventory,
  inventory, remove_inventoried}`, plus crate-private `build_inventory` (the
  build rules with explicit inputs, so carried rows can be tested without a
  second real generation) and `remove_inventory`.
- **Vector.** Independent stdlib vector
  `tests/vectors/snapshot_inventory.py` and its `.cbor` fixture: MAC
  `f73d24e0…e30c`, public all-one VK. It passes and is compared byte-for-byte
  by a Rust test.
- **Tests.** 6 `snapshot_inventory*` tests pass:
  - vector and round trip; wrong key, generation and vault; Debug;
  - every prefix and byte mutation;
  - missing, null and unknown keys; format; generation 1; bad UUID;
    unsorted, duplicate and out-of-range rows; a truncated row head;
    4097 well-formed rows refused and 4096 accepted; the 1 MiB cap;
  - building from authenticated and carried rows (another vault, damaged,
    changed and missing files ignored); cancellation; the production
    `prepare_inventory` path;
  - publication is atomic, refuses an existing name, leaves other
    generations' names untouched and returns a digest matching the file;
  - removal happens only on an exact hash and size match of a verified row
    (a forged row is NotFound; a changed file is Integrity and kept);
  - symlink, 0644, oversized, garbage and foreign-vault inventory files
    refused.
- **Fuzz target.** `snapshot_inventory` (raw bytes plus mutations of the
  verified vector; accepted input reencodes identically; a mutated seed never
  verifies). Cargo entry and a 60 s CI step added.
  - Fuzz fmt and locked build pass.
  - Local coverage campaign (stable 1.98.1, musl, sancov flags as in plan
    0021's log, `-use_cmp=0`): 473,987 runs in 61 s, cov 1817/ft 3574,
    32 MiB, no finding.
  - This was not an ASan run; CI uses cargo-fuzz nightly.
- `cargo test -p qv-core snapshot`: 19 passed, unchanged.

Difference from the plan: the codec cannot test a truncated 4097-row array
header for LimitExceeded, because `Decoder::new` validates well-formedness
first (Integrity). The bound is tested with a well-formed 4097-row array
instead.

2026-10-29: Step 7 done; plan Implemented (phase 1.15b only).
- **Docs.** qv-store crate docs (rotation section, modules table,
  not-yet-implemented), `ARCHITECTURE.md` §3 rotation paragraph and §7
  split, `CHANGELOG.md`, roadmap 1.15b tick, 1.15c entry and log,
  `plans/README.md`.
- **Gates.** Final required gates on the final source tree (logs in the
  session scratchpad `r22/`), all pass:
  - SPDX;
  - `cargo fmt --check`;
  - `cargo clippy --all-targets --locked -- -D warnings`, rerun after fixing
    test-only and `into_iter` lints;
  - `QV_TEST_XVFB=<private Xvfb> cargo test --locked`: **619 passed,
    0 failed, 2 pre-existing ignored**, 34 groups.
- **Other checks.** `git diff --check` is clean. Fuzz fmt and the locked build
  pass. Both independent vectors pass. No dependency, lockfile, profile,
  schema, `unsafe` or normative spec change, so deny/vet are not required.
- **Not available.** Network namespace isolation (`unshare -rn` fails:
  `No space left on device`); not counted as a pass.

Not claimed: installation, restart/rollback, anchor advancement across
generations, inventory-aware pruning, CLI, or the whole-rotation *Done when*
of roadmap 1.15. All of that is 1.15c. This was a same-context
implementation check only; the next fresh session reviews this plan before
1.15c. Changes are uncommitted; no commit, push or branch.

