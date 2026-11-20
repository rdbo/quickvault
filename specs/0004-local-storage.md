# 0004 — Local Storage (Vault File)

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0002, 0003 |

## Summary

A vault is a SQLite database of encrypted immutable objects and an authenticated
manifest. Snapshots, backups and file-exchange copies use a separate, simple
**archive** format (§6) that is authenticated before anything beyond a small
fixed header is parsed. Rollback detection also needs an external remembered
anchor. The active DB is private application storage, not a file-sync target.

## Specification

### 1. Files and opening

1.1. Extension `.qvault`; fixed `application_id` and `user_version` (the
schema version). Schema `0x7FFF0005` adds `snapshot_index` (§2.5); a file of
schema `0x7FFF0004` with exactly that schema's tables opens and gains the
table in its first write transaction (plan 0059). These values, and every
other constant and structure of this spec, are frozen at 1.0 as registered in
0015.
Use owner-only file permissions (0600, private 0700 directory on Unix;
equivalent ACLs elsewhere). Reject symlinks, nonregular files and unexpected
path replacement. The default location is private application storage. A
user-selected path (0011 `--vault`) inside a known file-sync, network or
removable location produces a warning, because those tools may copy or roll
back the live file. Archive destinations are explicit user choices; new archives
and restored vaults MUST NOT overwrite existing paths.

Keep the external rollback record independent of the vault's storage. Refuse a
vault inside the anchor directory. Warn if anchors are nested in the vault's
directory, or their recognized sync/network/removable location can roll back
together with it. Detection is heuristic, not a guarantee of independence.

1.2. Set `secure_delete=ON`, `temp_store=MEMORY`, `foreign_keys=ON`,
`journal_mode=DELETE`, `synchronous=FULL`, `trusted_schema=OFF`, `mmap_size=0`,
`cell_size_check=ON`. Disable extensions, triggers, views and unused
virtual-table features; enable SQLite defensive mode
(`SQLITE_DBCONFIG_DEFENSIVE`). Register no secret-bearing application SQL
functions. Required hardening failures abort opening. Run bounded `quick_check`
and validate the exact released schema before reading vault tables. Unexpected
triggers, views, expression indexes or schema versions are errors.
Attaching stays disabled except for the one compaction statement of §1.4.
See [SQLite security guidance](https://www.sqlite.org/security.html).
QuickVault never ingests a SQLite file it did not create as part of an
automatic workflow: snapshots, automatic imports and file exchange use archives
(§6). An explicit Android system-picker action may stage a user-selected raw
vault under §5.4; this exception does not apply to network/automatic ingestion.

Before opening an existing file with journal-changing settings, identify its
application/schema version, page size and exact catalog through a bounded,
immutable read-only connection. Configure defensive flags, SQL/allocation limits
and an execution-step budget before catalog reads. This connection MUST NOT
recover, checkpoint, rewrite or create any database/sidecar file. A private
percent-encoded file URI with `mode=ro&immutable=1` is permitted only for this
identification probe; ordinary mutable connections still reject caller URIs.
Close the probe before opening the mutable connection, retain the locked file
and recheck path identity. Identification is not authentication: normal full
hardening, own-journal recovery and authenticated unlock still follow.

1.3. Serialize writers with a private per-vault process lock plus SQLite
transactions. Re-read the local head inside `BEGIN IMMEDIATE`; an unexpected
head requires reload/merge before editing. Track file identity and reject
external replacement. Modification time and header hashes are not concurrency
or integrity checks. Local locks do not make external live copying safe.

1.4. **Compaction (owner, 2026-11-15; plan 0060).** Deleting data leaves free
pages that SQLite reuses but never returns to the volume. Compaction rewrites
the file without them, holding the vault's process lock and with no
transaction open and no anchor update pending:

1. Remove stale temporary siblings of the vault (§1.1 temp names). Refuse with
   a storage-capacity error unless the volume has the copy's size (pages in
   use) plus 256 MiB free.
2. Create the private, locked, empty temporary sibling as for a new vault and
   write the copy with `VACUUM INTO` on the vault's own hardened connection.
   Only for that one statement, with the bound temporary path, the attached
   database limit is 1 instead of 0; it is restored and read back afterwards,
   and a failed restore blocks further writes in the session.
3. Flush the copy, open it with the full §1.2 identification and hardening,
   and require byte equality of the header, header MAC, keyslots, local head,
   replica row, snapshot index, archive receipts and LAN links, plus every
   column of every object and manifest row, including full ciphertext bytes
   in key order (bounded to one row from each file at a time). Any difference
   removes the copy and leaves the vault unchanged.
4. Move the copy over the vault path (replacing it), flush the directory and
   reopen the session's connection at the path under the copy's lock, checking
   the header, MAC and slots again.

Check cancellation while copying with SQLite's progress handler and between
verification rows. Cancellation before replacement interrupts the statement,
removes the copy and preserves the source. The attach limit is restored even
after interruption. On Windows close only SQLite's source connection before
replacement; retain both process locks through replacement and reopening, as
on Unix. Use `FileRenameInfoEx` with replacement and POSIX semantics through
a write-through handle, then flush that handle; do not fall back to releasing
the source lock when the operation is unsupported. The process-lock handles
already share delete access. A failed move
reopens the source under its retained lock or blocks further writes.

Both files are complete states with the same head, so a crash at any point
leaves a valid vault, the external anchor is unchanged and no journal is
needed; a leftover temporary copy is removed by the next open or compaction.
Frontends compact automatically after a commit leaves at least 32 MiB and a
quarter of the file free, skipping it when the copy would not fit (best
effort, retried after a later commit), and on explicit request. The replaced
file's blocks are released by the file system; like any deletion, this is not
secure erasure.

### 2. Logical schema

Released DDL MUST implement these constraints and be validated on opening.
Fixed-length IDs, singleton counts and uniqueness are checked independently
of attacker-supplied SQL constraints.

| Table | Key | Contents |
|-------|-----|----------|
| `header` | exactly one row | format, vault ID, key generation, data profile, minimum profiles, header MAC |
| `keyslot` | slot ID | type, device binding, KDF profile/salt, KEK commitment, wrapping profile, wrapped VK |
| `object` | (key generation, object ID) | data profile, nonce, ciphertext |
| `manifest` | manifest hash | generation, profile, nonce and encrypted manifest: the live one named by `local_head`, plus those local snapshots retain (§2.5) |
| `local_head` | exactly one row | authenticated local state (§5.4 of 0005): sequence, previous digest, manifest hash, remote checkpoint, `archive_receipts_digest`, `lan_links_digest` |
| `sync_state` | remote ID | encrypted verified remote base, cursor and pending publication |
| `archive_receipts` | exactly one row | sealed local filename/complete-archive digest set (§2.3), bound by `local_head`; never in archives or sync |
| `replica` | exactly one row | local-only writer state (0005 §1.3): replica ID naming this DB's external anchor, writer ID, next counter; never in archives or sync |
| `snapshot_index` | exactly one row | sealed local snapshot list and the object IDs snapshots retain (§2.5); local-only, never in archives or sync |
| `lan_link` | link ID | kept for format compatibility and always empty after a commit (0013 §9.1, 0014 §5); bound by the local head's `lan_links_digest`; local-only, never in archives or sync |

Server checkpoint fields and `sync_state` rows are optional server-mode state.
Creating or operating an offline or LAN-only vault MUST NOT require a server
identity, account, checkpoint or dummy server row. LAN exchanges use the same
verified objects/manifests and local commit/anchor path; no LAN peer state is
stored (0013 §9.1), and nothing LAN-related may be inferred from the server
`sync_state` layout.

2.1. A record may have several active versions. The manifest defines active,
historical and suppressed versions; a single record-ID primary key or upload
order cannot do so. Logical version IDs remain stable across reencryption.
Causality does not require retained historical payloads (0005). Object IDs are
random 128-bit IDs. A changed attachment chunk gets a new object ID.

2.2. **Objects are unlinkable outside the manifest.** The plaintext of an object
row or object envelope is limited to object ID, key generation, data profile,
nonce, ciphertext and its length. Record IDs, version IDs, attachment IDs, chunk
indexes, kinds and roles exist only inside the encrypted manifest and encrypted
payloads; clients build the object-ID-to-role index in memory after verifying
the manifest. Neither the server nor a disk-image thief can group objects into
records, attachments or edit histories from routing data. Header/keyslot
metadata is MAC'd. Kinds, clocks, names, dates and deletions are encrypted.
Public server reference lists reveal object liveness and sizes as accepted
leakage (0001), not record linkage.

2.3. **Local archive receipts.** Filename-reuse detection (0005 §4.3) retains
at most 4,096 receipts per local replica and key generation, without silent
eviction. Each receipt maps a lexically normalized absolute path, encoded as
raw OS bytes (at most 4,096 bytes), to SHA-256 of the entire authenticated
private archive copy, including its header and framing. Identical redelivery
succeeds even at capacity; changed bytes at the same path are an integrity
error. Capacity exhaustion aborts before changing accepted state. Different
paths are independent; hard-link/inode identity is not the receipt key.

On Linux/Android, canonical stored paths start with `/`, name a file (not `/`),
and contain no NUL, empty, `.` or `..` component or trailing separator. Non-UTF-8
bytes are valid. Resolve relative input against the operation's captured
absolute working directory, remove `.` and repeated separators, and resolve
`..` lexically (clamping at root); bound both input and result before allocating.
Open the resulting source path component by component without following
symlinks, and use that same normalized byte path as the receipt key. The
receipt codec itself does not access the filesystem.

The STRICT singleton table is
`archive_receipts(id INTEGER PRIMARY KEY CHECK(id = 1), sealed BLOB NOT NULL)`.
Exactly one row with ID 1 and a bounded BLOB is required, checked independently
of SQL constraints before reading its value. The canonical plaintext is
`[1, [[path:bstr, archive_sha256:bstr32], ...]]`, strictly ascending and unique
by raw path bytes. Paths and plaintext serialization use protected secret
containers; Debug and errors MUST NOT reveal paths or receipt contents.

The canonical sealed envelope is
`[1, data_profile:uint, nonce:bstr24, ciphertext:bstr]`. Use stored-data/1
framing, Padmé and AEAD under the generation's existing `local-state` purpose
key, a fresh random nonce, and canonical AAD
`["qv/archive-receipts/v1", vault_id:bstr16, key_generation:uint,
replica_id:bstr16, data_profile:uint]`. Ciphertext is at most 32 MiB and the
complete envelope at most 32 MiB + 128 bytes; the maximal plaintext under the
row/path limits is below 17 MiB. Unknown versions/profiles fail closed.
`archive_receipts_digest` is object-hash/1 (SHA-256) of the complete canonical
envelope. It is mandatory local-head CBOR key 7; key 8 is the mandatory
`lan_links_digest` (§2.4). Verify the head MAC and envelope digest,
then authenticate/decrypt the envelope before parsing receipt plaintext.
Missing or invalid receipt state MUST NOT become an empty default.

Creation, new-path restore and a rotation replacement initialize fresh empty
receipts, sealed for their replica and generation, in the same unpublished
DB transaction as the head. Ordinary writes preserve them. Incoming acceptance
updates receipts together with objects, manifest and head in the existing
single transaction; anchor replacement follows durable commit before reporting
success (0005 §5.4). A failed attempt before commit records no receipt. Retry
after a durable commit must finish its pending anchor update first. Receipts
are local-only and never enter an archive, portable manifest or peer exchange.
The table is part of every 1.0 file (0015 §3).

2.4. **LAN peer state** (0013 §9). The layout is

```sql
CREATE TABLE lan_link (link_id BLOB PRIMARY KEY CHECK (length(link_id) = 16), key_generation INTEGER NOT NULL, sealed BLOB NOT NULL) STRICT, WITHOUT ROWID
```

`sealed` uses the canonical envelope
`[1, data_profile:uint, nonce:bstr24, ciphertext:bstr]`, with stored-data/1
framing and AEAD under the generation's `local-state` purpose key, a fresh
random nonce, AAD `["qv/lan-link-row/v1", vault_id, key_generation, link_id]`
and the plaintext of 0013 §9.1 before 0014 (link key, label, creation
time). The ciphertext is at most 512 bytes. Rows in this layout exist only in
files written before 0014 and are cleared at their next commit.

On open:
- at most 64 rows are allowed, checked before any value is read;
- each row needs a 16-byte ID, the header's key generation and a bounded
  blob;
- `lan_links_digest` (local-head key 8) must equal the digest of 0013 §9.1
  over the stored rows. A mismatch is an integrity error.

Rows are never read for authentication. No peer endpoint is stored (0013
§9.2). Every commit deletes all rows and writes the digest of the empty set
(0013 §9.1), so a file from before 0014 clears at its next commit. Creation,
new-path restore, new-device creation (0013 §10) and a rotation replacement
start with no rows. The table and digest stay in the 1.0 format (0015);
files with a header format older than `0x7FFF0004` are rejected.

2.5. **Local snapshots inside the vault (plan 0059).** A local snapshot is a
retained manifest in this file, not a copy of the vault (0007 §3.1). One
sealed `snapshot_index` blob (local-state purpose key; AAD binds vault ID and
key generation) lists each snapshot `[snapshot_id, created_at, kind,
manifest_hash]` and the sorted set of object IDs any snapshot's manifest
references. A commit deletes an object row only when neither the new manifest
nor that set references it, and a manifest row only when neither the head nor a
snapshot names it. Snapshot rows, the set and their removal change in the same
transaction as the commit that causes them. The number and sizes of retained
manifest rows are visible to a disk-image holder, as snapshot files were
(accepted leakage); which objects they retain is encrypted. Snapshots follow
the file: they do not protect against losing or corrupting it, and a new-file
operation (VK rotation, restore, import as a new vault) carries none.

### 3. Encoding and encryption

3.1. Use RFC 8949 core deterministic CBOR: shortest encodings, definite lengths,
integer map keys in deterministic order, valid UTF-8, no floats/tags/duplicate
keys. Reject noncanonical encodings. Preserve unknown optional payload keys
within budgets; unknown required features or security/control kinds fail closed.
Transcripts and hashes use exact canonical bytes, not ambiguous concatenation.

3.2. A record plaintext is
`{ kind, version_id, clock, modified_at, deleted, payload }`.
Pad with Padmé and authenticate framing with the original plaintext length;
validate that length against the decrypted buffer and decoding budget.
Encrypt under the per-record key with a fresh 24-byte nonce and canonical AAD
`["qv/record/v1", vault_id, key_generation, record_id, version_id,
object_id, data_profile]`. The verifier takes record ID and version ID from
the manifest role, not from the envelope. Decrypted `version_id` and `clock`
MUST equal the manifest's values. An object ID is immutable within a key
generation.

3.3. Chunks use the attachment key and AAD
`["qv/chunk/v1", vault_id, key_generation, attachment_id, object_id,
chunk_index, data_profile]`. Every chunk, including the last, is padded to the
full 64 KiB chunk size with authenticated framing of its true length, so chunk
sizes do not reveal exact attachment length. Attachment metadata names ordered
chunk objects, total length and SHA-256 content hash. Verify each chunk's AEAD
before release and complete length/hash before accepting the attachment as
complete. Changed content uses new objects.

3.4. Encrypt each manifest with the VK-derived manifest key, fresh nonce and AAD
`["qv/manifest/v1", vault_id, key_generation, data_profile]`.
Its plaintext names sorted active (record ID, version ID, clock, object ID)
heads, retained history, permanent tombstones, history suppression frontiers,
attachment chunk lists, and a sorted object reference list:
`[object_id, data_profile, ciphertext_length, SHA256(ciphertext)]`.
Each role resolves uniquely to one reference. Include a digest of portable
header configuration (format, vault ID, generation and stored-data/derivation
minima). Password-slot descriptors are authenticated inside complete keyslot
records; local operational slot selection and quick slots are bound by the
local header MAC, not a remote configuration digest. Local sync state uses a
separate purpose key and is excluded from archives. Manifests, checkpoints,
sync state and anchors are not ordinary records.

3.4.1. Permanent tombstone roles have canonical encoding
`[version_id, clock, object_id, true]`; ordinary roles omit the fourth item,
and attachment metadata roles use a chunk-ID array there instead. The marker
MUST equal the decrypted version's Final deletion state, checked on every role
read and archive verification. Marked dominated tombstones remain retained
history even at/below the history floor; no other covered history is valid.
Ordinary unlock authenticates marked historical tombstones as well as heads.
Pruning, purge and later final deletion MUST preserve all such roles/objects;
rotation preserves their markers. The manifest format is `0x7FFF0002`
(0015 §4.4).

3.5. `manifest_hash = SHA256(canonical manifest envelope including ciphertext)`.
`reference_digest = SHA256(canonical sorted reference list)`; publish the list
to the server for retention, and compare it to the decrypted manifest.
The manifest excludes itself, its checkpoint and local-only tables.

3.6. **Verification points.** Objects entering local storage (import, sync,
archive restore) are verified once against the manifest reference: exact
membership, no duplicates, length and SHA-256, then AEAD before acceptance.
On ordinary unlock verify the manifest, that every referenced object row exists
with the referenced length, and the AEAD of every active record (needed for
views anyway). Verify hash and AEAD again whenever a historical version or chunk
is read. A full re-hash of all stored ciphertext runs on explicit
`qv verify` and before creating an archive; it is not repeated on every
CLI command. Ignore unreferenced objects. Missing or mismatched data is an
integrity failure, never an empty record. A snapshot's objects are checked
when it is restored (as an archive, §6.3) and by explicit `qv verify`; unlock
checks only that the index authenticates and that each named manifest row
exists.

### 4. Resource budgets

4.1. Enforce bounds before allocating from untrusted lengths. Initial limits:
1 MiB padded record ciphertext; 64 KiB + framing per chunk ciphertext; 64 MiB
manifest; CBOR nesting 32; 4,096 fields per entry; 256 writers per clock; 256
concurrent heads per record; 50,000 record IDs including tombstones; 250,000
referenced objects other than attachment chunks, plus at most 131,072
attachment chunks (the total budget in 64 KiB chunks); 1,048,576 clock
components in total across a manifest's heads, retained history and history
floors; 8 GiB total referenced ciphertext; 2 GiB per attachment; at most 48
retained snapshot manifests;
256 KiB per text/byte field. Header/keyslot metadata is at most 64 KiB with at
most 64 slots. Apply SQLite length, column, expression, page-count and
execution-step limits. Stream object hashes; never load total ciphertext or all
attachments into RAM.

4.2. Budgets MUST be mutually consistent: the worst-case canonical manifest at
the maximum record, object, chunk, head and writer counts must fit the manifest
limit.
The aggregate clock-component budget, not the per-clock writer limit times the
object count, bounds the clocks in that worst case. History retention (0007)
yields to the object and clock-component budgets; active heads, tombstones
and floors never do. A release gate (0012) checks this with a generated
worst-case vector.

Candidate acceptance and local publication also require each record's active
head-clock union plus the actual local resolving writer to fit the per-clock
writer limit (0005 §1.2). Do not admit a valid-per-head conflict that cannot be
resolved under the same limit. Reading/exporting an existing state does not
apply this additional admission rule.

4.3. Network listing pages are at most 8 MiB and aggregate upload/download
staging 16 GiB. A single object transfer is bounded by its own per-type limit
(manifest, record or chunk) and is streamed, not buffered in a page. Group
traversal is iterative, bounded by record count. Check counter arithmetic.
Known KDF profiles select exact work factors; unknown profiles fail before any
KDF. The server cannot supply arbitrary work factors.

4.4. Limits are local safety policy, not server-controlled values. A user may
explicitly select a documented larger local policy before retrying. Limits
fail without replacing accepted state or dropping causal metadata.

### 5. Unlock and writes

5.1. Validate SQLite, header bounds and profiles; unwrap VK; verify header MAC;
authenticate local head, manifest and external anchor; verify per §3.6; then
build bounded metadata/search views. Protected values stay encrypted when
idle and are decrypted only into short-lived zeroizing buffers on demand.
Metadata and intermediate decoding buffers are confidential too (0008).

5.2. Each mutation is one transaction: store immutable objects, update
active/history references and suppression metadata, store the new manifest,
write the new authenticated local head, persist outbox, then prune by
references. Commit durably, advance the external anchor (0005 §5.4), then
report success. If COMMIT is durable but anchor completion fails, return the
distinct `CommittedAnchorPending` outcome: the change is saved, must not be
repeated, and the session follows the committed state while blocking subsequent
writes until the anchor is completed. Cancellation after COMMIT cannot turn
this into an unchanged/cancelled result. Integrity failure before COMMIT aborts
the whole candidate; never silently omit a bad record.

An unreadable anchor encoding is `DamagedAnchor`, separately from damaged vault
contents. Explicit recovery may authenticate and inspect the vault read-only
with status `Damaged`, preserving the anchor until deliberate baseline adoption.
Unsafe anchor paths and I/O errors still fail; they are not evidence of merely
damaged anchor bytes. Never advise deleting an anchor to repair a vault.

5.3. Never write plaintext to DB pages, journals, temp files, logs or crash
reports. Archives are built by writing verified objects into a new file
(§6), never by copying or normalizing the live SQLite file, so local sync
state, writer identity, anchors, sessions, device bundles and quick slots
are never present to be removed.

5.4. Explicit Android vault import stages only ciphertext in private owner-only
storage, bounded by `MAX_DB_BYTES` (16 GiB physical SQLite bytes: the 8 GiB budget plus
history, snapshot-only objects and manifests) using actual
streamed length, not provider metadata. Apply all ordinary identification,
SQLite hardening, password/header authentication and complete content validation
before publication. Staging has a source-only anchor context; never consult or
change another local replica's anchor because of the imported identity.

Before staging beyond the first 100 bytes, check the public SQLite magic,
4096-byte page size and nonzero declared page count within `MAX_DB_BYTES`.
Require actual length to equal that declared size; reject truncation and probe
at most one extra byte for overrun without writing it. These unauthenticated
header checks only reject obviously unsuitable input early, and never replace
the authentication and complete validation above.

The selected document is never changed. Require explicit acknowledgement that
its freshness is unestablished and that QuickVault will edit an independent
private copy. Use the verified archive/fresh-local creation protocol: preserve
replicated data, history and attachments; generate a new local writer, replica,
head and anchor; do not clone source local credentials or quick-unlock state.
Never silently select conflicting password/control heads. Archive intermediate
bounds remain §6 bounds, distinct from the raw physical-file bound. Preflight
model/index validity before no-replace durable publication. Preserve a published
file on any later failure and report `PublicationIncomplete`; return no late
unlocked session. Remove abandoned leased staging on drop/cancel/restart without
traversing provider/user files. No plaintext staging, provider write-back or
automatic import is authorized.

### 6. Archive format

Private unpublished temporary files use cooperative file leases. Serialize
creation→lease acquisition and stale cleanup with a short directory lock.
Known `.<final-name>.tmp-<16 lowercase hex>` files and their SQLite journals may
be reclaimed only when no live producer holds the matching base file's lease,
after no-follow/owner/identity checks. Keep the lease through publication or
removal, including after transferring its descriptor to a File. Reclaim stale
archive/restore/anchor temporaries on the next operation in that exact family;
never infer staleness from age or delete rotation-journal-owned replacements.
Cleanup is not secure erasure and does not establish crash durability itself.

6.1. An archive (`.qvsnap`) is the only format for explicit backups, file
exchange, restoring a local snapshot and the recovery copy of a VK rotation
(0005 §4, 0007 §3); local snapshots themselves live inside the vault (§2.5). It is a byte stream:

```
"QVSNAP\0" || u8 format_version || u32be header_length || header
          || frame(manifest envelope) || frame(object envelope)*
frame = u32be length || bytes
```

6.2. `header` is canonical CBOR (at most 64 KiB):
`{ archive_id, vault_id, key_generation, data_profile, minimum_profiles,
created_at, manifest_hash, reference_digest, object_count, total_length,
password_slot?, header_mac }`. `archive_id` is a random 128-bit ID.
`header_mac` uses the header-mac purpose key over canonical
`["qv/archive-header/v1", header fields excluding header_mac]`.
`password_slot` is present only in an explicitly **self-contained** archive
(§6.4).

The optional password slot is archive-header CBOR key 10, a bstr containing the
complete canonical local `Keyslot` descriptor (the same bytes as the local
password-slot body, including unknown optional fields), within the total 64 KiB
header budget. Strictly validate its encoding and known profiles without running
a KDF while decoding the bounded header; include these exact bytes in the
existing header MAC. An explicitly self-contained export copies the working
local operational slot, never selects a received/conflicted record version.
Ordinary snapshots remain slotless and their policy reader rejects slot-bearing
files. New-path restore may use the authenticated self-contained slot while
preserving all manifest conflicts; this does not resolve any keyslot record.
A local snapshot restore from an authenticated source vault may use that source's
working local password descriptor when a slotless snapshot has multiple keyslot
heads. It must preserve those heads, require the same vault/generation and never
choose an incoming descriptor implicitly. Generic archive restore without such
an authenticated source still refuses an ambiguous slotless keyslot set.

6.3. Readers MUST: check magic/version; reject any length beyond the
budgets before reading it; decode only the bounded header before
authentication; obtain VK (from the local vault with the same vault ID and
generation, the recovery phrase, or a self-contained slot) and verify
`header_mac`; then read the manifest frame, check its hash against
`manifest_hash`, and decrypt it. Every later frame must match the next manifest
reference in sorted order by length and SHA-256 **before** AEAD decryption.
Trailing bytes, missing frames, wrong `object_count`/`total_length` or
unreferenced frames are integrity errors. No unauthenticated byte other than
the fixed prefix, the bounded header and frame length fields is parsed.

6.4. By default archives contain **no password slot**: the receiving device
already holds VK for merges, and a new installation restores with the recovery
phrase, after which the VK-encrypted keyslot record re-establishes password
unlock. Such archives give a file-sync provider nothing to guess offline. A
self-contained archive includes the current password slot only after explicit
user choice with a warning that its holder can attempt offline master-password
guessing; the slot carries its KEK commitment (0002 §3.2).

6.5. Write archives to a private temporary path on the destination filesystem,
re-read and verify them, fsync, then publish atomically under a **new unique
filename**, never replacing an existing path; fsync the directory where
supported. Published archives are immutable.

### 7. View residency and authenticated path policy (0047)

7.1. A valid vault has no aggregate searchable-text eligibility limit. The
8 GiB referenced-ciphertext budget and every §4.1 per-record/model/manifest
limit remain. Use a compact structural index bounded by those limits and an
evictable metadata cache with at most 64 MiB of owned text capacity, including
normalized/sort-key copies and cursor text. Evict or bypass the cache when a
valid row will not fit. Cache exhaustion MUST NOT reject unlock, edits,
merge, restore, rotation or enrollment. Never spill plaintext to disk.
This ceiling does not include structural metadata, one-record decoding scratch,
returned pages, frontend/framework intermediates or KDF working memory; document
those categories separately and do not claim a 64 MiB total-RSS bound.

7.2. Unlock still authenticates and validates all required objects. Lazy
views do not permit skipping integrity/schema checks. Decode one head at a
time with compact merge summaries; do not retain all 256 maximum-size heads.
Remove aggregate-text preflight rejection from acceptance/publication paths;
validate the compact candidate and all existing model/storage budgets instead.
The unlock verification pass may hand each head, after its AEAD and role
checks, to the caller's index builder so that a head is decoded once. The
builder sees no version before manifest authentication. If unlock then fails,
the partial index and its text are discarded; no session is returned.

7.3. Page views return at most 32 rows and 2 MiB owned display text. Account
allocated capacity and Unicode normalization/lowercase expansion, including
returned type-classification keys. Custom page byte bounds must still fit one
maximum valid summary. Immutable cursor clones may share one zeroizing state;
they must not duplicate unaccounted plaintext. Cache residency and all active
query/sort/cursor text share the64MiB ceiling; a smaller cache target must not
reduce the fixed working budget. Excess outstanding cursors/concurrent view
work may fail a transient resource request; it never changes vault eligibility.
No field or
row truncation; a maximum valid row must remain readable. Preserve current
case-insensitive matching and order: group lowercase name/ID (owner,
2026-11-17; the stored `order` key is kept but not used for display), entry
lowercase title/ID,
search groups by lowercase name/ID before entries by lowercase title/ID. Use bounded top-k selection/on-demand reads
rather than all-results plaintext accumulation. A session may keep a few
text-free match sets: the ascending record IDs of every match of one
query/scope at one revision, bounded by the record limit, zeroized and
charged to the 64 MiB ceiling. They live in session state only, never in a
cursor or page, and are discarded on lock, revision change and eviction by
newer sets. A matching cursor may page through its set without rematching;
a new query at the same revision and scope may scan only a prior set when the
new normalized query contains the prior one. Exhausting the ceiling falls
back to a full scan, never a failure. The cache keeps labels (titles, type
hints, icons, group names and their normalized copies) apart from
searchable field text and evicts field text first; a sequential scan must not
evict resident views to admit new ones. Private redacted/zeroizing
cursors bind session, revision, query/scope and order; mismatches return
StateChanged, never mixed-snapshot output. Scans process at most 16 records
per session read, check cancellation between heads, release the mutex between
batches and reject changed revisions. No detached key copy may bypass locking.

7.4. Frontends retain bounded pages (app: the item, trash and conflict
lists scroll as one window of consecutive pages, at most 32 pages (1,024
rows) and 8 MiB of row text, loaded as the list's end comes into view; a
full window is replaced by the next one on request, and a window that does
not start at the first row offers a return to the start; other lists one
page; plus selected detail) and clear stale/locked rows. CLI listings,
search, paths and JSON stream pages without a full text/path map. A stale
snapshot after partial output fails explicitly without silent restart or
repeated rows. Path components may be resolved and emitted incrementally.

7.5. A valid authenticated vault may be moved, restored or copied before
opening; no persistent inode/directory binding or ancestor-writable refusal
is added. Runtime permission, no-follow, regular-file, lock and open-file
identity checks remain. Authentication rejects tampered/incomplete contents;
an intact remembered external anchor rejects known rollback. Byte-identical
copies are equivalent content, and divergent valid copies are not a pathname
identity attack the product promises to detect. No pre-start parent-directory
substitution detector or global fork/freshness guarantee is claimed.

7.6. Newly installed clear slots use 0003 §8.1's public projection. LAN
publication uses 0013 §15.6's method-bound verified capability, full private
staging and pre-publication validation. Phrase enrollment preserves the shared
password slot without another password check/reset. Report durable publication
or anchor outcomes accurately if a later stage fails. Recheck cancellation and
expiry after publication and platform binding before returning a new unlocked
session. If either has occurred, discard the new session/key state, retain the
created file and return a data-free publication-incomplete outcome with local
open/recovery guidance.

## Security Considerations

AEAD alone does not detect missing rows. Manifests detect omission relative to
an authenticated state; external anchors detect known rollback with the limits
in 0005. Physical deletion is not secure erasure on SSDs, copy-on-write storage
or backups. SQLite/CBOR are hostile parsers before authentication; the archive
format keeps attacker-supplied files away from the SQLite parser entirely and
authenticates archive content before decoding it. Ordinary active-file copying
is unsupported ([SQLite warning](https://www.sqlite.org/howtocorrupt.html)).

## Open Questions

1. ~~Benchmark budgets on supported mobile devices before freezing the first
   format.~~ Resolved 2026-11-16 (owner-delegated, plan 0064): the budgets
   are frozen as they are, on the host measurements of plan 0053 and the
   owner's use of the app on their Android test phone; no measured phone run
   exists. A later change is a documented policy/version update (0015 §1.5).

## Changelog

- 2026-11-19: §7.4: the app's item, trash and conflict lists scroll over a
  window of at most 32 consecutive pages (1,024 rows, 8 MiB of row text)
  instead of three pages with Previous/Next; beyond it, "Show more" starts
  the next window (owner report, plan 0072).

- 2026-11-17: §7.3: groups are listed by lowercase name, then ID, instead
  of the stored order key (owner report, plan 0069).
- 2026-11-16: §1.4: compare complete compaction ciphertext, interrupt copying
  on cancellation, and retain the Windows source process lock (plan 0065).
- 2026-11-16: §5.4: reject unsuitable picked streams at the fixed SQLite
  header and bound actual staging by its declared page count (plan 0065).

- 2026-11-16: Formats frozen at 1.0 as they are (owner, plan 0064 Decision 1
  C); registered in 0015; "development"/"volatile" wording removed from §1.1,
  §2.3, §2.4 and §3.4; the stale receipt-version sentence in §3.4 dropped;
  Open Question 1 resolved.

- 2026-11-15: §1.4 compaction (`VACUUM INTO` a private temporary sibling,
  verified, moved over the vault; automatic after large frees and on request);
  §1.2 notes its one-statement attach exception (owner request, plan 0060).

- 2026-11-15: Larger budgets and snapshots inside the vault (owner request,
  plan 0059; numbers delegated): 2 GiB per attachment, 8 GiB total, chunks
  counted apart from the 250,000 objects (at most 131,072), 16 GiB vault file
  and staging; §2.5 `snapshot_index` and retained manifests (schema
  `0x7FFF0005`, upgrade from `0x7FFF0004`); §3.6 snapshot verification;
  §6.1 archives no longer hold ordinary local snapshots.

- 2026-11-13: §7.2 lets unlock verification feed the index builder so each
  head is decoded once; §7.3 permits text-free per-query match sets, query
  refinement over them, a separately evicted label tier and scan-resistant
  admission (plan 0053, owner-delegated 2026-11-13 under the standing
  2026-11-02 delegation). Results, ordering and budgets are unchanged.
- 2026-11-10: §5.4 defines explicit bounded Android raw-document staging,
  complete verification and independent no-replace publication (plan 0049).

- 2026-11-09: Specify cooperative temporary-file lifetime/cleanup leases;
  implementation is pending in plan0050.
- 2026-11-09: Specify saved/anchor-pending outcomes, independent-anchor warnings
  and authenticated read-only inspection of damaged anchors (plan0050).
- 2026-11-09: Require non-mutating bounded vault identification before journal-changing hardening (QV-016, plan0050).

- 2026-11-09: Separate 64 MiB cache residency from vault eligibility; specify paging, move/copy policy and credential-verified publication.

- 2026-11-06: Accepted 0014 (owner, plan 0042): `lan_link` and
  `lan_links_digest` stay in the format but are always empty after a commit;
  new-device creation writes no row. The development version is unchanged.
- 2026-11-03: Drop the `lan_hint` table: no peer endpoint is stored (0013
  §9.2; owner decision). The development version stays `0x7FFF0004` (that
  format was never committed with hints).

- 2026-11-02: Add §2.4 development layouts for `lan_link`/`lan_hint`. Local
  head key 8 is the mandatory `lan_links_digest`, and the schema/header
  version is `0x7FFF0004` (plan 0037; owner-delegated, standing 2026-11-02).
  Formats remain volatile.

- 2026-10-31: Define working-source-slot fallback for ambiguous slotless local snapshot recovery without resolving incoming keyslot heads (0028 continuation).

- 2026-10-31: Specify optional self-contained header slot key 10, exact descriptor/MAC coverage and snapshot exclusion (0028; prior owner delegation in 0026).

- 2026-10-30: Combined 2.2b (owner direction): explicit permanent-tombstone
  role markers allow indefinite retention below floors; authenticate and
  preserve them through cleanup, archive operations and rotation (0027).

- 2026-10-30: Define owner-approved local archive receipt storage, bounded
  canonical paths/plaintext, AEAD transcript, head digest and lifecycle resets
  (plan 0027; delegation recorded in 0026). Formats remain volatile.

- 2026-10-30: Owner-delegated acceptance of 0013 (roadmap D10, plan 0025): add the local-only `lan_link` and `lan_hint` tables and `lan_links_digest` in `local_head`.
- 2026-10-26: Add an aggregate budget of 1,048,576 clock components per
  manifest so the §4.2 worst case fits the 64 MiB manifest limit (256 writers
  per clock over 250,000 objects did not); history yields to it. Add the
  local-only `replica` row (writer state, anchor name) to §2 (plan 0009).
- 2026-10-24: Make server sync state optional for offline/LAN-only vaults;
  preserve local transaction/anchor requirements without selecting peer-state DDL.
- 2026-10-14: Initial accepted encrypted-row design.
- 2026-10-15: Amendment: immutable multi-head objects, canonical manifests,
  external anchors, parser budgets, SQLite hardening and safe exports. Replace
  header/mtime checks and eager protected-value indexing.
- 2026-10-15: Security review amendment: remove record/version/chunk/type
  routing from object rows and public reference lists (server-visible record
  linkage); pad final chunks; replace SQLite-file exports with an archive format
  authenticated before parsing; omit password slots from archives by default;
  replace `head`/`anchor_update` with one authenticated local head; make
  budgets mutually consistent and stop re-hashing all ciphertext on every unlock.
