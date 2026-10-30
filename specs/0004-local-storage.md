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

1.1. Extension `.qvault`; fixed `application_id` and `user_version`.
Use owner-only file permissions (0600, private 0700 directory on Unix;
equivalent ACLs elsewhere). Reject symlinks, nonregular files and unexpected
path replacement. The default location is private application storage. A
user-selected path (0011 `--vault`) inside a known file-sync, network or
removable location produces a warning, because those tools may copy or roll
back the live file. Archive destinations are explicit user choices; new archives
and restored vaults MUST NOT overwrite existing paths.

1.2. Set `secure_delete=ON`, `temp_store=MEMORY`, `foreign_keys=ON`,
`journal_mode=DELETE`, `synchronous=FULL`, `trusted_schema=OFF`, `mmap_size=0`,
`cell_size_check=ON`. Disable extensions, triggers, views and unused
virtual-table features; enable SQLite defensive mode
(`SQLITE_DBCONFIG_DEFENSIVE`). Register no secret-bearing application SQL
functions. Required hardening failures abort opening. Run bounded `quick_check`
and validate the exact released schema before reading vault tables. Unexpected
triggers, views, expression indexes or schema versions are errors.
See [SQLite security guidance](https://www.sqlite.org/security.html).
QuickVault never ingests a SQLite file it did not create as part of an
automatic workflow: snapshots, imports and file exchange use archives (§6).

1.3. Serialize writers with a private per-vault process lock plus SQLite
transactions. Re-read the local head inside `BEGIN IMMEDIATE`; an unexpected
head requires reload/merge before editing. Track file identity and reject
external replacement. Modification time and header hashes are not concurrency
or integrity checks. Local locks do not make external live copying safe.

### 2. Logical schema

Released DDL MUST implement these constraints and be validated on opening.
Fixed-length IDs, singleton counts and uniqueness are checked independently
of attacker-supplied SQL constraints.

| Table | Key | Contents |
|-------|-----|----------|
| `header` | exactly one row | format, vault ID, key generation, data profile, minimum profiles, header MAC |
| `keyslot` | slot ID | type, device binding, KDF profile/salt, KEK commitment, wrapping profile, wrapped VK |
| `object` | (key generation, object ID) | data profile, nonce, ciphertext |
| `manifest` | manifest hash | generation, profile, nonce and encrypted manifest |
| `local_head` | exactly one row | authenticated local state (§5.4 of 0005): sequence, previous digest, manifest hash, remote checkpoint, `lan_links_digest` |
| `sync_state` | remote ID | encrypted verified remote base, cursor and pending publication |
| `replica` | exactly one row | local-only writer state (0005 §1.3): replica ID naming this DB's external anchor, writer ID, next counter; never in archives or sync |
| `lan_link` | link ID | sealed pairwise LAN link key, label and creation time, bound by the local head's `lan_links_digest` (0013 §9.1); local-only, never in archives or sync |
| `lan_hint` | link ID | sealed unauthenticated endpoint hints and last-success time (0013 §9.2); local-only, never in archives or sync |

Server checkpoint fields and `sync_state` rows are optional server-mode state.
Creating or operating an offline or LAN-only vault MUST NOT require a server
identity, account, checkpoint or dummy server row. LAN exchanges use the same
verified objects/manifests and local commit/anchor path; the local-only peer
state is the `lan_link`/`lan_hint` schema of 0013 §9, which MUST NOT be
inferred from the server `sync_state` layout.

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
`qvault verify` and before creating an archive; it is not repeated on every
CLI command. Ignore unreferenced objects. Missing or mismatched data is an
integrity failure, never an empty record.

### 4. Resource budgets

4.1. Enforce bounds before allocating from untrusted lengths. Initial limits:
1 MiB padded record ciphertext; 64 KiB + framing per chunk ciphertext; 64 MiB
manifest; CBOR nesting 32; 4,096 fields per entry; 256 writers per clock; 256
concurrent heads per record; 50,000 record IDs including tombstones; 250,000
referenced objects; 1,048,576 clock components in total across a manifest's
heads, retained history and history floors; 1 GiB total referenced
ciphertext; 10 MiB per attachment;
256 KiB per text/byte field. Header/keyslot metadata is at most 64 KiB with at
most 64 slots. Apply SQLite length, column, expression, page-count and
execution-step limits. Stream object hashes; never load total ciphertext or all
attachments into RAM.

4.2. Budgets MUST be mutually consistent: the worst-case canonical manifest at
the maximum record, object, head and writer counts must fit the manifest limit.
The aggregate clock-component budget, not the per-clock writer limit times the
object count, bounds the clocks in that worst case. History retention (0007)
yields to the object and clock-component budgets; active heads, tombstones
and floors never do. A release gate (0012) checks this with a generated
worst-case vector.

4.3. Network listing pages are at most 8 MiB and aggregate upload/download
staging 2 GiB. A single object transfer is bounded by its own per-type limit
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
report success. Integrity failure aborts the whole candidate; never silently
omit a bad record.

5.3. Never write plaintext to DB pages, journals, temp files, logs or crash
reports. Archives are built by writing verified objects into a new file
(§6), never by copying or normalizing the live SQLite file, so local sync
state, writer identity, anchors, sessions, device bundles and quick slots
are never present to be removed.

### 6. Archive format

6.1. An archive (`.qvsnap`) is the only format for local snapshots, explicit
backups and file exchange (0005 §4, 0007 §3). It is a byte stream:

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

## Security Considerations

AEAD alone does not detect missing rows. Manifests detect omission relative to
an authenticated state; external anchors detect known rollback with the limits
in 0005. Physical deletion is not secure erasure on SSDs, copy-on-write storage
or backups. SQLite/CBOR are hostile parsers before authentication; the archive
format keeps attacker-supplied files away from the SQLite parser entirely and
authenticates archive content before decoding it. Ordinary active-file copying
is unsupported ([SQLite warning](https://www.sqlite.org/howtocorrupt.html)).

## Open Questions

1. Benchmark budgets on supported mobile devices before freezing the first
   format. Changes require documented policy/version updates.

## Changelog

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
