# 0004 — Local Storage (Vault File)

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0002, 0003 |

## Summary

A vault is a SQLite database of encrypted immutable objects and an authenticated
manifest. A closed consistent export is self-contained for decryption. Rollback
detection also needs an external remembered anchor. The active DB is private
application storage, not a file-sync target.

## Specification

### 1. Files and opening

1.1. Extension `.qvault`; fixed `application_id` and `user_version`.
Use owner-only file permissions (0600, private 0700 directory on Unix;
equivalent ACLs elsewhere). Reject symlinks, nonregular files and unexpected
path replacement. Export destinations are explicit user choices; new exports
and restored snapshots MUST NOT overwrite existing paths.

1.2. Set `secure_delete=ON`, `temp_store=MEMORY`, `foreign_keys=ON`,
`journal_mode=DELETE`, `synchronous=FULL`, `trusted_schema=OFF`, `mmap_size=0`.
Disable extensions, triggers, views and unused virtual-table features; enable
SQLite defensive mode. Register no secret-bearing application SQL functions.
Required hardening failures abort opening. Run bounded `quick_check` and
validate the exact released schema before reading vault tables. Unexpected
triggers, views, expression indexes or schema versions are errors.
See [SQLite security guidance](https://www.sqlite.org/security.html).

1.3. Serialize writers with a private per-vault process lock plus SQLite
transactions. Re-read the manifest head inside `BEGIN IMMEDIATE`; an unexpected
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
| `keyslot` | slot ID | type, device binding, KDF profile/salt, wrapping profile, wrapped VK |
| `object` | (key generation, object ID) | type, record/attachment ID, version ID or chunk index, profile, ciphertext |
| `manifest` | manifest hash | generation, profile, nonce and encrypted manifest |
| `head` | exactly one row | current manifest hash |
| `sync_state` | remote ID | encrypted verified remote base, cursor and pending publication |
| `anchor_update` | old anchor digest | authenticated complete anchor transition pending external durability |

2.1. A record may have several active versions. The manifest defines active,
historical and suppressed versions; a single record-ID primary key or upload
order cannot do so. Logical version IDs remain stable across reencryption.
Causality does not require retained historical payloads (0005). Object IDs are
random 128-bit IDs. A changed attachment chunk gets a new object ID.

2.2. Plaintext routing data is limited to random IDs, profiles, key generation,
sizes and local keyslot type/device binding. Header/keyslot metadata is MAC'd.
Kinds, clocks, names, dates, deletions and reference roles are encrypted. Public
server reference lists reveal object liveness as accepted leakage (0001).

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
object_id, data_profile]`. Routing fields must match the envelope.
An object ID is immutable within a key generation.

3.3. Chunks use the attachment key and AAD
`["qv/chunk/v1", vault_id, key_generation, attachment_id, object_id,
chunk_index, data_profile]`. Attachment metadata names ordered chunk objects,
total length and SHA-256 content hash. Verify each chunk's AEAD before release
and complete length/hash before accepting the attachment as complete.
Changed content uses new objects.

3.4. Encrypt each manifest with the VK-derived manifest key, fresh nonce and AAD
`["qv/manifest/v1", vault_id, key_generation, data_profile]`.
Its plaintext names sorted active (record ID, version ID, clock) heads,
retained history, permanent tombstones, history suppression frontiers, and
a sorted object reference list:
`[object_id, object_type, data_profile, ciphertext_length, SHA256(ciphertext)]`.
Each role resolves uniquely to a reference with matching authenticated routing.
Include a digest of portable header configuration (format, vault ID, generation
and stored-data/derivation minima). Password-slot descriptors are authenticated
inside complete keyslot records; local operational slot selection and quick
slots are bound by the local header MAC, not a remote configuration digest.
Local sync state uses a separate purpose key and is excluded from exports.
Manifests, checkpoints, sync state and anchors are not ordinary records.

3.5. `manifest_hash = SHA256(canonical manifest envelope including ciphertext)`.
`reference_digest = SHA256(canonical sorted reference list)`; publish the list
to the server for retention, and compare it to the decrypted manifest.
The manifest excludes itself, its checkpoint and local-only tables.
On unlock/import/sync verify exact reference membership, duplicates, lengths
and hashes. Ignore unreferenced objects. Authenticate all active record AEADs
before exposing views. Check retained history/chunk ciphertext completeness
immediately and their AEADs on use.

### 4. Resource budgets

4.1. Enforce bounds before allocating from untrusted lengths. Initial limits:
1 MiB padded record ciphertext; 128 KiB chunk ciphertext; 32 MiB manifest;
CBOR nesting 32; 4,096 fields per entry; 256 writers per clock; 256 concurrent
heads per record; 100,000 record IDs including tombstones; 1,000,000 referenced
objects; 1 GiB total referenced ciphertext; 10 MiB per attachment; 256 KiB per
text/byte field. Header/keyslot metadata is at most 64 KiB with at most 64 slots.
Apply SQLite length, column, expression, page-count and execution-step limits.
Stream object hashes; never load total ciphertext or all attachments into RAM.

4.2. Network pages are at most 8 MiB and aggregate upload/download staging
2 GiB; per-object limits also apply. Checkpoint pages contain at most 1,024
links. Group traversal is iterative, bounded by record count. Check counter
arithmetic. Known KDF profiles select exact work factors; unknown profiles fail
before any KDF. The server cannot supply arbitrary work factors.

4.3. Limits are local safety policy, not server-controlled values. A user may
explicitly select a documented larger local policy before retrying. Limits
fail without replacing accepted state or dropping causal metadata.

### 5. Unlock and writes

5.1. Validate SQLite, header bounds and profiles; unwrap VK; verify header MAC;
authenticate manifest, completeness and external anchor; verify active versions;
then build bounded metadata/search views. Protected values stay encrypted when
idle and are decrypted only into short-lived zeroizing buffers on demand.
Metadata and intermediate decoding buffers are confidential too (0008).

5.2. Each mutation is one transaction: store immutable objects, update
active/history references and suppression metadata, store the new manifest,
update head, persist outbox and anchor transition, then prune by references.
Commit durably, advance external anchor (0005 §5.4), then report success.
Integrity failure aborts the whole candidate; never silently omit a bad record.

5.3. Never write plaintext to DB pages, journals, temp files, logs or crash
reports. SQLite backup exports contain portable manifest, referenced objects
and password slot; remove local sync state, writer identity, anchors, sessions
and quick slots, then recompute the export header MAC. Export normalization
uses a private writable backup copy before validation and publication (0005 §4).

## Security Considerations

AEAD alone does not detect missing rows. Manifests detect omission relative to
an authenticated state; external anchors detect known rollback with the limits
in 0005. Physical deletion is not secure erasure on SSDs, copy-on-write storage
or backups. SQLite/CBOR are hostile parsers before authentication.
Ordinary active-file copying is unsupported
([SQLite warning](https://www.sqlite.org/howtocorrupt.html)).

## Open Questions

1. Benchmark budgets on supported mobile devices before freezing the first
   format. Changes require documented policy/version updates.

## Changelog

- 2026-10-14: Initial accepted encrypted-row design.
- 2026-10-15: Amendment: immutable multi-head objects, canonical manifests,
  external anchors, parser budgets, SQLite hardening and safe exports. Replace
  header/mtime checks and eager protected-value indexing.
