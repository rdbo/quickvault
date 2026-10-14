# 0004 — Local Storage (Vault File)

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0002, 0003 |

## Summary

A vault is a single SQLite database file (`*.qvault`) whose rows are
individually encrypted with application-level AEAD. The file is
self-contained: master password (or recovery phrase) + file = full access.

## Specification

### 1. File

1.1. Extension `.qvault`. SQLite `application_id` set to a QuickVault-specific
constant; `user_version` holds the schema version.

1.2. Required pragmas: `secure_delete = ON`, `temp_store = MEMORY`,
`foreign_keys = ON`. Journal mode: `DELETE` (not WAL), so that a vault is a
single file safe to copy or sync with file-sync tools.

1.3. The client MUST hold an exclusive lock while writing and MUST detect
external modification (mtime + content hash of header row) before writing.

### 2. Schema (logical)

```sql
-- exactly one row
CREATE TABLE header (
  format_version   INTEGER NOT NULL,
  vault_id         BLOB    NOT NULL,   -- 16 bytes
  min_suite        INTEGER NOT NULL,
  kdf_suite        INTEGER NOT NULL,
  kdf_salt         BLOB    NOT NULL,
  header_mac       BLOB    NOT NULL    -- 0002 §7.3
);

CREATE TABLE keyslot (
  slot_id      BLOB PRIMARY KEY,
  slot_type    TEXT NOT NULL,          -- password | quick-unlock
                                       -- keyslots are never synced (0006)
  device_id    BLOB,                   -- quick-unlock only; never synced
  suite        INTEGER NOT NULL,
  wrapped_vk   BLOB NOT NULL
);

-- current version of every record
CREATE TABLE record (
  record_id    BLOB PRIMARY KEY,       -- 16 bytes
  suite        INTEGER NOT NULL,
  ciphertext   BLOB NOT NULL           -- nonce ‖ AEAD output
);

-- previous versions (0007)
CREATE TABLE record_history (
  record_id    BLOB NOT NULL,
  version_id   BLOB NOT NULL,          -- random
  suite        INTEGER NOT NULL,
  ciphertext   BLOB NOT NULL,
  PRIMARY KEY (record_id, version_id)
);

CREATE TABLE attachment_chunk (
  attachment_id BLOB NOT NULL,
  idx           INTEGER NOT NULL,
  suite         INTEGER NOT NULL,
  ciphertext    BLOB NOT NULL,
  PRIMARY KEY (attachment_id, idx)
);

-- per-remote sync bookkeeping (0005); contents encrypted
CREATE TABLE sync_state (
  remote_id    BLOB PRIMARY KEY,
  ciphertext   BLOB NOT NULL
);
```

2.1. Only IDs, suite numbers and slot types are plaintext. Timestamps, HLCs,
kinds and tombstone flags live inside the ciphertext.

### 3. Record encryption

3.1. Plaintext envelope (CBOR):
`{ kind, hlc, device_id, deleted, payload, prev_version_hash }`.

3.2. The envelope is padded with **Padmé** padding before encryption to hide
exact sizes (bounded overhead ≤ 12 %).

3.3. `ciphertext = nonce(24) ‖ XChaCha20-Poly1305(record_key(record_id), nonce, padded, aad)`
using the per-record key from 0002 §3.6,
with `aad = "qv/record" ‖ vault_id ‖ record_id ‖ suite`.

### 4. In-memory index

4.1. On unlock, all `record` rows are decrypted into an in-memory index
(search, tree) held by `qv-core`. Search never touches disk in plaintext.

4.2. On lock, the index MUST be zeroized and dropped (0008).

### 5. Writes

5.1. Every mutation is one SQLite transaction: move the current version to
`record_history`, write the new version, enforce history limits (0007).

5.2. Plaintext MUST NEVER be written to the database, temp files, logs or
crash reports.

## Security Considerations

- `secure_delete` overwrites freed pages, but filesystems with copy-on-write
  or SSD wear-leveling may keep old ciphertext. That is acceptable because
  old pages are ciphertext only.
- The header is authenticated after unlock; KDF minimums are enforced before
  the KDF runs (0002 §7.3).
- A tampered file (T5) can only cause a decryption failure, which MUST abort
  the operation for that record and be reported, never silently ignored.

## Open Questions

1. Is decrypting the whole vault at unlock acceptable for large vaults
   (10k+ entries) on mobile, or do we need lazy decryption?
2. Should attachments live in the same file (simple, portable) or in a
   sidecar (smaller main file for file-sync tools)? Current choice: same file.

## Changelog

- 2026-10-14: Initial draft.
- 2026-10-14: Status → Accepted.
