# 0003 — Data Model

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0002 |

## Summary

Defines the plaintext structures inside a vault: vault metadata, nested
groups, generic entries with typed fields, and attachments. Cryptographically
all of these are opaque payloads; types only exist so the UI knows how to
display them.

## Specification

### 1. Identifiers

1.1. Every object has a 128-bit **random** ID (UUIDv4). Time-ordered IDs
(UUIDv7) MUST NOT be used because they leak creation time to the server.

### 2. Records

2.1. Everything stored in a vault is a **record**: `{ id, kind, payload }`,
where `kind ∈ { vault_meta, group, entry, attachment_meta, password_keyslot }`. The `kind` is
part of the encrypted payload, so the server cannot tell groups from entries.

2.2. Payloads use deterministic CBOR with integer keys and budgets (0004).
Preserve unknown optional keys when rewriting. Unknown required features or
control kinds MUST fail closed. Manifests/checkpoints are separate containers,
not ordinary records. Whole-record causal versions are defined in 0005.

2.3. The manifest names exactly one vault metadata record, one password-keyslot
record and one root group. Root identity is fixed at vault creation and is not
changed by a metadata conflict. A password-keyslot payload contains an atomic
slot descriptor (KDF profile, salt, wrapping profile, nonce, wrapped VK and
portable slot ID); never merge its individual fields. Kind is immutable for a
record ID. Root, vault metadata and password-keyslot records cannot be deleted;
reject invalid control transitions rather than guessing replacements.

### 3. Vault metadata (one per vault)

| Field | Type | Notes |
|-------|------|-------|
| name | text | |
| description | text? | |
| root_group | ID | |
| settings | map | e.g. history depth, trash retention, password generator defaults |

### 4. Group

| Field | Type | Notes |
|-------|------|-------|
| parent | ID? | `null` only for the root group |
| name | text | |
| notes | text? | |
| icon | text? | built-in icon name |
| order | text | fractional index for stable manual ordering under concurrent edits |
| deleted_at | timestamp? | soft delete → trash (0007) |

4.1. Project group representatives (0005) into a display tree without writing
synthetic edits. Set the root parent to null; re-parent every non-root with a
missing/deleted parent to root. In each remaining directed parent cycle,
re-parent the lexicographically smallest group ID to root. Iterate in sorted
ID order, using bounded iterative traversal. Recompute from source versions on
every merge; traversal order must not affect the result.

4.2. Entries with missing/deleted groups appear in a recovered-items view under
root. Conflicted/deleted groups remain inspectable with their original parent
values. Display repair never deletes or rewrites source records. Depth-related
UI limits collapse presentation rather than dropping groups.

### 5. Entry

| Field | Type | Notes |
|-------|------|-------|
| group | ID | |
| type_hint | text | UI hint only: `login`, `note`, `card`, `ssh-key`, `identity`, `custom`, … |
| title | text | |
| fields | list<Field> | ordered |
| notes | text? | multi-line |
| icon | text? | |
| expires_at | timestamp? | |
| created_at / modified_at | timestamp | |
| deleted_at | timestamp? | soft delete → trash |

**Field**

| Field | Type | Notes |
|-------|------|-------|
| id | ID | stable, for UI handles (0008 §4) |
| name | text | e.g. "Username", "PIN" |
| kind | enum | `text`, `secret`, `url`, `email`, `totp`, `multiline`, `date` |
| value | text or bytes | |
| protected | bool | controls the secret boundary (0008 §4); see 5.3 |

5.1. `type_hint` MUST NOT change how data is encrypted or stored. An unknown
`type_hint` is shown as `custom`.

5.2. Templates (which fields a `login` has by default, etc.) are UI concerns,
defined in client code, not in the data.

5.3. **Protected vs. encrypted.** *Every* field is encrypted at rest and in
sync. `protected` only decides whether the UI may show the value directly.
Defaults: `secret` and `totp` fields are protected; usernames, URLs, emails
and other fields are not. The user can toggle `protected` per field.

5.4. **TOTP:** a `totp` field stores an `otpauth://` URI (RFC 6238 parameters).
Clients generate codes locally.

### 6. Attachments

6.1. `attachment_meta` record: `{ entry, name, mime, size, chunk_count,
chunk_object_ids, content_hash }`. Chunk IDs are an exact ordered list and
content_hash is SHA-256 of the complete plaintext content.

6.2. Content is stored as encrypted chunks of 64 KiB (0004), each
authenticated with its index and the attachment ID, so chunks cannot be
reordered or swapped.

6.3. Initial client maximum is 10 MiB. Server limits may be lower; they cannot
raise the client's local safety budget (0004). Filename/MIME are untrusted
metadata: sanitize explicit save paths, do not execute/open attachments or fetch
external resources automatically.

### 7. Tags

Not in v1. Nested groups cover organization. The CBOR model leaves room to add
`tags: list<text>` to entries later without migration.

## Security Considerations

- All fields, including titles, URLs and group names, are confidential (0001
  A2). Nothing in this spec is ever stored or transmitted in plaintext.
- Merge-induced inconsistencies (cycles, orphans) are repaired
  deterministically so that two devices converge to the same tree.

## Open Questions

1. Custom icons (user-uploaded images) — store them as attachments?
2. ~~Password generator settings: per vault or per device?~~ Per vault,
   proposed in 0010 §5.

## Changelog

- 2026-10-14: Initial draft.
- 2026-10-14: Protected-field defaults (§5.3). Status → Accepted.

- 2026-10-15: Amendment: causal atomic records, keyslot control kind, canonical
  CBOR, deterministic nonmutating tree projection and exact attachment references.
