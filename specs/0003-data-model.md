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
where `kind ∈ { vault_meta, group, entry, attachment_meta }`. The `kind` is
part of the encrypted payload, so the server cannot tell groups from entries.

2.2. Payloads are serialized as **CBOR with integer keys**. Unknown keys MUST
be preserved when reading and re-writing a record (forward compatibility).

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

4.1. Groups nest arbitrarily. Clients MUST detect cycles (possible after a
merge) and re-parent the offending group under the root group.

4.2. If a group's parent is missing after a merge, the group is re-parented
under the root group ("orphan rescue"); nothing is dropped.

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

6.1. `attachment_meta` record: `{ entry, name, mime, size, chunk_count, content_hash }`.

6.2. Content is stored as encrypted chunks of 64 KiB (0004), each
authenticated with its index and the attachment ID, so chunks cannot be
reordered or swapped.

6.3. Maximum attachment size: 10 MiB (configurable per server for hosted
deployments).

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
2. Password generator settings: per vault or per device?

## Changelog

- 2026-10-14: Initial draft.
- 2026-10-14: Protected-field defaults (§5.3). Status → Accepted.
