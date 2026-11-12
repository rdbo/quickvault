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
where `kind ∈ { vault_meta, group, entry, attachment_meta, password_keyslot }`.
The `kind` is part of the encrypted payload, and object envelopes carry no
record ID, version or role (0004 §2.2), so the server can neither tell groups
from entries nor link objects to the same record.

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
| icon | text? | built-in icon name, or the app colour token `hue:<0–11>` (see 5.5) |
| order | text | fractional index for stable manual ordering under concurrent edits |
| deleted_at | timestamp? | soft delete → trash (0007) |
| delete_operation | ID? | optional shared deletion operation; CBOR key 6, bstr 16 UUIDv4 |

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
| type_hint | text | UI hint only: `login`, `note`, `card`, `wifi`, `ssh-key`, `identity`, `custom`, … |
| title | text | |
| fields | list<Field> | ordered |
| notes | text? | multi-line |
| icon | text? | as for groups (see 5.5) |
| expires_at | timestamp? | |
| created_at / modified_at | timestamp | |
| deleted_at | timestamp? | soft delete → trash |
| delete_operation | ID? | optional shared deletion operation; CBOR key 10, bstr 16 UUIDv4 |

`delete_operation` is present only when `deleted_at` is present. New deletion
edits use one random operation ID for all records deleted by that operation.
Restoration clears both fields. Older payloads without the operation ID remain
readable; timestamps never identify a recursive deletion (0007 §2.1).

**Field**

| Field | Type | Notes |
|-------|------|-------|
| id | ID | stable, for UI handles (0008 §4) |
| name | text | e.g. "Username", "PIN" |
| kind | enum | `text`, `secret`, `url`, `email`, `totp`, `multiline`, `date` |
| value | text or bytes | |
| protected | bool | controls the secret boundary (0008 §4); see 5.3 |

5.1. `type_hint` MUST NOT change how data is encrypted or stored. Clients
show `login`, `note`, `card` and `wifi` (compared lowercased) as their own
types and every other hint, including an empty one, as one *Other* type;
`custom` is the hint a client stores for a new Other item. The hint itself is
kept unchanged.

5.2. Templates (which fields a `login` has by default, etc.) are UI concerns,
defined in client code, not in the data.

5.3. **Protected vs. encrypted.** *Every* field is encrypted at rest and in
sync. `protected` only decides whether the UI may show the value directly.
Defaults: `secret` and `totp` fields are protected; usernames, URLs, emails
and other fields are not. The user can toggle `protected` per field.

5.4. **TOTP:** a `totp` field stores an `otpauth://` URI (RFC 6238 parameters).
Clients generate codes locally.

5.5. An `icon` value of the form `hue:<n>`, with `n` a decimal integer from 0
to 11, is a colour the user chose for the group or entry; the app shows it on
the item's tile. Any other value (absent, a built-in icon name, or unknown)
is shown with the automatic colour derived from the record ID. Clients keep it
unchanged unless the user picks a colour, and choosing "Automatic" removes only
a `hue:` value. The value is ordinary confidential metadata and changes nothing
about encryption or storage.

### 6. Attachments

6.1. `attachment_meta` record: `{ entry, name, mime, size, chunk_count,
chunk_object_ids, content_hash }`. Chunk IDs are an exact ordered list and
content_hash is SHA-256 of the complete plaintext content.

6.2. Content is stored as encrypted chunks of 64 KiB (0004), each
authenticated with its index and the attachment ID, so chunks cannot be
reordered or swapped. The final chunk is padded to full size.

6.3. Initial client maximum is 10 MiB. Server limits may be lower; they cannot
raise the client's local safety budget (0004). Filename/MIME are untrusted
metadata: sanitize explicit save paths, do not execute/open attachments or fetch
external resources automatically.

6.4. **In-app preview** (owner request, 2026-11-07). On the user's explicit
action, a client may show an attachment inside the app. It verifies the complete
content hash by streaming with bounded protected buffers before accepting a
preview, then reads individually authenticated ranges on demand, at most64 KiB
per application range buffer. Range reads alone do not establish the complete
content hash. Keep no detached vault key: every read remains bound to the exact
unlocked session and attachment version, and closing/navigating/locking revokes
the source. Retain at most a1 MiB text prefix, with truncation clearly shown;
never silently collect a whole large attachment. The type is identified from
the content's bytes, never from
the stored MIME or name, and only an allow-list is rendered:
- images: PNG, JPEG, GIF, WebP;
- audio: MP3, Ogg, WAV, FLAC, MP4 audio (M4A/AAC);
- video: MP4, WebM;
- UTF-8 text without NUL bytes, shown as text (never as markup).

SVG, HTML, PDF, scripts and every other type are not rendered. The plaintext
never touches the disk unless the user saves a copy: no temporary or cache
file, no external app, no remote fetch. Browser-compatible playback may use the
app's existing numeric loopback listener, with an unguessable per-preview route,
strict Host/origin/range checks, bounded headers/connections and exact CSP origin.
Do not reuse the edit transport's secret in media URLs. Responses are no-store;
the adapter writes protected chunks directly rather than making plaintext Vec
response copies. Malformed/multiple/unsatisfiable ranges fail416 without a full
content fallback. Media is on demand, with no autoplay and preload none.

Before automatic image decoding, inspect bounded PNG/JPEG/GIF/WebP dimension
headers. If the RGBA lower-bound size exceeds64 MiB or the dimensions cannot be
established within64 KiB, show size/dimensions where known and require explicit
"Load image" for that preview. Ordinary images need no extra confirmation.
File size alone is not a decoded-memory bound. Webview decoders still parse
untrusted bytes, a residual risk; framework and decoder copies follow 0008's
best-effort cleanup limits.

### 7. Tags

Not in v1. Nested groups cover organization. The CBOR model leaves room to add
`tags: list<text>` to entries later without migration.

### 8. Public password-slot projection and view metadata (0047)

8.1. The public password-slot descriptor is an allowlisted projection of the
encrypted keyslot payload: only integer keys 0–6 (slot ID, KDF profile,
salt, wrap profile, KEK commitment, nonce, wrapped VK). Canonically encode
those defined fields; with current profiles its encoded size is 171 bytes.
Unknown optional record keys remain encrypted and preserved on rewrites under
§2.2, but MUST NOT be copied into a newly written clear local slot, archive
password descriptor or LAN grant. Compare projections, not opaque whole-record
encodings, when binding a verified record to a public descriptor. Existing
stored header bytes remain authenticated as stored; do not silently project
or rewrite them before verifying their MAC.

8.2. View residency is separate from record validity (0004 §4.5). Compact head
summaries MUST preserve existing kind, representative, conflict, trash,
tombstone and tree projection semantics. Decode/validate each required head
without retaining all full head payloads simultaneously. Cache only the
non-protected metadata needed for views; protected fields and notes are not
searchable. Paging MUST NOT silently omit records, fields or conflicts.

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

- 2026-11-11: §5.1: standard hints include `wifi`; every other hint shows
  as one Other type instead of `custom` (owner request, plan 0051).
- 2026-11-09: Specify bounded verified preview streams and explicit expensive
  image-decode consent; retain attachment eligibility limits (plan0050).
- 2026-11-09: Define optional encrypted deletion-operation UUIDs at group key6
  and entry key10, independent of timestamps (QV-004, plan0050).
- 2026-11-09: Define allowlisted public slot projection and equivalent compact view metadata.

- 2026-10-14: Initial draft.
- 2026-10-14: Protected-field defaults (§5.3). Status → Accepted.

- 2026-10-15: Amendment: causal atomic records, keyslot control kind, canonical
  CBOR, deterministic nonmutating tree projection and exact attachment references.
- 2026-10-15: Security review: unlinkable object envelopes; padded final chunk.
- 2026-11-05: §4/§5 icon note and 5.5: the app colour token `hue:<0–11>`
  (plan 0040, owner request for chosen colours; owner-delegated format).
- 2026-11-07: §6.4 in-app preview of an allow-list of sniffed types,
  decrypted only into memory (owner request, plan 0044; details
  owner-delegated).
