# Plan 0007 — Data model, version vectors and merge

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-26 | 2026-10-26 | 0003; 0005 §1–2 (D5); 0007 §1.2, §2.2; 0004 §3.1–3.2, §4.1; 0008 §1.1; 0012 §1 |

## Intent

Roadmap 0002 phase 1.5. Create `qv-model`: the plaintext records of a vault
(vault metadata, groups, entries with fields, attachment metadata, the
password-keyslot record) as canonical CBOR with an integer-key registry and
unknown-key preservation; version vectors; the maximal-version merge with its
integrity checks, conflict representative and tombstone semantics; history
floors as data; the deterministic group-tree projection; and TOTP codes. This is
the model that storage (1.6–1.7), core (1.8) and sync (2.x) build on.

## Scope

**In scope:**
- New crate `crates/qv-model` (trusted client; depends on `qv-crypto` and
  `qv-encoding` only).
- ID handling: random UUIDv4 generation and validation for every model ID;
  new `VersionId`, `WriterId`, `FieldId`, `ObjectId`.
- Record version plaintext (0004 §3.2 shape) and the five payload kinds, each
  with exact encode/decode, budgets and unknown-key preservation.
- `Clock` (version vector) with its wire form, comparison, join and edit clock.
- Generic merge over versions, `merge_record`, `HistoryFloor`, representative
  and record status.
- Group-tree projection and entry placement (recovered-items view).
- TOTP: `otpauth://totp` parsing and RFC 6238 codes. The HMAC-based HOTP core
  goes into `qv-crypto` (new module `otp`), with the new dependency `sha1`.
- A `record_decode` fuzz target and its CI step.

**Out of scope:**
- Encryption of records, AAD, manifests, object references, history
  retention/pruning (choosing which history to keep), writer-state persistence
  and counter reservation: phases 1.6–1.7. This phase gives them pure functions.
- Generator defaults inside vault `settings` (0010 §5.1): phase 1.8, with their
  first consumer. Settings key 2 is reserved for them; unknown settings keys
  are preserved, so 1.8 adds them without migration.
- Fractional-index generation for group `order` (a UI/core concern; the model
  stores the text).
- Attachment content, chunking and chunk AAD: phase 1.11.
- Conflict resolution UX and "edit requires resolution of all heads" policy:
  qv-core (1.8) and phase 2.2. The model provides `Clock::for_edit`.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| 128-bit random UUIDv4 IDs; no UUIDv7 | 0003 §1.1 | Accepted | Generation sets the v4 version/variant bits; decoding rejects other IDs (see *Design*) |
| Records `{id, kind, payload}`; kinds; kind inside encrypted plaintext | 0003 §2.1 | Accepted | Record ID is not in the plaintext (it comes from the manifest role) |
| Canonical CBOR, integer keys, budgets; preserve unknown optional keys; unknown control kinds fail closed | 0003 §2.2, 0004 §3.1 | Accepted | |
| Keyslot payload is atomic; kind immutable; root, metadata and keyslot cannot be deleted; reject invalid control transitions | 0003 §2.3 | Accepted | `InvalidTransition` |
| Vault metadata, group, entry, field, attachment metadata fields | 0003 §3–6.1 | Accepted | Registry below |
| Protected flag; secret/totp default protected | 0003 §5.3 | Accepted | Defaults are a constructor helper; every value is encrypted anyway |
| `type_hint` is a hint; unknown shown as custom | 0003 §5.1 | Accepted | Stored as text |
| TOTP: `otpauth://` URI, RFC 6238, generated locally | 0003 §5.4 | Accepted | |
| Group projection: root parent null; missing/deleted parent → root; break each cycle at its smallest ID; sorted, bounded, iterative; order independent | 0003 §4.1 | Accepted | |
| Recovered-items view; projection never rewrites sources | 0003 §4.2 | Accepted | `EntryPlace::Recovered` |
| Record plaintext `{kind, version_id, clock, modified_at, deleted, payload}` | 0004 §3.2 | Accepted | Shape and encoding only; encryption is 1.7 |
| Budgets: 4,096 fields, 256 writers, 256 heads, 256 KiB per text/byte field, 1 MiB record, 10 MiB attachment, 50,000 records | 0004 §4.1 | Accepted | |
| Version: random ID, clock as sorted `[writer, positive counter]` pairs, zero omitted; writer IDs without time | 0005 §1.1 | Draft (D5) | |
| Edit clock: join all known heads, advance local writer; receipt never creates versions | 0005 §1.2 | Draft (D5) | `Clock::for_edit`; merge is pure |
| Never reuse counters; counter exhaustion needs a new ID | 0005 §1.3 | Draft (D5) | `CounterExhausted`; reservation itself is 1.7 |
| Dominance and concurrency; equal clocks with different IDs, or one ID for different content, are integrity errors | 0005 §1.4 | Draft (D5) | |
| Dates are display only | 0005 §1.5 | Draft (D5) | `modified_at` never used by merge |
| Union, dedupe, validate, drop strictly dominated; commutative/associative/idempotent; limits abort without change | 0005 §2.1–2.2 | Draft (D5) | |
| Multiple heads = conflict; no field merge; representative = largest version ID subject to deletion visibility | 0005 §2.3 | Draft (D5) | Reading of "deletion visibility" in *Design* |
| Soft and final deletion are causal versions; tombstones keep ID, version and clock; no resurrection; concurrent delete/edit stays a conflict | 0005 §2.5, 0007 §2.2 | Draft (D5) / Accepted | |
| Groups, metadata and keyslot follow the same rules; projection is not an edit | 0005 §2.6 | Draft (D5) | |
| History floor: monotonic vector, joined by max, suppresses historical versions at or below it, never hides heads or tombstones | 0007 §1.2 | Accepted | `HistoryFloor` as data |
| Decrypted payloads and metadata in zeroizing allocations, redacted Debug | 0008 §1.1 | Draft (D5) | |
| 0012 rows: Order-dependent merges, Old-date concurrent edits, Mixed credentials, Deleted-entry resurrection (model level) | 0012 §1 | Accepted | |

**Spec changes required:** None. The specs fix the fields and say "integer
keys"; they do not assign key numbers. This plan assigns them as development
values (the format is unstable until phase 1.16, roadmap invariant), documents
them in the crate docs, and the 1.16 format freeze records the frozen registry
in 0003/0004 (noted in the roadmap *Revisions*).

## Decisions needed

None. The following readings and format choices follow from the specs; each is
recorded here so the reviewer and owner can see them:

- **UUIDv4 is a type invariant.** Generated IDs are 16 random bytes with the
  RFC 9562 version (`byte[6] >> 4 == 4`) and variant (`byte[8] & 0xC0 == 0x80`)
  bits set. Decoding an ID without those bits is `Malformed`. This rejects
  time-ordered IDs (0003 §1.1) instead of only not generating them.
- **Deletion visibility (0005 §2.3, §2.5).** Each head is `Live`, `SoftDeleted`
  (payload `deleted_at` set) or `Final` (tombstone). The *live* representative
  is the largest version ID among live heads; the *trash* representative is the
  largest among soft-deleted heads, or, when the record is in trash only
  because of a final-deletion conflict, the largest live head (a tombstone has
  nothing to show). A record is in trash if any head is soft-deleted, or if a
  final tombstone is concurrent with a non-final head ("concurrent deletion and
  edit remain a conflict in trash", 0005 §2.5, 0007 §2.2). It is in the live
  view while any head is live. For the group projection, a group
  is deleted only when no head is live. This is a display reading: it never
  drops or rewrites a version, so nothing concurrent with a delete disappears.
  Whether the live view also flags or hides such a record is a UI choice for
  1.8/1.10.
- **No "required features" key.** v1 has no required features. Fail-closed
  behaviour comes from unknown control values: an unknown record kind, an
  unknown KDF/wrap profile in a keyslot. A future required feature arrives as a
  new kind or a new record AAD version, not as a key this plan would invent.
- **Optional keys are absent, never `null`.** `null` appears only where the
  spec has a nullable required value (group `parent`). This keeps exactly one
  encoding per value, so `encode(decode(x)) == x` for every accepted input.
- **Final tombstone** = `deleted: true`, the `kind`, and no `payload` key.
  `deleted: false` requires `payload`. Vault-metadata and keyslot tombstones are
  `InvalidTransition`.
- **Timestamps** are signed milliseconds since the Unix epoch (`i64`), display
  only.
- **Attachment ID = the `attachment_meta` record ID** (0003 §6.1 lists no
  separate attachment ID field; 0004 §3.3 keys chunks by attachment ID).
- **Unknown field kinds** are preserved as `FieldKind::Unknown(u64)`; display
  follows the field's `protected` flag, which already controls the secret
  boundary (0003 §5.3).
- **Entry `modified_at`** exists in both the record plaintext (0004 §3.2) and
  the entry payload (0003 §5). Both are kept as specified, written equal by
  the model's constructors, and not cross-checked on decode (dates are display
  only, 0005 §1.5).
- **TOTP bounds:** `totp` type only (`hotp` → `Unsupported`), SHA1/SHA256/
  SHA512, 6–8 digits, period 1–86,400 s, secret 1–256 bytes after base32
  decoding. These are local parsing bounds for a URI the user stored, not
  format rules.

## Design

**Components touched:**
- `crates/qv-model` (new; trusted; no frontend dependencies; depends on
  `qv-crypto` and `qv-encoding`). It parses **authenticated** plaintext: records
  reach it only after AEAD verification (1.7). The authors may still be any VK
  holder (another device or a hostile peer with VK), so every decode is
  strict and bounded.
- `crates/qv-crypto`: new module `otp` (HOTP/TOTP truncation over HMAC from
  reviewed crates), so primitive crates stay in qv-crypto. qv-model has no
  direct dependency on `hmac`, `sha1` or `sha2`.
- `fuzz/`: new `record_decode` target.

**Interfaces** (`qv-model` re-exports these from `lib.rs`):

```rust
// error.rs — no data in any variant; Display fixed strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)] #[non_exhaustive]
pub enum ModelError {
    Malformed,          // not canonical, missing/extra/ill-typed key, bad ID bits, bad clock. CLI 7
    Unsupported,        // unknown record kind or keyslot profile. CLI 1
    LimitExceeded,      // a 0004 §4.1 budget. CLI 9
    Integrity,          // merge identity violations; kind changed for a record ID. CLI 7
    InvalidTransition,  // deleted root / vault metadata / keyslot. CLI 7
    CounterExhausted,   // the writer's counter cannot advance. CLI 1
    Rng,                // OS RNG failure. CLI 1
    Internal,           // encoder failure or a bug. CLI 1
}
// From<qv_encoding::DecodeError> → Malformed; From<EncodeError> → Internal; From<RngError> → Rng.

// ids.rs
pub trait RandomId: Sized + Copy {
    fn generate() -> Result<Self, ModelError>;               // OS RNG + v4 bits
    fn from_bytes(bytes: [u8; 16]) -> Result<Self, ModelError>; // checks v4 bits
    fn to_bytes(&self) -> [u8; 16];
}
// Implemented for qv_crypto::{VaultId, RecordId, AttachmentId, SlotId} and for:
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)] pub struct VersionId([u8; 16]);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)] pub struct WriterId([u8; 16]);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)] pub struct FieldId([u8; 16]);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)] pub struct ObjectId([u8; 16]);
// Private fields: only RandomId constructs them, so the v4 invariant holds.
pub use qv_crypto::{AttachmentId, RecordId, SlotId, VaultId};
pub fn attachment_id(record: RecordId) -> AttachmentId; // same bytes

// time.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i64); // ms since the Unix epoch; display only

// text.rs
pub struct Text(Zeroizing<String>);   // metadata text; ≤ MAX_TEXT_BYTES; redacted Debug; no Display/Clone/PartialEq
impl Text { pub fn new(s: &str) -> Result<Self, ModelError>; pub fn expose(&self) -> &str; }
pub enum FieldValue { Text(SecretText), Bytes(SecretBytes) } // locked (qv-crypto memory)
pub struct SecretText(SecretBytes);   // valid UTF-8 by construction; redacted Debug
impl SecretText { pub fn new(s: &str) -> Result<Self, ModelError>; pub fn expose_secret(&self) -> &str; }
pub struct Extensions(Vec<(i64, RawValue)>); // unknown keys, kept verbatim; Default; redacted Debug
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

// clock.rs
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Clock { /* Vec<(WriterId, u64)>: strictly ascending by writer, counters ≥ 1, ≤ 256 */ }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Causality { Equal, Before, After, Concurrent }
pub const MAX_WRITERS: usize = 256;
impl Clock {
    pub fn new() -> Self;                                         // zero vector
    pub fn from_pairs(pairs: Vec<(WriterId, u64)>) -> Result<Self, ModelError>; // validates
    pub fn get(&self, writer: WriterId) -> u64;                   // 0 if absent
    pub fn pairs(&self) -> &[(WriterId, u64)];
    pub fn is_empty(&self) -> bool;
    pub fn compare(&self, other: &Clock) -> Causality;
    pub fn dominates(&self, other: &Clock) -> bool;               // compare == After
    pub fn join(&self, other: &Clock) -> Result<Clock, ModelError>; // LimitExceeded past 256
    /// Join of all `heads`, then `writer` set to `counter`. `counter` comes from
    /// the durable reservation (1.7) and must exceed the joined component
    /// (else Integrity; CounterExhausted if the joined component is u64::MAX).
    pub fn for_edit<'a>(heads: impl IntoIterator<Item = &'a Clock>, writer: WriterId, counter: u64)
        -> Result<Clock, ModelError>;
}

// record.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind { VaultMeta, Group, Entry, AttachmentMeta, PasswordKeyslot }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deletion { Live, SoftDeleted, Final }
pub struct RecordVersion {               // redacted Debug; no Clone/PartialEq
    pub version_id: VersionId,
    pub clock: Clock,                    // nonempty for a version
    pub modified_at: Timestamp,
    pub body: RecordBody,
    pub ext: Extensions,
}
pub enum RecordBody { Live(Payload), Tombstone(RecordKind) }
pub enum Payload { VaultMeta(VaultMeta), Group(Group), Entry(Entry), AttachmentMeta(AttachmentMeta), PasswordKeyslot(Keyslot) }
impl RecordVersion {
    pub fn kind(&self) -> RecordKind;
    pub fn deletion(&self) -> Deletion;  // Final for Tombstone; SoftDeleted if group/entry deleted_at is set
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ModelError>; // canonical; budgets checked
    pub fn decode(input: &[u8]) -> Result<Self, ModelError>;         // strict; budgets before allocation
    pub fn check_root(&self) -> Result<(), ModelError>;              // root group: Live, parent null, no deleted_at
}

// payload/*.rs — public fields; every struct also has `pub ext: Extensions`.
pub struct VaultMeta { pub name: Text, pub description: Option<Text>, pub root_group: RecordId, pub settings: Settings, pub ext: Extensions }
pub struct Settings { pub history_depth: Option<u32>, pub trash_retention_days: Option<u32>, pub ext: Extensions }
impl Settings { pub fn history_depth_or_default(&self) -> u32 /* 10 */; pub fn trash_retention_days_or_default(&self) -> u32 /* 30 */; }
pub struct Group { pub parent: Option<RecordId>, pub name: Text, pub notes: Option<Text>, pub icon: Option<Text>,
                   pub order: Text, pub deleted_at: Option<Timestamp>, pub ext: Extensions }
pub struct Entry { pub group: RecordId, pub type_hint: Text, pub title: Text, pub fields: Vec<Field>,
                   pub notes: Option<Text>, pub icon: Option<Text>, pub expires_at: Option<Timestamp>,
                   pub created_at: Timestamp, pub modified_at: Timestamp, pub deleted_at: Option<Timestamp>, pub ext: Extensions }
pub struct Field { pub id: FieldId, pub name: Text, pub kind: FieldKind, pub value: FieldValue, pub protected: bool, pub ext: Extensions }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind { Text, Secret, Url, Email, Totp, Multiline, Date, Unknown(u64) }
impl FieldKind { pub fn protected_by_default(self) -> bool; } // Secret, Totp → true (0003 §5.3)
pub struct AttachmentMeta { pub entry: RecordId, pub name: Text, pub mime: Text, pub size: u64,
                            pub chunk_object_ids: Vec<ObjectId>, pub content_hash: [u8; 32], pub ext: Extensions }
// chunk_count is encoded from chunk_object_ids.len() and checked on decode.
pub const CHUNK_SIZE: u64 = 64 * 1024; pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;
pub struct Keyslot { pub slot: qv_crypto::PasswordSlot, pub ext: Extensions }

// merge.rs
pub trait Versioned {
    fn version_id(&self) -> VersionId;
    fn clock(&self) -> &Clock;
    fn deletion(&self) -> Deletion;
    /// Same logical content (for RecordVersion: identical canonical encodings).
    fn same_version(&self, other: &Self) -> bool;
}
pub const MAX_HEADS: usize = 256;
pub struct Merged<V> { /* heads and dominated, each sorted by version ID */ }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View { Live, Trash }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordStatus { pub live: bool, pub in_trash: bool, pub conflict: bool, pub finally_deleted: bool }
pub fn merge<V: Versioned>(versions: impl IntoIterator<Item = V>) -> Result<Merged<V>, ModelError>;
pub fn merge_record(versions: impl IntoIterator<Item = RecordVersion>) -> Result<Merged<RecordVersion>, ModelError>; // + one kind
impl<V: Versioned> Merged<V> {
    pub fn heads(&self) -> &[V];
    pub fn dominated(&self) -> &[V];
    pub fn into_parts(self) -> (Vec<V>, Vec<V>);
    pub fn is_conflict(&self) -> bool;                 // more than one head
    pub fn representative(&self, view: View) -> Option<&V>;
    pub fn status(&self) -> RecordStatus;
    /// Dominated versions split into (history, suppressed) by the floor (0007 §1.2).
    pub fn split_history(&self, floor: &HistoryFloor) -> (Vec<&V>, Vec<&V>);
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HistoryFloor(Clock);
impl HistoryFloor {
    pub fn new(clock: Clock) -> Self; pub fn clock(&self) -> &Clock;
    pub fn join(&self, other: &HistoryFloor) -> Result<HistoryFloor, ModelError>;
    pub fn suppresses(&self, clock: &Clock) -> bool;   // clock ≤ floor (Equal or Before)
}

// tree.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupNode { pub parent: Option<RecordId>, pub live: bool }
impl GroupNode { pub fn from_merged(m: &Merged<RecordVersion>) -> Result<GroupNode, ModelError>; } // Malformed if not groups
pub struct GroupTree { /* parents of live groups (root → None), repaired set */ }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryPlace { Group(RecordId), Recovered }
pub fn project_groups(root: RecordId, groups: &BTreeMap<RecordId, GroupNode>) -> Result<GroupTree, ModelError>;
impl GroupTree {
    pub fn parent(&self, group: RecordId) -> Option<Option<RecordId>>; // None: not in the tree
    pub fn children(&self, group: RecordId) -> Vec<RecordId>;          // sorted
    pub fn is_repaired(&self, group: RecordId) -> bool;
    pub fn place_entry(&self, group: RecordId) -> EntryPlace;
    pub fn len(&self) -> usize;
}

// totp.rs
pub struct Totp { /* SecretBytes key, OtpAlgorithm, digits, period */ } // redacted Debug
#[derive(Clone, Copy, Debug, PartialEq, Eq)] #[non_exhaustive]
pub enum TotpError { InvalidUri, Unsupported, BeforeEpoch, Internal }
impl Totp {
    pub fn parse(uri: &[u8]) -> Result<Self, TotpError>;
    pub fn code_at(&self, at: Timestamp) -> Result<qv_crypto::OtpCode, TotpError>;
    pub fn seconds_remaining(&self, at: Timestamp) -> Result<u32, TotpError>;
    pub fn algorithm(&self) -> qv_crypto::OtpAlgorithm; pub fn digits(&self) -> u32; pub fn period(&self) -> u32;
}

// qv-crypto otp.rs (re-exported from qv-crypto's lib.rs)
#[derive(Clone, Copy, Debug, PartialEq, Eq)] #[non_exhaustive]
pub enum OtpAlgorithm { Sha1, Sha256, Sha512 }
pub struct OtpCode { /* SecretArray<8>, len */ } // redacted Debug; no Clone/Display/PartialEq
impl OtpCode { pub fn expose_secret(&self) -> &str; }
/// RFC 4226 HOTP: HMAC(key, counter_be), dynamic truncation, mod 10^digits,
/// zero-padded. digits 6..=8, else Internal (the caller validates).
pub fn hotp(key: &[u8], algorithm: OtpAlgorithm, counter: u64, digits: u32) -> Result<OtpCode, CryptoError>;
```

**Integer-key registry** (development values; frozen in 1.16). "req" = key
must be present; "opt" = present iff the value exists. Every map also keeps
unknown keys verbatim in `ext`.

| Map | Key | Field | CBOR | |
|-----|-----|-------|------|---|
| Record version | 0 | kind | uint: 0 vault_meta, 1 group, 2 entry, 3 attachment_meta, 4 password_keyslot; other → `Unsupported` | req |
| | 1 | version_id | bstr 16 (v4) | req |
| | 2 | clock | array of `[bstr 16 writer, uint ≥ 1]`, strictly ascending by writer bytes, 1–256 pairs | req |
| | 3 | modified_at | int (ms) | req |
| | 4 | deleted | bool | req |
| | 5 | payload | map of the kind's payload | iff `deleted` is false |
| Vault meta | 0 name text req · 1 description text opt · 2 root_group bstr 16 req · 3 settings map req | | | |
| Settings | 0 history_depth uint (u32) opt · 1 trash_retention_days uint (u32) opt · 2 reserved (generator defaults, 1.8) | | | |
| Group | 0 parent bstr 16 or null req · 1 name text req · 2 notes text opt · 3 icon text opt · 4 order text req · 5 deleted_at int opt | | | |
| Entry | 0 group bstr 16 req · 1 type_hint text req · 2 title text req · 3 fields array req · 4 notes opt · 5 icon opt · 6 expires_at int opt · 7 created_at int req · 8 modified_at int req · 9 deleted_at int opt | | | |
| Field | 0 id bstr 16 req · 1 name text req · 2 kind uint req (0 text, 1 secret, 2 url, 3 email, 4 totp, 5 multiline, 6 date; others preserved) · 3 value text or bstr req · 4 protected bool req | | | |
| Attachment meta | 0 entry bstr 16 req · 1 name text req · 2 mime text req · 3 size uint req · 4 chunk_count uint req · 5 chunk_object_ids array of bstr 16 req · 6 content_hash bstr 32 req | | | |
| Keyslot | 0 slot_id bstr 16 req · 1 kdf_profile uint (u16) req · 2 kdf_salt bstr 32 req · 3 wrap_profile uint (u16) req · 4 kek_commit bstr 32 req · 5 nonce bstr 24 req · 6 wrapped_vk bstr 48 req | | | |

Decode checks, in addition to the table: input ≤ `MAX_RECORD_BYTES` before
`Decoder::new`; every text and byte value ≤ `MAX_TEXT_BYTES` before copying;
field count ≤ 4,096 and chunk list ≤ `MAX_ATTACHMENT_BYTES / CHUNK_SIZE` before
`Vec::with_capacity`; unique field IDs per entry; unique chunk object IDs;
`chunk_count == chunk_object_ids.len() == ceil(size / CHUNK_SIZE)`;
`size ≤ MAX_ATTACHMENT_BYTES` (else `LimitExceeded`); integer fields that do
not fit their Rust type → `Malformed`; known profile IDs via
`PasswordKdfProfile::from_id`/`PasswordWrapProfile::from_id` (unknown →
`Unsupported`); a vault-meta or keyslot tombstone → `InvalidTransition`;
a version clock that is empty → `Malformed`. `encode` applies the same budgets
and fails with the same variants, so the model never writes what it would
reject.

**Data and control flow:**
- **Decode:** length bound → `qv_encoding::Decoder::new` (whole-input
  validation, depth 32) → typed reads by ascending key (the codec guarantees
  order) → required-key and cross-field checks. Unknown keys go to
  `Extensions` via `raw_value`. Text values are copied straight into `Text` /
  `SecretText`; byte values into `SecretBytes`.
- **Encode:** `Encoder::map` with known entries plus `raw_entry` for each
  extension; canonical by construction. Property: `encode(decode(x)) == x` for
  every accepted `x`.
- **Merge** (`merge`): (1) dedupe by version ID in a `BTreeMap`; the same ID
  with `!same_version` → `Integrity`. (2) Equal clocks with different IDs →
  `Integrity` (a `HashMap<Clock, VersionId>` pass). (3) Sort the unique
  versions by the sum of their counters (as `u128`) descending, ties by
  version ID. A strictly dominating clock has a strictly larger sum, so when a
  version is processed every version that could dominate it has already been
  seen; it is a head iff no current head dominates it (transitivity covers
  dominated dominators). Heads only grow, so the merge aborts with
  `LimitExceeded` as soon as there would be 257 heads. Cost
  O(n · 256 · 256). (4) Return heads and dominated, each sorted by version
  ID. Pure: no new versions, no timestamps, nothing re-encrypted.
- `merge_record` checks that every input has the same `kind()` (else
  `Integrity`) before `merge`.
- **Representative:** `View::Live` → largest version ID among `Live` heads;
  `View::Trash` → largest among `SoftDeleted` heads, else (final-deletion
  conflict) largest `Live` head; `None` when the record is not in that view.
  `RecordStatus`: `live` = any live head; `in_trash` = any soft-deleted head,
  or a `Final` head together with a non-`Final` one; `conflict` = more than
  one head; `finally_deleted` = every head `Final`.
- **Floors:** `split_history` puts a dominated version in `suppressed` iff
  `floor.suppresses(clock)`; heads are never filtered.
- **Projection:** input is a `BTreeMap`, so iteration is in sorted ID order.
  At most 50,000 groups (`LimitExceeded`). Live non-root groups start with
  their own parent, replaced by root when it is `None`, missing, not live, or
  itself; the root's parent is `None` (root is in the tree even if absent from
  the map). Cycle breaking: for each group in sorted order, walk parents
  iteratively with states unvisited / on-path / done, at most `len` steps;
  reaching an on-path node closes a cycle, whose smallest ID is re-parented to
  root and marked repaired. Each cycle of the parent graph is broken exactly
  at its smallest member, so the result does not depend on traversal order.
  `place_entry` → `Group(g)` if `g` is in the tree, else `Recovered`.
- **TOTP:** `parse`: scheme `otpauth` and type `totp` case-insensitive, the
  label skipped up to `?`, parameters split on `&` into `name=value` with
  names compared case-insensitively and values percent-decoded; a repeated
  known parameter → `InvalidUri`; unknown parameters ignored. `secret` is
  RFC 4648 base32 (case-insensitive, `=` padding optional), decoded straight
  into `SecretBytes`; the decoded intermediate buffers are `Zeroizing`.
  `code_at`: seconds = `ms.div_euclid(1000)`, negative → `BeforeEpoch`,
  counter = seconds / period, then `qv_crypto::hotp`.
- No disk writes, no durability ordering in this phase.

**Secrets and hostile input:**
- Field values: `SecretText`/`SecretBytes` (locked, zeroizing). Metadata text
  (names, titles, notes, URLs-as-names, icons, MIME): `Text`
  (`Zeroizing<String>`, never grown after construction). Unknown entries:
  `RawValue` (zeroizing). Encoded output: `Zeroizing<Vec<u8>>` from the codec.
  TOTP key: `SecretBytes`; codes: `OtpCode` in a `SecretArray`.
- No payload type derives `Debug`, `Clone` or `PartialEq`; `Debug` is
  redacted for every type that holds text or values. IDs, clocks, kinds and
  timestamps are not secrets and derive normally.
- Every count and length is bounded before allocation; decoding never panics
  (fuzz target and a proptest over arbitrary and mutated inputs).
- Errors carry no data.

**Errors:** `ModelError` (CLI mapping in its rustdoc and above);
`TotpError` (all CLI 1, shown next to the field). `qv-crypto` reuses
`CryptoError::Internal` for out-of-range HOTP digits.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| `sha1 =0.11.0` (`default-features = false`; `zeroize` feature if offered, matching `sha2`) | HMAC-SHA1 for RFC 6238 TOTP (the most common otpauth algorithm). Roadmap candidate table, phase 1.5 | None reasonable: SHA1 TOTP is what services issue; `sha2`/`hmac` already cover SHA256/512 | RustCrypto, `MIT OR Apache-2.0`; same `digest 0.11`/`cpufeatures 0.3` as `sha2 0.11.1` already in the lock. Expect one `cargo vet` exemption (no imported audit for the 0.11 line) |

`qv-crypto` becomes a workspace dependency (`path`, `=0.0.0`) for qv-model.
Dev-only: `proptest` (already in the workspace).

## Steps

### Step 1 — Crate, errors, IDs, time and text types

- [x] **Do:** Add `crates/qv-model` (workspace package fields, `[lints]
  workspace = true`, deps `qv-crypto`, `qv-encoding`, `zeroize`; dev
  `proptest`) and `qv-crypto` to `[workspace.dependencies]`. Write `error.rs`,
  `ids.rs` (`RandomId` for the four qv-crypto IDs and the four new ones,
  `attachment_id`), `time.rs`, `text.rs` (`Text`, `SecretText`, `FieldValue`,
  `Extensions`, the two byte limits) and crate docs (purpose, trust boundary,
  the error → CLI table). Tests: generated IDs have the v4 bits (1,000
  draws) and differ; `from_bytes` rejects a UUIDv7-shaped ID, a wrong variant
  and all-zero bytes; `Text::new` at exactly 256 KiB passes and one byte more
  is `LimitExceeded`; redacted `Debug` for `Text`, `SecretText`, `FieldValue`,
  `Extensions`; error strings are fixed; `compile_fail` doctests (with passing
  twins) for `Text` `.clone()` and `==`.
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/qv-model/{Cargo.toml,src/lib.rs,src/error.rs,src/ids.rs,src/time.rs,src/text.rs}`.
- **Done when:** tests pass; clippy clean (allow the usual `dead_code` until
  later steps only if logged, as in plans 0004/0005).
- **Verify:** `cargo test --locked -p qv-model`

### Step 2 — Version vectors

- [x] **Do:** `clock.rs` per *Interfaces*, plus crate-private
  `encode_clock(&Clock, &mut Encoder)` / `decode_clock(&mut Decoder) ->
  Result<Clock, ModelError>` (the pair-array wire form; pair count ≤ 256
  checked before allocating). Tests: `from_pairs` rejects unsorted, duplicate
  writer, zero counter and 257 pairs (exact variants); wire form golden bytes
  for a two-writer clock; decode rejects a CBOR map, a 3-element pair, a
  negative or zero counter, a 15-byte writer and descending writers; every
  `Causality` case including missing components as zero; `join` is the
  componentwise max and fails past 256 writers; `for_edit` joins three heads
  and sets the writer, rejects a counter not above the joined component
  (`Integrity`) and a joined `u64::MAX` (`CounterExhausted`). Proptests:
  `compare` is antisymmetric and consistent with `join` (`a ≤ a ⊔ b`), `join`
  is commutative, associative and idempotent, and decode∘encode is identity.
- **Files:** `crates/qv-model/src/{clock.rs,lib.rs}`.
- **Done when:** tests pass with exact variants.
- **Verify:** `cargo test --locked -p qv-model clock`

### Step 3 — Record version, codec helpers, vault metadata and keyslot

- [x] **Do:** `record.rs` (envelope keys 0–5, `RecordKind`, `Deletion`,
  `RecordBody`, `Payload`, `encode`/`decode`, `check_root`), crate-private
  `codec.rs` helpers (read a bounded text/bytes/ID/u32/u16/timestamp; collect
  unknown keys; reject `null` for optional keys), `payload/vault_meta.rs`
  (with `Settings`) and `payload/keyslot.rs`, following the registry and the
  decode checks. Group, entry and attachment payloads are added in step 4, so
  until then their kinds decode as `Unsupported` (logged; replaced in step 4).
  Tests: golden bytes for a minimal vault-meta version and a keyslot version;
  round trip with unknown keys at the envelope, payload and settings levels
  (byte-for-byte); missing each required key → `Malformed`; `payload` present
  on a tombstone or absent on a live version → `Malformed`; `null`
  description → `Malformed`; unknown kind 5 → `Unsupported`; unknown KDF
  profile → `Unsupported`; vault-meta and keyslot tombstones →
  `InvalidTransition`; input over 1 MiB → `LimitExceeded` before decoding;
  settings defaults (10, 30) when absent.
- **Files:** `crates/qv-model/src/{record.rs,codec.rs,payload/mod.rs,payload/vault_meta.rs,payload/keyslot.rs,lib.rs}`.
- **Done when:** tests pass.
- **Verify:** `cargo test --locked -p qv-model record`

### Step 4 — Group, entry, field and attachment payloads

- [x] **Do:** `payload/group.rs`, `payload/entry.rs` (with `Field`,
  `FieldKind`), `payload/attachment.rs` per the registry and checks;
  `RecordVersion::deletion` for `deleted_at`; `check_root`. Tests: golden bytes
  for an entry with a text, a secret (bytes value) and a TOTP field; round trip
  with unknown keys inside a field and an entry; 4,096 fields pass and 4,097 →
  `LimitExceeded` (checked from the array header, before allocation);
  duplicate field IDs → `Malformed`; a field value of 256 KiB + 1 →
  `LimitExceeded`; unknown field kind 9 round-trips as `Unknown(9)`;
  `protected_by_default`; attachment: `size` 0 with no chunks, exactly 64 KiB
  (1 chunk) and 64 KiB + 1 (2 chunks) pass; a count/list/size mismatch,
  duplicate chunk IDs → `Malformed`; 10 MiB + 1 → `LimitExceeded`; `check_root`
  rejects a root with a parent, with `deleted_at`, or as a tombstone; deletion
  states for live, soft-deleted and tombstone versions of each kind. Proptest:
  for arbitrary bytes and for single-byte mutations of valid encodings,
  `decode` never panics, and whenever it succeeds `encode(decode(x)) == x`.
- **Files:** `crates/qv-model/src/{payload/group.rs,payload/entry.rs,payload/attachment.rs,payload/mod.rs,record.rs,lib.rs}`.
- **Done when:** tests pass; the step 3 `Unsupported` placeholder is gone.
- **Verify:** `cargo test --locked -p qv-model record payload`

### Step 5 — Merge, representative, status and history floors

- [x] **Do:** `merge.rs` per *Interfaces* and *Data and control flow*;
  `Versioned for RecordVersion` (`same_version` compares canonical encodings;
  an encoding failure counts as different, so it fails closed as
  `Integrity`). Tests with hand-built versions: duplicate delivery of the
  same version is idempotent; same version ID with a different clock or
  payload → `Integrity`; equal clocks with different IDs → `Integrity`, also
  when both would be dominated; a strictly dominated version moves to
  `dominated`; three concurrent versions stay three heads; 256 concurrent
  heads pass and 257 → `LimitExceeded`; 300 concurrent versions plus one
  version dominating all → one head (the limit applies to the result, not to
  intermediate state); `merge_record` with mixed kinds → `Integrity`;
  representative and status for live/soft/final mixes (largest ID per view;
  `None` when the view is empty); `HistoryFloor::join` is the componentwise
  max; `split_history` with a floor equal to, below and concurrent with a
  dominated version; a floor covering a head clock does not hide the head.
- **Files:** `crates/qv-model/src/{merge.rs,lib.rs}`.
- **Done when:** tests pass with exact variants.
- **Verify:** `cargo test --locked -p qv-model merge`

### Step 6 — Merge properties and the 0012 rows

- [x] **Do:** In `merge.rs` tests, a proptest history generator: 2–4 writers,
  up to 24 versions; each new version's clock is `for_edit` over a random
  subset of existing versions (its "known heads") with the writer's next
  counter, so histories are honest by construction. Properties: (a) any
  permutation of the versions gives identical head and dominated ID lists;
  (b) regrouping: `merge(merge(A).heads ∪ merge(B).heads) == merge(A ∪ B)` for
  heads, for random splits; (c) duplicate delivery (each version repeated 1–3
  times) changes nothing; (d) every head is an input version, byte-identical
  (no synthetic version); (e) heads are pairwise concurrent and every input is
  ≤ some head. Named scenario tests: **Old-date concurrent edits** (a
  concurrent version with an older `modified_at` survives); **Mixed
  credentials** (two concurrent entry versions with different
  username/password/TOTP: both heads keep their own complete field sets, and
  the representative's encoding equals one input exactly); **Deleted-entry
  resurrection** (a tombstone dominating an old edit wins regardless of
  delivery order or a years-older `modified_at`; a tombstone concurrent with an
  edit stays a two-head conflict with `in_trash` true, `live` true,
  `finally_deleted` false, and both representatives the live head; an old covered version delivered later lands in `dominated`,
  or `suppressed` under a covering floor); a late edit after a resolution that
  did not see it stays concurrent with the resolution.
- **Files:** `crates/qv-model/src/merge.rs`.
- **Done when:** properties pass at the default proptest case count; the four
  scenario tests pass.
- **Verify:** `cargo test --locked -p qv-model merge`

### Step 7 — Group-tree projection

- [x] **Do:** `tree.rs` per *Interfaces* and *Data and control flow*,
  including `GroupNode::from_merged` (live representative's parent; `live` =
  status.live; non-group payload → `Malformed`). Tests: orphan (missing
  parent) → root, repaired; deleted parent → root; a non-root with `parent:
  None` → root; self-parent → root; a 2-cycle and a 3-cycle each broken at the
  smallest ID only, other members keep their parents; two disjoint cycles plus
  a tail leading into one; root with a non-null parent in its record still has
  parent `None`; a 50,000-deep chain finishes (iterative, no recursion) and
  50,001 groups → `LimitExceeded`; `place_entry` for a live, a deleted and a
  missing group; `children` sorted. Proptest: random parent maps over up to 64
  groups (random liveness) → every tree node reaches root in at most `len`
  steps; non-repaired live groups whose parent is live and non-cyclic keep it;
  building the input map from a shuffled list gives an identical tree; the
  result is identical after removing and re-inserting nodes (no hidden
  insertion-order state).
- **Files:** `crates/qv-model/src/{tree.rs,lib.rs}`.
- **Done when:** tests pass.
- **Verify:** `cargo test --locked -p qv-model tree`

### Step 8 — HOTP in qv-crypto and TOTP in qv-model

- [x] **Do:** Add `sha1` (workspace pin, `default-features = false`) to
  qv-crypto. Run `cargo deny check`, then `cargo vet` (regenerate imports,
  exempt if no audit is imported, prune) with the sandbox tools; log the
  licence and vet status. `qv-crypto/src/otp.rs`: `OtpAlgorithm`, `OtpCode`,
  `hotp` (MAC output in a `Zeroizing` buffer; `ctutils` not needed: the code
  is shown to the user, not compared). Vectors from the RFC text itself
  (fetch `https://www.rfc-editor.org/rfc/rfc4226.txt` and `rfc6238.txt`;
  transcribe, do not recall): `tests/vectors/rfc4226-hotp.txt` (Appendix D,
  counters 0–9) and `tests/vectors/rfc6238-totp.txt` (Appendix B, all 18 rows;
  the SHA-256 and SHA-512 seeds are the 32- and 64-byte ones of the RFC's
  reference code, not the 20-byte seed of the table text — record this in a
  `#` comment, see RFC 6238 errata). `qv-model/src/totp.rs` per *Interfaces*
  with a crate-private base32 decoder. Tests: all RFC 6238 rows through
  `Totp::parse` of an `otpauth://totp/...` URI with the base32 seed and
  `algorithm`/`digits=8`/`period=30`, and through `code_at`; defaults (SHA1,
  6 digits, 30 s); `seconds_remaining`; case-insensitive scheme, names,
  algorithm and base32; `%3D` padding; `hotp` type → `Unsupported`; SHA3,
  digits 5 and 9, period 0 and 86,401 → `Unsupported`; missing secret, bad
  base32 character, repeated `secret`, bad percent escape, non-numeric digits
  → `InvalidUri`; 257-byte secret → `InvalidUri`; `Timestamp(-1)` →
  `BeforeEpoch`; redacted `Debug` for `Totp` and `OtpCode`; `hotp` with digits
  5 → `Internal`.
- **Files:** `Cargo.toml`, `Cargo.lock`, `supply-chain/*`, `crates/qv-crypto/{Cargo.toml,src/otp.rs,src/lib.rs,tests/vectors/rfc4226-hotp.txt,tests/vectors/rfc6238-totp.txt}`, `crates/qv-model/src/{totp.rs,lib.rs}`.
- **Done when:** vectors pass; `cargo deny check` and `cargo vet --locked` pass.
- **Verify:** `cargo test --locked -p qv-crypto otp && cargo test --locked -p qv-model totp`

### Step 9 — `record_decode` fuzz target

- [x] **Do:** Add `fuzz/fuzz_targets/record_decode.rs`: `RecordVersion::decode`
  on the input; on success, assert `encode` succeeds and equals the input.
  Add the `qv-model` path dependency and the `[[bin]]` to `fuzz/Cargo.toml`,
  update `fuzz/Cargo.lock`, and add a "Fuzz record_decode (60 s)" CI step
  after the `cbor_decode` one. Run it locally for 60 s with the pinned nightly
  (musl needs `-s none` and `-- -use_cmp=0`, see the sandbox notes); seed a
  small corpus directory only in the scratchpad, not in the repo.
- **Files:** `fuzz/{Cargo.toml,Cargo.lock,fuzz_targets/record_decode.rs}`, `.github/workflows/ci.yml`.
- **Done when:** 60 s run clean; `cargo fetch --locked --manifest-path fuzz/Cargo.toml`
  and `cargo fmt --check --manifest-path fuzz/Cargo.toml` pass;
  `cargo deny --manifest-path fuzz/Cargo.toml check advisories bans sources` passes.
- **Verify:** the commands in *Done when*.

### Step 10 — Docs and final gates

- [x] **Do:** Complete the qv-model crate docs (module map, registry table as
  development values, the readings under *Decisions needed*, error → CLI
  table, secret types) and the qv-crypto crate docs (`otp`). Update the files
  under *Documentation*, run the full gates and set the plan to `Implemented`.
- **Files:** `crates/qv-model/src/lib.rs`, `crates/qv-crypto/src/lib.rs`, see *Documentation*.
- **Done when:** docs match the tree; all gates green.
- **Verify:** `sh scripts/check-spdx.sh && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && cargo deny check && cargo vet --locked`

## Test plan

- **Unit and property tests:** clock algebra (proptest); codec round trips
  with unknown keys at every map level; merge commutativity, associativity
  (regrouping), idempotence (duplicates) and no synthetic versions over
  generated honest histories; projection invariants over random parent maps;
  `encode(decode(x)) == x` over mutated inputs.
- **Rejection, malformed-input and crash-path tests:** every required key
  missing; tombstone/payload mismatch; `null` optionals; bad ID bits; bad
  clocks; every budget at its boundary and one past it, checked before
  allocation; unknown kinds and profiles; control-record deletion; merge
  identity violations; TOTP URI rejections. No durability paths in this phase.
- **Vectors:** RFC 4226 Appendix D, RFC 6238 Appendix B (upstream). Golden
  CBOR bytes for each record kind are development vectors only (format
  unstable until 1.16).
- **Fuzzing:** `record_decode` with a canonical round-trip oracle, in CI.
- **0012 §1 matrix rows addressed:** Order-dependent merges (step 6
  properties), Old-date concurrent edits, Mixed credentials (model level),
  Deleted-entry resurrection (model level) (step 6 scenarios).

## Risks and stop conditions

- **Spec gaps:** if a 0003/0005 requirement needs a behaviour not described
  here (for example, a field the registry lacks, or a reading of "deletion
  visibility" that the tests show to be inconsistent), log it and ask. Do not
  amend specs or invent required-feature mechanisms.
- **Supply chain:** if `sha1 0.11.0` brings a licence outside the allow-list,
  an advisory, or a crate not already in the lock other than itself, stop and
  ask. Do not widen `deny.toml`.
- **Vectors:** if an RFC vector fails, find the bug; never edit a vector to
  match. If the RFC text and errata disagree, record both and ask.
- **Merge correctness:** if a property test finds a counterexample, fix the
  algorithm, not the generator. Do not weaken a property or reduce the case
  count to make it pass.
- **Performance:** if the debug-build test time for qv-model exceeds 30 s, log
  it and lower only the proptest case count of the slowest property with a
  comment, never below 64 cases.
- **No `unsafe`**, and no dependency other than `sha1` (and `qv-crypto` as a
  path dependency).
- Never weaken a test or turn an exact error variant into `is_err()`.

## Documentation

- [x] `CHANGELOG.md` — Unreleased/Added: qv-model (records, clocks, merge, projection, TOTP), qv-crypto `otp`, `sha1`, `record_decode` fuzz target
- [x] `ARCHITECTURE.md` — §3 "Implemented so far" gains `qv-model`; §6 unchanged unless a tech choice differs (check)
- [x] Specs — no change. 0003 stays Accepted, not fully implemented (§6.2–6.3 content/chunks in 1.11); 0005 stays Draft
- [x] `AGENTS.md` — *Current state* mentions `qv-model`
- [x] `plans/README.md` — index row; roadmap 0002: tick 1.5, plan number, execution log, *Revisions* note (generator defaults in settings → 1.8; 1.16 records the frozen integer-key registry in 0003/0004)

## Revisions

None.

## Execution log
- 2026-10-26: Approved (standing approval, roadmap 0002): no open decisions, no spec amendment, one new dependency from the candidate table (`sha1`, phase 1.5 row), no `unsafe`, matches phase 1.5 (`qv-model`; the HOTP core goes into `qv-crypto` with the other primitives, as listed under *Files*).
- 2026-10-26: Status `In progress`.
- 2026-10-26: Step 1 done. New crate `qv-model` (deps `qv-crypto`, `qv-encoding`, `zeroize`; dev `proptest`); `qv-crypto` added to `[workspace.dependencies]`. `Cargo.lock` gains only the `qv-model` package (no new external crate). `error.rs` (`ModelError`, fixed strings, CLI table, `From` for codec and RNG errors), `ids.rs` (`RandomId` for the four qv-crypto IDs and the new `VersionId`/`WriterId`/`FieldId`/`ObjectId` with private fields; v4 bits set on generation and checked on `from_bytes`; `attachment_id`; crate-private test ID helpers), `time.rs` (`Timestamp`), `text.rs` (`Text` as `Zeroizing<String>` of exact capacity, `SecretText`/`FieldValue` in `SecretBytes`, `Extensions`, `MAX_TEXT_BYTES`, `MAX_RECORD_BYTES`). Tests: 1,000 generated IDs are v4 and distinct; UUIDv7, wrong variant, all-zero and all-0xff IDs → `Malformed`; text at 256 KiB passes and +1 → `LimitExceeded` (Text, SecretText, bytes); redacted `Debug`; fixed error strings; `compile_fail` doctests for `Text` `.clone()` and `==` with a passing twin. `RngError` cannot be built outside qv-crypto, so `From<RngError>` is not unit-tested here. As planned, clippy's `dead_code` fails on helpers that steps 2–5 use (`Extensions::push/iter`, test ID helpers); everything else is clean.
- 2026-10-26: Step 2 done. `clock.rs`: `Clock` (sorted pairs, no zeros, ≤ 256), `Causality`, `compare` (single merge walk, early exit once concurrent), `dominates`, `join` (fails at the 257th writer), `for_edit` (join of all heads, then the reserved counter; `Integrity` if not above the joined component, `CounterExhausted` at `u64::MAX`), crate-private `total` (u128 sum, for the merge order in step 5), `encode_clock`/`decode_clock` (pair count checked against 256 before `Vec::with_capacity`; writers must be v4). Test helper `test_clock::clock`. Tests: `from_pairs` exact variants (unsorted, duplicate, zero → `Malformed`; 256 ok; 257 → `LimitExceeded`); golden wire bytes for a two-writer clock (including a 2-byte counter) and the empty clock; decode rejects a map, a 3-element pair, negative and zero counters, a 15-byte writer, descending writers, a non-v4 writer and 257 pairs; every `Causality` case; join limit; `for_edit` over three heads, a new writer, reused counters and exhaustion. Proptests: antisymmetry and `Equal` ⇔ `==`; join is an upper bound, commutative, idempotent, associative and the componentwise max; wire round trip.
- 2026-10-26: Step 3 done. `codec.rs` (typed bounded reads: text, ID, fixed-size bytes, u16/u32, timestamp, array length against a budget; `keep` for unknown keys; `put_*` writers; `req`), `record.rs` (`RecordKind` codes, `Deletion`, `RecordBody`, `RecordVersion` with shared `check`, `encode` with the 1 MiB output bound, `decode` with the length bound before `Decoder::new`), `payload/{mod,vault_meta,keyslot}.rs` (`VaultMeta`, `Settings` with defaults 10/30 and key 2 kept as unknown, `Keyslot` over `qv_crypto::PasswordSlot`, unknown KDF/wrap profile → `Unsupported`). A crate-private `redacted_debug!` macro gives every payload type a `Name(<redacted>)` `Debug`. Key 5 is decoded inline with the kind from key 0, which sorts first. Tests: golden bytes for a vault-meta and a keyslot version; byte-for-byte round trip with unknown keys at the envelope (positive and negative), payload and settings levels; each missing required key (envelope, vault meta, keyslot) → `Malformed`; tombstone with payload, live without payload, `null` optional, ill-typed `deleted`, non-v4 version ID, empty clock, an out-of-range `u32`, a non-map top level and trailing bytes → `Malformed`; unknown kind (live and tombstone) and unknown KDF/wrap profiles → `Unsupported`; vault-meta and keyslot tombstones → `InvalidTransition` (decode and encode); 1 MiB + 1 → `LimitExceeded` before parsing. Until step 4, group, entry and attachment payloads decode as `Unsupported` (placeholder in `Payload::decode`).
- 2026-10-26: Step 4 done. `payload/group.rs` (required nullable `parent`), `payload/entry.rs` (`Entry`, `Field`, `FieldKind` with `Unknown(u64)` and `protected_by_default`, `MAX_FIELDS`; field values decoded straight into `SecretText`/`SecretBytes`), `payload/attachment.rs` (`CHUNK_SIZE`, `MAX_ATTACHMENT_BYTES`; `chunk_count` written from the list and checked on decode); `Payload` now has all five kinds, `soft_deleted` and `check` (entry: ≤ 4,096 fields, unique field IDs, no `Unknown` with a known code; attachment: ≤ 10 MiB, count = list = `ceil(size / 64 KiB)`, unique chunk IDs); `RecordVersion::check_root`. The step 3 placeholder is gone. Tests (`payload/tests.rs`): an entry built through the public API encodes to exactly the hand-assembled wire bytes (text, bytes-valued secret and TOTP fields) and round-trips; golden bytes for a root group payload; every optional group key; missing required keys for group, entry and field; unknown keys inside a field (positive and negative) and an entry; 4,096 fields pass and 4,097 → `LimitExceeded`; duplicate field IDs → `Malformed`; a 256 KiB + 1 value (text and bytes) and title → `LimitExceeded`, 256 KiB passes; unknown kind 9 round-trips, `Unknown(3)` cannot be encoded; protected defaults; attachments of 0, 1, 64 KiB, 64 KiB + 1 and exactly 10 MiB (160 chunks) pass, size/list/count mismatches, duplicates and a 31-byte hash → `Malformed`, 10 MiB + 1 → `LimitExceeded`; `check_root` cases; deletion states for every kind. Proptests: arbitrary bytes and single-byte mutations or truncations of five valid samples never panic, and every accepted input re-encodes to the same bytes. One justified `#[allow(clippy::large_enum_variant)]` on `RecordBody` (boxing would add an allocation per version for no memory saving). Remaining clippy failure: `Clock::total` unused until step 5.
- 2026-10-26: Step 5 done. `merge.rs`: `Versioned` (implemented for `RecordVersion`: `same_version` compares canonical encodings, an encoding failure counts as different), `merge` (dedupe in a `BTreeMap`, empty clock → `Malformed`, equal clocks under two IDs → `Integrity` via a `HashMap<&Clock, VersionId>`, then the descending-counter-sum pass from the plan with the 256-head limit enforced as heads are found), `merge_record` (one kind), `Merged` (`heads`, `dominated`, `into_parts`, `is_conflict`, `representative`, `status`, `split_history`), `View`, `RecordStatus`, `HistoryFloor` (`join`, `suppresses` = at most the floor). Test-only `Tv` version type. Tests: duplicates idempotent; same ID with a different clock or content → `Integrity`; equal clocks with different IDs → `Integrity`, also when both are dominated; dominance and three-way concurrency; empty merge; 256 heads pass, 257 → `LimitExceeded`; 300 concurrent versions plus two dominating versions → exactly those two heads; `merge_record` with mixed kinds or a changed payload under one version ID → `Integrity`, identical versions dedupe; representative and status for live/live, live/soft, soft only, final/live (a conflict in trash shown through the live head), final/soft and final only; floor join; `split_history` with floors at, below and beside dominated versions; a floor covering a head never hides it. clippy is clean for qv-model again.
- 2026-10-26: Step 6 done. `merge.rs` tests, `properties`: an honest-history generator (2–4 writers, 1–24 versions; each clock is `Clock::for_edit` over a random subset of earlier versions with the writer's next counter; version IDs scrambled relative to creation order). Properties: the heads equal a brute-force maximal set (an extra oracle on top of the plan); permutation invariance of heads and dominated lists; regrouping (two-way, and three-way with an intermediate merge) converges on the same heads; duplicate delivery (1–3 copies each) changes nothing; heads are input versions, pairwise concurrent, and every input is at most some head. Default proptest case count (256). `scenarios` (0012 rows, on real entry `RecordVersion`s): old-date concurrent edit survives in both delivery orders; mixed credentials: both heads and the representative encode exactly like an input, and each head's username/password/TOTP triple is one input's; deleted-entry resurrection: a tombstone dated decades before the edit it covers wins in both orders and after late delivery (the edit lands in `dominated`, then `suppressed` under a covering floor), and a concurrent tombstone/edit stays a conflict in trash shown through the live head; a late edit unseen by a resolution stays concurrent with it. Mutation check: sorting by ascending counter sum made 7 of the 16 merge tests fail, including both brute-force properties; the original was restored and passes.
- 2026-10-26: Step 7 done. `tree.rs`: `GroupNode` (`from_merged`: the live representative's parent, else the trash representative's for inspection; `live` = a live head exists; a non-group head → `Malformed`), `project_groups` (≤ `MAX_GROUPS` = 50,000 inputs; root fixed with parent `None` and marked repaired if its record names a parent; invalid parents → root; iterative cycle breaking with done / on-path sets, each cycle re-parented at its smallest ID), `GroupTree` (`parent`, `children`, `is_repaired`, `place_entry`, `len`, `is_empty`), `EntryPlace`. Tests: missing, deleted, `null` and self parents → root and repaired; root fixed (also when absent from the input or naming a parent); a 2-cycle and a 3-cycle with tails broken only at 3 and 7; a 50,000-deep chain and a 50,000-group cycle finish (the cycle breaks at its smallest ID), 50,001 groups → `LimitExceeded`; `place_entry` for live, deleted, missing groups and the root; `children` sorted; `from_merged` for two live heads, live + soft-deleted, soft-deleted only, a tombstone and a non-group. Proptests (up to 64 groups, some parents missing, ~15 % not live): every tree node reaches the root within `len` steps; non-repaired groups keep their record's parent; a group repaired despite a valid parent is the smallest member of a cycle of valid parents; only live groups and the root are in the tree; rebuilding the input from a shuffled list gives an identical tree. Beyond the plan: the 50,000-group cycle case and the cycle-minimum oracle.
- 2026-10-26: Step 8 done. Dependency: `sha1 = "=0.11.0"` (`default-features = false`, `zeroize` feature, matching `sha2`) in the workspace and `qv-crypto`. Licence `MIT OR Apache-2.0` (crates.io), not yanked, released 2026-03-27; deps `cfg-if`, `cpufeatures 0.3`, `digest 0.11`, all already in the lock, so `Cargo.lock` gains only `sha1` (plus the `qv-model` package from step 1). `cargo deny check`: advisories, bans, licenses, sources ok. `cargo vet`: `regenerate imports` found no audit for `sha1 0.11.0` (`suggest` offers none to import), so one exemption was added (`cargo vet add-exemption sha1 0.11.0`), `prune` changed nothing else; `cargo vet --locked`: 12 fully audited, 34 exempted. `qv-crypto/src/otp.rs`: `OtpAlgorithm`, `OtpCode` (`SecretArray<8>`, redacted `Debug`), `hotp` (HMAC output in a `Zeroizing` buffer, the tag wiped, truncated value in `Zeroizing`; digits 6–8 else `Internal`), re-exported from `lib.rs`. Vectors: `tests/vectors/rfc4226-hotp.txt` and `rfc6238-totp.txt` were generated by a scratch script that parses the fetched RFC texts (rfc-editor.org), not typed from memory; the script also checks every table `T` equals `time / 30`. The RFC 6238 file's comment records that the SHA-256/SHA-512 rows use the reference code's 32- and 64-byte seeds while the prose names only the 20-byte string; all 18 rows pass with those seeds, which confirms it. Deviation: the plan said "see RFC 6238 errata"; I did not verify an erratum number, so the comment cites only the RFC text. `qv-model/src/totp.rs`: `Totp` (redacted `Debug`), `TotpError`, `parse` (bounded to 256 KiB, case-insensitive scheme, type, names and algorithm; percent-decoding into exact-capacity `Zeroizing` buffers; base32 decoded straight into `SecretBytes`; repeated known parameter → `InvalidUri`; unknown parameters and the label ignored), `code_at`, `seconds_remaining`, accessors. Tests: all 18 RFC 6238 rows through `otpauth://` URIs (base32 of the seeds, the vector file shared with qv-crypto); 10 RFC 4226 rows; 6/7/8 digits; defaults; `seconds_remaining` edges; lenient spellings (case, `%3D` and `=` padding, fragment, unknown and value-less unknown parameters); 23 rejection cases with exact variants (hotp, SHA3, digits 5/9, periods 0/86,401, missing/empty/bad secret, bad length, repeats including different case, bad percent escapes, non-numeric and overlong numbers, wrong scheme/type, a 257-byte key); a 256-byte key passes; `BeforeEpoch`; base32 round trips for 0–39 bytes, padded and unpadded lowercase; redacted `Debug`; `hotp` digits 0/5/9/10 → `Internal`. Workspace clippy is clean.
- 2026-10-26: Step 9 done. `fuzz/fuzz_targets/record_decode.rs` (any accepted record must re-encode to the same bytes); `fuzz/Cargo.toml` gains the `qv-model` path dependency and the `[[bin]]`; `fuzz/Cargo.lock` gains qv-model's tree, with the same versions as the root lock for every shared package; CI gets a "Fuzz record_decode (60 s)" step after `cbor_decode`. `cargo fetch --locked` and `cargo fmt --check` for `fuzz/` pass; `cargo deny --manifest-path fuzz/Cargo.toml check advisories bans sources` passes. Local run with `nightly-2026-10-01` and cargo-fuzz 0.13.2 (musl: `-s none`, `-use_cmp=0`), seeded with four hand-built records (vault meta, group, entry, tombstone) in the scratchpad only: 35,855,668 runs in 61 s, coverage 1,075, no crash or mismatch. The package keeps the name `qv-encoding-fuzz` (renaming it is churn outside this plan).
- 2026-10-26: Step 10 done; plan `Implemented`. Crate docs: `qv-model` (module map with spec sections, the registry as development values, the readings under *Decisions needed*, secret types, errors) and `qv-crypto` (one-time codes). Docs: `CHANGELOG.md`, `ARCHITECTURE.md` §3 "Implemented so far" (§6 unchanged: `sha1` is a RustCrypto crate under the existing primitives choice), `AGENTS.md` current state, roadmap 0002 (1.5 ticked with plan 0007, *Revisions* note, execution log), `plans/README.md`. Specs unchanged: 0003 stays Accepted, not fully implemented (§6.2–6.3 chunk storage is 1.11); 0005 stays Draft; 0007 stays Accepted (§1.1 retention, §1.3–1.5, §2–4 remain). Final gates: SPDX ok; `cargo fmt --check` ok (root and `fuzz/`); clippy `-D warnings` clean; `cargo test --locked` 257 passed, 0 failed, 1 ignored (the plan 0005 vector generator), 6.3 s wall time, qv-model unit tests 0.39 s; `cargo doc` with `-D warnings` ok for qv-encoding, qv-crypto and qv-model; `cargo deny check` ok; `cargo vet --locked` ok (12 audited, 34 exempted); fuzz lockfile, fmt and deny ok.
  Found, not fixed: (1) `Settings` has no bounds on `history_depth`/`trash_retention_days` beyond `u32`; the store's budgets govern retention (0007 §1.1 "subject to resource budgets"), so 1.7/1.12 should clamp at use. (2) `merge` checks equal clocks across all inputs, but a regrouped merge that already dropped a dominated version cannot see a later duplicate clock against it (0005 §1.4 is still enforced among everything delivered together); the store keeps dominated versions as history, so 1.7 should merge against retained history, not heads alone. (3) `GroupNode::from_merged` takes a trash representative's parent for deleted groups; it is display-only and unused by the projection. (4) For 1.8: qv-core decides whether the live view flags or hides records whose status is both `live` and `in_trash`.
- 2026-10-26: Reviewed ([REVIEW.md](REVIEW.md)): Approved, no fixes. One low finding carried forward to phase 1.6: the four `qv-crypto` IDs have public fields, so `encode` can write a non-v4 ID that `decode` rejects.
