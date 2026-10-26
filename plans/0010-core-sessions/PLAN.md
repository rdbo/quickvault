# Plan 0010 — qv-core sessions and vault operations

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-26 | 2026-10-26 | 0008 §1, §4.1 (D5); 0007 §2 (and §1.2–1.4 for final deletion); 0003 §2–5; 0005 §1.2, §2.3–2.6 (D5); 0010 §5; 0011 §4, §6; 0012 §1 |

## Intent

Roadmap 0002 phase 1.8. Create `qv-core`, the single entry point for every
frontend. It owns session policy: unlock and lock, cancellation of in-flight
work, session-scoped handles and mutation authorization. On top of `qv-store` it
provides bounded metadata views and search over non-protected fields,
on-demand decryption, causal edits of entries and groups, the trash with
final tombstones, read-only conflict surfacing and the vault settings,
including the generator defaults. The CLI (1.10) and the app spike (1.9)
build on it.

## Scope

**In scope:**
- `qv-store` (small hooks):
  - redacted `Debug` for `Manifest`, `RecordEntry`, `VersionRef` and
    `ObjectRef` (review of plan 0009, finding 3);
  - final deletion: when `put_local` stores a final tombstone, the record's
    history is dropped and its history floor advanced (0007 §2.2, §1.3–1.4).
- `qv-model`: generator defaults in vault `settings` key 2 (0010 §5.1;
  roadmap revision of 2026-10-26, phase 1.5).
- New crate `qv-core`:
  - `Core` (configuration, process hardening, protection report), `create`
    (returns the recovery phrase once), `unlock`, `unlock_for_recovery`,
    `adopt_baseline`;
  - `Session` (thread-safe; `lock`; cancellation; terminal after lock) and
    session-scoped handles;
  - the metadata index built from every head after unlock and refreshed after
    each commit, with a view budget;
  - reads: tree and listings, recovered items, trash, conflicts, search over
    non-protected fields, entry details, protected reveal, TOTP codes, overview,
    the generator with vault defaults;
  - edits: create, edit and move entries and groups through drafts; soft
    delete (a group with its descendants, in one transaction); restore from
    trash; final deletion (explicit purge, empty trash) including owned
    attachment metadata; the trash-expiry report; settings.
- Unit, property and integration tests; docs.

**Out of scope:**
- Conflict **resolution** and merges (2.2). In 1.8 conflicts are shown and
  every mutation of a conflicted record is refused with `Conflict`. A 1.8
  vault cannot get a conflict; the index tests use synthetic heads.
- History listing, restore of old versions, retention depth enforcement and
  purge (1.12). `history_depth` can be edited but is not applied yet; history
  grows until a budget is hit (as in 1.7).
- Attachments (1.11): no attachment is created. Final deletion of an entry
  still tombstones its `attachment_meta` records (0007 §2.2), tested with an
  attachment written through `qv-store` directly.
- Path addressing (0011 §2), `info` header inspection, clipboard, terminal
  I/O, the inactivity timer and OS lifecycle hooks: frontends and platform
  (1.9, 1.10, 2.3). Core provides `lock()` and cancellation for them to call.
- Password change, recovery-phrase unlock and rotation (1.14, 1.15).
- Automatic trash expiry: nothing is deleted without an explicit call (see
  *Readings*).

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Zeroizing, redacted metadata and payload buffers; hardening before secrets; report reduced protection | 0008 §1.1 | Draft (D5) | `Core::new` hardens, `Core::protection` reports |
| Protected values encrypted when idle; wipe decrypted buffers after views; no plaintext password index; metadata confidential | 0008 §1.2 | Draft (D5) | Index keeps non-protected metadata only; search scans it |
| Lock cancels in-flight work, invalidates handles, zeroizes; late responses never repopulate | 0008 §1.4 | Draft (D5) | `Session::lock` |
| Handles scoped to one unlocked session, unforgeable, expire on lock; core owns authorization | 0008 §4.1 | Draft (roadmap 1.8 entry, D5) | See *Readings* |
| Unlock order; views after verification; decrypt on demand | 0004 §5.1 | Accepted | Store verifies, core then builds views |
| Every mutation is one store transaction | 0004 §5.2 | Accepted | Uses `qv_store::Write` only (roadmap: no second write path) |
| Exactly one vault metadata, keyslot and root; kinds immutable; control records undeletable | 0003 §2.3 | Accepted | |
| Preserve unknown keys when rewriting | 0003 §2.2 | Accepted | Drafts edit the decoded payload in place |
| Vault metadata and settings | 0003 §3, 0010 §5.1 | Accepted | Generator defaults at settings key 2 |
| Group fields, fractional `order`, display projection, recovered items | 0003 §4 | Accepted | `qv_model::project_groups` |
| Entry and field fields, protected flag, type hint, TOTP | 0003 §5 | Accepted | |
| Edits join every head and advance the local component | 0005 §1.2 | Draft (D5) | `Clock::for_edit` over the store's head clocks |
| Conflicts shown with every version; representative; choose a version for copy | 0005 §2.3 | Draft (D5) | Read-only; field handles name the version |
| Resolution is an explicit edit covering all heads | 0005 §2.4 | Draft (D5) | Not offered in 1.8; mutations of conflicted records refused |
| Soft and final deletion are causal versions; tombstones permanent; delete/edit conflict stays in trash | 0005 §2.5, 0007 §2.2 | Draft (D5) / Accepted | |
| Groups, metadata and keyslot follow the same rules; repair is a projection | 0005 §2.6 | Draft (D5) | |
| Soft delete, 30-day retention by client policy, anomaly confirmation, bulk group deletion in one transaction | 0007 §2.1 | Accepted | |
| Final deletion removes payload and history, keeps a tombstone, tombstones owned attachments | 0007 §2.2 | Accepted | Store hook, step 1 |
| Floors advance only over removable history; written in the same manifest transaction | 0007 §1.2–1.4 | Accepted | Floor = join of the dropped versions' clocks |
| Generator: vault defaults, overrides, revalidation at use | 0010 §2.1.3, §5 | Accepted | Validation stays in `qv-crypto` |
| Search scope: titles, usernames, URLs, group names (non-protected) | 0011 §4 (`search`) | Accepted | See *Readings* |
| Exit-code classes | 0011 §6 | Accepted | `CoreError` docs |

**Spec changes required:** none.

## Decisions needed

None. D5 (roadmap 0002) covers 0005 §0–2 and 0008 §1–3. The readings below
follow from the specs or the approved roadmap; they are listed for the
reviewer.

**Readings:**
- **0008 §4.1.** D5 lists 0008 §1–3 and §5. The approved roadmap entry for
  1.8 cites "0008 §1, §4.1 (D5)" and asks for session-scoped handles, so 1.8
  implements §4.1's handle and authorization rules only. §4.2–4.4 (webview,
  bridge and native input) are not used.
- **Handles** carry the session's random 128-bit tag and a record ID (and,
  for fields, the version and field ID). Their fields are private, so other
  crates cannot forge them. A handle from another session is `StaleHandle`,
  and any call after `lock` is `SessionLocked`. A locked session stays
  locked; unlocking again makes a new `Session` with a new tag.
- **Mutations are refused on conflicted records** (`Conflict`, exit 8),
  because resolution is phase 2.2 and an edit with unresolved heads requires
  explicit resolution (0005 §1.2). Empty-trash and purge skip or refuse
  conflicted items (0005 §2.5).
- **Drafts carry their base version.** Saving fails with `StaleHandle` if the
  record's head is no longer that version. Drafts may not change
  `deleted_at`, `created_at` or the vault metadata's `root_group`; deletion
  has its own calls (`NotAllowed`).
- **Trash expiry is explicit.** `Settings::trash_retention_days` already
  reads "days before trashed items are offered for final deletion" (plan
  0007). `expired_trash()` lists the items older than the retention period
  and sets `clock_anomaly` when any timestamp in the vault is more than 10
  minutes after `now` (this device's clock is behind, or another device's
  is ahead). Nothing is deleted until the frontend calls `purge`, which it
  confirms (0011 `trash empty`), with a stronger warning on an anomaly.
  A clock set forward cannot be detected without trusted time; the explicit
  confirmation is the safeguard (0007 §2.1).
- **Final deletion** puts a tombstone covering every head. In the same
  transaction it drops all history and sets the floor to the join of the old
  floor and every dropped version's clock. All covered versions are
  removable, so the floor rule of 0007 §1.3 holds. An entry's live or trashed
  `attachment_meta` records get tombstones in the same transaction
  (0007 §2.2). Their chunks lose their references and are pruned.
- **Group deletion** soft-deletes the group and everything displayed under
  it (descendant groups in the projected tree and the entries placed in
  them), all with the same `deleted_at`, in one `Write` (0007 §2.1). A
  non-empty group needs `recursive` (`NotEmpty` otherwise, 0011 `rm -r`). The
  root cannot be deleted. **Restoring a group** restores it plus the trashed
  groups and entries deleted with it: those with the same `deleted_at` whose
  source parent chain reaches the group through groups being restored.
  Restoring an entry whose group is gone shows it under recovered items
  (0003 §4.2).
- **Moves** need a live target group. A group cannot move into itself or a
  descendant (checked on the projected tree). The root never moves. New
  groups are appended after their siblings with a fractional key (`order`).
- **Search** matches case-insensitively (`str::to_lowercase`) against live
  entry titles, live group names, and the values of non-protected fields of
  kinds `text`, `url` and `email`, which covers usernames and URLs without
  hard-coding template field names. Protected values, notes and other
  kinds are never searched. Choosing which field to show as "username" in
  `ls` is a frontend template concern (0003 §5.2).
- **Views are rebuilt from decrypted heads.** `qv-store` unlock already
  decrypts every head to verify it. Core decrypts each head once more to build
  its index, so it can be cancelled between records. The second pass costs
  little next to Argon2id; folding it into the store pass is a 1.16 benchmark
  item (plan 0009 note 2).
- **View budget** (development value, like the 0004 budgets): at most 64 MiB
  of retained index text. Unlock or a commit that would exceed it is
  `LimitExceeded` with nothing changed (0004 §4.4).

## Design

**Components touched:** `qv-store` (trusted; two hooks), `qv-model`
(trusted; one settings key), new `qv-core` (trusted; session policy, the only
crate frontends call, per `ARCHITECTURE.md` §3). `qv-core` depends on
`qv-crypto`, `qv-model`, `qv-store` and `zeroize`. It has no frontend,
network or server dependency, and no `unsafe`.

**qv-store hooks (step 1).**
- `Manifest`, `RecordEntry`, `VersionRef` and `ObjectRef` drop
  `derive(Debug)` for impls that print `Name(..)`. They keep `Clone`,
  `PartialEq` and `Eq`. Tests that compare manifests still work, since
  `assert_eq!` only needs some `Debug`.
- `Write::put_local`: if `version.deletion() == Deletion::Final` and the
  record exists, `Manifest::finalize(record, head, reference)` replaces the
  heads, removes every history version (and its chunk references), and sets
  `floor = floor ∨ clock(v)` for every dropped version (old heads and
  history). The commit's existing prune removes the unreferenced rows. A
  final tombstone for a new record is `InvalidEdit`.

**qv-model settings (step 2).** `Settings` gains
`generator: Option<GeneratorDefaults>` at key 2:

```rust
pub struct GeneratorDefaults { pub settings: GeneratorSettings, pub ext: Extensions }
```

Encoding (canonical map; every key required for its mode; development
values): `0` mode (`0` characters, `1` passphrase, `2` PIN), then for
characters `1` length, `2` lowercase, `3` uppercase, `4` digits, `5` symbols,
`6` exclude_ambiguous, `7` exclude_chars (text), `8` require_each_class; for
a passphrase `1` words, `2` wordlist (`0` = eff-large), `3` separator (text of
one character), `4` capitalize (`0` none, `1` first letter), `5`
append_digit; for a PIN `1` length. Unknown keys go into `ext` and are
re-encoded. An unknown mode, word list or capitalization keeps the whole key-2
value in `Settings::ext` (raw, unchanged) and gives `generator: None`: this is
not a security or control kind, so it is preserved rather than failing
closed. Ranges are not checked at decode. `qv-crypto` revalidates at use
(0010 §2.1.3).

**qv-core interfaces:**

```rust
// lib.rs re-exports what frontends need, so they depend on qv-core only:
pub use qv_crypto::{MasterPassword, RecoveryPhrase, GeneratorSettings, CharacterSettings,
    PassphraseSettings, PinSettings, Capitalization, WordListId, Generated, Estimate, Strength,
    GeneratorError, MemoryProtection, ProcessHardening, Hardening, OtpCode};
pub use qv_model::{Entry, Field, FieldKind, FieldValue, Group, Text, SecretText, Timestamp,
    Extensions, VaultMeta, Settings, GeneratorDefaults, TotpError};
pub use qv_store::{AnchorDir, AnchorStatus, LocationWarnings, StoreError};
pub fn generate(settings: &GeneratorSettings) -> Result<Generated, CoreError>;  // no vault needed
pub fn estimate(settings: &GeneratorSettings) -> Result<Estimate, CoreError>;

pub trait TimeSource: Send + Sync { fn now(&self) -> Timestamp; }
pub struct SystemTime;                                   // the default TimeSource

pub struct CoreConfig { pub anchors: AnchorDir, pub time: Arc<dyn TimeSource> }
pub struct Protection { pub process: ProcessHardening, pub memory: MemoryProtection }
impl Protection { pub fn is_reduced(&self) -> bool; }

pub struct Core { /* config, process hardening result */ }
impl Core {
    /// Runs harden_process() once; the result is in protection().
    pub fn new(config: CoreConfig) -> Core;
    pub fn protection(&self) -> Protection;              // memory part read fresh
    pub fn create(&self, path: &Path, password: &MasterPassword, name: &str)
        -> Result<Created, CoreError>;
    pub fn unlock(&self, path: &Path, password: &MasterPassword, cancel: Option<&CancelToken>)
        -> Result<Session, CoreError>;
    /// Opens a vault whose anchor is missing or mismatched, read-only.
    pub fn unlock_for_recovery(&self, path: &Path, password: &MasterPassword,
        cancel: Option<&CancelToken>) -> Result<(Session, AnchorStatus), CoreError>;
}
pub struct Created { pub session: Session, pub recovery_phrase: RecoveryPhrase }

#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);
impl CancelToken { pub fn cancel(&self); pub fn is_cancelled(&self) -> bool; }

/// Send + Sync; share it with Arc. Every method takes &self.
pub struct Session { /* Mutex<State>, AtomicBool lock flag, tag, time */ }
impl Session {
    pub fn lock(&self);                                   // idempotent, terminal
    pub fn is_locked(&self) -> bool;
    pub fn warnings(&self) -> Result<LocationWarnings, CoreError>;
    pub fn adopt_baseline(&self) -> Result<(), CoreError>; // explicit recovery (0005 §5.4)
    pub fn is_read_only(&self) -> Result<bool, CoreError>; // writes blocked until adopt_baseline

    // Views (cheap; from the index)
    pub fn overview(&self) -> Result<Overview, CoreError>;     // name, counts, local_seq, modified_at
    pub fn root(&self) -> Result<GroupHandle, CoreError>;
    pub fn list(&self, group: GroupHandle) -> Result<Listing, CoreError>;
    pub fn recovered(&self) -> Result<Vec<EntrySummary>, CoreError>;
    pub fn trash(&self) -> Result<Vec<TrashItem>, CoreError>;
    pub fn conflicts(&self) -> Result<Vec<ConflictSummary>, CoreError>;
    pub fn search(&self, query: &str) -> Result<Vec<SearchHit>, CoreError>;
    pub fn expired_trash(&self) -> Result<ExpiryReport, CoreError>;

    // On-demand decryption
    pub fn entry(&self, entry: EntryHandle) -> Result<EntryDetail, CoreError>;   // representative
    pub fn entry_versions(&self, entry: EntryHandle) -> Result<Vec<EntryDetail>, CoreError>; // every head
    pub fn group(&self, group: GroupHandle) -> Result<GroupDetail, CoreError>;
    pub fn reveal(&self, field: FieldHandle) -> Result<FieldValue, CoreError>;
    pub fn totp(&self, field: FieldHandle) -> Result<TotpNow, CoreError>;
    pub fn generator_defaults(&self) -> Result<GeneratorSettings, CoreError>;
    pub fn generate(&self, overrides: Option<&GeneratorSettings>) -> Result<Generated, CoreError>;

    // Drafts (short-lived decrypted buffers) and mutations
    pub fn new_entry(&self, group: GroupHandle, type_hint: &str, title: &str) -> Result<EntryDraft, CoreError>;
    pub fn edit_entry(&self, entry: EntryHandle) -> Result<EntryDraft, CoreError>;
    pub fn save_entry(&self, draft: EntryDraft) -> Result<EntryHandle, CoreError>;
    pub fn new_group(&self, parent: GroupHandle, name: &str) -> Result<GroupDraft, CoreError>;
    pub fn edit_group(&self, group: GroupHandle) -> Result<GroupDraft, CoreError>;
    pub fn save_group(&self, draft: GroupDraft) -> Result<GroupHandle, CoreError>;
    pub fn move_item(&self, item: ItemHandle, to: GroupHandle) -> Result<(), CoreError>;
    pub fn delete(&self, item: ItemHandle, recursive: bool) -> Result<(), CoreError>;  // soft
    pub fn restore(&self, item: ItemHandle) -> Result<(), CoreError>;
    pub fn purge(&self, items: &[ItemHandle]) -> Result<(), CoreError>;  // final; must be in trash
    pub fn empty_trash(&self) -> Result<PurgeReport, CoreError>;         // skips conflicted items
    pub fn edit_settings(&self) -> Result<SettingsDraft, CoreError>;
    pub fn save_settings(&self, draft: SettingsDraft) -> Result<(), CoreError>;
}

// Handles: Copy, Eq, Ord, redacted Debug, private fields.
pub struct EntryHandle { session: SessionTag, record: RecordId }
pub struct GroupHandle { session: SessionTag, record: RecordId }
pub enum ItemHandle { Entry(EntryHandle), Group(GroupHandle) }
pub struct FieldHandle { entry: EntryHandle, version: VersionId, field: FieldId }

// View types: hold zeroizing Text copies, redacted Debug, no Clone.
pub struct EntrySummary { pub handle: EntryHandle, pub title: Text, pub type_hint: Text,
    pub icon: Option<Text>, pub fields: Vec<FieldSummary>, pub modified_at: Timestamp,
    pub expires_at: Option<Timestamp>, pub conflict: bool }
pub struct FieldSummary { pub name: Text, pub kind: FieldKind, pub value: Text } // non-protected text/url/email only
pub struct GroupSummary { pub handle: GroupHandle, pub name: Text, pub icon: Option<Text>,
    pub order: Text, pub repaired: bool, pub conflict: bool }
pub struct Listing { pub groups: Vec<GroupSummary>, pub entries: Vec<EntrySummary> }
pub struct TrashItem { pub item: ItemHandle, pub name: Text, pub deleted_at: Option<Timestamp>, pub conflict: bool }
pub struct ConflictSummary { pub item: ItemHandle, pub name: Text, pub heads: usize, pub in_trash: bool }
pub enum SearchHit { Entry(EntrySummary), Group(GroupSummary) }
pub struct ExpiryReport { pub expired: Vec<TrashItem>, pub clock_anomaly: bool }
pub struct PurgeReport { pub purged: usize, pub skipped_conflicts: usize }
pub struct Overview { pub name: Text, pub entries: usize, pub groups: usize,
    pub in_trash: usize, pub conflicts: usize, pub local_seq: u64, pub last_modified: Option<Timestamp> }
pub struct EntryDetail { pub version: VersionId, pub handle: EntryHandle, pub title: Text,
    pub type_hint: Text, pub group: Option<GroupHandle>, pub notes: Option<Text>, pub icon: Option<Text>,
    pub created_at: Timestamp, pub modified_at: Timestamp, pub expires_at: Option<Timestamp>,
    pub deleted_at: Option<Timestamp>, pub fields: Vec<FieldDetail> }
pub struct FieldDetail { pub handle: FieldHandle, pub name: Text, pub kind: FieldKind,
    pub protected: bool, pub value: Option<FieldValue> }      // None when protected
pub struct GroupDetail { /* handle, name, notes, icon, order, parent, deleted_at */ }
pub struct TotpNow { pub code: OtpCode, pub seconds_remaining: u32 }

// Drafts own the decoded payload (zeroizing model types) plus the base version.
pub struct EntryDraft { /* base: Option<(RecordId, VersionId)>, entry: Entry, ext: Extensions */ }
impl EntryDraft {
    pub fn entry(&self) -> &Entry;
    pub fn entry_mut(&mut self) -> &mut Entry;
    /// Appends a field with a new FieldId; protected per FieldKind::protected_by_default.
    pub fn add_field(&mut self, name: &str, kind: FieldKind, value: FieldValue) -> Result<(), CoreError>;
}
pub struct GroupDraft { /* … */ }   // group() / group_mut()
pub struct SettingsDraft { /* … */ } // meta() / meta_mut()

#[non_exhaustive]
pub enum CoreError {
    Store(StoreError),        // exit code per StoreError's table
    SessionLocked,            // 1
    StaleHandle,              // 6 (changed during the command)
    Cancelled,                // 1
    Conflict,                 // 8
    NotFound,                 // 4
    NotEmpty,                 // 1
    NotAllowed,               // 1
    InvalidInput,             // 1
    Generator(GeneratorError),// 1
    Totp(TotpError),          // 1
    LimitExceeded,            // 9
    Rng,                      // 1
    Internal,                 // 1
}
```

All inner enums are data-free, so `CoreError` stays data-free in effect.
`ModelError` maps to `LimitExceeded`, `Rng`, `Internal`,
`Store(Integrity)` (for `Integrity` and `Malformed` on decrypted data) or
`InvalidInput` (for `InvalidTransition`, and for `Malformed` on draft values).
The call site decides which.

**Modules:** `lib.rs` (docs, re-exports), `error.rs`, `core.rs` (`Core`,
config, time, protection), `session.rs` (state machine, `with_open`,
cancellation, handles), `index.rs` (pure index build and refresh, budget),
`views.rs` (view types and read calls), `edit.rs` (drafts, mutations,
trash), `settings.rs` (settings draft, generator), `order.rs` (fractional
keys).

**Session state machine.** `Session { tag: SessionTag, locking: AtomicBool,
state: Mutex<Option<Open>>, time }` where `Open { vault: UnlockedVault, index:
Index }`. Every call runs `with_open(|open| …)`:
1. If `locking` is set, return `SessionLocked`. Take the mutex. A poisoned
   mutex is `Internal`, and the state is dropped as on lock. If the state is
   `None`, return `SessionLocked`. Check that every handle's tag equals
   `self.tag`, else `StaleHandle`.
2. Run the operation. Long loops (index build, search, bulk edits) check
   `locking` between records and stop with `Cancelled`.
3. Reads: if `locking` was set during the call, return `Cancelled` and drop
   the result, so nothing is handed out once a lock was requested.

`lock()` sets `locking`, then takes the mutex (waiting for a running call to
reach a check), sets the state to `None` (dropping `UnlockedVault`: VK,
connection, index Text all zeroize on drop) and releases it. On a poisoned
mutex it takes the inner value and drops it too. Nothing can repopulate a
`None` state, so a late result never brings a locked session back. Unlock
takes an optional `CancelToken`. The store's unlock (Argon2id and
verification) cannot be interrupted; the token is checked after it and
between records while the index is built.

**Mutation flow** (inside `with_open`, reusing the 1.7 write path):
1. Authorize: handle tags; every touched record exists, has the expected
   kind, is not finally deleted, has exactly one head (`Conflict` otherwise),
   and the draft's base equals that head (`StaleHandle`); operation rules
   (*Readings*).
2. Build payloads. Check the model's encode rules and the index budget for
   the new text **before** opening the write.
3. `vault.write()` (the store refuses read-only sessions with `Rollback` /
   `NoAnchor`). For each record: `reserve_counter`, `Clock::for_edit(head
   clocks, writer, counter)`, a new `VersionId`, `modified_at = time.now()`,
   the base version's `ext`, then `put_local`.
4. If `locking` is set, drop the `Write` (rollback) and return `Cancelled`.
5. Remember `local_seq`, then `commit()`. If `local_seq` advanced (the
   change is durable, even when the anchor update then failed), refresh the
   index for the touched records and recompute the group tree. Then return
   the commit's result. If the refresh fails, the session locks itself and
   returns the error (fail closed).

**Index** (pure; built from `(RecordId, heads: Vec<RecordVersion>)` and the
control IDs). Per record: kind, `RecordStatus`, head version IDs, and for
the representative (live view, else trash view): an entry summary (title,
type hint, icon, group, timestamps, non-protected `text`/`url`/`email` field
values), a group node (`GroupNode::from_merged`) plus name/icon/order/
deleted_at, an attachment's owner entry, and the vault metadata's name and
settings. Protected values and notes are not retained. Decrypted versions
are dropped after each record. The group tree is `project_groups(root,
nodes)`. Listing order: groups by (`order`, record ID), entries by
(lowercased title, record ID). Retained text is counted against the 64 MiB
budget.

**Fractional keys** (`order.rs`, letters `a`–`z`): `key_after(s)`: empty →
`"n"`; else if the first letter is below `z`, that letter + 1 as a
one-letter key; else `"z"` + `key_after(rest)`. The result always sorts
after `s`. Equal keys from concurrent appends tie-break by record ID.

**Secrets and hostile input.**
- Decrypted payloads exist only inside the index build, the detail and
  reveal calls, and drafts. They are model types (zeroizing `Text`, locked
  `FieldValue`/`SecretText`) and are dropped after use. The index holds
  zeroizing `Text` copies of non-protected metadata only.
- View, detail and draft types have no `Clone` or `Display`, and their
  `Debug` is redacted. Handles' `Debug` prints `EntryHandle(..)`.
  `CoreError` holds no data.
- Vault content was authenticated by `qv-store` but can be authored by any VK
  holder (qv-model trust boundary). Core relies on the model's bounded
  decoding, treats every reference as possibly dangling (a missing group →
  recovered items; a missing owner → ignored), bounds the search query
  (≤ 1 KiB, `InvalidInput`), and bounds the retained index (64 MiB).
- TOTP seeds never leave core: `totp` returns the code only.

**Errors:** see the interface sketch. The `CoreError` rustdoc table maps
every variant to its 0011 §6 exit class, as `StoreError` does.

**Dependencies:** no new external crate. `qv-core` is a new workspace member
using `qv-crypto`, `qv-model`, `qv-store` and `zeroize`, plus `proptest`
(dev). `qv-store` gets a `[workspace.dependencies]` entry. `Cargo.lock`
gains only the new path crate. `cargo deny check` and `cargo vet` are re-run
because the lockfile changes.

## Steps

### Step 1 — qv-store: redacted manifest Debug and final deletion

- [x] **Do:** Replace `derive(Debug)` on `Manifest`, `RecordEntry`,
  `VersionRef` and `ObjectRef` with redacted impls. Add
  `Manifest::finalize(record, head, reference)` (crate-private) per *Design*.
  Make `Write::put_local` call it for a final tombstone of an existing
  record, and return `InvalidEdit` for a final tombstone of a new record.
  Update the `write.rs` module docs.
- **Files:** `crates/qv-store/src/manifest.rs`, `write.rs`, `lib.rs` (docs).
- **Done when:** unit tests: `format!("{m:?}")` contains no record or
  object ID bytes in hex or decimal; finalizing an entry with three history
  versions leaves one tombstone head, no history, a floor that dominates
  every dropped clock and validates, and after commit and reopen the dropped
  object rows are gone and `read_version` of a dropped version is
  `NotFound`; a tombstone for a new record → `InvalidEdit`; a tombstone of
  the vault metadata or keyslot record → `InvalidEdit` (model rule) with
  nothing written; an `attachment_meta` with zero chunks can be tombstoned.
- **Verify:** `cargo test --locked -p qv-store -- manifest write`.

### Step 2 — qv-model: generator defaults in settings

- [x] **Do:** Add `GeneratorDefaults` and `Settings::generator` with the key-2
  codec per *Design*; export it. Update the `vault_meta.rs` docs (key 2 is
  no longer reserved).
- **Files:** `crates/qv-model/src/payload/vault_meta.rs`, `payload/mod.rs`,
  `lib.rs`, `payload/tests.rs`.
- **Done when:** round trip of each mode; byte-identical re-encode; unknown
  key inside key 2 kept; unknown mode, word list or capitalization → `None`
  with the raw value kept and re-encoded unchanged; a two-character separator
  and a non-bool flag → `Malformed`; out-of-range lengths decode (validation
  is at use); the `record_decode` fuzz target still builds.
- **Verify:** `cargo test --locked -p qv-model -- vault_meta settings`;
  `cargo fetch --locked --manifest-path fuzz/Cargo.toml` (the CI fuzz job
  builds the target).

### Step 3 — qv-core crate, `Core`, sessions and handles

- [x] **Do:** Create `crates/qv-core` (manifest with workspace lints, add the
  `qv-store` workspace dependency), `error.rs`, `core.rs`
  (`Core`, `CoreConfig`, `TimeSource`, `SystemTime`, `Protection`,
  `create`, `unlock`, `unlock_for_recovery`), `session.rs` (`Session`,
  `with_open`, `lock`, `CancelToken`, handles, `adopt_baseline`,
  `is_read_only`, `warnings`), and the re-exports. Use a stub `Index` with
  only the control IDs and kinds for now. `create` returns
  `RecoveryPhrase::from_vault_key`. Add a test-only KDF mutex and a fixture
  vault copied per test (as in `qv-store`).
- **Files:** `Cargo.toml` (workspace dependency), `crates/qv-core/Cargo.toml`,
  `src/lib.rs`, `src/error.rs`, `src/core.rs`, `src/session.rs`, `Cargo.lock`.
- **Done when:** unit tests: create → session unlocked, the phrase has 24
  words and unlocks the same VK (`VaultKey::from_recovery_phrase` equals);
  unlock with a wrong password → `Store(WrongPassword)`; after `lock()`
  every call → `SessionLocked`, and `lock` is idempotent; a handle from
  another session → `StaleHandle`; a cancelled token before unlock →
  `Cancelled` and no session; a missing anchor → `unlock` is
  `Store(NoAnchor)`, `unlock_for_recovery` gives a read-only session until
  `adopt_baseline`; `Session` is `Send + Sync` (compile-time assertion);
  `Protection::is_reduced` follows its parts; `CoreError` strings are fixed and
  `Debug` of handles and errors contains no ID bytes.
- **Verify:** `cargo test --locked -p qv-core -- core session`.

### Step 4 — The index

- [x] **Do:** `index.rs`: the pure builder and per-record refresh per
  *Design*, the group tree, listing order, recovered placement, trash and
  conflict sets, the budget, and the cancellable build on unlock. Wire it
  into `unlock`/`create`.
- **Files:** `crates/qv-core/src/index.rs`, `session.rs`, `core.rs`.
- **Done when:** pure unit tests on synthetic heads: a live entry, a
  soft-deleted entry (trash), a final tombstone (hidden), two concurrent
  heads (conflict; the representative is the largest version ID), a
  delete/edit race (in trash and conflicted), a group cycle and an orphan
  (repaired under root), an entry with a missing group (recovered), protected
  values and notes absent from the index, retained text at the budget passes
  and one byte over → `LimitExceeded`; refreshing one record equals a full
  rebuild; building on a vault with a locking flag set stops with
  `Cancelled`.
- **Verify:** `cargo test --locked -p qv-core -- index`.

### Step 5 — Read calls

- [x] **Do:** `views.rs`: view types and `overview`, `root`, `list`,
  `recovered`, `trash`, `conflicts`, `search`, `entry`, `entry_versions`,
  `group`, `reveal`, `totp`. `settings.rs`: `generator_defaults`,
  `generate`, and the free `generate`/`estimate`.
- **Files:** `crates/qv-core/src/views.rs`, `settings.rs`, `lib.rs`.
- **Done when:** tests on a vault populated through `qv-store` writes (step
  6 is not needed for this): listing order; search hits on title, group name,
  a non-protected username and URL, case-insensitively, and never on a
  protected value, a notes text or a multiline field; an empty or 1,025-byte
  query → `InvalidInput`; `entry` omits protected values and `reveal`
  returns them; `reveal` of a field handle whose version is no longer a head →
  `StaleHandle`; `totp` on a non-TOTP field → `InvalidInput`, on a TOTP field
  returns the RFC 6238 code for the injected time; `generate(None)` uses the
  vault defaults (or the 0010 defaults) and invalid stored defaults →
  `Generator(..)`; every view type's `Debug` is redacted.
- **Verify:** `cargo test --locked -p qv-core -- views settings`.

### Step 6 — Drafts and edits

- [x] **Do:** `edit.rs`: `EntryDraft`, `GroupDraft`, `new_entry`,
  `edit_entry`, `save_entry`, `new_group`, `edit_group`, `save_group`,
  `move_item` and the shared mutation flow (authorization, payloads, budget,
  `Write`, cancel check, commit, refresh). `settings.rs`: `SettingsDraft`,
  `edit_settings`, `save_settings`. `order.rs`: `key_after`.
- **Files:** `crates/qv-core/src/edit.rs`, `settings.rs`, `order.rs`,
  `session.rs`.
- **Done when:** tests: create, edit and move entries and groups, and each
  change is visible in the index and after a reopen; the new clock dominates
  the old head and has this writer's next counter; unknown keys in the entry,
  field and record survive an edit (an entry written through `qv-store`
  with extensions); refusals with nothing written (`local_seq` unchanged):
  stale base → `StaleHandle`, conflicted record → `Conflict` (via a
  test-only index entry with two heads), a draft changing `deleted_at`,
  `created_at` or `root_group` → `NotAllowed`, move into a trashed group, into
  itself or a descendant, or a root move → `NotAllowed`, a 257 KiB title →
  `InvalidInput`; settings round trip including generator defaults;
  `key_after` property (result > input, length grows by at most one letter
  for an input of any length; `key_after("") = "n"`).
- **Verify:** `cargo test --locked -p qv-core -- edit order settings`.

### Step 7 — Trash, final deletion and expiry

- [x] **Do:** `delete` (entry, group with `recursive`), `restore`, `purge`,
  `empty_trash`, `expired_trash` per *Readings*, including attachment
  tombstones for purged entries.
- **Files:** `crates/qv-core/src/edit.rs`, `views.rs`.
- **Done when:** tests: a group with nested groups and entries deleted with
  `recursive` → one commit (`local_seq` + 1), every item in trash with one
  `deleted_at`; without `recursive` → `NotEmpty`; the root → `NotAllowed`;
  restore of the group brings back what was deleted with it but not an entry
  deleted earlier on its own; a restored entry whose group is still trashed
  is under recovered items; `purge` of an item not in trash → `NotAllowed`;
  after `empty_trash`, the purged records are tombstones in the manifest with
  no history, hidden from every view, and stay so after a reopen; an entry's
  `attachment_meta` (written through `qv-store`) becomes a tombstone in the
  same commit; `empty_trash` skips a conflicted trash item (synthetic) and
  reports it; `expired_trash` with an injected clock: an item deleted 31
  days ago is listed and one deleted 29 days ago is not; a vault timestamp
  11 minutes in the future sets `clock_anomaly`, 9 minutes does not.
- **Verify:** `cargo test --locked -p qv-core -- trash`.

### Step 8 — Lock, cancellation and late results

- [x] **Do:** A test-only pause hook in `with_open` (a channel the test
  controls). Make sure every long loop checks `locking`.
- **Files:** `crates/qv-core/src/session.rs`, `edit.rs`, `index.rs`.
- **Done when:** tests with two threads: a read paused inside `with_open`,
  then `lock()` from another thread → the read returns `Cancelled`, `lock`
  returns after it, and the session is locked; a mutation paused before
  commit, then `lock()` → `Cancelled`, `local_seq` unchanged on reopen; a
  mutation paused after commit → the commit is durable and reported, and the
  session is locked afterwards; a `search` started after `lock()` →
  `SessionLocked`; handles from before the lock fail in a new session with
  `StaleHandle`.
- **Verify:** `cargo test --locked -p qv-core -- lock cancel`.

### Step 9 — Integration and property tests, documentation and gates

- [x] **Do:** `crates/qv-core/tests/offline.rs`: the full offline flow
  through the public API only (create, read the phrase, add groups and
  entries, edit, move, delete, restore, purge, settings, lock, reopen in a new
  `Core`, every view equal to the state before the lock). There is no server
  or network configuration (0012 *Implicit server prerequisite*, core
  level). Add a property test: random operation sequences over a few records,
  where the index after the sequence equals the index of a fresh unlock (6
  cases; each costs KDF runs). Update the docs (below) and run every gate,
  plus `cargo deny check` and `cargo vet`.
- **Files:** `crates/qv-core/tests/offline.rs`, `src/edit.rs` (proptest
  module), `ARCHITECTURE.md`, `AGENTS.md`, `CHANGELOG.md`,
  `plans/0002-roadmap/PLAN.md`, `plans/README.md`, this plan.
- **Done when:** the integration and property tests pass; all gates green;
  deny and vet green.
- **Verify:** `sh scripts/check-spdx.sh && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked`;
  `cargo deny check`; `cargo vet` (scratch `CARGO_HOME` as in earlier phases).

## Test plan

- Unit and property tests: index builder (synthetic heads), fractional keys,
  settings codec, mutation rules, the random-operations property (index after
  operations = index after reopen).
- Rejection, malformed-input and crash-path tests: every refused mutation
  asserts its exact `CoreError` and that `local_seq` is unchanged; a lock
  during a mutation leaves the old state; cancelled unlock; invalid generator
  defaults; hostile references (missing group, missing attachment owner,
  cycles). Crash ordering itself stays with the 1.7 harness, since core adds no
  durable state.
- Vectors: none (format unstable until 1.16).
- 0012 §1 matrix rows: **Implicit server prerequisite** (core level: a full
  offline lifecycle with no server configuration and no network dependency in
  `qv-core`); **Deleted-entry resurrection** (trash part: tombstones persist
  across reopen with history dropped and floors advanced; a delete/edit
  conflict stays in trash and is not emptied implicitly).

## Risks and stop conditions

- **Draft sections:** only 0005 §1–2, 0008 §1 and §4.1 as in *Readings*. If
  the work seems to need 0008 §4.2–4.4 or 0005 §3–6, stop.
- **Conflict resolution creep:** do not add any call that lets a frontend
  edit, restore or purge a conflicted record. That is phase 2.2 and needs its
  own plan.
- **Second write path:** every durable change goes through
  `qv_store::Write`. If an operation seems to need a store change beyond
  step 1 (for example writing a floor without a tombstone, or history
  pruning), stop: that is 1.12.
- **Format:** the settings key-2 layout is a development value. Do not
  change other record formats. If the floor rule for final deletion cannot
  pass `Manifest::validate`, stop and report rather than relaxing validation.
- **Deadlocks:** `lock()` waits for the running call. If a test shows a call
  that can block indefinitely while holding the mutex (for example waiting on
  user input), stop: frontends must not hold the session across user
  interaction.
- **Test time:** Argon2id runs stay serialized and few (fixture vault copied
  per test; the property test uses 6 cases). If the qv-core suite takes
  more than about 60 s in the debug profile, log it and reduce the cases, not
  the coverage of the rejection tests.
- Never weaken a test or turn an exact error variant into `is_err`. No
  `unsafe`, no new external dependency.

## Documentation

- [x] `CHANGELOG.md` — Unreleased: `qv-core`; the `qv-store` final-deletion
  hook and redacted manifest `Debug`; generator defaults in settings.
- [x] `ARCHITECTURE.md` — §3 "Implemented so far" gains `qv-core`.
- [x] Specs — no change.
- [x] `crates/qv-core/src/lib.rs` — module table, readings, errors, "not in
  this phase"; `qv-store` and `qv-model` module docs for the hooks.
- [x] `AGENTS.md` — "Current state" line gains `qv-core`.
- [x] `plans/README.md` — index row; `plans/0002-roadmap/PLAN.md` — tick,
  plan number, *Revisions* (development values: settings key 2, the 64 MiB
  view budget, the 10-minute anomaly tolerance) and *Execution log*.

## Revisions

- 2026-10-26: Approved under standing approval, roadmap 0002 (no open
  decision, no spec amendment, no new dependency, no `unsafe`). The two
  `qv-store` hooks and the `qv-model` settings key are not a deviation from
  the phase entry: the review of plan 0009 assigned the `Debug` change to
  1.8, the roadmap revision for phase 1.5 assigned the generator defaults to
  1.8, and final tombstones (in the 1.8 entry) need the store to drop history.

## Execution log

- 2026-10-26: Approved (standing approval, roadmap 0002); status In progress.
- 2026-10-26: Step 1 done. `Manifest`, `RecordEntry`, `VersionRef`, `ObjectRef` print `Name(..)`. `Manifest::finalize` (tombstone head, history dropped with its chunk references, floor = old floor ∨ every dropped clock); `put_local` uses it for a final tombstone of an existing record. `check_edit` refuses a tombstone for a new record, and (new, explicit) a tombstone of the vault metadata or keyslot record: the model refuses to encode those, but that maps to `Integrity`, and an edit-rule breach should be `InvalidEdit` as the plan says. Tests: four versions → tombstone (objects 7 → 4; floor suppresses every dropped clock, not the tombstone; dropped versions `NotFound`; survives reopen); tombstone refusals (new record, vault metadata, keyslot, root) with nothing written; a zero-chunk `attachment_meta` tombstoned; redacted `Debug`.
- 2026-10-26: Step 2 done. `Settings::generator: Option<GeneratorDefaults>` at key 2 with the planned layout (`vault_meta.rs` docs carry the table). An unknown mode, word list or capitalization keeps the raw key-2 value in `Settings::ext`; unknown keys inside the map go to `GeneratorDefaults::ext`. Tests: round trip of every mode and of none (byte-identical); unknown inner key kept; the three unknown cases kept raw and re-encoded unchanged; a two-character or empty separator, a non-bool flag, a missing mode key, an empty map and a map without key 0 → `Malformed`; a PIN length of 1000 decodes (checked at use). The existing `record_unknown_keys_survive_at_every_level` used `{0: 1}` at key 2 as an unknown value; key 2 is now defined and `{0: 1}` is an incomplete passphrase, so its input became `{0: 9}` (an unknown mode, still kept raw), which keeps the test's intent. `cargo fetch --locked` on the fuzz crate passes.
- 2026-10-26: Step 3 done. New crate `qv-core` (`qv-store` workspace dependency added; dev-dependency on the workspace crate `qv-encoding` for a test that crafts unknown keys, step 6). `setup.rs` holds `Core`, `CoreConfig` (plus `CoreConfig::new` with the system clock), `TimeSource`, `SystemTime`, `Protection`, `Created`: the plan named the module `core.rs`, which would shadow the `core` crate inside `qv-core`. `session.rs`: `Session` (mutex over `Option<Open>`, a lock-request flag, a random tag), `read` (drops the result if a lock was requested meanwhile) and `mutate`, `lock` (idempotent, terminal, also on a poisoned mutex), `CancelToken`, the four handle types (private fields, redacted `Debug`), `adopt_baseline`, `is_read_only`, `warnings`, and test-only pause hooks. The real index (step 4) was written directly instead of a stub. Tests: `Send + Sync`; create returns a 24-word phrase that maps back to the stored VK; wrong password, a cancelled token and a missing path; lock is terminal and idempotent; handles of another session are `StaleHandle`; a missing anchor is `Store(NoAnchor)`, recovery gives a read-only session until `adopt_baseline`, then writes work and survive a reopen; the protection report; redacted `Debug`.
- 2026-10-26: Step 4 done. `index.rs`: `RecordInfo::from_heads` (merge status, representative live-else-trash, group node, the representative's payload moved into the index with only non-protected `text`/`url`/`email` values copied; heads of another kind → `Integrity`), `Index` (`build` from the vault with a cancellation check per record, `insert` with the budget, `check` for a batch, `replace` after a commit, `retree`, `meta`), `MAX_VIEW_BYTES` = 64 MiB. Tests: live, soft-deleted, final-tombstone, two-head conflict (largest version ID shown), delete/edit race (live, in trash, conflicted), wrong kind; a parent cycle broken at the smaller ID and an orphan, both repaired under the root, and an entry with a missing group under recovered items; budget exactly at the limit and one byte over (nothing inserted); an incremental replace equals a rebuild; a cancelled build on a real vault. The "protected values and notes absent" check is structural (the index types have no field for them) plus the retained-value assertion.
- 2026-10-26: Step 5 done. `views.rs`: the view types (redacted `Debug`, no `Clone`) and `overview`, `root`, `list`, `recovered`, `trash`, `conflicts`, `search`, `expired_trash` (step 7 tests it), `entry`, `entry_versions`, `group`, `reveal`, `totp`; `settings.rs`: `generator_defaults`, `generate`, the free `generate`/`estimate`. The tests populate vaults through the core's own drafts (step 6 was written alongside) rather than through `qv-store` writes. Tests: listing order (groups by fractional key, entries by lowercased title), listed fields are the non-protected text/URL ones only; search on titles, URLs, usernames and group names, case-insensitive, never on a protected value, notes or a multiline field; empty and 1,025-byte queries refused, 1,024 accepted; overview counts; `entry` hides protected values and `reveal` returns them; a field handle of a replaced version → `StaleHandle`; RFC 6238 SHA-1 code at t = 59 s (94287082, 1 s left); `totp` of a text field → `InvalidInput`; generator defaults (spec defaults, vault defaults, revalidation at use).
- 2026-10-26: Step 6 done. `edit.rs`: `commit` (the one path to `qv_store::Write`: counter, `Clock::for_edit` over the store's head clocks, new version ID, model encode check, index info from the decoded copy, batch budget check, cancel check, commit, index follows a durable commit and a failed retree locks the session), `EntryDraft`/`GroupDraft` (private base version, base group/parent/created/deleted values), `new_entry`, `edit_entry`, `save_entry`, `new_group` (appended with `key_after` of the largest sibling key), `edit_group`, `save_group`, `move_item` (internal helpers, never a nested session call, so no re-entrant lock). `settings.rs`: `SettingsDraft`, `edit_settings`, `save_settings`. `order.rs`: `key_after`; for a key with characters outside `a`–`z` (another client's) it appends `n`, because no `a`–`z` key sorts after a string starting with a byte above `z`. Tests: create/edit/move entries and groups, visible in listings and after reopen; the new clock is `After` the old head with this writer's component + 1; unknown keys at the record, entry and field level survive an edit (an entry with `100: "x"` planted in every map, written through `qv-store`); refusals with `local_seq` unchanged: stale draft, changed `created_at`/`deleted_at`, `root_group`, duplicate field IDs, too many fields, moves into a trashed group, into itself, below itself and of the root, a conflicted record (a second head added to the index) for edit, move and delete; settings round trip. Deviation: a 257 KiB title is `LimitExceeded` (the model's text budget, exit 9), not `InvalidInput` as the plan's *Done when* says; a size budget is what `LimitExceeded` means everywhere else.
- 2026-10-26: Step 7 done. `delete` (an entry; a group with its displayed subtree and the entries placed in it, all with one `deleted_at`, one commit), `restore` (an entry; a group plus the trashed records with the same `deleted_at` reached through source parents), `purge` and `empty_trash` (minimal tombstones without unknown keys, the owned `attachment_meta` records tombstoned in the same commit, conflicted items refused or skipped), `expired_trash`. Tests: `NotEmpty` without `recursive`, the root refused; a recursive delete is one commit; restore brings back the group, its subgroup and both entries but not an entry deleted earlier; a restored entry of a trashed group is under recovered items; purge of a live item → `NotAllowed`; `empty_trash` purges the entry (heads = one tombstone, no history, its attachment a tombstone too, hidden from entry, trash and search, also after reopen) and skips a conflicted item; 31 days old expired, 29 not, a shorter retention applies at once; an anomaly at 11 minutes, none at 9. Test fixture change: the fixed test clock now starts at the real time, because the store stamps the fixture's control records with the system clock (otherwise every expiry check saw an anomaly).
- 2026-10-26: Step 8 done. Test-only pause points (`InCall`, `BeforeCommit`, `AfterCommit`, armed per thread). Tests (two threads; the lock is requested while the call is paused, which then continues): a paused search returns `Cancelled` and later calls are `SessionLocked`; a mutation paused before its commit returns `Cancelled` and a reopen shows nothing written, and its old handles are `StaleHandle` there; a mutation paused after its commit reports `Ok` and the change survives; a recursive group delete paused at entry is cancelled with nothing written.
- 2026-10-26: Step 9 done. `tests/offline.rs`: the full lifecycle through the public API only (create with the phrase, groups and entries, edit, moves, recursive delete, restore, purge, settings, search, lock), then a new `Core` unlocks the same file and every view (revealed values included) equals the state before the lock; `CoreConfig` has no server or network setting (0012 *Implicit server prerequisite*, core level). Property test `edit_random_operations_match_reopen` (6 cases, up to 24 random operations over groups and entries, including moves, deletes, restores and purges): the incrementally maintained index equals the index of a fresh unlock. Docs: `qv-core` crate docs, `qv-store` readings, `CHANGELOG.md`, `ARCHITECTURE.md` §3, `AGENTS.md` current state, roadmap tick, revision and log. Gates: SPDX, `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (400 passed, 0 failed, 2 ignored; the qv-core suite takes about 10 s), `cargo deny check` (advisories, bans, licenses, sources ok) and `cargo vet` (17 fully audited, 39 exempted; the lockfile only gained the path crate `qv-core`). Status Implemented.
  Found, not fixed: (1) `qv-core`'s unit tests use `std::os::unix` (as `qv-store`'s do), so they are Linux/Android only; the library uses only `qv-store` API that `unsupported.rs` mirrors, but no non-Linux target is installed to build it. (2) Each mutation re-encodes and decodes the new version once to index exactly what a reopen would see; cheap, but a 1.16 benchmark item together with the second decryption pass at unlock. (3) `purge` of a group does not purge its trashed contents unless they are listed too (`empty_trash` covers everything); 1.10 can decide whether `trash rm <group>` should include them. (4) A conflicted vault-metadata or keyslot record shows only in `Overview::conflicts`, since `ConflictSummary` names entries and groups; 2.2 adds its view. (5) Frontends must drop views on lock; core cannot reach copies already handed out (0008 §1.4 lists destroying revealed UI state as a frontend duty).
- 2026-10-26: Reviewed ([REVIEW.md](REVIEW.md)): Approved, no fixes. One low finding carried forward: new generator defaults cannot replace an unreadable key-2 value (`DuplicateKey` → `InvalidInput`); fix by phase 2.5. Status Reviewed.
