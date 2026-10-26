# Plan 0008 — Vault file: hardened SQLite, schema, header and keyslots

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-26 | 2026-10-26 | 0004 §1, §2, §4, §5.1 (first half); 0002 §1.4, §3.1–3.3, §7.2, §8; 0008 §5; 0011 §6; 0012 §1 |

## Intent

Roadmap 0002 phase 1.6. Create `qv-store` and the vault file it owns: a
SQLite database that is opened only with every hardening setting in 0004 §1.2
and an exact schema, that is protected by owner-only permissions, symlink
rejection, a process lock and file-identity tracking, and that stores the
header and the local password keyslot under the header MAC. This phase covers
vault creation and unlock to VK. Records, objects and manifests come in 1.7.
It also carries out the low finding from the plan 0007 review: `qv-model` must
not encode an ID it would reject on decode.

## Scope

**In scope:**
- New crate `crates/qv-store` (trusted; depends on `qv-crypto`, `qv-encoding`,
  `qv-model`, `rusqlite`, `rustix`, `zeroize`).
- File safety: owner-only creation, permission/owner/type checks, symlink
  rejection, parent-directory check, process lock, file identity, and
  sync/network/removable location warnings.
- The SQLite connection: open flags, `db_config` hardening, pragmas with
  read-back, limits, an execution-step budget, a size cap before opening,
  bounded `quick_check`, and exact schema validation.
- Schema v-dev with two tables, `header` and `keyslot`, plus independent
  row checks.
- Header and local slot encodings (development values), and the header MAC.
- `VaultFile::create` (atomic: temp file, then rename with no-replace) and
  `VaultFile::open` → `unlock` → `UnlockedVault`.
- `StoreError` with the 0011 §6 exit-code mapping.
- A `vault_open` fuzz target and its CI step.
- Bundled-SQLite compile options trimmed through `LIBSQLITE3_FLAGS` in
  `.cargo/config.toml`, with a test that checks them.
- `qv-model`: encode-time v4 checks for the embedded `qv-crypto` IDs (review
  0007 finding 1) and a public standalone codec for the keyslot descriptor.

**Out of scope:**
- Tables `object`, `manifest`, `local_head` and `sync_state`; object envelopes,
  record encryption, manifests, local head, anchor, writer state and the
  mutation transaction (all 1.7). 1.7 adds its tables and bumps the
  development schema version.
- Re-reading the local head inside `BEGIN IMMEDIATE` (0004 §1.3, second
  sentence): 1.7, which has the head. This phase provides
  `check_identity()` for 1.7's write path to call.
- Quick/platform slots (2.6). Slot types other than password are `Unsupported`.
- Vault name and the password-keyslot *record* (VK-encrypted, in the
  manifest): 1.7.
- Default private storage location and directory creation: 1.10 (CLI) and
  2.3 (platform). `create` requires an existing parent directory.
- Windows and macOS file-safety code: 4.1 and later. Non-Linux/Android
  targets get a compile-time `Unsupported`, so they do not build silently
  without protection.
- Password acceptance / strength (0010 §4.2): 1.10.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| `.qvault`, fixed `application_id` and `user_version` | 0004 §1.1 | Accepted | Development values, see *Design* |
| 0600 file, private directory, reject symlinks, nonregular files and path replacement | 0004 §1.1, 0008 §5 | Accepted / Draft (D5) | Reading of "private directory" in *Decisions needed* |
| Sync-folder, network or removable location → warning | 0004 §1.1, 0011 *Security Considerations* | Accepted | Returned as data; the CLI prints it (1.10) |
| New vaults never overwrite existing paths | 0004 §1.1 | Accepted | `O_EXCL` temp file + `RENAME_NOREPLACE` |
| Hardening pragmas, defensive mode, no extensions/triggers/views/unused vtables, no app SQL functions, failures abort | 0004 §1.2 | Accepted | Read back every setting |
| Bounded `quick_check`, exact schema, unexpected triggers/views/expression indexes/schema versions are errors | 0004 §1.2 | Accepted | |
| Process lock + SQLite transactions; file identity; mtime is not a check | 0004 §1.3 | Accepted | `flock` on the vault file's own fd |
| `header` exactly one row; `keyslot` by slot ID; constraints checked independently of SQL | 0004 §2 | Accepted | Two of the six tables; rest in 1.7 |
| Header/keyslot metadata ≤ 64 KiB, ≤ 64 slots; SQLite length, column, expression, page-count and execution-step limits | 0004 §4.1 | Accepted | |
| Known KDF profiles only; unknown fails before any KDF | 0004 §4.3, 0002 §1.1 | Accepted | |
| Header carries data profile and minimum profiles; password policy travels with the slot | 0002 §1.4, 0004 §3.4 | Accepted | |
| KEK, commitment, slot wrap/unwrap (already in `qv-crypto`) | 0002 §3.1–3.2 | Accepted | `PasswordSlot::{create, unlock}` |
| `header-mac` purpose key; MAC over canonical header fields plus slots sorted by slot ID | 0002 §3.3, §7.2 | Accepted | Transcript layout is a development value |
| Unlock order; wrong password vs integrity error | 0004 §5.1, 0002 §8 | Accepted | First half: up to the header MAC |
| Exit codes 3/6/7/9 | 0011 §6 | Accepted | `StoreError` mapping |
| Hostile SQLite (SQLite half) | 0012 §1 | Accepted | Tamper suite + `vault_open` fuzz target |
| Model IDs are UUIDv4 | 0003 §1.1 | Accepted | Review 0007 finding 1 |

**Spec changes required:** None. The specs give the contents and constraints
of `header` and `keyslot` but not their byte layout, application ID or MAC
transcript. This plan assigns them as development values (format unstable
until 1.16, roadmap invariant), documents them in the crate docs, and leaves
1.16 to record the frozen values in 0002/0004 (roadmap *Revisions* note).

## Decisions needed

None. These readings follow from the specs and are recorded here so the
reviewer and owner can see them:

- **"Private directory" for user-selected paths** (revised 2026-10-26, see
  *Revisions*). The vault's parent directory must be owned by the effective
  UID or by root and writable by no one else: no other-write bit, with no
  sticky-bit exception, and no group-write bit, except on Android, whose
  per-app `files` directory is `0771` with the app's own UID and GID. Read
  and search bits are allowed, so `~/Documents` (0755) works with `--vault`.
  Anything else is `UnsafeFile`. Only the parent is checked, not every
  ancestor. *Superseded first reading:* sticky world-writable parents and
  group-writable parents with the effective GID were accepted; the review
  showed that lets another user plant SQLite sidecar files.
- **SQLite sidecar files** (added 2026-10-26). Before SQLite opens the vault
  (and the temp file in `create`), `<path>-journal`, if present, must be a
  regular file owned by the effective UID with no group or other bits, and
  `<path>-wal` and `<path>-shm` must not exist. Otherwise `UnsafeFile`.
- **Permissions are refused, not repaired.** An existing vault file whose mode
  has any group or other bits, whose owner is not the effective UID, or that is
  not a regular file is `UnsafeFile`. Silently running `chmod` would hide a
  copy or restore that went wrong. The CLI can offer a fix later.
- **Lock = `flock(LOCK_EX | LOCK_NB)` on the vault file's own descriptor.** The
  same descriptor gives the file identity (`st_dev`, `st_ino`). It must stay
  open until the SQLite connection is closed: closing any descriptor of a file
  drops the process's POSIX locks on it, including SQLite's
  ([howtocorrupt §2.2](https://www.sqlite.org/howtocorrupt.html)). On Linux,
  `flock` and SQLite's `fcntl` locks are independent. A sidecar lock file was
  rejected because it leaves extra files next to user-chosen paths.
- **Exactly one password slot.** v-dev requires exactly one `keyslot` row of
  type password. Zero or several is `Integrity`. Several local slots arrive with
  quick unlock (2.6) and password-change recovery (1.14), and those phases
  extend this rule.
- **Unknown header keys fail closed** (`Unsupported`). The header is security
  configuration, and a new field means a new format value. Unknown keys inside
  the slot descriptor are preserved, as in the keyslot record (plan 0007), and
  the header MAC covers them.
- **Initial key generation is 1.** Rotation adds 1 (0002 §3.5).

## Design

**Components touched:**
- `crates/qv-store` (new). A trusted client component. It parses the SQLite
  file, which is hostile until authenticated (0004 *Security
  Considerations*), only after the file checks, size cap and hardening, and it
  authenticates header and slots with the header MAC before returning
  `UnlockedVault`. It never sees plaintext record data in this phase.
- `crates/qv-model`: `RecordVersion::check` gains v4 checks for embedded
  `qv-crypto` IDs; `Keyslot` gets a public `encode`/`decode` for the bare
  descriptor map (the same bytes as the record payload). `qv-store` reuses it,
  so the slot descriptor has a single encoding (0003 §2.3 "atomic slot
  descriptor").
- `fuzz/`: new `vault_open` target. `.cargo/config.toml` (new): SQLite build flags.

**Interfaces** (`qv-store` re-exports these from `lib.rs`):

```rust
// error.rs — no data in any variant; Display is a fixed string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)] #[non_exhaustive]
pub enum StoreError {
    WrongPassword,  // KEK commitment / slot AEAD failed. CLI 3
    NotFound,       // the path does not exist (open). CLI 4
    Locked,         // another open holds the vault lock, or SQLITE_BUSY. CLI 6
    Replaced,       // the path no longer names the opened file. CLI 6
    Integrity,      // quick_check, schema, row checks, header MAC, SQLITE_CORRUPT/NOTADB. CLI 7
    LimitExceeded,  // file size, header/slot budget. CLI 9
    NotAVault,      // application_id is not QuickVault's. CLI 1
    Unsupported,    // unknown user_version, header format/key, profile, slot type; unsupported OS. CLI 1
    UnsafeFile,     // symlink, nonregular, owner/mode, unsafe parent directory. CLI 1
    Exists,         // create: the path exists. CLI 1
    Hardening,      // a required SQLite setting did not take effect. CLI 1
    Io,             // other I/O or SQLite failure. CLI 1
    Rng,            // OS RNG failure. CLI 1
    Internal,       // a bug. CLI 1
}
// From<CryptoError>: WrongPassword→WrongPassword, Integrity→Integrity,
// UnknownProfile→Unsupported, LimitExceeded→LimitExceeded, Rng→Rng, _→Internal.
// From<ModelError>: Malformed/Integrity/InvalidTransition→Integrity,
// Unsupported→Unsupported, LimitExceeded→LimitExceeded, Rng→Rng, _→Internal.
// rusqlite::Error and io::Error are mapped by crate-private helpers (never
// From, so no path or SQL text is carried): SQLITE_BUSY/LOCKED→Locked,
// SQLITE_CORRUPT/NOTADB→Integrity, SQLITE_TOOBIG/FULL→LimitExceeded,
// ENOENT→NotFound, ELOOP→UnsafeFile, EEXIST→Exists, else Io.

// location.rs
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocationWarnings { pub sync_folder: bool, pub network_fs: bool, pub removable: bool }
impl LocationWarnings { pub fn any(&self) -> bool; }

// header.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub vault_id: VaultId,
    pub key_generation: KeyGeneration,
    pub data_profile: StoredDataProfile,
    pub derivation_profile: DerivationProfile,
    pub mac_profile: MacProfile,
    pub min_data_profile: StoredDataProfile,
    pub min_derivation_profile: DerivationProfile,
}

// vault.rs
pub const VAULT_EXTENSION: &str = "qvault";
pub struct VaultFile { /* conn: Connection (declared first: dropped first), lock: OwnedFd,
                          identity: (dev, ino), path: PathBuf, header: Header,
                          header_body: Vec<u8>, header_mac: MacTag, slots: Vec<LocalSlot>,
                          warnings: LocationWarnings, budget: Arc<AtomicU64> */ }
impl VaultFile {
    /// Creates a new vault at `path` (must not exist; parent must exist and
    /// be private). One password KDF run. Returns it unlocked.
    pub fn create(path: &Path, password: &MasterPassword) -> Result<UnlockedVault, StoreError>;
    /// File checks, lock, hardening, quick_check, schema, header and slot
    /// decoding. No KDF, nothing authenticated yet.
    pub fn open(path: &Path) -> Result<VaultFile, StoreError>;
    /// One KDF run; VK from the password slot; header MAC verified.
    pub fn unlock(self, password: &MasterPassword) -> Result<UnlockedVault, StoreError>;
    pub fn warnings(&self) -> LocationWarnings;
    /// `Replaced` if the path no longer names the locked file (0004 §1.3).
    pub fn check_identity(&self) -> Result<(), StoreError>;
}
impl fmt::Debug for VaultFile; // "VaultFile(..)"; no path (the path is user data)
pub struct UnlockedVault { /* file: VaultFile, vk: VaultKey */ }
impl UnlockedVault {
    pub fn header(&self) -> &Header;
    pub fn warnings(&self) -> LocationWarnings;
    pub fn check_identity(&self) -> Result<(), StoreError>;
    /// For qv-core (1.8) and the 1.7 write path only; frontends never call this.
    pub fn vault_key(&self) -> &VaultKey;
}
impl fmt::Debug for UnlockedVault; // redacted
```

`LocalSlot` (crate-private): `{ slot_id: SlotId, kind: SlotType (Password),
body: Vec<u8> /* exact stored bytes */, slot: qv_model::Keyslot }`.

**Development format values** (frozen in 1.16):

| Item | Value |
|------|-------|
| `PRAGMA application_id` | `0x5156_4C54` ("QVLT") |
| `PRAGMA user_version` (schema) and header `format` | `0x7FFF_0001` (development) |
| `page_size` | 4096 (checked on open; another value → `Integrity`) |
| `MAX_DB_BYTES` | 2 GiB (1 GiB referenced ciphertext, 0004 §4.1, plus room for history, manifests and pending pruning); `max_page_count` = `MAX_DB_BYTES / 4096` |
| `MAX_HEADER_BYTES` | 64 KiB for the header body plus all slot rows (0004 §4.1) |
| `MAX_SLOTS` | 64 |
| Initial key generation | 1 |

**Schema v-dev** (exact text; stored in `sqlite_schema` exactly as executed):

```sql
CREATE TABLE header (id INTEGER PRIMARY KEY CHECK (id = 1), body BLOB NOT NULL, mac BLOB NOT NULL) STRICT
CREATE TABLE keyslot (slot_id BLOB PRIMARY KEY CHECK (length(slot_id) = 16), type INTEGER NOT NULL, body BLOB NOT NULL) STRICT, WITHOUT ROWID
```

Validation reads `SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER
BY name` (bounded with `LIMIT 17`) and requires exactly these two rows:
`table` entries with these names and byte-identical `sql`. Any other row
(index, trigger, view, extra table, `sqlite_sequence`, autoindex) is
`Integrity`. Then it checks rows independently of the SQL constraints: the
`header` count is exactly 1 with `id = 1`, `length(mac) = 32`, and every
`slot_id` is 16 bytes. It reads lengths with `length()` before reading blobs,
keeps the slot count ≤ 64, and keeps the sum of the header body and all slot
rows ≤ 64 KiB. Slot IDs come back distinct (`ORDER BY slot_id`, which is also
the MAC order) and are checked again in Rust.

**Header body** (canonical CBOR map; every key required; unknown key →
`Unsupported`): 0 `format` uint (= dev value, else `Unsupported`) · 1
`vault_id` bstr 16 (v4) · 2 `key_generation` uint (u32, ≥ 1) · 3
`data_profile` uint (u16, stored-data) · 4 `derivation_profile` uint (u16) · 5
`mac_profile` uint (u16) · 6 `min_data_profile` uint (u16) · 7
`min_derivation_profile` uint (u16). Unknown profile IDs → `Unsupported`
(`from_id`); `data_profile.accepts(min_data_profile)` and the same for
derivation, else `Unsupported`. Decoded with `qv_encoding::Decoder` (strict,
canonical; the length bound comes first).

**Local slot row:** `slot_id` = the slot ID; `type` = 0 (password; other →
`Unsupported`); `body` = `qv_model::Keyslot::encode` (canonical descriptor map
from plan 0007: slot ID, KDF profile, salt, wrap profile, KEK commitment,
nonce, wrapped VK, preserved unknown keys). On decode, the descriptor's
`slot_id` must equal the row key (`Integrity`). Unknown KDF/wrap profiles are
already `Unsupported` in `Keyslot::decode`, before any KDF.

**Header MAC** (0002 §3.3, §7.2): key = `vk.purpose_key::<HeaderMac>(vault_id,
key_generation, derivation_profile)`; tag = `mac(&key, mac_profile,
transcript)` with transcript = canonical CBOR array `["qv/header-mac/v1",
header_body (bstr), [[slot_id (bstr), type (uint), body (bstr)], …]]`. The
slots are sorted by slot ID, and the transcript uses the exact stored bytes.
`verify_mac` compares in constant time. The label is new and is a development
value; it does not collide with any 0002 label.

**Data and control flow:**

*Open* (`VaultFile::open`):
1. `lstat(path)`: missing → `NotFound`; a symlink → `UnsafeFile`. Check the
   parent directory (rule under *Decisions needed*).
2. `open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY)` (`ELOOP` →
   `UnsafeFile`); `fstat`: regular file, owner = euid, `mode & 0o077 == 0`,
   else `UnsafeFile`; `st_size ≤ MAX_DB_BYTES`, else `LimitExceeded`.
   `flock(LOCK_EX | LOCK_NB)`: `EWOULDBLOCK` → `Locked`.
3. Location warnings from the path and `fstatfs` (below).
4. `Connection::open_with_flags(path, SQLITE_OPEN_READ_WRITE |
   SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE)`: no
   `CREATE`, no `URI`. Then `stat(path)` must have the locked descriptor's
   `(dev, ino)`, else `Replaced`.
5. Harden (below) before any statement reads the schema.
6. `PRAGMA application_id` → `NotAVault`; `PRAGMA user_version` →
   `Unsupported`; `PRAGMA page_size` = 4096 → else `Integrity`.
7. `PRAGMA quick_check(1)`: the result must be exactly one row `ok`, else
   `Integrity`. It is bounded by the size cap (2), `max_page_count` and the
   step budget.
8. Exact schema validation and the independent row checks above; decode the
   header and slots.
9. Return `VaultFile` (nothing authenticated yet; only `unlock` gives a usable vault).

*Unlock* (`VaultFile::unlock`), following 0004 §5.1 and 0002 §8: take the one
password slot → `PasswordSlot::unlock(password, vault_id, key_generation)`.
KEK commitment and AEAD failures are `WrongPassword`. Then derive the
header-MAC key and verify the MAC over the stored bytes; a mismatch is
`Integrity`, never `WrongPassword`. Return `UnlockedVault`. On any error the
`VaultFile` is dropped (connection first, then the lock), and callers reopen
to retry. A wrong password costs a KDF run, and reopening costs much less.

*Create* (`VaultFile::create`):
1. `lstat(path)` must be `ENOENT` (else `Exists`). Parent checks as for open.
   File name extension `.qvault`, else `Unsupported`.
2. In the parent directory, create `.<name>.tmp-<16 hex random>` with
   `O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`, mode 0600; `flock` it.
3. Open SQLite on the temp path with the open flags above. The file exists
   and is empty, so SQLite starts a new database. Harden it, then set
   `page_size = 4096` before the first write.
4. Generate `VaultId`, `SlotId` (`RandomId::generate`) and `VaultKey`; then
   `PasswordSlot::create(…, PasswordKdfProfile::V1, PasswordWrapProfile::V1)`;
   build the header (generation 1, all profiles V1); compute the MAC.
5. One `BEGIN IMMEDIATE` … `COMMIT`: `application_id`, `user_version`, the
   DDL, the header row and the slot row. `synchronous = FULL` makes the commit
   durable.
6. Close the connection, then `fsync` the temp file and
   `renameat_with(…, RenameFlags::NOREPLACE)` it to `path` (`EEXIST` →
   `Exists`). Then `fsync` the parent directory. Keep the locked descriptor
   across the rename: same inode.
7. Re-run *Open* steps 3–9 on the final path, reusing that descriptor, and
   wrap the result with the VK already in memory into `UnlockedVault`. Then
   check the header MAC once as a self-test.
On any failure before the rename, unlink the temp file (best effort; its
SQLite `-journal` too). A crash leaves at most a `.tmp-` file and never a
partial vault at `path`.

*Hardening* (`sqlite.rs`, before any schema read):
- `db_config`: `SQLITE_DBCONFIG_DEFENSIVE` on; `ENABLE_TRIGGER`,
  `ENABLE_VIEW`, `TRUSTED_SCHEMA`, `ENABLE_LOAD_EXTENSION` (if rusqlite exposes
  it; otherwise the compile option covers it), `DQS_DDL`, `DQS_DML`,
  `ENABLE_FTS3_TOKENIZER` and `WRITABLE_SCHEMA` off. Each one is read back,
  and a mismatch is `Hardening`.
- Pragmas: `secure_delete=ON`, `temp_store=MEMORY`, `foreign_keys=ON`,
  `journal_mode=DELETE`, `synchronous=FULL`, `trusted_schema=OFF`,
  `mmap_size=0`, `cell_size_check=ON`, `max_page_count`, `busy_timeout=0`.
  Each is read back (`journal_mode` returns its value; the others with a
  `PRAGMA x` query), and a mismatch is `Hardening`.
- Limits (`set_limit`, read back): `LENGTH` = 64 MiB + 64 KiB (the largest
  1.7 blob is an encrypted manifest; 1.7 confirms it), `SQL_LENGTH` = 64 KiB,
  `COLUMN` = 16, `EXPR_DEPTH` = 32, `COMPOUND_SELECT` = 2, `VDBE_OP` =
  25,000, `FUNCTION_ARG` = 8, `ATTACHED` = 0, `LIKE_PATTERN_LENGTH` = 64,
  `VARIABLE_NUMBER` = 32, `TRIGGER_DEPTH` = 1, `WORKER_THREADS` = 0. These are
  development values. If one of our own statements hits a limit, raise only
  that limit, with a comment.
- Execution steps: `progress_handler(1000, …)` decrements a shared
  `AtomicU64` budget and interrupts at zero. `open`, `create` and `unlock` each
  reset it to `STEP_BUDGET` = 100,000,000 VM operations (development value).
  An interrupt is `LimitExceeded`.
- No application SQL functions, collations or hooks are registered except
  the progress handler.
- A crate-private, `cfg(test)`-only hook makes one named setting report a
  wrong value, so tests can show that a hardening failure aborts the open.

*Compile options* (`.cargo/config.toml` `[env]`): `LIBSQLITE3_FLAGS =
"-USQLITE_ENABLE_FTS3 -USQLITE_ENABLE_FTS3_PARENTHESIS -USQLITE_ENABLE_FTS5
-USQLITE_ENABLE_RTREE -USQLITE_ENABLE_DBSTAT_VTAB -USQLITE_ENABLE_LOAD_EXTENSION
-USQLITE_ENABLE_COLUMN_METADATA -USQLITE_SOUNDEX -USQLITE_USE_URI
-DSQLITE_USE_URI=0 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_OMIT_JSON
-DSQLITE_DQS=0 -DSQLITE_TEMP_STORE=3 -DSQLITE_SECURE_DELETE"`. A test reads
`PRAGMA compile_options` and asserts that `ENABLE_FTS3`, `ENABLE_FTS5`,
`ENABLE_RTREE`, `ENABLE_DBSTAT_VTAB`, `ENABLE_LOAD_EXTENSION` and `USE_URI`
are absent, and that `OMIT_LOAD_EXTENSION`, `TEMP_STORE=3` and
`SECURE_DELETE` are present. This catches a build that lost the flags, such
as one with an overriding environment variable. If `SQLITE_OMIT_LOAD_EXTENSION`
or `SQLITE_OMIT_JSON` breaks the rusqlite build, drop only that flag, keep its
`-U` counterpart, and log it.

*Location warnings* (`location.rs`; pure functions over the canonical parent
path plus one `fstatfs`; no network access; ancestor walk ≤ 64 levels):
- `sync_folder`: a path component equal, case-insensitively, to `Dropbox`,
  `OneDrive` (or starting with `OneDrive - `), `Google Drive`, `GoogleDrive`,
  `My Drive`, `iCloud Drive`, `iCloudDrive`, `Mobile Documents`, `Nextcloud`,
  `ownCloud`, `pCloudDrive`, `MEGA`, `Seafile`, `Sync` (Resilio, only directly
  under the home directory); or an ancestor containing `.stfolder`
  (Syncthing), `.dropbox`, `.sync` (Resilio) or `.owncloudsync.log`.
- `network_fs`: `f_type` is NFS (`0x6969`), SMB (`0x517B`), CIFS
  (`0xFF534D42`), SMB2 (`0xFE534D42`), FUSE (`0x65735546`, covering sshfs,
  rclone and many sync clients), AFS (`0x5346414F`), Ceph (`0x00C36400`) or 9P
  (`0x01021997`).
- `removable`: the path is under `/media/` or `/run/media/`, or `f_type` is
  VFAT (`0x4d44`) or exFAT (`0x2011BAB0`). Such filesystems usually cannot
  hold 0600 anyway, so the permission check then refuses the file.

The warnings are advisory. `open` and `create` succeed and report them.

*Platforms:* the file-safety module is
`cfg(any(target_os = "linux", target_os = "android"))`. On other targets,
`open`/`create` return `Unsupported`, and a `compile_error!` is not used so
the workspace still builds everywhere.

**Secrets and hostile input:**
- Secrets: `MasterPassword` (caller-owned), `VaultKey` (inside
  `UnlockedVault`, locked, zeroizing) and the `HeaderMac` purpose key (dropped
  after use). None of them reaches SQLite, errors or `Debug`. Nothing secret is
  stored in this phase: the slot holds only wrapped VK.
- Before authentication, a hostile file can cost one Argon2id run at a fixed
  profile (no attacker-chosen work factors, 0004 §4.3), a SQLite parse bounded
  by the 2 GiB cap and the limits, and decoding of at most 64 KiB of CBOR.
- `Debug` output never includes paths (they can name the user's vault).
  Errors carry no data.

**Errors:** `StoreError` as above. The roadmap's "wrong password vs
integrity" split: `WrongPassword` only from the slot; header MAC failures are
`Integrity`; tests show both on the same file.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| `rusqlite =0.40.2` (`default-features = false`, features `bundled`, `limits`, `hooks`) | SQLite access with `db_config`, limits, progress handler, open flags. Roadmap candidate (1.6); `ARCHITECTURE.md` §6. `bundled` pins SQLite 3.53.2 and its compile options. `hooks` is needed only for `progress_handler` | `sqlite` crate (less used; no `db_config`); raw `libsqlite3-sys` (needs `unsafe`) | MIT; widely used; no formal audit. `0.41.0` was released 2026-10-24, too new to adopt. Expect vet exemptions |
| `libsqlite3-sys =0.38.2` (transitive, `bundled`) | Builds the bundled SQLite C source with `cc` | System SQLite (unpinned options) | MIT (SQLite itself is public domain); exemption |
| New transitive crates (expected: `cc`, `shlex`, `find-msvc-tools`, `fallible-iterator`, `fallible-streaming-iterator`, `smallvec`; maybe `pkg-config`, `vcpkg`) | rusqlite/libsqlite3-sys build and runtime deps | — | All `MIT OR Apache-2.0` on crates.io. For each crate new to `Cargo.lock`, pin the newest version published on or before 2026-10-12 (two weeks old) that satisfies the requirements (`cargo update -p <crate> --precise <ver>`). `cc 1.10.0` and `smallvec 1.16.4` are days old, so they are not used |
| `rustix` (existing `=1.1.5`): add feature `fs` | `openat`/`O_NOFOLLOW`, `fstat`, `fstatfs`, `flock`, `renameat_with(NOREPLACE)`, `fsync` without `unsafe` | `libc` (needs `unsafe`), `nix` (new crate) | Already in the tree (plan 0003); feature only |

`qv-model` becomes a dependency of `qv-store` (path); dev-only: `proptest`.
No `unsafe`.

## Steps

### Step 1 — qv-model: encode-time ID checks and the keyslot codec

- [x] **Do:** In `qv-model`, make `RecordVersion::check` (shared by encode and
  decode) verify the v4 bits of every embedded `qv-crypto` ID:
  `VaultMeta.root_group`, `Group.parent`, `Entry.group`,
  `AttachmentMeta.entry` and `Keyslot.slot.slot_id`, with `Malformed` if one
  is not v4 (via the crate-private `is_v4`). Fix the `ids.rs` module doc: the
  invariant holds for the model's own IDs by construction and for the
  `qv-crypto` IDs by the decode and encode checks. Add
  `impl Keyslot { pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ModelError>; pub fn decode(input: &[u8]) -> Result<Keyslot, ModelError> }`
  for the bare descriptor map (`decode` bounds the input to `MAX_RECORD_BYTES`,
  then `Decoder::new`, the existing map decoder, and `finish`). Tests: for each
  of the five fields, a non-v4 `RecordId`/`SlotId` built through the public
  field makes `encode` fail with `Malformed`; `Keyslot::encode` equals the
  payload bytes inside an encoded keyslot record version; decode rejects
  trailing bytes, an unknown profile (`Unsupported`) and a missing key
  (`Malformed`); a round trip keeps unknown keys.
- **Files:** `crates/qv-model/src/{record.rs,ids.rs,payload/mod.rs,payload/keyslot.rs,payload/tests.rs}`.
- **Done when:** tests pass; existing qv-model tests are unchanged and pass.
- **Verify:** `cargo test --locked -p qv-model`

### Step 2 — Crate, dependencies, SQLite build options

- [x] **Do:** Add `rusqlite` (workspace pin, features above) and the `rustix`
  `fs` feature (`[workspace.dependencies]` keeps `process`; `qv-store` adds
  `fs`). Create `crates/qv-store` (workspace package fields, `[lints]
  workspace = true`, deps `qv-crypto`, `qv-encoding`, `qv-model`, `rusqlite`,
  `zeroize`, `rustix` for linux/android; dev `proptest`) with `lib.rs` crate
  docs (purpose, trust boundary, module map) and `error.rs` (`StoreError`,
  fixed `Display` strings, the CLI table in rustdoc, `From<CryptoError>`,
  `From<ModelError>`, crate-private `sqlite_err`/`io_err` mappers). Add
  `.cargo/config.toml` with `LIBSQLITE3_FLAGS`, with a comment saying why
  and pointing at the `compile_options` test. Pin the new transitive crates per the dependency table.
  Run `cargo deny check`, then `cargo vet` (regenerate imports, `suggest`,
  add exemptions only where nothing can be imported, `prune`) with the sandbox
  tools, and log every new crate with its version, release date and licence.
  Tests: `compile_options` (the assertions under *Compile options*); the SQLite
  version is 3.53.2; error strings are fixed; every `From` arm maps as in
  *Interfaces*.
- **Files:** `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `supply-chain/*`, `crates/qv-store/{Cargo.toml,src/lib.rs,src/error.rs}`.
- **Done when:** `cargo deny check` and `cargo vet --locked` pass; tests pass; no new licence.
- **Verify:** `cargo test --locked -p qv-store && cargo deny check && cargo vet --locked`

### Step 3 — File safety, lock, identity and location warnings

- [x] **Do:** `fs.rs` (linux/android): `check_parent(path)`, `open_existing(path)
  -> LockedFile` (*Open* steps 1–2), `create_temp(parent, name) -> (LockedFile,
  PathBuf)`, `rename_noreplace`, `fsync_dir`, `LockedFile { fd: OwnedFd, dev,
  ino }` with `same_as_path(path) -> Result<(), StoreError>`. `location.rs`:
  `LocationWarnings` and `warnings_for(path, &LockedFile)`, with the path rules
  as a pure function `path_warnings(&Path, home: Option<&Path>)` so it can be
  tested without real mounts. Tests (in a private `tempdir` created with mode
  0700 under `std::env::temp_dir()`; write a small crate-private test helper,
  no new dependency): a missing path → `NotFound`; a symlink to a valid file →
  `UnsafeFile`; a directory and a FIFO → `UnsafeFile`; modes 0640 and 0604 →
  `UnsafeFile`, 0600 and 0700 pass (only group/other bits matter); an other-writable parent → `UnsafeFile`, a sticky
  other-writable parent passes; a second `open_existing` of the same file →
  `Locked`; after renaming another file over the path, `same_as_path` →
  `Replaced`; `create_temp` never follows a pre-planted symlink at its name and
  never reuses an existing name; `rename_noreplace` onto an existing path →
  `Exists` and leaves both files; `path_warnings` for each listed name (case
  variants), `OneDrive - Contoso`, `~/Sync` vs `/srv/Sync`, `/media/x`,
  `/run/media/u/x`, a `.stfolder` ancestor, and a clean path → no warnings.
- **Files:** `crates/qv-store/src/{fs.rs,location.rs,lib.rs}`.
- **Done when:** tests pass.
- **Verify:** `cargo test --locked -p qv-store fs location`

### Step 4 — Hardened SQLite connection

- [x] **Do:** `sqlite.rs`: `open_connection(path) -> Connection` (the flags
  above), `harden(&Connection, &Arc<AtomicU64>)` (db_config, pragmas, limits,
  progress handler, each read back), `reset_budget`, and the `cfg(test)`
  failure hook. Tests: after `harden` on a fresh temp DB, each pragma, db_config
  flag and limit reads back as set; the hook makes `harden` return `Hardening`
  for a pragma, a db_config flag and a limit; with defensive mode on, `PRAGMA
  writable_schema=ON` has no effect and writes to `sqlite_schema` fail;
  `CREATE TRIGGER` and `CREATE VIEW` statements may still be stored in the
  schema but do not run (insert through a trigger leaves no side effect); a
  query that loops (recursive CTE without bound) is interrupted with
  `LimitExceeded` under a small test budget; `ATTACH` fails; `load_extension()`
  is unavailable.
- **Files:** `crates/qv-store/src/{sqlite.rs,lib.rs}`.
- **Done when:** tests pass with exact variants.
- **Verify:** `cargo test --locked -p qv-store sqlite`

### Step 5 — Schema, header and slot encodings, validation

- [x] **Do:** `schema.rs`: the DDL constants, the development
  `APPLICATION_ID`/`SCHEMA_VERSION`, `install(&Transaction)`,
  `validate(&Connection)` (application ID, user version, page size,
  `quick_check(1)`, the exact `sqlite_schema` rows, independent row checks
  with `length()` first and the budgets). `header.rs`: `Header`, its body
  encode/decode per the key table, and `mac_transcript(header_body, slots)`.
  `slot.rs`: `LocalSlot` from a row (type, row key = descriptor ID). Tests,
  each on a DB built by the module's own `install` plus rows written with raw
  SQL: golden bytes for a header body and for a two-slot MAC transcript (slot
  order by ID, not insertion); header decode rejects every missing key, an
  unknown key (`Unsupported`), `format` ≠ dev (`Unsupported`), generation 0
  (`Integrity`), an unknown profile (`Unsupported`), a non-v4 vault ID
  (`Integrity`) and trailing bytes; schema tamper, each → exact variant: an
  extra table, an index on `keyslot(body)`, an expression index, a trigger, a
  view, a `header` DDL with its `CHECK` removed (recreated table), a renamed
  column, a changed `user_version` (`Unsupported`), a foreign `application_id`
  (`NotAVault`), a `page_size` of 8192 (`Integrity`); row checks (called directly on rows
  that schema validation alone would not catch): zero header rows, a 31-byte MAC, a 15-byte slot ID, 65 slots and a 64 KiB + 1 body
  (`LimitExceeded`), a descriptor whose ID differs from its row key
  (`Integrity`), slot type 1 (`Unsupported`), zero and two password slots
  (`Integrity`); a file whose bytes are corrupted in the middle of a page →
  `Integrity` from `quick_check`, and a truncated file → `Integrity`.
- **Files:** `crates/qv-store/src/{schema.rs,header.rs,slot.rs,lib.rs}`.
- **Done when:** tests pass with exact variants.
- **Verify:** `cargo test --locked -p qv-store schema header slot`

### Step 6 — Create, open and unlock

- [x] **Do:** `vault.rs`: `VaultFile::{create, open, unlock, warnings,
  check_identity}` and `UnlockedVault` per *Interfaces* and *Data and control
  flow*, with redacted `Debug` and the field order that drops the connection
  before the lock descriptor (with a comment on why). Tests: there are few
  Argon2id runs (256 MiB each), so tests that run the KDF take a shared
  `static KDF: Mutex<()>`, and one created vault file is reused by copying its
  bytes for tamper cases (made once through a `OnceLock`). Cases: create,
  then the file is 0600, the header has generation 1 and V1 profiles, and
  `unlock` with the same password returns a VK equal to `create`'s (compare a
  derived `HeaderMac` MAC over a fixed message, not raw bytes); a wrong
  password → `WrongPassword`; the MAC column with one bit flipped →
  `Integrity` (right password); an unknown key added to the slot descriptor
  (re-encoded canonically, so it decodes) → `Integrity` (the MAC covers slots);
  the slot replaced by one from a second vault created with the same password
  → `WrongPassword` (different vault ID in the AAD); create onto an existing
  path → `Exists` without touching it; create in an unsafe parent →
  `UnsafeFile`; create with a non-`.qvault` name → `Unsupported`; no
  `.tmp-` file remains after a failed create (inject a failure after the
  temp file exists through a `cfg(test)` hook); open in the same process
  while another `VaultFile` is open → `Locked`; `check_identity` after an
  external rename-over → `Replaced`; `Debug` of both types is redacted and
  shows no path.
- **Files:** `crates/qv-store/src/{vault.rs,lib.rs}`.
- **Done when:** tests pass; the qv-store test binary uses at most 2 concurrent Argon2id runs (the mutex).
- **Verify:** `cargo test --locked -p qv-store vault`

### Step 7 — Second-process lock and tamper integration suite

- [x] **Do:** `tests/lock.rs`: the test re-executes its own binary
  (`std::env::current_exe()`, `--exact <helper> --ignored`, path in an env
  var) as an ignored helper test that tries `VaultFile::open` and exits with a
  code that tells `Locked` apart from other outcomes. While the parent holds
  the vault open, the child gets `Locked`. After the parent drops it, the child
  opens successfully. `tests/tamper.rs`: through the public API only, starting
  from a vault created once: every schema tamper case from step 5 again
  through `VaultFile::open` (so the open path, not only `validate`, rejects
  them), plus a trigger that would modify `header` on read, together with
  proof that it never ran (the header bytes are unchanged after an open
  attempt). Map each case to the 0012 row "Hostile SQLite/CBOR" in a module
  comment.
- **Files:** `crates/qv-store/tests/{lock.rs,tamper.rs}`.
- **Done when:** tests pass; the roadmap *Done when* items are each covered by a named test (list them in the log).
- **Verify:** `cargo test --locked -p qv-store --test lock --test tamper`

### Step 8 — `vault_open` fuzz target

- [x] **Do:** `fuzz/fuzz_targets/vault_open.rs`: once per process, create a
  private 0700 directory under the temp dir. Per input, write the bytes to
  `fuzz.qvault` (mode 0600, replacing the previous file) and call
  `VaultFile::open`. Any result is fine, but it must not panic, abort or hang.
  Add the `qv-store` path dependency and the `[[bin]]`, update
  `fuzz/Cargo.lock` with the same pins as the root lock, and add a "Fuzz
  vault_open (60 s)" CI step with `-max_len=65536`. Run it locally for 60 s
  with the pinned nightly (musl: `-s none`, `-use_cmp=0`), seeded only in the
  scratchpad: a vault made by `create` and a few truncations of it.
- **Files:** `fuzz/{Cargo.toml,Cargo.lock,fuzz_targets/vault_open.rs}`, `.github/workflows/ci.yml`.
- **Done when:** the 60 s run is clean; `cargo fetch --locked --manifest-path fuzz/Cargo.toml`, `cargo fmt --check --manifest-path fuzz/Cargo.toml` and `cargo deny --manifest-path fuzz/Cargo.toml check advisories bans sources` pass.
- **Verify:** the commands in *Done when*.

### Step 9 — Docs and final gates

- [x] **Do:** Complete the `qv-store` crate docs (module map, the development
  format values, the schema, the header/slot/MAC layouts, the readings under
  *Decisions needed*, error → CLI table, what is not in this phase). Update the
  files under *Documentation*, run the full gates and set the plan to
  `Implemented`.
- **Files:** `crates/qv-store/src/lib.rs`, see *Documentation*.
- **Done when:** docs match the tree; all gates green.
- **Verify:** `sh scripts/check-spdx.sh && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && cargo deny check && cargo vet --locked`

## Test plan

- **Unit tests:** header/slot codecs (golden bytes, every rejection),
  hardening read-back, schema validation, row checks, file-safety primitives,
  location rules, error mapping.
- **Rejection, malformed-input and crash-path tests:** schema tamper (trigger,
  view, index, expression index, extra table, altered DDL, user version,
  application ID, page size), corrupted and truncated files, budget
  boundaries (64 slots / 64 KiB pass, one more fails), symlinks, nonregular
  files, permissions, unsafe parents, replacement, locks (same process and a
  second process), hardening failures, a failed create leaving no
  partial vault. The only write path in this phase is create; its crash
  safety comes from temp + no-replace rename. The 1.7 crash-injection harness
  covers later writes.
- **Wrong password vs integrity:** the same vault file gives `WrongPassword`
  for a wrong password and `Integrity` for a MAC or slot-set tamper with the
  right password.
- **Vectors:** golden header body and MAC transcript bytes (development only).
- **Fuzzing:** `vault_open` in CI.
- **0012 §1 matrix rows addressed:** Hostile SQLite/CBOR (SQLite half:
  malformed schema, pages, lengths; fuzz before authentication).
  Password-slot partitioning oracle is already covered in qv-crypto; here the
  slot-swap test shows the vault binding.

## Risks and stop conditions

- **Supply chain:** if any new crate has a licence outside the allow-list, an
  advisory, or is yanked, or if `rusqlite 0.40.2` pulls a crate other than
  those listed (beyond `pkg-config`/`vcpkg`), stop and ask. Do not widen
  `deny.toml`.
- **rusqlite API gaps:** if a `db_config` flag, limit or open flag named here
  has no safe rusqlite API, log it and use the compile-time flag that covers
  it. If neither exists, stop and ask. Never add `unsafe` or call
  `libsqlite3-sys` directly.
- **Hardening readback:** if a pragma cannot be read back on SQLite 3.53.2,
  for example a write-only setting, log it with the SQLite documentation
  reference instead of silently skipping it.
- **Platform:** if `RENAME_NOREPLACE` is not supported by the test
  filesystem (e.g. some overlay or tmpfs setups return `EINVAL`), stop and
  ask. Do not fall back to a plain rename.
- **Spec gaps:** if a 0004 §1–2 requirement needs a behaviour not described
  here, log it and ask. Do not amend specs or add tables that belong to 1.7.
- **Test time:** Argon2id at 256 MiB dominates. If the qv-store tests take
  more than 60 s in debug, log it and cut KDF runs by sharing fixtures, not by
  weakening the profile or adding a test-only profile.
- No `unsafe`. Never weaken a test or replace an exact variant with `is_err()`.

## Documentation

- [x] `CHANGELOG.md`: Unreleased/Added: qv-store (vault file, hardening, schema, header MAC, create/unlock), `rusqlite`, `.cargo/config.toml` SQLite flags, `vault_open` fuzz target; Fixed: qv-model encode-time ID checks
- [x] `ARCHITECTURE.md`: §3 "Implemented so far" gains `qv-store` (vault file, header and keyslots); §6 local-storage row gains "bundled SQLite 3.53.2, trimmed compile options"
- [x] Specs: no change. 0004 stays Accepted, not fully implemented
- [x] `AGENTS.md`: *Current state* mentions `qv-store`; *Repository layout* gains `.cargo/config.toml`
- [x] `plans/README.md`: index row; roadmap 0002: tick 1.6, plan number, execution log, *Revisions* note (1.16 records the header/slot layouts, the `qv/header-mac/v1` transcript, the application ID and the schema in 0002/0004)

## Revisions

- 2026-10-26 (review finding 1, owner decision): the review showed that
  SQLite rolls back a hot `-journal` and replays a `-wal` next to the vault
  before any check runs, and that the first parent-directory reading let
  other users plant them (sticky `/tmp`, shared groups). The owner chose both
  remedies the review recommended: (a) the parent rule follows 0004 §1.1
  ("private 0700 directory", read as "writable by no one else"; read bits
  allowed), and (b) sidecar checks before SQLite opens. The `-wal`/`-shm`
  refusal goes slightly beyond the journal-only wording of (b): a probe
  showed that a planted WAL is replayed and written into the vault even
  though the vault is in rollback-journal mode, and QuickVault never uses
  WAL. No spec amendment: (a) is the spec's own rule, and the sidecar check
  implements 0004 §1.1/§1.2 and 0008 §5. The 1.16 format freeze may record
  the sidecar rule in 0004 §1.

## Execution log

- 2026-10-26: Approved (standing approval, roadmap 0002): no open decisions, no spec amendment, `rusqlite` with `bundled` is the phase 1.6 candidate (its transitive build/runtime crates follow from it), `rustix` gains only the `fs` feature, no `unsafe`. Scope matches phase 1.6 (`qv-store`, `fuzz/`). Two small additions outside the entry's file list, both justified: the plan 0007 review finding (encode-time ID checks in `qv-model`, plus the public keyslot codec that `qv-store` reuses) and `.cargo/config.toml` for the SQLite compile options.
- 2026-10-26: Status `In progress`.
- 2026-10-26: Step 1 done. `Payload::check` (shared by encode and decode) now rejects a non-v4 `root_group`, group `parent`, entry `group`, attachment `entry` or keyslot `slot_id` with `Malformed`; the `ids.rs` docs now say where the invariant holds for the `qv-crypto` IDs. `Keyslot::{encode, decode}` are the public bare-descriptor codec (input bounded to `MAX_RECORD_BYTES`, strict, `finish`; encode also checks the slot ID). Tests: each of the five fields with a public-field non-v4 ID fails `encode` with `Malformed` (a null root parent still encodes); the standalone codec equals the record payload bytes, keeps unknown keys, and rejects trailing bytes, an unknown KDF profile, each missing key, 1 MiB + 1 and a non-v4 slot ID. qv-model: 69 unit tests pass, clippy clean.
- 2026-10-26: Step 2 done. Workspace: `rusqlite = "=0.40.2"` (`default-features = false`, `bundled`, `hooks`, `limits`) and `qv-model` as a path dependency; `qv-store` adds the `rustix` `fs` feature (linux/android only). New packages in `Cargo.lock` (crates.io release date, licence): `rusqlite 0.40.2` (2026-08-08, MIT), `libsqlite3-sys 0.38.2` (2026-08-08, MIT; bundles SQLite 3.53.2), `cc 1.8.0` (2026-10-11), `find-msvc-tools 0.1.14` (2026-09-25), `shlex 2.0.1` (2026-05-17), `smallvec 1.16.3` (2026-10-10), `pkg-config 0.3.34` (2026-08-14), `vcpkg 0.2.15` (2021-06-19), `fallible-iterator 0.3.0` (2023-05-22) and `fallible-streaming-iterator 0.1.9` (2018-05-02), all `MIT OR Apache-2.0` except the MIT pair. Cargo first picked `cc 1.10.0`, `find-msvc-tools 0.1.15` and `smallvec 1.16.4`, which are days old; I pinned them back with `cargo update --precise` to the newest releases on or before 2026-10-12. `cargo deny check`: advisories, bans, licenses and sources ok. `cargo vet`: imports cover `fallible-iterator`, `fallible-streaming-iterator`, `pkg-config`, `vcpkg` and `shlex`; 5 exemptions added (`cc`, `find-msvc-tools`, `libsqlite3-sys`, `rusqlite`, `smallvec`; `suggest` offered only `trust` entries, which are a policy choice for the owner, not added); `prune` made no change; `cargo vet --locked`: 17 fully audited, 39 exempted. `.cargo/config.toml` sets `LIBSQLITE3_FLAGS`. Deviation: the plan's `-DSQLITE_USE_URI=0` was dropped. `PRAGMA compile_options` lists `USE_URI` whenever the macro is defined, even as 0, so the build only undefines it (SQLite's default is off) and the test checks that `USE_URI` is absent. `SQLITE_OMIT_LOAD_EXTENSION` and `SQLITE_OMIT_JSON` build and link fine. `crates/qv-store`: `lib.rs` (crate docs, `compile_options` test: FTS3/FTS5/R-Tree/dbstat/load-extension/column-metadata/soundex/URI absent; `OMIT_LOAD_EXTENSION`, `OMIT_JSON`, `TEMP_STORE=3`, `SECURE_DELETE`, `DQS=0` present; SQLite 3.53.2) and `error.rs` (`StoreError`, fixed strings, CLI table, `From<CryptoError>`/`From<ModelError>`, `sqlite_err` and the linux/android `errno_err` in place of the plan's `io_err`, because rustix returns `Errno`, not `io::Error`). A temporary crate-level `#![allow(dead_code)]` covers the helpers that steps 3–6 use; it is removed in step 6. 6 tests pass; workspace clippy clean.
- 2026-10-26: Step 3 done. `fs.rs` (linux/android): `LockedFile` (descriptor + `Stat` identity; `same_as_path` uses `lstat`, so a symlink or a missing path is also `Replaced`; `sync`), `check_parent`, `open_existing` (`lstat` → symlink refused; parent check; `open(O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK)` with `ENXIO`/`EISDIR` → `UnsafeFile`, then `fstat` checks and the size cap, then `flock`), `create_temp` (`.<name>.tmp-<16 hex>`, `O_EXCL | O_NOFOLLOW`, 0600, locked; removed again if a check fails), `rename_noreplace` (`EINVAL`/`ENOSYS` → `Unsupported`, never a plain-rename fallback), `sync_dir`, `remove_best_effort`, `with_suffix`, plus a test-only `TestDir` (0700 under the temp dir, no new dependency). `O_NONBLOCK` is an addition: a FIFO swapped in after the `lstat` cannot block the open. `limits.rs` holds `MAX_DB_BYTES`, `PAGE_SIZE`, `MAX_HEADER_BYTES` and `MAX_SLOTS` (public). `location.rs`: `LocationWarnings`, pure `path_warnings` and `fs_type_warnings` (32-bit magic, so a sign-extended C long works), `has_sync_marker` (≤ 64 ancestors) and `warnings_for` (canonical parent, `$HOME`, `fstatfs`). Tests: missing → `NotFound`; symlink, directory and FIFO → `UnsafeFile`; modes 0640/0604/0660/0606/0610 refused, 0600/0700 pass; other-writable parent refused, sticky 1777 passes, group-writable with our GID passes, 0755 passes, a non-directory parent is refused; a second open → `Locked`, and the lock is released on drop; identity survives an in-place rewrite and detects rename-over, deletion and a symlink; the temp file is 0600, empty and locked, and `rename_noreplace` onto an existing path → `Exists` with both files kept; the `O_EXCL | O_NOFOLLOW` flags refuse a planted symlink without touching its target; 32 temp names are distinct; a sparse file of `MAX_DB_BYTES` + 1 → `LimitExceeded` and exactly `MAX_DB_BYTES` passes; every sync name in three cases, `OneDrive - …`, `Mobile Documents`, near-misses, `~/Sync` vs `/srv/Sync`, `/media`, `/run/media`, `/mediafiles`; a `.stfolder` ancestor; filesystem magics (NFS, FUSE, sign-extended CIFS, VFAT; ext4 and tmpfs clean). 21 qv-store tests pass, clippy clean.
- 2026-10-26: Step 4 done. `sqlite.rs` (linux/android): `open_connection` (`READ_WRITE | NO_MUTEX | NOFOLLOW | EXRESCODE`; no `CREATE`, no `URI`), `harden` (db_config, limits, integer pragmas, `max_page_count` and `journal_mode` with `pragma_update_and_check`, then the progress handler; every value read back, mismatch → `Hardening`), `StepBudget` (an `Arc<AtomicU64>` counted in units of 1,000 VM operations; `reset` per operation), and the `cfg(test)` thread-local `FAIL_SETTING` hook. rusqlite has no `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION`, so as planned the compile option (`SQLITE_OMIT_LOAD_EXTENSION`) covers it. Additions to the plan's list: `ENABLE_ATTACH_CREATE` and `ENABLE_ATTACH_WRITE` are off as well (defence in depth next to the `ATTACHED = 0` limit). Tests: every setting reads back; the open never creates a missing file; the hook fails `harden` for two db_config flags, two limits, two pragmas, `max_page_count` and `journal_mode`, and a clean `harden` succeeds; defensive mode ignores `writable_schema`, so `sqlite_schema` stays unmodified; on SQLite 3.53.2 a trigger can still be stored but never fires, and a view is stored but every use is refused (probed first, then asserted exactly); an unbounded recursive CTE is interrupted → `LimitExceeded`, and the budget works again after `reset`; `ATTACH` fails without creating the file; `load_extension()` and `json()` do not exist; 70 KB of SQL is refused. 28 qv-store tests pass, clippy clean.
- 2026-10-26: Step 5 done. `schema.rs`: DDL constants, `APPLICATION_ID` (`0x5156_4C54`), `SCHEMA_VERSION` (= header `FORMAT`, `0x7FFF_0001`), `install`, `validate_schema` (application ID → `NotAVault`, user version → `Unsupported`, page size, `quick_check(1)` = exactly one `ok` row, the exact `sqlite_schema` rows with `LIMIT 17`), `read_rows` (header count 1, then `typeof`/`octet_length` of every value before reading any of them; `id = 1`; 32-byte MAC; ≤ 64 slots; ≤ 64 KiB for the header body plus 16 bytes and the body of each slot; slot IDs strictly ascending in Rust) and `validation_err` (inside validation, any non-operational SQLite error, including type-conversion errors and `SQLITE_ERROR` from a hostile schema, is `Integrity`; busy → `Locked`; interrupt/too big → `LimitExceeded`; I/O, OOM and permission → `Io`). `header.rs`: `Header` (public), `encode`/`decode` per the key table (missing key, non-v4 ID, out-of-range integers, trailing bytes → `Integrity`; unknown key, other format, unknown profile, data/derivation profile below its minimum → `Unsupported`; generation 0 → `Integrity`), `mac_transcript`, `MAC_LABEL`, `INITIAL_GENERATION`. `slot.rs`: `LocalSlot` (`from_stored`: type 0 only, v4 row key, `Keyslot::decode`, descriptor ID = row key; `password`; `row`) and `password_slot` (exactly one). The plan's `octet_length` use differs from its `length()`: `octet_length` counts bytes for text values too, so the size check holds before the type check rejects them. Tests: header golden bytes and the transcript golden bytes for two slots plus the empty list; every header rejection; schema tamper (extra table, index, expression index, trigger, view, a recreated `header` without its `CHECK`, a renamed column, `AUTOINCREMENT` / `sqlite_sequence` → `Integrity`; `user_version` → `Unsupported`; `application_id` → `NotAVault`); page size 8192 → `Integrity`; a plain SQLite database → `NotAVault`; random bytes → `Integrity`; a byte-corrupted b-tree page and a truncated file → `Integrity` (for the truncated file, hardening's `journal_mode` read can notice first, so the test covers harden + validate together); row checks (no header row, a 31-byte MAC, a 15-byte slot ID inserted with `ignore_check_constraints`, 64 vs 65 slots, exactly 64 KiB vs one byte more, a 64 KiB + 1 header body, a negative type → `Unsupported`); a text slot ID smuggled into the STRICT table by editing and restoring the stored DDL → `Integrity`; slot identity, unknown type, non-v4 key, garbage body, an unknown KDF profile in the descriptor (`Unsupported`), zero or two password slots. 39 qv-store tests pass, clippy clean.
- 2026-10-26: Step 6 done. `vault.rs` (linux/android): `VaultFile::{open, unlock, warnings, check_identity, create}` and `UnlockedVault::{header, warnings, check_identity, vault_key}` per the plan, with `VAULT_EXTENSION`, redacted `Debug` (no path) and the connection declared before the lock so it is dropped first (commented). `open_locked` is shared by `open` and the end of `create`, so a new vault is validated by the same path as any other. In `create`, the temp file is fsynced and renamed with no-replace, and on any failure before the rename the temp file and its `-journal` are removed. The header MAC is recomputed as a self-test after reopening. One addition: `create` maps a missing parent directory to `NotFound`. The temporary crate-level `allow(dead_code)` from step 2 is gone; the only remaining `allow` is on the `conn` field, which nothing reads until 1.7 (commented). New `unsupported.rs`: on targets other than Linux/Android the same API uses uninhabited types, and `open`/`create` return `Unsupported`. On Linux it compiles only under `cfg(test)`, with a test, because no other target is installed here to check it. Tests (Argon2id runs serialized by a `static` mutex; one shared fixture vault made through `OnceLock` and copied per test): create gives a 0600 file, generation 1 and V1 profiles, no warnings, `Locked` while open, the same VK after reopen (compared through a header-MAC-key MAC, never raw), and nothing left in the directory besides the vault; the fixture unlocks; a wrong password → `WrongPassword`; a flipped MAC bit with the right password → `Integrity`; an unknown key added canonically to the slot descriptor (it still decodes) → `Integrity`, which shows the MAC covers slots; the slot row of another vault with the same password → `WrongPassword` (vault-bound KEK and AAD); create onto an existing file or a dangling symlink → `Exists` (the file is untouched), a non-`.qvault` name → `Unsupported`, an other-writable parent → `UnsafeFile`, a missing parent → `NotFound`; the `FAIL_CREATE` hook → `Internal` with an empty directory afterwards; a second open → `Locked`; rename-over → `Replaced`, and the replacement opens on its own once the first handle is dropped; redacted `Debug`. 50 qv-store tests pass in 3.6 s (8 Argon2id runs), clippy clean.
- 2026-10-26: Step 7 done. `tests/lock.rs`: `second_process_gets_lock_error` creates a vault, holds it open and re-runs its own test binary as the ignored `lock_helper` (path in an environment variable; exit code 3 = `Locked`, 0 = opened, 4 = other). The child gets `Locked`, and after the parent drops the vault it opens. `tests/tamper.rs` (public API only, one vault made by `create`, modified with a plain unhardened rusqlite connection as an attacker would; every refusal also checks that the file is byte-for-byte unchanged): an untouched copy opens without changing a byte; 18 schema and row changes with exact variants (extra table, index, expression index, partial index, two triggers, view, a `header` recreated without its `CHECK` with its rows copied back, a renamed column, an added column → `Integrity`; `user_version` → `Unsupported`; `application_id` → `NotAVault`; deleted header or slots, a short MAC, a garbage header body or slot body → `Integrity`; slot type 7 → `Unsupported`); a file truncated to one page or half a page, each page after the first overwritten in turn, and random bytes → `Integrity`; an empty file → `NotAVault`; mode 0644 → `UnsafeFile`; a symlink → `UnsafeFile`. The plan's "trigger that would modify `header` on read" is covered by the byte-identity check: SQLite has no read triggers, the stored `AFTER UPDATE`/`BEFORE DELETE` triggers are refused, and the file is unchanged. Roadmap *Done when*, by named test: unexpected trigger, view and schema version → `tamper_schema_changes_are_refused` (and unit test `schema_tamper_is_rejected`); pragma failure → `sqlite_hardening_failures_abort`; wrong password vs integrity, on the same file → `vault_wrong_password` vs `vault_header_mac_tamper_is_integrity` and `vault_mac_covers_slots`; second process → `second_process_gets_lock_error`. Clippy clean.
- 2026-10-26: Step 8 done. `fuzz/fuzz_targets/vault_open.rs`: a 0700 directory per process under the temp dir; each input is written to `fuzz.qvault` (0600, replacing the previous one) and passed to `VaultFile::open`; any result is accepted. `fuzz/Cargo.toml` gains the `qv-store` path dependency and the `[[bin]]`. In `fuzz/Cargo.lock`, `cc`, `find-msvc-tools` and `smallvec` are pinned to the root lock's versions, so every shared package has the same version (checked by script; the only fuzz-only packages are `arbitrary`, `jobserver`, `libfuzzer-sys` and the fuzz crate). CI: a "Fuzz vault_open (60 s)" step with `-max_len=65536`, run from the repository root so `.cargo/config.toml` applies to the fuzz build too. Deviation in seeding: the plan said to seed with a vault made by `create` and truncations of it. I built an equivalent schema-exact vault with Python's stdlib `sqlite3`: the exact DDL (the stored SQL compared equal to ours), a canonical header body and slot descriptor, and a garbage MAC (open never checks the MAC), so `create` and its Argon2id run were not needed. Plus a one-page and a tail truncation, all in the scratchpad only. Local run (`nightly-2026-10-01`, cargo-fuzz 0.13.2, musl: `-s none`, `-use_cmp=0`): 855,970 runs in 61 s, Rust coverage 597 (bundled SQLite C code is not instrumented), 73 corpus entries, no crash, timeout or leak. `cargo fetch --locked` and `cargo fmt --check` for `fuzz/` pass; `cargo deny --manifest-path fuzz/Cargo.toml check advisories bans sources` passes.
- 2026-10-26: Step 9 done; plan `Implemented`. Crate docs for `qv-store`: module map with spec sections, the development format values, the tables, the header/slot/MAC layouts, the readings under *Decisions needed*, the error → CLI table, and what is not in this phase. Docs: `CHANGELOG.md` (Added: qv-store; Fixed: qv-model encode-time ID checks), `ARCHITECTURE.md` §3 "Implemented so far" and the §6 local-storage row, `AGENTS.md` (current state; `.cargo/config.toml` in the layout table), roadmap 0002 (1.6 ticked with plan 0008, *Revisions* note, execution log), `plans/README.md`. Specs unchanged: 0004 stays Accepted and is not fully implemented (§2 tables `object`, `manifest`, `local_head`, `sync_state`, §3, §5.1 second half and §5.2–5.3 remain; §6 archives in 1.13); 0002 and 0008 unchanged. Final gates: SPDX ok; `cargo fmt --check` ok (root and `fuzz/`); clippy `-D warnings` clean; `cargo test --locked` 314 passed, 0 failed, 2 ignored (the plan 0005 vector generator and the `lock_helper` child test), qv-store unit tests 3.2 s; `cargo doc` with `-D warnings` ok for qv-store and qv-model; `cargo deny check` ok; `cargo vet --locked` ok (17 audited, 39 exempted); fuzz lockfile ok.
  Found, not fixed: (1) `create` checks the name and the parent, then creates the temp file. Between those steps a same-user process could swap the parent directory, but it could do the same to any of the user's files, and other users are excluded by the parent rule. (2) `LocationWarnings` are heuristics (no network access): a sync client that uses none of the listed names, markers or filesystem types goes unnoticed, so the CLI text should say "may" (1.10). (3) The 2 GiB `MAX_DB_BYTES` and the SQLite limits are development values; 1.7 should confirm `LENGTH` against the manifest envelope, and 1.16 freezes them. (4) A `.tmp-` file can survive a crash during `create` (never a partial vault at the path); a later `create` does not clean it up. Removing stale temp files with our naming is a possible 1.10 `init` nicety. (5) The `unsupported.rs` stub was compiled and tested on Linux only (no other target installed); phase 4.1 compiles it for real.
- 2026-10-26: Reviewed ([REVIEW.md](REVIEW.md)): **Changes requested**; status stays `Implemented`. Finding 1 (high, escalated): another user who can create `<path>-journal` in the parent directory can make SQLite roll back a crafted hot journal before validation and truncate or overwrite the vault (confirmed with a temporary probe). The parent rule under *Decisions needed* (sticky world-writable and own-GID group-writable parents) is looser than 0004 §1.1's "private 0700 directory". The owner chooses the directory rule; then the fix (parent rule, journal check before SQLite opens, tamper tests) is done within this plan.
- 2026-10-26: Owner decision on review finding 1: both remedies, (a) and (b). Status `In progress`.
- 2026-10-26: Review finding 1 fixed (see *Revisions*). `fs.rs`: `check_parent` no longer accepts a sticky world-writable or a group-writable parent; group write is allowed only on Android, for a directory owned by the effective UID with the effective GID (`own_group_dir`, `cfg(target_os = "android")`). New `owner_only` (shared by the vault-file check and the sidecar check) and `check_sidecars`: an existing `-journal` must be a regular, owner-only file of the effective UID (`lstat`, so a symlink, even a dangling one, is refused); any `-wal` or `-shm` entry is refused; all `UnsafeFile`. `vault.rs` calls `check_sidecars` before `open_connection` in `open_locked` and in `build` (the temp file). Docs: `fs` module docs, `lib.rs` readings and module map, `vault` docs. Tests: `fs_parent_rules` now expects `UnsafeFile` for 1777, 0770 and 1770 parents and accepts 0750 (the earlier assertions encoded the superseded reading); new `fs_owner_only_rule` (another owner, root, modes, file types) and `fs_sidecars` (own journal passes; 0666/0644/0660/0604 journals, a symlink, a dangling symlink and a directory are refused; private `-wal` and `-shm` are refused). `tests/tamper.rs`: `tamper_planted_sidecars_are_refused` (the review's truncating journal at 0666, a symlinked journal, a real WAL that zeroes the header MAC, an empty `-shm`; each refused with the vault byte-identical, then the clean vault opens), `tamper_own_hot_journal_is_rolled_back` (a torn page 2 plus a hand-built synced journal with the original page and a valid checksum: open succeeds, the journal is gone and the file equals the original, so crash recovery still works), `tamper_shared_parent_is_refused` (1777 parent). A first version of the hot-journal test copied a journal from the middle of a transaction; with `synchronous=FULL` SQLite writes the journal magic only when it syncs, so that journal was correctly not hot, and the test now builds a synced journal. Mutation check: with `check_sidecars` removed from `open_locked`, `tamper_planted_sidecars_are_refused` fails. Gates: SPDX ok, `cargo fmt --check` ok (root and `fuzz/`), clippy `-D warnings` clean, `cargo test --locked` 319 passed, 0 failed, 2 ignored. No dependency change, so deny and vet were not re-run. Found, not fixed: the Android branch of `own_group_dir` is not compiled here (no Android target installed); phase 1.9 or 2.3 builds it. Status `Implemented`.
- 2026-10-26: Fix checked against review finding 1 ([REVIEW.md](REVIEW.md), *Follow-up*): Approved; status `Reviewed`.
