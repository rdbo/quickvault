# Plan 0018 — Archives, local snapshots and `verify` (roadmap 1.13a)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-27 | 2026-10-28 (D1 approved by owner; standing approval for the rest, roadmap 0002) | 0004 §3.6, §4, §5.3, §6; 0007 §3 (+ D6 amendment); 0005 §5.4; 0008 §1–2/§5; 0011 §1–6; 0012 §1 |

## Intent

Make a vault's committed state independently recoverable: write immutable
authenticated archives from verified local objects, take and prune local
snapshots on the schedule 0007 §3 defines, and give the user an explicit full
integrity check. This plan covers **phase 1.13a**; the phase was split (see
*Revisions*) because the whole of 1.13 does not fit one session.

## Scope

**In scope (1.13a):**
- The D6 0007 amendment (slot policy for local snapshots, pre-change deletion
  offer) and the concrete 0011 contracts for `snapshot ls` and `verify`.
- `qv-store`: archive header codec, archive writer with the temp → re-read and
  verify → fsync → publish-under-a-new-name protocol, archive reader
  (bounded prefix/header, VK → header MAC → manifest hash → frames in
  reference order before AEAD), a `SnapshotDir` for the private snapshot
  directory, and one full `verify` pass over all referenced ciphertext.
- `qv-core`: snapshot policy (hourly coalescing, first unlock of the day,
  mandatory pre-operation recovery snapshots), count/byte/age budgets with
  pruning, authenticated snapshot listing, pre-change-snapshot API for 1.14,
  and `Session::verify`.
- `qv-cli`: `qvault snapshot ls`, `qvault verify`, the recovery-snapshot step of
  `trash empty`.
- The archive-reader fuzz target and its CI wiring; the four 0012 §1 rows the
  roadmap assigns to this phase, for the writer/reader/`verify`/policy halves.

**In scope (1.13b, separate plan written in its own session):** `snapshot
restore <id> <path>` — building a **new** vault file from a verified archive
(store `create_from_archive`, core orchestration, CLI command, restore-path
evidence).

**Out of scope:** `snapshot export` and archive merge/file exchange (2.2),
self-contained archives with a password slot (0004 §6.4, phase 2), password
change and rotation (1.14/1.15), repair of a damaged vault (only reporting and
snapshot restore), configurable larger budgets (0007 §3.3), server purge
acknowledgements, new dependencies, `unsafe`, any change to the SQLite schema,
and any second durability/write path.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Archive stream, header fields, reader order, no slot by default, publish protocol | 0004 §6 | Accepted | Primary contract; format integers are development values until 1.16 |
| Full re-hash on `qvault verify` and before an archive; verified-object verification points | 0004 §3.6 | Accepted | `verify` and writer behaviour |
| Budgets before allocation; mutual consistency | 0004 §4 | Accepted | Header 64 KiB, manifest 64 MiB, objects 250,000 / 1 GiB |
| Archives are built from verified objects, never from the live SQLite file | 0004 §5.3 | Accepted | 0012 row "Live SQLite copying" |
| Snapshot policy (3.1 slot policy after the D6 amendment), coalescing, budgets, restore-as-new-path | 0007 §3 | Accepted | 3.1/3.5 amended by step 1 |
| Local head, external anchor, one-step crash rule, explicit recovery baseline | 0005 §5.4 | Draft | Roadmap D5 go-ahead |
| Confidential metadata, one authenticated object at a time, bounded buffers | 0008 §1–2/§5 | Draft | Roadmap D5 go-ahead |
| `snapshot ls` / `verify` command contracts, output, exit codes | 0011 §4–6 | Accepted | Concrete amendment below requires **D1** |
| Evidence rows and release-gate expectations | 0012 §1, §3 | Accepted | Rows named in the test plan |

**Spec changes required:** the 0007 §3 amendment of step 1 (authorized by owner
decision D6 as recorded in roadmap 0002, and named in the phase entry's own
scope) and the 0011 §4–5 amendment of step 2 (requires D1). No spec is promoted
to `Implemented`: 0004 still lacks 1.16's freeze evidence, 0007 §4 (server
retention) is unimplemented, and 0011 has phase 2–3 command families missing.

## Decisions needed

1. **D1 — Approve the concrete `snapshot`/`verify` CLI amendment (step 2).**
   Recommendation: approve it as written. The current 0011 §4 rows are one line
   each and do not define JSON schemas, archive-ID addressing, what `verify`
   reports, how the anchor is treated, or the ordering/prompt rule for the
   mandatory recovery snapshot before `trash empty`. These are user-visible
   data and failure behaviour; guessing them in code repeats exactly what
   1.11/1.12 had to amend. Alternatives: narrow `snapshot ls` to human output
   only (no `--json`), or drop `verify`'s anchor-recovery semantics (then a
   vault with a missing anchor cannot be diagnosed, only unlocked for
   recovery). Blocks: step 2 onwards. Resolution: **owner approved amendment B
   as written on 2026-10-28.** Steps 2–10 therefore run under the roadmap's
   standing approval; the split into 1.13a/1.13b is the roadmap-authorized
   session-size split recorded in *Revisions*.

**Not owner decisions (recorded readings, so the developer does not have to
invent them):**

- The 0007 amendment is *authorized*: D6's recorded resolution (roadmap 0002)
  names it as this phase's first step, so it is not a deviation from the phase
  entry. Standing approval still does not apply because of D1.
- Roadmap 0002's noted gap "0011 has no command to adopt a vault with a
  missing or mismatched anchor" is untouched here: a restored copy (1.13b)
  starts with a fresh anchor and needs no adoption; `recover` (1.14) owns it.
- "Explicit file imports" in 0007 §3.2 means archive/exchange import (0005 §4,
  `merge`), not `attach add`, which is an ordinary causal edit whose
  intermediate states record history covers. Mandatory recovery snapshots are
  wired to bulk deletion (`trash empty`) now and exposed for 1.14, 1.15 and 2.2.
- Snapshot files need bookkeeping the archive header does not carry (ordinary
  vs recovery copy). It stays **outside the archive format**: a filename
  prefix. Nothing in the format, header MAC or budgets changes.
- `verify` never repairs, rewrites or "fixes" anything, and never writes to the
  vault. The documented remedy for a failed `verify` is restoring a snapshot.

## Design

### Adopted normative amendment A — 0007 §3 (owner decision D6)

Step 1 replaces 0007 §3.1's third sentence, adds §3.5, resolves OQ1 and appends
a Changelog line. Exact text:

> 3.1. Snapshots are archives (0004 §6) written from verified local objects.
> They never contain device-local quick slots, signing keys, session tokens,
> sync state or external anchors. By default a local snapshot carries **no
> password slot** (0004 §6.4; roadmap 0002 decision D6): it opens only with the
> vault key of the same vault ID and key generation — i.e. from the active
> vault that wrote it, or any other replica holding that key — or with the
> recovery phrase. An archive that gives a file-sync provider, a backup thief
> or a copy on a shared medium nothing to attack offline MUST NOT be weakened
> for convenience: no slot is added unless the user explicitly chooses a
> self-contained archive (0004 §6.4). Store snapshots in a private application
> directory, outside exchange directories.
>
> 3.5. **Password changes and existing snapshots.** Changing the master
> password (0002 §3.4) leaves the vault key and key generation unchanged, so
> snapshots taken before the change remain decryptable with that key. Because
> the old password may be the reason for the change, the frontend MUST, after a
> successful password change, offer to delete the snapshots created before it,
> naming how many exist. It MUST delete them only on explicit confirmation, and
> it MUST NOT describe the result as cryptographic erasure: copies held
> elsewhere, on other media or by other devices are unaffected (§4.3), and a
> party that obtains the vault key from an old vault-file copy or an old keyslot
> can still open them. Declining the offer keeps them under the ordinary
> snapshot budgets (§3.2–3.3).
>
> Open Questions 1. **Password slots in local snapshots.** *Resolved
> 2026-10-25 (owner decision D6, roadmap 0002): no password slot by default.
> On password change, offer to delete pre-change snapshots (§3.1, §3.5).
> Self-contained archives remain an explicit, warned user choice (0004 §6.4).*
>
> Changelog: `2026-10-27: Resolve OQ1 per owner decision D6. Local snapshots
> carry no password slot and open with the vault key or the recovery phrase;
> add §3.5 (offer to delete pre-change snapshots on password change) and the
> private-directory requirement (plan 0018).`

Consequences to implement: `password_slot` is never emitted; the archive header
type must still *recognise* the field so that a self-contained archive is
rejected with an explicit "unsupported until phase 2" error rather than as a
generic malformed header; the pre-change-snapshot API exists in core from this
phase and is used by `passwd` in 1.14.

### Adopted normative amendment B — 0011 §4–5 (requires D1)

Step 2 adds these contracts under 0011 §4 (new subsection "Snapshots and
verification", after *History and snapshots*) plus a §5 cross-reference and a
Changelog line.

- **`qvault verify [--json]`** — requires unlocking the selected vault. It
  re-hashes every referenced object, authenticates the manifest, every active
  head, every retained history version and every attachment chunk (0004 §3.6),
  and reports the local head and the external anchor comparison. It never
  mutates the vault and never repairs it. It unlocks with the recovery-anchor
  semantics, so a vault whose anchor is missing or mismatched is still
  checked and reported rather than refused before the report exists.
  Human output is one line per check group plus a summary line; JSON is
  `{"vault_id","key_generation","local_seq","anchor","objects","records",
  "active_heads","retained_versions","tombstones","total_bytes","ok","notes"}`,
  where `anchor` is `"verified"|"advanced"|"missing"|"mismatch"`, counts are
  integers, `notes` is an array of fixed-label strings (for example
  `"suppression-floor-covers-dominated-versions"`) and no object ID, hash,
  record ID, payload or path appears. Exit 0 when every check passes and the
  anchor is `verified` or `advanced`; 7 for any integrity failure (missing or
  mismatched object, length, hash, AEAD, manifest, head, anchor); 3 wrong
  password; 6 locked or changed on disk; 9 over a bound; 1 otherwise
  (including cancellation).
- **`qvault snapshot ls [--json]`** — requires unlocking the selected vault (it
  authenticates each snapshot header with the vault key) and lists only local
  snapshots of that vault ID and key generation, newest first by authenticated
  `created_at` and then archive ID. Rows: `id` (32 lowercase hex archive ID),
  `created_at` (RFC3339), `kind` (`"ordinary"` or `"recovery"`), `size`
  (bytes on disk), `objects` (integer), `total_bytes` (referenced ciphertext).
  JSON is `{"snapshots":[…]}`. Files in the snapshot directory that cannot be
  authenticated, belong to another vault or generation, or carry a password
  slot are reported as warnings on stderr and never appear as rows, so one
  damaged file cannot hide the healthy ones; that case does not change the exit
  code. Exit 0; 3/6/9 as above; 1 for I/O.
- **`<id>`** in `snapshot restore` (1.13b) is a full 32-hex archive ID or an
  unambiguous prefix of at least six hex characters, with optional `@`.
  Invalid syntax 2; absent 4; ambiguous 5 with the matching IDs; an archive of
  another vault or generation, or one carrying a password slot, is 7 when the
  header cannot be authenticated with the available vault key.
- **Snapshots and destructive operations (0007 §3.2–3.3).** `trash empty`
  writes and verifies a recovery snapshot before its deletion commits. If the
  snapshot does not fit the ordinary budgets it reports the required space and
  asks for explicit approval to exceed them (`--yes` gives that approval);
  declining aborts the deletion with exit 9 and no change. If the snapshot
  cannot be written at all (disk full, unsafe directory), the deletion is
  aborted with exit 1 and nothing is purged. After the deletion commits the copy
  becomes an ordinary snapshot subject to pruning. Soft deletes (`rm`,
  `trash restore`) and `attach add` take no snapshot.
- **Ordinary snapshots are automatic policy, not user actions.** An unlock may
  take at most one ordinary snapshot per hour and one on the first unlock of a
  day (0007 §3.2). Snapshot failures and budget skips never fail the requested
  command and never touch stdout; they are warnings on stderr.
- With `--password-stdin`, the confirmation and budget question of
  `trash empty` require `--yes` before unlock, as for the other destructive
  commands. Read commands reject nothing new; `snapshot restore` rejects
  `--json` before unlock.
- Changelog: `2026-10-27: Owner-approved snapshot/verify CLI contract: full
  integrity report with anchor status, authenticated local-snapshot listing,
  scoped archive IDs and the mandatory recovery snapshot before bulk deletion
  (plan 0018).`

### Components and interface sketch

No new crate and no new trust boundary. The CLI continues to reach vaults only
through `qv-core`; `qv-store` keeps all filesystem and format work; policy
stays in `qv-core`.

```rust
// qv-store/src/archive.rs (new; Linux/Android with fail-closed stubs elsewhere)
pub const ARCHIVE_MAGIC: [u8; 7] = *b"QVSNAP\0";
pub const ARCHIVE_FORMAT: u8 = 0x01;            // development value (1.16)
pub const MAX_ARCHIVE_HEADER_BYTES: usize = 64 * 1024;

/// 0004 §6.2; bounded decode before authentication, `Debug` redacted.
pub struct ArchiveHeader { /* archive_id, vault_id, key_generation,
    data_profile, minimum_profiles: (u16, u16), created_at, manifest_hash,
    reference_digest, object_count, total_length, header_mac */ }
impl ArchiveHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError>;   // bounded, strict
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError>;
    pub fn archive_id_hex(&self) -> String;
    pub fn verify_mac(&self, vk: &VaultKey) -> Result<(), StoreError>; // qv/archive-header/v1
}

/// One published archive's authenticated facts.
pub struct ArchiveStats { pub archive_id: String, pub created_at: Timestamp,
    pub object_count: u64, pub total_length: u64, pub vault_id: VaultId,
    pub key_generation: KeyGeneration }

impl UnlockedVault {
    /// Streams the committed state into `out` (0004 §6). Manifest envelope bytes
    /// and every referenced object, in the manifest's sorted reference order.
    pub fn write_archive<W: std::io::Write>(&mut self, out: W, created_at: Timestamp,
        cancelled: &dyn Fn() -> bool) -> Result<ArchiveStats, StoreError>;

    /// Full re-hash/authentication pass over the vault (0004 §3.6).
    pub fn verify_all(&self, cancelled: &dyn Fn() -> bool) -> Result<VerifyCounts, StoreError>;
}
pub struct VerifyCounts { pub objects: u64, pub records: u64, pub active_heads: u64,
    pub retained_versions: u64, pub tombstones: u64, pub suppressed_records: u64,
    pub total_bytes: u64 }

/// The private snapshot directory (0005 §5.4 anchors are the model).
pub struct SnapshotDir { /* path */ }
impl SnapshotDir {
    pub fn open(dir: &Path) -> Result<Self, StoreError>;
    pub fn default_dir() -> Result<PathBuf, StoreError>;  // $XDG_STATE_HOME/quickvault/snapshots
    /// temp file in the same directory → write → re-read and verify → fsync →
    /// RENAME_NOREPLACE under a new unique name → fsync the directory (0004 §6.5)
    pub fn publish(&self, vault: &mut UnlockedVault, kind: SnapshotKind,
        created_at: Timestamp, cancelled: &dyn Fn() -> bool)
        -> Result<PublishedSnapshot, StoreError>;
    pub fn entries(&self) -> Result<Vec<SnapshotEntry>, StoreError>; // file name + size only
    pub fn read_header(&self, entry: &SnapshotEntry, vk: &VaultKey)
        -> Result<ArchiveHeader, StoreError>;
    pub fn remove(&self, entry: &SnapshotEntry) -> Result<(), StoreError>;
    pub fn reclassify_as_ordinary(&self, entry: &SnapshotEntry) -> Result<SnapshotEntry, StoreError>;
}
pub enum SnapshotKind { Ordinary, Recovery }   // file name prefix "", "recover-"

// qv-core/src/snapshot.rs (new)
pub struct SnapshotPolicy { pub dir: SnapshotDir, pub max_count: u32, /*48*/
    pub max_bytes: u64, /*512 MiB*/ pub max_age_seconds: i64 /*30 d*/ }
pub struct SnapshotSummary { pub archive_id: String, pub created_at: Timestamp,
    pub kind: SnapshotKind, pub size: u64, pub objects: u64, pub total_bytes: u64 }
pub struct SnapshotReport { pub published: Option<SnapshotSummary>,
    pub pruned: Vec<String>, pub skipped: Option<SnapshotSkip> }
pub enum SnapshotSkip { Disabled, OnePerHour, AlreadyToday, OverBudget { needed: u64 } }

impl CoreConfig { pub fn with_snapshots(self, policy: SnapshotPolicy) -> Self; }
impl Session {
    pub fn snapshots(&self) -> Result<Vec<SnapshotSummary>, CoreError>;
    /// 0007 §3.2 mandatory pre-operation copy; the handle pins the copy until
    /// it is finished or dropped.
    pub fn begin_destructive(&self, allow_over_budget: bool,
        cancel: Option<&CancelToken>) -> Result<RecoverySnapshot, CoreError>;
    pub fn finish_destructive(&self, snap: RecoverySnapshot) -> Result<(), CoreError>;
    /// 1.14 `passwd` support: snapshots created before `cutoff`.
    pub fn snapshots_before(&self, cutoff: Timestamp) -> Result<Vec<SnapshotSummary>, CoreError>;
    pub fn delete_snapshots(&self, ids: &[String]) -> Result<usize, CoreError>;
    pub fn verify(&self, cancel: Option<&CancelToken>) -> Result<VerifyReport, CoreError>;
    pub fn snapshot_status(&self) -> Option<SnapshotReport>; // automatic-policy outcome
}
pub struct VerifyReport { pub counts: VerifyCounts, pub local_seq: u64,
    pub anchor: AnchorStatus, pub notes: Vec<VerifyNote> }
```

Every listed type gets a redacted `Debug` and no `Clone` where it holds key or
metadata material. `CoreError`/`StoreError` variants are reused; the only new
one is `CoreError::SnapshotOverBudget { needed: u64 }` (maps to exit 9), so
`verify`/`snapshot` add no exit-code mapping.

### Data and control flow

**Archive creation (no vault mutation, therefore no new commit path).**
The private core path — used by the automatic unlock policy and by
`begin_destructive` — is `take_snapshot(kind)` → `SnapshotDir::publish`:
1. Build the header from the *verified* committed state this session holds
   (`manifest_hash` = the manifest row's stored hash, `reference_digest` =
   `Manifest::reference_digest()`, `object_count` = reference count,
   `total_length` = sum of reference lengths), header MAC under the
   `header-mac` purpose key with transcript
   `["qv/archive-header/v1", header fields]`.
2. `fs::create_temp` in the snapshot directory (owner-only, no symlinks,
   private parent, `RENAME_NOREPLACE`).
3. Write `"QVSNAP\0" || version || u32be header_length || header`, then
   `frame(manifest envelope)`: the canonical envelope
   `[key_generation, data_profile, nonce, ciphertext]` re-encoded from the
   stored parts, whose SHA-256 is checked against the stored `manifest_hash`
   first. Then one frame per reference, in the manifest's already-validated
   sorted object-ID order, each `u32be length || ObjectEnvelope::encode()`.
4. Each object row is streamed and its ciphertext hashed and length-checked
   against its reference before the frame is written; a missing row, wrong
   profile, wrong length or wrong hash aborts with `Integrity` and nothing is
   published. Bytes are copied in bounded buffers (never a whole vault, never
   the whole archive in memory). Cancellation is checked between objects and
   between 1 MiB blocks → `Io`, temp removed.
5. Re-open the temp file and verify it with the archive reader (header MAC,
   manifest frame hash, manifest decrypt + decode + `validate`, every frame's
   length and SHA-256 in order, exact EOF, `object_count`/`total_length`), then
   `fsync` the file, `rename_noreplace` to `<archive_id>.qvsnap` (or
   `recover-<archive_id>.qvsnap`), and `fsync` the directory.
6. On any failure: remove the temp (and its sidecars); report the error. A
   crash leaves at most an unpublished temp file, never a published partial
   archive.

The whole write runs under one SQLite read transaction opened after re-checking
that the on-disk head is the one this session verified (`StoreError::Changed`
otherwise); the live SQLite file is never copied, opened for reading as a file,
or normalized. Nothing calls `Write`, so no manifest/head/pruning/anchor
ordering is involved and no DB row changes. If a step ever seems to need a
vault write, stop: that is a new write path and forbidden here.

**Snapshot policy (0007 §3.2–3.3).** On unlock, `Core` consults the snapshot
directory only (authenticated headers of this vault ID and generation): take an
ordinary snapshot when there is no ordinary snapshot from today's local date,
or when the newest is more than an hour old. Budgets are 30 days / 48 ordinary
snapshots / 512 MiB aggregate, oldest first by authenticated `created_at`.
Before writing, prune to make room; never delete the copy pinned by the
operation in progress; a `recover-` file that is not pinned is reclassified to
an ordinary snapshot first, so recovery copies cannot accumulate forever, and a
pinned one is never deleted. No policy state is stored in the vault: a marker
row or settings write would put a commit (and the 1.12 retention scan and its
failure modes) on every read command.

**Destructive ordering (0007 §3.2/§3.3).** `trash empty` → `begin_destructive`
(snapshot published and verified, or `SnapshotOverBudget`) → approval prompt if
over budget → `empty_trash` (existing transaction/anchor path unchanged) →
`finish_destructive` (reclassify). A failure before the commit leaves the trash
intact; a failure after it is reported as an anchor-ordering error exactly as
today.

**`verify` (0004 §3.6).** One pass, deterministic order (records by ID; heads,
then retained history; attachments verified with the existing streaming chunk
verifier): manifest ↔ head ↔ anchor agreement, then for every reference
existence/profile/length/hash, then AEAD of every head and retained version and
whole-content checks for attachments. A history floor that covers versions
absent by design is *expected state* after purge (0007 §1.2/§1.4): it is
counted in `suppressed_records` and reported as a note, never as damage.
Unreferenced object rows are ignored. One object is authenticated at a time;
memory is bounded by the largest single object; cancellation between objects.
Missing or mismatched data is `Integrity`, never an empty record.

### Secrets and hostile input

No new secret type. VK and purpose keys stay inside `qv-store`; manifest
plaintext and decrypted records are confidential metadata (0008 §1.2) held in
`Zeroizing` buffers one at a time and never `Debug`/log/error/argv material.
Archive writers hash ciphertext only; only `verify` and the reader decrypt.

Hostile bytes: the archive is attacker-supplied (0012 row "Hostile files from
sync folders"). Order of operations is fixed: fixed prefix (7-byte magic +
version) → `u32be` header length ≤ 64 KiB → bounded canonical-CBOR header
decode (unknown fields and a present `password_slot` fail closed; no
allocation from a length before it is checked) → header MAC with the caller's
VK → manifest frame length ≤ 64 MiB and SHA-256 equal to `manifest_hash` →
manifest decrypt/decode/validate → frames matched to the next sorted reference
by length and SHA-256 **before** AEAD, with per-frame buffers bounded by the
referenced length and `u64` totals checked with `checked_add`. Trailing bytes,
missing frames, extra frames, wrong `object_count`/`total_length`, wrong
profile or generation, and a substituted frame are `Integrity`. No byte of an
archive ever reaches the SQLite parser, and no path in this phase opens SQLite
on an exchange file. No `unwrap`/`expect`/`panic!` on untrusted data; all
decoding goes through `qv-encoding`'s bounded decoder.

### Errors

Existing variants only, plus `CoreError::SnapshotOverBudget`: `Integrity` for
archive/manifest/frame/`verify` failures (exit 7), `UnsafeFile`/`Io` (exit 1),
`LimitExceeded` (exit 9), `WrongPassword` (3), `Locked`/`Replaced`/`Changed`
(6), `NotFound` (4), plus the CLI's own usage (2) and ambiguity (5) mapping.
Messages carry counts, sizes, ids of *archives* (random, non-linkable),
field names from the fixed vocabulary, and escaped paths only — never payload
values, record IDs, object IDs, hashes or key material.

### Dependencies

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| none | `rustix`, `rusqlite`, `qv-encoding`, `qv-crypto` already cover filesystem safety, hashing and CBOR | — | no manifest or lockfile change expected |

No `unsafe`, no MSRV change, no schema change. If a step looks like it needs a
crate, stop and record it under *Decisions needed* instead.

## Steps

### Step 1 — Amend 0007 §3 for the D6 slot policy

- [x] **Do:** Apply amendment A exactly as written in *Design* (replace §3.1's
  third sentence, add §3.5, resolve OQ1 in place, append the Changelog line).
  Add the `specs/README.md` index note that 0007 includes the D6 amendment.
  Remove `0007 OQ1` from the owner-decision list at the end of
  `ARCHITECTURE.md` (it is now resolved) and record the decision's date there.
  Add the `CHANGELOG.md` Unreleased entry.
- **Files:** `specs/0007-history-and-backups.md`, `specs/README.md`,
  `ARCHITECTURE.md` (open-decisions paragraph), `CHANGELOG.md`.
- **Done when:** 0007 §3.1 says no slot by default, §3.5 states the
  offer-to-delete duty and its limits, OQ1 shows the D6 resolution, and no
  other normative text changes. 0007 stays `Accepted`.
- **Verify:** `rg -n '3\.[15]\.|Open Questions|password slot' specs/0007-history-and-backups.md`;
  `git diff --check`; `rg -n '0007' ARCHITECTURE.md specs/README.md CHANGELOG.md`.

### Step 2 — Adopt the concrete 0011 snapshot/verify amendment (after D1)

- [x] **Do:** Apply amendment B exactly as written in *Design* (new §4
  subsection, §5 cross-reference, Changelog line), plus the `specs/README.md`
  note and the `CHANGELOG.md` entry.
- **Files:** `specs/0011-cli.md`, `specs/README.md`, `CHANGELOG.md`, this plan.
- **Done when:** the contract precedes the code: `snapshot ls`, `verify`, the
  recovery-snapshot rule for `trash empty`, JSON shapes, addressing and exit
  codes are all stated. No command is removed or renamed; no spec is promoted.
- **Verify:** `rg -n 'snapshot|verify' specs/0011-cli.md`; `git diff --check`.

### Step 3 — Archive header codec, budgets and framing in `qv-store`

- [x] **Do:** Add `archive.rs` with the magic/version/prefix, the bounded
  canonical-CBOR `ArchiveHeader` codec (0004 §6.2), the `qv/archive-header/v1`
  MAC transcript under the existing `header-mac` purpose key, `frame`
  read/write helpers with `u32be` lengths, and the constants
  (`MAX_ARCHIVE_HEADER_BYTES`, manifest/object/total frame bounds, format
  version). Unknown fields, noncanonical encodings, wrong types, a
  header length over the bound and a present `password_slot` are explicit
  errors (`Integrity` / `Unsupported`), never ignored. Add fail-closed stubs to
  `unsupported.rs` and the module table/development-value rows in `lib.rs`.
- **Files:** `crates/qv-store/src/archive.rs` (new), `src/limits.rs`,
  `src/lib.rs`, `src/unsupported.rs`.
- **Done when:** encode/decode round-trips are canonical and deterministic;
  a 64 KiB+1 header, a header claiming more fields than fit, a truncated
  header, an unknown field and a slot-bearing header are all rejected before
  allocating; the MAC covers the exact encoded field set with `header_mac`
  excluded; size claims are `u64`/`checked_add`.
- **Verify:** `cargo test --locked -p qv-store archive_header`.

### Step 4 — Archive writer and publish protocol

- [x] **Do:** Implement `UnlockedVault::write_archive` (manifest envelope +
  every referenced object, one SQLite read transaction, head re-check, hash and
  length verification per object, bounded buffers, cancellation) and
  `SnapshotDir::publish` (temp → write → re-read and verify → fsync →
  `RENAME_NOREPLACE` under a new unique name → directory fsync; failure removes
  the temp). Reuse `fs::create_temp`, `fs::rename_noreplace`, `fs::sync_dir`,
  `fs::check_private_dir`; add crash points to `crash.rs` for the publish
  steps. Never copy or normalize the live SQLite file.
- **Files:** `crates/qv-store/src/archive.rs`, `src/vault.rs` (read-transaction
  scope helper), `src/fs.rs` if a directory-walk helper is needed, `src/crash.rs`,
  `src/lib.rs`, `src/unsupported.rs`.
- **Done when:** only verified objects are written; the manifest envelope is
  byte-identical to the stored value's canonical encoding and its SHA-256 equals
  the stored `manifest_hash`; frame order is the manifest's sorted reference
  order; a corrupt/missing object aborts with nothing published; an existing
  target path is never replaced; a failure at any publish step leaves no
  published file; a `Changed` head or a second process's lock aborts the
  archive; cancellation removes the temp.
- **Verify:** `cargo test --locked -p qv-store archive`;
  `cargo test --locked -p qv-store crash`.

### Step 5 — Archive reader and the `archive_read` fuzz target

- [x] **Do:** Implement the reader in the 0004 §6.3 order (prefix → bounded
  header → caller's VK and matching vault ID/generation → header MAC → manifest
  frame hash → decrypt/decode/validate → frames matched to the next sorted
  reference by length and SHA-256 before AEAD → exact EOF, counts and totals),
  streaming from `impl Read` with per-frame bounded buffers. Provide the
  header-only path used by `snapshot ls`, and a frame-sink callback used by
  1.13b. Add `fuzz/fuzz_targets/archive_read.rs`: build one small real vault and
  archive per process (`OnceLock`, test password), keep its bytes and
  `UnlockedVault::vault_key()`, then feed mutated archive bytes to the reader
  each iteration. Register the bin in `fuzz/Cargo.toml` and add the CI step
  next to `vault_open`.
- **Files:** `crates/qv-store/src/archive.rs`, `fuzz/fuzz_targets/archive_read.rs`
  (new), `fuzz/Cargo.toml`, `.github/workflows/ci.yml`.
- **Done when:** truncated, reordered, duplicated, extra, missing and
  substituted frames, wrong lengths, wrong `object_count`/`total_length`,
  trailing bytes, another vault/generation and a slot-bearing header all fail
  with a specific error and no panic, huge allocation or SQLite call; the fuzz
  target builds and the CI step exists.
- **Verify:** `cargo test --locked -p qv-store archive`;
  `cargo fuzz build archive_read` (pinned nightly: `cargo +nightly fuzz run
  archive_read -- -max_total_time=60 -max_len=262144`). If the pinned nightly
  is not installed in the session, record that in the execution log and rely on
  `cargo fmt --check --manifest-path fuzz/Cargo.toml` plus the CI step.

### Step 6 — Full `verify` pass in `qv-store`

- [x] **Do:** Implement `UnlockedVault::verify_all` and `VerifyCounts`:
  manifest ↔ head ↔ anchor agreement, then every reference's existence,
  profile, length and SHA-256, AEAD of every active head and retained history
  version, and whole-content verification of attachments via the existing
  streaming chunk verifier. Count floors that cover absent dominated versions
  as expected state. Ignore unreferenced rows. Bounded memory, one object at a
  time, cancellation between objects, deterministic order.
- **Files:** `crates/qv-store/src/vault.rs` (or a small `src/verify.rs`),
  `src/lib.rs`, `src/unsupported.rs`.
- **Done when:** a healthy vault reports exact counts; a deleted object row, a
  short/long object, a flipped ciphertext byte, a substituted object, a
  truncated history version and a corrupt attachment chunk each fail with
  `Integrity`; a purge-created floor is *not* a failure; no allocation grows
  with total vault size.
- **Verify:** `cargo test --locked -p qv-store verify`.

### Step 7 — Core snapshot policy, listing and `verify`

- [x] **Do:** Add `snapshot.rs` with `SnapshotPolicy`, `SnapshotSummary`,
  `SnapshotReport`/`SnapshotSkip`, the coalescing/first-of-day decision from
  authenticated headers only, count/byte/age pruning with the in-process pin,
  `begin_destructive`/`finish_destructive`, `snapshots_before`/
  `delete_snapshots` for 1.14, `Session::snapshots`, `Session::snapshot_status`
  and `Session::verify`. Wire `CoreConfig::with_snapshots` and the automatic
  ordinary snapshot into `Core::unlock`/`unlock_for_recovery` as best-effort.
  Add the `CoreError::SnapshotOverBudget` variant and its exit mapping.
- **Files:** `crates/qv-core/src/snapshot.rs` (new), `src/setup.rs`,
  `src/session.rs`, `src/edit.rs` (pre-operation hook point), `src/error.rs`,
  `src/lib.rs`.
- **Done when:** no code path in this step writes to the vault; a failed or
  skipped snapshot never fails an unlock or read and never prints to stdout;
  the hourly/first-of-day decision is derived from authenticated headers only;
  pruning honours 48 / 512 MiB / 30 days oldest-first and never removes a pinned
  copy; a recovery copy becomes ordinary after `finish_destructive`; a
  `recover-` file left by a crash is reclassified before any pruning; `verify`
  reports counts, anchor status and notes without modifying anything.
- **Verify:** `cargo test --locked -p qv-core snapshot`;
  `cargo test --locked -p qv-core verify`.

### Step 8 — CLI `snapshot ls`, `verify` and the `trash empty` ordering

- [x] **Do:** Wire `snapshot ls` and `verify` (human + `--json`, escaping,
  exit codes, warnings to stderr, nothing on stdout when `--json`), and make
  `trash empty` call `begin_destructive` before `empty_trash`, prompt on
  `SnapshotOverBudget` (or accept `--yes`), abort with 9/1 when it cannot take
  the copy, then `finish_destructive`. Add the snapshot directory to the CLI's
  `CoreConfig` construction.
- **Files:** `crates/qv-cli/src/cli.rs`, `src/cmd/snapshot.rs` (new),
  `src/cmd/verify.rs` (new), `src/cmd/mod.rs`, `src/cmd/trash.rs`,
  `src/select.rs`, `tests/snapshots.rs` (new), `tests/verify.rs` (new),
  `tests/common/mod.rs` if fixtures are needed.
- **Done when:** every documented exit code has a test; `verify` on a vault
  with a missing anchor reports `anchor: missing` and exits 7 while still
  checking objects; a corrupted object gives 7 with no repair; `snapshot ls`
  never lists another vault's files as rows; `trash empty` with an injected
  snapshot-write failure exits non-zero with the trash unchanged; production
  runs work with the network blocked.
- **Verify:** `cargo test --locked -p qv-cli snapshot`;
  `cargo test --locked -p qv-cli verify`;
  `unshare -rn cargo test --locked -p qv-cli --test snapshots`.

### Step 9 — Rejection, hostile-input, crash and budget evidence (0012 rows)

- [x] **Do:** Add the cross-layer tests the four rows need, each named after
  its row: *Live SQLite copying* (archive during a concurrent writer attempt,
  external replacement mid-archive, crash at each publish point, incomplete
  archive, no SQLite file copying), *Hostile files from sync folders* (the
  frame matrix and the fuzz target; nothing reaches the SQLite parser),
  *Exchange-file password guessing* (written archives carry no slot; a
  slot-bearing archive is rejected; a local snapshot is not openable with the
  master password alone), *Snapshot disk growth* (repeated snapshots prune to
  count/bytes; a mandatory recovery copy with a full disk aborts the destructive
  operation).
- **Files:** `crates/qv-store/src/archive.rs` tests, `src/crash_tests.rs`,
  `crates/qv-core/src/snapshot.rs` tests, `crates/qv-cli/tests/snapshots.rs`.
- **Done when:** every named test fails against the unfixed production code
  path and passes now; no test is weakened or ignored; the disk-full case is
  driven by a test-only write-failure hook plus, where available, a small tmpfs.
- **Verify:** `cargo test --locked -p qv-store archive`;
  `cargo test --locked -p qv-store crash`;
  `cargo test --locked -p qv-core snapshot`.

### Step 10 — Documentation and final gates

- [x] **Do:** Update `CHANGELOG.md` (Unreleased: archives, snapshots, `verify`,
  the two amendments, documented limits), `ARCHITECTURE.md` §3 (implemented
  qv-store/qv-core/qv-cli responsibilities and the snapshot/verify description),
  crate-level docs (`qv-store` module table and the "Not yet implemented" list,
  `qv-core` module table), CLI help text, this plan's status and log, and the
  `plans/README.md` row. Run all `AGENTS.md` gates on the final tree. Also
  discharge the two doc-only carry-overs from the plan 0017 review:
  `crates/qv-store/src/write.rs`'s numbered module steps must include the
  retention/floor/reference-release step and its cancellation point before
  `COMMIT` (finding 4), and the roadmap's 1.12 phase line keeps its plan
  reference current (finding 5). Plan 0017 review finding 2
  (`changed_properties` always lists `modified_at`) is left as documented
  behaviour, not changed here.
- **Files:** `CHANGELOG.md`, `ARCHITECTURE.md`, `crates/*/src/lib.rs`, this
  plan, `plans/README.md`.
- **Done when:** no unqualified security/erasure claim; the snapshot
  retention/pruning rules, the cost of a full `verify`/archive pass and the
  "`verify` never repairs" limit are documented; all gates pass and the changes
  are left uncommitted for the fresh-context review.
- **Verify:** `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`,
  `cargo test --locked --no-fail-fast` with private Xvfb for the clipboard
  integration tests, `git diff --check`.

## Test plan

- Final verification: all `AGENTS.md` gates on the final tree, plus the
  focused step checks above; no dependency change is planned, so `cargo deny
  check`/`cargo vet --locked` become required only if that changes (and need
  owner approval first).
- Unit and property tests: archive header canonical round-trip and rejection
  matrix; frame-boundary arithmetic with `u64` totals; snapshot budget/pruning
  ordering with equal timestamps; policy decisions (hourly boundary, day
  rollover, clock anomalies) over authenticated headers.
- Rejection, malformed-input and crash-path tests: the full frame matrix
  (truncated, reordered, duplicated, extra, missing, substituted, lying
  length/count/total, trailing bytes, foreign vault/generation, slot-bearing
  header), the `archive_read` fuzz target in CI, crash points at each publish
  step, a full-disk snapshot before a destructive operation, cancellation in
  the writer/reader/`verify` loops, and a corrupt object for `verify`.
- Vectors: development-only golden files are not published (format frozen in
  1.16); tests build archives from real vaults and compare round-tripped bytes
  with the stored manifest envelope hash.
- 0012 §1 matrix rows addressed:
  - *Live SQLite copying* — archive creation against a concurrent writer
    attempt, external replacement, crash points, incomplete archives, and no
    copying of the live SQLite file.
  - *Hostile files from sync folders* — fuzzed prefix/header/frame lengths plus
    the deterministic frame matrix; no SQLite ingestion on any exchange path.
  - *Exchange-file password guessing* — no password slot in any archive this
    phase writes; slot-bearing archives rejected explicitly.
  - *Snapshot disk growth* — coalescing, count/byte/age pruning and the
    mandatory recovery copy with a full disk aborting the operation.
- Tests and review are evidence, not security proof (0012 *Security
  Considerations*).

## Risks and stop conditions

- **D1 is open.** Do not start step 2 (or any code step) before the owner
  approves amendment B; if the owner changes the CLI contract, stop and revise
  this plan first.
- **A second write path.** Any temptation to record snapshot state, a "last
  snapshot" marker or repair metadata in the vault DB is forbidden here: it
  would put a commit (and the 1.12 whole-vault retention scan and its
  one-corrupt-object failure mode) on every read command. Stop and ask.
- **Retention cost on the commit path.** History retention already decrypts all
  retained history on every commit (plan 0017 review finding 1), and one
  corrupt history object blocks every write. Do not work around it by skipping
  retention in the destructive path; `verify` diagnoses it and restoring a
  snapshot is the documented remedy. If a snapshot-policy step appears to need
  to inspect vault history to decide, stop.
- **Purge floors are not damage.** Never report a suppression floor that covers
  later-dominated versions as an integrity failure, in `verify` or in the
  archive reader, and never "repair" it by clearing floors.
- **Hostile-parser scope.** Nothing from an archive may reach the SQLite parser
  or an unbounded allocation; a frame length may only be used after a bound
  check. Unknown header fields and features fail closed. No `unwrap`/`expect`
  on untrusted data.
- **Live SQLite copying.** Never read, copy or normalize the `.qvault` file to
  build an archive; only verified objects from the authenticated state go in.
- **Disk-full and budget semantics.** A mandatory recovery copy that cannot be
  written aborts the destructive operation (exit 1 for I/O, 9 for the budget
  refusal); an ordinary snapshot that cannot be written only warns. Never
  proceed with a destructive operation without its recovery copy.
- **Do not reuse the index-only multi-head conflict fixture** (plan 0017 review
  finding 3) for anything here; if a snapshot/`verify` test needs multi-head
  state, either drive it through the existing manifest-level helpers or defer
  it to 2.2 with a note.
- **Scope:** no `snapshot restore` implementation, no `snapshot export`, no
  self-contained slot, no repair, no new dependency, no `unsafe`, no schema or
  format redefinition. If a step needs any of these, stop and record it.
- **Session size:** if implementation of this plan also starts to absorb 1.13b,
  stop and split again rather than leaving half-done steps at a session
  boundary.

## Documentation

- [x] `CHANGELOG.md` — Unreleased entries for archives/snapshots/`verify`, both
  spec amendments, and the documented limits (no repair, no slot, no erasure).
- [x] `ARCHITECTURE.md` — §3 implemented responsibilities for `qv-store`,
  `qv-core` and `qv-cli`; the open-decision list at the end of the file (0007
  OQ1 resolved); §6 only if a technology changes (none expected). No crate or
  trust-boundary change, so no diagram change.
- [x] Specs — amendment A (0007 §3.1/§3.5, OQ1, Changelog), amendment B (0011
  §4/§5, Changelog), `specs/README.md` index notes. No spec promoted to
  `Implemented` (0004 needs 1.16's freeze evidence, 0007 §4 and 0011's phase
  2–3 families are unimplemented).
- [x] `AGENTS.md` — no change (no convention, layout or workflow change).
- [x] `plans/README.md` — row for plan 0018, and this plan's status/log.

## Revisions

- 2026-10-27: Phase 1.13 split into **1.13a** (this plan) and **1.13b**. The
  whole phase needs the two amendments, a new archive format module
  (writer + reader + fuzz target + CI), a full `verify` pass, snapshot policy
  and budgets, two CLI command families and the restore-into-a-new-path builder
  — 15+ steps, past roadmap 0002's session-size rule. 1.13a delivers the writer,
  reader, `verify`, snapshot policy/listing and the CLI `snapshot ls`/`verify`;
  1.13b delivers `snapshot restore` and the restore-path evidence. Recorded as
  this roadmap *Revisions* entry (authorized by roadmap 0002 *Session protocol*
  step "split it into N.Ma/N.Mb as a dated Revisions entry"; no owner decision
  needed for the split itself):

  > 2026-10-27 (phase 1.13, plan 0018): split 1.13 into **1.13a** and
  > **1.13b**. 1.13a: the D6 0007 amendment, the 0011 `snapshot ls`/`verify`
  > amendment, the archive header/writer/reader in `qv-store` with the
  > `archive_read` fuzz target and CI wiring, the full `verify` pass, snapshot
  > policy/coalescing/budgets/pruning and authenticated listing in `qv-core`,
  > and the CLI `snapshot ls`, `verify` and the mandatory recovery snapshot of
  > `trash empty`. 1.13b: `snapshot restore <id> <path>` — building a new vault
  > file from a verified archive (fresh replica, head and anchor), its CLI
  > contract and the restore-path evidence for the remaining 0012 rows —
  > planned as 0019 in its own session. Development values for the 1.16 freeze
  > from 1.13a: the archive magic/format version, header field set, frame
  > layout, the `qv/archive-header/v1` label, the snapshot directory
  > (`$XDG_STATE_HOME/quickvault/snapshots`), the local filename scheme and the
  > 30-day/48-snapshot/512 MiB budgets. 1.13a adds no dependency, no `unsafe`
  > and no new write path; the 0007 amendment is authorized by D6 and the 0011
  > amendment is the phase's owner-approved step 2 (D1).

## Execution log

### 2026-10-28 — Steps 1–2 (spec amendments)

**Step 1 — 0007 §3 amendment A.** Applied amendment A verbatim to
`specs/0007-history-and-backups.md`: §3.1's third sentence replaced by the
"no password slot by default" text (sentences 1–2 and the private-directory
sentence unchanged, as the amendment restates them), new §3.5, OQ1 rewritten
in place as the D6 resolution, and the 2026-10-27 Changelog line prepended.
`specs/README.md` gained the "0007 includes the D6 amendment" note,
`ARCHITECTURE.md` dropped `0007 OQ1` from the owner-decision paragraph and
records the 2026-10-25 D6 resolution with its date, and `CHANGELOG.md` has the
Unreleased entry. 0007 stays `Accepted`; no other normative text changed.
Evidence: `rg -n '3\.[15]\.|Open Questions|password slot' specs/0007-history-and-backups.md`
shows §3.1, §3.5 and the resolved OQ1; `git diff --check` clean.

**Step 2 — 0011 §4–5 amendment B.** Applied amendment B verbatim: a new `####
Snapshots and verification` subsection under §4 (after *History and
snapshots*, before *Sync and later*) with the `verify`, `snapshot ls`,
`<id>` addressing, destructive-ordering, automatic-policy and
`--password-stdin` bullets; the §5.2 cross-reference (the `verify`/`snapshot
ls` JSON carries no object ID, hash, record ID, payload or path — the plan
prescribes "a §5 cross-reference" without wording, so this is its placement);
and the 2026-10-27 Changelog line. `specs/README.md` gained the corresponding
note and `CHANGELOG.md` the owner-approved 0011 entry. No command was removed
or renamed and no spec was promoted. Evidence: `rg -n 'snapshot|verify'
specs/0011-cli.md`; `git diff --check` clean.

Files: `specs/0007-history-and-backups.md`, `specs/0011-cli.md`,
`specs/README.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, this plan,
`plans/README.md` (status row only).

Deviation: none. `plans/README.md`'s 0018 row read `Proposed` although the plan
is approved; it is set to `In progress` with the plan status (step 10 still
owns the final row).

Found, not fixed: plan 0018 *Revisions* states the 1.13a/1.13b split "is
recorded as this roadmap *Revisions* entry", but
`plans/0002-roadmap/PLAN.md` has no `1.13a` text yet; the roadmap revision
entry and the 1.12/1.13 status lines stay with the roadmap session (plan 0017
review finding 5 and step 10's roadmap item).

### 2026-10-28 — Step 3 (archive header codec, budgets, framing)

Added `crates/qv-store/src/archive.rs`: the magic/version/prefix, the bounded
strict canonical-CBOR [`ArchiveHeader`] codec (0004 §6.2, keys 0–11 exactly as
in *Design*), the `qv/archive-header/v1` transcript under the existing
`header-mac` purpose key with `header_mac` excluded from the covered map, the
`u32be` frame read/write helpers, and the constants (`ARCHIVE_MAGIC`,
`ARCHIVE_FORMAT`, `MAX_ARCHIVE_HEADER_BYTES`, `ARCHIVE_HEADER_LABEL`,
`ARCHIVE_EXTENSION`). `src/limits.rs` gained
`MAX_ARCHIVE_MANIFEST_FRAME`, `MAX_ARCHIVE_OBJECT_FRAME` and
`MAX_ARCHIVE_TOTAL_LENGTH`; `src/object.rs` exposes `ENVELOPE_OVERHEAD`
crate-internally so the frame bounds are derived, not guessed. `src/lib.rs`
registers the module, the module table and the development-value rows.
`mod archive` is *not* platform-gated for the codec: the codec, framing and
(later) the reader are pure bounded-CBOR code with no filesystem or SQLite
call, so they compile everywhere; only the writer and the snapshot directory
fail closed off Linux/Android (step 4). Recorded here because the sketch's
"(Linux/Android with fail-closed stubs elsewhere)" is satisfied for the API
surface rather than by duplicating the codec.

Decisions (all development values, frozen in 1.16, listed in the module docs):
the header MAC covers the canonical map *without* key 11 (`["qv/archive-header/
v1", header_body]`, mirroring the vault header MAC's exact-bytes shape); the
MAC key is derived with `ARCHIVE_DERIVATION_PROFILE = derivation/1` because the
header carries no derivation-profile field of its own, and §6.2's
`minimum_profiles` are floors for acceptance, not that profile; `created_at`
is a CBOR int of Unix milliseconds like every model timestamp; `archive_id` is
16 raw random bytes (0004 §6.2 "random 128-bit ID"), not a UUIDv4.

Evidence: `cargo test --locked -p qv-store archive` — 6 passed
(`archive_header_round_trips_canonically`,
`archive_header_mac_binds_fields_vault_and_generation`,
`archive_header_rejections`, `archive_header_accepts_its_own_boundaries`,
`archive_frames_round_trip_and_bound`, `archive_scope_matches_exactly`), 0
failed. The rejection test covers a 64 KiB+1 header, a map claiming more
entries than fit, truncated/empty/trailing/garbage input, an unknown field, a
present `password_slot`, every missing key, wrong types, a zero key
generation, an unknown stored-data profile, `object_count`/`total_length`
over budget, and a data profile below the minimum. `cargo fmt --check` clean.

Next: step 4 (writer and publish protocol).

### Files touched so far

### 2026-10-28 — Steps 4–6 (writer, publish, reader, `verify`)

**Step 4 — writer and publish protocol.** `UnlockedVault::write_archive`
(`archive::platform`) writes the prefix, the header, the manifest frame and one
frame per reference in the manifest's validated sorted order, all inside one
read transaction opened by the new `UnlockedVault::begin_read`
(`vault.rs`), which re-reads the head and replica rows first (`Changed`
otherwise) and never writes. The manifest envelope is re-encoded from the
stored parts (`manifest::envelope_bytes`) and its SHA-256 is checked against
the stored `manifest_hash` before a byte is written; each object is re-read
from its row and its profile, length and SHA-256 are checked against its
reference before its frame is written. Buffers are one object at a time (never
a whole vault or archive), cancellation is checked between objects and so
between 1 MiB blocks → `Io`, and no `Write` is involved anywhere.
`SnapshotDir` (open/default_dir/entries/read_header/remove/
reclassify_as_ordinary/publish) implements 0004 §6.5: temp file in the
snapshot directory (a name no listing ever shows) → write → re-open and
verify with the archive reader → `fsync` → `RENAME_NOREPLACE` to
`<prefix><archive id>.qvsnap` → directory `fsync`; any failure removes the
temp and publishes nothing. Crash points `ArchiveVerified` and
`ArchivePublished` were added to `crash.rs` with a directory-copying `arm_dir`.
`fs` gained `LockedFile::into_file` and `open_private_ro`; `schema` gained
`read_manifest`; `manifest` gained `envelope_bytes` and `config_digest_for`.

**Step 5 — reader and fuzz target.** `read_header`/`read_archive` implement
the fixed 0004 §6.3 order: prefix → `u32be` header length ≤ 64 KiB → bounded
strict decode (unknown field or `password_slot` → `Unsupported`) → the
caller's `ArchiveScope` vault ID and generation → header MAC with the caller's
VK → manifest frame ≤ 64 MiB hashed against `manifest_hash` → manifest
decrypt/decode/validate plus the configuration digest → `object_count` and
`total_length` → one frame per reference, each matched by its **exact**
computed envelope length and SHA-256 before any AEAD, buffers bounded by the
referenced length → exact EOF. A sink callback (`ArchiveObject<'_>`, ciphertext
borrowed from the frame buffer) is the 1.13b restore seam; `SnapshotDir::read_header`
is the header-only path for `snapshot ls`. `fuzz/fuzz_targets/archive_read.rs`
builds one real vault and archive per process (a `OnceLock<Mutex<…>>`: the
vault holds a SQLite connection, so it is `Send` but not `Sync`) and applies
the input to a copy of the seed as `(offset, byte)` patches plus a truncate/
extend selector. Registered in `fuzz/Cargo.toml` and wired into `ci.yml` next
to `vault_open` with `-max_len=262144`.

**Step 6 — `verify`.** New `src/verify.rs` with `VerifyCounts` and
`UnlockedVault::verify_all`: manifest ↔ head agreement (hash, generation,
profile, AEAD, decode, validation and identity with the session's manifest),
then every reference's existence/profile/length/full SHA-256, then every head
and retained history version (reference hash before AEAD for history, the
per-head rules, one kind per record, the control-record rules now shared as
`check_control_kinds`), then whole-content verification of every attachment
version through the existing streaming chunk verifier. Records by ID and
versions by ID make the order deterministic; one object at a time bounds
memory; cancellation between objects is `Io`. A non-empty history floor is
counted in `suppressed_records` and never treated as damage. The
head-versus-anchor comparison stays with the caller (0011 reports
`anchor: missing|mismatch` together with the counts, so raising it here would
destroy the report the amendment requires).

Evidence: `cargo test --locked -p qv-store archive` — 19 passed;
`cargo test --locked -p qv-store crash` — 9 passed;
`cargo test --locked -p qv-store verify` — 7 passed; full `-p qv-store` 136 +
1 + 7 passed, 0 failed; `cargo clippy -p qv-store --all-targets --locked --
-D warnings` and `cargo fmt --check` clean; `sh scripts/check-spdx.sh` clean.
The rejection matrix covers a 64 KiB+1 header, a header length over the
budget, a manifest frame over its budget, an object frame over its budget, a
truncated archive at every boundary, trailing bytes, wrong magic and version,
missing/extra/reordered/duplicated/substituted frames, lying object-frame
lengths, a substituted manifest frame, wrong `object_count`/`total_length`
under a valid MAC, another vault and another generation, a slot-bearing
header, a foreign vault key, a corrupt/missing/short/long/flipped/substituted
object, a truncated history version, a corrupt attachment chunk, a purge floor
(expected), a changed head, cancellation and a full disk at the writer
(`archive_write_failure_is_io_and_publishes_nothing`: a sink that fails after
0, 1, 16, 64, half and all-but-one byte gives `Io` and leaves no published
file). Fuzz: `cargo build
--manifest-path fuzz/Cargo.toml --bin archive_read` succeeds and the target
runs — `./fuzz/target/debug/archive_read -max_total_time=20 -max_len=262144`
finished **73,982 runs in 21 s with no finding** (`fuzz/fuzz_targets/archive_read.rs:1`) (this session has no
pinned nightly or `cargo-fuzz`, so the exact `cargo +nightly fuzz run` form was
not used; `cargo fmt --check --manifest-path fuzz/Cargo.toml`,
`cargo fetch --locked --manifest-path fuzz/Cargo.toml` and the CI step are in
place).

Deviations, all recorded here rather than silently:
1. The reader core landed with step 4 because publish's protocol re-reads and
   verifies the temp *with the reader*; step 5's own deliverables (its
   rejection matrix, header-only path and the fuzz target) were completed and
   tested after it.
2. `mod archive` is not platform-gated: the codec, framing and reader are
   bounded-CBOR code with no filesystem or SQLite call, so they compile on
   every target; only the writer and `SnapshotDir` fail closed through
   `unsupported.rs`. This keeps one definition of the header/format values
   instead of duplicating them for non-Linux targets.
3. `fuzz/Cargo.toml` gains a path dependency on the already-present
   `qv-crypto` (the fuzz target needs `MasterPassword` to build a real vault);
   no new external crate, no root manifest or `Cargo.lock` change, and
   `fuzz/Cargo.lock` gains one line in the fuzz package's dependency list.
4. The mutation uses `OnceLock<Mutex<…>>` rather than `OnceLock<…>` because an
   `UnlockedVault` holds a `rusqlite::Connection` (Send, not Sync).

Found, not fixed: `MAX_ARCHIVE_HEADER_BYTES` is defined in `archive.rs` (per
the *Design* sketch) while the frame bounds are in `limits.rs`; both are
development values for the 1.16 freeze, which should record them in one table.
`object.rs`'s `ENVELOPE_OVERHEAD` under-counted a 24-byte byte string's
two-byte head; it is now a true upper bound (61 bytes) and is what the archive
frame bounds are derived from.

**Final gates on the steps 1–6 tree** (full output in `/tmp/opencode/qv18/`):
`sh scripts/check-spdx.sh` exit 0 (`spdx-final.log`); `cargo fmt --check` exit 0
(`fmt-final.log`); `cargo clippy --all-targets --locked -- -D warnings` exit 0
(`clippy-final.log`); `cargo test --locked` exit 0 with
`QV_TEST_XVFB=/tmp/opencode/qv17-review/xvfb/usr/bin/Xvfb` — **537 passed,
0 failed, 2 ignored** across 31 targets (`test-final.log`; the two ignored tests are
pre-existing and by design — the `kat_generate_dev_stored_data` generator and
the `lock_helper` subprocess helper — and the clipboard integration tests ran
and passed against that private Xvfb). `git diff --check` clean.
`cargo fmt --check --manifest-path fuzz/Cargo.toml` and
`cargo fetch --locked --manifest-path fuzz/Cargo.toml` exit 0. `cargo
deny`/`cargo vet` were not run: the root `Cargo.lock`, every manifest and the
MSRV are unchanged (the archive work adds no crate), so 0012 §3 does not apply
to this tree.

Next: steps 7–10 (another session): core snapshot policy/listing/`verify`, CLI
`snapshot ls`/`verify`/`trash empty` ordering, the cross-layer 0012 rows,
documentation and final gates. The store API they build on:
`SnapshotDir::{open, default_dir, entries, read_header, remove,
reclassify_as_ordinary, publish}`, `PublishedSnapshot::{entry, stats,
archive_id, created_at, kind, size, objects, total_bytes}`,
`SnapshotEntry::{name, size, kind}`, `ArchiveScope::new(vault_id,
key_generation)`, `UnlockedVault::{write_archive, verify_all}`, `VerifyCounts`,
`ArchiveHeader::{archive_id_hex, created_at, object_count, total_length,
vault_id, key_generation, verify_mac, matches}`, `archive::{read_header,
read_archive}` and `ArchiveObject`.

### 2026-10-28 — Step 7 (core snapshot policy, listing and `verify`)

New `crates/qv-core/src/snapshot.rs`: `SnapshotPolicy` (private `SnapshotDir`
plus 48 / 512 MiB / 30 days), `SnapshotSummary`, `SnapshotReport`,
`SnapshotSkip`, `SnapshotListing`, `VerifyNote`, `VerifyReport`,
`RecoverySnapshot`, and `Session::{snapshots, snapshots_before,
delete_snapshots, begin_destructive, finish_destructive, verify,
snapshot_status}` plus the crate-private `run_automatic_snapshot`. The
automatic decision reads **only authenticated headers of this vault ID and
generation**: take when there is no ordinary snapshot from today's UTC date or
the newest is more than an hour old, so no marker row, settings write or vault
commit exists on a read command. Pruning is oldest-first by authenticated
`created_at` then archive ID (age, then count, then bytes), never the pinned
copy and never the just-written one; `recover-` files that nothing pins are
reclassified before pruning; a finished or dropped operation's copy becomes
ordinary. Publishing happens before the count/byte prune so the real size, not
an estimate, decides `SnapshotOverBudget { needed }`; a copy that cannot fit is
removed again and nothing else changes. `CoreConfig::with_snapshots` and the
automatic pass in `Core::unlock`/`unlock_for_recovery` are wired best-effort:
a failure or skip is recorded in `snapshot_status()` for the frontend and never
fails the unlock. `Core::unlock` now uses the store's recovery unlock and maps
`Missing`/`Mismatch` to `NoAnchor`/`Rollback` exactly as before, so the session
also carries the unlock-time anchor comparison that `verify` reports; the
store's `verify_all` stays anchor-free as its docs require. `CoreError` gains
the single new variant `SnapshotOverBudget { needed: u64 }` (exit 9).
`testutil` gained `core_with`/`snapshot_policy`/`unlock_with` and the new
`CoreConfig.snapshots` field.

Deviations from the interface sketch, all forced by the 0011 contract or by
Rust ownership; recorded for the reviewer:
1. `Session::snapshots()` returns `SnapshotListing { snapshots, unreadable }`
   rather than `Vec<SnapshotSummary>`. 0011 §4 requires unauthenticatable files
   to be *reported as warnings*, and a frontend that may not read the snapshot
   directory has no other channel; the count (not names or paths) is the
   smallest sufficient one.
2. `SnapshotReport` gains `failed: bool`: a copy that cannot be written is
   neither a `skipped` policy decision nor a publication, and 0011 requires it
   as a warning.
3. `VerifyReport` gains `vault_id`/`key_generation`, which the mandated JSON
   carries and the sketch's fields could not supply.
4. `SnapshotSummary`/`SnapshotReport`/`VerifyReport`/`SnapshotListing` are
   `Clone` (only printable archive IDs, fixed labels and aggregate counts) so
   `snapshot_status()` can hand the stored automatic report to the frontend;
   every `Debug` is explicit and holds no key or record material.
5. A session without a snapshot policy cannot pin a recovery copy:
   `begin_destructive` returns `CoreError::Internal` (a frontend error). The
   CLI checks `SnapshotSkip::Disabled` first and aborts with a clear exit 1
   instead of reaching it.
6. `SnapshotSkip::AlreadyToday` is not produced by the implemented rule (the
   first-of-day copy may bypass the hourly window, as 0007 §3.2 says); it stays
   in the public enum, documented, for a future daily-only policy.
7. "Today" is the UTC date: core has no time-zone source and this phase adds no
   dependency. Development value for the 1.16 freeze.

Evidence: `cargo test --locked -p qv-core snapshot` — 12 passed at this step
(now 14): hourly coalescing, first-of-day, count/byte/age pruning, equal
timestamps broken by archive ID, pinned copy never deleted, recovery copy
reclassified after a crash, `SnapshotOverBudget` and approval, disabled policy,
snapshot failure never failing an unlock, unauthenticated files ignored, the
`verify` counts/notes/vault-file-unchanged and missing-anchor reports, and
cancellation. `cargo test --locked -p qv-core verify` passed; full `-p qv-core`
63 passed, 0 failed; `cargo clippy -p qv-core --all-targets --locked -- -D
warnings` and `cargo fmt` clean.

### 2026-10-28 — Step 8 (CLI `snapshot ls`, `verify`, `trash empty` ordering)

Added `qvault snapshot ls [--json]` (`cmd/snapshot.rs`) and `qvault verify
[--json]` (`cmd/verify.rs`), both registered in `cli.rs`, and the mandatory
recovery snapshot in `cmd/trash.rs`: after the ordinary confirmation (and
before `empty_trash`) `begin_destructive` publishes and verifies the copy; a
`SnapshotOverBudget` prints the required size on stderr and asks once unless
`--yes` approved it, declining exits 9 with nothing deleted, and any other
failure exits through the ordinary mapping (I/O 1) with the trash intact. After
the purge commits the copy is reclassified to ordinary; a reclassification
failure reports "the deletion was committed". `select::core()` now configures
the default private snapshot directory; an unusable one disables snapshots (a
warning, never a read failure), and `trash empty` refuses with exit 1 rather
than delete without its recovery copy. `Ctx::unlock_path` prints
`warn_snapshots` (failed, over-budget, disabled) to stderr only. `verify`
unlocks with `unlock_for_recovery`, so a missing/mismatched anchor is reported
with exit 7 *and* the full pass; human output is one line per check group plus
a summary, JSON is the documented key set/order, and a failed pass prints
nothing on stdout. `exit.rs` maps only the new `SnapshotOverBudget` to 9
(tested in `exit_table_rows`).

Evidence: `cargo test --locked -p qv-cli --test snapshots` 4 passed and
`--test verify` 4 passed (full `-p qv-cli` 79 passed, 0 failed, including the
pre-existing trash and clipboard tests under the private Xvfb). Tests:
`snapshot_ls_lists_authenticated_local_snapshots`,
`hostile_files_from_sync_folders_are_warnings_not_rows`,
`trash_empty_takes_a_recovery_snapshot_before_the_deletion`,
`snapshot_disk_growth_a_snapshot_failure_aborts_the_destructive_operation`,
`verify_reports_every_check_group_and_never_repairs`,
`verify_missing_anchor_is_reported_and_exits_7`,
`verify_wrong_password_and_a_damaged_vault_exit_3_and_7`,
`exchange_file_password_guessing_a_snapshot_does_not_open_with_the_password`.

Found, not fixed: the budget-approval *prompt* has no end-to-end CLI test
because snapshot budgets are not configurable in 1.13a (0007 §3.3 defers
larger/configurable budgets); the core refusal and the exit-9 mapping are
tested, and `--yes` is passed as the approval. A corrupted *object* is not
provoked from `qv-cli` because the frontend depends on `qv-core` only (no
`qv-store` dev-dependency is allowed by the boundary); object corruption is
covered by `qv-store`'s `verify` tests, and the CLI's 7 path by the missing
anchor and the truncated vault.

### 2026-10-28 — Step 9 (0012 §1 rows)

Each row now has a test named after it, cross-layer where the row is about
behaviour. *Live SQLite copying*: `qv-store`'s
`live_sqlite_copying_archive_is_built_from_verified_objects`,
`archive_during_a_concurrent_writer_is_safe` and
`snapshot_publish_crash_points_leave_no_partial_archive` plus the new core
`live_sqlite_copying_snapshots_never_copy_or_write_the_vault` (vault bytes and
sequence unchanged, every snapshot starts `QVSNAP\0` and contains no SQLite
page). *Hostile files from sync folders*: `qv-store`'s frame matrix
(`hostile_archive_files_are_rejected_before_any_sqlite_call`, 64 KiB+1 header,
truncation, reordering, extra/missing/substituted frames, lying lengths,
foreign vault/generation, slot-bearing header) and the `archive_read` fuzzer,
plus the new CLI `hostile_files_from_sync_folders_are_warnings_not_rows` (a
validly named, hostile file is a stderr warning, never a row, exit 0, the
vault still verifies). *Exchange-file password guessing*: `qv-store`'s
`exchange_file_password_guessing_archives_carry_no_slot` and the new CLI
`exchange_file_password_guessing_a_snapshot_does_not_open_with_the_password`
(the copy used as a vault fails, not with exit 3, so the password was never a
keyslot). *Snapshot disk growth*: core
`snapshot_disk_growth_prunes_to_the_budgets_and_never_the_pinned_copy`,
`snapshot_budget_covers_bytes_and_age`,
`snapshot_pruning_breaks_equal_timestamps_by_archive_id`,
`snapshot_disk_growth_recovery_copy_left_by_a_crash_is_reclassified` and
`snapshot_disk_growth_a_full_disk_aborts_the_mandatory_copy`, plus the CLI
`snapshot_disk_growth_a_snapshot_failure_aborts_the_destructive_operation`
(unsafe 0777 and unwritable 0500 snapshot directories: exit 1, trash intact,
sequence unchanged). The unavailable-copy case is driven through the real
filesystem: the mode check on an unsafe private directory is
privilege-independent, and a read-only directory reaches the same
`create_temp`/write error path as `ENOSPC`. Both tests probe the read-only arm
with a real write and skip only that arm when the process has
permission-override privileges (uid 0 in a user namespace), printing why; a
genuine tmpfs was not available (`mount -t tmpfs` is denied even inside
`unshare -rn`), so 0012's "where available" qualifier is recorded. The
`unshare -rn cargo test --locked -p qv-cli --test snapshots` form passes, and
the core snapshot tests pass under it too.

No test was weakened, skipped or ignored. Evidence: `cargo test --locked -p
qv-store archive` 19 passed, `-p qv-store crash` 9 passed, `-p qv-core
snapshot` 14 passed (three consecutive runs to confirm the equal-timestamp and
crash-reclassify tests are not order-flaky), `-p qv-cli --test snapshots` 4
passed.

### 2026-10-28 — Step 10 (documentation and final gates)

`CHANGELOG.md` Unreleased gains the snapshots/`snapshot ls`/`verify`/`trash
empty` entry with the budgets, the no-slot rule, the no-repair and no-erasure
limits and the warning-only failure semantics. `ARCHITECTURE.md` §3 names the
archive/`verify`/snapshot responsibilities of `qv-store`, `qv-core` and
`qv-cli` and describes policy, budgets, the pinned copy, the pre-deletion copy,
the read-only `verify` and its remedy; §6 and the diagram are unchanged (no
technology, crate or trust-boundary change). Crate docs: `qv-core`'s module
table, snapshot/verify paragraph and "Not yet implemented" line; `qv-cli`'s
phase note; `qv-store`'s module table/"Not yet implemented" were already
current. The plan 0017 review finding 4 carry-over is discharged:
`crates/qv-store/src/write.rs`'s numbered order now has the retention/floor/
reference-release step and the before-`COMMIT` cancellation check, and the
crash paragraph is renumbered. Finding 5 (roadmap wording) is left to the
owner as instructed; finding 2 remains documented behaviour. No spec was
promoted to `Implemented` (0004 needs 1.16's freeze evidence, 0007 §4 and
0011's phase 2–3 families are unimplemented). `plans/README.md`'s row is
`Implemented`.

**Final gates on the steps 7–10 tree** (full output in `/tmp/opencode/qv18b/`):
`sh scripts/check-spdx.sh` exit 0 (`spdx-final2.log`); `cargo fmt --check` exit
0 (`fmt-final2.log`); `cargo clippy --all-targets --locked -- -D warnings` exit 0
(`clippy-final2.log`); `cargo test --locked` exit 0 with
`QV_TEST_XVFB=/tmp/opencode/qv17-review/xvfb/usr/bin/Xvfb` — **560 passed,
0 failed, 2 ignored** across 30 targets (`test-final5.log`; the two ignored are
the pre-existing by-design generator/subprocess helpers, and the clipboard
tests ran and passed). `unshare -rn cargo test --locked -p qv-cli --test
snapshots` passes (4 passed). `git diff --check` clean. `cargo deny check`/`cargo vet
--locked` were not run: the root `Cargo.lock`, every manifest and the MSRV are
unchanged (no dependency added), so 0012 §3 does not apply.

Next: fresh-context review (`quickvault-reviewer`); 1.13b (`snapshot restore`,
plan 0019) remains a separate session.

### 2026-10-28 — Fresh-context review: re-plan needed

Reviewed committed phase 1.13a (`66474cb` against `2dc7ac5`); see
[REVIEW.md](REVIEW.md). Approval is withheld. Four temporary diagnostic probes
confirmed that nonce-only corruption is accepted by the archive reader and
snapshot publication, including retained-history corruption that survives a
normal unlock even though `verify_all` rejects it. A valid-MAC header with a
reference digest disagreeing with its manifest is also accepted. Probe source
and logs are in `/tmp/qv18-review/`; product source was restored byte-for-byte.

The role-aware archive authentication/publication fix needs an architect
revision; no remediation or phase 1.13b implementation was started. Status
stays `Implemented` under the reviewer lifecycle, with verdict **Re-plan
needed**. Roadmap 0002 session protocol step 2 requires stopping on the
escalations. Reviewer gate results and environment limitations are recorded in
REVIEW.md. All review records remain uncommitted for the owner.

### 2026-10-28 — Owner-authorized review remediation revision

Owner requested “fix and then implement 1.13b”, authorizing this remediation
and continuation without an intervening commit. Preserve existing review
records. No new spec, dependency, crypto primitive, format or schema.

The stream's sorted object order differs from record/chunk role order. Change
`read_archive` to `Read + Seek`: first check every bounded frame's hash and
record its offset plus whole-envelope SHA-256 (at most MAX_OBJECTS entries),
then seek through authenticated manifest roles to verify record AEAD, version
identity/clock, root/control kinds, history and every attachment's chunk AEAD,
length and whole-content hash. Reuse `open_record`, `open_chunk`, chunk AAD
and shared head/control checks; extract these checks to a platform-independent
validation module. No SQLite input and no plaintext staging. Finally deliver
objects to the sink only after complete validation, rechecking each whole-frame
digest so a changed nonce between passes is rejected. Buffers hold one bounded
frame and one record/chunk, never total archive contents. Update slice callers
to Cursor and retain fail-closed cross-platform behavior. Compare header and
manifest reference digests before processing objects.

The writer validates source content before emitting an archive by using the
existing full verifier; publication's reread also performs full role checks.
Prune snapshots only after a newly published copy is fully verified, including
age pruning, so failure preserves existing recovery material.

- [x] R1 **Do:** implement seek-based archive authentication and shared role
  checks, digest agreement and validation-before-sink; **Files:** archive.rs,
  validation.rs / archive_verify.rs (new), vault.rs, verify.rs, verify_tests.rs, attachment.rs, lib.rs,
  fuzz/fuzz_targets/archive_read.rs; **Done when:** nonce-only corruption in
  active/history/chunk objects and wrong reference digest fail with Integrity
  before any sink call; healthy archives round-trip; **Verify:**
  `cargo test --locked -p qv-store archive` and `-p qv-store verify`.
- [x] R2 **Do:** reject corrupt source before publication and defer age pruning
  until successful publication; add regression tests proving old copies remain
  on corrupt-source failure; **Files:** archive.rs, qv-core/src/snapshot.rs;
  **Done when:** corrupt history after normal unlock cannot publish or replace
  recovery material; **Verify:** store archive and core snapshot suites.
- [x] R3 **Do:** document remediation, run all AGENTS gates and reviewer pass;
  **Files:** CHANGELOG.md, this plan/review/index/roadmap; **Done when:** findings
  addressed with rejection tests, no security-proof claim; **Verify:** all four
  required gates, fuzz formatting/build where available and git diff --check.

Status In progress, owner authorization 2026-10-28. Existing original review
remains historical; append remediation review evidence after implementation.

### 2026-10-28 — Remediation implemented and resumed review

R1–R3 complete. Shared head/control validation and chunk AAD now serve the
seek-based archive validator. Complete-envelope commitments protect subsequent
passes; no sink is called before record/history/chunk AEAD, role and attachment
whole-content checks succeed. The header reference digest is compared before
object processing. Source full verification precedes archive writing; failed
publication preserves existing copies, including expired ones. Four new store
regressions cover nonce-only corruption in every role, post-unlock historical/
chunk corruption, contradictory digest and between-pass changes; a core test
covers expired-copy preservation after publication failure. Focused archive
23 pass, core snapshot 15 pass, store verify suite passes.

Reviewer pass traced authenticated roles, bounded index/frame reads, shared
AAD/semantic checks, no-SQLite archive parsing, failure ordering and existing
callers. Both original findings are addressed; verdict Approved for remediation
(same-session resumed review, not a fresh independent review). Required SPDX,
fmt, Clippy and full locked tests pass in `/tmp/qv18-review/fix-*.log` with private
Xvfb: 565 passed, 0 failed, 2 pre-existing ignored. Fuzz formatting/build pass;
non-sanitized debug smoke fuzz run completes 94,607 executions in 61 seconds,
no finding (not an instrumented release campaign). No dependencies changed.
Only behavior-preserving test slicing/comment/KDF-serialization edits followed
the full-suite build; Clippy and the final phase-1.13b gates cover the final
combined tree. No commit. Proceeding to 0019 under explicit owner instruction.
