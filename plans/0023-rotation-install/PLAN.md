# Plan 0023 — Rotation installation, restart and `recovery rotate` (roadmap 1.15c)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-30 | 2026-10-30 (standing approval, roadmap 0002) | 0002 §2.2, §3.5 (offline path), §4; 0004 §1–6; 0005 §5.4 (D5); 0007 §3; 0008 §1–3, §5 (D5); 0011 §3–6; 0012 §1 |

## Intent

Finish offline VK rotation. Publish the verified replacement of plan 0022
through the reviewed journal of plan 0021, advance the anchor across the
generation step, and resume or roll back an interrupted transition on
restart. Make snapshot budgets count old-generation copies, and give users
`qvault recovery rotate`. This closes roadmap 1.15 and its whole-rotation
*Done when*.

## Scope

**In scope:**
- Store installation of a `PreparedRotation`:
  - name the replacement;
  - publish the new inventory and the journal (`<vault>.qvrotate`);
  - two no-replace renames;
  - one-step anchor advance;
  - cleanup, with the journal removed last.
- Store restart: authenticate the journal and every present copy with the
  matching credential, classify the state against the anchor, then complete
  or roll back per the 0021 state table.
- Pre-rotation cleanup of inert leftovers from a crash before the journal
  was published (orphaned `-new-` candidates and their temp files, an unused
  next-generation inventory).
- Core:
  - a `Rotation` lifecycle: mandatory pinned recovery snapshot, the session
    consumed, prepare, inventory, three-word phrase confirmation, install;
  - an `InterruptedRotation` resume API;
  - `Core::rotation_pending`;
  - inventory-aware snapshot policy (count, bytes, age, hash-checked
    removal; fail closed on a bad inventory).
- CLI: `recovery rotate` for both a new rotation and resuming one, with
  typed confirmation, exit codes and hints.
- Crash injection at every journal step, for installation and for both
  restart choices.
- Evidence that old-generation archives are neither listed, restored nor
  merged automatically.

**Out of scope:**
- The server step (3.8), LAN peer re-approval (2.9) and remote
  configuration: rotation keeps refusing remote state (Unsupported).
- Quick slots: none exist, and the schema rejects unknown slot types.
  Invalidation is satisfied by the replacement holding exactly one password
  slot (0002 §3.5.5). Platform quick unlock is phase 2.6.
- Listing old-generation snapshots in `snapshot ls` or its JSON (that would
  change the 0011 output contract). They are only counted, aged and pruned.
- Salvaging old-generation edits (0002 §3.5.6), standalone archive import,
  compatibility of development vaults, profile changes.
- Changing the copied `vault_meta` (for example a stale
  `recovery_skipped_at` from an earlier phrase). Nothing reads it yet.
  Rotation preserves logical state and adds only the keyslot edit.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Freeze writes, resolve control conflicts, recovery snapshot, new VK/phrase/slot | 0002 §3.5.1 | Accepted | Replacement built by plan 0022; core freezes and snapshots |
| Phrase confirmation (or explicit warning) and replacement-password unlock before publication | 0002 §3.5.2 | Accepted | Replacement unlock already done in `prepare_rotation`; this plan requires three confirmed words and offers no skip (see Design) |
| Install with a durable journal; advance the anchor before reporting success; restart resumes or rolls back only through the journal; retain the old DB until confirmed; both credentials may be needed | 0002 §3.5.4 | Accepted | Offline path only |
| Invalidate quick slots; never wrap new VK solely with old VK | 0002 §3.5.5 | Accepted | One slot in the replacement; no wrap under the old VK |
| New phrase replaces the old; old-generation peers stop; no automatic salvage | 0002 §3.5.6 | Accepted | Evidence: old archives are not listed or restored and never merged |
| Head/anchor generation step | 0005 §5.4 | Draft, D5 | `head::compare` → `Advanced` |
| Recovery snapshot pin, budgets, recovery copy over budget only with consent | 0007 §3.2–3.3 | Accepted | Durable pin = the journal; inventory rows counted |
| Atomic owner-only files, no-follow, sidecars | 0004 §1–5; 0008 §5 | Accepted; Draft, D5 | Existing `fs` helpers |
| Secret handling, prompts, no secrets in argv or errors | 0008 §1–3; 0011 §3 | Draft, D5; Accepted | |
| `recovery rotate` command and typed confirmation that `--yes` never skips | 0011 §4 (Vault), §5.5, §6 | Accepted | Exit codes per 0011 §6 |
| Matrix rows | 0012 §1 | Accepted | Rotation/purge ambiguity (interrupted rotation), Migration coupling (data part), Whole-file rollback, Hostile SQLite/CBOR (journal file read) |

**Spec changes required:** None. 0011 defines `recovery rotate` as the
resumable workflow of 0002 §3.5 with a typed confirmation. Re-running the
same command to resume an interrupted transition is that workflow; there is
no new command, flag, output format or exit code. File names, the journal
and the inventory are development formats already defined by plans 0021 and
0022. Phase 1.16 freezes them.

## Decisions needed

None. These choices fall under existing requirements and the reviewed design
of plan 0021 (owner: "use best judgment"):

- **No skip of phrase confirmation in rotation.** 0002 §3.5.2 allows
  confirmation *or* an explicit warning. `init` offers a skip because a
  first vault must be creatable. A rotation can simply be cancelled before
  publication with nothing changed. A skipped confirmation during a
  compromise response would leave the user without any working recovery
  path for the new generation. The CLI therefore offers "show the phrase
  again" and "cancel the rotation", but no skip.
- **Credentials on restart.** Every restart state needs both the old and
  the new master password, except "new active, new anchor" (cleanup only),
  which needs only the new one. This follows plan 0021 ("both credentials
  while both copies participate; after new-anchor confirmation the new
  credential suffices"). It also means no file is ever renamed or deleted
  unless the authenticated journal and each authenticated copy agree.
- **Durable pin.** While `<vault>.qvrotate` exists, every ordinary open is
  refused (plan 0021), so no snapshot policy pass can run for that vault. The
  journal's `snapshot_id` is therefore the durable pin. After completion the
  recovery copy is a generation-g file carried by the g+1 inventory and
  counts as ordinary. After rollback it is an unpinned `recover-` file that
  the next ordinary policy pass reclassifies (existing behaviour).
- **Inventory rows are ordinary regardless of their file prefix** once no
  journal exists (0007 §3.2: after confirmed completion the recovery copy
  becomes ordinary). Removal goes only through `remove_inventoried`, which
  needs an exact hash and size match.
- **Bad inventory fails closed** (plan 0021):
  - at generation ≥ 2, a missing or non-verifying current inventory means
    no automatic ordinary snapshot and no pruning, reported as a failed
    snapshot status (the existing warning path);
  - a mandatory recovery snapshot then needs the existing explicit
    over-budget consent;
  - at generation 1, no inventory is expected.
  - Known effect, kept from the reviewed 0021 rule: a generation ≥ 2 vault
    restored on a machine without its inventory runs with reduced snapshot
    protection. This is reported on every unlock, never silent. It is
    recorded for the 1.16 offline audit and is not changed here.
- **Leftovers before a journal exists are removed.** Plan 0022 noted that
  1.15c removes them. They can never be installed without a journal, and
  their names are reserved. A `-old-` sibling without a journal is never
  deleted: it is reported (it would be a user's copy or a broken cleanup).

## Design

**Components touched:**
- `qv-store` (trusted client; parses its own files only after
  authentication):
  - new `rotation_install.rs` (installation, restart, leftover cleanup);
  - `rotation_guard.rs` (sibling names);
  - `vault.rs` (`FileRole::Transition`);
  - `rotation.rs` (`install` entry and accessors);
  - `crash.rs` (new points, multi-directory copy);
  - `snapshot_inventory.rs` (`remove_inventory` becomes used);
  - `unsupported.rs` (fail-closed stubs);
  - `lib.rs` (exports, docs).
- `qv-core` (single frontend entry point): new `rotation.rs`;
  `snapshot.rs` (inventory-aware policy); `session.rs` (take the open
  state); `setup.rs` (`rotation_pending`, `resume_rotation`); `error.rs`
  if mapping is needed.
- `qv-cli` (frontend): `cmd/credentials.rs` (`rotate`), `cli.rs`
  (subcommand), `exit.rs` (hint), `main.rs` docs.
- No new crate, dependency, profile, schema, `unsafe` or trust boundary.

**Interfaces** (names may follow local conventions; contracts, ownership and
bounds are fixed):

```rust
// qv-store — rotation_install.rs (Linux/Android; unsupported.rs fails closed)

/// What is on disk for an authenticated interrupted transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationState {
    /// Old DB active, verified candidate at `-new-`, anchor = old head.
    CandidateReady,
    /// Active path missing, old at `-old-`, candidate at `-new-`, anchor = old head.
    ActiveRetired,
    /// New DB active, old at `-old-`, anchor = old head.
    AnchorPending,
    /// New DB active, anchor = new head; `-old-` may or may not remain.
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationChoice { Complete, RollBack }

impl PreparedRotation {
    /// Publishes the verified replacement (steps I1–I9 below). `snapshot_id`
    /// is the pinned recovery snapshot of the old generation; `inventory` is
    /// the result of `SnapshotDir::prepare_inventory(self, ..)`. Errors
    /// before I3 leave no journal and an unchanged active vault and anchor;
    /// from I3 on they leave a recoverable transition (see `Installed`).
    pub fn install(
        self,
        snapshots: &SnapshotDir,
        inventory: &SnapshotInventory,
        snapshot_id: [u8; 16],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Installed, InstallError>;
}

/// Success. `cleanup_pending` is true when the anchor advanced and the
/// rotation is committed, but the retained old DB, the superseded inventory
/// or the journal could not be removed. The next `recovery rotate` finishes
/// that with the new password.
pub struct Installed { pub new_generation: KeyGeneration, pub cleanup_pending: bool }

/// An installation error, with whether the journal was already published:
/// if so, the frontend says the rotation may be partly applied and directs
/// the user to `recovery rotate`.
pub struct InstallError { pub error: StoreError, pub journal_published: bool }

/// An authenticated interrupted transition. Holds the marker lock and the
/// locks of every opened copy; Debug redacted; no key or path accessor.
pub struct InterruptedRotation { /* journal, copies, vks, state, paths */ }

impl InterruptedRotation {
    /// Reads `<path>.qvrotate` (no-follow, owner-only regular file, size
    /// ≤ MAX_ROTATION_JOURNAL_BYTES by fstat before reading, exclusive lock),
    /// authenticates as described under *Restart*, and classifies the state.
    /// `old` may be None only for `Committed`.
    pub fn open(
        path: &Path,
        anchors: &AnchorDir,
        old: Option<&MasterPassword>,
        new: &MasterPassword,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, StoreError>;
    /// Prompt hint only, from unauthenticated bytes (it authorizes nothing):
    /// false when the active file's header and the stored anchor both claim
    /// the journal's new generation, true otherwise. `open` still
    /// authenticates; `old: None` when an old copy participates is Integrity.
    pub fn needs_old_password(path: &Path, anchors: &AnchorDir) -> Result<bool, StoreError>;
    pub fn state(&self) -> RotationState;
    pub fn old_generation(&self) -> KeyGeneration;
    pub fn new_generation(&self) -> KeyGeneration;
    /// Applies the choice per the state table. `RollBack` on `Committed` is
    /// Integrity (generation regression), checked before any change.
    pub fn finish(
        self,
        choice: RotationChoice,
        snapshots: &SnapshotDir,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), StoreError>;
}

/// Whether `<path>.qvrotate` exists (lstat only, never followed or parsed).
pub fn rotation_pending(path: &Path) -> Result<bool, StoreError>;

/// What `remove_rotation_leftovers` found.
pub struct Leftovers { pub removed: usize, pub retained_old: usize }

impl UnlockedVault {
    /// Pre-journal leftovers of this vault (gate Open; `check_identity`, so
    /// never while a marker exists): removes `<name>.qvrotate-new-<32 hex>`,
    /// `.<name>.qvrotate-new-<32 hex>.tmp-<16 hex>` and their `-journal`
    /// siblings (regular files only, lstat, no-follow; anything else is
    /// UnsafeFile), and the unused `inventory-<vault>-<g+1>` in `snapshots`;
    /// `sync_dir` each directory. Counts but never touches `-old-` names.
    pub fn remove_rotation_leftovers(&self, snapshots: &SnapshotDir)
        -> Result<Leftovers, StoreError>;
}

// qv-core — rotation.rs
pub struct Rotation { /* PreparedRotation, SnapshotInventory, RecoverySnapshot,
    Arc<SnapshotPolicy>, confirmed: BTreeSet<usize> */ }
impl Session {
    /// Refusals before the recovery snapshot exists leave the session open
    /// and unchanged: a read-only/recovery session (NotAllowed), no
    /// snapshot policy (NotAllowed), cancellation, and `SnapshotOverBudget`
    /// without consent (the pass already removed the copy), so the frontend
    /// can retry with consent. Once the pinned recovery snapshot is
    /// published, the open state is taken out and the session is locked
    /// whatever follows: leftovers removal, `prepare_rotation` (a control
    /// conflict → Conflict, a marker → Integrity) and the inventory.
    pub fn begin_rotation(
        &self,
        new_password: &MasterPassword,
        allow_snapshot_over_budget: bool,
        cancel: Option<&CancelToken>,
    ) -> Result<Rotation, CoreError>;
}
impl Rotation {
    pub fn phrase(&self) -> &RecoveryPhrase;
    pub fn new_generation(&self) -> KeyGeneration;
    pub fn leftovers(&self) -> Leftovers;
    /// Records a correctly typed word (constant-time via RecoveryPhrase).
    pub fn confirm_word(&mut self, position: usize, typed: &[u8]) -> Result<bool, CoreError>;
    /// NotAllowed unless three distinct positions were confirmed.
    pub fn install(self, cancel: Option<&CancelToken>) -> Result<RotationOutcome, RotationError>;
}
pub struct RotationOutcome { pub new_generation: KeyGeneration, pub cleanup_pending: bool }
pub struct RotationError { pub error: CoreError, pub journal_published: bool }

impl Core {
    pub fn rotation_pending(&self, path: &Path) -> Result<bool, CoreError>;
    pub fn resume_rotation(
        &self, path: &Path, old: Option<&MasterPassword>, new: &MasterPassword,
        cancel: Option<&CancelToken>,
    ) -> Result<InterruptedRotation, CoreError>;      // re-exported store type
    pub fn finish_rotation(
        &self, rotation: InterruptedRotation, choice: RotationChoice,
        cancel: Option<&CancelToken>,
    ) -> Result<(), CoreError>;
}
```

**Names** (all siblings in the vault's directory, built by
`rotation_guard` from the vault path and the 16-byte suffix; never from
journal bytes other than the suffix):
- marker/journal: `<name>.qvrotate`;
- candidate: `<name>.qvrotate-new-<32 hex>`;
- retained old DB: `<name>.qvrotate-old-<32 hex>`.

**Data and control flow — installation** (`PreparedRotation::install`).
Before I1, core has taken and pinned the recovery snapshot, removed
leftovers, and built the replacement and inventory. Each step is followed
by a crash point (new `CrashPoint` variants named after the step), and
every rename is `rename_noreplace` plus `sync_dir`:

| Step | Action | Crash leaves |
|------|--------|--------------|
| I0 | Re-check: source `check_identity`, no marker, anchor loads and `compare(old head) == Verified`, replacement `check_identity` | nothing changed |
| I1 | Rename the replacement temp file → candidate name; `sync_dir` | inert orphan (removed by the next rotation) |
| I2 | `snapshots.publish_inventory(inventory)` → digest | orphan g+1 inventory (removed by the next rotation) |
| I3 | Sign `RotationJournal` (new random operation ID; vault/replica IDs, generations, sequences, digests, suffix, `snapshot_id`, inventory digest) with old and new VK; write it via `create_temp(marker)`, `write_all`, fsync, re-read and compare, `rename_noreplace`, `sync_dir`. Keep the locked marker fd. | **CandidateReady** |
| I4 | Rename active → old name | **ActiveRetired** |
| I5 | Rename candidate → active | **AnchorPending** |
| I6 | Load the anchor again; require `compare(new head, new digest, anchor) == Advanced`; `anchors.store(replica, anchor_of(new state))` (existing points `AnchorTempWritten`, `AnchorReplaced`) | AnchorPending or **Committed** |
| I7 | Remove the old DB (and its `-journal` if any); `sync_dir` | Committed |
| I8 | `snapshots.remove_inventory(vault, g)` (superseded; its rows are in g+1) | Committed |
| I9 | Remove the marker; `sync_dir`. Then drop the locks. | done |

- An error in I0–I2 returns `journal_published = false`. Cleanup removes
  the candidate and the g+1 inventory best effort.
- An error from I3 on returns `journal_published = true` and changes
  nothing further. Cancellation is checked only up to I3; from I4 on, the
  sequence runs to completion or to the first error.
- An I7–I9 failure after a successful I6 is `Ok(Installed {
  cleanup_pending: true })`: the rotation committed (0002 §3.5.4 "advance
  the anchor before reporting success").

**Data and control flow — restart** (`InterruptedRotation::open`/`finish`):

1. **Read the marker.** Lock it: `fs::open_existing` semantics, but
   read-only parsing, size ≤ 4096 by fstat. `RotationJournal::decode`
   (syntax only). Require its vault ID to equal the header vault ID of every
   copy opened below.
2. **Open the copies.** lstat active, old and new names. Open each present
   one with the new crate-private `FileRole::Transition`:
   - it skips the reserved-name and marker tests, and only for the paths
     derived from this journal;
   - its `begin` and `finish_pending_anchor` refuse, as for Candidate;
   - it is never given to `finish_unlock`.

   For each copy, read the unverified header generation:
   - old generation: unlock with `old` (absent → `WrongPassword`-free
     refusal: `NotAllowed` at core; the store returns Integrity);
   - new generation: unlock with `new`;
   - any other generation: Integrity.

   Then verify the header MAC, load the state without anchor access, and
   run a full `verify_all` (cancellable). Require head generation, sequence
   and digest to equal the journal's side. Verify the journal MAC of that
   side with that copy's VK (`RotationJournal::verify`).
3. **Classify.** Load the anchor of the journal's replica ID; it must equal
   the old head (`Verified` against old) or the new head (`Verified`
   against new). Anything else, a missing anchor, or any file combination
   outside the table is Integrity. Nothing is changed and the evidence is
   preserved.

| State | Files | Anchor | Complete | Roll back |
|-------|-------|--------|----------|-----------|
| CandidateReady | active = old, new sibling | old | I4–I9 | remove candidate (+`-journal`), `sync_dir`; remove g+1 inventory; remove marker |
| ActiveRetired | old sibling, new sibling, no active | old | I5–I9 | rename old → active; then as above |
| AnchorPending | active = new, old sibling | old | I6–I9 | rename active → candidate name, old → active; then as above |
| Committed | active = new, old sibling optional | new | I7–I9 (only what remains) | Integrity, before any change |

   Committed needs only `new`. If the old sibling is present, it is removed
   only because the authenticated journal names it and the anchor already
   confirms the new head. It is not unlocked.

4. Every filesystem step of `finish` is one of the step points above, so the
   crash matrix restarts again from each one. Re-running `open` after any
   crash must classify the new on-disk state correctly.

**Data and control flow — core lifecycle:**
- `begin_rotation`: under the session lock, with `read_only` false and a
  policy configured:
  1. check cancellation;
  2. `begin_destructive`-equivalent recovery snapshot of the current
     generation (pinned in memory). An error here returns with the session
     open;
  3. take the `Open` out of the session; the session is locked and handles
     become stale;
  4. remove leftovers;
  5. `vault.prepare_rotation(new_password, cancelled)`;
  6. `dir.prepare_inventory(&prepared, cancelled)`;
  7. return `Rotation`.

  On any error the session is already locked. The recovery snapshot stays as
  an unpinned `recover-` file, which the next unlock's policy reclassifies.
- `Rotation::install`:
  1. require three confirmed distinct positions;
  2. call `prepared.install(dir, inventory, snapshot_id)`;
  3. on success, drop the in-memory pin;
  4. return `RotationOutcome`.

  A new unlock with the new password is required afterwards.
- Snapshot policy (`snapshot_pass`, listings unchanged):
  1. At generation ≥ 2, `dir.inventory(vault)`:
     - `Ok(Some)`: its rows join the age and count/byte passes as ordinary
       candidates;
     - `Ok(None)` or `Err`: no ordinary snapshot is written and nothing is
       pruned; report `SnapshotReport::failed()`. A Recovery-kind pass
       continues only with `allow_over_budget` and prunes nothing.
  2. Removal of a row uses `dir.remove_inventoried(vault, row, cancelled)`.
     `NotFound` means already gone. `Integrity` keeps the file and stops
     pruning that pass with a failed report: never delete on mismatch.
  3. Rows are never pinned (no journal can exist while a session is open)
     and are never the new copy. Ordering stays oldest-first by authenticated
     `created_at`.
  4. Stale rows (file gone) are harmless and remain until the next rotation
     drops them.

**Secrets and hostile input:**
- Passwords stay `MasterPassword`, keys `VaultKey`, the phrase
  `RecoveryPhrase`; typed words are bounded `SecretBytes` from the existing
  TTY reader.
- The journal holds no key, path or plaintext, and is authenticated by both
  generation MACs against each authenticated copy before it is acted on.
- The marker read is bounded before allocation; a symlink, directory,
  non-owner-only file or oversized file is refused.
- Names come only from the vault path and the 16-byte suffix.
- `InterruptedRotation`, `Rotation`, `Installed` and the error types have
  redacted Debug.
- Errors carry no path or secret.

**Errors:** existing `StoreError`/`CoreError` only. Mapping:

| Condition | Error | Exit |
|-----------|-------|------|
| Marker present on ordinary open | Integrity | 7, plus a new hint: "an interrupted key rotation exists; run `qvault recovery rotate` to complete or roll it back" (the CLI checks `rotation_pending`) |
| Wrong old/new password | WrongPassword | 3 |
| Lock held / replaced | Locked / Replaced | 6 |
| Control conflict | Conflict | 8 |
| Overflow, over budget | LimitExceeded / SnapshotOverBudget | 9 |
| Cancellation, I/O | Cancelled / Io | 1 |

  An error with `journal_published` gets the line: "The rotation may be
  partly applied. Do not delete any `.qvrotate` file; run `qvault recovery
  rotate` again with both passwords."

**CLI** (`qvault recovery rotate`):
1. Reject `--json` and `--password-stdin` (exit 2) and require a TTY for
   both stdin and stdout, before any secret.
2. If `rotation_pending(path)`:
   - say "An interrupted key rotation was found";
   - prompt for the new master password, then for the old one when
     `Core::rotation_needs_old_password` (the store hint) says so; then
     `resume_rotation`, which authenticates;
   - show the state in one line and the two generations;
   - Committed: confirm "finish cleanup" (typed `complete`);
   - otherwise: require typing `complete` or `rollback` (no default;
     `--yes` ignored).
3. Otherwise:
   - unlock with the current password;
   - print what rotation does and does not protect (0002 §3.5 closing
     paragraph: old copies, snapshots and old phrase still open the old
     generation; retained old-generation snapshots need the old phrase);
   - require typing `rotate` (0011 §5.5, even with `--yes`);
   - `choose_password` (0010 §4.2 / 0011 §5.4);
   - `begin_rotation` with the existing over-budget consent prompt
     (`recovery_copy` pattern);
   - report leftovers removed / old siblings retained;
   - `show_phrase` on the alternate screen;
   - confirm three random words (`confirmation_positions`), with "show
     again" and "cancel rotation (nothing changes)" and no skip;
   - `install`;
   - print "Key rotation complete: generation N" and, if
     `cleanup_pending`, the cleanup note;
   - lock.

   Signals cancel only before publication; after the journal is published,
   a signal is ignored until `install` returns (the store no longer polls
   cancellation).

**Dependencies:** None.

## Steps

### Step 1 — Transition primitives and crash harness

- [x] **Do:**
  - Add sibling-name helpers to `rotation_guard`.
  - Add `FileRole::Transition`, with `guard`, `begin` and
    `finish_pending_anchor` behaviour as in *Restart*.
  - Add a crate-private `read_marker(path) -> (LockedFile,
    RotationJournal)` with the bounds above, `rotation_pending`, and the
    leftover scan/removal (`Leftovers`).
  - Add the new `CrashPoint` variants (I1–I9 and the rollback steps R-cand,
    R-old, R-inv, R-marker).
  - Add a `Copy::Dirs(vault dir, anchors, snapshots)` mode to
    `crash::test`, which copies every file of the three directories.
  - Add stubs in `unsupported.rs`.
- **Files:** `crates/qv-store/src/{rotation_guard,vault,write,rotation_install,crash,unsupported,lib}.rs`.
- **Done when:** unit tests cover:
  - names;
  - the Transition role refusing writes and anchor access;
  - `read_marker` refusing symlink, directory, 0644, oversized, garbage and
    locked markers;
  - leftovers: removes exactly the candidate/temp/`-journal`/g+1-inventory
    patterns, counts but keeps `-old-`, and refuses when a marker exists;
  - `rotation_pending` lstat-only.
- **Verify:** `cargo test --locked -p qv-store rotation_install_primitives`; `cargo test --locked -p qv-store rotation_guard`.

### Step 2 — Installation

- [x] **Do:** implement `PreparedRotation::install` (I0–I9), `Installed`
  and `InstallError`, with the cleanup rules and crash points above.
- **Files:** `crates/qv-store/src/{rotation_install,rotation,snapshot_inventory}.rs`.
- **Note:** after I1 the replacement session's path is stale and after I4
  the source's is. Do not call `check_identity` on either after those
  points; I6 uses the in-memory verified new state, and the marker fd and
  inode locks are held throughout.
- **Done when:** `rotation_install_*` tests show:
  - after success, the active path unlocks ordinarily with the new password
    only, the anchor is `Verified` at g+1/seq+1, no `.qvrotate*` or g
    inventory remains, the g+1 inventory verifies and includes the
    recovery snapshot, and the old password/phrase fail on the active file;
  - an I0 refusal (anchor changed, marker appeared, identity replaced)
    changes nothing;
  - an injected I7/I8/I9 failure reports `cleanup_pending`.
- **Verify:** `cargo test --locked -p qv-store rotation_install`.

### Step 3 — Restart: open, classify, complete, roll back

- [x] **Do:** implement `InterruptedRotation` per *Restart* and the state
  table, the Transition opens, both MAC checks and every refusal.
- **Files:** `crates/qv-store/src/{rotation_install,vault}.rs`.
- **Done when:** `rotation_resume_*` tests, built from an installation
  stopped at I3, I4, I5 and after I6, show:
  - each state is classified correctly;
  - Complete ends in the new generation active (anchor verified, no
    siblings);
  - Roll back ends in the old generation active (anchor still `Verified`
    for the old head, no siblings, no g+1 inventory, the recovery snapshot
    unpinned and present);
  - Committed refuses rollback before any change;
  - Committed works with the new password only;
  - wrong old or new passwords are `WrongPassword` with nothing changed.

  Hostile cases are Integrity with byte-identical evidence:
  - a forged journal (either MAC wrong, a bit flipped, swapped suffix,
    another vault's journal);
  - a swapped or substituted copy (another vault, a stale old copy, the
    candidate replaced by a fresh rotation of a copy);
  - the anchor at neither head; a missing anchor;
  - a missing required copy; an extra active in ActiveRetired.
- **Verify:** `cargo test --locked -p qv-store rotation_resume`.

### Step 4 — Crash matrix (every journal step)

- [x] **Do:** tests named `rotation_crash_*`:
  - For each installation point I1–I9, plus `AnchorTempWritten` and
    `AnchorReplaced` during I6: copy the three directories at the point,
    then on the copy:
    - an ordinary unlock is refused (Integrity) while a marker exists, or
      succeeds with exactly one of the two generations when none exists;
    - `InterruptedRotation::open` classifies;
    - `finish(Complete)` and, separately on a second copy,
      `finish(RollBack)` (where allowed) both end in a single consistent
      generation, with an ordinary unlock and a verified anchor;
    - logical state is identical to the source (manifest record set,
      heads, history and attachments by content);
    - for points before I3, the next rotation's leftover removal leaves no
      reserved files.
  - For each rollback and complete-from-restart step point: crash there
    and restart again (a second-level crash) to a consistent end.
- **Files:** `crates/qv-store/src/rotation_install_tests.rs`.
- **Done when:** every point fires (`disarm` returns false), each case
  passes, and no case ends with both or neither generation openable.
- **Verify:** `cargo test --locked -p qv-store rotation_crash`.

### Step 5 — Inventory-aware snapshot policy

- [x] **Do:** extend `snapshot_pass`/`authenticated` callers as in
  *Snapshot policy*, with tests `snapshot_inventory_policy_*`:
  - inventory rows count toward count/bytes and are pruned oldest-first and
    by age;
  - a row whose file changed is kept, and the pass reports failed;
  - a missing or corrupt inventory at generation ≥ 2 writes no ordinary
    snapshot and prunes nothing, and a recovery snapshot requires
    over-budget consent;
  - generation 1 is unchanged;
  - existing snapshot tests are unchanged.
- **Files:** `crates/qv-core/src/snapshot.rs`.
- **Done when:** all listed tests and `cargo test --locked -p qv-core snapshot` pass.
- **Verify:** `cargo test --locked -p qv-core snapshot`.

### Step 6 — Core rotation lifecycle and resume

- [x] **Do:** implement `Session::begin_rotation`, `Rotation`,
  `RotationOutcome`/`RotationError`, `Core::{rotation_pending,
  rotation_needs_old_password, resume_rotation, finish_rotation}`, the session take-out, and the error
  mapping (`InvalidEdit` from control conflicts → `Conflict`).
- **Files:** `crates/qv-core/src/{rotation,session,setup,snapshot,error,lib}.rs`.
- **Done when:** `rotate_*` tests show:
  - a full rotation through core, after which a new unlock with the new
    password works at g+1 with all entries, history and attachments, and
    the old password fails;
  - the session is locked and its handles are stale after `begin_rotation`,
    whatever the result;
  - install without three confirmed words is NotAllowed;
  - read-only, no-policy and pending-journal sessions are refused;
  - an over-budget recovery copy needs consent;
  - a cancelled `begin_rotation` publishes nothing and leaves an unpinned
    `recover-` copy, reclassified at the next unlock;
  - a resume through core works with both choices;
  - after rotation, an old-generation snapshot is not listed by
    `snapshots()`, `restore_snapshot` of its ID is NotFound, and the
    inventory counts it.
- **Verify:** `cargo test --locked -p qv-core rotate`.

### Step 7 — CLI `recovery rotate`

- [x] **Do:** add the subcommand, both flows, prompts, typed choices,
  messages and the ordinary-open hint.
- **Files:** `crates/qv-cli/src/{cli,exit,main}.rs`, `crates/qv-cli/src/cmd/credentials.rs`.
- **Done when:** the command builds; `--help` text names the typed
  confirmation; `--json`/`--password-stdin`/non-TTY are exit 2 before any
  prompt.
- **Verify:** `cargo test --locked -p qv-cli`.

### Step 8 — CLI evidence

- [x] **Do:** add PTY tests in `crates/qv-cli/tests/rotation.rs`, following
  the existing credentials PTY harness:
  - a successful rotation with a typed `rotate`, a new password, the phrase
    shown and three words confirmed; then `ls` with the new password is exit
    0, with the old password exit 3, and `info` shows generation +1;
  - `--yes` does not skip `rotate`;
  - a wrong typed confirmation or a declined phrase check (cancel) leaves
    the vault and anchor byte-identical, with exit 1;
  - a real interrupted transition, with no test hook in the binary: make
    the anchor directory 0500 before `recovery rotate`, so I6 fails after
    the journal is published (unlock and snapshots do not write anchors).
    That run must exit 1 with the "partly applied" line; the test asserts
    that the marker exists, and fails rather than skips if it does not
    (for example when running as root). Restore 0700. Then:
    - ordinary `ls` is exit 7 with the hint;
    - on one copy of the directories, `recovery rotate` with both
      passwords and `complete` gives the new generation;
    - on a second copy, `rollback` gives the old generation, and `ls` with
      the old password is exit 0;
  - after rotation, `snapshot ls` shows no old-generation copies and
    `snapshot restore <old id>` is exit 4.
- **Files:** `crates/qv-cli/tests/rotation.rs`.
- **Done when:** all cases pass under the private Xvfb run as well (no
  clipboard use).
- **Verify:** `cargo test --locked -p qv-cli --test rotation`.

### Step 9 — Documentation, roadmap and gates

- [x] **Do:** update:
  - the qv-store/qv-core/qv-cli crate docs;
  - `ARCHITECTURE.md` §3 (the rotation paragraph: installation and restart
    complete) and §7 (1.15 complete);
  - `CHANGELOG.md`;
  - 0002 is unchanged (status stays `Accepted`; implemented status only in
    1.16);
  - the roadmap: tick 1.15c and 1.15, the plan number, the execution log;
  - the `plans/README.md` row;
  - this plan's log.

  Run every gate.
- **Files:** as listed.
- **Done when:** the plan is Implemented and all gates are green.
- **Verify:** all `AGENTS.md` gates; `git diff --check`.

## Test plan

- Final verification: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings` and `cargo test
  --locked` with a private Xvfb (`QV_TEST_XVFB`), with logs in the session
  scratchpad. No dependency change, so deny/vet are not required.
- Unit tests: names, roles, marker read, leftovers, state classification,
  policy accounting.
- Rejection, malformed-input and crash-path tests:
  - step 3 hostile journals and copies;
  - step 4 crash matrix at I1–I9 and the anchor points, with both restart
    choices and second-level crashes;
  - step 5 changed or missing inventory;
  - CLI refusals before secrets.
- Vectors: none new (journal and inventory vectors exist).
- Fuzz: no new parser. Marker bytes go through the existing
  `rotation_journal` codec, which is already fuzzed.
- 0012 §1 rows:
  - Rotation/purge ambiguity: interrupted rotation, every step, both
    choices;
  - Migration coupling (data part): logical state equal after rotation and
    after each recovery;
  - Whole-file rollback: no reserved copy is openable, rollback after
    Committed is refused, anchor one-step;
  - Hostile SQLite/CBOR: marker read bounds;
  - Old-generation archives: not listed, not restored, never merged
    automatically.

## Risks and stop conditions

Stop and report if:
- the state table cannot be applied without deleting or renaming a file
  that is not authenticated as described;
- any rename can replace an existing name on the target filesystem
  (`rename_noreplace` must stay mandatory; Unsupported aborts before I3);
- the anchor cannot be advanced through the existing `AnchorDir::store`
  after a `compare` of `Advanced`;
- snapshot policy changes would alter the existing `snapshot ls`/JSON
  contract;
- a phrase-skip path, a new exit code, a new CLI flag or a spec amendment
  seems necessary;
- a schema, profile, dependency or `unsafe` change is needed;
- a secret would reach the journal, an error, Debug, argv or a log.

Never install a candidate without a verified journal. Never delete an
`-old-` sibling before the anchor confirms the new head. Never advance the
anchor without both MAC'd sides verified (or Committed). Never treat a
missing file as permission to create a vault at the active path.

## Documentation

- [x] `CHANGELOG.md`: Unreleased: offline rotation complete, `recovery
  rotate`, restart/rollback, inventory-aware budgets.
- [x] `ARCHITECTURE.md`: §3 rotation paragraph; §7 1.15 complete.
- [x] Specs: no normative change; statuses unchanged.
- [x] `AGENTS.md`: no change.
- [x] Plans: this plan's log; the roadmap 1.15c/1.15 ticks and log;
  `plans/README.md` row.

## Revisions

None.

## Execution log

2026-10-30: Clean tree at `5fe3495` apart from the owner's uncommitted D13
roadmap revision (not phase work). Plan 0022 (1.15b) got a fresh-context
review in this session: Approved with minor fixes, see its REVIEW.md. Planned
1.15c in 9 steps (within the session-size rule). No open decision, spec
amendment, dependency, `unsafe`, or crate/scope/order deviation from the
roadmap entry, so this is standing approval, roadmap 0002. Developer starts
at step 1.

2026-10-30: Steps 1–4 done (qv-store).
- **Primitives.**
  - `FileRole::Transition`: no marker or reserved-name test, identity
    checked, never written or anchored.
  - `VaultFile::relocate` (no-replace rename, directory fsync, then follows
    the locked inode) and `enter_transition`.
  - `rotation_guard::{marker, sibling, Sibling}`; `rotation.rs` now uses the
    sibling helper.
  - `LockedFile::read_bounded` (fstat cap, then read through a duplicate
    descriptor).
  - `rotation_install.rs`: `rotation_pending`, the locked journal read,
    exact leftover patterns and `UnlockedVault::remove_rotation_leftovers`.
  - New `CrashPoint`s for I1–I9 and the rollback steps, and
    `crash::test::arm_dirs` (copies three directories). The existing
    single-directory copy now skips non-regular entries, which snapshot
    directories never contain.
  - Fail-closed stubs in `unsupported.rs`; exports in `lib.rs`.
- **Installation** (`PreparedRotation::install`): I0–I9 as designed. The
  journal's locked descriptor is kept until it is removed. The
  `RotationAnchored` point fires after the anchor write; from there a
  failure is `cleanup_pending`, not an error.
- **Restart** (`InterruptedRotation::{open, state, finish}`,
  `needed_passwords`): the state table, both MACs, head, sequence and
  digest per side, anchor comparison, refusals before change.
- **Tests.** 13 new `rotation_install_*`, `rotation_resume_*` and
  `rotation_crash_*` tests:
  - names and leftover patterns;
  - leftover removal (symlink refused, marker refused);
  - Transition role write/adopt refusal;
  - marker symlink, directory, 0644, oversized, garbage and locked;
  - successful install, with the recovery snapshot carried in the g+1
    inventory;
  - refusals before publication (changed anchor, late marker,
    cancellation);
  - `cleanup_pending` at three points;
  - each state classified and finished both ways;
  - wrong or missing passwords;
  - RollbackPending;
  - hostile journals, copies and anchors (forged new or old MAC, flipped
    bit, anchor at neither head, missing anchor, swapped old copy, extra
    candidate, missing active, a candidate from another rotation), each
    with byte-identical evidence;
  - the crash matrix at all 11 installation points and at 8 completion
    and 5 rollback points after a restart (second-level crashes). Every
    case ends with exactly one generation openable, its anchor verified
    and its logical state equal to the source.

  `cargo test --locked -p qv-store rotation_`: 36 passed (140 s).
  `cargo clippy --locked -p qv-store --all-targets -- -D warnings`: clean.

Differences from the plan:
- An extra state, **`RollbackPending`**: a rollback interrupted after the
  candidate was removed leaves the old vault active with only the journal
  and the unused inventory. It needs only the old password, and Complete
  is refused.
- So the password hint is `needed_passwords → NeededPasswords { old, new }`
  instead of `needs_old_password`, and `open` takes `new:
  Option<&MasterPassword>` as well.
- Committed cleanup removes an unopened `-old-` sibling only as a regular
  file (lstat, no-follow), as designed.

2026-10-30: Steps 5–6 done (qv-core).
- **Policy** (`snapshot.rs`):
  - `old_rows` reads the current generation's verified inventory
    (generation ≥ 2) and keeps rows whose file still exists.
  - Rows age out and join count/byte pruning as ordinary candidates,
    removed only through `remove_inventoried`. A mismatch keeps the file,
    marks the report failed and stops pruning.
  - A missing or non-verifying inventory: no ordinary copy (reported
    failed), no pruning; a recovery copy needs the over-budget consent.
  - `snapshots()` subtracts inventoried files from `unreadable`, so old
    copies are neither listed nor warned about.
- **Lifecycle** (`rotation.rs`):
  - `Session::begin_rotation`: preflight refusals and the recovery
    snapshot with the session still open; then `take_open`, leftovers,
    `prepare_rotation` and `prepare_inventory`.
  - `Rotation::{phrase, new_generation, leftovers, confirm_word, install}`;
    `ROTATION_CONFIRMATIONS = 3` distinct positions.
  - `RotationOutcome`, `RotationError`.
  - `Core::{rotation_pending, rotation_passwords, resume_rotation,
    finish_rotation}`.
  - Store `InvalidEdit` → `Conflict`; `Io` after cancellation →
    `Cancelled`.
- **Tests** (`rotation_tests.rs`, 8):
  - the full lifecycle: the session is consumed; entries, groups and
    attachment content are kept; seq +1; the old password fails;
    `verify` at generation 2; old copies unlisted, not unreadable, not
    restorable, still on disk;
  - refusals that keep the session (no policy, recovery session, over
    budget then consent, cancellation);
  - install without three distinct words, and a dropped rotation, publish
    nothing (vault and anchor byte-identical; the recovery copy is
    reclassified at the next policy pass);
  - resume through core both ways, from a real interrupted install (the
    anchor directory made 0500);
  - resume without a policy is NotAllowed;
  - inventory-aware count and age pruning;
  - a changed old file is kept with a failed report;
  - a missing inventory fails closed.

  `cargo test --locked -p qv-core`: 82 passed. `cargo clippy --locked -p
  qv-core --all-targets -- -D warnings`: clean.

Differences from the plan:
- `Core::rotation_passwords` (returns `NeededPasswords`) replaces
  `rotation_needs_old_password`; `resume_rotation` takes optional old and
  new passwords (see steps 1–4).
- Restoring an old-generation snapshot by ID is refused with the store's
  authentication error (Integrity, exit 7), not NotFound: the file exists
  but does not authenticate with the current key. Step 8 asserts that
  refusal instead of exit 4.

2026-10-30: Steps 7–9 done; plan Implemented.
- **CLI.** `qvault recovery rotate`, in `cmd/credentials.rs`:
  - it refuses `--json`, `--password-stdin` and non-TTY use (exit 2)
    before any prompt;
  - it requires a typed `rotate` (`--yes` ignored) and uses the existing
    password chooser;
  - the over-budget consent is the existing recovery-copy pattern;
  - it reports leftovers;
  - the phrase is shown on the alternate screen and checked with three
    words: an empty line offers show-again or cancel, with no skip;
  - an install error after publication adds the "partly applied" line;
  - resume asks only for the needed passwords
    (`Core::rotation_passwords`), then a typed `complete`/`rollback` (or
    the single valid choice for Committed and RollbackPending).

  `cli::rotation_hint` adds the `recovery rotate` hint to ordinary,
  `recovery show` and `recover` unlock refusals when a marker exists.
- **CLI tests** (`tests/rotation.rs`, 3):
  - a full rotation with `--yes` still prompting for `rotate`; the new
    password exits 0 and the old one 3; `info` shows generation 2; the old
    snapshot is unlisted, its restore is exit 7 (no output), and the file
    is kept;
  - refusals: usage forms exit 2; a wrong typed word or a cancelled phrase
    check exits 1, with the vault and anchors byte-identical and no
    reserved files;
  - a real interrupted installation (the anchor directory made 0500):
    `ls` exits 7 with the hint; a copy of the home completes, another rolls
    back, and each ends openable only with its generation's password.
- **Docs.** qv-store/qv-core/qv-cli crate docs, `ARCHITECTURE.md` §3/§7,
  `CHANGELOG.md`, the roadmap, `plans/README.md`, this plan.
- **Final gates** on the final tree (logs: session scratchpad `r23/`):
  - `sh scripts/check-spdx.sh`: pass;
  - `cargo fmt --check`: pass;
  - `cargo clippy --all-targets --locked -- -D warnings`: pass;
  - `cargo test --locked` with private Xvfb (`QV_TEST_XVFB`): **645
    passed, 0 failed, 2 pre-existing ignored**, 35 groups;
  - `git diff --check` clean.

  No dependency, lockfile, profile, schema, `unsafe` or spec change, so
  deny/vet are not required. Network namespace isolation is unavailable and
  not counted as a pass.

Found, not fixed:
- `qvault info` on a vault with a pending rotation reports the
  unauthenticated header as before, with no rotation hint. It is a
  read-only header view; noted for the 1.16 audit.
- A generation ≥ 2 vault restored on a machine without its inventory
  reports a failed snapshot status on every unlock (the fail-closed rule
  kept from plan 0021); for the 1.16 audit.
- The same-session check before the fixes is not an independent review. The
  next fresh session reviews 0023; changes are uncommitted, with no commit,
  push or branch.

2026-10-30: Fresh-context review (next-phase session after the owner commit
`c7b6c1d`): **Approved with minor fixes**, see [REVIEW.md](REVIEW.md). The
directory fsync of the journal now follows the candidate handover, so a
failure there is reported as published. Added the three planned hostile
restart cases (swapped suffix, another vault's journal, stale old copy) and
corrected a stale doc comment. Status Reviewed.
