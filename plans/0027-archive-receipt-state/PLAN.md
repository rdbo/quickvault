# Plan 0027 — Archive receipts and atomic incoming acceptance (roadmap 2.2b)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-30 | 2026-10-30 | 0004 §2–5; 0005 §4, §5.4; 0008 §1–3, §5; 0012 §1 |

## Intent

Complete roadmap 2.2b: authenticate and atomically accept incoming archive
candidates, with durable confidential filename receipts and the existing
commit/anchor ordering. Both formerly split B parts are one owner-directed unit.

## Scope

**In scope:** bounded sealed receipts, safe source-path handling, conservative
candidate validation, encrypted object/chunk staging, atomic receipt/head/data
commit, restart/idempotency, permanent tombstone retention, and adversarial/crash
evidence. Steps 1–7 record the completed storage foundation; steps 8–12 complete
acceptance under the owner's explicit continuation below.

**Out of scope:** core/CLI exchange commands, mandatory recovery-snapshot policy
at that future core operation boundary, explicit conflict/slot resolution and
archive export (2.2c); LAN/server transports, compatibility and release claims.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Durable changed-filename rejection | 0005 §4.3 | Draft | D5 and owner delegation in 0026 |
| Local encrypted state and bounded input | 0004 §2–4 | Accepted | Amend exact receipt layout before code |
| Head/anchor ordering | 0005 §5.4; 0004 §5 | Draft / Accepted | Reuse current transaction/anchor path |
| Confidential paths and serialization | 0008 §1–3, §5 | Draft | D5 and 0026 delegation |

**Spec changes required:** 0004 §2.3 defines the receipt envelope, AAD, bounds,
digest, reset and preservation rules; 0005 §4.3/§5.4 names that contract.
Continuation adds 0004 §3.4.1 tombstone markers and 0007 preservation/view
clarifications before code. Update Changelogs/index. Existing local-state key,
stored-data/1 and object-hash/1 profiles are reused (0002 §1/§3.3).

## Decisions needed

None. Plan 0026 records the owner's approval of complete-stream SHA-256 receipts,
4096-byte raw absolute paths, 4096 receipts, no eviction, sealing, head binding,
atomic acceptance, and reset on restore/rotation, including delegation of exact
layouts/transcripts. This plan implements that approval, not a new owner choice.
The preceding 0026 review is Approved with all gates passing.

## Design

The following records the completed steps 1–7 foundation. The owner-directed
continuation below defines the final acceptance API and remaining implementation.

**Components touched:** qv-store owns receipt metadata, codecs and SQLite state;
qv-crypto enables its existing LocalState purpose key for the already specified
AEAD use. No frontend or dependency boundary changes.

**Interfaces:**

```rust
// Pure bounded metadata, never an authentication or publication capability.
pub struct ArchiveReceipts { /* sorted protected paths and stream digests */ }
impl ArchiveReceipts {
    pub fn new() -> Self;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn remember(&mut self, canonical_absolute_path: &[u8], digest: [u8; 32])
        -> Result<bool, StoreError>; // new=true, same=false, changed=Integrity
    pub fn encode(&self) -> Result<SecretBytes, StoreError>;
    pub fn decode(plaintext: &[u8]) -> Result<Self, StoreError>;
}
// Internal receipt_store: seal/open using header + replica ID; bounded SQL
// reads; insert an empty initial row and return its digest. No receipt commit API.
```

Keep sorted `Vec` rows with each path in SecretBytes. Canonical raw POSIX paths
start with `/`, have a filename, contain no NUL, duplicate/trailing separator or
`.`/`..` component; non-UTF-8 bytes are valid. The next subphase normalizes input
and opens source components without symlinks. This codec never opens paths.
Enforce 4096 rows and 4096 bytes per path before growing allocations. Existing
keys are checked before the capacity limit, so identical redelivery succeeds
at capacity and changed bytes report Integrity without mutation.

Plaintext: canonical `[1, [[path:bstr, sha256:bstr32], ...]]`, strictly sorted
by raw path. Envelope: `[1, data_profile, nonce:bstr24, ciphertext:bstr]`.
Use stored-data/1 padding/AEAD, random nonce and the existing local-state key;
AAD is `["qv/archive-receipts/v1", vault_id:bstr16, key_generation:uint,
replica_id:bstr16, data_profile:uint]`. Ciphertext cap 32 MiB; whole-envelope
cap 32 MiB + 128 bytes (the worst plaintext is below 17 MiB). Hash the complete
canonical envelope with object-hash/1; local head key 7 is its mandatory digest.
Reserve key 8 for future LAN-link binding. Unknown fields/profiles fail closed.

`archive_receipts(id INTEGER PRIMARY KEY CHECK(id = 1), sealed BLOB NOT NULL)`
is STRICT with exactly one row, independently checked before allocating the blob.
Bump volatile header/schema from 0x7FFF0002 to 0x7FFF0003; no migration.

**Data and control flow:** creation and shared restore/rotation builders insert
fresh empty receipt state in the same unpublished DB transaction as their head.
Restore gets a new replica binding; rotation gets a new generation/key and empty
receipts. Ordinary writes preserve the existing envelope and head digest; begin
rechecks the bounded blob against the session's authenticated head. Unlock
checks head MAC, receipt envelope digest and AEAD before decoding paths, within
the existing read transaction. Nothing can drop missing/malformed state to an
empty default. Archive writers remain independent of local tables.

Future incoming acceptance must write its new receipt envelope, objects,
manifest and head in the existing one transaction, then advance the anchor
before reporting success. This subphase adds no production receipt insertion
or incoming-acceptance API and makes no exchange-completion claim.

**Secrets and hostile input:** paths and encoded plaintext use SecretBytes;
the encoder's intermediate storage zeroizes. No path-bearing Debug/errors.
Sealed envelopes alone may use ordinary Vec. Bound SQL values and envelope
lengths before allocation, verify digest/AEAD before parsing plaintext. Drop
decoded receipts after validation; no persistent plaintext index.

**Errors:** fixed StoreError values: Integrity for changed bytes, invalid paths,
duplicate/unsorted rows and mismatched bindings; LimitExceeded for size/count
limits; Unsupported for unknown formats/profiles; preserve operational errors.

**Dependencies:** none. No unsafe, new primitive, KDF purpose or external crate.

## Steps

### Step 1 — Split and normative contracts

- [x] **Do:** Record 2.2b1/b2 under the roadmap session-size rule; amend the
  approved receipt contracts and index before code.
- **Files:** roadmap, 0004, 0005, specs/README, this plan, plans index.
- **Done when:** exact formats, scope and authorization are recorded.
- **Verify:** `git diff --check`; same-session architect check.

### Step 2 — Protected receipt codec

- [x] **Do:** Implement the pure API, raw canonical path checks and bounded
  decoding/encoding. Test exact independent CBOR bytes and refusal atomicity.
- **Files:** new `crates/qv-store/src/receipts.rs`, src/lib.rs.
- **Done when:** changed/duplicate/malformed/oversized data rejects without
  mutation; same delivery at capacity succeeds; Debug is redacted.
- **Verify:** `cargo test --locked -p qv-store receipts`.

### Step 3 — Sealing and bounded storage

- [x] **Do:** Enable LocalState AEAD; implement internal receipt sealing/opening
  and shape-checked singleton reads; bump volatile schema/header.
- **Files:** qv-crypto/src/keys.rs; new qv-store/src/receipt_store.rs;
  qv-store/src/{schema,header,lib}.rs and existing schema tests.
- **Done when:** malformed/tampered/foreign-replica or generation blobs fail;
  no untrusted SQL blob is allocated beyond the envelope cap.
- **Verify:** `cargo test --locked -p qv-crypto keys`;
  `cargo test --locked -p qv-store receipt_store`;
  `cargo test --locked -p qv-store schema`.

### Step 4 — Head and lifecycle integration

- [x] **Do:** Add mandatory head digest, initialize empty receipts in creation,
  restore and rotation; authenticate on unlock and recheck before writes.
  Preserve exact sealed bytes through ordinary commits.
- **Files:** qv-store/src/{head,vault,write,restore,rotation}.rs;
  qv-core/src/setup.rs and qv-cli/tests/init_info.rs (expected development-schema
  values in existing tests).
- **Done when:** no production path can omit/reset receipt state except the
  specified new-replica/generation builders; old development files reject.
- **Verify:** `cargo test --locked -p qv-store head`;
  `cargo test --locked -p qv-store receipt`.

### Step 5 — Integration and rejection evidence

- [x] **Do:** Test nonempty receipt fixtures across restart/ordinary writes;
  missing/swapped/oversized/corrupt SQL state; restore/rotation empty reset and
  archives excluding receipts; begin-time mutation rejection. Test fixture
  installation is explicitly not a production incoming-acceptance path.
- **Files:** new qv-store/src/receipt_tests.rs, src/lib.rs; existing lifecycle
  tests only if fixture assertions need the new mandatory head field.
- **Done when:** full existing crash matrices still pass and receipt failures
  never silently clear state or publish a new anchor.
- **Verify:** `cargo test --locked -p qv-store receipt`.

### Step 6 — Parser fuzz coverage

- [x] **Do:** Add bounded plaintext-codec round-trip fuzz target and CI entry;
  check the fuzz lockfile and compile/run a bounded local smoke campaign.
- **Files:** fuzz/Cargo.toml, fuzz/fuzz_targets/archive_receipts.rs, CI workflows (per-push and extended).
- **Done when:** accepted inputs round-trip exactly; malformed bytes reject.
- **Verify:** `cargo fmt --check --manifest-path fuzz/Cargo.toml`;
  `cargo check --locked --manifest-path fuzz/Cargo.toml --bin archive_receipts`.

### Step 7 — Documentation and final gates

- [x] **Do:** Document the storage-only boundary, volatile schema and deferred
  acceptance work; run all gates; leave changes uncommitted.
- **Files:** architecture §3/§7, CHANGELOG, plan/index/roadmap.
- **Done when:** 2.2b1 Implemented, b2/c unticked; no format/status/security claim.
- **Verify:** final gates in Test plan below.

## Test plan

Final: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`
(private Xvfb), `sh scripts/check-matrix.sh`; focused checks above. No dependency
change; the preceding review separately checks deny/vet for 0026's graph change.
0012 rows: Hostile SQLite/CBOR, Hostile files from sync folders and Whole-file rollback
(storage prerequisites only; add exact existing row labels to applicable tests).
Independent development CBOR/AAD fixtures, no final-format vectors. Existing
creation/restore/rotation/write crash matrices cover integration ordering.

## Risks and stop conditions

Reject candidates that invent/drop known state, change immutable object/version
identity, weaken authentication, advance unrelated checkpoints, or lose permanent
tombstones. No operational slot adoption without C's explicit reauthentication.
Stop for a new dependency/unsafe or unresolved security ambiguity. The explicit
owner continuation below overrides the original intermediate B split and its
commit/fresh-review requirement; the complete B implementation still needs its
ordinary fresh-context review before C.

## Documentation

- [x] CHANGELOG — receipt-state foundation and deferred atomic acceptance.
- [x] ARCHITECTURE §3/§7 — local-only state and delivery split.
- [x] Specs — 0004/0005 amendment + Changelogs/index, no status promotions.
- [x] AGENTS — no workflow/layout convention change.
- [x] Plans index/roadmap — b1 only on completion.

## Revisions

- 2026-10-30: Step 4 also updates the existing qv-core setup test's expected
  schema number to the explicitly planned 0x7FFF0003; the same adjustment
  applies to the CLI info test's displayed-format assertion. No core/CLI
  behavior changes beyond the planned new development format.

## Execution log

- 2026-10-30: Planned while the fresh-context 0026 review's full suite finishes;
  no production code or normative amendment yet. Receipt storage/lifecycle and
  atomic acceptance together require more than the roadmap's 8–10 steps, so
  split b before implementation. Spec/layout authority comes from the explicit
  owner delegation preserved in 0026; no new owner decision is inferred.

- 2026-10-30: 0026 review Approved, all gates passed. Approved under the
  explicit owner delegation recorded in 0026; standing approval, roadmap 0002
  covers the session-size split. Receipt normative amendments precede code.
  Step 1 complete; implementation started.

- 2026-10-30: First full implementation gate run stopped at the CLI info
  test's old-format display expectation. Updated that expectation for the
  planned schema bump (architect revision above); no assertion removed or
  weakened. Rerunning affected checks and the full suite.

- 2026-10-30: Steps 2–6 complete. Protected paths and canonical receipt sets,
  complete-envelope digest/replica-generation AEAD, bounded singleton reads,
  mandatory head binding and volatile schema 3 are implemented. Creation,
  new-path restore and rotation initialize empty receipts; ordinary commits
  preserve exact bytes and recheck them before starting a mutation. No public
  incoming publication/receipt-commit API was introduced.
- 2026-10-30: Six receipt tests pass, including the maximal 4096×4096-byte
  plaintext, identical redelivery at capacity, unchanged-state refusals,
  authenticated malformed plaintext, digest/AEAD/replica/generation failures,
  missing/oversized/invalid-ID SQL state, restart/ordinary write preservation,
  new-path restore and rotation resets. Independent CBOR and AAD vectors pass.
  Focused crypto keys, schema and head suites also pass after updating the
  planned schema/head fixtures. Early head tests correctly rejected the old
  fixtures until their mandatory receipt field/version values were updated.
- 2026-10-30: Fuzz target added to per-push and weekly CI. Locked fuzz build and
  format checks pass; a local stable, uninstrumented libFuzzer smoke run passed
  10,000 inputs (no coverage instrumentation or ASan; not a release campaign).
  No dependency/lockfile change, unsafe or new cryptographic primitive.
  Final SPDX/matrix/fmt/Clippy pass; complete locked workspace suite rerunning
  after the CLI info fixture correction. Logs: /tmp/qv27-review/.

- 2026-10-30: Step 7 complete. Final SPDX, matrix, fmt, Clippy and locked
  workspace tests pass: **669 passed, 0 failed, 2 pre-existing ignored** with
  private Xvfb. This includes existing creation, mutation, restore and full
  rotation/restart crash matrices, plus the six new receipt tests. Focused
  checks: crypto keys 8, schema 8, head 19, receipts 6, all passed. Fuzz locked
  compilation/format and 10,000-input uninstrumented smoke pass. Final suite
  log is /tmp/qv27-review/final-tests-rerun.log; prior failed fixture run is
  retained separately. No dependency inputs changed; the review's independent
  deny/vet results cover the unchanged dependency graph.
- 2026-10-30: Architecture, spec Changelogs/index, repository changelog and
  roadmap/index updated. Only 2.2b1 is complete. Found, not fixed: 0026's
  covered-dominated permanent-tombstone representation remains fail closed;
  source normalization/no-symlink traversal, actual atomic incoming acceptance
  and receipt recording are 2.2b2; core/CLI resolution/export are 2.2c.
  No incoming state was published and no format freeze or release claimed.
  Preserve owner commit and fresh-context review before b2. All changes remain
  uncommitted; no commit, push or branch. Documentation-only final status/log
  edits do not alter tested Rust/dependency inputs; SPDX/diff checks rerun.


## Owner-directed continuation — complete both B parts (2026-10-30)

The owner explicitly said “Do both Bs already.” This supersedes the b1/b2
session split, intermediate commit/review requirement and earlier out-of-scope
clauses for acceptance, path handling and tombstone representation. Continue
on the owner's staged b1 tree without committing, branching or restaging it.
Steps 1–7 above remain the completed historical receipt-storage work. This
continuation completes all of roadmap 2.2b in this session; 2.2c stays separate.
The original 0026 owner delegation covers exact storage amendments/design.
No unresolved owner decisions, dependency or unsafe are needed.

### Continuation design

- `VerifiedIncoming::open` captures and bounds absolute normalized raw path
  bytes, opens from root using pinned directory descriptors and NOFOLLOW at
  every component (NONBLOCK for final leaf), then copies the descriptor as
  before. It owns a protected filename used for receipts; callers cannot supply
  an unrelated receipt name. Relative paths use a captured current directory;
  `.`/repeated separators collapse and `..` clamps at root. Bound raw input,
  cwd and normalized result to 4096 bytes before allocating/growing.
- Define store `IncomingSource { Local, Incoming }`, reexport as sync `Source`.
  Store exposes `UnlockedVault::accept_incoming(incoming, build, cancelled)
  returning bool (new local acceptance vs identical redelivery). `build` takes
  both manifests and a role-bound reader callback with that source enum and
  returns candidate Manifest metadata. Sync `accept_archive(vault, incoming,
  cancelled)` invokes its existing merge and this API. Frontends still use core;
  no CLI/core command is introduced in this B continuation.
- Start existing Write after pending-anchor retry. Read/authenticate receipts
  in the transaction and remember only the capability's own normalized name
  and stable-copy digest. Identical redelivery rolls back the empty transaction
  and succeeds without a sequence/counter advance. Scope must match first.
- Build through authenticated transaction-local reads. Independently validate
  candidate projection: exact union of record IDs; joined floors; immutable
  reference collisions; unique version ownership; equal-clock/content/kind
  checks; local-preferred envelopes for duplicate logical versions; candidate
  roles/references come only from those two inputs. Every known version must
  remain or be dominated and floor-covered, with permanent tombstones always
  retained. Existing manifest validation ensures maximal/concurrent heads and
  exact unique references. Reject a callback dropping/substituting/inventing
  state; no arbitrary Manifest becomes a write authorization.
- Stage only missing incoming encrypted objects. Recheck complete envelopes,
  hashes, role-bound AEAD, kinds, attachment chunk lists and full chunk length/
  content hash before candidate installation. Existing rows with matching IDs
  must have identical profile, nonce and ciphertext, including unreferenced
  rows. Preserve ciphertext and writer counters. Keep the working operational
  password slot; incoming slot versions/conflicts are metadata only until C's
  explicit selected-slot reauthentication.
- Write carries an optional sealed receipt envelope and incoming flag. Commit
  uses the same retention/sealing/head/SQL commit/anchor path. Receipt envelope
  update and head digest are in this one transaction, with ReceiptsWritten
  crash point. Incoming SQL staging errors poison/drop the whole write.
  Cancellation before COMMIT rolls back; after durability report actual state
  and leave pending anchor for retry. No separate acceptance commit machinery.
- Permanent tombstones get explicit authenticated manifest-role markers:
  `[version_id, clock, object_id, true]`, mutually exclusive with the attachment
  chunk-array fourth field. Ordinary roles stay three fields. Set marker iff
  decrypted deletion is Final; check at every role read and on archive input.
  Allow floor-covered dominated history only for marked tombstones. Authenticate
  those retained tombstone objects on unlock. Bump volatile manifest format to
  0x7FFF0002, retain combined-phase schema/header 0x7FFF0003. No migration.
  Merge keeps every tombstone; retention/purge/finalize never discard old ones,
  even after later causal edits, and rotation preserves markers. Amend 0004
  encoding/verification and 0007 preservation wording before code.
- Mandatory pre-import recovery snapshots remain at the core operation boundary
  in C, as already scoped in the roadmap; this is the storage-level primitive.

### Step 8 — Contracts, combined roadmap and tombstone roles

- [x] **Do:** Record owner direction, normative role marker/retention rules;
  implement marker codec, authenticated reads and preservation through
  merge/history/purge/finalize/rotation. Update development fixtures faithfully.
- **Files:** this plan/index/roadmap; specs 0004/0007 + Changelogs/index;
  store manifest/validation/vault/archive_verify/write/lib; sync lib/tests;
  qv-model/src/merge.rs (floor helper must retain permanent tombstones too);
  qv-core/src/history.rs (exclude tombstone metadata from payload-history views
  rather than failing the whole listing on a valid newly representable state).
- **Done when:** dominated covered tombstones can be retained, false markers
  reject, all deletion knowledge survives ordinary cleanup and export/restore.
- **Verify:** focused store manifest/history tests and `cargo test --locked -p qv-sync`.

### Step 9 — Capability-bound safe paths

- [x] **Do:** Protected normalization and descriptor-based source traversal;
  retain normalized name inside the stable verified capability.
- **Files:** store incoming.rs and new incoming_path.rs, lib.rs.
- **Done when:** aliases normalize to the same name; no ancestor/leaf symlink
  or FIFO can redirect/hang input, relative/non-UTF8/bounded paths work.
- **Verify:** `cargo test --locked -p qv-store incoming`.

### Step 10 — Atomic candidate/receipt acceptance

- [x] **Do:** Implement callback-driven store acceptance with independent
  conservative projection and object/chunk validation, same Write commit;
  add sync orchestration. Never adopt operational slots or reserve counters.
- **Files:** new store acceptance.rs; write/crash/lib; sync lib.rs.
- **Done when:** valid input is one durable local commit followed by anchor,
  changed filenames reject after restart, identical retries are idempotent,
  invalid candidates/sources/cancellation leave the prior accepted state.
- **Verify:** store acceptance tests and `cargo test --locked -p qv-sync`.

### Step 11 — End-to-end and crash evidence

- [x] **Do:** Real encrypted archive/store acceptance, source-path attacks,
  repeated/permuted delivery, deletion/edit conflicts, old suppressed history,
  tombstones across purge/restore/rotation, attachments and slots. Exercise
  staging/receipt/manifest/head/prune/commit/anchor crashes and retries, plus
  malicious candidate builders, foreign/corrupted sources, cancellation and
  bounds; preserve pending anchor semantics.
- **Files:** new store acceptance_tests.rs, incoming_path tests; sync tests;
  existing manifest/vector fixture tests only as needed for explicit markers.
- **Done when:** receipts and data are always both absent or both committed;
  restart advances at most one anchor step; no counters/encryption rewritten.
- **Verify:** focused suites while editing; all required final gates in Step 12.

### Step 12 — Complete B documentation and gates

- [x] **Do:** Update architecture/changelog/spec index/roadmap and execution
  log for completed 2.2b; run SPDX/fmt/Clippy/locked full tests and matrix.
  Run fuzz format/build for affected existing manifest/vault/receipt targets.
- **Files:** this plan/index/roadmap, architecture, changelog, relevant specs.
- **Done when:** both B parts are implemented with all gates passing; only C
  remains. Leave staged/unstaged changes for owner; no independent-review claim.
- **Verify:** `sh scripts/check-spdx.sh`, `sh scripts/check-matrix.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked` (private Xvfb), fuzz locked check/format. No dependency
  changes: deny/vet are unchanged-input evidence from this session's earlier B work.

- 2026-10-30: Owner-directed continuation implemented steps 8–11. B is one
  combined phase again, with no intermediate commit/review request. Source
  names are protected and capability-owned; all source components open through
  pinned no-follow descriptors. Store acceptance starts the existing Write,
  verifies conservative candidate provenance, complete immutable overlapping
  envelopes, role AEAD and complete retained attachments, then stages receipts
  in the same head/manifest/objects commit. Operational slots, counters and
  remote checkpoints are not adopted/advanced from incoming data. Identical
  receipts finish pending anchors and return without a new commit.
- 2026-10-30: Permanent tombstone role markers (manifest format 0x7FFF0002)
  remove the former covered-history limitation. Merge, floor splitting,
  retention, purge, later final deletion, archive restore and rotation retain
  them. Core payload-history listing skips these non-restorable metadata roles
  instead of failing on valid restored state; a regression test passes. The
  worst-case manifest fixture now includes the extra byte for every marker.
- 2026-10-30: Focused evidence passed: 8 store acceptance tests (including
  nine crash points through commit/anchor, last-precommit cancellation and
  receipt capacity); 11 sync tests including six actual archive acceptance
  orders with concurrent deletion/edit, attachments, restarts and duplicate
  delivery; 15 focused manifest tests, plus covered-tombstone lifecycle and
  core payload-history regression. The source inputs remain protected/bounded;
  no new dependency/unsafe or cryptographic primitive was added.
- 2026-10-30: First full continuation run was intentionally interrupted during
  store tests to tighten the full nonce/profile/ciphertext overlap check, even
  for subsequently suppressed versions. Final SPDX/matrix/fmt/Clippy pass on
  that tree; the complete locked workspace suite is rerunning. Retain separate
  logs b-final-tests.log (interrupted) and b-final-tests-complete.log (final)
  under /tmp/qv27-review. Final fuzz compile/format checks are also running.

- 2026-10-30: The final continuation suite reached store with 210 passing
  tests and one stale fixture failure: history_retention_floor_purge_and_old_delivery
  represented prunable old payload as Final tombstones. Updated it to merge
  the actual captured original payload with the actual live head, retaining
  its original suppression assertions. Permanent-tombstone retention is checked
  separately by model/store/sync lifecycle tests. No production change or
  assertion weakening. Rerun affected checks and the complete suite.

- 2026-10-30: Step 12 complete: **both B parts are implemented as roadmap
  2.2b**. Final required gates pass: SPDX, matrix, fmt, Clippy and full locked
  workspace tests, **679 passed, 0 failed, 2 pre-existing ignored**, private
  Xvfb. The original suppression test passes with its actual old payload;
  all eight acceptance tests, all eleven sync tests and the new core history
  regression pass in the final complete suite. Final log:
  /tmp/qv27-review/b-handoff-tests.log (zero exit status). Affected fuzz target
  locked compile/format checks pass on the final source tree. No dependency
  inputs changed; no new deny/vet exception or dependency policy change.
- 2026-10-30: Updated architecture, normative spec Changelogs/index, repository
  changelog and roadmap/index for completed B. The former dominated/covered
  permanent-tombstone limitation is resolved. Core/CLI exchange commands,
  mandatory pre-import recovery snapshot policy at the core boundary, conflict
  resolution, selected-slot reauthentication and export remain C as originally
  scoped. No B work is deferred to another B subphase. No compatibility,
  independent-review or release claim. All changes remain uncommitted;
  the owner's existing staged index was preserved, with continuation edits
  left unstaged. No commit, push or branch. Documentation-only final status
  edits do not change tested Rust inputs; SPDX/diff checks rerun after them.

- 2026-10-31: Fresh-context review Approved (REVIEW.md). Independent SPDX, matrix, fmt, Clippy and locked full suite pass: 679 passed, 0 failed, 2 ignored; affected fuzz format/compilation passes. No code fixes or escalations. Logs /tmp/qv-next-review/.
