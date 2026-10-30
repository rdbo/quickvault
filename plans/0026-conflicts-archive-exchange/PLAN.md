# Plan 0026 — Verified archive input and merge candidates (roadmap 2.2a)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-30 | 2026-10-30 | 0005 §1–2, §4; 0004 §3–4, §6; 0007 §1–2; 0008 §1–3, §5; 0012 §1 |

## Intent

Build the authenticated input and shared candidate-merge foundation for archive
exchange. Do not publish incoming state until the later atomic-acceptance phase.

## Scope

**In scope:** private bounded stable copies of hostile archives; fully verified
record/object access; qv-sync candidate construction preserving causal versions,
floors and encrypted object references; validation and adversarial tests.

**Out of scope:** durable acceptance/filename receipts (2.2b), core/CLI conflict
resolution and archive export (2.2c), LAN/server transports, cross-generation
imports, format compatibility and release claims.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Causal whole-record merge and conflicts | 0005 §1–2 | Draft | Owner explicitly delegated implementation/design on 2026-10-30 |
| Private authenticated same-generation archives | 0005 §4; 0004 §6 | Draft / Accepted | D5 plus owner approval |
| Complete roles, bounded input and manifests | 0004 §3–4 | Accepted | Reuse existing role-verifying archive reader |
| Monotonic floors, permanent tombstones | 0007 §1–2 | Accepted | No acceptance or new retention policy in this phase |
| Protected memory/private files | 0008 §1–3, §5 | Draft | D5 and owner approval |

**Spec changes required:** none for 2.2a; it adds no durable format or user
command. The approved later receipt and CLI amendments remain prerequisites
of 2.2b/2.2c and must precede their code.

## Decisions needed

None for 2.2a. The owner said “Just do whatever you feel is right and go ahead”
on 2026-10-30, approving the original D1–D3 recommendations and delegating
remaining details. That covers necessary store/workspace changes and Draft
sections, without further permission requests for routine design completion.

For subsequent phases the approved directions are:
- Persist complete-archive SHA-256 receipts keyed by lexically normalized
  absolute raw-OS-byte paths per local replica/generation; 4096-byte paths,
  4096 receipts, no silent eviction, no symlink traversal. Identical redelivery
  succeeds, changed bytes fail integrity after restart. Seal local state,
  bind its digest into the authenticated head, commit with acceptance, exclude
  it from archives and reset on restore/rotation. Specify exact layout/AEAD
  transcript/digest encoding in 2.2b's normative amendment before code.
- Conflict inspection is masked by default with explicit reveal; select a
  complete active version and create one new edit joining all known heads.
  Support explicit record-ID addressing for non-entry conflicts, safe per-kind
  views, and selected-slot reauthentication before operational slot adoption.
  Specify exact CLI/JSON contracts in 2.2c before code.
- Merge preserves conflicts and reports local acceptance separately. Export
  is immutable/no-replace, slotless by default; self-contained export warns
  about offline guessing and requires explicit consent. Automatic snapshots
  remain slotless. Specify exact contracts in 2.2c before code.

## Design

**Components touched:** qv-store owns files, archive authentication and manifest
validation. qv-sync depends on crypto/model/store, never core, and computes a
candidate without writes. qv-model's maximal-version algorithm is reused.
Frontends still reach vaults only through core; this phase adds no frontend API.

**Interfaces:**

```rust
// qv-store, Linux/Android: an unlinked private encrypted file and authenticated
// manifest/frame index. Constructed only by bounded copying + full validation.
pub struct VerifiedIncoming { /* private */ }
impl VerifiedIncoming {
    pub fn open(source: &Path, private_dir: &Path, scope: ArchiveScope,
                vk: &VaultKey, cancelled: &dyn Fn() -> bool) -> Result<Self, StoreError>;
    pub fn manifest(&self) -> &Manifest;
    pub fn header(&self) -> &ArchiveHeader;
    pub fn digest(&self) -> &[u8; 32]; // whole copied archive, for later receipt
    pub fn read_version(&mut self, vk: &VaultKey, record: RecordId,
                        version: VersionId) -> Result<RecordVersion, StoreError>;
    pub fn read_object(&mut self, object: ObjectId) -> Result<ObjectEnvelope, StoreError>;
}
// qv-store validated assembly; inputs are untrusted until final validation.
// RecordEntry::from_parts(record_id: RecordId, heads: Vec<VersionRef>,
//     history: Vec<VersionRef>, floor: HistoryFloor) -> Result<RecordEntry, StoreError>
// Manifest::candidate(&self, records: Vec<RecordEntry>, references: Vec<ObjectRef>)
//     -> Result<Manifest, StoreError>
// Manifest::same_configuration(&self, other: &Manifest) -> bool
// Assembly validates record-local invariants and all manifest budgets,
// role uniqueness, control IDs and reference completeness. Configuration
// comparison alone authenticates neither input.

// qv-sync: caller supplies role-bound authenticated record reads; the merge
// validates binding/kinds again and holds at most two decoded payloads at once.
pub enum Source { Local, Incoming }
pub struct Candidate { /* validated manifest, object source mapping */ }
pub fn merge(
    local: &Manifest, incoming: &Manifest,
    read: &mut impl FnMut(Source, RecordId, VersionId) -> Result<RecordVersion, StoreError>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Candidate, StoreError>;
```

Copying: open the source with NOFOLLOW/NONBLOCK/CLOEXEC, require a regular file,
allow exchange-file permissions, bound metadata size and streaming reads by
`MAX_DB_BYTES` before writing. Require a private destination directory, create
0600/O_EXCL temporary storage using existing helpers and unlink immediately.
Only ciphertext is staged. Source mutation during the copy either yields a
complete authentic archive or is rejected; the returned capability owns stable
bytes independently of the source. Full header/manifest/role/chunk verification
and exact EOF precede construction. Subsequent frame reads recheck complete
frame commitments and ciphertext hashes, plus AEAD for decoded record access.
Store no VK in the capability; callers provide it per read. Redact Debug and
errors; hold streaming buffers in SecretArray; file descriptors close on drop.

Merge: verify matching control IDs/config digest; reject any overlapping
object ID whose reference/profile/length/hash differs, including objects later
suppressed. Union every known active/history version per record. Role-bound
reads validate version ID, clock, kind and attachment chunk list; compare full
canonical encodings for duplicate version IDs. Keep the local envelope when
the same logical version has distinct envelopes. Reject equal clocks with
different IDs and kind changes. Use model merge for maximal heads, then join
floors and suppress only dominated history. Never suppress a maximal head.
Final tombstones survive indefinitely; no timestamps, counters, IDs or new
encryption are created. Referenced chunks follow their complete selected
attachment versions. Every object reference in the resulting manifest maps to
a local or incoming source; the final manifest is validated before return.

Bound work before growing collections: sum of input record counts <= 2 ×
MAX_RECORDS, roles/references <= 2 × MAX_OBJECTS, clock components <= 2 ×
MAX_CLOCK_COMPONENTS (each manifest is already independently bounded). Apply
ordinary manifest caps to output before cloning/appending entries/references.
At most two decoded record payloads/canonical encodings are held for identity
comparison, never the whole vault's plaintext. Duplicate canonical encodings are compared through confidential SHA-256 digests
and constant-time equality. If a permanent tombstone would become dominated
and floor-covered, reject the candidate: the existing manifest cannot encode
such a retained role. This is an explicit fail-closed limitation, not authority
to discard final-deletion knowledge or to publish an incomplete state.
No arbitrary caller-supplied
manifest is a verified data capability; Candidate is metadata only, not a write
authorization. 2.2b must revalidate sources/candidate against its transaction.

**Data and control flow:** this phase never changes accepted DB state, writer
reservations, manifests, anchors, operational slots, or receipt state. It
returns a candidate for subsequent atomic integration. This phase does not
implement filename-reuse detection or report exchange completion.

**Errors:** reuse fixed StoreError: Integrity for identity/role/content mismatch,
LimitExceeded for bounds, Io for cancellation; preserve other read errors.

**Dependencies:** add only qv-sync and existing workspace path dependencies;
no new external crate, cryptographic label/primitive, unsafe or storage format.
Run cargo deny/vet for the changed graph.

## Steps

### Step 1 — Record delegated decisions and split

- [x] **Do:** Revise this plan and roadmap before code, separating foundation,
  atomic acceptance and core/CLI flows. Record owner approval and deferred
  amendments; do not change normative specs just for implementation APIs.
- **Files:** this plan, roadmap, plans index, CHANGELOG.
- **Done when:** the phase boundary and remaining requirements are explicit.
- **Verify:** `git diff --check`; same-session plan check.

### Step 2 — Private verified incoming archive

- [x] **Do:** Implement the capability and bounded encrypted-object/role access
  using existing reader/frame verification. Cover source replacement, symlink,
  FIFO, truncation, foreign scope, cancellation and cleanup.
- **Files:** new `crates/qv-store/src/incoming.rs`, `src/lib.rs`, existing
  archive helpers (only visibility or bounded accessor changes if necessary).
- **Done when:** no unchecked archive can construct a capability; no private
  temporary filename remains on success/failure; source edits cannot affect it.
- **Verify:** `cargo test --locked -p qv-store incoming`.

### Step 3 — Validated manifest assembly

- [x] **Do:** Add RecordEntry::from_parts and Manifest::candidate for validated
  merge output, keeping existing codecs and invariant checks authoritative.
- **Files:** `crates/qv-store/src/manifest.rs`.
- **Done when:** malformed heads/history/floors/references reject; output obeys
  all existing budgets and retains template config/control identity.
- **Verify:** `cargo test --locked -p qv-store manifest`.

### Step 4 — Shared candidate merge

- [x] **Do:** Create qv-sync with the typed algorithm above and bounded output
  source mappings; no writes or frontend dependencies.
- **Files:** `crates/qv-sync/{Cargo.toml,src/lib.rs}`, workspace Cargo.toml,
  Cargo.lock.
- **Done when:** concurrent heads survive, old covered history is suppressed,
  collisions reject, complete ciphertext references are preserved.
- **Verify:** `cargo test --locked -p qv-sync`.

### Step 5 — Adversarial/convergence evidence

- [x] **Do:** Exercise all permutations/regroupings/duplicates with immutable
  input manifests, floors, final tombstones/concurrent deletion, unknown
  fields, cross-object identity reuse and cancellation/bounds. Add a real
  authenticated archive + local-store merge test, not only metadata fixtures.
- **Files:** qv-sync tests; qv-store incoming tests, existing archive fuzz target
  if its new entry point needs additional parser coverage.
- **Done when:** 0012 tagged tests cover the foundation without claiming
  atomic acceptance, durable receipts or user-level exchange are complete.
- **Verify:** focused tests above; `sh scripts/check-matrix.sh`.

### Step 6 — Documentation and gates

- [x] **Do:** Document qv-sync and the candidate-only boundary; record all gates
  and remaining 2.2b/2.2c work. Leave changes uncommitted.
- **Files:** this plan, plans index/roadmap, ARCHITECTURE §3/§7, CHANGELOG.
- **Done when:** 2.2a is Implemented; 2.2b/2.2c stay unticked.
- **Verify:** all commands below on final code tree, logs retained in /tmp.

## Test plan

`sh scripts/check-spdx.sh`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`,
`cargo deny check`, `cargo vet --locked`. Private Xvfb for CLI clipboard tests.
`sh scripts/check-matrix.sh` preserves existing coverage.

0012 exact row tags: `Deleted-entry resurrection`, `Order-dependent merges`,
`Hostile files from sync folders`. Candidate-only tests supplement current
coverage; they do not establish storage acceptance/durability or security.
Independent deterministic development fixtures, no final format vectors.

## Risks and stop conditions

No acceptance API until 2.2b authenticates source capabilities inside the one
transaction/anchor path; no unchecked Candidate can bypass this. Stop on causal
information loss, unbounded plaintext accumulation, a new dependency/unsafe or
an unresolved security ambiguity. Preserve the commit and fresh-context review
boundary before 2.2b, as required by the roadmap split rule.

## Documentation

- [x] CHANGELOG — foundation delivered and remaining work.
- [x] ARCHITECTURE — §3 qv-sync/capability boundary; §7 split delivery.
- [x] Specs — no normative changes in this subphase; no status promotions.
- [x] AGENTS — no convention/layout change.
- [x] Plans index and roadmap — 2.2a only completed.

## Revisions

- 2026-10-30: Owner approved original D1–D3 and delegated further choices.
  Before code, split 2.2 into a/b/c: the original nine steps hid separate
  schema/head/receipt/generation-transition and keyslot-reauthentication work.
  This plan now covers 2.2a only. Later parts get fresh plans and reviews.

## Execution log

- 2026-10-30: Initial proposal passed SPDX/fmt/Clippy and full tests (649 pass,
  2 ignored) after supplying private Xvfb; logs /tmp/qv26-plan-gates. No code.
- 2026-10-30: Owner: “Just do whatever you feel is right and go ahead.”
  Approval and delegation recorded; no additional permission needed for the
  identified choices. Plan revised before code under the roadmap split rule.

- 2026-10-30: Steps 1–5 complete. VerifiedIncoming uses the existing full
  archive reader, immediate pre-copy unlink, protected bounded streaming,
  complete-frame/AEAD rechecks and no SQLite exchange opening. A crash in the
  create/unlink gap can leave an empty file; no copy data is written first.
  Three incoming tests pass, including FIFO/symlink/oversize/cancellation,
  foreign/truncated/modified input, source replacement, private-descriptor
  mutation and unchanged local DB bytes. Manifest assembly focused suite:
  15 passed. Shared qv-sync suite: 10 passed, including all six permutations
  and both regroupings, duplicate/reencrypted identity, floors/tombstones,
  complete attachment references, bound/role/identity collisions and a real
  encrypted archive/store test. Existing parser fuzzing is reused; no new
  parser/format, so no new fuzz target or compile requirement was introduced.
- 2026-10-30: Same-context design/implementation inspection only. Found, not
  fixed: the current manifest cannot retain a dominated final tombstone once
  covered by a history floor. Candidate construction fails Integrity rather
  than silently forgetting it; a regression test pins this conservative
  limitation. 2.2b must revisit its representation/acceptance implications
  before publication. No accepted state is changed by this phase.
- 2026-10-30: Final SPDX, fmt, Clippy, matrix, deny and vet checks pass; full
  workspace tests running. Installed CI-pinned cargo-deny 0.20.2 and cargo-vet
  0.10.3 under /tmp/qv26-tools. Vet needed the CARGO executable environment;
  it reports 27 fully audited, 6 partially audited, 79 exempted. Cargo home is
  read-only, so deny used /tmp/qv26-impl-logs/deny-cache.toml, identical to the
  repo policy except db-path=/tmp/qv26-advisory-dbs; all four checks pass.
  No policy was weakened. Full logs: /tmp/qv26-impl-logs/.
- 2026-10-30: Step 6 complete. Final full locked workspace suite with private
  Xvfb passes: **663 passed, 0 failed, 2 pre-existing ignored**, including 14
  new tests (3 incoming, 1 manifest assembly, 10 sync). All standard gates plus
  matrix and deny/vet pass on final code/dependency inputs. Documentation-only
  status/log updates afterward do not change those Rust/dependency inputs;
  SPDX and diff checks rerun after handoff edits. Plan Implemented, 2.2a ticked.
  Architecture §3/§7 and changelog describe the candidate-only boundary. No
  normative format/status change. Next fresh session reviews this implementation
  before planning 2.2b; the owner must commit first. Nothing committed/pushed/
  branched. No independent review or security-validation claim.

- 2026-10-30: Fresh-context review Approved; see REVIEW.md. Independent gates
  pass (663 passed, 0 failed, 2 existing ignored), including private Xvfb,
  matrix, deny and vet. No code fixes or blocking findings.
