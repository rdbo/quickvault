# Plan 0028 — Conflict resolution and archive exchange (roadmap 2.2c)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-31 | 2026-10-31 | 0004 §4–6; 0005 §2, §4–5.4; 0007 §3; 0008 §1–3, §5; 0011 §3–6 |

## Intent

Expose verified archive exchange and deliberate complete-version resolution
through core and the CLI. Preserve conflicts and the working password slot
until explicit selection/proof, require a recovery copy before import, and
make self-contained backup export an explicit, warned choice.

## Scope

**In scope:** `merge <archive> [--allow-over-budget]`, `snapshot export
<directory> [--self-contained]`, all-kind `conflicts` inspection and `resolve
--version`, selected-slot reauthentication, complete protected/unknown values,
bounded attachment restaging, snapshot recovery with keyslot conflicts,
view-budget preflight, cancellation and durable-outcome reporting.

**Out of scope:** standalone phrase/password archive import, LAN/server
transports, production GUI/platform adapters, compatibility and release claims.
The original archive steps remain completed history; the owner-directed
continuation below completes the resolution and recovery work in this same plan.

## Spec basis

| Behaviour | Spec | Status | Authority |
|-----------|------|--------|-----------|
| Complete causal import and receipts | 0005 §2, §4, §5.4 | Draft | D5; explicit 0026 delegation |
| Bounded authenticated archives and publication | 0004 §4–6 | Accepted | Existing reader/writer and transaction |
| Mandatory recovery copy and budgets | 0007 §3 | Accepted | Before explicit import, serialized with acceptance |
| Protected buffers and lock cancellation | 0008 §1–3, §5 | Draft | D5 and 0026 delegation |
| Exact CLI and backup-consent contracts | 0011 §3–6 | Accepted | Exact amendments delegated in 0026 |

**Spec changes required:** first amend 0011 with exact arguments, confirmation,
outputs and exit semantics; specify optional archive-header key 10 as a bounded
bstr containing the complete canonical local `Keyslot` descriptor in 0004 §6.2.
Include it in the existing header MAC, and define authenticated working-source
slot fallback for ambiguous local snapshots. No new profile, label or format version.

## Decisions needed

None. Plan 0026 records approval of the recommended CLI behavior and delegation
of remaining details, including later exact amendments. That is prior explicit
authorization for these amendments; no new permission request is inferred from
the roadmap's ordinary spec-amendment stop rule. The 0027 review passed; the
owner explicitly authorized the complete C continuation on the staged tree.

## Design

**Components:** qv-store owns bytes and safe publication; qv-sync computes the
candidate; qv-core authorizes import/export and owns views/snapshots; qv-cli calls
only core. Add the existing workspace qv-sync dependency to core, without a new
external crate. No unsafe.

**Interfaces:**

```rust
pub struct ArchiveMergeReport {
    pub accepted: bool, // one new durable commit, false for identical redelivery
    pub conflicts: usize, // every kind, including control records
    pub completion_error: Option<CoreError>, // only after durable acceptance
}
pub struct ArchiveExportReport {
    pub archive_id: String,
    pub self_contained: bool,
}
impl Session {
    pub fn merge_archive(&self, source: &Path, allow_over_budget: bool,
        cancel: Option<&CancelToken>) -> Result<ArchiveMergeReport, CoreError>;
    pub fn export_archive(&self, directory: &Path, self_contained: bool,
        cancel: Option<&CancelToken>) -> Result<ArchiveExportReport, CoreError>;
}
```

Store retains the existing slotless `write_archive`/`SnapshotDir::publish`
contracts. Add explicitly named export variants accepting `self_contained`,
sharing the writer and verified temp → fsync → no-replace publish → dir fsync
machinery. The optional slot is the exact working local descriptor, independently
validated when decoding the bounded header, and MAC-covered. Never choose an
incoming or conflicted manifest slot for export. SnapshotDir's snapshot-header
reader continues to reject slot-bearing files, including policy/inventory paths.
General authenticated archive input may read either form using its existing VK.
New-path restore uses the optional authenticated slot if present; otherwise its
existing single-keyslot-head rule applies. Restore preserves the full manifest.

Core import holds the session mutex for source authentication, a mandatory pinned
recovery snapshot, candidate preflight and acceptance. Factor snapshot start/end
into crate-private helpers operating on the already-held Open state; reuse them
in the existing public wrappers. Do not take a snapshot outside this serialized
operation. Without a usable snapshot policy fail before acceptance; explicit
`--allow-over-budget` is the only CLI permission to bypass ordinary budgets.
Use that private snapshot directory for VerifiedIncoming's unlinked stable copy.
Reject read-only recovery sessions before attempting import.

Inside the store's candidate callback, use qv-sync::merge, then build a proposed
Index from its role-bound source reader and manifest. Enforce MAX_VIEW_BYTES and
normal group projection before publication. Add an Index helper sharing the
existing build logic, deriving/checking kinds from complete authenticated heads.
No persistent plaintext password index. Save the proposed index only after
successful preflight. If local_seq advances, install it even when anchor update
fails; if that invariant cannot be established, poison/lock the session. Identical
redelivery keeps the existing index. Precommit cancellation returns Cancelled;
after commit report the durable acceptance and any completion error separately.
On success reclassify/release the recovery copy; on failure leave recovery data
available and release its in-memory pin through the existing handle cleanup.

Export is serialized through the session and checks lock/token cancellation
through verification/publication. It creates a private destination directory if
absent, rejects unsafe permissions/symlinks and refuses the configured snapshot
directory as the export destination (0007 §3.1). No replacement or plaintext
file is produced. Publication may already be durable if a later directory-sync
error occurs; report the existing fixed error and never overwrite on retry.

**CLI:** both mutation-style commands reject `--json` before unlock. Merge prints
`local acceptance: committed` or `local acceptance: already accepted`, plus the
current conflict count, without claiming resolution, peer receipt or freshness.
Unresolved conflicts after a successful merge do not turn acceptance into an
error. Postcommit completion failure prints acceptance first, then returns its
normal mapped exit code. Export prints the random archive ID. `--self-contained`
warns that a file holder can guess the master password offline and asks for
confirmation; `--yes` is explicit consent to skip this confirmation, but alone
never adds a slot. No prompt accepts a secret through argv/environment.

**Secrets and bounds:** reuse all input/archive/receipt limits, protected path
and plaintext containers, profile allowlists and existing MAC/AEAD. Slot bytes
are wrapped key material; never print descriptors, salts, commitments or paths
in data-bearing errors. Header key 10 is bounded by the entire 64 KiB header
before allocation and is strictly decoded as Keyslot. No unauthenticated slot
can change operational state. Core report types have redacted Debug.

**Errors:** existing CoreError/StoreError and CLI mappings. Keep preflight errors
before COMMIT; preserve pending-anchor retry and distinguish postcommit errors.

**Dependencies:** existing qv-sync workspace edge only; update Cargo.lock and run
deny/vet. No new package, exception, cryptographic profile or MSRV change.

## Steps

### Step 1 — Contracts and phase sizing

- [x] **Do:** Record the split of the roughly sixteen-step combined C work into
  archive commands (eight steps) and conflict/slot operations (a separate phase).
  Amend 0004/0011 and their Changelogs/index before code.
- **Files:** roadmap, this plan, plan index, specs/0004-local-storage.md,
  specs/0011-cli.md, specs/README.md.
- **Done when:** all new byte/CLI contracts and prior authorization are recorded.
- **Verify:** `git diff --check`; architect conformance check.

### Step 2 — Optional authenticated backup slot

- [x] **Do:** Bounded optional header slot encoding/decoding and MAC coverage;
  explicit export writer mode; preserve default slotless writer. New-path restore
  can retain a header's authenticated working slot without resolving manifest heads.
- **Files:** qv-store/src/{archive,restore}.rs and archive tests.
- **Done when:** header tampering rejects; unknown profiles and oversized/malformed
  descriptors fail; default archives contain no slot.
- **Verify:** `cargo test --locked -p qv-store archive`.

### Step 3 — Immutable export publication

- [x] **Do:** Factor existing publication to share verified-temp/no-replace/fsync
  behavior with explicitly slot-bearing exports; keep snapshot header reads slotless.
- **Files:** qv-store/src/archive.rs and its publication tests.
- **Done when:** both modes reverify persisted bytes, reject unsafe/existing targets,
  and never leave a partial published archive; snapshot policy refuses backup slots.
- **Verify:** `cargo test --locked -p qv-store archive`.

### Step 4 — Serialized core import

- [x] **Do:** Add qv-sync edge, shared Index preflight helper and in-session
  snapshot helpers; implement merge_archive with durable index/outcome handling.
- **Files:** qv-core/Cargo.toml, Cargo.lock, dependent spikes/ui-feasibility/Cargo.lock (internal graph only), qv-core/src/{lib,index,snapshot}.rs,
  new qv-core/src/exchange.rs and tests.
- **Done when:** no accept without the recovery copy; view/lock/cancel failures
  abort; imports preserve conflicts and working slots, retries stay idempotent.
- **Verify:** `cargo test --locked -p qv-core exchange` and snapshot/lock tests.

### Step 5 — Core explicit export

- [x] **Do:** Implement export_archive modes, safe separate destination and
  cancellation; expose only random ID/mode in the report.
- **Files:** qv-core/src/exchange.rs, lib.rs and exchange tests.
- **Done when:** default slotless export round-trips; explicit self-contained
  backup includes only the local working slot; policy directories are refused.
- **Verify:** `cargo test --locked -p qv-core exchange`.

### Step 6 — CLI commands and consent

- [x] **Do:** Register merge/export, preflight JSON, signal cancellation,
  backup warning/confirmation, exact acceptance/conflict/ID output and mapped errors.
- **Files:** qv-cli/src/{cli,cmd/mod,cmd/snapshot}.rs, new cmd/merge.rs,
  new qv-cli/tests/exchange.rs, existing command-tree tests as necessary.
- **Done when:** commands reach core only; refusal precedes unlock/publication;
  `--yes` alone never creates a guessing target.
- **Verify:** `cargo test --locked -p qv-cli --test exchange`.

### Step 7 — End-to-end rejection and race evidence

- [x] **Do:** Test real restored replicas and archives: old payload suppression,
  tombstone/concurrent edit preservation, changed filename after restart,
  mandatory snapshot failure/budget refusal, precommit lock/cancellation and
  postcommit state reporting; slotless/default vs explicit backup consent.
  Use existing session hooks and storage crash coverage rather than a second
  transaction path. Extend hooks only in the affected core exchange operation.
- **Files:** core exchange tests, CLI exchange tests; store archive tests.
- **Done when:** no failed preflight accepts a receipt/head, and every durable
  merge leaves a matching core index or locks the session on an internal failure.
- **Verify:** affected core/store/CLI suites; full gates in Step 8.

### Step 8 — Documentation and final gates

- [x] **Do:** Update architecture §3/§7, changelog and plan/index/roadmap;
  run all required gates and affected fuzz format/build checks. Tick only c1.
- **Files:** ARCHITECTURE.md, CHANGELOG.md, component lib.rs module documentation, plan/index/roadmap.
- **Done when:** archive commands implemented, conflicts/slot resolution clearly
  remain c2, all gates pass, changes uncommitted.
- **Verify:** Test plan below.

## Test plan

Final: `sh scripts/check-spdx.sh`, `sh scripts/check-matrix.sh`,
`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
`cargo test --locked` with private Xvfb, `cargo deny check`, `cargo vet --locked`;
`cargo fmt --check --manifest-path fuzz/Cargo.toml` and locked fuzz compilation
of archive_read/manifest_decode/vault_open/archive_receipts. Keep full logs in /tmp.
0012 §1 rows: Hostile files from sync folders; Deleted-entry resurrection;
Order-dependent merges; Exchange-file password guessing; Snapshot disk growth;
Ambiguous trust boundary (including session lock races).
Independent header slot/MAC fixtures; development bytes only, no format freeze.

## Risks and stop conditions

Stop for unresolved security/spec ambiguity, new dependency/unsafe or a second
commit path. Do not silently resolve keyslots or discard unknown payload fields.
Never reuse a core index that predates a durable incoming acceptance. An export
does not establish global freshness, erase old slots, or validate security.

## Documentation

- [x] CHANGELOG.md — commands, backup consent and remaining c2 work.
- [x] ARCHITECTURE.md §3/§7 — current core/sync orchestration and phase split.
- [x] Specs — 0004/0011 contracts, Changelogs and index; no status promotions.
- [x] AGENTS.md — no convention/layout change.

## Revisions

- 2026-10-31: Dependency review found the isolated feasibility prototype also
  locks qv-core. Include its lockfile's necessary internal qv-sync edge/package
  so the core dependency change does not stale that consumer's lock. Validate
  locked metadata and preserve every external version. This is dependency
  metadata maintenance under 0026's workspace-change authorization, not
  production GUI work or a change to the D13 gate.


## Execution log

- 2026-10-31: Planned during the independent 0027 verification run; no product
  changes yet. The prior explicit 0026 delegation covers exact archive/CLI
  amendments. Implementation is conditional on passing the 0027 review.

- 2026-10-31: 0027 review Approved with all gates passing. Approved under the explicit delegation recorded in 0026; standing approval, roadmap 0002 covers the session-size split. Implementation started; normative amendments precede product code.

- 2026-10-31: Steps 2–6 implemented. Optional exact working-slot bytes are
  header-MAC bound; all default snapshot writers/readers remain slotless. Export
  shares the existing persisted-byte verification/no-replace/fsync path. Core
  holds its mutex across the recovery copy, candidate-index budget checks and
  acceptance; post-durable anchor failure retains a matching index and report.
  Unsupported platform adapters fail closed through core stubs.
- 2026-10-31: Focused store archive suite passed (26 tests), core exchange suite
  passed (6 tests) and actual CLI exchange suite passed (2 tests, including PTY
  refusal). Evidence covers conflicted-slot backup preservation, suppression,
  changed filename after restart, budget/view refusal and lock timing on both
  sides of commit. Tightened optional-slot malformed/profile/header-limit tests
  are being finalized. Initial test-only method-name/encoder-error conversions
  and a local Clippy let-return issue were corrected without changing assertions.
- 2026-10-31: Root dependency graph adds only the existing qv-sync workspace
  edge; no external versions, policies or exemptions changed. CI-pinned
  cargo-deny 0.20.2/cargo-vet 0.10.3 installed under /tmp because absent here.
  Vet passed. Deny needed a writable isolated CARGO_HOME copied from the public
  registry cache (the default cargo home is read-only); advisories/bans/licenses/
  sources then passed. Logs /tmp/qv-next-review/; final gates still pending.

- 2026-10-31: Final source inspection aligned cancellation during recovery-copy
  creation with the import's precommit Cancelled outcome; no acceptance occurs.
  Rerunning affected gates and the complete suite on this final source revision;
  the earlier full run is retained separately, not reused as current evidence.

- 2026-10-31: Step 7/8 complete. Final root gates passed on the final Rust
  source: `sh scripts/check-spdx.sh`, `sh scripts/check-matrix.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked` with private Xvfb: **689 passed, 0 failed, 2 pre-existing
  ignored** (zero exit status, final-tests.log). Affected fuzz format and locked
  compilation of archive_read/manifest_decode/vault_open/archive_receipts pass.
  Deny passes all four categories; vet passes (27 fully audited, 6 partially
  audited, 79 existing exemptions). No dependency-policy/exemption change.
- 2026-10-31: Prototype lock maintenance adds only qv-core → qv-sync and the
  local qv-sync production-dependency record. Compared parsed external package
  records against HEAD: every external record is unchanged. Locked offline
  `cargo metadata --no-deps` passes. Full offline prototype metadata initially
  lacked cached Dioxus registry entries; an automatic targeted lock update also
  rewrote unrelated Windows dependency edges, which were discarded. Retained
  only the internal edge/package. No prototype GUI build/device validation is
  claimed; its external graph/runtime remain outside this phase and D13 stays
  pending. Root Rust/dependency gate inputs are unchanged by this isolated lock
  maintenance and final status/log edits; SPDX/matrix/fmt/diff checks rerun.
- 2026-10-31: Documentation/spec Changelogs/index and roadmap/index completed.
  Only 2.2c1 is complete. Found, not fixed within this slice: conflict inspection,
  explicit complete-version resolution, selected-slot reauthentication and
  slotless new-path restore when keyslot heads conflict remain 2.2c2. Explicit
  self-contained backup restore preserves the working slot and unresolved heads
  (tested). No compatibility, release or independent 0028 review claim. All
  changes remain uncommitted; no commit, push or branch. Logs /tmp/qv-next-review/.


## Owner-directed continuation — finish phase 2.2c (2026-10-31)

The owner explicitly requested “Do 2.2c2 as well” and objected to excessive
splitting. Continue on the staged 2.2c1 tree, without committing, branching or
restaging it. This overrides the artificial c1/c2 commit/fresh-review boundary;
review the complete implementation in the next fresh session. Steps 1–8 above
remain historical completed work. This continuation completes phase 2.2c.

### Continuation design

Authority: 0026's explicit delegation and 0005 §2.3–2.6, 0007 §1–3, 0004 §5–6,
0008 §1–3/§5, 0011 §3–6. No unresolved decisions, new dependency, unsafe,
primitive, crypto profile, on-disk layout or format version.

- Add session-bound `ConflictRecordHandle` (record ID), `ConflictVersionHandle`
  (selected active version plus exact inspected head IDs), all with redacted
  Debug. APIs: `conflict_records()` lists all conflicted kinds; `conflict_matches`
  matches a 6–32 hex record prefix including control/attachment/tombstone records;
  `conflict_versions(record)` returns bounded metadata-only version handles;
  `conflict_version(&handle)` returns one bounded typed masked view. Entry views
  reuse EntryDetail/reveal; group/vault views expose known metadata; attachment
  views show owner/name/MIME/size/chunk count, never content/hash; keyslot views
  show only slot ID and profile IDs, never descriptor/salt/commitment/wrapped VK.
  Unknown optional values are indicated, not dumped, and preserved on selection.
  Stream one version at a time; never collect all plaintext conflict payloads.
- `resolve_version(&handle, Option<&MasterPassword>, Option<&CancelToken>)`
  rejects a stale session/head set before any write. Read the complete selected
  version anew and create a fresh version/clock joining all current heads through
  existing `edit::commit_with`/Write. Preserve payload/record/field unknown values,
  protected fields and TOTP together. Update entry modified_at for the new edit.
  Group projection remains display-only; control/root rules stay enforced.
  Ordinary edit refusal remains. A later unseen head remains a conflict.
- Password selection requires `Write::stage_selected_password(version,password)`.
  It selects only an active keyslot role, unwraps through the existing pinned
  PasswordSlot KDF/commitment/AEAD, and verifies the current header MAC with that
  VK as key confirmation. No raw-key API/comparison is introduced. Poison the
  transaction on failure. Stage the exact descriptor; existing commit binding
  checks require the identical new causal keyslot payload and update header MAC,
  operational row/head/anchor in the same transaction. Wrong password is 3;
  valid unwrap to another VK is Integrity (7). --yes never bypasses this proof.
- Attachment resolution is a deliberate new version. Existing manifest roles
  cannot share chunk IDs, so `Write::restage_attachment(record,version,cancelled)`
  fully verifies the selected content, then decrypts/reencrypts one bounded chunk
  at a time into fresh IDs/nonces in this transaction. Recheck hashes/AEAD/length,
  full constant-time content hash and budgets; use the existing staging token
  consumption checks. Preserve selected owner/name/MIME/extensions and history.
  Never buffer a whole attachment or introduce plaintext files. Failure poisons
  and rolls back the existing Write.
- Selecting a final entry tombstone also tombstones its currently owned live
  attachment metadata in this transaction. Inspect all attachment heads for
  ownership; refuse if an affected attachment remains conflicted, so it must be
  explicitly resolved first. Never silently resolve another record. Preserve
  permanent tombstone metadata; final deletion uses minimal empty extensions.
- Return `ResolutionReport { conflicts, completion_error }` after a durable
  commit, retaining the matching index even if anchor completion fails. Before
  commit errors/cancellation leave accepted state intact. Existing session hooks
  cover pre/postcommit locking. Protected views are discarded on lock.
- Complete local snapshot recovery: when a slotless snapshot has conflicting
  keyslot heads, restore its full manifest into a new baseline using the source
  session's authenticated working local slot. This preserves all heads and makes
  no incoming slot choice. CLI already reauthenticates that source password.
  Ordinary single-head restore keeps its old behavior; self-contained restore
  keeps its explicit header slot. Generic archive restore without a source slot
  still refuses ambiguity. Amend 0004/0011 before code and correct restore hint.
- Exact CLI: `conflicts [<entry/group-path|@record-id>] [--reveal] [--json]`.
  Without a target list every conflicted record as ID/kind/head count; --reveal
  needs a target (usage 2 before unlock). With a target, show every complete head
  one at a time, masked by default; JSON has record_id and versions, each with
  version_id/kind/state/modified_at/clock/unknown_extensions and typed details.
  Never reveal keyslot material or attachment content/hash, even with --reveal.
  `resolve <target> --version <hex-prefix>` rejects JSON/invalid prefix before
  unlock; missing/ambiguous IDs use 4/5. Confirm the new edit over all shown heads
  (--yes may skip); keyslot selection always prompts separately for that slot's
  password via the TTY, never argv/environment/another unframed stdin secret.
  Print actual local resolution and conflict count, then any completion error.
  Version selection is the complete edit; subsequent ordinary edits are separate.

### Step 9 — Recombine and amend exact contracts

- [x] **Do:** Record owner direction, remove arbitrary step-count phase splitting
  in roadmap/AGENTS/architect guidance, and amend 0011/0004/index before code.
- **Files:** this plan/index/roadmap, AGENTS.md, architect/developer skills,
  specs/0004-local-storage.md, specs/0011-cli.md, specs/README.md.
- **Done when:** phase 2.2c is one owner-authorized unit with exact contracts.
- **Verify:** `git diff --check`; architect conformance check.

### Step 10 — Selected-slot proof and bounded attachment restaging

- [x] **Do:** Add the two Write staging methods; use existing commit binding,
  poisoned failure behavior and chunk AEAD/profiles. No second write path.
- **Files:** qv-store/src/write.rs, unsupported.rs (matching fail-closed API), focused credential/attachment tests.
- **Done when:** wrong/foreign slot proof cannot commit; selected attachment
  content is copied with fresh objects and preserved logical bytes/metadata.
- **Verify:** focused store credential/attachment tests.

### Step 11 — Generic capabilities, views and explicit resolution

- [x] **Do:** Add all-kind handles/views/resolution, exact-head staleness,
  per-kind authorization, owned-attachment handling and durable outcome reporting.
- **Files:** new qv-core/src/conflict.rs and conflict_tests.rs; core lib/views;
  existing edit::commit_with path (only if sharing a helper is necessary).
- **Done when:** complete versions survive selection; stale/locked/invalid
  choices reject; all kinds, delete/edit and unseen later heads behave causally.
- **Verify:** `cargo test --locked -p qv-core conflict`.

### Step 12 — Recover slotless snapshots with keyslot conflicts

- [x] **Do:** Factor private restore with optional authenticated source slot;
  use it from local SnapshotDir::restore only for ambiguous slotless input.
- **Files:** store restore/archive, core snapshot tests, CLI snapshot hint.
- **Done when:** new-path restore unlocks with current working password and
  preserves the snapshot's unresolved keyslot versions; generic ambiguity rejects.
- **Verify:** focused store/core snapshot/restore tests.

### Step 13 — CLI inspection and resolution

- [x] **Do:** Add exact command syntax, generic ID/path matching, streaming
  masked/explicit-reveal human/JSON output, confirmation and separate slot prompt.
- **Files:** qv-cli/src/{cli,cmd/mod}.rs, new cmd/conflicts.rs,
  qv-cli/tests/conflicts.rs; reuse existing JSON/output/TTY helpers.
- **Done when:** IDs reach every record kind; no secret enters argv/errors/Debug;
  JSON is valid, masked by default and bounded per version.
- **Verify:** `cargo test --locked -p qv-cli --test conflicts`.

### Step 14 — Adversarial and crash/race evidence

- [x] **Do:** Real archive merges, all kinds, complete unknown/protected values,
  deletion/edit, owned attachment conflicts, attachment copy/history, stale/lock
  races, wrong/foreign selected slot, working-slot preservation/reopen, slotless
  recovery and selected-slot transaction/anchor crash points.
- **Files:** store credential tests, core conflict/snapshot tests, CLI conflicts.
- **Done when:** no partial selected-slot installation or implicit resolution;
  no received/unseen state disappears and durable state has matching views.
- **Verify:** focused suites; final gates in Step 15.

### Step 15 — Complete phase 2.2c

- [x] **Do:** Update architecture/changelog/spec index and all plan/roadmap
  statuses. Run SPDX/matrix/fmt/Clippy/full locked tests and affected fuzz checks;
  deny/vet for the combined tree's existing dependency edge. Preserve staging.
- **Files:** architecture, CHANGELOG, plan/index/roadmap; relevant module docs.
- **Done when:** full 2.2c is Implemented with no c subphase left; fresh complete
  review remains next session, not a claimed same-context independent review.
- **Verify:** all AGENTS gates; temporary logs, exit status preserved.

- 2026-10-31: Owner requested immediate completion of 2.2c2 on the staged
  2.2c1 tree and rejected excessive splitting. Combined continuation approved
  explicitly; no new plan number or intermediate commit/review request. Prior
  0026 delegation covers exact specification/API details. Preserve the staged
  index and leave continuation edits unstaged. No production code changed yet.

- 2026-10-31: Continuation steps 9–14 implemented. Added all-kind capabilities,
  bounded masked views, complete-version selection with inspected-head binding,
  selected-slot password/key confirmation, bounded fresh attachment chunk
  staging and ambiguous slotless local snapshot recovery. Existing write/anchor
  path is shared; no dependency/profile/format/unsafe change. CLI uses generic
  IDs, streaming human/JSON inspection, explicit reveal and a separate selected
  slot TTY prompt that --yes cannot bypass.
- 2026-10-31: Focused evidence: core conflict filter 9 tests passed (5 new),
  selected-slot store suite 2 passed including 9 crash points, attachment
  corruption/partial-staging cancellation test passed, CLI conflicts suite 2
  passed across all five kinds and real PTY password proof. Unknown extension
  tests cover record/payload/field levels and protected/TOTP content. Initial
  compile errors around AttachmentMeta's Drop ownership and an optional-@ CLI
  preflight discrepancy were fixed without weakening assertions. Final combined
  source gates are next; retain logs under /tmp/qv-next-review/c2-*.log.

- 2026-10-31: Step 15 complete. **Phase 2.2c is Implemented as one unit**,
  including all former c2 work. Final combined-tree gates pass with zero exit
  status: SPDX, matrix, fmt, Clippy and `cargo test --locked` with private Xvfb,
  **699 passed / 0 failed / 2 pre-existing ignored**. Final suite log:
  /tmp/qv-next-review/c2-final-tests.log. Deny passes advisories/bans/licenses/
  sources; vet passes (27 fully audited, 6 partially audited, 79 unchanged
  exemptions). Affected fuzz formatting and locked archive_read/manifest_decode/
  vault_open/archive_receipts compilation pass. No new dependencies, policies,
  exemptions, unsafe, profiles or format versions in the continuation.
- 2026-10-31: Full tests include record/payload/field unknown-value preservation,
  protected/TOTP complete selection, all five kinds, actual CLI masked/revealed
  views, head-set staleness, pre/postcommit lock races, owned-attachment conflicts,
  fresh-chunk restaging, source corruption/partial-cancellation rollback,
  foreign-VK/wrong-password slot proof and all nine slot commit/anchor crash
  points. Slotless local snapshot restoration now retains a usable working
  source slot without resolving the snapshot's keyslot heads. No C work remains
  deferred; standalone archive bootstrap, GUI/platform work and transports were
  outside this phase. No independent review/security/release claim is made.
- 2026-10-31: Recombined roadmap/index/architecture and current changelog around
  complete 2.2c; removed arbitrary step-count splitting from roadmap and agent
  guidance. Next fresh session reviews complete 0028 before phase 2.3. The
  owner's staged c1 index is preserved; all continuation edits are unstaged.
  No commit, push or branch. Final documentation/status edits change no tested
  Rust/dependency inputs; SPDX/matrix/fmt/diff checks rerun for handoff.
