# Plan 0019 — Restore a local snapshot to a new vault (roadmap 1.13b)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-28 | 2026-10-28 (owner: fix then implement 1.13b; standing approval, roadmap 0002) | 0004 §3.6/§5/§6; 0007 §3.4; 0005 §5.4 (D5); 0011 §4–6; 0012 §1 |

## Intent

Restore a selected local snapshot into a new vault file without changing the
active vault or its anchor. Resolve plan 0018's review findings first.

## Scope

In scope: store archive-to-new-file builder, core snapshot ID selection and
restore orchestration, CLI `snapshot restore <id> <path>`, rejection/crash
coverage and documentation. Out of scope: archive merge/export, standalone
phrase import (1.14), self-contained archives, key/password changes, sync,
new dependencies, schema/format changes and unsafe.

## Spec basis

| Behaviour | Spec | Status | Notes |
|-----------|------|--------|-------|
| Verify before acceptance, private atomic creation | 0004 §1/§3.6/§5/§6 | Accepted | Existing schema and creation ordering |
| Restore new path, preserve source | 0007 §3.4 | Accepted | No latest-global-state claim |
| Fresh local baseline | 0005 §5.4 | Draft | Roadmap D5 authorization |
| IDs, JSON refusal, exits, secret handling | 0011 §3–6 | Accepted | Existing snapshot contracts |
| Hostile archives/crash evidence | 0012 §1–3 | Accepted | Tests are evidence, not proof |

Spec changes required: None. Invoking `snapshot restore` explicitly selects a
new recovery baseline, as does calling `Session::restore_snapshot`; no implicit
adoption on ordinary unlock. It creates only a new path and is not among the
confirmation-required destructive commands in 0011 §5.5. Warn that the copy may
be old and uses the password slot from the snapshot; no new password choice.

## Decisions needed

None. The owner explicitly authorizes fixing 0018 and continuing 1.13b despite
uncommitted review/remediation records. Preserve the fresh-context review
requirement for this phase's later roadmap handoff.

## Design

Components: qv-store owns files and crypto/format validation; qv-core owns
session and snapshot selection; qv-cli calls only core.

Interfaces:
- `VaultFile::create_from_archive<R: Read + Seek>(path, input, scope, &VaultKey,
  &AnchorDir, cancelled) -> Result<(), StoreError>`: explicit new baseline.
- `SnapshotEntry::archive_id() -> &str` and `SnapshotDir::open_entry(...) ->
  Result<File, StoreError>` (private-file safety, never SQLite ingestion).
- `Session::snapshot_matches(prefix: &str) -> Result<Vec<String>, CoreError>`:
  validate 6–32 ASCII hex (optional @), return sorted unique filename IDs,
  including files whose authentication will fail. This lets an exact foreign
  or damaged selection fail Integrity rather than silently disappear.
- `Session::restore_snapshot(id: &str, path: &Path, cancel) -> Result<(),
  CoreError>`: exact full ID, scope-authenticate selected header, refuse
  duplicate ID files, enforce anchor-location policy and run the store builder.
- CLI validates syntax and rejects --json before unlock; zero matches exit 4,
  multiple exit 5 with matching archive IDs; calls restore on the selected ID.
  Existing mappings: 3 bad source password; 6 lock/changed; 7 integrity;
  9 bounds; 1 filesystem/exists/cancel. Success is silent on stdout, with a
  fixed stderr baseline/old-state warning. No format or new exit code.

Data flow: validate destination (.qvault, absent, private parent, no symlink);
fully validate archive without creating any accepted state; recover the single
active password-keyslot record under VK, retaining unknown descriptor fields;
reject ambiguous keyslot heads. Derive portable header identity/generation,
profiles and minima from the archive. Generate a fresh replica ID and writer
ID, counter 1, local head sequence 1 with no previous/remote state. Preserve
all manifest records, heads, retained history, floors and object IDs/bytes;
reseal the manifest under its existing scope, construct local header MAC over
the reconstructed operational password slot. No local source state is copied.

Build a private temp vault using the existing schema install/parameter-bound
inserts, one IMMEDIATE transaction, durable commit; reread header/state and full
verification before publication. Reuse create ordering: fsync temp -> crash
CreateBuilt -> store fresh anchor -> crash CreateAnchored -> no-replace rename
-> directory fsync. On pre-publication error remove temp/sidecars and only the
new anchor; never source anchors. After publication a directory-fsync failure
reports failure but may leave a complete new vault, matching existing create.
Use a borrowed VK (no new key-copy API). Check cancellation during archive
passes and before commit/publication; no plaintext on disk. Bounded seek/frame
index and per-object buffers as in 0018 remediation; restore inputs are private
local snapshots. Rehash frames against the verified index when reading again.

Dependencies: None; reuse existing RustCrypto, SQLite, rustix and codec APIs.
No manual crypto primitive, raw key exposure, source mutation or changed bytes.

## Steps

### Step 1 — Verified new-vault builder

- [x] **Do:** add store restore module, archive entry access and fail-closed
  stubs. Reuse creation helpers and crash points; keep verification before
  publication and preserve state. **Files:** qv-store/src/{restore,archive,
  vault,lib,unsupported}.rs; validation helpers as needed.
- **Done when:** restored vault unlocks using archived password; content,
  history, floors and attachment bytes match; fresh replica/writer/head/anchor;
  source vault/anchor bytes unchanged; existing target refused unchanged;
  corrupt/foreign/truncated/trailing/slot archives, cancellation, unsafe paths
  and failures at both creation crash points leave no accepted partial vault.
- **Verify:** `cargo test --locked -p qv-store restore`.

### Step 2 — Core and CLI restore

- [x] **Do:** implement scoped selection/restore, CLI parsing/preflight/warning
  and integration tests. **Files:** qv-core/src/{snapshot,setup,session}.rs;
  qv-cli/src/{cli,signals,cmd/snapshot}.rs; qv-cli/tests/snapshots.rs.
- **Done when:** full/prefix/@ addressing; invalid/absent/ambiguous/foreign
  cases, --json rejection before password read, target refusal, successful
  fresh baseline and source preservation tested through production components.
- **Verify:** `cargo test --locked -p qv-core snapshot`;
  `cargo test --locked -p qv-cli --test snapshots`.

### Step 3 — Documentation and gates

- [x] **Do:** update current component descriptions, CLI/crate docs, changelog,
  plans/index/roadmap and execution log; run required gates and reviewer pass.
- **Files:** ARCHITECTURE.md §3, CHANGELOG.md, crate docs, plans.
- **Done when:** implemented but not claimed independently reviewed; all
  changes remain uncommitted. No spec status promotion.
- **Verify:** all four AGENTS gates; git diff --check.

## Test plan

Focused checks per step; final `sh scripts/check-spdx.sh`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`
with private Xvfb. Deny/vet if dependencies change (none planned). Cover 0012
Live SQLite copying, Hostile files from sync folders, Snapshot disk growth,
Whole-file rollback and purge/suppression preservation through new-path restore.
Use existing crash harness and real private filesystem paths. Attempt network
namespace isolation; record unavailability honestly. No frozen golden vectors.

## Risks and stop conditions

Stop for spec contradiction, owner decisions, new dependency/format/schema,
unsafe or secret exposure. Archive validation must never open archive bytes as
SQLite. Do not implement restore by making causal edits that drop history or
floors. Do not reuse source replica/anchor or overwrite a target. Failure after
publication may leave a complete destination; report honestly, never roll back
the active vault or remove another file. No standalone recovery command here.

## Documentation

- [x] CHANGELOG.md — fixes and snapshot restore.
- [x] ARCHITECTURE.md §3 — implemented restore and validation responsibilities.
- [x] Specs — no amendment/status change.
- [x] AGENTS.md — no conventions change.
- [x] Plans — log/index/roadmap; retain later fresh-context review requirement.

## Revisions

2026-10-28: Reviewer inspection found new-path restore must use Session's
mutation-result semantics: a lock requested after publication must not discard
success and incorrectly report a cancelled read. Use the existing serialized
`mutate` wrapper with explicit cancellation before publication, and test lock
requests before and after the durable boundary with existing test-only hooks.
No source vault mutation or second transaction path is introduced.

2026-10-28: Add `CancelToken::from_shared_flag(Arc<AtomicBool>)` and a private
CLI signal-token adapter so SIGINT/TERM/HUP cancel restore between bounded
units without another thread or unsafe handlers. Add `ArchiveScope::with_archive_id`
to bind the selected ID across file reopen/reader passes. These are explicit
interface refinements within the approved scope, with no new behavior choice.

2026-10-28: Source trace found that a normal CLI unlock may prune the requested
snapshot before it is selected. Add `Core::unlock_for_snapshot_restore` using
the normal anchor checks but deferring the automatic snapshot pass; successful
`Session::restore_snapshot` runs that pass only after the selected archive is
safely restored. Failed restore never prunes its input. This is ordering of the
existing best-effort policy, not a new snapshot schedule or source-vault write.
Other unlocks retain their policy. Core/CLI tests must restore an expired
selected copy without unlock deleting it first. Store uses
`SnapshotDir::restore(entry, source_vault, path, cancelled)` to keep VK and
anchor access internal; it authenticates filename/header ID agreement and
exposes no raw keys. The lower-level `VaultFile::create_from_archive` remains
the new-file builder. Its self-test reopens the completed temp through existing
schema/header/state verification and compares every stored envelope byte-for-
byte to the already fully authenticated archive before anchor/publication.


## Execution log

2026-10-28: Approved under explicit owner continuation and standing approval,
roadmap 0002; no unresolved decisions. Initial tree contains only this session's
review records. Implement after 0018 remediation and its reviewer pass.


2026-10-28: Steps 1–2 implemented. The store validates the entire seekable
archive before making a temp vault; reconstructs the single operational slot;
preserves exact objects and causal metadata; then reopens and verifies the
new schema/header/state and compares every persisted complete envelope before
fsync/anchor/no-replace publication. Fresh replica/writer, counter 1, head 1,
no previous/remote state. Creation crash hooks and cleanup protect source
anchors. Source archives never reach the SQLite file parser; accepted object
ciphertext is inserted with bound parameters. A borrowed VK avoids a new key
copy API. Cross-platform APIs fail closed.

Core exposes filename-ID matching and explicit restore; the selected archive
ID is bound across reader passes. Restore-specific unlock defers automatic
pruning until success. CLI implements full/prefix/@ IDs, invalid/absent/
ambiguous/integrity exits, --json preflight, and a fixed baseline/password-era
warning. Shared signal flags drive the existing cancellation token without a
thread or unsafe callback. No confirmation was added: the explicit new-path
command selects a baseline and cannot replace an active file (0011 §4/§5.5).

Focused store restore: 4 passed, including history/floors/chunks, fresh state,
new edits, unchanged source/old anchors, hostile/truncated/foreign inputs,
existing/symlink/unsafe targets, pre-start and mid-build cancellation and both
creation crash points. Core snapshot: 17 passed, including restoring an expired
selected input before pruning and locked/cancelled/absent/malformed selection.
CLI snapshots: 6 passed, including full production restore/verify/search,
source preservation, target refusal and preflight/addressing exits. Logs:
`/tmp/qv18-review/restore-{store,core,cli}.log`. Final combined-tree gates and
reviewer inspection pending; no dependency or normative-spec change.


2026-10-28: Same-session reviewer inspection traced snapshot identity binding,
role authentication, exact envelope rereads, new-file transaction/anchor/crash
ordering, selected-input preservation, metadata/secret lifetimes, frontend
boundaries and errors. Found and fixed a local lifecycle issue within this
plan: restore now uses Session's mutation-result wrapper, so a lock after
publication reports committed success. Existing test-only before/after commit
hooks drive the new lock-race regression: cancellation before creation leaves
no destination, while locking after publication returns success and the complete
new file verifies. Three focused snapshot-restore tests pass, including that
race (`restore-lock.log`). This is an implementation review in the same context;
phase 1.13b still requires fresh-context review before the next phase. Final
required gates are being repeated after the lifecycle fix.


2026-10-28: Step 3 complete. Current component/crate and CLI documentation,
Unreleased changelog, plan index and roadmap updated. No spec status promotion,
new crate boundary, dependency, format, schema or MSRV change. All required
final-tree gates pass: `sh scripts/check-spdx.sh` (`final2-spdx.log`),
`cargo fmt --check` (`final2-fmt.log`),
`cargo clippy --all-targets --locked -- -D warnings` (`final2-clippy.log`), and
`QV_TEST_XVFB=/tmp/qv18-review/xvfb/usr/bin/Xvfb cargo test --locked`
(`final2-test.log`): **574 passed, 0 failed, 2 pre-existing ignored**, across
33 reported test groups. Private-Xvfb clipboard tests ran and passed. Full
logs in `/tmp/qv18-review/`. `git diff --check`, fuzz formatting and locked
archive fuzz-target build pass. No dependencies changed, so deny/vet are not
required for this work; their tools were unavailable in the initial review.

The network-isolated snapshot command was attempted but namespace creation
fails with `No space left on device` (`final-offline.log`): no isolated test ran,
and no networking-blocked pass is claimed. The earlier 61-second debug fuzz
smoke run is not an instrumented release campaign. No security proof, global
freshness or secure-erasure claim. Independent fresh-context review of 0019
remains the next roadmap session's prerequisite; status Implemented, not
Reviewed. All changes are uncommitted; no commit, push or branch.
