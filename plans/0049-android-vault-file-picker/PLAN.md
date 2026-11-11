# Plan 0049 — Open vault files through Android's file picker

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| In progress | 2026-11-09 | 2026-11-10: owner reiterates “Just do the implementation already” after the SAF constraints were explained; execute the original verified private-import design | 0009 §1.8, 0004 §1/§4/§5/§7, 0007 §3.4, 0008 §1/§4, 0012 §1–3 |

**Current execution (2026-11-10):** Implement the original bounded, verified
private-import design below under the owner's repeated execution instruction.
The earlier entry claiming an owner-selected in-place design was an agent
inference, not a decision the owner made. The copy notice is explicit in the
Android flow; Linux continues referencing the selected file. Preserve staging
of the owner's existing documentation edits; do not alter the Git index.

## Intent

Android must offer **Open a vault file…** through its system file picker.
Selecting an existing `.qvault` must lead to password unlock and ordinary
offline use, without asking anyone to type a filesystem path. The owner
requested this plan before committing the current 0048 validation checkpoint.

## Scope

In scope: the Android welcome/vault menus, Storage Access Framework (SAF)
selection, bounded handling of a selected encrypted vault, authentication,
verified creation of an independent private copy, list selection and real
phone verification. Reuse the shared UI and document stream channel.

Out of scope: changing Linux opening,
vault/archive/wire formats, crypto/KDF profiles or dependencies; automatic file
watching/sync, background provider write-back, external file-manager associations,
and repairs to 0048's unrelated keystore/latency findings. Independent security
review and unfinished release/device evidence remain tracked in 0048.

## Current gap and spec basis

`qv-app/src/ui/mod.rs` sets `can_pick` to Linux only, and `pick_vault` calls the
Linux portal only. Both welcome and locked-menu open-file choices disappear
on Android. Its SAF channel already supports attachments/archives, but not
vault opening. `typed_path = fixture` correctly hides the manual field from
the regular app; exposing it again is not part of this plan.

| Requirement | Basis/status | Consequence |
|-------------|--------------|-------------|
| System picker, no typed locked-screen paths | 0009 §1.8; named Draft section previously owner-approved | Add the missing Android action; keep automation controls out of normal UI |
| Current import references the original file in place | 0009 §1.8 owner decision | Private-copy behavior requires a specific amendment and owner approval |
| Private ordinary SQLite, bounded hardening and atomic writes | 0004 §1/§4/§5 Accepted | A provider URI is not a safe filesystem path or an ordinary SQLite transaction backend |
| New-path restore creates fresh local identity | 0007 §3.4 Accepted; existing store restore | An independent imported copy must not reuse a source writer/replica/anchor |
| Secrets, lifecycle and stale results | 0008 §1/§4; named owner-approved requirements | Protected password/key state, no plaintext staging, lock cancels late work |
| Existing large-vault policy | 0004 §7 Accepted | Keep all model/storage budgets; no aggregate searchable-text rejection |
| Actual target evidence | 0012 Accepted | Test hostile providers, failures and real system-picker use; passing tests are not security certification |

Android's [SAF documentation](https://developer.android.com/training/data-storage/shared/documents-files)
returns a URI with a user-granted document capability; providers can be local
or cloud backed. It does not promise a stable private filesystem path, a
seekable descriptor, or SQLite-compatible locking/atomic replacement. Do not
resolve a `content:` URI by inventing a `/storage/...` path. Linux's `file:`
restriction remains; Android document capabilities need a platform-specific
spec clarification.

## Decisions needed

None outstanding for the original implementation. Execute the recommended
verified private-copy flow under the owner's repeated implementation request,
with explicit copy/baseline consent and the Android spec exception. Linux
continues opening the selected file where it is. The earlier revision claiming
an owner-selected in-place implementation was an agent inference, corrected
when execution resumed; it is retained below as history, not an active gate.

No additional performance target, limit increase or dependency is proposed.
The source-file limit is the existing `qv_store::MAX_DB_BYTES` (currently
2 GiB), distinct from the unchanged 1 GiB referenced-ciphertext budget.

## Design — verified private copy

### UX and components

- Add **Open a vault file…** to Android's welcome page, locked vault menu and
  phone vault-switcher sheet. Use the shared UI; show no path textbox.
- From an unlocked vault, apply existing switching rules: refuse while a form
  has unsaved input, lock the current vault before opening the picker. Cancel
  leaves it locked; never silently restore an unlocked session.
- Use SAF `ACTION_OPEN_DOCUMENT` / `CATEGORY_OPENABLE`. Existing `.qvault`
  files may report generic MIME types; filename/MIME hints are not validation.
  Keep the URI/grant in the native adapter, with only bounded request IDs,
  display metadata and streamed ciphertext crossing JNI. No broad storage
  permission or persistent URI grant is needed for a one-time import.
- After selection, stage the encrypted file, show a bounded proposed local
  name and the private-copy explanation, then request the master password.
  Enforce the existing 1–64-character filename rules. A collision asks for a
  different name; never overwrite, silently merge or auto-replace a vault.
- Wrong passwords can retry the same staged candidate without rereading a
  changing provider. Clear the password control after each attempt. After
  verified publication, select/list the local vault and open it normally.
- Provider display names, paths and URIs never become trusted vault identity.
  The authenticated metadata name replaces the unverified filename as usual.

`qv-app` owns UI/SAF glue and the existing list; `qv-core` owns staging and
authorization; `qv-store` owns bounded SQLite verification and fresh durable
creation. Frontends do not open SQLite, hold VK or choose control-record heads.
No crate or new third-party dependency is needed.

### Core interface sketch

```rust
// Opaque, non-Clone, redacted types; private guards own ciphertext cleanup.
pub struct PendingVaultImport { /* private immutable staging ownership */ }
pub struct VerifiedVaultImport { /* source-bound protected verified state */ }

impl Core {
    pub fn stage_vault_import(
        &self, input: &mut dyn std::io::Read, cancel: Option<&CancelToken>,
    ) -> Result<PendingVaultImport, CoreError>;
    pub fn authenticate_vault_import(
        &self, source: &PendingVaultImport, password: &MasterPassword,
        cancel: Option<&CancelToken>,
    ) -> Result<VerifiedVaultImport, CoreError>;
    pub fn publish_vault_import(
        &self, source: VerifiedVaultImport, destination: &std::path::Path,
        cancel: Option<&CancelToken>,
    ) -> Result<Session, CoreError>;
}
```

Pending/verified objects share private staging lifetime through an internal
guard so retry/drop cannot remove a still-used source. Publication consumes
the verified capability. Bind it to the exact immutable staged source and
authenticated scope; another pending import cannot be substituted. Keep the
controller's operation/epoch cancellation active through every stage. Preserve
existing required platform/protection checks before secret use/publication.

### Authentication, identity and publication

1. Read in bounded chunks into a unique 0600 file in a 0700 private import
   directory. Enforce actual bytes against `MAX_DB_BYTES`, including a +1
   read to detect excess; do not trust reported size or preallocate from it.
   Handle unknown sizes, partial reads and cancellation. Sync/close the writer
   before the hardened store opens the staged file.
2. Use existing SQLite permission/identity/schema/resource hardening, then
   password unwrap, header MAC, authenticated manifest/object/model validation
   and compact-index preflight. Raw files are untrusted, even when named
   `.qvault`. Do not skip hardening or parse encrypted payloads before auth.
   Use a source-only temporary anchor context: never adopt/change an existing
   local vault's anchor because an external file claims the same identity.
3. A selected raw file has no independently trusted external anchor. Require
   the existing recovery-baseline acknowledgement before installation and
   explain that file freshness cannot be established. Do not assert that a
   live external SQLite copy is safe; ask for a closed/exported vault file.
   A partial/inconsistent file fails verification, without repair.
4. Internally reuse the verified-object archive/restore machinery to create a
   fresh local replica, writer, counters, local head and anchor. Preserve vault
   identity/generation, shared password and all replicated records, history,
   floors, settings and attachments; do not clone source local quick-unlock,
   peer/account credentials or replica state. Apply existing restore checks for
   password/control conflicts; never manufacture a slot or silently pick a
   conflicting control head. VK stays inside core/store protected containers.
5. Build the complete private destination, verify/preflight before publication,
   fsync and publish with existing no-replace creation/anchor ordering. A
   pre-publication failure exposes no destination/list entry. After a durable
   publication, retain the file and report `PublicationIncomplete` if cancel,
   anchor or platform binding fails; return no late unlocked session. Update
   the list only for an actually published local file. List persistence failure
   reports the existing limitation without undoing durable publication.
6. Close/release provider state promptly after staging; never write back or
   retain its URI. Remove abandoned ciphertext staging on cancel/drop/restart
   within an app-owned import directory. No cleanup traverses user/provider
   files or removes a published vault. Plaintext never goes to a temp file.

Use current archive frame/total bounds for any intermediate verified archive;
do not apply the 1 GiB archive ciphertext sum to the raw SQLite file's physical
length. Account for simultaneous raw/archive/destination disk usage and fail
cleanly on disk full. No physical/RSS ceiling or provider-locality guarantee is
invented. A provider may fetch the explicitly selected document; QuickVault
starts no network sync, background retry or continuing provider dependency.

### Errors and state

Reuse fixed `CoreError`/`AppError` categories for invalid input, unsupported
format, wrong password, integrity, cancellation, limit exceeded, unavailable
provider, invalid/colliding names and publication-incomplete outcomes. No native
exception text, URI, password, key or document content enters errors/logs.
Picker cancellation changes no vault data; stale request/epoch results are
discarded. New user-visible error categories beyond this mapping require a
plan revision rather than improvised strings.

## Steps

### Step 1 — Settle import policy and amend the contract

- [x] **Do:** Resolve the decision above. If private-copy is approved, amend
  0009 §1.8 with the Android exception, SAF capability handling and honest UX;
  amend 0004 §1.2/§5 as needed for explicit user-selected raw-vault staging and
  verified fresh-local creation. Preserve archive-only automatic/network input,
  Linux import-in-place and all format/crypto limits. Record the exact approved
  sections without promoting the full Draft client/memory specs.
- **Files:** this PLAN.md; `specs/0009-clients-and-platforms.md`,
  `specs/0004-local-storage.md`, `specs/README.md`, Changelog.
- **Done when:** No copy/in-place or URI/path contract is guessed.
- **Verify:** Trace the amended requirements against 0004/0007/0008 and existing
  restore/creation code; no implementation before approval and owner commit.

### Step 2 — Core/store verified private import

- [x] **Do:** Implement the opaque import phases and minimum store helpers
  using existing verified archive/restore and durable creation code. Cover byte
  bounds, hostile SQLite, credential retries, source substitution, fresh local
  identity, control conflicts, cancellation and publication/anchor failures.
- **Files:** `crates/qv-core/src/vault_import.rs` (new), `lib.rs`, `setup.rs`;
  `crates/qv-store/src/restore.rs`, `creation.rs`, `vault.rs`, `lib.rs` and focused
  import/creation tests. Keep helpers in these components, not frontend SQL.
- **Done when:** Imported state reopens/writes with fresh local identity; source
  and existing local vaults/anchors remain intact; no partial/unauthenticated
  publication or frontend-accessible key capability.
- **Verify:** `cargo test --locked -p qv-core vault_import`;
  `cargo test --locked -p qv-store vault_import`; affected restore/crash tests.

### Step 3 — SAF selection and shared app flow

- [x] **Do:** Add the Android open action and picker purpose, stage through
  core, show the approved copy/baseline acknowledgement and password/name flow,
  then select the published local vault. Preserve picker-lifecycle handling;
  genuine lock/background cancellation and stale callbacks cannot reopen UI.
- **Files:** `crates/qv-app/src/{documents,android,controller,vaults}.rs`,
  `src/ui/{mod,shell}.rs`, `android/MainActivity.kt`, focused controller tests.
- **Done when:** A regular Android build opens a selected file through the
  approved import flow; no raw path field, broad permissions or source write-back.
- **Verify:** `cargo test --locked -p qv-app`; Android build/manifest inspection;
  controller tests for picker cancel, stale result and collision/late completion.

### Step 4 — Real provider and device qualification

- [x] Actual `content:` provider/instrumentation fixture implemented and built
  under a disposable UID with ordinary production UI/native bytes.
- [x] Host >64 MiB searchable-text and >99%-ciphertext-budget import checks.
- [ ] Run the provider tests and attended Downloads/system-picker flow on a
  real Android device. No authorized device is currently connected.

- [ ] **Do:** Add isolated-UID instrumentation with an actual `content:` test
  provider (unknown size, pipe/short reads, refusal/revocation, malicious bytes),
  then an attended system-picker run from Downloads. Open, search, edit, lock
  and reopen; hash the source before/after. Exercise large data and publication
  faults. Reuse 0048's separate-UID packaging; never run against personal vaults.
- **Files:** app Android test/provider fixture, test manifest and
  `scripts/{build,test}-android.sh` as required; this directory/VALIDATION.md;
  isolated packaging support only if needed for the new tests.
- **Done when:** Regular-UI/device evidence covers picker→core→durable reopen,
  no typed path, no overwritten source/destination and accurate failure results.
- **Verify:** Selected new instrumentation methods in the isolated package;
  ordinary Android build plus all final AGENTS.md gates, matrix and focused
  maintained-vendor tests only if that vendor is actually changed.

### Step 5 — Documentation and fresh review

- [ ] **Do:** Record final behavior/results/limits, update component boundary
  descriptions and owner-facing docs, then obtain the required fresh-context
  implementation review before calling the import implementation complete.
- **Files:** `ARCHITECTURE.md` §3, app README, Changelog, specs/index as amended,
  plans index and this plan/VALIDATION.md/REVIEW.md.
- **Done when:** Review findings addressed; Linux and existing Android file
  operations regressions pass; independent release gates remain explicit.
- **Verify:** Current-tree required gates and review of the complete flow.

## Test plan

No new primitive, format or dependency; reuse existing authenticated fixtures.
Cover 0012 §1 rows **Hostile SQLite/CBOR**, **Hostile files from sync folders**
(automatic/archive paths remain archive-only), **Live SQLite copying**,
**Whole-file rollback**, **Anchor crash windows**, **Webview exposure** and
**Budget inconsistency**. Preserve exact row comments where a test covers an
offline matrix row and run `sh scripts/check-matrix.sh`.

Include MAX_DB_BYTES/+1 and unknown-length streaming without huge allocation;
all record/history/attachment/conflict data preserved; no password retained
through unrelated work; stale/cancel/lock outcomes before and after publication;
destination collision, disk-full and list/anchor failure; raw source cannot
substitute another verified candidate; unchanged source digest and fresh local
writer/replica; complete >64 MiB text search and an actual near-budget fixture.
Only real-window app tests need RUST_TEST_THREADS=1. Final gates: SPDX, fmt,
all-target locked Clippy and locked tests; deny/vet only if an approved revision
actually changes dependencies. Do not count the existing failed 0048 UI run
or a validation-only typed-path flow as evidence for this feature.

## Risks and stop conditions

- Decision unresolved, in-place editing requested, or the owner has not committed
  the current checkpoint: do not implement the conditional copy path.
- Unknown control-record, archive-conversion, local identity or crash semantics:
  stop for architect/spec revision rather than reuse a source replica or relax
  verification. No new format, unsafe code, dependency, VFS or URI write-back.
- No overwrite, silent duplicate merge, plaintext temp, broad storage access,
  lower KDF cost or weakened platform requirement to make a provider work.
- A device/provider fault is evidence to record, not permission to mark release
  qualification complete. 0048's first hardware failure remains independent.

## Documentation

- [x] Changelog and app README: file-picker UX and approved source/edit policy.
- [x] Specs/Changelogs/index: only the exact approved amendments in step 1.
- [x] Architecture §3: selected-document boundary and core/store import role;
  update the diagram only if that trust boundary is shown.
- [ ] Plan/index, VALIDATION.md and fresh REVIEW.md; no AGENTS.md/workflow change.

## Revisions

### 2026-11-10 — Resume the original import implementation

Owner reiterates implementation after the document-access constraints were
explained. The previous revision attributed an in-place policy selection to a
rhetorical objection; the owner made no such new decision. Execute the original
recommended design with an explicit Android copy/baseline notice and the exact
spec amendments in step 1. This supersedes the prior revision's blocked status
and replacement-backend task list. No VFS, unsafe code, dependency, format change
or truncating provider write-back is authorized or needed.

Implementation refinement: store owns leased raw staging and source-only anchor
state. Pending input retains the same hardened connection across wrong-password
retries; unwrap/header verification borrows it before consuming it. Core verifies
all content and preflights its index, then publication streams a verified archive
and uses the existing fresh-local creation protocol. Stage and verified objects
are opaque and redacted. Publication consumes the verified object, requires the
existing baseline consent in the app, and retains post-publication failures.
The new store/core `vault_import.rs` modules own these opaque capabilities;
the app's controller child `vault_import.rs` owns the flow and tests. Amend
0007 §3.2 to distinguish creation of a new independent path from an import
that mutates an existing vault: no unmodified local/source vault needs a
destructive-operation recovery snapshot. Verified leased archive staging and
the existing no-replace restore protocol protect new-path publication.
Retain the existing unsupported-platform API stubs for the new opaque store
types (`qv-store/src/unsupported.rs`); the core API remains available and fails
closed there. This adds no platform backend or storage permission.
Reuse `qv-core/src/large_vault_tests.rs` for the >64 MiB searchable-text import
round trip after rotation. Add an explicitly invoked near-budget qualification
test in the core import module: 990 MiB of streamed attachments, unknown-size
input, bounded read requests and complete imported verification. It writes
several GiB of disposable ciphertext, so run it separately on disk-backed
private temporary storage; it is not part of the ordinary parallel CI run.
As in 0048's P3 dataset, 99 ten-MiB attachments fill over 99% of the ciphertext
budget after padding. Assert that a hundredth is refused unchanged; do not
increase a limit or confuse plaintext size with padded ciphertext size.

### 2026-11-10 — Preserve cross-platform in-place opening

Owner instruction: “I told you to execute a plan. not ask questions. Why would
the behavior on android be any different than in other platform????” Execute
within the existing in-place requirement; do not interpret this as approval of
the previously proposed copy exception. No normative behavior has changed.

#### Completed investigation

- [x] Confirm execution authorization and a clean, committed checkpoint.
- [x] Trace the current picker, storage API and mandatory filesystem checks.
- [x] Check the relevant Android and SQLite primary documentation.

The platform mechanism differs even when the intended behavior is the same:

- Android's [document picker](https://developer.android.com/training/data-storage/shared/documents-files)
  returns a document URI, not a direct filesystem path. Selecting one document
  does not grant its containing directory. A tree grant is a separate API and
  still exposes provider operations rather than a POSIX filesystem contract.
- [DocumentsProvider.openDocument](https://developer.android.com/reference/android/provider/DocumentsProvider#openDocument(java.lang.String,java.lang.String,android.os.CancellationSignal))
  may return a pipe for read/write-only modes. The `rw` mode implies a seekable
  on-disk file, but does not itself grant sibling-journal access or establish
  the existing path, ownership, directory and identity checks.
- SQLite's [rollback journal](https://www.sqlite.org/tempfiles.html#rollback_journals)
  lives beside the database, and its [atomic commit](https://www.sqlite.org/atomiccommit.html)
  depends on locking, synchronization and journal recovery. A seekable document
  descriptor alone does not provide this complete contract.
- In this implementation, `qv-store/src/fs.rs::check_parent`, `owner_only` and
  `check_sidecars` enforce the accepted local-file policy;
  `sqlite.rs::open_connection` opens an ordinary no-follow path and hardening
  requires `journal_mode=DELETE` and `synchronous=FULL`. The Kotlin adapter's
  `qvOpenRead`/`qvOpenWrite` only implement document streams. `qvOpenWrite`
  opens with `wt`, which truncates; it cannot serve as a transactional vault
  backend. No selected document was opened or changed during this investigation.

#### Required replacement design before production edits

- [ ] Specify a concrete supported Android storage capability that provides
  selected-file identity, coordinated writer exclusion, durable journal
  creation/recovery and synchronization, including permission revocation,
  provider/process death and concurrent external writers. Distinguish what
  documented APIs guarantee from what needs actual device/provider evidence.
- [ ] Define persistent selection/reopening and bounded list representation
  without pretending a document URI is a filesystem path. Keep frontend SQL
  and vault keys out of the native adapter. No URI-to-path guessing or
  `/proc/self/fd` shortcut may bypass the storage checks.
- [ ] Amend the exact affected specs and replace the superseded interfaces,
  steps and tests with the supported backend contract before implementing it.
  A new VFS, dependency, unsafe adapter or relaxation of file policy needs an
  explicit reviewed design; the old copy plan authorizes none of these.
- [ ] Implement and test that design, including crash/reopen and stale-result
  handling, then qualify real provider/device behavior and obtain fresh review.

Do not replace the selected document by truncating/copying a working database
back, claim provider rename is atomic replacement, disable journaling/locking,
or silently turn opening into import. No supported general SAF backend has
been established by this investigation. The plan remains incomplete, rather
than shipping an open button whose normal selections cannot work safely.

## Execution log

- 2026-11-11 final handoff: current-tree SPDX, fmt, matrix, all-target locked
  workspace Clippy and locked workspace tests pass (1,011 passed, zero failed,
  seven intentional ignored cases across 48 groups). The new heavy case was
  additionally run explicitly and passes. Desktop/validation all-target Clippy,
  Android arm64 release/mobile Clippy, ordinary Android app/test packaging and
  isolated regular-UI provider packaging/native-identity checks pass. Shell and
  Python syntax and `git diff --check` pass. No dependency change, so no new
  deny/vet baseline is required. `VALIDATION.md` records commands, final hashes,
  limits and actual failed/interrupted attempts. Source steps 1–3 and local
  documentation are complete; physical step 4 and fresh-context step 5 remain
  open. The plan stays In progress for that evidence. Existing staging remains
  untouched; the implementation is uncommitted.

- 2026-11-11: Implement store/core opaque pending and verified import capabilities,
  64 KiB actual-byte staging with the unchanged 2 GiB physical limit, whole-content
  verification, current-password/control binding and index preflight. Reuse
  archive restoration for fresh writer/replica/head/anchor publication; preserve
  source files and existing anchors. Keep leased candidates across wrong-password
  and pre-publication retries; immediately reclaim unleased archive output after
  failure and clean abandoned staging at startup. Keep unsupported-platform APIs
  uninhabited/fail-closed. No dependency, unsafe code, format or crypto change.
- 2026-11-11: Implement Android locked/welcome/switcher picker actions, bounded
  request-purpose/epoch handling, local filename/password/copy-baseline consent,
  no-overwrite publication and list selection. Release native document URIs after
  staging. Preserve foreground-return deferral using only a metadata request ID;
  old cleanup cannot clear a newer selection and late callback metadata cannot
  reappear after lock. Provider metadata IPC runs outside the cancellation
  monitor. Post-publication cancellation retains the file and reports completion
  failure without reopening or selecting a late session. Linux opening is unchanged.
- 2026-11-11: Eleven focused import regressions pass across store/core/app:
  bounds, foreign bytes, retry/consent/collision, history/attachment retention,
  fresh local identity, live cleanup, pre/post-publication crash injection and
  cancellation during platform binding/late completion. A new crash assertion
  initially used the hook's disarm boolean backwards; corrected it to require
  that the armed point was actually reached. Initial test signature/lint errors
  were fixed locally; no existing assertions or limits were weakened.
- 2026-11-11: Extend the stock >64 MiB searchable-text regression with raw import
  after generation rotation; it passes. Explicit near-budget qualification passes
  with 990 MiB actual attachment plaintext, 1,071,078,080 referenced ciphertext bytes
  (>99% of the existing limit), a 1,106,436,096-byte physical source, <=64 KiB read
  requests, complete verification and durable reopen. The initial 1,000-MiB
  plaintext fixture correctly exceeded the padded-ciphertext budget. Follow
  0048's P3 sizing at 99 attachments, and retain an explicit assertion that the
  hundredth is refused without advancing the source head. No limit was raised.
  Owned disk-backed qualification fixtures were removed after the run.
- 2026-11-11: Ordinary Android and disposable validation49 app/test packages build;
  native byte identity is checked and no test provider enters the production APK.
  The provider fixture covers unknown sizes, short/pipe reads, refusal, malformed
  data, background cancellation, stale IDs/results, password retry, editable copy,
  source digest and reopen. It uses ordinary UI (no validation path input); optional
  quick unlock is disabled only in the fresh disposable test UID to isolate the
  separate Class3 matrix. No package was installed: `adb devices -l` lists none.
  Final command results/artifact hashes are recorded in VALIDATION.md. Step 4's
  real-device evidence and step 5's fresh-context review remain open; this session
  does not supply independent review or release approval. Existing Git staging
  is preserved; no commit, branch or push.

- 2026-11-10 verification: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`,
  `sh scripts/check-matrix.sh` and `git diff --check` pass. The first
  `cargo test --locked` fails because Xvfb is absent. Restore signed Alpine
  packages in a private temporary directory, following 0050/VALIDATION.md;
  the Xvfb-backed default-debug rerun passes the clipboard tests but is
  interrupted (exit 143) during the CPU-active large-vault regression after
  more than eleven minutes in core. Final complete `cargo test --locked`
  passes (1,000 tests, zero failures, six intentional ignored tests across
  48 groups) using 0050's documented environment:
  `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`,
  `CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1`,
  `QV_TEST_KDF_JOBS=2` and
  `QV_TEST_XVFB=/tmp/qv-0049-checks.8d00rw/xorg/Xvfb`. Tests/assertions are
  unchanged. Full logs: `/tmp/qv-0049-checks.8d00rw/`, including
  `test.log`, `test-xvfb.log` and `test-validated-profile.log` for the three
  attempts. Subsequent edits only update Markdown; Rust/gate inputs remain
  unchanged. These checks cover the existing implementation, not an Android
  in-place backend. No feature implementation or security/release claim.
- 2026-11-10: Owner requests execution without another policy question and
  challenges platform-specific behavior. Use architect/developer roles to
  investigate the in-place contract. Initial `git status --short` is empty;
  checkpoint `9e1472d` includes the prior work. Retain 0009 §1.8 in-place
  semantics and supersede the conditional copy path. Primary API documentation
  and the actual store/adapter show that the document-stream bridge cannot
  provide the required SQLite journal/locking/path contract. Mark Blocked on
  replacement storage design, not owner reapproval. `adb devices -l` reports
  no connected device. No product code, spec behavior, vault, branch, commit
  or external service changed; verification of these documentation edits is
  recorded below when complete.
- 2026-11-09: Owner requested a plan and a commit-readiness check, explicitly
  intending to commit the current validation work first. Planning only. The
  recommended Android private-copy exception is unapproved; no normative text,
  production code, staging, branch, commit or push changed by this plan.
