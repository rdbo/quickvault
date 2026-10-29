# Plan 0020 — Password change and recovery flows (roadmap 1.14)

| Status | Created | Implemented | Specs |
|--------|---------|----------|-------|
| Approved | 2026-10-29 | 2026-10-29 (owner: fix it and do the phase; standing approval, roadmap 0002) | 0002 §1–4/§8; 0004 §3.6/§5; 0005 §5.4 (D5); 0007 §3; 0008 §1–3/§5 (D5); 0010 §4.2; 0011 §3–6; 0012 §1 |

## Intent

Implement master-password replacement, protected recovery-phrase redisplay,
and recovery of an existing local vault without its old password. Complete
plan 0019's owner-authorized error correction and resumed review first.

## Scope

In scope: atomic operational slot/encrypted keyslot record/header MAC update;
phrase unlock; session APIs; `passwd`, `recovery show`, `recover <path>`;
post-change snapshot deletion offer; cancellation, crash and terminal evidence.
Out of scope: new KDF profiles, generation rotation (1.15), archive import from
a standalone phrase, self-contained archives, network/sync, new dependencies,
schema/format changes and unsafe. `recover <path>` operates on an existing
`.qvault` file. Archive recovery remains partial spec coverage, not a claim of
fully implementing 0004 §6.4.

## Spec basis

| Behaviour | Spec | Status | Notes |
|-----------|------|--------|-------|
| Atomic complete slot/record replacement, same VK | 0002 §1.4/§2.1/§3.4 | Accepted | Fresh slot ID/salt/nonce; current fixed profiles |
| Phrase representation and redisplay | 0002 §4 | Accepted | Existing reviewed encoding; password reauthentication |
| Single durable write/anchor path | 0004 §5; 0005 §5.4 | Accepted / Draft | D5 covers local anchor recovery |
| Recovery copy and old-snapshot offer | 0007 §3.2–3.5 | Accepted | Explicit consent; no erasure claim |
| TTY secrets, weak passwords, exits | 0011 §3–6; 0010 §4.2 | Accepted | Reuse existing bounded protected prompts |
| Migration/rollback/secret lifecycle evidence | 0012 §1; 0008 §1–3/§5 | Accepted / Draft | D5 covers memory sections |

Spec changes required: None; implement existing contracts. The phrase is a
candidate VK: malformed phrases or failure of initial key confirmation through
the header MAC report wrong phrase (3); once that MAC confirms the key,
head/manifest/object/anchor integrity failures remain integrity (7). A wrong
valid phrase and a damaged header cannot be distinguished at that initial
confirmation; document this limitation rather than inventing a verifier.

## Decisions needed

None. The owner's 2026-10-29 instruction explicitly authorizes correcting 0019
and implementing this phase without a commit boundary. Storage support is
necessary for the already specified atomic slot update; the roadmap's abbreviated
core/CLI file list is extended to the existing qv-store internals, preserving
component boundaries and the single write path. Record this narrow extension
in the roadmap. No new behavior, dependency, crypto profile or format is selected.

## Design

Components: store owns key confirmation, password slots and SQL; core owns
session authorization/index updates; CLI owns protected TTY interaction.

Interfaces (names may follow surrounding conventions, with these contracts):
- `VaultFile::unlock_with_phrase(&[u8], &AnchorDir)` returns `(UnlockedVault,
  AnchorStatus)` after bounded phrase decode, header MAC, full ordinary unlock
  checks and anchor comparison. It never silently adopts a baseline.
- `UnlockedVault::recovery_phrase(&MasterPassword) -> RecoveryPhrase` checks
  file identity and reauthenticates the current slot/header; no raw-key bridge.
- `Write::stage_password(&MasterPassword, PasswordKdfProfile,
  PasswordWrapProfile) -> Keyslot` builds a complete replacement descriptor,
  preserving its unknown extensions, and stages the operational row/header MAC.
  Commit refuses unless exactly the matching encrypted keyslot head is present.
- `Core::unlock_with_phrase(path, phrase: &[u8], cancel)` returns the same
  read-only recovery session/anchor status as password recovery unlock, with
  automatic snapshots deferred until explicit recovery work is safely complete.
- `Session::change_password(&MasterPassword, cancel)` uses common
  `commit_with`: reject conflicting keyslot heads, preserve record extensions,
  stage the descriptor and make one new causal keyslot version. Current profile
  IDs are V1; supplying the same password exercises the KDF-only rewrap path.
- `Session::recovery_phrase(&MasterPassword)` uses a serialized read and drops
  the result if locking raced; password replacement uses mutation semantics
  and preserves durable success after the commit boundary.
- A typed `StoreError::WrongPhrase`, mapped to CLI 3, distinguishes the fixed
  redacted message from WrongPassword without carrying secret data.

Durability: stage fresh descriptor, encrypted causal record, header MAC,
manifest/head/counter in the existing IMMEDIATE transaction; check cancellation
before COMMIT; update in-memory slots immediately after durable commit even if
anchor advancement fails, then advance anchor/report. Rollback/drop keeps old
slot and in-memory header. Add a crash point after slot/header SQL staging;
reuse all existing mutation/anchor crash points. There is no second commit path.
A failed anchor update may leave a committed password change, as other writes;
CLI must report that possibility without claiming rollback.

Recover: prompt for a bounded no-echo phrase, unlock/verify it, display any
anchor warning. Missing/mismatched anchors require an explicit confirmation
that this becomes a baseline and cannot prove freshness; create/pin a mandatory
verified recovery snapshot before adopting the baseline. A normal anchored
vault can reset its password without accepting a new baseline. Password reset
uses the same replacement transaction. Existing baseline adoption remains a
separate explicit transaction; an interruption between adoption and replacement
leaves the original password valid. No automatic rollback bypass on normal unlock.

CLI: `passwd` and `recover` reject `--password-stdin` and `--json` before reading
secrets (further-secret prompts); require input/output TTY because the shared
password chooser offers a generated passphrase on the alternate screen.
`recovery show` rejects `--json`, requires stdout TTY, reads current password
through the existing master-password path and explicitly reauthenticates it
before alternate-screen display. `--yes` never skips the five-second weak
password question or the post-change snapshot deletion consent. After success,
list authenticated snapshots existing before the change, name their count and
offer deletion with a fixed warning about independent copies. Delete only after
explicit confirmation; decline retains ordinary policy. Use existing snapshot
IDs for the offer to avoid depending solely on a potentially anomalous clock.
A recovery snapshot protecting adoption is released only after the operation;
release/deletion errors do not falsely describe the committed reset as undone.

Secrets: reuse SecretBytes-backed TTY input, MasterPassword, RecoveryPhrase,
VaultKey and existing key wrappers. No Clone/Display/log/argv/env secret path.
Phrase input bounded at 1024 bytes; exactly 24 words validated by crypto. Unknown
profiles fail before KDF; new fixed profiles are not invented for a migration
unit test. Cancellation checked before/after KDF and before durable commit.

Errors: existing 1/2/3/4/6/7/8/9 mappings, adding WrongPhrase -> 3. Keyslot
conflicts -> 8; failed/cancelled precommit operations leave accepted data intact;
no hidden baseline reset. All messages fixed/redacted; vault text escaped.

Dependencies: None. Existing crypto, model, SQLite, TTY and cancellation APIs.

## Steps

### Step 1 — Storage credentials and transaction integration

- [x] **Do:** add phrase unlock, reauthentication, complete staged descriptor,
  commit consistency checks, transactional slot/header writes and post-durable
  in-memory repair. Add unsupported-platform stubs and WrongPhrase mapping.
- **Files:** qv-store/src/{credentials,write,vault,slot,error,crash,lib,unsupported}.rs.
- **Done when:** old/new password switch atomically, same VK/generation,
  record/descriptor extensions preserved; phrase unlock verifies all ordinary
  state; partial staging/cancellation fails closed.
- **Verify:** `cargo test --locked -p qv-store credentials`.

### Step 2 — Core session flows

- [x] **Do:** implement phrase sessions, change-password and phrase redisplay
  with common commit/index/cancellation semantics; expose typed error mapping.
- **Files:** qv-core/src/{credentials,setup,lib,session,snapshot}.rs; qv-cli/src/exit.rs.
- **Done when:** session stays usable after password replacement, wrong
  reauthentication fails unchanged, old password fails/new works, locking before
  commit cancels and after commit preserves the actual outcome.
- **Verify:** `cargo test --locked -p qv-core credentials`.

### Step 3 — CLI credentials and snapshot offer

- [x] **Do:** add commands/dispatch, share password selection/phrase display,
  implement phrase recovery and explicit anchor baseline consent/snapshot,
  offer deletion only after successful password change, update error hints.
- **Files:** qv-cli/src/{cli,exit,cmd/mod,cmd/init,cmd/credentials}.rs.
- **Done when:** all three commands follow TTY/stdin/JSON/weak-password rules;
  no displayed phrase remains in scrollback; destructive snapshot consent is
  explicit and old copies are not described as cryptographically erased.
- **Verify:** `cargo test --locked -p qv-cli --test credentials`.

### Step 4 — Crash, migration and rejection evidence

- [x] **Do:** test each slot/transaction/anchor crash boundary, exact old/new
  credentials after reopen, unchanged non-keyslot object envelopes and
  generation; wrong/checksummed-foreign phrase, corruption, lock races,
  invalid profiles, failed/partial staging, protected TTY and snapshot consent.
- **Files:** credential tests in store/core; qv-cli/tests/{credentials,common}.rs.
- **Done when:** failures never leave mismatched operational/encrypted slots,
  copied old credentials remain a documented limitation, and required 0012
  Migration coupling/Whole-file rollback/Implicit server prerequisite evidence
  is recorded without a security proof claim.
- **Verify:** focused commands above; offline namespace probe when available.

### Step 5 — Documentation, gates and implementation review

- [x] **Do:** update component coverage, CLI/store/core docs, changelog,
  roadmap/index and this log; run all gates and inspect final implementation.
- **Files:** ARCHITECTURE.md §3; CHANGELOG.md; crate docs; plans.
- **Done when:** all checks pass, phase ticked with accurate limits and fresh
  context review still required next session. No spec status promotion.
- **Verify:** `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`,
  `git diff --check`. Deny/vet only if dependency inputs change (none planned).

## Test plan

Focused checks above while editing, all AGENTS gates on final tree with private
Xvfb. Keep complete output/exit status in /tmp/qv20. No new dependency or fake
crypto profile. Crash harness copies DB/journal/anchor at real boundaries;
protected TTY tests exercise cancellation and alternate-screen cleanup. Existing
KDF/mobile benchmarks and format freeze remain 1.16, rotation remains 1.15.

## Risks and stop conditions

Stop for unresolved spec conflict, new crypto profiles/format/dependency,
unsafe, secrets in diagnostics, non-atomic slot replacement, or an implicit
anchor bypass. Initial phrase-key confirmation cannot distinguish a foreign
valid phrase from damage to the only header confirmation; later authenticated
failures remain integrity errors. Old slots/snapshots do not revoke copies of VK.
Do not claim all archive recovery or profile migration variants are implemented.

## Documentation

- [x] CHANGELOG.md — credentials and restore correction.
- [x] ARCHITECTURE.md §3 — updated implementation coverage; no new component.
- [x] Specs — no normative amendment or status change.
- [x] AGENTS.md — no conventions/layout change.
- [x] Plans — status/index/roadmap, evidence and remaining limitations.

## Revisions

2026-10-29: Implementation inspection found the existing pre-change snapshot
deletion helper used read-result cancellation semantics despite removing files.
Use the mutation wrapper with a pre-deletion cancellation check, so a lock after
removal reports the actual completed count. Add before/after-removal lock-race
coverage using the existing hooks. No new API or deletion policy; the CLI is
this helper's first production consumer in 1.14.

## Execution log

2026-10-29: Approved by explicit owner continuation and standing approval,
roadmap 0002. Plan 0019 correction/re-review prerequisite completes before
implementation. Store extension implements the specified existing atomicity;
no new format, dependency or owner decision. Keep all changes uncommitted.

2026-10-29: Steps 1–4 implemented. The current fixed-profile stage and matching
causal keyslot record commit together with the operational row and header MAC;
partial/mismatched/unstaged changes are refused. Cache updates occur immediately
after durability, before anchor error reporting. Phrase/key confirmation and
current-password reauthentication reuse existing protected crypto APIs. Core
uses commit_with and its established index/cancellation/lock semantics.

Focused evidence: five store credential tests (including nine crash points,
full old-object envelope preservation, same-password rewrap, partial staging,
mismatch and cancellation); five core tests (including snapshot deletion and before/after commit
lock races and mandatory-copy/explicit-anchor recovery); six production CLI
TTY tests (phrase display cleanup, wrong credentials, weak-password delay even
with --yes, preflight, explicit baseline and snapshot-consent flows). Logs in
/tmp/qv20. Initial Clippy findings were local test-helper/style issues and were
corrected; final full gates and same-context inspection follow. No external
dependency, profile, schema, format or spec amendment. No independent review
or security-proof claim; next fresh session must review this phase.

2026-10-29: Same-context reviewer inspection traced protected input/phrase
lifetimes, candidate-key confirmation vs later integrity errors, staged-slot
binding, SQL rollback/commit and in-memory slot/anchor ordering, common core
index repair and before/after commit lock races. Found and fixed the existing
snapshot deletion helper's read-result wrapper: it now reports completed file
removals after a lock, with a before/after-removal regression. Five focused core
credential tests pass. No new public API, format or deletion consent policy for
this correction. Final gates cover the combined tree after this change; status
remains In progress pending results. Independent fresh-context review remains
required before 1.15.

2026-10-29: Full verification caught the pre-existing crypto-error mapping test
still expecting WrongPhrase -> Internal; updated that exact assertion to the
new typed WrongPhrase authentication mapping (CLI 3), retaining all other
cases. A separate private-Xvfb run hit a startup timeout while earlier checks
were still active. No clipboard code/assertions or timeout changed. Final gates
are repeated sequentially, with all verbose failure logs retained. Strengthened
rewrap evidence to include real entry history and multi-chunk attachment
ciphertext using the existing verification fixture.

2026-10-29: Step 5 complete. All final required gates pass: SPDX, fmt and
Clippy `--all-targets --locked -- -D warnings` (`handoff-{spdx,fmt,clippy}.log`),
and full `cargo test --locked` with private Xvfb (`final4-test.log`): **591
passed, 0 failed, 2 pre-existing ignored**, across 34 reported groups. Private
clipboard integration ran and passed. The only source edit after that run's
build was a comment explaining the existing test-only lint allowance; no test
logic or product input changed, and SPDX/fmt/Clippy were repeated afterward.
`git diff HEAD --check` passes. Full logs in `/tmp/qv20/`; earlier failures
remain recorded. No dependency input changed, so deny/vet were not required.

The network-namespace probe still fails with `No space left on device`
(`network-namespace.log`). The networking-blocked test's runtime skip is not
claimed as a pass, despite the harness aggregate. No device benchmark,
extended fuzz campaign, external audit, global freshness, revocation of copied
keys or cryptographic-erasure claim.

Documentation and roadmap/index updated. Plan 0019's resumed review is
Approved/Reviewed after the explicit owner-authorized correction. Plan 0020 is
Implemented and has same-context implementation inspection only; preserve the
fresh-context reviewer prerequisite before phase 1.15. Recovery here targets an
existing local vault; standalone phrase/archive import and real future-profile
migration choices remain outside this implementation. All changes uncommitted;
no branch, commit or push. The owner's existing staged changes are preserved.
