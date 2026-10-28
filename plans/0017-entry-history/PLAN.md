# Plan 0017 — Entry history, restore and purge (roadmap 1.12)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-27 | 2026-10-27 | 0007 §1; 0003 §2/§5; 0004 §3–5; 0005 §1–2/§5.4; 0008 §1–2/§5; 0011 §2–6; 0012 §1–3 |

## Intent

Make retained entry history usable from core and the CLI. Bound retention without
forgetting suppression knowledge, restore a historical value only as a new causal
edit, and purge historical payloads without resolving conflicts or claiming erasure.

## Scope

**In scope:** default ten-version retention under existing budgets; monotonic
history floors; bounded authenticated history views; explicit historical reveal;
restore as a fresh edit; confirmed history purge; CLI history/list/show/restore/
purge; rejection, durability and suppression tests.

**Out of scope:** archive import/export and snapshots (1.13), automatic trash
expiry, network synchronization, general conflict-resolution UI (2.2), changing
the development file format, configurable larger budgets, new dependencies,
cryptographic primitives or application unsafe code. Restore with explicit
conflict consent below is limited to the historical-entry operation.

## Spec basis

| Behavior | Spec | Status | Application |
|----------|------|--------|-------------|
| Ten-version retention, floors, purge and intentional restore | 0007 §1 | Accepted | Primary contract |
| Whole-record versions and unknown optional keys | 0003 §2/§5 | Accepted | Preserve complete selected payload/extensions |
| Authentication, exact references, resource limits, one write transaction | 0004 §3–5 | Accepted | Existing manifest/object/write/anchor path |
| Join all heads, preserve concurrent edits, monotonic floors | 0005 §1–2/§5.4 | Draft | Roadmap D5 go-ahead |
| Confidential metadata/values, lock invalidation, constant-time comparisons | 0008 §1–2/§5 | Draft | Roadmap D5 go-ahead |
| History command families, masking, confirmation and errors | 0011 §2–6 | Accepted | Concrete amendment below requires D1 |
| Rejection and crash validation, no assurance overclaim | 0012 §1–3 | Accepted | Focused evidence and final gates |

**Spec changes required:** the concrete CLI amendment below, its Changelog and
specs index note. No spec is promoted to Implemented. No change to 0007's
normative retention or suppression policy.

## Decisions needed

1. **D1 — Approve the concrete history CLI amendment below.** Recommendation:
   approve it as written. The current command table does not define version
   selection, JSON, historical change-baseline/attribution or explicit consent
   for a historical restore that resolves several current heads. These affect
   data and user-visible behavior; do not guess them in code. Alternatives:
   adjust the proposal, especially conflict consent or restore state fields.
   **Resolution: owner approved on 2026-10-27 ("Yes I approve, just go ahead").**

## Design

### Adopted normative CLI amendment

Expand 0011 §4 History and snapshots, plus §5/§6 cross-references:

- `history <entry>` lists retained dominated versions, newest first by
  `(modified_at, version_id)`, with version ID, date, writer components,
  changed-field metadata and whether the entry currently has multiple heads.
  It is not an active-head list. Entry addressing remains 0011 §2: live entries
  only, with ordinary ambiguity errors; no implicit trash addressing.
- `<version>` in `history show` and `restore` is a full 32-hex version ID or an
  unambiguous prefix of at least six hex characters, with optional `@`, scoped
  to retained history of the addressed entry. Invalid syntax is 2, absent or
  suppressed is 4, ambiguous is 5 with matching IDs. Never search other entries.
- A version vector is not an author/device identity. List its writer IDs and
  counters; display origin device as unknown unless authenticated attribution
  exists. Do not invent an author from the largest counter or writer ID.
- Changed fields are compared with the current deterministic browsing
  representative, explicitly labelled `compared_to`; this is a value comparison,
  not an assertion about causal parentage or authorship. Include changed field
  IDs/names and changed top-level entry properties, never old/new values.
  Compare complete fields (presence, order, name, kind, protection and value);
  protected-value comparisons must satisfy 0008 §2. Unknown optional content
  differences are labelled unknown-extension changes, not silently ignored.
- `history show <entry> <version> [--reveal]` shows exactly that retained version.
  Default masking and explicit reveal follow current `show`; never enable copy,
  TOTP generation or generic current-field reveal through a history handle.
- `restore <entry> <version> [--resolve-conflicts]` creates a new random version
  ID and clock joining all current heads with the reserved local counter.
  With multiple current heads, fail 8 unless `--resolve-conflicts` explicitly
  authorizes replacing all known heads with the selected historical payload.
  Reject that flag on other history operations. An unseen future concurrent edit
  is not covered by this choice. Restore the complete selected Entry payload and
  record extensions, except set modification time to now, keep current creation
  time and current live/deleted state, and require its historical destination
  group to exist and be live. Otherwise fail 1, with no edit; do not silently
  remap to root or revive an entry/group. Attachments are separate records and
  are neither restored nor removed by this operation.
- `history purge <entry>` requires confirmation (`--yes` allowed). Explain that
  it advances the suppression floor to the join of all currently known head
  clocks; those heads remain active but are suppressed if later dominated.
  Concurrent unseen history may survive. Preserve active heads, conflicts and
  permanent tombstones. Say this is local logical purge, no server acknowledgement
  is applicable in the current offline implementation, snapshots/independent
  copies may retain data and no secure erasure is promised. With
  `--password-stdin`, require `--yes` before unlock if confirmation is needed.
- Read operations accept `--json`; mutations reject JSON before unlock.
  List JSON is `{ "versions": [...] }`; each row has `version_id` (32 lowercase
  hex), `modified_at` (existing RFC3339 convention), `device` (null without
  authenticated attribution), `writers` (array of `{id,counter}`), `conflict`
  (boolean), `compared_to` (32-hex ID), `changed_properties` (array of fixed
  property labels), `changed_fields` (array of `{id,name}`; removal uses the old
  name), and `unknown_extensions_changed` (boolean). No values or content hashes.
  Sort fields by ID and properties by fixed label; writer IDs ascending.
  Historical-show JSON uses the current show entry schema, identifying the
  selected `version_id`; masked protected values are null. Human output escapes
  all stored names. Purge output explicitly states local-only status and limits.
- Existing errors retain their codes: 7 integrity, 8 unresolved restore conflict,
  9 bounds, 6 stale handles/changed file; cancellation and invalid restore
  destination are 1. No errors contain payload values. Explicit restore reports
  success only after DB commit and external anchor advancement.

### Components and interface sketch

Keep existing crates and trust boundaries. Frontend vault access goes only
through core. Reuse qv-model Clock/HistoryFloor and existing protected types.
Private `history.rs` modules in store/core/CLI keep changes focused.

```rust
// qv-store: within the existing Write transaction, never an alternate writer.
Write::purge_history(record: RecordId) -> Result<(), StoreError>;
// Internal retention runs before seal_manifest/commit, reading historical
// objects through authenticated roles and applying the policy below.

// qv-core: opaque session/entry/version-bound historical handle, redacted Debug.
Session::history(entry: EntryHandle) -> Result<Vec<HistorySummary>, CoreError>;
Session::history_entry(version: HistoryHandle) -> Result<EntryDetail, CoreError>;
Session::reveal_history(version: HistoryHandle, field: FieldId)
    -> Result<FieldValue, CoreError>;
Session::restore_history(version: HistoryHandle, resolve_conflicts: bool)
    -> Result<EntryHandle, CoreError>;
Session::purge_history(entry: EntryHandle) -> Result<(), CoreError>;
// HistorySummary contains the handle, timestamp, clock components, current
// conflict flag, compared-to version, changed-property labels and protected Text
// field names. Expose version_hex() and metadata writer IDs, never raw keys/SQL.
```

Every historical use rechecks session, record kind and exact current retained
reference. A purged handle is stale, not permission to decrypt an old object.
Current FieldHandle reveal remains head-only; do not broaden it for history.
Read-only recovery sessions may read history but cannot restore/purge. Listing
conflicts never picks a fabricated combined record. History purge may operate
on conflicts because it changes no heads or payloads; restore requires D1's
explicit consent. Final tombstones remain inaccessible and unmodified.

### Retention and floors

Use authenticated version.modified_at (not arrival time or causality) plus ID
for deterministic ordering, with a default target of ten retained histories
per record. Apply the existing general version policy to record histories, not
only CLI-visible entries; never prune active heads or permanent tombstones.
Use existing HistoryFloor joins; stored floor components never regress.

For each record, choose the newest N historical versions as protected retained
candidates. Older dominated versions are eligible, not automatically removable.
Starting with the old floor, consider eligible clock-component advances in
deterministic writer/counter order. Accept an advance only if the *cumulative*
candidate floor suppresses none of the protected retained candidates. This is
0007 §1.3's conservative component rule: never combine individually safe
advances without checking their combined effect. Drop only eligible versions
actually covered by the resulting floor; keep anything that cannot safely be
suppressed. N is a target, not permission to violate suppression knowledge.
At N=0 the eligible set is all history; explicit purge separately joins all
active head clocks into the existing floor and removes covered history while
leaving every head intact. The next ordinary edit must filter old heads moved
to history against that floor before sealing, so purged heads cannot reappear.

Before sealing enforce object/count/clock-component/ciphertext/manifest budgets.
If retaining N does not fit, deterministically retry with a smaller retention
target down to zero, never relaxing active/floor/tombstone budgets. If no safe
candidate fits, abort the write with LimitExceeded and preserve accepted state.
Do not reinterpret integrity failures as budget pressure. Process bounded
metadata vectors and one authenticated payload at a time; never accumulate
whole historical records for all versions. Check cancellation during scans.

Floor updates and reference release happen in the candidate manifest, then
reuse existing immutable objects → manifest → local head → referenced-row
pruning → durable DB commit → external anchor → success. No plaintext staging,
new tables or extra commit. Keep core index aligned after durable anchor failure
even on a floor-only write; no synthetic payload version/timestamp/counter for
purge. Retain read-only conflict/suppression fixtures for old-version re-delivery
through qv-model's merge API; real archive ingestion waits for 1.13/2.2.

### Secret handling and errors

Use Text/FieldValue and zeroizing encode/diff intermediates. Summary budget is
64 MiB including changed names/arrays; bound vector allocation before growth.
Protected value differences use existing confidential ContentHasher and
SecretArray::ct_eq, with the value's Text/Bytes variant compared separately;
do not add a crypto dependency or use ordinary equality on protected bytes.
Do not persist diff hashes. Hashes/temporary records drop promptly; no payload
Debug, errors or argv. Unknown extensions compare canonical protected encodings.
Use current CoreError/StoreError variants and CLI error mapping; no new codes.

**Dependencies:** none. No unsafe, format migration or MSRV change.

## Steps

### Step 1 — Adopt the concrete CLI amendment

- [x] **Do:** After D1 approval apply the proposal, Changelog and spec-index note.
- **Files:** `specs/0011-cli.md`, `specs/README.md`, this plan.
- **Done when:** version selection/output/restore/purge contracts precede code.
- **Verify:** inspect cross-references; `git diff --check`.

### Step 2 — Store retention, suppression and floor-only purge

- [x] **Do:** Add retention scan/planning and manifest floor/reference mutation;
  integrate before commit budget validation, preserve rollback and anchor order.
  Add model helpers only if the policy needs them; reuse existing floor joins.
- **Files:** `crates/qv-store/src/{history,manifest,write,unsupported,lib}.rs`,
  related store tests; `crates/qv-model/src/merge.rs` and tests if needed.
- **Done when:** N=10 with deterministic ties; safe lower targets under budgets;
  no retained candidate covered; floor monotonic; purge preserves multiple heads;
  next edit does not reintroduce a suppressed old head; unreferenced rows pruned.
- **Verify:** `cargo test --locked -p qv-store history`;
  `cargo test --locked -p qv-model merge`.

### Step 3 — Core historical handles, diffs, reveal and intentional restore

- [x] **Do:** Implement the interfaces above, bounded protected metadata/diffs,
  stale/session/conflict checks, floor-only commit and full-record restore.
- **Files:** `crates/qv-core/src/{history,views,edit,session,lib}.rs`, tests.
- **Done when:** historical read authenticates; current reveal remains head-only;
  restore has fresh ID/clock, preserves unknown keys and leaves attachments alone;
  lock/read-only/foreign/purged handles and unavailable groups fail correctly.
- **Verify:** `cargo test --locked -p qv-core history`;
  `cargo test --locked -p qv-core lock`.

### Step 4 — CLI history/show/restore/purge

- [x] **Do:** Wire commands, version resolver, escaped/JSON output, masking,
  explicit conflict consent, purge confirmation and signal checks.
- **Files:** `crates/qv-cli/src/cli.rs`, `src/cmd/{mod,history,show}.rs`,
  history integration/PTY tests and common fixtures.
- **Done when:** preflight errors precede unlock, no accidental secret output;
  full/prefix/absent/ambiguous version selection uses the scoped contract;
  production restore and purge persist across fresh commands.
- **Verify:** `cargo test --locked -p qv-cli history`.

### Step 5 — Cross-layer rejection, suppression and crash evidence

- [x] **Do:** Cover corrupt/missing historical objects; component-join traps;
  concurrent/tombstone preservation; duplicate/old-version re-delivery; budget
  pressure; cancellation and existing transaction/anchor crash boundaries.
- **Files:** scoped tests in qv-model/store/core/CLI and existing crash hooks.
- **Done when:** no suppression resurrection, conflict loss or accepted-state
  replacement on failures; post-durable anchor errors are reported accurately;
  old backup semantics exercised through model delivery fixtures without
  claiming archive import is implemented. Production CLI works network-blocked.
- **Verify:** focused history suites above; `cargo test --locked -p qv-store crash`;
  `unshare -rn cargo test --locked -p qv-cli --test history`.

### Step 6 — Documentation and final gates

- [x] **Do:** Update implemented responsibilities/help and phase records, then
  run all final gates. Leave changes uncommitted for fresh-context next review.
- **Files:** CHANGELOG, ARCHITECTURE §3, affected crate docs, this plan,
  plans index and roadmap phase/log.
- **Done when:** all acceptance evidence complete, documented limits accurate,
  no unsupported spec-completion/erasure/security claims and all gates pass.
- **Verify:** `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`,
  `git diff --check`. Use private Xvfb for clipboard integration.

## Test plan

Step checks are focused; full AGENTS.md gates run on the final tree with outputs
and exit status retained under /tmp/opencode. No dependency changes planned;
deny/vet become required if that changes (and approval is required first).
Exercise 0012 rows old-date concurrent edits, order-dependent merge, deleted-entry
resurrection, rotation/purge ambiguity (local only), incomplete commitments,
hostile input/budgets, secret copies, CLI leakage and anchor crash windows.
Include deterministic equal timestamps, non-dominating retained clocks,
cumulative-floor combination traps, future/old dates, unknown optional keys,
masked and explicit reveal, no-origin attribution and all restore error paths.
Tests and source review are evidence, not security proof.

## Risks and stop conditions

- D1 is resolved by owner approval; further normative changes still need approval.
- Stop for required layout/profile/dependency changes or a scope split beyond
  the roadmap; archives/snapshots/general resolution are not shortcuts here.
- Never remove a history payload without preserving its suppression knowledge,
  or discard active heads/floor components to make a budget pass.
- Restoration must not silently resolve conflicts, resurrect final tombstones,
  fabricate origin devices or remap unavailable groups.
- Do not broaden current-field handles into historical capabilities. Report
  nonlocal validation/retention failures instead of bypassing existing tests.

## Documentation

- [x] CHANGELOG Unreleased: history, restore and purge, local/copy limits.
- [x] ARCHITECTURE §3: implemented core/store/CLI history responsibilities.
- [x] 0011 amendment/Changelog and specs index; no spec promotion.
- [x] Crate/API/help docs: historical handle lifetimes and suppression boundary.
- [x] Plan/index/roadmap status, evidence and fresh-context handoff.
- AGENTS/workflow/layout conventions: no change.

## Revisions

- 2026-10-27: Retention stays in write.rs/manifest.rs rather than adding a
  store history module with no separate interface. Candidate metadata holds
  timestamps/IDs/clocks only; one authenticated record is decrypted per scan
  iteration. Conservative component-floor planning may retain more than ten
  versions when date ordering opposes causal order (0007 §1.3); tests explicitly
  cover this, instead of weakening floors to meet a numerical target. Existing
  history_depth remains reserved, consistent with this plan's fixed default ten;
  settings.rs docs updated to remove the obsolete pre-1.12 wording. Retention
  budget fallback is exercised with an injected fit predicate using the same
  production planner, plus existing real global-budget validation tests.

- 2026-10-27: Integration details: add `Write::commit_cancellable` (same
  transaction and durability contract) so retention scans and final pre-commit
  work can stop on session lock; maintain unsupported-target stubs. Add
  `Extensions::content_eq` in model text.rs, delegating confidential digest
  comparison to existing reviewed crypto; this exposes no extension contents.
  Core reexports existing RandomId/WriterId metadata types and adds FieldHandle's
  field_id accessor for the separate historical reveal API; current-field reveal
  authorization remains head-only. No dependency or format change. An initial
  bulk history-decryption API was removed before handoff in favor of one
  authenticated historical record per iteration.

## Execution log

- 2026-10-27: Phase started in architect role after the owner-requested phase
  1.11 remediation and completed resumed review (490 workspace tests pass, 2
  ignored; all gates pass). Owner explicitly authorized same-session continuation
  without the intervening commit. Read roadmap approvals/constraints/phase 1.12,
  0007 §1 and relevant model/storage/session/CLI requirements and code. Existing
  model already has componentwise HistoryFloor join and suppression; store has
  manifest history/reference hooks but no retention/purge path; core's field
  handles intentionally remain head-only. Proposed six-step plan above. D1
  blocks standing approval because a concrete normative CLI amendment is needed.
  No history product code, normative text, phase completion checkbox or dependency
  changed; no commit, push, branch, personal display or phone operation.

- 2026-10-27: Owner approved D1 and directed implementation to proceed. Status
  moved to In progress; step 1 is complete and implementation continues.

- 2026-10-27: Steps 2–5 implemented. Store retention authenticates history,
  computes conservative cumulative floors, retries lower targets only on budget
  errors, and releases payload references atomically before durable commit and
  anchor advancement. Floor-only purge never creates a record version/counter;
  later edits filter suppressed prior heads. Same-transaction dropped objects
  are included in reference pruning. Core handles recheck exact retained roles,
  preserve head-only generic reveal, diff confidential values/extensions via
  protected digests and restore unknown fields in a fresh whole-record edit.
  CLI masking/JSON, scoped resolver, confirmation and conflict consent are wired.
  No dependency, lockfile, schema or MSRV change.
- 2026-10-27: Focused checks pass: store history (including cumulative-floor
  traps, safe old-date retention, corruption/cancellation, budget fallback,
  monotonic floors and purge crash windows); core history (6 including lock
  and read-only/conflict/durable-anchor paths); model merge suite; production
  history tests in a blocked network namespace (3 including PTY confirmation
  cancellation/SIGINT/TERM/HUP). Logs /tmp/opencode/qv17-review/phase17-*.log.
  Full gates and final documentation verification remain in step 6.

- 2026-10-27: Step 6 verification in progress. First full final run passes:
  509 workspace tests, 0 failures, 2 ignored (private-Xvfb clipboard integration
  and doctests included); SPDX/fmt/Clippy/diff checks pass. Separate store crash
  suite passes (8), core lock suite passes (10), model merge suite passes (17).
  Added a missing-history-object rejection/accepted-sequence regression and
  corrected stale qv-store crate docs after that run. Repeating all final gates
  on those inputs: handoff SPDX/fmt/Clippy/diff pass; handoff full tests pending.
  Logs /tmp/opencode/qv17-review/phase17-{final,handoff}-*.log. No tests weakened
  or ignored for this phase. Original staged owner work is preserved; new phase
  changes remain uncommitted. Independent phase review is for the next fresh
  session, not claimed by this implementation session.

Found, not fixed: a protected newest-by-date history may conservatively retain
more than ten dominated versions when clock/date order opposes safe pruning;
this is required by 0007 §1.3, not permission to drop suppression knowledge.
History-depth configuration remains reserved; the implemented target is ten.
Archive import, snapshots, network purge acknowledgements and general conflict
resolution are later phases; current old-delivery evidence uses real model
merge/suppression, not an invented archive importer. No secure erasure or
proof-of-security claim. No personal clipboard, display or phone operations.

- 2026-10-27: Step 6 complete. Final handoff tree gates pass:
  `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`
  (510 passed, 0 failed, 2 ignored, including doctests and private-Xvfb clipboard
  integration). Logs /tmp/opencode/qv17-review/phase17-handoff-{spdx,fmt,clippy,test}.log.
  No dependency changes, so no new deny/vet run required. Final diff check passes;
  subsequent completion records are Markdown only. Plan Implemented, roadmap
  phase 1.12 complete. Changes uncommitted, owner staging preserved. Next action
  is owner commit and fresh-context reviewer for plan 0017, before phase 1.13.
