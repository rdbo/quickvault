# Plan 0014 — CLI editing, trash and signal cleanup (roadmap phase 1.10b)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-27 | 2026-10-27 | 0011 §1–6; 0003 §4–5; 0007 §2; 0008 §1–3; 0012 §1–2 |

## Intent

Finish CLI entry/group editing and trash operations through the existing core,
with protected prompts and terminal cleanup on signals. Resolve the clipboard
dependency's secret-buffer handling separately before implementing copy commands.
The owner approved this delivery split on 2026-10-27.

## Scope

**In scope:** `add`, `edit`, `mv`, `mkdir [-p]`, `rm [-r]`,
`trash ls|restore|empty`, `--notes`, `-i`, generator options for entry passwords,
and SIGINT/SIGTERM/SIGHUP cancellation with terminal restoration. PTY and
persisted-vault regression tests; documentation and gates.

**Out of scope:** phase **1.10c**: `copy`, `totp --copy`,
`generate --copy`, clipboard timeout/countdown, and their library integration.
Also history, attachments, anchor adoption, recovery, conflicts and sync.
No core API, on-disk layout, normative behavior or cryptographic change.

## Spec basis

| Behavior | Spec | Status | Notes |
|----------|------|--------|-------|
| Command options and exit mapping | 0011 §1–2, §4 Editing, §6 | Accepted | Existing addressing/selection/error modules |
| Prompts, notes, scripting refusals, no plaintext temp files | 0011 §3.1–3.5 | Accepted | Check prompt requirements before unlocking or mutating |
| Escaping, JSON for trash listing, confirmation | 0011 §5 | Accepted | Existing Out/Json |
| Fields, kinds, protected defaults and stable IDs | 0003 §5 | Accepted | Core drafts preserve unknown fields/keys |
| Group edits and trash | 0003 §4; 0007 §2 | Accepted | Existing core mutation APIs |
| Secret lifetime and cancellation | 0008 §1–3 | Draft | Roadmap D5 go-ahead applies |
| Validation evidence | 0012 §1–2 | Accepted | CLI argument leakage; implicit server prerequisite |

**Spec changes required:** None for this editing phase. Clipboard
requirements remain unchanged and unimplemented until 1.10c.

## Decisions needed

1. **D1 — Split remaining CLI work at the clipboard boundary.** The previous
   approval covers arboard 3.6.1, X11-only features and license exceptions,
   but source inspection found retained plaintext outside the required secret
   containers and a second ordinary write buffer in its X11 transport. Neither
   has zeroizing destruction. Wrapper-side wiping cannot wipe these allocations.
   Ordinary `clear()` also ignores current ownership; a value comparison would
   not prove ownership and would introduce a race.

   **A (recommended):** approve this narrower 1.10b (editing/trash/signals),
   then require a dedicated 1.10c architect plan for clipboard memory handling,
   ownership-safe release and transport-buffer review. That plan must identify
   exact patches/dependencies and obtain approval for any scope/dependency or
   spec exception. No clipboard protection claim is made meanwhile.

   **B:** retain the original 1.10b scope and re-plan its clipboard dependency
   chain before any implementation. This may require maintained dependency
   patches or another adapter; neither approach is approved here. A direct
   x11rb adapter alone does not remove x11rb's write-buffer copies.

   Resolution: owner approved option A on 2026-10-27 ("fine"). Plan
   Approved under that explicit approval, then In progress; no open decision.

### Clipboard evidence behind D1

Reconfirmed 2026-10-27 from the versioned upstream archives. Source-only
review artifacts: `/tmp/qv-review19-deps/{arboard-3.6.1,x11rb-0.13.2}.rs`.
No clipboard crate has been added to either application workspace.

Source archives fetched from the crates.io versioned download endpoints;
only the two cited files were read, without executing dependency code.

- arboard `src/platform/linux/x11.rs`: `ClipboardData` (191–196) derives
  Debug/Clone over ordinary bytes; `set_text` (967–982) moves text into that
  storage. SelectionClear (834–835) drops it without wiping. `Inner::clear`
  (229–237) unconditionally sets the selection owner to NONE. Drop destroys
  its own window after optional manager handover; exclude-from-history inhibits
  that handover, but does not add memory wiping.
- x11rb `src/rust_connection/write_buffer.rs`: `WriteBuffer` (8–10) stores
  ordinary queued bytes; `write_helper` (80–120) copies short outgoing data,
  and `flush_buffer` drains it without zeroizing storage. 0.13.2 is an inspected
  compatible version, not a new resolved dependency or an assertion about every
  version of the transport.
- Upstream references: [arboard 3.6.1 source](https://crates.io/api/v1/crates/arboard/3.6.1/download),
  [x11rb 0.13.2 source](https://crates.io/api/v1/crates/x11rb/0.13.2/download),
  [arboard clipboard API](https://docs.rs/arboard/3.6.1/arboard/struct.Clipboard.html),
  [Linux sensitive-hint API](https://docs.rs/arboard/3.6.1/arboard/trait.SetExtLinux.html).

This is a prospective dependency-integration blocker, not a finding in shipped
QuickVault clipboard code: that code does not yet exist. OS clipboard recipients
can still retain copies even after application buffers are hardened (0008 §3).

## Design

**Components touched:** only `qv-cli` plus workspace dependency policy/lockfile
and docs. Every vault operation uses existing `qv-core` entry points. Keep
crypto/store/model APIs unchanged. No unsafe code.

**Private interfaces:** new `signals.rs` owns safe signal-hook flag registration
and a process cancellation flag; `check() -> Result<(), CliError>` and a bounded
poll interval (at most 100 ms) let blocking terminal loops observe cancellation.
Registration lives for the process; RAII restores termios/alternate screens.
No signal callback locks a mutex, accesses a session or performs clipboard I/O.
Errors remain redacted and cancellation uses existing exit 1.

`term.rs` gains bounded TTY text and multiline input returning `Typed` (locked
SecretBytes, exposed only by reference). Single-line field values and notes are
at most 256 KiB, matching model limits. Notes preserve LF and finish with Ctrl-D;
Ctrl-C or a termination signal aborts without saving. Reject invalid UTF-8 and
over-limit input; clear secret buffers on every exit. Never echo protected
values or notes; labels/metadata output use Out escaping. All prompted field
values are converted directly into the core's SecretText/FieldValue or Text.

`cmd/edit.rs` handles entry drafts. `cmd/groups.rs` handles mkdir/mv/rm;
`cmd/trash.rs` handles trash commands. Reuse generator option parsing by making
its existing helper private-to-crate and share option construction in cli.rs.
No secret-taking argument is introduced.

**Entry options:** add uses the final parsed path segment as title and resolves
its parent; it creates a login password field unless another type is requested
and still follows the command's password prompt/generate rule. Edit preserves
untouched fields, IDs, order, timestamps and unknown data through core drafts;
it prompts for a new password only when requested. Username/URL updates target
fields named username/url; generic named changes require a unique name or fail
with usage error 2 before saving. Repeated contradictory changes to one field
are usage errors. Added generic fields are text/unprotected; secret-field values
are secret/protected. Refuse argv updates to existing protected/secret/TOTP fields,
even when --unprotect is also supplied: a flag cannot retroactively prevent
argv leakage. --protect/--unprotect only changes the existing field's policy.
-i prompts for field values, including supplied named-field values; argv help
continues to explain title/path and other argument visibility. --notes takes no
value and prompts. No editor or plaintext temporary file.

**Scripting refusal:** validate option conflicts, required prompts and TTY
availability before unlock or writes. --password-stdin plus notes/-i/any other
value prompt is exit 2, even if stdin is a TTY. add --generate without further
prompts is scriptable. edit with only non-protected argv changes is scriptable.
No change is committed after a failed/cancelled input.

**Groups/trash:** reuse address parsing and core `move_item`, `new_group`,
`save_group`, `delete`, `restore`, `empty_trash`. mkdir -p walks iteratively,
refuses ambiguity and preserves existing parents; each missing parent uses the
existing durable core operation. If a later mkdir fails, earlier created parents
may remain; do not claim a cross-call atomic transaction. Refuse root deletion
and nonrecursive deletion of nonempty groups through core. Trash restore resolves
only trashed @IDs or a unique displayed name, never live matches; duplicate names
are exit 5 with escaped IDs. trash ls shows ID, kind, name, deletion time and
conflict; stable JSON object `items` contains those keys. trash empty confirms
unless --yes, warns if the core expiry report flags the clock, and delegates
final deletion to core. Never silently resolve conflicting items.

**Durability:** entry draft save is one existing core commit. Group subtree
soft-delete, restore and final delete use core's transactions. Success follows
durable commit and anchor update; no frontend SQLite access or second write path.

**Dependencies:** only already approved `signal-hook =0.4.5`, defaults disabled,
using its safe flag API; signal-hook-registry is transitive. Existing rustix poll
features move into runtime dependencies as needed. No arboard/x11rb dependency
in this phase. Add justified vet exemptions only after dependency review;
run deny and vet. No unsafe lint exemption.

## Steps

### Step 1 — Record approved scope and dependencies

- [x] **Do:** Resolve D1; record owner approval and the 1.10b/1.10c split in the
  roadmap. Add signal-hook with the approved features and lockfile/vet evidence.
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/qv-cli/Cargo.toml`,
  `supply-chain/config.toml`, roadmap and this plan.
- **Done when:** no unresolved decision; dependency tree matches the approved
  scope; no clipboard crate is added.
- **Verify:** `cargo check --locked -p qv-cli`; `cargo deny check`; `cargo vet --locked`.

### Step 2 — Signal cancellation and bounded prompts

- [x] **Do:** Add signals.rs; poll terminal/stdin reads and countdowns for the
  flag, preserving existing Ctrl-C input behavior and all cleanup guards. Add
  bounded single/multiline value prompts; labels cannot render vault controls.
- **Files:** `crates/qv-cli/src/{signals,main,term}.rs`, PTY test helpers.
- **Done when:** SIGINT/TERM/HUP restore echo and alternate screen; notes/secret
  input is absent from echoed output, buffers remain bounded, cancel writes nothing.
- **Verify:** `cargo test --locked -p qv-cli term`; focused subprocess signal tests.

### Step 3 — Command tree and scripting preflight

- [x] **Do:** Register editing/group/trash options per 0011, share generator
  args/parser, and remove obsolete dead-code allowances for --yes. Check prompts
  and option conflicts before opening the vault.
- **Files:** `crates/qv-cli/src/{cli,config}.rs`, `src/cmd/{mod,generate}.rs`.
- **Done when:** clap tree valid; secret-taking-argument regression updated for
  permitted non-protected --field syntax; every stdin/prompt conflict exits 2.
- **Verify:** `cargo test --locked -p qv-cli cli` plus preflight pipe tests.

### Step 4 — Entry add/edit

- [x] **Do:** Build and save drafts per Design; generation uses vault defaults
  or explicit generator settings; preserve unknown/untouched fields and IDs.
- **Files:** `crates/qv-cli/src/cmd/edit.rs`, `tests/edit.rs`.
- **Done when:** PTY/pipes cover generated and prompted passwords, custom fields,
  notes, -i, protect/unprotect/remove, cancellation, ambiguity and refusal to
  replace a protected value from argv; reopen verifies edits and rejected calls
  preserve local sequence/state. Conflicted drafts remain refused by core.
- **Verify:** `cargo test --locked -p qv-cli --test edit`.

### Step 5 — Group creation, moves and soft deletion

- [x] **Do:** Implement iterative mkdir -p, mv and rm using existing core APIs.
- **Files:** `crates/qv-cli/src/cmd/groups.rs`, address helpers, `tests/edit.rs`.
- **Done when:** nested escaped names, duplicates, invalid destinations/cycles,
  root/nonempty group refusals and recursive trashing have persisted regressions.
- **Verify:** `cargo test --locked -p qv-cli --test edit`.

### Step 6 — Trash listing, restore and empty

- [x] **Do:** Implement trash addressing, escaped/JSON listings, restore and
  confirmed empty; wire --yes without bypassing existing weak-password prompts.
- **Files:** `crates/qv-cli/src/cmd/trash.rs`, `src/{address,json}.rs`, `tests/trash.rs`.
- **Done when:** live/trashed scopes remain separate; ambiguous names list IDs;
  restore recovers contents; refusal/cancel leaves state unchanged; empty produces
  permanent deletion, not a hide operation; JSON schema and confirmation tested.
- **Verify:** `cargo test --locked -p qv-cli --test trash`.

### Step 7 — Offline/signal integration evidence

- [x] **Do:** Extend production-binary offline flow through edit, reopen, move,
  trash and restore. Exercise termination signals during each prompt type;
  dependency allowlist includes signal-hook and permits no network/clipboard crate.
- **Files:** `crates/qv-cli/tests/{offline,edit,trash}.rs`, common test harness.
- **Done when:** PTY lifecycle tests prove restoration/no secret echo; rejected
  operations preserve data; unavailable namespace isolation is reported as skipped.
- **Verify:** `cargo test --locked -p qv-cli`.

### Step 8 — Documentation and final gates

- [x] **Do:** Update current implementation and plan/roadmap status; record
  clipboard deferral explicitly and leave all changes uncommitted.
- **Files:** `CHANGELOG.md`, `ARCHITECTURE.md` §3/§6, plans index/roadmap/this plan,
  qv-cli module docs. No normative spec or AGENTS changes anticipated.
- **Done when:** all scope complete, documented and verified; plan Implemented;
  next fresh session reviews it before beginning clipboard work.
- **Verify:** all gates below.

## Test plan

Final tree: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`,
`cargo deny check`, `cargo vet --locked`. Keep complete output in /tmp logs,
report counts/failures and preserve exit status. Never weaken rejection tests.
Existing crypto/store crash evidence is reused through core's mutation interface;
this phase adds no transaction primitive. 0012 rows: CLI argument leakage and
implicit server prerequisite gain editing coverage, with clipboard evidence
explicitly deferred. No cryptographic vectors or security assurance claim.

## Risks and stop conditions

D1 is resolved by explicit owner approval. Stop if safe signal registration
cannot interrupt reads without bypassing cleanup, if editing requires core API or
format changes, or if an unplanned dependency/spec exception becomes necessary.
Do not compensate for clipboard library copies with wrapper wiping, content
comparison, forced process exit, or weakened memory claims. Clipboard follows a
separate architect/developer/reviewer sequence after its design is approved.

## Documentation

- [x] CHANGELOG Unreleased: editing/trash/signals and clipboard deferral.
- [x] ARCHITECTURE §3/§6: commands and runtime signal dependency.
- [x] Specs: no changes; do not mark partial CLI/security specs Implemented.
- [x] AGENTS: no convention/layout changes anticipated.
- [x] Plans index and roadmap: approved scope split, status, execution evidence.

## Revisions

- 2026-10-27: New plan after phase 1.9; supersedes the withdrawn proposal
  in plan 0012 without reviving its abandoned status. Rechecked the current CLI,
  core mutation APIs and upstream arboard 3.6.1/x11rb 0.13.2 source. The same
  prospective clipboard blocker remains; no scope split is assumed approved.

## Execution log

- 2026-10-27: Architect prepared this concrete proposal for the next remaining
  phase, 1.10b. D1 needs the owner's decision under roadmap Session protocol
  step 4 (phase scope deviation); no implementation or dependency change made.
  Proposed 1.10c remains a recommendation until approved. No commit, push,
  branch or staging performed.

- 2026-10-27: Previous phase 1.9 passed fresh review and is Reviewed. All
  handoff gates pass on unchanged code/build inputs: SPDX, root/spike fmt,
  all-target Clippy and locked tests; root/spike deny/vet also pass. Root
  456 passed/2 ignored; spike2 passed. Evidence /tmp/qv-review19-*.log and
  plan 0013 REVIEW.md. Final edits are documentation only. D1 remains pending;
  status Proposed, no implementation started.

- 2026-10-27: Owner approved D1 option A and plan 0014. Continuing the same
  session from its own review/planning edits; no unrelated owner edits present.
  Developer begins the approved editing/trash/signals scope.

- 2026-10-27: Step 1 complete: signal-hook 0.4.5 (default features off),
  registry 1.4.8, rustix runtime polling feature. Safe atomic flag API source
  inspected; no application unsafe, additional signal framework, clipboard or
  networking crate. cargo check --locked -p qv-cli, deny and vet pass after two
  explicit version exemptions (not audits); vet reports 27 fully audited,
  6 partially audited, 77 exempted. Logs /tmp/qv14-{deps,deny-deps,vet-deps}.log.
- 2026-10-27: Command tree, protected drafts, group/trash operations and bounded
  polling prompts implemented. Focused unit suite passes (26); first persisted
  edit/trash suite passes (7). Test harness initially matched the old master
  password prompt as a later field prompt; fixed matching to use its watermark.
  A field-order test now locates the intended named field, retaining ID/order
  preservation checks. No product behavior or rejection requirement weakened.
  Adding final bounds, alternate-screen and offline/signal coverage.

- 2026-10-27: Steps 2–7 implemented: atomic signal flags plus 100 ms input/
  countdown polls; bounded single/multiline protected prompts; editing/group/
  trash command tree and preflight; single-save core drafts; iterative mkdir -p,
  mixed-kind addressing, subtree deletion/restore and confirmed tombstones.
  `cargo test --locked -p qv-cli` passes (53 tests before the final two signal
  cases); focused all-target Clippy passes. Persistent tests verify field IDs,
  untouched values, no save after refusal/cancellation, protected argv refusal,
  duplicate field names and address ambiguity, bound/UTF-8 errors, no secret echo,
  signals in master/field/notes/confirmation prompts and recovery-screen cleanup.
  Full offline binary flow now includes add/edit/move/trash/restore/reopen.
  Namespace isolation is unavailable (`unshare -rn true`: No space left on
  device, /tmp/qv14-network-isolation.log); that case is reported SKIPPED,
  not evidence of a blocked-network run. No core API/format or spec change.
  Final two signal cases additionally cover weak-password countdown and an
  open empty password pipe; final gates follow.

- 2026-10-27: Step 8 complete. All final gates pass: `sh scripts/check-spdx.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked` (467 passed, 0 failed, 2 ignored, including doctests),
  `cargo deny --locked --config /tmp/qv-review19-root-deny.toml check`, and
  `cargo vet --locked`. Logs /tmp/qv14-final-{spdx,fmt,clippy,test,deny,vet}.log.
  Deny's temporary policy differs only in advisory-cache db-path; vet uses the
  retained root store with XDG_CACHE_HOME=/tmp/qv14-cache. CI-pinned tools are
  under /tmp/qv-review-tools/bin. `git diff --check` passes. Final changes to
  status/logs are documentation only; code/build inputs are unchanged since
  these checks. No gate or test assertion was weakened. No secret-handling,
  core API, storage/crypto format or profile exception was introduced.
  Plan Implemented, roadmap 1.10b ticked; 1.10c remains pending. No commit,
  staging, push or branch. Next fresh session reviews this phase before any
  1.10c implementation.

- 2026-10-27: Fresh-context review Approved; see REVIEW.md. Independent SPDX,
  fmt, all-target Clippy, locked tests (467 passed, 2 ignored), deny and vet
  passed. No code fixes or blocking findings. Next remaining phase: 1.10c;
  clipboard integration decisions remain separate from this approval.

Found, not fixed: clipboard dependency buffer/ownership concerns remain for
1.10c. Namespace-based network isolation is unavailable here as recorded above.
History, attachments, recovery/anchor-adoption commands and conflict resolution
remain in their existing later phases. Initial vet exemptions are not audits;
passing checks are not security validation.
