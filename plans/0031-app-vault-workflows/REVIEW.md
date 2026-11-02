# Review — Plan 0031: App vault workflows

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Changes requested | 2026-11-02 | `a6b2252..2c993c6`, checked against current `1a40186` including subsequent plan 0032 changes |

## Summary

The shared workspace implements substantial offline functionality, with real
core operations, protected controller state and actual web-engine/device
evidence. The review found outstanding requirements in credential strength
handling, Android document-choice lifetime and generator controls. Phase 2.5
cannot be marked Reviewed; roadmap Session protocol step 2 stops progression
to phase 2.6 on these escalated findings. This review is not a security audit
or release approval.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | File helpers moved to platform; descriptor/identity and cancellation checks retained. |
| 2 | partial | Navigation/epoch, reveal expiry and lock-generation tests exist; Android Back misses document cleanup (finding 2). |
| 3 | yes | Entry/group/trash operations and protected replacements implemented. |
| 4 | yes | History/conflicts/snapshots/archives/verify/about paths implemented. |
| 5 | partial | Attachments implemented; generator omits an option and required strength warnings (finding 3). |
| 6 | partial | Password/phrase/rotation paths exist, but credential strength handling is incomplete (finding 1). Interrupted-rotation app test remains explicitly uncovered. |
| 7 | yes | Rust clipboard hold, replacement and lock cancellation implemented. |
| 8 | partial | Native clipboard/SAF and prior device evidence exist; screen-scoping incomplete (finding 2). |
| 9 | partial | Shared responsive screens exist; required warnings/controls incomplete. |
| 10 | yes | Dropped-batch failure closes hardened webview; native ingress refusal counter asserted. |
| 11 | partial | Existing engine/device evidence is useful but narrower than the step: host flow does not exercise edit/history restore, archive/attachment round trips or lock during save; device flow does not cover every listed equivalent. |
| 12 | partial | Documentation exists; completed status overstates the outstanding requirements. |

The documented `qv-store` O_PATH ancestor change preserves no-follow,
directory-only descriptor traversal; its search-only ancestor test is present.
Additional platform/CLI/vendor changes are recorded in the plan/roadmap.

## Findings

1. **[medium] Password-change flow skips the required strength safeguards** —
   `crates/qv-app/src/ops.rs:799`, `crates/qv-app/src/workspace.rs:815`,
   `crates/qv-app/src/ui/workspace.rs:253`.
   A weak password produces `ConfirmKind::WeakPassword`, but an immediate
   `Answer(true)` consumes that confirmation and passes `weak_ok = true` to
   `change_password`. There is no deadline check, and Continue is always
   enabled with no countdown. The `Warn` verdict is discarded by the catch-all
   arm. The password-change pane also lacks the required six-word suggestion.
   This violates Accepted 0010 §4.2 and step 6's promised creation-strength
   semantics. Rotation additionally refuses weak passwords outright
   (`ops.rs:875`) instead of offering the specified confirmation.
   Restore the full strength contract: a Rust-enforced five-second cooldown
   bound to the candidate, visible countdown and stronger-password default,
   Fair warning and generated passphrase suggestion. Cover early confirmation,
   changing inputs, navigation/lock and successful confirmation.
   Action: escalated; no product fix applied by reviewer.

2. **[medium] Android Back retains a document choice from the previous screen** —
   `crates/qv-app/src/workspace.rs:716`.
   `navigate` forgets the Android pick, but `back` changes screen and epoch
   without calling `forget_pick`. The choice is global, and `picked_for`
   checks its create/read mode and native readiness rather than its screen or
   epoch (`crates/qv-app/src/android.rs:145`). Following Back through the
   navigation stack can therefore carry a choice to another file-operation
   screen, where it can be reused. This contradicts the plan's 2026-11-02
   screen-scoping revision and the README's promise that navigation forgets
   chosen destinations; that revision specifically addressed writing to an
   earlier destination. Apply the same cleanup to Back and audit action-driven
   screen transitions. Add a device regression covering Back and destination
   reuse, including stale picker callbacks.
   Action: escalated; no product fix applied by reviewer.

3. **[medium] Generator changes a saved constraint and omits weak-output warnings** —
   `crates/qv-app/src/ops.rs:138`, `crates/qv-app/src/ui/workspace.rs:961`.
   `GenForm`/`GenFlag` have no `require_each_class` state. Loading defaults
   ignores it, and `settings_from` reconstructs it from `Default` as true.
   Saving defaults can silently change a CLI-created false setting; the app
   cannot access the full generator option set promised by step 5. The screen
   shows only a numeric entropy value, with no §3.3 label or warning below
   64 bits, including PIN mode (0010 §2.3/§4.1). Preserve and expose the option,
   show strength labels and a low-strength warning, and test a false-setting
   round trip plus weak PIN/passphrase settings.
   Action: escalated; no product fix applied by reviewer.

4. **[low] Validation completion claims exceed the exercised GUI flows** —
   `plans/0031-app-vault-workflows/PLAN.md:473`.
   Step 11 is checked complete, but `src/bin/flow.js` exercises create,
   generated entry/reveal/hide/copy, delete/restore, generator and unlock/recover.
   It does not exercise all the edit/history/file/lock-race flows listed in
   the step. `VALIDATION.md` accurately lists the narrower evidence, and the
   interrupted-rotation app case is explicitly uncovered. Extend the required
   GUI coverage or record an explicit scoped plan revision; do not treat
   headless controller tests as equivalent engine/device evidence.
   Action: escalated; no test or completion claim weakened.

## Fixes applied by reviewer

None. The findings concern credential safeguards, document authorization
lifetime and incomplete feature/verification scope. They require developer
work and regression evidence before a Reviewed verdict.

## Gates

Independent checks on the current tree are recorded below. Full output is in
`/tmp/qv-next-phase/` (temporary session evidence).

| Check | Result |
|-------|--------|
| SPDX headers, SPDX rejection fixtures, offline matrix, `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `QV_TEST_XVFB=/tmp/qv-next-phase/xvfb-wrapper cargo test --locked` | pass, 741 passed, 0 failed, 2 existing ignored |
| `cargo test --locked -p qv-app --features validation` | pass, 22 unit + 3 real-WebKit tests |
| qv-app validation Clippy, all targets | pass |
| Isolated dioxus-desktop hardened tests | pass, 5 tests |
| `cargo deny check`, `cargo vet --locked` | pass; vet: 93 fully audited, 11 partially audited, 421 exempted |

The first workspace run failed because Xvfb was absent. Unpacked Alpine's
Xvfb 21.1.25 and misc fonts into the temporary evidence directory, without
changing the host installation; the rerun uses `QV_TEST_XVFB` pointing at a
private wrapper. Tool versions for supply-chain checks match CI; their cache
and advisory database live under the temporary evidence directory. Android
instrumentation has not been rerun in this session; historical device results
remain historical evidence.

The retained vendor archive hashes to
`236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d`.
Compared the working snapshot against that archive; changed files match the
documented patch areas, plus publication/license metadata and the recorded
hash. Reviewed the 0031 edits/hardened/webview patch and ran its focused tests.
Plan 0032's separate fresh-context review remains due; this report does not
mark it Reviewed.

## Documentation

- CHANGELOG/architecture/app documentation exist for the implemented scope.
- Spec statuses remain unchanged; passing tests do not establish security.
- Plan remains Implemented, with this changes-requested note in its log/index.
- Roadmap phase 2.6 remains unticked and unplanned, pending remediation and
  completion of the prerequisite reviews.

## Escalations for the owner

Findings 1–3 must be repaired and verified under the existing plan's specified
requirements. Finding 4 needs the promised GUI evidence or a documented scope
revision. No new dependency, cryptographic construction or owner design choice
is proposed. The owner's 2026-11-02 delegation of implementation choices and
approvals is recorded in the execution log; no approval request is pending.

## Owner-authorized continuation and repair evidence (2026-11-02)

The owner explicitly directed repair and continuation to phase 2.6 on the
staged tree, without another approval/commit/session boundary. The developer
applied the existing plan's dated repair revision:

- Finding 1: workspace deadline and accepted-consent state, reset by candidate
  input/navigation; early Answer(true) refused in Rust, visible countdown,
  stronger-password default, Fair warning and six-word suggestions. Both
  rotation/password paths share consent, without granting over-budget consent.
- Finding 2: Back and both synchronous/worker screen-transition helpers forget
  native picks. Native request codes are unique/bounded and stale result
  callbacks cannot resurrect forgotten choices. Device regression added.
- Finding 3: require_each_class survives load/save and has a toggle; strength
  labels and <64-bit warning included. Persistence regression passes.
- Finding 4: expanded host engine flow passes edit/history restore, archive
  export/merge, attachment success where ancestors permit it (explicit refusal
  otherwise) and lock during save. Byte-exact attachment output is checked by
  the Rust fixture when file rules permit it. Device test extended with
  edit/history restore and Back/destination cleanup; APK compiles, but those
  new device checks are not yet run.

Focused app tests pass (24 library; validation adds the runtime test and three
real-engine cases). Updated native/app artifacts are identified in 0033
VALIDATION.md. The earlier review verdict is retained as the independent
baseline: repairs were implemented in the same continuation, and fresh review
of those changes/device evidence remains due. The earlier stop handoff is
superseded by the owner's explicit continuation; phase 2.6 code proceeds.

## Follow-up review (2026-11-02)

The fresh-context review of commit `54e9764` (recorded in plan 0033 REVIEW.md)
confirmed the repairs for findings 1–4 in code, and gates were rerun: 747
workspace tests, 28 app validation tests and 6 vendor tests pass. Device
PlatformTest evidence including Back/destination cleanup is recorded in 0033
VALIDATION.md. Plan status: Reviewed.
