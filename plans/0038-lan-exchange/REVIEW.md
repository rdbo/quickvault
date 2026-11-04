# Review — Plan 0038: LAN sessions, exchange, CLI and app

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-11-03 | `git diff 1d8e470..138bdde`, with the committed repair diff `92aa8c4..138bdde` and the validation-only changes in this session |

## Summary

Fresh-context review closes the four original findings against committed
`138bdde`. Absolute window lifetimes cover ready socket I/O and core acceptance;
frontend waits no longer manufacture user activity. Reports retain both durable
acceptance metadata after lock and completion errors in the app.

The reviewer completed step 9's already-planned core-peer fallback in the Linux
WebKit fixture. The renderer now approves a real pairing, checks the confirmed
receipt and secret cleanup, and requires the joining core to open the transferred
vault. The original cancellation assertions remain. This is validation-only code;
no production behaviour, protocol, public API, dependency or vendor patch changed.

Implementation is **Reviewed**. Under the subsequent owner-directed transfer,
roadmap 2.10 is ticked for implementation, with its still-pending attended
offline Linux/phone run carried into plan 0039 step 6. This review does not authorize LAN release
or replace the independent protocol review required by D12 / 0012 §3.

## Findings and closure

| Original finding | Current evidence | Result |
|------------------|------------------|--------|
| Unbounded app prompts and inactivity exemption | `Bridge::waiting`, `LanRun::defers_idle`, autonomous expiry/idle regressions and the real-engine approval flow | closed |
| Active exchanges outlive window expiry | Persistent `Conn::cap`, checks before each socket operation, acceptor ownership of listener; core token/expiry checks through staging, snapshots and cancellable commit | closed |
| App discards completion failures | `round_done` supplies both acceptance lines and the completion error for sync, receive and pairing follow-up; regression checks anchor/I/O and timeout categories | closed |
| Lock hides durable acceptance report | `SessionExchange` captures conflicts and completion state at acceptance; `report` reads only saved state; a real-commit-then-lock regression passes | closed |

Followed the affected store acceptance/staging, session handshake/key schedule,
wire codecs, CLI and UI callers. The shared archive acceptance transaction and
DB-commit → anchor → report order remain in place. No additional production
finding was established. The old parallel instance-lock test failure remains a
test-isolation limitation; serialized success does not establish parallel stability.

## Fixes applied by reviewer

- `crates/qv-app/src/lan.rs`: Linux validation-only core peer, started by an
  explicit fixture event after opening a window. It checks the same comparison
  code as the controller question, confirms the synthetic vault, verifies its
  name/entry/link after local creation and locks the peer. Window cancellation
  is propagated. Fixed status and data-free errors are the only diagnostics.
- `crates/qv-app/src/{ui/mod.rs,controller.rs}`: validation-only event and
  successful-peer-completion requirement. Production builds expose no new action.
- `crates/qv-app/src/bin/flow.js`: retain window cancellation/cleanup; then click
  the real comparison-code control, require confirmed transfer, check removal of
  code/SAS and wait for the peer's successful open. New stages distinguish failures.
- Plan, index, roadmap and changelog: record review completion and the remaining
  attended gate accurately. No spec amendment or architecture-boundary change.

## Gates

| Check | Result |
|-------|--------|
| SPDX, matrix, `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `RUST_TEST_THREADS=1 QV_TEST_XVFB=/tmp/qv-0038-review-xvfb/root/usr/bin/Xvfb cargo test --locked` | 870 passed, 0 failed, 2 pre-existing ignored; one full workspace run |
| `RUST_TEST_THREADS=1 cargo test --locked -p qv-app --lib` | 32 passed after the fixture changes |
| `cargo clippy --locked -p qv-app --features validation --all-targets -- -D warnings` | pass; existing upstream vendor warnings unchanged |
| `QV_TEST_XVFB=… RUST_TEST_THREADS=1 cargo test --locked -p qv-app --features validation --test engine` | 3 passed, including both synthetic-OS and real-Linux completed-pairing flows |
| `python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py` | pass: 34 values independently recomputed |
| `QV_DX=/tmp/qv-dx-0.7.10/dx sh crates/qv-app/scripts/build-android.sh` | pass: app/test debug APKs; no installation |
| deny/vet; fuzz campaign | no dependency/parser changes; not repeated |
| Attended offline LAN test; Android instrumentation | pending: `adb devices` lists no device |

The full suite began before the validation-only fixture addition. Its unaffected
crate results are retained, with the current app library and real-engine tests
rerun after that addition. No second full KDF/rotation suite was needed. Final
static checks cover the handoff tree. Early engine runs failed because the new
synthetic peer used an unsupported `.qv` suffix; `.qvault` fixes the fixture.
No production check or assertion was weakened.

Xvfb comes from signed Alpine packages extracted under `/tmp`, selected through
`QV_TEST_XVFB`. The official Dioxus 0.7.10 archive was verified against the GitHub
release digest `4363e4ed2a3f1eb7f4d38d2d59aed59ce43271c44c16b425e92c89a64761fbe7`.
Its GNU binary uses an isolated Debian runtime in `/tmp`; the tool's ELF loader
and RPATH were adjusted locally so its self-invocation can run Rust's musl tools.
The initial loader-wrapper build failed and was superseded by the successful
packaging run. Nothing was installed system-wide or changed in repo dependencies.

Artifact: `crates/qv-app/dist/quickvault-debug.apk`, SHA-256
`5dbba78f1190ab283ef15c36f1b3e4a873cc4e2691dece09096e62728f01b9ef`.
Later source edits are confined to Linux validation code and do not change the
Android product build. The APK is debug signed; no device or release claim.

Logs: `/tmp/qv-0038-fresh-review-{tests,app-final,engine-final,clippy,validation-clippy,checks,apk-final}.log`.
Historical failure logs remain separate; only the final successful runs supply
current evidence for their affected scopes.

## Documentation and remaining evidence

- CHANGELOG, plan status/execution log, plans index and roadmap updated.
- Architecture and normative specs need no change for validation-only code.
- Owner continuation (2026-11-03) moves the remaining attended 2.10 checks to
  plan 0039 step 6 and authorizes QR implementation now. This supersedes the
  earlier blocking workflow notes below; the evidence remains pending.
- The attended Linux/phone pairing and sync run from either initiation direction,
  with Internet unavailable and no account/server, remains mandatory under the
  plan's Test plan / Risks and stop conditions. 2.10 implementation is ticked; 2.10b device acceptance remains pending.
- D12 independent protocol review remains a release gate. Tests and this internal
  implementation review do not prove protocol security.

## Original blocking review and developer repair record (historical)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Re-plan needed | 2026-11-03 | `git diff 1d8e470..92aa8c4` |

### Summary

The implementation connects the session handshake, exchange, archive acceptance,
CLI and app workflows. Review found window-expiry and inactivity-lock defects,
and incomplete reporting of completion failures. These prevent approval and
advancement to phase 2.10b. This is a blocking review, not a completed security
audit: remaining review and device evidence must follow the repairs.

### Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | 0013 and 0011 amendments and index notes present. |
| 2–3 | yes | Session key schedule and codecs present; development vector crosscheck required below. |
| 4 | yes | LAN staging and shared acceptance body present; existing write/anchor path reused. |
| 5 | partial | Exchange implemented, but active receive sessions outlive window expiry (finding 2). |
| 6 | partial | Core APIs present; post-commit reporting can be lost on lock (finding 4). |
| 7 | partial | Vectors and fuzz targets present; previous fuzz evidence is developer evidence only. |
| 8 | yes | CLI contracts implemented; focused integration checks recorded below. |
| 9 | partial | Prompt expiry and completion error reporting need repair (findings 1 and 3). Real-engine pairing fallback from the plan was replaced with headless coverage; remaining real-engine/device coverage must be revisited. |
| 10 | partial | Documentation present; roadmap correctly remains unticked pending attended evidence. |

Out-of-scope changes: the preceding 0037 review and its creation-guard repair
are included in the commit and identified in its existing REVIEW.md. No new
dependency or unsafe code was introduced by 0038.

### Findings

1. **[high] An unanswered app prompt can suppress inactivity locking indefinitely** —
   `crates/qv-app/src/lan.rs:295`, `crates/qv-app/src/controller.rs:644`.
   `Bridge::wait` checks only `slot.closed` and keeps resetting activity every
   250 ms. It never checks `LanRun.expires`, a prompt deadline, or the peer's
   departure. Meanwhile `running()` stays true until an outcome exists, so
   `snapshot` exempts the operation from idle locking. Leaving the SAS approval
   unanswered can therefore retain the unlocked session, pairing secret and
   listener past the ten-minute window; new-device password prompts also have
   no deadline. The protocol's expiry check runs only after the callback
   returns (`approver.rs:325`). This violates 0013 §8.2 and defeats the bounded
   exemption described in plan 0038 decision 9 / Revisions; see also 0008 §1.4.
   **Evidence:** temporary diagnostic `review_probe_expired_prompt_keeps_waiting`
   passed: a Bridge with an already-expired Pair run was still waiting and
   `running()` remained true after 600 ms, until explicitly closed. Diagnostic
   source was removed; `/tmp/qv-0038-prompt-probe.log` retains its result.
   **Action:** escalated. Propagate expiration into frontend waits, clear
   secrets/listener promptly, and bound idle suppression for joins and rounds
   as well as windows. Add expiry-during-prompt and idle-lock regressions.

2. **[medium] An authenticated receive exchange can complete after window expiry** —
   `crates/qv-sync/src/lan/receiver.rs:293`,
   `crates/qv-sync/src/lan/transport.rs:195`.
   The hello/Confirm are capped by `self.expires`, but the subsequent exchange
   gets only the external cancellation callback. Exchange reads use
   `ch.recv(t.idle, None)` and sends reset their deadline without an expiry
   cap. The acceptor stopping does not close the listener owned by the blocked
   caller or abort its active connection. A peer can continue a transfer past
   the displayed window limit, contrary to 0013 §8.2. Pairing follow-up
   exchanges need the same lifetime audit.
   **Evidence:** temporary diagnostic `review_probe_exchange_after_window_expiry`
   passed: open a 500 ms receive window; authenticate and Confirm; wait 800 ms;
   then run the exchange. It succeeds and the receiver returns `Completed`,
   rather than expiring. Diagnostic source was removed;
   `/tmp/qv-0038-expiry-probe.log` retains the result.
   **Action:** escalated. Carry an absolute window deadline through active
   transport and acceptance, preserving post-commit reporting. Cover expiry
   during every exchange turn and a continuously sending peer; checking only
   socket-timeout retries is insufficient for absolute deadlines.

3. **[medium] App discards completion errors from successful local acceptance** —
   `crates/qv-app/src/lan.rs:388`, `crates/qv-app/src/lan.rs:617`.
   `round_lines` reads acceptance, conflicts and peer receipt, but ignores
   `SyncReport.completion_error`. Sync, receive and successful pairing-follow-up
   reports become `LanDone { error: None }` through `outcome(Ok(lines))`.
   An anchor completion failure can therefore be shown as an ordinary success,
   even with a confirmed peer receipt. The CLI correctly checks this field in
   `finish_report`. Plan 0038 explicitly requires the completion error to be
   surfaced without hiding the durable commit (0004 §5, 0005 §6.5).
   **Evidence:** code-path inspection; failure injection not performed here.
   **Action:** escalated with the acceptance/reporting repair. Preserve the
   lines and expose the completion error in every app LAN result; test a
   durable local commit followed by anchor or acknowledgement failure.

4. **[medium] Lock after commit can replace the acceptance report with SessionLocked** —
   `crates/qv-core/src/lan.rs:613`.
   `SessionExchange::report` consumes the saved acceptance, then makes a fresh
   `session.read` to count conflicts. If the session locks after acceptance
   but before Done/reporting, the read returns `SessionLocked` and the saved
   local commit never reaches the frontend. The transport correctly retains
   the RoundReport on a lost Done, but this later read defeats that contract.
   This contradicts plan 0038 failure semantics and 0013 §7.7 / 0005 §6.5.
   **Evidence:** code-path inspection of `report` and `Session::run`'s locking
   check; the exact scheduling race was not injected here.
   **Action:** escalated. Save the report metadata at acceptance so reporting
   a completed commit does not require an unlocked session. Add a lock between
   commit and Done/report regression.

### Fixes applied by reviewer

No product changes. Temporary diagnostic tests reproduced findings 1–2 and
were removed, restoring both source files exactly. Review records and plan
status notes are the only retained changes.

### Gates

At the original review handoff, product source equaled `92aa8c4`; diagnostic
sources were absent. Subsequent repairs and their gates are recorded below.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | fail: two CLI clipboard tests cannot spawn Xvfb (not installed); execution stops there, so later suites are not covered by this command |
| `cargo test --locked -p qv-crypto -p qv-protocol -p qv-store -p qv-sync -p qv-core -p qv-platform`; `cargo test --locked -p qv-cli --test lan` | pass: 614 passed, 2 ignored |
| `python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py` | pass: 34 values independently recomputed |
| `cargo deny check`, `cargo vet --locked` | not applicable: no dependency changes |
| Real-engine and Android checks | not rerun in this blocking review; no Xvfb or attached phone |

Full logs: `/tmp/qv-0038-review-gates.log`,
`/tmp/qv-0038-review-tests.log`, `/tmp/qv-0038-review-focused.log`.
The initial gate wrapper tried `xvfb-run`, which is also absent; the actual
`cargo test --locked` command was then run directly, yielding the failures above.

### Documentation

- [x] CHANGELOG.md implementation entry and review hold
- [x] ARCHITECTURE.md component and LAN notes
- [x] Spec statuses and Changelogs
- [x] Review verdict recorded in plan, index and roadmap
- [ ] Attended two-device test with Internet unavailable
- [ ] Repair findings, complete remaining review, and rerun gates

### Escalations for the owner

Recommend revising plan 0038 with quickvault-architect before further phases.
Carry a single bounded operation lifetime through the window, transport,
frontend prompts and acceptance, including cancellation and expiry without
losing durable-commit reports. Bound the app's idle-lock exemption, retain
completion errors, and add regressions for the demonstrated expiry paths and
commit/report races. These repairs cross protocol orchestration and secret
lifetime boundaries, so the reviewer has not applied them as minor fixes.

The attended Linux/phone test without Internet remains pending: `adb devices`
returned no devices. D12 independent review remains a separate release gate;
passing these tests would not establish protocol security.


### Developer repair supplement — 2026-11-03

Owner authorized repair after this blocking review (“do whatever you think is
best”). The plan's Repair revision records the design and implementation.
Findings 1–4 have implementation changes and regressions; this supplement is
**not** a fresh-context reviewer approval and does not replace the verdict above.

- **Finding 1:** callback waits check absolute expiry and genuine inactivity,
  closing and clearing code/password or locking without UI polling. Only
  unexpired Pair/Receive listeners without questions defer idle lock. Network
  callbacks do not refresh activity. CLI pairing confirmation is also capped.
- **Finding 2:** persistent transport caps apply to every exchange turn and
  abort, checked before each actual socket read/write even when immediately
  ready. Acceptor ownership drops the listener independently of local work.
  Core cancellation/expiry applies to staging, snapshots, verification, merge
  and the cancellable commit path. Post-commit reporting is retained.
- **Finding 3:** app sync, receive and pairing-follow-up results carry both
  local acceptance lines and completion errors; pairing transfer failures
  remain visible too.
- **Finding 4:** acceptance saves conflict counts with the completion state;
  constructing the final report does not read the session again. A regression
  performs a real merge/commit, locks, and then obtains the committed report.

New tests are retained in the sync transport/sync-round, core LAN, app LAN and
CLI terminal suites. The initial review's diagnostic probes remain historical;
current regression tests assert the required behavior.

Current verification is recorded in the plan's execution log. Xvfb is now
available from signed Alpine packages extracted in `/tmp` and selected with
`QV_TEST_XVFB`; the initial environment failure is superseded by the final
workspace run. App validation and real-engine flows and Android arm64 Clippy
pass. APK packaging refuses the installed dx 0.8.0-alpha.0 because 0.7.10 is
required. Attended offline Linux/phone evidence and fresh-context review remain
pending. No independent-review or LAN-release claim.


Final developer gate evidence (current source, all tests retained):

| Check | Result |
|-------|--------|
| SPDX, matrix, fmt, workspace Clippy | pass |
| `RUST_TEST_THREADS=1 QV_TEST_XVFB=/tmp/qv-xvfb-root/usr/bin/Xvfb cargo test --locked` | 870 passed, 0 failed, 2 pre-existing ignored |
| Default-parallel workspace run | failed at unchanged instance-lock post-drop reacquisition (Busy); passes in isolation and serialized; root cause not established |
| Final CLI package tests | 102 passed |
| App validation | 33 unit tests and 3 real-engine flows passed |
| Android arm64 Clippy (`mobile`, `mobile,validation`) | pass |
| Python development vectors | 34 values independently recomputed, OK |
| APK packaging | blocked: available dx 0.8.0-alpha.0; script requires 0.7.10 |
| Attended offline LAN run | pending, no phone attached |

Logs and the passing full-gate command are in the plan's final execution-log
entry. Repairs are Implemented; fresh-context review remains due. The original
review verdict is not changed by this developer supplement.
