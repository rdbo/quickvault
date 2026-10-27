# Review — Plan 0013: Dioxus Android/Linux feasibility

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-27 | `git diff 981c39d..18e426c`; clean tree at session entry |

This checks the approved disposable Linux/Android feasibility scope, not
production readiness. D8 is settled: stock Dioxus input with bounded best-effort
cleanup. Root crypto/store/core interfaces, formats and security checks remain
unchanged. Fresh-context review is recorded below; the earlier implementation-session
observations remain as historical evidence.

## Implementation checks and fixes

- Framework input promptly enters protected Rust containers; stored protected
  values never go to the renderer. Queued input is form-generation/busy checked;
  worker results are epoch checked. Lock cancels work and drops sessions/input.
- Post-create Session ownership is published before seeding, allowing lock to
  cancel those writes. Cancelled creation may leave an encrypted fixture; no
  automatic destructive reset was added.
- Whole-entry form keying clears both inputs after Save. Linux observation
  verified empty fields and literal rendering of script-like title text.
- Already-locked idle calls do not churn generations. Controller tests cover
  persistence/rejected input, stale input/results and repeated idle behavior.
- Android wrapper enforces minimum SDK 29. Actual APK manifest, permissions,
  network resource and signature inspected before install. INTERNET is required
  for the local Dioxus socket and also permits broader networking; remote
  cleartext is denied, with only a 127.0.0.1 exception.
- Android startup fixes restore standard socket permission and loopback policy.
  Device creation trace identified SQLite CANTOPEN_SYMLINK (1550). Canonicalizing
  only the OS-provided existing app root fixes the alias without weakening
  NOFOLLOW, ownership or mode checks. The normal final APK has no tracing;
  original qv-store files match their pre-diagnostic bytes and have no diff.

## Observed validation

Linux real-core create/edit/save/lock/reopen, cleanup and literal text were
observed. The owner confirmed Android create/edit/save/reopen, Home/background
locking, expected screenshot refusal, API availability button and five unlocks.
The private fixture/anchor metadata has expected permissions. Numeric CSVs in
REPORT.md show Linux median 408 ms and Android median 865 ms; main-process RSS
sampling excludes renderer processes. No credential or user vault was collected.

Final root/spike SPDX, fmt, all-target Clippy, locked tests, deny and vet all
pass. Logs /tmp/qv-final19-*.log; exact commands/scopes are in PLAN.md/REPORT.md.
Root 456 passed/2 ignored; spike 2 passed. No test assertions
or release requirements were weakened. Temporary logs are not security proofs.

## Follow-ups retained

1. Stock bootstrap/CSP, IPC ingestion, file-dialog and external-navigation
   findings require production hardening/validation; this prototype does not
   waive them.
2. Availability calls and inert autofill entry-point packaging do not validate
   key wrapping, biometric authentication, sensitive clipboard behavior or a
   working autofill provider. Linux adapters/logind are deferred explicitly.
3. Broader Android hardware/KDF budgets, total multiprocess memory, precise
   background latency, renderer suspension and device race coverage remain.
4. Four approved spike-only advisory exceptions and initial vet exemptions are
   residual risks, not audits or proofs of unreachable affected APIs. Root
   dependency policy and audit records remain unchanged.

Earlier partial findings (missing host library, failing dependency policy,
Android build/startup/path and absent runtime evidence) were resolved within the
approved spike scope. Production follow-ups above remain visible in REPORT.md.
No commit, push, branch, phone-setting change, personal-data read or agent
uninstall/data-clear was performed. The owner independently uninstalled an early
test build; the final dummy app remains installed.

## Fresh-context review — 2026-10-27

**Verdict: Approved for the disposable feasibility scope.** No code fixes or
new blocking findings. Reviewed plan steps 1–8, revisions/execution log, the
committed diff, shared controller/UI/platform code, Android source/packaging,
dependency policies and retained evidence against 0008 §1–5, 0009 §6,
0002 §1.3/§4.2 and 0012 §1–3. All eight steps meet their feasibility criteria;
this does not approve the spike as a production frontend.

### Conformance and findings

- Owner-authorized spec/input revisions retain OS, active-content, lifecycle
  and release requirements. D8 is resolved. Existing root crypto/model/store/
  core source and root dependency/audit policies are unchanged by this phase.
- Input setters check generation/busy state and byte bounds before retaining
  protected Rust input. Save uses a core draft and the existing commit/anchor
  path. Rejected bounds and wrong-password attempts preserve persisted data;
  the tests reopen and verify the edited protected value.
- Lock cancels/increments epochs, clears pending inputs/metadata and locks the
  published Session. Late opens cannot publish a session. Creation publishes
  Session ownership before seeding; cancellation may leave an encrypted fixture
  as documented. Form keys force DOM remount after use/lock.
- Native event handling includes Suspended/CloseRequested/LoopDestroyed; the
  Android watcher is additional protection. Checked locked Tao 0.34.8 Android
  source: Pause produces Suspended, and Wry 0.53.5 forwards onPause. Thus the
  50 ms level-polling watcher is not the sole pause-event lock mechanism.
  Exhaustive device races and precise latency remain unvalidated.
- Android path canonicalization is confined to the OS-provided existing root;
  it does not alter qv-store NOFOLLOW or permission policy. Packaging keeps
  minSdk 29, backup disabled, FLAG_SECURE, the distinct app ID and a narrowly
  scoped cleartext loopback rule. INTERNET grants broader network capability
  as the report states. No new device action was needed for this review.
- Four advisory exceptions, license exceptions and vet exemptions are isolated
  and documented. No exemption is represented as an audit. Existing CSP/IPC/
  navigation and adapter gaps remain production release blockers, explicitly
  allowed as reported gaps in this disposable spike's approved scope.
- Retained Linux/Android CSV values match the report. Earlier observed Linux
  and owner-confirmed Android runtime results are historical evidence, not
  rerun or independently observed device results in this review. RSS excludes
  renderer processes; no broader hardware or erasure claim follows.

Out-of-scope changes requiring escalation: none. Prior CLI remediation review
and abandoned plan 0012 are historical records, not new CLI implementation.
Reviewer fixes: none.

### Independent gates

| Command / scope | Result |
|-----------------|--------|
| `sh scripts/check-spdx.sh` | Pass |
| `cargo fmt --check` | Pass |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass |
| `cargo test --locked` | Pass: 456 passed, 0 failed, 2 ignored, including doctests |
| Spike `cargo fmt --manifest-path spikes/ui-feasibility/Cargo.toml --check` | Pass |
| Spike `cargo clippy --manifest-path spikes/ui-feasibility/Cargo.toml --all-targets --locked -- -D warnings` | Pass |
| Spike `cargo test --manifest-path spikes/ui-feasibility/Cargo.toml --locked` | Pass: 2 passed |
| Root and spike `cargo vet --locked` | Pass, using each retained audit store |
| Root and spike `cargo deny --locked --config <temporary-policy> check` (spike adds `--manifest-path`) | Pass: advisories, bans, licenses, sources |

Logs: `/tmp/qv-review19-{spdx,fmt,clippy,test,deny,vet}.log` and
`/tmp/qv-review19-spike-{fmt,clippy,test,deny,vet}.log`. Toolchain bootstrap initially
raced between commands; the pinned 1.98.1 installation completed and failed
commands were rerun successfully. CI-pinned cargo-deny 0.20.2 and cargo-vet
0.10.3 are installed under `/tmp/qv-review-tools`, since the default install
store is read-only. Vet uses temporary XDG cache roots; no audit store changes.
`git diff --check` and Android build-script `sh -n` also pass.
Deny uses temporary copies of the retained policies changing only db-path to a
writable advisory cache; no advisory/license exception added by this review.

### Documentation and handoff

- [x] CHANGELOG and ARCHITECTURE describe the isolated current implementation.
- [x] Spec status/Changelogs/index reflect approved amendments, without claiming
  complete implementation or security validation.
- [x] Plan steps/log/index and roadmap record this fresh review.

Owner escalation: none for phase 1.9. Separate next-phase clipboard planning
must resolve its prospective dependency/ownership issue before implementation;
it is not a defect in this spike.
