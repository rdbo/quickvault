# Plan 0013 — Dioxus Android/Linux feasibility (roadmap phase 1.9)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-26 | 2026-10-26 | 0008 §1–5; 0009 §6; 0002 §1.3/§4.2; 0004 §4–5; 0012 §1–3 |

## Intent

Use the owner's selected Dioxus framework with ordinary webview input. Build a
disposable shared Linux/Android vault-list/edit/persistence spike, measure unlock
and memory, and record OS adapter feasibility. D8 is resolved, not awaiting a
second framework decision. This is not a production vault application.

## Scope

An isolated `spikes/ui-feasibility/` workspace, shared controller/screens, focused
controller tests, minimal Android packaging/OS hooks, bounded device exercises,
benchmarks and REPORT.md. All vault behavior goes through existing qv-core APIs.
Use only a dedicated disposable fixture. No existing/user vault selection.

No native GTK/JNI input dependency, framework fork, custom engine, production
qv-app/qv-platform crates, network sync, complete recovery UI, enabled quick
unlock/autofill, cryptographic/profile/format changes, or production release.

## Spec basis

| Requirement | Source | Authorization |
|-------------|--------|---------------|
| Standard Dioxus input, framework/OS copy limits | 0008 §1.1/§4.4; 0009 §6 | Explicit owner decision 2026-10-26 |
| Native-independent lifecycle and protected Rust state | 0008 §1.2–1.4/§5 | D5 and owner direction; no complete-erasure claim |
| Active-content/bridge controls and honest release evidence | 0008 §4.1–4.3; 0012 | Unchanged; record prototype gaps, do not claim production compliance |
| Shared offline app and adapter probes | 0009 §6 | Roadmap D5 |
| Full password-kdf/1 and budget measurements | 0002 §1.3; 0004 §4 | Accepted; no parameter changes |
| Existing durable mutations and external anchors | 0004 §5; ARCHITECTURE §3 | Existing core APIs only |

## Decisions needed

**D3 — Dependency advisory disposition (resolved, spike only).** The isolated spike's
license/source/ban checks passed initially, while cargo-deny rejected four
upstream advisories: glib 0.18.5 (RUSTSEC-2024-0429), rand 0.7.3
(RUSTSEC-2026-0097), fxhash 0.2.1 (RUSTSEC-2025-0057), and
proc-macro-error 1.0.4 (RUSTSEC-2024-0370). Four scoped ignores are now installed following the resolution below.
Dioxus desktop 0.7.10 still declares Wry 0.53.5; a patch-version bump alone
does not remove the GTK dependency family. See DEPENDENCIES.md for reachability
limits and the locked graph, and REPORT.md for what has actually passed.

Resolution: owner instructed “let’s keep going” on 2026-10-26 after the
scoped-exception proposal and installed libxdo. Proceed with option A: four
explicit advisory exceptions in the isolated spike policy, with reasons and
residual risk documented. Root/production policy remains unchanged. No claim
that all affected APIs are unreachable. Review the lockfile whenever updating.
The missing host libxdo prerequisite is now resolved; full desktop build passes.


Owner chose Dioxus and stock webview input on
2026-10-26 after discussing native/framework copying limits. D8 is resolved.
Original D1 (GTK/JNI input bindings) is withdrawn; original D2 is replaced by the
owner-authorized 0008 amendment and go-ahead for its Dioxus input contract.
User direction authorizes this spec/plan revision; standing approval is not
used to bypass the original scope/spec stop conditions.

## Design

**Workspace/dependencies:** own Cargo.lock and workspace under spikes, excluded
from root default members; pinned dioxus/dioxus-desktop 0.7.3, existing qv-core
path and zeroize version. Dioxus's GTK/JNI transitives remain normal framework
implementation details. No separate input adapters or direct GTK/JNI deps.
Match dx to Dioxus 0.7; do not silently upgrade to installed 0.8 alpha. Use
existing setup-android.sh for SDK/NDK/targets. Reuse root SQLite build flags and
Argon2/BLAKE2 dev optimization. Equivalent stable-toolchain/unsafe/Clippy lints.
Review dependency graph, age, licenses and vet coverage. The owner's explicit
Dioxus selection covers its ordinary transitive graph: document narrowly scoped
per-crate license exceptions required by that graph in the isolated spike policy,
retaining the repository's default policy. Do not add unrelated dependencies or
blanket license allowances. Retain lockfiles and audit/exemption evidence for
owner commit; exemptions are not independent audits.

**Private controller:** owns paths, optional Arc<Session>, operation epoch,
protected pending input, metadata views, busy/error status and last user action.
Core work runs on a worker, never while holding the controller mutex. UI receives
bounded zeroizing metadata snapshots, masks fields, and never receives VK/keys.
Use a thread-safe Dioxus signal or bounded completion notification to re-render.

Private operations: set_password, create_fixture, unlock, list, edit/save,
lock, cancel and benchmark. Bound password to 1,024 bytes and record field/title
input to the existing 256 KiB model limit before conversion/retention. Framework
input events may contain ordinary Strings; promptly wrap/wipe application-owned
intermediates and convert to MasterPassword/SecretBytes/SecretText. Keep pending
secret input in protected Rust containers; do not mirror existing stored secrets
into JS. Editing a protected value uses a blank replacement field; no input means
unchanged. Use password controls, autocomplete/no-learning hints where available,
no spellcheck, and reset/unmount form controls on submit/cancel/lock.

Create only a labeled disposable fixture. Require an explicit recovery-confirmation
skip acknowledgement; record it through Session::record_recovery_skip and drop
the Created phrase without printing/logging it. No claim of complete recovery UX
or production master-password setup; users must use dummy fixture credentials.
List actual core entries; edit title and a protected field through EntryDraft,
preserving unknown/untouched data, save once, lock and reopen to verify persistence.
Use existing DB commit → anchor ordering. No alternate store implementation.

**Lifecycle:** explicit Lock, 60-second spike idle timeout and immediate Android
background lock; native Tao/Wry lifecycle/window events call controller lock
independently of delayed renderer results. Lock increments epoch, cancels work,
clears protected inputs/views, invalidates handles and calls Session::lock. Late
unlock/create completions must lock/drop the new Session; late edit results must
not repopulate the UI. Test races and preservation of old/new committed data.
Use existing framework OS context for FLAG_SECURE, app-private no-backup path
and read-only API probes. Minimal platform glue only when actually needed; stop
for new direct bindings, unsafe, or unplanned public/core API changes. Linux
screen-lock/logind integration not demonstrated by a window-focus test must be
reported as pending rather than claimed.

**Active content:** use bundled local assets and escaped text; no stored HTML,
remote content, user-provided eval or automatic link opening. Exercise injection
and cancellation paths. Stock Dioxus bootstrap/CSP and generic IPC/file-dialog
source risks in REPORT.md remain separate release-hardening issues, not a demand
for guaranteed wiping or a custom engine. This phase uses only synthetic fixture
data and is explicitly non-production; document each unmet release control.
Do not amend 0008 §4.2/§4.3, enable unsafe-inline/eval policies or claim production
compliance just to complete a spike. A release cannot rely on prototype deferrals.

**Probes:** read availability of keystore/biometrics and inspect packaged autofill
entry-point feasibility. Do not enable a provider, quick unlock or device settings.
Clipboard uses a fixed dummy marker only after an explicit app button; never read
the user's clipboard or copy a real vault value in the spike. Record native API
access versus actual validated behavior separately. If a probe needs extra native
bindings, record the exact follow-up instead of quietly adding dependencies.

**Benchmarks:** one warmup plus at most five measured full-profile unlocks per
run. Record individual monotonic timings, fixture/build configuration and process
memory before/during/after using only spike-specific diagnostics. Do not lower KDF
cost or run a stress loop. No secret/phone serial in evidence. Full app persistence
and lifecycle evidence must come from the production core, not mocks.

**Phone boundaries (owner):** use existing authorized localhost:5037 adb server;
install only the inspected, locally built debug spike with a distinct app ID
`org.quickvault.feasibility`. All files/anchors stay in its private directories.
No rooting, personal-data reads, security-setting changes, existing-app/data
removal, wipe or reboot. No accessibility/admin/broad-storage/contact/account
permissions, provider activation or globally exposed adb server. Inspect manifest
and permissions before install. Do not uninstall/clear even the spike without an
owner request. Use dummy data, app-scoped diagnostics and explicit test actions.

## Steps

### Step 1 — Owner decision and spec amendment

- [x] **Do:** Amend 0008 input/memory rules, 0009 framework decision, 0002 recovery
  cross-reference and 0012 validation wording; align index, architecture, roadmap,
  AGENTS and affected skills. Keep unrelated security requirements/statuses intact.
- **Files:** those specs/docs plus this plan and CHANGELOG.
- **Done when:** D8 resolved, native-input-only approval requests withdrawn,
  application-owned secret rules and framework limits explicit.
- **Verify:** scoped cross-reference search and diff inspection; final gates below.

### Step 2 — Isolated reproducible Dioxus workspace

- [x] **Do:** Create spike manifest/config/lints and locked graph, review
  dependencies/coverage and pin compatible build tooling. No source in root crates.
- **Files:** spike Cargo.toml/Cargo.lock/Dioxus.toml; root exclusion/.gitignore.
- **Done when:** host and Android build prerequisites identified; no unapproved
  dependency/license/MSRV change; root and spike graphs separate.
- **Verify:** spike cargo metadata --locked; host cargo check; deny/vet graphs.

### Step 3 — Protected controller and offline fixture

- [x] **Do:** Implement bounded input, create/unlock/list/edit/save and epoch-based
  lock/cancel using existing core. Add persistence/rejection/race tests.
- **Files:** spike src/controller.rs, lib.rs, controller tests.
- **Done when:** save survives reopen; rejected/cancelled inputs preserve state;
  late completion cannot resurrect a Session/view; no secrets in diagnostics.
- **Verify:** spike cargo test --locked (focused controller suite).

### Step 4 — Shared Dioxus UI and Linux evidence

- [x] **Do:** Add masked Dioxus controls, explicit fixture/skip acknowledgement,
  listing/edit flows and reset/unmount cleanup; wire lifecycle and idle lock.
- **Files:** spike src/main.rs, app.rs, platform module, local assets/README.
- **Done when:** real Linux shared flow works and host-runtime evidence is recorded;
  injection/lock cleanup checked; framework gaps reported, not hidden.
- **Verify:** host build/run and focused controller checks; root gates later.

### Step 5 — Android package, safe install and device workflow

- [x] **Do:** Build arm64 APK; inspect manifest/permissions before install; run
  shared create/list/edit/reopen and background/lock races on the connected phone.
- **Files:** spike platform/packaging and reproducible scripts.
- **Done when:** only inspected spike installed; private no-backup storage and
  screenshot flag checked; actual device lifecycle evidence recorded.
- **Verify:** pinned dx Android build; existing adb server commands naming only
  the spike; app-specific diagnostics. No existing/user data touched.

### Step 6 — OS probes and bounded benchmarks

- [x] **Do:** Run the read-only/explicit dummy probes and bounded timing/memory
  procedure on both platforms; leave optional features disabled.
- **Files:** spike probe/benchmark code and sanitized report evidence.
- **Done when:** every required probe has observed results or an explicit gap;
  full-profile unlock timing and process-memory samples retained.
- **Verify:** reproducible run per platform, evidence scrubbed of secrets/serial.

### Step 7 — Report and documentation

- [x] **Do:** Replace preliminary report with measured Linux/Android findings,
  known limits and follow-ups; document actual architecture/technology additions.
- **Files:** REPORT.md/evidence, README, ARCHITECTURE, CHANGELOG, plan index/roadmap.
- **Done when:** build/source/runtime/device evidence distinguished; no repeated
  D8 approval, erasure proof, native-input workaround or production-readiness claim.
- **Verify:** report-to-command/sample cross-check and diff review.

### Step 8 — Gates and reviewer handoff

- [x] **Do:** Run all root and spike gates and inspect secret/lifecycle changes
  under reviewer role; leave phase Implemented for next session's fresh review.
- **Files:** plan/review records and implementation fixes within approved scope.
- **Done when:** required checks green, measured phase criteria complete, no hidden
  failures; tick phase 1.9 only then. Preserve owner staging; never commit/branch.
- **Verify:** SPDX; root/spike fmt, Clippy --all-targets --locked -D warnings,
  locked tests; deny/vet for changed dependency graphs; host/Android builds.

## Test plan

Focused controller tests with actual core persistence; bounded input refusal,
wrong password, lock/cancel/late completions, protected value edit, reopened data.
Host/device shared-flow and background/idle locks; literal text/injection checks.
Keep complete command output in /tmp and preserve exit status. Record skips and
source-only observations honestly. No crypto vectors/format changes. No tests
claim exhaustive wiping of Qt/GTK/JS/OS memory. Required final gates remain all
AGENTS checks and deny/vet when dependencies change.

## Risks and stop conditions

Stop for unrelated dependencies, undisclosed license/unsafe changes, core API/MSRV changes,
phone operations beyond the boundaries, secrets in logs/argv/persisted UI state,
or lifecycle/data failures. Framework-copy limits alone are not blockers. Record
prototype release-hardening gaps without presenting them as production compliance.
No alternative renderer/framework or secret-input adapter unless owner directs it.

## Documentation

- [x] Normative input amendment + Changelogs and specs index.
- [x] D8/framework/memory policy in architecture/roadmap/AGENTS/skills.
- [x] Actual spike status, README, measured REPORT, CHANGELOG, plan index/roadmap.
- [x] Reviewer record, gate results and final status.

## Revisions

- 2026-10-26: Initial proposal required GTK/JNI native input and awaited D1/D2.
- 2026-10-26: Owner explicitly selected stock Dioxus/webview input and bounded
  cleanup claims. Revise unstarted plan in place; approval is owner direction,
  not standing approval. Withdraw D1; D2 resolved through the approved amendment.
  D8 is settled. No fork/custom engine or further native-input approval needed.

## Execution log

- 2026-10-26: Approved revised direction; step 1 amended specs/docs before code.
  Existing staged review/planning records are preserved; new edits are unstaged.
  No phone actions beyond earlier read-only prerequisites yet. Next: isolated
  workspace/dependency review, controller, shared UI and measured validation.

## Earlier execution log (superseded proposal)

- 2026-10-26: Prerequisite investigation only. Current dx is 0.8.0-alpha.0,
  while the roadmap calls for 0.7; installed Rust targets currently list only
  x86_64-unknown-linux-musl. GTK 3.24.52 and WebKitGTK 2.48.1 pkg-config entries
  exist. Phone is authorized through owner-started adb at localhost:5037 and
  meets D7: model 2412DPC0AG, API 35, arm64-v8a, MemTotal 11,584,740 KiB.
  Only model/API/ABI/RAM were read. No APK, fixture, clipboard marker, keystore
  object or service was installed/created/enabled on the phone.
- 2026-10-26: Reviewed upstream Dioxus 0.7 mobile guide and downloaded source
  archives dioxus-desktop 0.7.3, Wry 0.53.5 and Tao 0.34.0 to /tmp for planning.
  Wry exposes safe Android dispatch with JNIEnv/activity, enabling a design
  without custom unsafe JNI exports. GTK/JNI direct bindings and Draft §4
  go-ahead still require D1/D2; no dependency or implementation change made.

- 2026-10-26: Preliminary stock-renderer source risks are recorded in REPORT.md:
  injected inline bootstrap/eval, IPC ingestion bounds and framework file-dialog/
  navigation behavior. Step 3 must evaluate them before real secret input;
  no contract exception or framework patch is authorized by this plan. If the
  native/CSP contract cannot be met, stop with evidence for D8/follow-up work.

- 2026-10-26: Documentation handoff checks passed: SPDX, fmt, Clippy with
  -D warnings, locked root tests (456 passed, 0 failed, 2 ignored), and
  git diff --check. Logs: /tmp/qv-phase19-{spdx,fmt,clippy,test}.log.
  No dependency/code/build-input change; no deny/vet run required yet.
  Native binding/Draft-scope approval was requested; implementation remains
  pending that answer. No phone operation beyond the read-only prerequisites.

- 2026-10-26: Developer began revised step 2: isolated minimal Dioxus 0.7.3
  graph (no direct GTK/JNI, devtools or Tokio-runtime features), protected core
  path dependency, lints, profile optimization and root exclusion. No app code
  or device installation before dependency-policy review.

- 2026-10-26: Step 2 dependency review resolved 497 packages initially. Dioxus
  0.7.3's internal semver dependencies resolve to 0.7.10; record exact versions
  in the spike lockfile. Minimal desktop without tokio_runtime fails in
  upstream edits.rs (unconditional Tokio calls); enable its normal runtime
  feature, with devtools still disabled. No fork or new direct dependency.
  Architect records isolated per-crate exceptions for ordinary Dioxus graph
  licenses (BSD-3-Clause, ISC, MPL-2.0, Zlib), as part of the owner's explicit
  choice to use Dioxus; no global allowlist expansion or new approval loop.

- 2026-10-26: Revised Dioxus input policy implemented in specs/docs. Added
  isolated workspace, shared Dioxus fixture UI, protected controller and
  small framework OS hooks (no direct GTK/JNI input adapters). Controller
  tests pass (2: real-core create/edit/reopen, refusal bounds/wrong password,
  explicit skip, idle/lock and discarded late Session results). Default UI
  cargo check and all-target Clippy pass; full GUI linking fails because
  libxdo development library is absent. A downloaded host-only package has
  libxdo.so.4, not the requested libxdo.so; no ABI substitution was made.
- 2026-10-26: Dependency check: isolated per-crate license exceptions for the
  standard Dioxus graph make licenses/bans/sources pass. Four advisories still
  fail the required gate; D3 records the owner decision instead of silently
  adding ignores. Vet against a temporary copy of root audit records reports
  396 missing coverage entries; no mass audit/exemption or root-store change.
  Plan Blocked; no phase tick, GUI runtime claim, Android build or phone install.
  Full logs/evidence in REPORT.md. No existing staged work was staged over.

- 2026-10-26: Reviewer pass found that old queued form input needed the same
  invalidation as late worker results. Added a local form-generation/busy guard
  to password/title/replacement input and a stale-input regression assertion,
  exactly as 0008 §4.4 requires. No core/public API/format change. Re-running
  affected spike checks; root code/build inputs unchanged.

- 2026-10-26: Owner installed libxdo and directed continuing. Desktop build
  now passes. Resolved D3 as the previously proposed spike-only advisory
  exceptions with per-ID reasons; no root/production ignore. Resumed In progress.
  Owner-staged files are preserved; edits remain unstaged. No phone install yet.

- 2026-10-27: Resumed developer work. Host prerequisites resolved; default
  GUI-linked tests pass (2), and Linux create/edit/save/lock/reopen succeeds.
  Verified literal script-like title rendering and empty controls after save;
  keyed the whole entry form to ensure remount. Fixed already-locked idle form
  churn, with regression assertion. Linux five unlocks: 408/406/402/408/410 ms;
  sampled app-process RSS peak 428732 KiB (25 ms sampling, excludes renderer
  processes). One warmup, unchanged full profile, dummy data only.
- 2026-10-27: Built pinned dx 0.7.3 from source, Android arm64 release library
  and debug-signed package. Added build-only wrapper enforcing minSdk 29 in a
  copied generated Gradle project. Inspected distinct ID, permissions, backup,
  signature and native imports. Added inert OS availability/service packaging
  hooks; runtime availability and lifecycle evidence still pending. Isolated
  deny/vet pass with approved exceptions and documented initial exemptions.
- 2026-10-27: Reconnected owner phone reachable via existing adb server. No
  pre-existing spike package. First install rejected as USER_RESTRICTED;
  owner saw a USB installation restriction and requested retry. No setting
  changed or bypass attempted. Continuing docs/local verification meanwhile.

- 2026-10-27: Owner requested retry; second install returned the same
  INSTALL_FAILED_USER_RESTRICTED error. No APK installed or launched. Owner
  phone configuration is unchanged. Android device validation remains pending;
  no phase tick/status completion. Partial reviewer record and report refreshed.

- 2026-10-27: Third install succeeded after owner resolved the phone restriction;
  launched only the spike. Owner observed blank UI. App-PID-scoped log identified
  a Dioxus edits.rs startup panic: loopback TcpListener::bind denied without
  Android INTERNET permission. Framework source binds 127.0.0.1 with ephemeral
  port and per-process transport keys. Add the standard Android socket permission
  required by this selected framework; no remote networking feature, personal-data
  permission, dependency or security-setting change. Rebuild/reinspect before
  updating only this newly installed spike (retain its data). Document that the
  permission itself grants broader network capability than loopback.

- 2026-10-27: INTERNET fixed the Rust listener panic but owner still observed
  white WebView. Source comparison found custom manifest omitted upstream
  networkSecurityConfig reference. Restore the required 127.0.0.1 cleartext
  WebSocket exception with a checked-in policy explicitly denying remote
  cleartext; no global cleartext flag or CSP waiver. Owner independently
  uninstalled the spike and requested reinstall. Build and inspect before
  fresh install; no agent uninstall/data-clear action.

- 2026-10-27: Refreshed root/spike SPDX, fmt, all-target Clippy -D warnings,
  locked tests and deny/vet pass. Root 456 passed/2 ignored; spike 2 passed.
  Logs /tmp/qv-continue-*.log. Subsequent packaging-only fixes rebuilt and
  inspected; Rust inputs unchanged. Latest APK SHA-256
  3815e2049f946a323b6fe28d1368e88f0a4e6f2b06674eb24eb07cfebf186e39.
  Actual manifest/resource enforce minSdk29, backups off, INTERNET plus own
  signature permission, remote cleartext denied and 127.0.0.1 exception only.

- 2026-10-27: Fresh install of loopback-policy package succeeded; launch -W
  completed normally. Owner confirmed the shared form is now visible. The two
  packaging fixes resolve the observed startup/UI failures. Requested dummy
  create/edit/save/lock/reopen and background-lock exercise; results pending.

### Diagnostic scope revision — 2026-10-27

Android creation returns redacted StoreError::Io with empty fixture/anchor dirs.
To diagnose the approved real-core device flow, temporarily instrument private
qv-store error mapping/create/SQLite hardening stages with static labels and
numeric SQLite/errno values only. No paths, SQL text, password, title, IDs or
payloads. Files: crates/qv-store/src/{error,vault,sqlite}.rs. This is diagnostic
observation, not a normative storage/format/API/ordering change. No dependencies
or public feature added. Preserve exact originals, retain a sanitized diagnostic
patch as build provenance, build/inspect the diagnostic APK, and restore originals
before handoff. No checks may be disabled; any actual storage fix requires its
own evidence and plan revision before implementation. Verify original source
restoration, root/spike gates on the final source, and only PID-scoped phone logs.

- 2026-10-27: Diagnostic stage-only APK built/inspected, SHA-256
  9b9bebe49e4dc64672b0d3525165098b7399f1859e08f33bf39735c7c3809faa.
  Exact original qv-store source restored after build; git diff for that crate
  is empty. Diagnostic patch retained at evidence/android-storage-trace.patch;
  only added fixed-stage and numeric-code output, no storage behavior changes.

- 2026-10-27: Diagnostic trace reached sqlite-open and returned extended code
  1550 (SQLITE_CANTOPEN_SYMLINK), before hardening/KDF. SQLite source confirms
  NOFOLLOW rejects symlinks in ancestor components. Architect revision: resolve
  the existing OS-provided Android noBackupFilesDir with std::fs::canonicalize
  before joining the dedicated fixture root, failing initialization on failure.
  This is private platform path adaptation within the existing spike, not a
  storage-policy/format/API change. Retain every qv-store NOFOLLOW/owner/mode
  check; no fallback, data migration, deletion or broad file selection. Developer
  rebuilds the normal uninstrumented source and tests on device; reviewer checks
  original core restoration and unchanged refusal semantics. No new dependency.

- 2026-10-27: Normal (untraced) path-fix APK rebuilt, inspected, updated and
  launched successfully; SHA-256
  57e68b1417efc9622f212e7552783741e856ec5517de3d0b908adfe2970e7e60.
  Affected SPDX, root/spike fmt, spike all-target Clippy and 2 locked tests
  pass (/tmp/qv-canonical-*.log). Original core bytes match backups. Requested
  creation retry to verify the observed SQLite symlink refusal is resolved.

- 2026-10-27: Owner confirmed the path-fix build now works. App-only metadata
  shows a private 0600 encrypted fixture and 0600 separate anchor. Shared core
  source remains unchanged. Requested confirmation of edit/reopen/background,
  screenshot refusal, availability output and bounded Android benchmark. Retained
  sanitized Linux numeric CSV at evidence/linux-unlock.csv.

- 2026-10-27: Owner confirms all requested physical-device exercises work:
  edit/save/lock/unlock preserves title; Home/reopen is locked; screenshot attempt
  blocked as expected; API availability button and five-sample benchmark worked.
  Collected only numeric CSV from this app's private directory, validated its
  exact header/5 numeric rows, retained evidence/android-unlock.csv. Unlock ms
  852/865/861/866/881 (median865); sampled main-process RSS peak617980 KiB,
  excludes renderer processes. Exact API feature booleans not retained; full
  adapters remain explicitly unvalidated. Device is not a low-end budget proxy.
  Report rewritten around final observations/gaps; implementation-session
  reviewer check refreshed. Final root/spike gates running, no further phone
  operations needed. Leave final app/data installed; fresh review next session.

- 2026-10-27: Final root and spike gates all pass: SPDX, fmt, all-target
  Clippy --locked -D warnings, locked tests (root456 passed/2 ignored;
  spike2 passed), deny and vet. Logs /tmp/qv-final19-*.log; dependency commands
  use the retained policies/stores with only advisory-cache location overridden.
  diff --check and shell syntax pass. Normal Android build/runtime evidence and
  numeric Linux/Android CSVs retained in REPORT.md/evidence. All feasibility
  steps complete; plan Implemented and roadmap phase1.9 ticked. Production gaps
  remain explicit; no spec marked fully Implemented. Next session must review
  this phase with fresh context. No commit/staging/branch/push performed.

- 2026-10-27: Fresh-context review of committed 981c39d..18e426c approved
  the disposable feasibility scope; no fixes or new escalations. Independently
  reran SPDX, root/spike fmt, all-target Clippy, locked tests (root456 passed,
  2 ignored; spike2 passed), deny and vet; all pass. Logs /tmp/qv-review19-*.log;
  command/cache details and limits in REVIEW.md. Device evidence was reviewed,
  not rerun; no phone operation performed. Status Reviewed. Next: remaining CLI
  phase 1.10b, subject to the separate clipboard planning decision in plan 0014.
