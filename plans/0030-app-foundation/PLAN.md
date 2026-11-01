# Plan 0030 — Shared app foundation and webview security boundary (roadmap 2.4)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-31 | 2026-10-31 | 0008 §1, §3–5; 0009 §1.1–1.6, §2, §5; 0002 §4.2; 0010 §4.2 |

## Intent

Build the shared Android/Linux production app's security boundary and initial
create, unlock, lock and local recovery flows. Preserve Dioxus and its ordinary
secret input controls, with protected Rust state, bounded ingress and visible
protection status. Owner approved this architecture under D13 on 2026-10-31.

## Scope

In scope: qv-app, its shared screens/controller, strict webview integration,
Android lifecycle/FLAG_SECURE/keyboard and private-storage glue, Linux platform
configuration and instance ownership, local asset packaging and adversarial
tests. All vault operations remain through qv-core. Include the necessary
core platform/confirmation reexports only where the app cannot use the current
core facade; no frontend crypto/store dependency.

Out of scope: the full vault workflows in 2.5, quick unlock/autofill in 2.6–2.7,
network sync, an alternate renderer, native secret-entry dialogs, format
migration, release approval and a claim of deterministic framework erasure.
Do not split this phase by step count or context size.

## Spec basis

| Behaviour | Spec | Status / authority |
|-----------|------|--------------------|
| Shared UI, core facade and platform adapters | 0009 §1.1–1.6, §5 | Draft; explicit phase-2.4/D13 owner go-ahead |
| Bounded input, cleanup and lifecycle cancellation | 0008 §1, §3–5 | Draft; D5, D8 and explicit phase-2.4 go-ahead |
| Local assets, strict CSP, navigation/bridge restrictions | 0008 §4.2–4.4 | Draft; explicit phase-2.4 go-ahead; no exception to requirements |
| Generated master password and typed strength/delay | 0010 §4.2; 0008 §1 | Accepted generator; owner-approved frontend integration |
| Creation phrase display and confirmation/recorded skip | 0002 §4.2 | Accepted |
| Local phrase recovery and anchor handling | 0002 §4.3, §8; 0005 §5.4 | Accepted crypto; existing owner-approved core recovery semantics |
| Supply-chain and validation evidence | 0012 §1, §3 | Accepted |

Spec changes required: none for the proposed integration. Do not loosen CSP,
bridge or secret-lifetime requirements to accommodate the framework.

## Decisions needed

1. **Authorize one additional maintained vendor package and its dependency
   integration.** Recommend a narrowly scoped hardened integration of
   `dioxus-desktop = 0.7.10`, retaining Dioxus's standard interpreter and input
   controls. Approve an explicit vendor exception for that exact package,
   alongside existing x11rb, and the framework/support dependency graph below.
   Preserve upstream licensing and existing upstream lints/unsafe code;
   QuickVault code and new patch code introduce no unsafe. Approve the listed
   AGENTS/checker/provenance/CI changes needed to maintain this exception.

   Why necessary: stock 0.7.3 and inspected 0.7.10 generate inline bootstrap
   modules even with a custom index, deserialize IPC before app checks, and
   expose built-in file-dialog/filesystem and browser-opening routes. The
   public Config API has no hook replacing all those boundaries. 0.7.10's
   navigation callback is reached after its implicit http/https/mailto opener,
   so it does not resolve the full navigation requirement.

   Alternatives: wait for upstream hooks (no current phase implementation),
   or a separate renderer integration (larger architecture change). A CSP
   exception is not proposed. This is an active-content/ingress requirement,
   unrelated to the accepted best-effort framework-memory-copy limits.

   Resolution: owner delegated the recommended choice and continuation on
   2026-10-31 ("Whatever you say man."). The exact dioxus-desktop vendor
   exception and listed dependency integration are approved. D13 is already
   resolved; neither approval needs to be requested again.


2. **Production dependency remediation beyond the exact desktop package.**
   Actual dependency checks fail after feature trimming: glib 0.18.5
   unsoundness, two unmaintained crates and old rand remain; 16 licenses need
   scoped allowances and current locked audit imports leave 395 candidate
   versions uncovered. See [DEPENDENCIES.md](DEPENDENCIES.md) and its exact
   [UNVETTED.json](UNVETTED.json) candidate list.

   Recommend authorizing the four additional package patches (glib,
   glib-macros, gtk3-macros, selectors), maintained replacement helper
   dependencies, exact compatible license allowances and a documented
   development audit-debt baseline after minimizing/import assessment. Keep
   no advisory ignores, no product unsafe and no false audit certification.
   This extends D1's exact vendor scope and requires a new dependency-policy
   disposition; D1 and D13 remain resolved. Alternative: wait for upstream
   remediation. Blocks Step 1 and all dependent implementation. Resolution:
   owner delegated phase choices and tradeoffs on 2026-11-01.
   Proceed with the recommended source remediation, scoped licenses and
   documented version-specific development audit debt; retain advisory gates.

## Design

### Components and interfaces

qv-app depends on qv-core, Dioxus and UI parsing/support libraries, never on
qv-crypto/store/model directly. qv-platform gains Android services; core
reexports their construction as it does Linux services. The renderer remains
part of the trusted client. Hardened dependency integration is an opt-in
configuration on the maintained desktop package, used for every app window.

App interfaces (private unless required by the test harness):

```rust
struct Controller { /* shared protected state, epoch, bounded worker */ }
enum Action { Create, Unlock, Recover, Lock, Cancel, ConfirmPhrase, SkipPhrase }
struct FormEpoch(u64);
impl Controller {
    fn input(&self, epoch: FormEpoch, field: InputField, value: &mut String);
    fn submit(&self, epoch: FormEpoch, action: Action) -> Result<(), AppError>;
    fn lock(&self); // increments epoch, cancels work, drops all protected state
    fn snapshot(&self) -> View; // redacted status and allowed display only
}
```

`AppError` is a data-free enum wrapping the existing data-free core categories;
all messages are static. No input, path, URL, raw IPC, debug dump or underlying
OS/framework error enters diagnostics. View is not a general secret transport.
Phrase text has a separate short-lived, epoch-checked protected display path.
No revealed entry values exist in this phase.

### Renderer boundary

Maintain only dioxus-desktop 0.7.10. Record the upstream archive and SHA-256
`236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d`.
Expected patch areas: config.rs (opt-in policy), protocol.rs (local static
bootstrap and asset allowlist), webview.rs (IPC/origin/navigation/popup
checks), ipc.rs/app.rs (permitted framework methods), edits.rs (bounded local
transport). Tests may live in a new dependency-local module. Any required
patch outside this package follows the approved D2 remediation below.

Replace DOM inline bootstrap modules with a bundled same-origin module route;
do not install the unused document-eval module or offer query/browser-open
methods in hardened mode. Standard DOM event serialization and mutation
rendering remain. Do not introduce raw HTML rendering or executable content
from vault strings. Deny file-dialog, arbitrary filesystem resolution and
unknown protocol routes. Serve only compiled assets; no path-based fallback.

At native IPC ingress, check the exact local main-document origin and a
64 KiB UTF-8 body limit before JSON parsing or queueing. Permit only one
initialization and bounded ordinary user events; unknown/query/browser-open
messages refuse. Validate node/event/epoch and field bounds again in Rust
before dispatching app actions. Cap queued app work at one task; busy/new
submissions refuse, rather than spawning unbounded workers. Reset permits on
completion/drop. Lock always bypasses a busy refusal and cancels the task.
The framework-created String and event copies remain documented intermediates;
do not claim these native checks prevent all engine-side allocation.

CSP baseline: default-src 'none'; script-src 'self'; style-src 'self';
img-src 'self'; font-src 'self'; object-src 'none'; frame-src 'none';
base-uri 'none'; form-action 'none'. No unsafe-inline, unsafe-eval or remote
origin. connect-src allows only the exact current authenticated loopback UI
transport endpoint plus required same-origin framework event routes. Deny
subframes, popups, permissions/downloads and every navigation after the exact
initial local document, including lookalike hosts and local alternate paths.
No external-link feature is needed for these foundation screens. Include CSP
on generated HTML responses and verify enforcement in the real engine.

Bound the loopback handshake, frame/message sizes, worker/connection count and
timeouts before accepting UI transport messages. Acknowledgements have a fixed
bounded shape; unexpected messages fail closed. Preserve the existing
constant-time transport-key check; no new crypto construction. Redact transport
failure logs so handshake paths cannot expose transport keys. These measures
must be exercised at actual ingress, not solely in app helper predicates.

### Flow, storage and secrets

On startup harden before reading secrets; obtain private OS state roots,
configure core snapshots/platform services and acquire the Linux instance
guard before displaying secret controls. Paths are chosen by native selection
or bounded local path input handled in Rust, never by an arbitrary filesystem
bridge. App-owned anchors/snapshots remain outside the selected active vault
directory. Android uses canonical OS noBackupFilesDir, backup disabled.

Show process/memory/platform protection and explicit reduced-protection consent
before persistent use. Owner amendment 2026-11-01: Linux OS lock/sleep monitoring
is optional; its absence is prominent, with manual/idle locking always active.
Android lifecycle monitoring remains required.
Use existing core create/unlock/phrase-unlock/anchor-recovery APIs, with their
existing transaction → anchor → report ordering. Do not create a second write
path or change file formats. Wrong password, integrity, missing anchor and
rollback remain distinct fixed error categories. Anchor adoption requires the
existing explicit recovery-baseline consent and verified recovery snapshot.

Password limit: 1024 UTF-8 bytes; phrase limit: 1024 UTF-8 bytes; display-name
limit: 1024 UTF-8 bytes; local path limit: 4096 UTF-8 bytes. Bound before
normalizing/copying; reject invalid/oversized input. Protect application-owned
Rust copies through core's SecretBytes/MasterPassword facade and clear incoming
mutable buffers promptly. No protected value enters persistent signals,
ordinary app String caches, Debug, logs, errors, argv or environment. Shared
masked Dioxus inputs clear on submit/cancel/lock by controlled reset/remount;
use no-learning/password/autocomplete hints where supported.

Creation uses core password-strength assessment and existing weak-password
confirmation semantics. Keep returned session and phrase protected until three
random positions are confirmed or an explicit skip calls the existing core
record_recovery_skip operation. Drop phrase on completion/cancel/lock. A
durably created vault can remain after cancellation; report that existing
outcome accurately and never claim cancellation undid a durable write.

Each operation carries the current epoch plus CancelToken. Lock advances the
epoch first, cancels pending work, locks live sessions and destroys forms,
phrase/error/result state. Late task completions drop their result without
reopening or populating the screen. Poll core's locked state and receive native
lifecycle notifications to clear renderer state even without another user
action. App inactivity locks after 60 seconds for this foundation, matching
the existing spike; treat it as a local default, not a format commitment.

Android lifecycle installation precedes accepting input: screen-off/sleep,
background expiry and destroyed activity lock/cancel; returning foreground
never unlocks. Use immediate background locking as a conservative policy.
FLAG_SECURE is set before the window is shown. Configure password/no-suggestion
input hints; report unsupported hardening rather than claiming enforcement.
Keystore and quick unlock stay unavailable. OS callbacks carry metadata only.
Validate JNI/dispatch mechanisms through the existing Wry integration rather
than adding unsafe product code. Real-device checks remain necessary.

### Dependencies

| Dependency | Purpose / alternatives | Review status |
|------------|------------------------|---------------|
| dioxus 0.7.10, dioxus-desktop 0.7.10 | Shared standard webview UI; align framework versions instead of duplicating UI | D8 selects Dioxus; D1 vendor exception approved |
| serde 1.0.229, serde_json 1.0.154 (maintained desktop dependency) | Typed bounded IPC envelopes; hand parsing adds an unnecessary parser | Used inside integration; no independent audit claimed |
| url 2.5.8 (maintained desktop dependency) | Exact parsed URL/origin checks; avoid substring scheme/host checks | Used inside integration; no independent audit claimed |
| ctutils (workspace version) | Constant-time password-repeat/generated-suggestion comparison | Existing workspace dependency |
| zeroize 1.9.1 | Prompt cleanup of unavoidable framework event intermediates | Existing workspace version |
| qv-core and existing platform graph | Vault/session services and OS hooks | Reuse current workspace; no primitive/format change |

Pin direct versions; resolve and review the actual transitive graph before
writing app flows. Run deny and vet for root and all affected isolated
consumers. D2 authorizes assessed, exact-version development audit exemptions; record
the missing coverage honestly. No advisory ignores, blanket publisher trust or
fabricated audits. Keep optional UI features from making default
headless tests depend on a graphical display, but CI must also compile/test the
real desktop feature; headless-only success cannot complete this phase.

## Steps

### Step 1 — Approved dependency integration and provenance

- [x] Do: after D1 approval, add the exact vendor package, opt-in hardened
  configuration and provenance controls; review resolved dependency/audit graph.
- Files: third-party/dioxus-desktop, third-party/README.md, AGENTS.md, SPDX
  checker/rejection fixtures, Cargo.toml/lock, supply-chain records, CI.
- Done when: hashes/licenses and exact patch scope are reproducible; no unsafe
  product code; dependencies pass unchanged security policy or explicitly stop.
- Verify: `sh scripts/test-check-spdx.sh`, `sh scripts/check-spdx.sh`,
  `cargo deny check`, `cargo vet --locked`; record vendor package tests.

### Step 2 — Webview ingress, assets and runtime security harness

- [x] Do: implement the strict integration above and actual-ingress regression
  tests, then a disposable-data engine harness on Linux and Android.
- Files: approved vendor patch areas; crates/qv-app boundary/assets/harness;
  crates/qv-app/Cargo.toml and Android test glue.
- Done when: CSP boots the UI with no inline/eval exception; malicious HTML,
  URL, IPC and protocol requests fail safely; no built-in bypass remains.
- Verify: `cargo test --locked -p qv-app boundary`, dependency-focused tests,
  Linux real-engine harness; Android harness recorded. Stop before real secrets
  if the selected integration cannot enforce a requirement.

### Step 3 — Shared controller and protected forms

- [x] Do: implement the epoch/task/cancellation state machine and bounded input
  conversion; expose only current authorized actions and fixed error/status views.
- Files: crates/qv-app/src/controller.rs, input.rs, error.rs and focused tests;
  qv-core facade reexports if needed.
- Done when: wrong epochs, oversized input, invalid actions, lock during work
  and late results fail safely and drop protected state.
- Verify: `cargo test --locked -p qv-app controller`,
  `cargo test --locked -p qv-app input`.

### Step 4 — Core-backed foundation flows

- [x] Do: create with recovery confirmation/recorded skip; password unlock,
  phrase recovery, explicit anchor recovery and lock/cancel. Include process,
  memory and OS status with reduced-protection acknowledgement.
- Files: app controller/flow tests; core facade only as needed.
- Done when: persisted vaults reopen via core; wrong password/phrase and unsafe
  recovery refuse; lock cannot be undone by a late success; no secret logging.
- Verify: `cargo test --locked -p qv-app flows`; affected core tests.

### Step 5 — Linux app startup and shared UI

- [x] Do: responsive shared screens, packaged local styles/assets, private
  root setup, platform injection, instance guard and renderer cleanup on lock.
- Files: crates/qv-app UI/entry point/assets and Linux packaging.
- Done when: real Linux runtime create/unlock/lock/recover works offline;
  unsafe storage/second instance refuse; absent Linux monitoring is disclosed
  and permits use after reduced-protection acknowledgement.
- Verify: `cargo check --locked -p qv-app --features desktop`, engine harness
  and disposable-vault manual checklist with results recorded.

#### Linux capability follow-up — owner amendment 2026-11-01

- [x] Amend 0008 §1.4/0009 §5 and index first, preserving Draft status and the
  owner's explicit implementation approval. OS integration is optional on Linux;
  manual/idle locks and every received lock notification retain full cleanup.
- [x] Add explicit Linux core configuration (`Core::with_linux_platform`) that
  attempts lifecycle attachment and permits an unavailable watcher only with
  reduced-protection acknowledgement. Existing with_platform/Android stays strict.
  An already-observed lock still cancels opening. No storage/crypto/format change.
- [x] App startup attempts the Linux watcher but accepts unavailable capability.
  Track failed installation/loss in redacted view/protection status, show a
  persistent warning on locked/phrase/unlocked screens. Rearm before opening;
  loss of previously available monitoring clears forms once and requires fresh
  acknowledgement before a retry. Unknown/missing capability never masquerades
  as an active watcher. Android remains strict.
- [x] Test absent watcher create/unlock/phrase recovery, consent rejection,
  manual/idle lock and late-result handling; retain available-watcher event tests
  and explicit initial-lock rejection. Exercise real Linux UI with missing login1.
  Run all product gates and Android compilation. Record actual runtime evidence
  without promoting passing tests into a security or release claim.

### Step 6 — Android adapters and packaging

- [x] Do: lifecycle, FLAG_SECURE, keyboard hints, private no-backup storage and
  production app identity/package. Core exposes platform construction to app.
- Files: crates/qv-platform Android module/tests, core reexports,
  crates/qv-app Android packaging/scripts; CI cross-build jobs.
- Done when: shared UI builds for supported arm64/API29+; no secret-bearing
  native callback; unsupported quick unlock stays disabled.
- Verify: Android cross-build using the pinned SDK/NDK recipe; inspect packaged
  manifest, permissions, backup rules and signature. Do not read SDK internals.

### Step 7 — Physical-device and cross-platform adversarial evidence

- [x] Do: run instrumented/engine injection, input clearing, screen lock,
  suspend/background, late-result, recovery phrase and screenshot tests on
  supported Android hardware and Linux desktop where available.
- Files: app/platform integration tests, Android instrumentation, plan evidence.
- Done when: results identify actual devices/platforms and failures; missing
  hardware leaves phase incomplete, never represented as a passing test.
- Verify: `cargo test --locked -p qv-app`; Android instrumented runner;
  private Xvfb and real-desktop procedure where relevant. Request the owner's
  phone only when an inspectable APK/test package is ready.

### Step 8 — Documentation and final gates

- [x] Do: update current component/technology status, app entry points,
  framework-memory and OS limitations, dependency record and phase log.
- Files: ARCHITECTURE.md §3/§6/§7, CHANGELOG.md, .agents/README.md navigation,
  plan evidence, plans index/roadmap; specs only if approved scope changes.
- Done when: full requirements and runtime evidence are met; only then mark
  Implemented/tick 2.4. No blanket spec status promotion or release claim.
- Verify: final gate set below; fresh-context review is the next session.

## Test plan

Final gates: `sh scripts/check-spdx.sh`, `sh scripts/check-matrix.sh`,
`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
`cargo test --locked`, `cargo deny check`, `cargo vet --locked`. Also compile
the real UI feature, cross-build Android, run instrumented/engine checks and
maintained-vendor focused tests. Keep logs in /tmp and preserve exit status.

Cover unknown/oversized/deep/duplicate-key IPC, forged node/session/epoch,
HTML/URL injection, alternate origins, frames/popups, filesystem/file-dialog
routes, remote subresources, malformed loopback handshakes/frames, queue limits,
input cleanup on every refusal/error/cancel/lock, initial locked state, lock
during KDF, late results and exact recovery outcomes. Runtime tests exercise
production configuration, not helper predicates alone. Tag tests for 0012 §1
rows Webview exposure and Ambiguous trust boundary; do not infer that every
release requirement is proven from their presence.

## Risks and stop conditions

- D1 and D2 are resolved by owner delegation; continue without intermediate
  approval requests for dependency/integration decisions within this phase.
- Evaluate and record routine dependency/integration choices under the owner
  delegation. Preserve the no-advisory-ignore and no-product-unsafe choices;
  do not weaken the active-content, secret-handling or validation requirements.
- Missing physical hardware prevents completing runtime evidence; keep the
  durable phase log rather than inventing another phase suffix.
- Preserve core/storage/crypto contracts and existing owner work; no format or
  normative changes are authorized by this plan without separate approval.

## Documentation

- [x] CHANGELOG.md — foundation, limitations and completed evidence.
- [x] ARCHITECTURE.md — app/current OS boundary and integration status.
- [x] Specs — no change; statuses unchanged.
- [x] AGENTS.md/SPDX checker/third-party provenance — only if D1 approved.
- [x] .agents/README.md — app/packaging navigation when implemented.

## Revisions

- 2026-10-31: D1 approved by owner delegation. During Step 1, actual
  production-policy checks exposed the distinct transitive remediation/audit
  disposition in D2. Keep all existing steps and the whole-phase scope;
  propose the additional package patch authority in DEPENDENCIES.md before
  adding any source or production dependency. No phase split or policy waiver.

## Execution log

- 2026-10-31: D13 resolved by owner's "Yes". Planning continues on the current
  review-documentation tree; no commit/session question is needed. Inspected
  actual 0.7.3 cached source and downloaded upstream 0.7.10 archive, including
  Config, protocol, native IPC/navigation and loopback transport. Public hooks
  do not meet the complete existing contract. Latest source/reference:
  https://docs.rs/crate/dioxus-desktop/0.7.10/source/src/.
  Proposed D1 is required by roadmap Session protocol step 4 and AGENTS.md's
  sole-vendor exception. No source/dependency/spec changes or implementation.
  Prior independent gates for unchanged product inputs remain current evidence
  (0029 REVIEW.md, /tmp/qv29-review); plan/doc checks are recorded at handoff.
- 2026-10-31: Plan-only handoff checks pass: `git diff --check`,
  `sh scripts/check-spdx.sh`, `cargo fmt --check` (logs /tmp/qv30-inspect).
  Product source, dependencies, features and test inputs are unchanged from
  the independent 0029 full-gate pass; no second full suite was needed for
  these Markdown-only changes. Await D1 before any implementation.

- 2026-10-31: Owner approved the recommended D1 integration by delegation
  ("Whatever you say man."). Set In progress and continue on the staged
  documentation tree, preserving the index. Start by checking the dependency
  graph against the unchanged production supply-chain policy before renderer
  patches or app flows. No automatic advisory/audit-policy exceptions.

- 2026-10-31: Step 1 prerequisite assessment performed in an isolated /tmp
  probe to preserve the staged tree and current root graph. Trimmed unused
  image codecs using only the approved desktop manifest scope; paste drops
  out, but four advisories and 16 license entries remain. Vet with a copied
  locked root store reports 395 uncovered candidate package versions.
  Dependency bans/sources pass after correcting a probe-only wildcard.
  Recorded dependency paths, exact candidate list and recommended remediation
  in DEPENDENCIES.md/UNVETTED.json. Set Blocked on D2: the plan explicitly
  requires stopping on further vendor packages or a new audit-policy
  disposition. No app/renderer source, root lockfile or security policy
  changed. Existing owner staging is preserved. D1 and D13 stay approved.

- 2026-11-01: Owner explicitly delegates choices/tradeoffs and requests no
  further approval checkpoints until the UI is ready for major review. D2
  approved; resume In progress. Choose small provenance-tracked upstream
  correctness/maintenance patches over ignoring advisories or replacing the
  selected renderer. Trim unused image codecs. Use exact compatible license
  exceptions and clearly named development audit debt instead of claiming
  unperformed audits. This instruction overrides inferred intermediate
  approval/commit/session boundaries; preserve staging. UI hardware evidence
  remains honestly separate from container tests.

- 2026-11-01: Implementation continuation: added qv-app protected forms,
  epoch/worker cancellation, create/confirmation/skip, password and phrase
  unlock, explicit snapshot-backed anchor recovery and responsive shared UI.
  Added Android lifecycle metadata adapter and native window/webview hardening.
  Maintained five new snapshots; GLib mutable-pointer backport, diagnostic
  helper proc-macro-error3 (error2 rejected as also unmaintained), selectors
  rustc-hash/phf update and PNG-only image graph. No advisory ignores. Scoped
  license exceptions and assessed development vet debt; prior run passed
  deny and vet (93 fully/11 partially audited/404 exempted), not certification.
  Added isolated vendor-test workspace and CI app/Android jobs. Initial Linux
  WebKit boundary harness and seven controller tests passed; full rendered-flow
  harness still needs diagnosis (fixed metadata-only stage reporting exists).
  Optimized GLib iterator, selectors and macro regressions passed in the prior
  environment. Android native build and app/instrumentation APK assembly also
  passed, but must be rebuilt after the last source changes. No connected
  Android device; physical instrumentation is pending. UI screenshots were
  visually checked at desktop/mobile widths; latest mobile CSS keeps the
  primary form above the fold. Host environment reset removed /tmp tools/logs
  on owner continuation; restore tools and revalidate final inputs. Preserve
  staged owner changes, no commits/branches/pushes. Do not mark phase complete
  or tick step 7 without actual device evidence. Continue the authorized phase;
  no further approval checkpoint is needed.

- 2026-11-01: Final continuation evidence in [VALIDATION.md](VALIDATION.md).
  Linux actual-WebKit boundary and complete rendered create/confirm/lock/wrong
  password/unlock/phrase-recovery flows pass (2 engine tests, 7 controller tests).
  Fixed reused DOM input values with explicit local-script clearing on epoch
  transitions/actions/visibility; password-repeat refusal also clears protected
  forms and invalidates old events. Shared preview visually checked at desktop
  and mobile sizes. Android lifecycle generations preserve rapid pause/resume
  events; final app and instrumentation APKs rebuilt and signatures/final
  manifest inspected. No device connected, no installation or instrumented run.
  Steps 1–4 and 6 implemented/verified within their container/build scope;
  Step 5 implementation exists but real-desktop procedure is pending. Steps
  7–8 remain incomplete until supported-device evidence and final handoff.
  Updated architecture, changelog, app README, dependency disposition and roadmap;
  no blanket spec promotion. Full workspace tests: 720 passed, 2 ignored;
  affected app tests rerun after final app-only changes. SPDX, regression
  fixtures, matrix, fmt, workspace/UI Clippy, deny and vet pass. Maintained
  source test outcomes are recorded below after completion. Owner staging
  remains intact; no commit, branch or push.

- 2026-11-01: Maintained-source final regressions passed: optimized GLib
  variant iterators 11, selectors 7, diagnostic macros 21 across their
  unit/compile/integration suites, desktop hardened ingress/navigation and
  stalled/bounded handshake transport 3. All commands exited successfully;
  logs `/tmp/qv30-work/vendor-*.log`. Final documentation/header/matrix/format
  checks pass. Remaining work is supported-device evidence described in
  VALIDATION.md, then fresh-context implementation review. Read-only visual
  preview and inspectable debug APKs are available; no device was contacted
  beyond listing attached devices (empty). Continue this same approved phase
  when hardware is available; do not create a suffix or repeat approvals.

- 2026-11-01: Owner connected a POCO X7 Pro (2412DPC0AG, Android 15/API35,
  arm64, Google WebView 156.0.8078.47) and authorized continuing device checks.
  Host ADB sees it after the competing workspace server was terminated at the
  owner's request. Installed the inspected app/test APKs, with no data clear.
  Initial instrumentation exposed a fixture bug: unchecked checkbox value
  defaults to "on". Corrected the assertion to check text values and checkbox/
  radio checked-state separately, rebuilt/signed test APK, reran actual phone
  instrumentation: OK (1 test), 9.803s. Default test discovery also produced a
  startup ANR; explicit class selection plus bringing MainActivity forward
  completed successfully. Preserve failures and working invocation in
  VALIDATION.md; no product security check weakened. App hash is unchanged;
  new test APK identity recorded. Pending: manual vault/recovery/screenshot/
  keyboard and real OS lock/suspend scenarios, Linux desktop checks and fresh
  implementation review. Phase remains In progress, step 7 unticked. Rust and
  dependency inputs unchanged from the recorded full gates; rebuilt/tested
  affected Java fixture, rechecked SPDX/format/diff, preserve owner staging.

- 2026-11-01: Owner reports successful vault creation in the installed phone UI.
  With the vault open, both locking the phone screen and leaving the foreground
  task locked the vault. Recorded these manual observations separately from
  instrumentation in VALIDATION.md. No claim for untested phrase recovery,
  screenshot/keyboard behavior, KDF races, backup exclusion or Linux desktop
  lifecycle. Step 7 and phase status remain incomplete pending those checks
  and fresh implementation review. Documentation only; source/dependency/test
  inputs unchanged from the recorded gates. Preserve owner staging.

- 2026-11-01: Owner confirms screenshot protection and asks why engineering
  validation is being delegated to them. Record screenshot observation; agent
  owns recovery/error/race test execution. Added instrumentation-only flow
  driver and reusable scripts/test-android.sh, including synthetic private
  fixtures, explicit test class/foreground launch and honest failure exits.
  A synchronous native-driven run passed confirmation, wrong-password refusal,
  password/phrase unlock and no late reopen after pause during opening, but
  failed at second-vault phrase display; it is not a passing suite. Subsequent
  policy inspection found the phone off/securely locked due to timeout. Final
  fixture keeps only its test window awake and waits explicitly for readiness;
  rebuilt and syntax/header/matrix/fmt/Clippy/diff checks pass. Production app
  bytes and Rust/dependency inputs unchanged; no owner vault opened or data
  cleared. Expanded test APK identity and partial/failed runs in VALIDATION.md.
  Final rerun awaits the owner unlocking the phone once; no engineering
  checklist assigned to the owner. Keep step 7 unticked and phase In progress.

- 2026-11-01: Owner requested continuation with the phone unlocked. Expanded
  native/shared-screen suite now passes: OK (1 test), 15.287s, POCO X7 Pro /
  Android 15 / WebView 156.0.8078.47. Confirms creation, requested recovery
  words, wrong-password refusal, password/phrase unlock, pause while opening,
  cleared controls/no late reopen and recorded skip. The prior second-create
  refusal was a fixture filename error (.qvault-skip); use -skip.qvault to meet
  the existing extension rule. No product change or relaxed assertion. Preserve
  prior timeout/package-update failures; runner now skips reinstalls only on
  exact installed APK SHA-256 matches. Final app/test hashes and logs in
  VALIDATION.md. Test-only keep-awake cleared on completion; own synthetic
  files removed, owner vault untouched. Linux system bus reports no logind
  service, so positive real-desktop lock/suspend evidence remains unavailable
  here. Keep phase In progress for remaining runtime evidence and fresh review;
  no further engineering checklist assigned to the owner.

- 2026-11-01: Production Linux binary builds, but this system bus lacks logind.
  Startup observation under private Xvfb/private state yielded black captures;
  no readable unavailable-protection screen was established. Treat as
  inconclusive, not successful refusal or real-desktop evidence. Logs in
  /tmp/qv30-linux-real; investigate startup path/renderer mapping on continuation
  and retain Step 5/7 as incomplete. No host lock/suspend requested. Phone
  expanded suite remains passing and app was reopened for the owner. Source
  and dependency inputs unchanged except instrumentation/runner from this phase;
  final header/matrix/format/diff checks pass, preserve staging.

- 2026-11-01: Owner sees the production Linux "Protection unavailable" screen.
  This is direct owner observation of the startup refusal view; the earlier
  private-Xvfb captures remain inconclusive. Agent system bus has no owner for
  org.freedesktop.login1; whether the owner's normal terminal shares that bus
  is not yet established. Within Steps 3/5's approved fixed status reporting,
  distinguish private storage, instance contention and lock-monitor setup in
  data-free UI errors. On failed operation-time monitor rearming, invalidate
  protected forms/session before reporting refusal. Existing specs already
  require failure disclosure and fail-closed cleanup; no new backend, bypass,
  dependency, format or normative change. Add one monitor-failure regression,
  run focused UI/controller checks and all required gates. Preserve staging.

- 2026-11-01: Startup diagnostics follow-up verified. AppError distinguishes
  lifecycle monitoring, private storage and instance ownership. Failed watch
  rearm invalidates forms/session and reports the fixed monitor category;
  async startup-error transitions refresh UI. Added one monitor-failure/cleanup
  regression; limited runtime Controller import to supported configurations to
  remove an Android-only unused import. Owner confirms normal desktop terminal;
  agent bus missing logind does not establish the owner's host cause. Await
  updated heading after relaunch, no service/backend change or security bypass.
  Final gates: SPDX, matrix, fmt, workspace Clippy and cargo test --locked pass
  (721 passed, 2 existing ignored); validation feature passes 8 controller +
  2 actual-WebKit tests and UI Clippy. Android arm64/mobile cargo check passes
  after restoring the pinned target in the reset tool environment; upstream
  vendor warnings retained, no product warning. Logs /tmp/qv30-startup. Existing
  installed phone APK/evidence precede these shared-status changes; no new
  phone APK identity or runtime pass claimed. Preserve owner staging; phase
  remains In progress pending host diagnosis, remaining evidence and review.

- 2026-11-01: Owner reports updated heading "Lock monitoring unavailable".
  Their normal-terminal temp.sh GetSessionByPID probe returns ServiceUnknown
  for org.freedesktop.login1. Required login1-compatible service is therefore
  absent on their host's fixed system-bus endpoint; the existing logind-only
  integration cannot open vaults there. Do not misdiagnose this as storage,
  password, simple permission or session-PID lookup failure. Updated temporary
  untracked helper to collect public OS/init/desktop metadata and filtered
  lock/portal service names; await those to assess a suitable backend. No
  product/backend/spec changes or bypass. Temp helper syntax/self-test and
  SPDX/fmt/diff checks pass; product gate inputs unchanged from 721-test pass.

- 2026-11-01: Host metadata confirms Alpine edge 3.25 alpha, init process
  "init", Wayland/Mango; only org.freedesktop.portal.Desktop is advertised
  among queried lock/portal services. Existing backend is logind-only, so this
  is an integration coverage gap. Architect assessment: portal service name
  alone is not sufficient evidence of lifecycle monitoring. Official Inhibit
  docs describe CreateMonitor/StateChanged (screensaver-active and session end),
  but do not establish the required pre-sleep notification path. Any alternative
  must preserve 0008 §1.4 and 0009 §5 lock/sleep behavior and fail closed on
  missing initial state, owner/session loss or incomplete monitoring. No
  alternative/backend exception implemented or approved as satisfying those
  requirements. Updated temporary helper for Inhibit.version and installed
  portal/backend interfaces; agent cannot reach owner's session bus directly.
  Await actual capability result before choosing the integration. Primary
  research: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Inhibit.html
  and https://github.com/mangowm/mango. No product/spec/dependency changes;
  prior product gates still apply. Helper syntax/self-test, SPDX/fmt/diff pass.

- 2026-11-01: Owner explicitly changes the policy: automatic OS screen-lock/
  sleep handling cannot be a Linux startup prerequisite. Amend 0008/0009 before
  code; this supersedes the earlier mandatory Linux watcher assumption and
  logind/portal blocker. Architect choice: existing logind watcher remains an
  optional capability, detected and visibly disclosed when absent; no new
  compositor/portal dependency. Add explicit Linux core policy, keep generic/
  Android configuration strict, retain consent for reduced protection. Manual
  and 60s idle locking always work; observed lock or watcher loss still clears
  live sessions/pending work, while a later explicit Linux open can proceed.
  Implementation steps above stay in this phase. Owner instruction approves
  this normative amendment and execution; do not ask again. Fresh-context
  implementation review is still required after final code/tests.

- 2026-11-01: Optional Linux monitoring implementation verified. Final gates
  pass: SPDX, matrix, fmt, workspace/UI Clippy, cargo test --locked (724 passed,
  2 existing ignored), 9 controller + 3 actual-WebKit tests, Android arm64/mobile
  check and production desktop build. New real-Linux-services flow passes in
  the environment without login1; deterministic tests cover absent watcher
  consent/create/unlock/recovery/manual/idle lock and retry after watch loss.
  Existing strict binding and available-watcher tests remain. Rebuilt Android
  app/instrumentation APKs with pinned tools; v2 signatures verified with the
  prior debug certificate and final manifest re-inspected (API29/target35,
  backups off). App hash 5704f2d55fd921bb838bc49db0cbe490f2504343e7f90f33c38ac4fe91407f8d;
  test package unchanged d3743c2b1e183d2238fd90d9089cb84bfebc120d2d31528e4180a12440c94939.
  Latest packages built/inspected, not installed or rerun on phone; earlier
  physical evidence covers unchanged Android requirements. Private-Xvfb root
  screenshots remain inconclusive; do not call them a visual production pass.
  Functional actual-engine Linux evidence and owner's real-window observations
  are distinguished in VALIDATION.md. Implemented status denotes foundation
  implementation, not independent security review/release validation. Fresh-
  context reviewer is next; no claim of Reviewed or spec status promotion.
  Owner staging preserved; no commit/branch/push. temp.sh now explicitly launches
  the updated app for the owner, replacing its obsolete read-only probe.

- 2026-11-01: Owner confirms the updated Linux app shows the vault screen and
  unavailable-monitoring warning in their normal Alpine/Mango desktop session.
  Startup blocker is resolved and the reduced-mode disclosure is observed in
  the real window. Recorded separately from automated flow tests and earlier
  inconclusive private-Xvfb captures. No new owner vault-flow test inferred.
  Documentation only; product/test inputs unchanged from the passing 724-test
  gate set. Implemented status retained; fresh-context review remains next.
