# Plan 0029 — Platform traits and Linux adapters (roadmap 2.3)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-31 | 2026-10-31 | 0009 §1.6, §5; 0008 §1.3–1.4, §3; 0002 §5.2 |

## Intent

Give core an injectable OS boundary and implement Linux lifecycle, clipboard,
single-instance and protection-reporting services before production GUI work.
A screen-lock/sleep event must lock the bound session; unavailable protection
must be visible rather than silently treated as working.

## Scope

In scope: qv-platform, injected core services, bounded lifecycle handling,
Linux logind monitoring, existing X11 ownership engine reuse, single-instance
locking and conservative swap/hibernation reporting. Secure input and keystore
have typed interfaces; Linux quick unlock remains unavailable.
Out of scope: production GUI, Android adapters, new secret persistence, a
Linux quick-unlock backend, Wayland clipboard implementation, protocol work.

## Spec basis

| Behaviour | Spec | Status | Authority |
|-----------|------|--------|-----------|
| Shared platform boundary and Linux session behavior | 0009 §1.6, §5 | Draft | Owner explicitly requested phase 2.3 on 2026-10-31 |
| Reduced protection and lifecycle/clipboard cleanup | 0008 §1.3–1.4, §3 | Draft | D5 and explicit phase request |
| No quick unlock without a validated backend | 0002 §5.2 | Accepted | No backend is introduced |

Spec changes required: none; these implement existing requirements.

## Decisions needed

1. Approve `zbus = 5.19.0` for Linux logind D-Bus integration. The roadmap has
   no D-Bus dependency candidate, so its Session protocol step 4 requires owner
   approval before adding one. Recommend zbus instead of hand-written D-Bus
   parsing or command-output parsing. Also approve touching qv-cli only to
   consolidate its existing X11 engine in qv-platform and preserve CLI behavior;
   this necessary reuse extends the phase entry's literal file list.
   Resolution: owner delegated the choice and instructed continuation on
   2026-10-31 ("Whatever you feel is best. keep going"). Approved: zbus and
   the necessary CLI clipboard consolidation scope.

## Design

Components: qv-platform depends on qv-crypto for protected bytes and existing
rustix/X11 libraries, with zbus only on Linux. Core depends on qv-platform;
frontends continue through qv-core's reexports. No dependency back to core.

Interfaces (final names may follow existing local conventions):

- Redacted `PlatformError` categories: Unavailable, Cancelled, InvalidInput,
  LimitExceeded, Busy, Io. No OS error/path/secret payloads.
- `SecureInput::read_secret` accepts a typed input purpose, a byte bound and
  cancellation, returns SecretBytes. Framework-controlled input remains in
  phase 2.4; no native dialog or renderer change is introduced.
- `Clipboard::hold` consumes SecretBytes, a validated duration, cancellation and
  a metadata-only progress callback. It never reads clipboard contents or
  hands a value to a clipboard manager. Lock/cancel/expiry destroys only its
  own selection window; existing X11 limits and protected transport remain.
- `Lifecycle::watch` takes a callback receiving ScreenLocked, PreparingForSleep,
  BackgroundExpired or ProtectionLost and returns an owned cancellable guard.
  Core binds it through weak references to private session state/lock flags;
  callbacks cannot retain keys or unlock a session.
  Stop/drop must close the D-Bus connection and join the worker without waiting
  indefinitely for another signal. Event loss/disconnection fails closed by
  locking the session and reporting unavailable monitoring.
- `Keystore` exposes availability and authenticated wrapping operations through
  protected buffers; the Linux backend returns Unavailable for quick unlock.
  No Linux key material is written and no unsupported backend is advertised.
- `ProtectionStatus` reports storage/swap/hibernation as Verified, KnownGap or
  Unknown, alongside lifecycle/clipboard availability and quick-unlock support.
  Linux cannot establish locked-state disk-key custody from configuration and
  must not report full protection from a mounted encrypted device alone.
- Core accepts `Arc<dyn PlatformServices>` through an explicit builder on Core
  (preserving existing CoreConfig literals and CLI construction). Configured platform flows
  require explicit reduced-protection acknowledgement before create/unlock
  if prerequisites are unknown/missing. Report current status to frontends;
  use existing NotAllowed/Cancelled errors rather than invent CLI exit codes.

Linux lifecycle: authenticated system-bus connection, resolve this process's
session via GetSessionByPID; subscribe to its Lock and LockedHint changes and
manager PrepareForSleep(true). Pin service owner, paths, interface/member and
body types; ignore unrelated sessions/resume and fail closed on owner loss.
Subscribe before initial state query to avoid a lock-state race. Bound queues
and method/connection waits; document that OS scheduling and logind availability
limit pre-suspend completion and actual desktop validation remains required.

Single instance: nonblocking advisory flock on an owner-only, no-follow regular
file inside an owner-only directory. Retain fd for lifetime; never unlink on
release, which would allow split locking. Reject symlinks, foreign ownership,
unsafe permissions and unexpected file types, without exposing paths in errors.

Detection: bound reads of /proc/swaps, /sys/power/state and resume configuration;
unknown/malformed/unreadable configuration is Unknown, active swap whose key
custody cannot be established is Unknown/KnownGap rather than verified. No
privileged changes to swap, suspend or encryption configuration.

Secrets: reuse qv-crypto containers; no secret argv/environment/log/error/Debug.
Clipboard lifetime/default 20 seconds, size and transfer limits remain those
of plan 0015. Move the maintained engine/transport with cancellation injected
instead of direct CLI signal references. CLI retains prompt/countdown/error
mapping and its integration tests. No crypto/storage/wire changes or unsafe.

Dependencies: existing rustix, x11rb, x11rb-protocol, zeroize and workspace qv
crates are reused. zbus is a maintained typed Rust D-Bus implementation; no
independent security audit is claimed. Inspect its locked transitive graph,
run deny/vet, and record audit coverage. Do not silently add exemptions.
Sources consulted: official zbus 5.19 blocking API documentation
(https://docs.rs/zbus/5.19.0/zbus/blocking/) and logind D-Bus API
(https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.login1.html).

## Steps

### Step 1 — Traits and dependency boundary

- [x] Do: create qv-platform and typed traits/status/errors; inject services in core.
- Files: workspace Cargo metadata, qv-platform, qv-core setup/platform modules;
  affected isolated spike/fuzz lock metadata only if their internal graph changes.
- Done when: unsupported services fail closed and core status/acknowledgement
  are tested without an OS backend; existing CLI construction remains valid.
- Verify: `cargo test --locked -p qv-platform`, core platform tests.

### Step 2 — Linux protection and single instance

- [x] Do: implement bounded detection and hardened instance lock.
- Files: qv-platform Linux modules/tests.
- Done when: unknown/gap status is explicit; unsafe paths and simultaneous
  instance acquisition reject; release permits a new instance without unlink.
- Verify: `cargo test --locked -p qv-platform`.

### Step 3 — Lifecycle and session binding

- [x] Do: implement logind adapter and core session guard; cancellation and drop
  terminate workers; disconnect/lock/sleep invalidate bound session capabilities.
- Files: qv-platform lifecycle; qv-core platform/session integration/tests.
- Done when: integration test delivers a lock to core; unrelated signals cannot
  unlock or repopulate state; unavailable OS backend reports reduced protection.
- Verify: core platform tests, private D-Bus tests where available; document a
  real Linux screen-lock/sleep manual procedure and environmental limits.

### Step 4 — Shared clipboard ownership

- [x] Do: consolidate existing X11 engine/transport into platform and inject
  cancellation/progress; core reexports validated clipboard access to CLI.
- Files: qv-platform clipboard, qv-core exports, qv-cli clipboard wrapper and
  affected dependency-boundary tests/metadata.
- Done when: private Xvfb ownership/INCR/refusal/expiry and key-drop tests pass;
  no new manager handover, plaintext intermediary or command is introduced.
- Verify: `cargo test --locked -p qv-cli --test clipboard`, platform tests and
  maintained vendor transport tests.

### Step 5 — Documentation and final verification

- [x] Do: update architecture component/diagram/current state, changelog,
  plan/index/roadmap and integration/manual evidence; run all final gates.
- Files: ARCHITECTURE.md §3/§6/§7, CHANGELOG.md, this plan/index/roadmap;
  DEPENDENCIES.md, LINUX-VALIDATION.md, CI/matrix checker, AGENTS/reviewer
  guidance, supply-chain records and isolated consumer metadata as revised.
- Done when: phase 2.3 implemented with honest OS validation limitations;
  phase 2.4 remains held for D13 owner architecture review.
- Verify: all AGENTS gates plus matrix, deny/vet, focused vendor tests and
  affected isolated lockfile metadata/fuzz compilation if changed.

## Test plan

Final: SPDX, matrix, fmt, Clippy all-targets locked, full locked tests with
private Xvfb, deny and vet locked; retain logs in /tmp. Include rejected file
paths, bounded malformed configuration, lifecycle races/drop/disconnection,
weak session lifetime, explicit reduced acknowledgement, clipboard ownership
races and cancellation. 0012 §1 rows: Ambiguous trust boundary and Swap/hibernation leaks.
Clipboard ownership/cancellation also exercises 0008 §3 directly.
No format/security/release approval follows from passing tests.

## Risks and stop conditions

Stop on unresolved lifecycle/security semantics, new unsafe, additional external
dependency, audit-policy change, undocumented platform protection claim or a
need for production GUI. D13 remains pending and gates phase 2.4.

## Documentation

- [x] CHANGELOG.md — platform scope and limitations.
- [x] ARCHITECTURE.md — current adapters and boundaries.
- [x] Specs — no normative change/status promotion.
- [x] AGENTS.md and reviewer guidance — matrix working-tree enumeration.

## Revisions

- 2026-10-31: Under owner delegation, use zbus 6.2.0 after the 5.x graph fails
  current unmaintained-advisory checks; keep deny policy unchanged. See the
  dated execution entries and DEPENDENCIES.md for supporting runtime edges,
  precise vet baseline, isolated consumer metadata and verification/CI scope.
  Refine session watchers to weak private-state references, synchronous initial
  lock delivery and core's existing construction style. No spec/format change.

- 2026-10-31: Owner delegation approves ordinary implementation choices within
  this plan, including API spelling and necessary dependency/audit assessment.
  Keep unsafe forbidden and do not silently weaken security/audit policy. Use
  a session-owned watcher with weak references to shared session state rather
  than changing every public session result to Arc<Session>. The configuration
  builder lives on Core, preserving existing CoreConfig literals. Linux
  keystore operations fail closed; do not invent a wrapping format.

## Execution log

- 2026-10-31: Owner requested fixing 0028 and completing the next phase on the
  current tree. Plan prepared while that fix is verified; no phase 2.3 product
  code yet. Dependency/file-scope approval above is required by roadmap 0002.

- 2026-10-31: Owner approved the pending dependency/scope choices by delegation
  and requested continued implementation. Current uncommitted 0028 repair and
  records are authorized continuation work and will be preserved. Step 1 starts.

- 2026-10-31: Interface refinement under owner delegation: Core::with_platform
  preserves CoreConfig literals. Session owns its watcher; callbacks hold weak
  references to shared private session state/lock flag (no strong key lifetime).
  Session drop locks before joining its subscription. Session-bound clipboard
  cancellation shares the lock flag without holding the session mutex. Linux
  native-input/keystore adapters return Unavailable; no wrapping format/fallback.
  Add direct async-io 2.6.0 and futures-lite 2.6.1 edges already required by
  zbus, to bound connection setup and idle shutdown without blocking threads
  on another signal. No extra package beyond zbus's graph is introduced.
  Pin the system Unix endpoint rather than environment-controlled bus addresses;
  tests use an internal private-bus builder. Use a logind delay inhibitor while
  a session is monitored; its OS-imposed maximum cannot prove pre-suspend erasure.
  zbus's upstream per-message bound is 128 MiB and each filtered queue is 8;
  the peer is the local OS system bus, not a remote sync endpoint. No secret
  is sent to logind. Filter the unique owner/session and fail closed on malformed
  lifecycle messages, owner loss or disconnection; queue backpressure retains
  events instead of deliberate dropping.
- 2026-10-31: Focused platform tests (10), core platform tests (4), and private
  Xvfb CLI clipboard tests (3) pass. The private D-Bus fixture covers actual
  Lock/sleep delivery, owner loss and idle guard shutdown; stalled authentication
  is bounded. Initial mock acronym naming (GetSessionByPID) and typed error
  conversion compile/fixture mistakes were corrected without weakening checks.
  Clippy passes the first integrated tree. Dependency graph review: 52 added
  external records, zero prior external records removed/changed. Vet initially
  reports 52 unvetted versions; checking current imported audit coverage before
  selecting a documented disposition. No exemptions or policy were changed.

- 2026-10-31: Dependency review found current RustSec unmaintained advisories
  RUSTSEC-2026-0370/0371/0372 against zbus 5 companion crates (merged into zbus
  6). Under the owner's delegated dependency choice, revise to pinned zbus
  6.2.0 with default-rt/proxy/service; adapt to its merged wire/name APIs. Keep
  deny's no-ignore policy. Supporting async-io/futures-lite remain explicit for
  timeout races. Include supply-chain/config.toml and imports.lock in dependency
  review scope: current vet identity discovery requires an explicit
  audit-as-crates-io=false for maintained vendored x11rb, which is reviewed as
  application source under plan 0015, not upstream registry audits. Refresh
  imports while preserving existing exemptions; assess remaining coverage and
  record any precise baseline exemption as audit debt, not a certification.
  Owner delegation covers the necessary dependency baseline disposition; do
  not add blanket publisher trust, false audit attestations or advisory ignores.

- 2026-10-31: Final dependency disposition is documented in DEPENDENCIES.md:
  root adds 26 external records (two covered by existing audit imports, 24
  precise development-baseline exemptions with explicit audit-debt notes), no
  prior external record changes. No advisory ignore, blanket publisher trust
  or audit attestation. Vet passes at 29 fully/6 partially audited/103 exempted.
  Production zbus features exclude service; the private-bus server is dev-only.
  X11/rustix dependencies are Linux-only, leaving Android's platform traits
  available without compiling an X11 adapter. A bounded local X11 probe reports
  clipboard availability without reading or owning a selection.
- 2026-10-31: The isolated spike must select the same maintained x11rb patch
  now exposed through core. Include its Cargo.toml patch and refreshed lockfile
  as necessary consumer metadata. The resolver also corrects six old Windows
  dependency edges (dirs-sys/errno/region/rustix/tempfile/winapi-util) to match
  registry manifests and enables uuid's serde_core edge; no prior external
  package version changes. Full locked metadata succeeds; no prototype GUI or
  Android device validation is claimed. Fuzz has no core/platform edge.
- 2026-10-31: Include CI's private D-Bus test-server prerequisite and the
  matrix checker's working-tree file enumeration in verification scope.
  Relocating the transport exposes that the matrix checker reads deleted
  tracked paths and omits new untracked sources. Enumerate cached+untracked
  Rust sources and skip missing paths, retaining every row/tag assertion.
  Record that gate convention in AGENTS/reviewer guidance. This is required
  to check the actual uncommitted tree without staging the owner's changes.
- 2026-10-31: Final source review caught an already-locked subscription startup
  window. Deliver the initial lock synchronously before returning the watcher;
  private-bus evidence asserts it is already delivered on return. The earlier
  full-suite run was interrupted and superseded. Final source checks use
  all-tests-final.log; old logs are not final evidence.

- 2026-10-31: Final fail-closed review clarifies reduced-protection consent:
  acknowledgement covers uncertain OS persistence prerequisites, not bypassing
  required lifecycle monitoring. If a configured lifecycle watch cannot be
  installed, bind_platform returns NotAllowed and drops the session. Add the
  explicit acknowledgement-plus-unavailable-monitor rejection test. Initial
  absence cannot silently yield an unmonitored platform session; a disconnected
  established watch still locks immediately. Final source gates are rerun after
  this refinement; earlier full runs are historical/superseded.

- 2026-10-31: Steps 1–4 are complete; Step 5 verification is in progress.
  The pre-final-monitoring full run all-tests-final.log passed on its own source
  revision, but is not reused for the last bind-platform refinement. Current
  source has 5 focused core platform tests and 10 platform tests passing, plus
  final Clippy, production check, SPDX, matrix, fmt, deny/vet and vendor transport
  evidence in /tmp/qv-work/. Full confirmed final-tree suite is running as
  `QV_TEST_XVFB=/tmp/qv-tools/root/usr/bin/Xvfb cargo test --locked` with output
  /tmp/qv-work/all-tests-confirmed.log. Final status/roadmap ticks wait for its
  successful exit. No further product source changes are planned. Isolated
  prototype full locked metadata passes; affected fuzz formatting/compilation
  passes. CI installs dbus with Xvfb. No GUI/device/independent review claim.

- 2026-10-31: Core entry-point cross-check found interrupted-rotation resume and
  finish bypass setup.rs. Extend the same reduced-protection acknowledgement
  gate to those two existing Core methods before using protected artifacts.
  Include qv-core/src/rotation.rs in scope; no artifact/format/exit semantics
  change for existing unconfigured CLI callers. Strengthen the existing consent
  test with a snapshot-enabled core and a resume attempt, so missing policy is
  not masked by the independent snapshot-policy refusal. Recheck final core/CLI
  tests and Clippy after this local requirement-conforming guard addition; other
  workspace package inputs are unchanged and their current full-suite evidence
  remains applicable. Pending frontend rotation artifacts still require the
  app's lifecycle cancellation/drop policy, as documented in LINUX-VALIDATION.md.

- 2026-10-31: Step 5 complete; phase 2.3 Implemented. Full locked workspace
  suite passed with private Xvfb: 712 passed, 0 failed, 2 pre-existing ignored
  (all-tests-confirmed.log, exit 0). After the final two rotation consent guards
  and strengthened existing test, reran the entire affected core/CLI suites:
  196 passed, 0 failed, 0 ignored (affected-tests-handoff.log, exit 0), plus
  all-target locked Clippy (clippy-handoff.log, exit 0). Other package source,
  dependency, feature and test inputs are unchanged from the workspace pass;
  that evidence is retained without rerunning unaffected storage/crypto suites.
  SPDX/matrix/fmt and production compilation pass; deny passes all categories;
  vet passes with the documented 24 added audit-debt exemptions and no new
  attestation/advisory ignore. Current focused platform/private-bus tests pass
  (10), maintained vendor transport tests pass (12, including the subprocess
  memory-limit case), and affected fuzz format/locked compilation pass. Root
  and isolated spike locked metadata pass; the spike uses the same local x11rb
  patch. Logs /tmp/qv-work/; dependency disposition and real-desktop procedure
  are in DEPENDENCIES.md and LINUX-VALIDATION.md. Actual logind-managed desktop,
  suspend hardware, native Wayland clipboard, Android adapters and Linux quick
  unlock remain unvalidated/unavailable as documented; no production GUI,
  independent phase-0029 review or security/release claim. Next fresh context
  reviews this phase; D13 still gates planning phase 2.4. All changes are left
  uncommitted and the index is unchanged; no commit, push or branch.
