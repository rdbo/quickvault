# Plan0048 — Security release validation and large-vault qualification

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Blocked | 2026-11-09 | 2026-11-09; owner instructed execution of the follow-up plan | 0012 §1–3/D12, 0013 §15, 0002 §9, 0004 §7, 0008 §6, 0009 §7 |

## Intent

Close the release-evidence gaps left explicitly open by0047 without extending
that completed implementation indefinitely. Keep independent cryptographic and
dependency review, physical-device qualification and capacity work visible.

## Scope

In scope: the exact LAN/2 composition and dependency baseline; actual Android/
Linux lifecycle and interoperability; representative large-vault latency/RSS;
measurement and design recommendations for bulk-mutation memory.

Out of scope: automatic release, external messages/paid engagements without
owner authorization, vault/wire format changes, new crypto suites, increasing
the1 GiB ciphertext budget or implementing a new mutation architecture.
Other0046 findings remain in that plan's ledger.

## Spec basis

| Work | Spec / status | Requirement |
|------|---------------|-------------|
| Independent composition/dependency review | 0012 §3 Accepted/D12 | Local tests, exemptions and older upstream audits are not certification |
| LAN qualification | 0013 §15 Accepted; owner-approved0009 §7 | Both enrollment methods, spent admission, key confirmation, cancellation/publication outcomes |
| Memory/target qualification | 0004 §7 Accepted; owner-approved0008 §6 | No aggregate searchable-text cap; cache is distinct from RSS; target evidence |

No normative amendment is required for measurement/review. Any resulting
behavior/parameter/architecture change needs a spec/plan amendment and approval.

## Decisions needed

1. Owner selects the independent reviewer, budget and permitted external
   contact/material sharing before an engagement. Prepare locally meanwhile.
2. Owner identifies available Android/Linux targets and representative synthetic
   datasets. Do not operate on personal vaults or infer a latency/peak-RSS target.
3. After measurements, owner decides whether tighter bulk-mutation memory is
   required and selects a target. No implementation is authorized by this plan.

## Design

Use0047's LAN-VALIDATION.md, DEPENDENCIES.md, vectors and local review as the
starting package. Review the exact ephemeral registration, role/intent binding,
outer/final-key mixing, KE3/FinishedB/grant and PB/PA/State transitions. Check
library scratch/RNG assumptions and actual new-family audits, including the two
updated SQLite packages. Development exemptions remain explicit debt.

Use existing app device scripts and fresh private synthetic vaults. Preserve
password/KDF/protocol/ciphertext limits and production compile flags. Report
complete receipt, key disclosure, durable local action and publication separately.
Use protected Rust secrets, bound hostile inputs and redact logs/artifacts.
No interface, dependency or persistent data-flow change is selected here.

## Steps

### Step1 — Independent review and dependency evidence

- [ ] **Do:** Prepare the exact local package; after explicit owner engagement
  authorization, obtain independent composition review and genuine dependency
  evidence. Classify findings; plan required changes before implementing them.
- [x] Local source/checksum/feature/vector package and honest dependency debt.
- [ ] Actual independent report, matching dependency audits and D12 verdict.
- **Files:** this directory/REVIEW-PACKAGE.md, DEPENDENCY-REVIEW.md; references
  to0047 evidence and vector provenance; supply-chain records only for real audits.
- **Done when:** D12 verdict and audit scope are explicit, with no exemptions
  presented as audits and no unresolved release-blocking findings hidden.
- **Verify:** Source/vector trace; deny/vet; independent reviewer's actual report.

### Step2 — Physical targets and large-vault qualification

- [ ] **Do:** Run supported-device create/unlock/search/lock and both LAN
  enrollment directions, including password/phrase, biometric-unlocked source,
  background/cancel, adverse network and publication/anchor outcomes. Measure
  final-dependency KDF latency and process memory on representative large and
  conflicted vaults; separately exercise an actual near1 GiB ciphertext vault.
- [x] Fresh host and physical-phone P0–P3 core benchmarks, including an actually
  populated near1 GiB fixture; optimized stock searchable-text lifecycle.
- [ ] Full app/device matrix: original UI run failed before fixture creation;
  isolated boundary/QR/regular-UI checks pass and Class3 repeat passes, but its
  first seal failed; attended LAN/lifecycle/biometric/publication and
  representative-conflicted rows remain open.
- **Files:** this directory/DEVICE-VALIDATION.md and LARGE-VAULT-VALIDATION.md;
  existing app validation records/scripts if corrections are required.
- **Done when:** Device/build identities, exact datasets/commands, results and
  limits are reproducible; synthetic keystores/arithmetic are not device evidence.
- **Verify:** Tracked app README Android/Linux procedures; optimized fixture;
  full gates after any source changes. No repeated full gates for doc-only work.

### Step3 — Bulk-mutation memory decision

- [x] **Do:** Measure recursive delete/batch-edit preparation separately from
  cache/page residency. Compare bounded preparation approaches against atomicity,
  cancellation and existing limits; record a recommendation for the owner.
- **Files:** this directory/CAPACITY.md; an approved spec/plan amendment only if
  the owner chooses a behavior or architecture change.
- **Done when:** Peak-memory evidence and tradeoffs are clear; no new cap,
  partial commit, architecture or correctness compromise is silently implemented.
- **Verify:** Reproducible synthetic measurements; source/transaction trace;
  owner decision before dependent implementation.

## Test plan

Reuse0047 fixtures and independent vectors rather than duplicating them. Trace
0012 rows for LAN trust/partial acceptance, hostile input, budget consistency,
anchor crash windows and mixed credentials. Run all AGENTS.md gates after code/
dependency changes, and affected checks after later edits; record failures as
well as successes. Device and independent evidence cannot be replaced by CI.

## Risks and stop conditions

Stop before contacting external reviewers or spending money without explicit
owner authorization. Stop for unresolved cryptographic findings, changed costs/
limits, formats or mutation ordering. No release assertion until required
independent/device gates and any resulting fixes are complete.

## Documentation

- [x] Record actual review/device/capacity evidence and remaining release gates.
- [x] Update Changelog and architecture/specs only for resulting approved changes.
- [x] Update plan/index; no AGENTS.md/workflow change expected.

## Revisions

- 2026-11-09: Add measurement-only `capacity-harness.rs` and
  `measure-capacity.py` beside CAPACITY.md to make step3's synthetic measurements
  reproducible. They use existing public core APIs and exact product registry
  versions in a disposable external package; no product API, dependency,
  architecture, limit or persistent format changes. Held public drafts measure
  decoded-payload preparation as a proxy; actual batch/recursive operations
  receive separate sampled RSS and integrity/commit-count checks. The proxy is
  not claimed as an isolated internal production preparation measurement.
- 2026-11-09: Add optional preparation tracing in a disposable copy of core;
  the retained patch prints only change counts and RSS immediately before
  `commit` consumes the prepared vector. Product source stays byte-identical.
  Add `package-isolated-android.py` to repackage the built validation native
  library under a distinct test application ID/UID. The first ordinary-package
  device run raced automatic unlock of the selected regular vault and failed
  before fixture creation. Separate UID/storage/keystore isolation is required
  for further tests on this populated phone. Native library bytes must match
  the validation baseline; no product application ID or protocol is changed.
- 2026-11-09: Add `--normal-ui` to the disposable packaging helper: copy the
  exact prebuilt regular native library into the generated test project, check
  its hash against the regular APK, and assert the regular Create UI has no raw
  vault-path input. The owner observed the validation-only automation field;
  verify the existing production gate rather than selecting a UX change.

## Execution log

- 2026-11-09: Owner requested wrapping0047 and recording follow-up work. Planning
  only; no engagement, device access, release or additional implementation.
- 2026-11-09: Owner instructed execution of the follow-up plan. Approved and
  started on clean tree `ee0cafd`. Preparing the exact local review package and
  host measurements. Asked for reviewer/engagement scope and physical targets/
  representative datasets; dependent qualification remains pending. `adb devices
  -l` lists no attached device. Existing synthetic benchmark profiles may supply
  host development evidence, without selecting owner qualification targets.
- 2026-11-09: Owner connected the POCO X7 Pro during execution. Treat this as
  identification of the available Android target and continue synthetic device
  validation. Owner has not chosen an independent reviewer or performance
  acceptance target. Initial Android build attempts found the default Dioxus
  CLI was 0.8 alpha and the Android Rust target absent; select the existing
  pinned 0.7.10/JDK21 tools and install the Rust target, without changing pins.
- 2026-11-09: Prepared REVIEW-PACKAGE.md, 110-file source hash inventory,
  22-version registry/exemption inventory, locked feature traces and actual
  upstream-audit scope references. Fresh deny/vet pass with existing debt;
  no certification or exception was added. D12 remains pending, not a local
  approval. No reviewer was contacted and no material sent externally.
- 2026-11-09: Final host P0–P3 measurements and physical POCO P0–P3 samples
  pass. P3 contains 1,071,077,760 actual referenced ciphertext bytes (99.752%
  of the unchanged 1 GiB budget); each sample unlocks, fully verifies, edits
  and locks. Physical 67.5/135 MiB searchable-text fixtures also pass; the
  latter takes 70.895 s for complete search. Record the latency finding rather
  than selecting a new cap/index. Device shell-UID results are not app RSS,
  biometrics or LAN interoperability evidence. See LARGE-VAULT-VALIDATION.md.
- 2026-11-09: Step3 host measurements complete through existing core APIs,
  plus a disposable-core instrumentation repeat with the retained count/RSS
  patch. At 180 rows, prepared batch/recursive vectors reach about211 MiB
  process RSS separately from the view cache. Atomic operations each commit
  once and pass verification. CAPACITY.md records alternatives and recommends
  considering one-transaction sequential staging if the owner wants tighter
  memory. No target, architecture or implementation of that change is selected.
- 2026-11-09: Normal Android PlatformTest failed before synthetic fixture
  creation because automatic regular-vault unlock raced mode selection. The
  owner observed fingerprint-background flicker. The test deliberately forces
  pause/resume; a connection is plausible but not confirmed. Retained failure
  logs omit regular workspace labels. Built a separate-UID validation APK with
  identical native library bytes, and a distinct focused boundary method; the
  failed full-flow test is not weakened or counted as passed. Android rejected
  installation with INSTALL_FAILED_USER_RESTRICTED. Asked whether to retry
  with owner acceptance on the phone; no bypass/retry without an answer.
- 2026-11-09: All required final source gates pass: SPDX, fmt, all-target
  Clippy and complete locked workspace tests (978 passed,2 existing ignored).
  Matrix, manual harness formatting, standalone baseline/instrumented Clippy,
  optimized stock lifecycle, Android builds and pinned deny/vet also pass.
  CHECKS.md records exact commands/settings and retained failures. No production
  source/dependency/format/security-policy change; all110 baseline hashes match.
  No commit, branch, staging or push. Removed only this session's generated
  device benchmark subtree after retaining its synthetic results.
- 2026-11-09: Blocked for remaining dependent work: owner-selected independent
  review/engagement and genuine matching audits; phone approval for the isolated
  UI rerun; full attended device/LAN/lifecycle/biometric/publication evidence and
  representative conflicted qualification. Owner-observed flicker remains open
  for isolated reproduction. Step3's recommendation is ready; an owner-selected
  target and spec/plan amendment are required before any mutation redesign.
- 2026-11-09: Owner reports the phone is back on; resume the pending isolated
  installation/device check on the existing uncommitted tree. Previously
  prepared APKs and source remain available; preserve earlier failures and
  independent-review gates. Retry only the separate synthetic application.
- 2026-11-09: The verified isolated APK retry again failed with
  INSTALL_FAILED_USER_RESTRICTED before any test. Device status confirms screen
  on, unlocked keyguard and unrestricted input. Asked whether an installation
  prompt appeared; do not treat the generic error as an intentional owner
  cancellation or bypass device installation policy. Source baseline still
  matches; no rebuild or repeated workspace gates are needed for this retry.
- 2026-11-09: Owner clarified not watching the installation attempt. Retried
  with owner attendance: isolated app and test packages install successfully.
  Current-UI native input/CSP/secure-window/lifecycle boundary test passes
  (2.932 s); existing native QR stride/bounds/no-implicit-capture test passes
  (1.880 s). Original full-flow failure and unrun matrix rows remain open.
  Started the existing Class3 keystore round-trip/wrong-vault-AAD test, asking
  the owner to authenticate three prompts and observe any background flicker
  without the earlier artificial pause/resume sequence.
- 2026-11-09: First attended Class3 native seal fails at stage70 (49.809 s),
  with validated hardware metadata and no retained exception type. Owner asks
  to show prompts again; unchanged repeat passes all three operations including
  wrong-vault AAD rejection (19.665 s). Owner reports no flicker on that repeat.
  Preserve both results; cause of first failure and original flicker remains
  unresolved. No production adapter/protocol/secret-lifetime change is selected
  to repair an unexplained failure; classify/plan any required fix first.
- 2026-11-09: Owner observed the validation-only vault-path field. Source
  confirms `typed_path = fixture`. Exact regular native UI in the synthetic
  package passes the no-path-control assertion and retained CSP/input/lifecycle
  checks on-device (3.037 s). No product UX change needed. Removed only the
  temporary test application/instrumentation and returned regular QuickVault
  to the foreground. Updated shared evidence and records; production source
  baseline stays unchanged, so previous workspace gate results still apply;
  packaging syntax/build/focused tests and diff whitespace checks are current.
- 2026-11-09: Blocked on remaining independent review and matching audits,
  unresolved first hardware failure, original full-flow test adaptation and
  outstanding physical LAN/app qualification. Phone install approval is now
  resolved. The observed path field was test-only; flicker did not reproduce
  in the attended native repeat. No release or completed-plan claim.
- 2026-11-09: Owner asks whether Android still opens an arbitrary vault file
  without the path box. Source inspection finds the external-vault picker
  entry/callback is Linux-only; Android's SAF picker is not wired for vaults.
  Found, not fixed: missing Android external-vault open flow. Hiding the
  validation field does not supply that capability. This requires a scoped
  behavior/implementation plan respecting 0009 §1.8's import-in-place contract;
  do not silently choose provider-copy or write-back semantics in 0048.
- 2026-11-09: Owner requests a separate Android file-opening plan before
  committing. Added proposed0049; no implementation or spec approval inferred.
  Commit-readiness inspection found blank evidence EOFs and a trailing-space
  context line in the trace patch, previously invisible to unstaged-only diff
  checks. Normalize log endings and render the identical patch with zero
  context; update its generator and validate with git apply --check. Preserve
  the owner's staged snapshot; these cleanup edits/new planning files need
  restaging. This is a commit-ready validation checkpoint, not completed0048
  or release qualification.
