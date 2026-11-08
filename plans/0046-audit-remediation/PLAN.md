# Plan 0046 — Security assessment: initial repairs

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-11-08 | 2026-11-08, owner request to fix audit findings | 0004 §1/§4, 0008 §1, 0011 §3, 0013 §1.4, 0014 §6.4 |

## Intent

**Follow-up:** the three policy discussions now have explicit owner directions
and are planned in [0047](../0047-audit-policy-and-lan-auth/PLAN.md). Its LAN
baseline is owner-selected v4, with password entry on both devices and no
persistent authentication state. The original initial-batch scope and completed
steps below remain historical; none of these later changes is implemented here.

Check the friend's 32 findings against the current implementation, fix defects
whose required behavior is settled, and explain consequential changes before
implementing them. Preserve the supplied `security-review` symlink and report.

## Scope

**In scope:** an initial repair batch and a durable disposition of
every assessment item. Later batches require concrete designs for the pending
decisions below; this plan does not authorize those choices silently.

**Out of scope:** release approval, independent security assurance, committing,
branching, changing cryptographic constructions or dependency versions.

## Spec basis

| Behavior | Spec | Spec status / authorization | Notes |
|----------|------|-----------------------------|-------|
| Build hardening and honest checks | 0004 §1.2, 0012 §3, AGENTS.md | Existing implemented requirements; owner requested repairs | Force committed SQLite flags; fail closed on git errors |
| LAN addresses and typed override | 0013 §1.4, 0014 §6.4 | Accepted | Normalize mapped addresses; one shared unicast policy; typed endpoints replace QR hints |
| Terminal secret input | 0011 §3, 0008 §1 | Existing implemented sections, owner requested repairs | Keep input protected through command exit, flush before restoring |
| Accurate documentation | 0005 §5.4, 0014 §2.3, 0008 §1/§4.4 | Existing requirements | Correct removed key schedule, anchor behavior, residual-copy limits |

**Spec changes required:** clarify address classification in 0013 and command
terminal lifetime in 0011 before code. Other changes in this batch correct
implementation or non-normative documentation; preserve existing spec statuses.

## Decisions needed

1. **Index policy (T3-08): pending discussion, explicitly requested by owner.**
   Keep 64 MiB unchanged. Stock edits and archive/LAN merge candidate acceptance already
   preflight the budget; the supplied reproducer raises the constant to author
   its fixture. Propose documentation plus an explicit larger local policy,
   including propagation across core/CLI/app and recovery, only after agreement.
   Code inspection also found new-device join publishes before its final unlock
   builds the index; preflight before publication belongs in that policy design.
2. **Parent substitution (QV-013): pending discussion, explicitly requested by
   owner.** No new ancestor restrictions or persistent directory binding yet.
   Descriptor pinning and pre-start substitution are distinct problems; account
   for legitimate moves/restores, sticky shared directories, and platform limits.
3. **LAN window closure (QV-005/006/009 timing): pending discussion, explicitly
   requested by owner.** No change to budget/session semantics or probe timeout.
   Explain interruption vs independently bounded detector and post-commit reports.
4. **Other designs:** VW-02 commit outcomes/retry semantics; QV-004 delete-operation
   payload identity; T3-09 clock growth/resolution capacity; QV-011 destructive-copy
   authorization; QV-021 concurrent temp reclamation; T3-02 media transport;
   T3-04 Unicode display policy. Record exact proposals in the finding ledger
   before extending this batch. Existing crypto rejection (QV-010) stays intact.

## Design

**Components touched:** build configuration/checker; qv-sync endpoint/joiner;
qv-core option docs; qv-cli terminal/entry point/help; qv-crypto docs; specs and
architecture wording. No new component, trust boundary, disk/wire format,
dependency or public signature.

**Interfaces:** keep `EndpointPolicy::accepts` as the shared endpoint classifier.
`JoinCode::candidates` selects the explicit endpoint list when nonempty. A
crate-private command terminal guard holds the original stdin termios through
dispatch; prompt guards nest inside it. Restore with input flush on normal/error
exit. Keep ISIG enabled between prompts so existing signal cancellation works.

**Data/control flow:** no vault transaction changes in this batch. Validate
addresses before contact; no hostname resolution. Explicit unusable endpoints
must not fall back silently to a scanned address.

**Secrets and hostile input:** preserve all prompt bounds and protected buffers.
Do not log supplied QR or terminal bytes. Do not retain a command guard for
nonterminal stdin. Flushing discards type-ahead rather than returning it to the
shell. SIGKILL cannot run cleanup; make no broader erasure claim.

**Errors:** retain existing redacted errors and exit codes. Fail the SPDX gate
if obtaining its file list fails. Call the vendor check identity metadata, not
content provenance; archive/content review remains a separate obligation.

**Dependencies:** None.

## Steps

### Step 1 — Record findings and clarify requirements
- [x] **Do:** write the assessment disposition ledger, amend the two clarified
  spec sections and their Changelogs/index before behavior edits.
- **Files:** this directory/{FINDINGS,DECISIONS}.md; specs/0011-cli.md,
  specs/0013-lan-sync-protocol.md, specs/README.md.
- **Done when:** all 32 IDs have an explicit status and policy-dependent work is
  distinguishable from the first repair batch.
- **Verify:** manual comparison against the supplied findings register.

### Step 2 — Build checks and endpoint consistency
- [x] **Do:** force SQLite build flags; fail closed on git listing failure;
  correct vendor assurance wording; unify normalized endpoint classification
  including link-local/multicast/unspecified/broadcast; enforce typed replacement.
- **Files:** .cargo/config.toml, scripts/check-spdx.sh,
  scripts/test-check-spdx.sh, AGENTS.md, third-party/README.md,
  crates/qv-sync/src/lan/{endpoint,qr,joiner,tests}.rs,
  crates/qv-core/src/lan.rs.
- **Done when:** git failures reject, endpoint policies agree, and an explicit
  typed endpoint prevents contact with any QR hint, even if invalid.
- **Verify:** `sh scripts/test-check-spdx.sh`; `cargo test --locked -p qv-sync`;
  `cargo test --locked -p qv-store compile_options`.

### Step 3 — Terminal command lifetime
- [x] **Do:** add command-lifetime no-echo guard; retain signals between prompts,
  flush pending input when restoring; add PTY regression covering delayed input
  after Enter and restoration on success/cancellation.
- **Files:** crates/qv-cli/src/{cli,term}.rs, crates/qv-cli/tests/audit.rs.
- **Done when:** type-ahead during the KDF is not echoed or returned to the
  invoking shell, and terminal modes restore on handled exits.
- **Verify:** `cargo test --locked -p qv-cli --test audit` and terminal unit tests.

### Step 4 — Documentation, review and gates
- [x] **Do:** correct LAN derivation docs, X-Wing type wording without crypto
  changes, HKDF/HMAC residuals, verify/anchor description, healthy-copy restore
  guidance and raw-copy warning; record remaining work accurately. Review diff.
- **Files:** crates/qv-crypto/src/{lan,lib,xwing}.rs,
  crates/qv-cli/src/cli.rs, ARCHITECTURE.md, CHANGELOG.md, plans/README.md,
  this directory/{PLAN,FINDINGS,REVIEW}.md.
- **Done when:** docs describe implementation accurately; reviewer evidence
  covers this batch without representing pending repairs as completed.
- **Verify:** all gates below on the final tree.

## Test plan

Run `sh scripts/check-spdx.sh`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`.
Keep full output in temporary logs, preserve exit status. Also run
`sh scripts/check-matrix.sh`. Endpoint tests cover rejected and mapped addresses,
typed override and no silent fallback. PTY tests cover the unlock window and
terminal restoration. 0012 §1: LAN discovery mistaken for trust; secret-input
tests retain the existing validation-row annotations as applicable.
No dependency changes; deny/vet not required for this batch.

## Risks and stop conditions

- Do not implement any of the three policies the owner explicitly asked to
  discuss first. Do not infer approval from silence.
- Stop if a repair requires changing storage/crypto/wire formats or extending a
  public API beyond this plan. Extend the design first.
- Supplied PoCs refer to unbundled harnesses and some modify a copied build;
  inspect them before executing and do not claim complete reproduction.

## Documentation

- [x] CHANGELOG.md — exact initial repair scope and pending decisions.
- [x] ARCHITECTURE.md — wording corrections only; no component change.
- [x] Specs — 0011/0013 clarifications, Changelogs and index.
- [x] AGENTS.md — accurate identity-metadata check description.

## Revisions

- 2026-11-08: Owner requested a QuickVault-specific cryptographic construction
  driven by product security rather than external-protocol conformance. Add
  `diagrams/DESIGN-v3.md` and `lan-auth-v3.*` as exploratory analysis only.
  Do not rewrite the historical v1/v2 proposals or infer implementation approval.

- 2026-11-08: At the owner's request, analyse the exploratory LAN diagram and
  add a revised exploratory flow (`diagrams/ANALYSIS.md`, `lan-auth-v2.*`).
  Documentation only; no spec, protocol or code change.

- 2026-11-08: At the owner's request, add exploratory authentication-diagram
  artifacts under `diagrams/` (Mermaid source, SVG/PNG exports and render notes).
  This documentation follow-up does not alter the completed implementation
  steps or approve a cryptographic composition.

- 2026-11-08: keep the command guard in `cli::run` after argument parsing,
  instead of `main`, so it covers dispatch directly and leaves help parsing
  alone. No public interface change.

## Execution log

- 2026-11-08: owner requested fixes, explanations of the 64 MiB cap and advance
  notice of consequential changes. Initial tree clean except untracked audit
  symlink. Read all three role skills and assessment findings. The owner
  explicitly selected discussion first for index, filesystem and LAN policies;
  those changes remain unapproved. The initial repair batch is covered by the
  owner's explicit fix request; no separate approval requested for these fixes.
- 2026-11-08: Steps 1–3 complete. All 32 IDs match the supplied register exactly.
  `sh scripts/test-check-spdx.sh` passed; `cargo test --locked -p qv-sync`
  passed; `LIBSQLITE3_FLAGS=-DSQLITE_DQS=3 cargo test --locked -p qv-store
  compile_options` passed (one compile-options test), demonstrating the forced
  config despite an ambient weakening flag. `cargo test --locked -p qv-cli
  --test audit` passed (four tests, including unlock type-ahead and cancellation).
  Terminal unit tests are included in the final workspace run.
- 2026-11-08: Reviewed the actual diff and affected callers in the same session.
  Corrected a duplicated word in the architecture explanation. No independent
  audit or fresh-context review is claimed. `cargo fmt --check`, SPDX and
  Clippy passed. The first workspace test attempt stopped at missing Xvfb,
  not a product assertion. Fetched signed Alpine packages and extracted them
  under `/tmp/qv-0046-xvfb`, with a test-only launcher setting its library paths.
  Rerunning the required suite with `QV_TEST_KDF_JOBS=2` and
  `QV_TEST_XVFB=/tmp/qv-0046-xvfb/run`; both previously blocked clipboard tests
  now pass. No system installation, repository dependency or lockfile change.
- 2026-11-08: Additional source observation, not yet execution-validated:
  new-device join publishes its destination before building its index on
  unlock. Record preflight-before-publication in the pending index-policy
  design. Do not confuse this with the already-preflighted LAN merge path.
- 2026-11-08: Initial batch Implemented, then reviewed with one wording fix;
  verdict Approved with minor fixes (REVIEW.md). All required gates passed:
  SPDX, formatting, Clippy with warnings denied, and `cargo test --locked`
  (930 tests). Matrix check and SPDX rejection tests passed. Full gate logs
  are `/tmp/qv-0046-review-{spdx,fmt,clippy,test,matrix}.log`. Full tests used
  `QV_TEST_KDF_JOBS=2 QV_TEST_XVFB=/tmp/qv-0046-xvfb/run`. No dependency changes,
  so deny/vet not required. Plan status Reviewed refers only to this initial
  scope: the full assessment remains open, and the owner's three requested
  policy discussions are unresolved. No commit, branch or push performed.
- 2026-11-08: Owner requested that the editable LAN-authentication diagram and
  image exports be placed in the repository instead of `/tmp`. Copied the
  validated Mermaid source, SVG and PNG to `diagrams/`, with portable layout
  configuration and explanatory notes. Source/export bytes are unchanged;
  environment-specific browser state and launch configuration are excluded.
  The proposed password PAKE and recovery-key paths remain exploratory. No
  production or normative protocol change is included in this follow-up.
- 2026-11-08: Artifact-copy verification: repository Mermaid/SVG/PNG/layout
  files match their rendered source artifacts byte for byte. The blanket
  every-change gate rule prompted an unnecessary Cargo run for this doc-only
  copy. Owner objected and directed scope-appropriate verification; a stop was
  attempted, but the runner had already finished. No further Cargo run is
  needed for this artifact operation.
- 2026-11-08: LAN diagram analysis. Root defect: the 0013 §4.7 grant goes out
  before any password proof; §10 step 4 is a client-side check. Ten findings on
  `lan-auth` (credential-state location, a VK proof that proves nothing on the
  password route, a redundant grant envelope, method negotiation, the guess
  budget, the active-quantum OPAQUE gap, the B-side slot check). v2 recommends
  OPAQUE (the 0006 profile) with its state in the VK-encrypted keyslot record
  and the PAKE key folded into the record keys. Rendered with mmdc using a
  scratch no-sandbox Puppeteer config. Doc-only: SPDX check run, no Cargo gates.
- 2026-11-08: Owner requested a follow-up review of the other agent's diagram
  changes. `diagrams/REVIEW.md` requests changes to the verifier-compromise
  explanation, quantum-attack time horizon, missing explicit listener closure,
  proposed metadata leakage and key-confirmation rationale. A minor README fix
  distinguishes v1 from v2. Cryptographic proposals and exports are unchanged;
  the initial code batch's Reviewed status is preserved. The owner-selected
  close-after-first-valid-attempt policy must be carried into the next design.
  Artifact-only verification follows the owner's direction; no Cargo commands.
- 2026-11-08: Follow-up artifact checks passed: both Mermaid sources render;
  repository SVG text equals fresh source renders; both PNGs pass structure/CRC
  validation; local documentation links resolve; SPDX and whitespace checks
  pass. Analysis, Mermaid, SVG, PNG and layout files remain identical to their
  staged versions. No Cargo commands, production changes or staging operations.
- 2026-11-08: Drafted the requested product-specific v3 construction and
  diagram. Identified a repository-specific prospective leak: the current
  restore path serializes the encrypted keyslot payload into a clear local
  slot, so future secret authentication state needs distinct types/encoders.
  V3 specifies listener closure, one credential attempt, session-bound
  authentication, an explicit key-epoch transition, and slot/VK consistency
  checking before bulk transfer. A synthetic fake-emitter example confirmed
  that a direct password-derived HMAC can become an offline guessing target;
  it is a counterexample to a rejected shortcut, not validation of v3. No
  primitive, production protocol, dependency, accepted spec or staging change.
- 2026-11-08: V3 documentation/artifact checks passed: Mermaid renders; SVG
  parses and contains the updated flow; PNG structure/CRCs are valid and the
  export was visually inspected; local links, SPDX and whitespace checks pass.
  V1/v2 sources, exports, analysis and review are unchanged from staging.
  Source and exports are in the repository. Render logs are under
  `/tmp/qv-lan-v3-final-3j6r54a9/`. No Cargo commands were run for this design work.
  These checks validate documentation artifacts, not cryptographic security.
- 2026-11-08: Reviewed v3 against product fit only (owner: no external-document
  conformance criterion). `diagrams/REVIEW-v3.md`: direction sound; v3 fixes
  v2 review R1-R5. Confirmed the restore-path encoder hazard
  (`qv-store/src/restore.rs:153` writes the record payload, `ext` included,
  as the clear local slot). Requested simplifications: drop the context
  commitment, Finished pair, GrantAccepted and key-method acknowledgement;
  send Reveal with KE1; separate key-method MAC and schedule keys; use the
  record version in place of a credential epoch; move the text-cache policy
  out of scope. Recorded a product reason for the augmented PAKE (leaked state
  degrades only to offline guessing). Doc-only; no Cargo run.
- 2026-11-08: Completed another requested design review in
  `diagrams/REVIEW-v3-followup.md`, preserving the original proposals and review.
  Changes requested: exclude old readers before introducing encrypted secret
  fields, assess authentication-KDF guessing cost against the password slot,
  and define the atomic snapshot-check/grant-sealing boundary. Qualified the
  previous review's claim that removing Finished preserves every guarantee;
  no credential bypass demonstrated. Updated review navigation/index and
  changelog only. SPDX, whitespace and changed local-link checks pass. No
  production/spec/dependency or staging changes, no Cargo commands. Initial
  code-batch approval remains unchanged; v3 is still exploratory.
- 2026-11-08: At the owner's request for solutions, refined exploratory
  `diagrams/DESIGN-v3.md` with §13: structurally incompatible control records
  plus file/archive/LAN gates, a 256 MiB/t=3/p=4 Argon2id authentication-profile
  candidate with assessed profile pairs and upgrade rules, atomic snapshot
  verification/grant sealing under the existing session mutex, and conservative
  disclosure accounting from completed sealing. Retain FinishedA/B. Called out
  older-app incompatibility and the impossibility of guaranteed recall after
  grant authorization. These are proposed resolutions awaiting review, not
  closed findings or accepted/implemented behavior. No code, spec, dependency,
  Mermaid/export or staging change. Documentation checks: SPDX, whitespace and
  changed local links pass; no Cargo commands.
- 2026-11-08: Reviewed v3 §13 and the v3 follow-up; drafted `DESIGN-v4.md`
  and `lan-auth-v4.*`. The follow-up's F1-F3 all come from persisting
  password-authentication state. v4 removes that state: A's user types the
  vault password when approving the code, A checks it against its local slot,
  builds an ephemeral engine registration and wipes it with the session. This
  means no storage-format break, no migration, no credential lifecycle and no
  stored guessing target. Accepted F4: FinishedB is kept but sent in the same
  flight as KE3. Applied the agreed simplifications (no C/R, no GrantAccepted
  or ack, Reveal+KE1, split key-method secrets). The keyslot `ext`-to-clear-slot
  coupling is recorded as independent hardening. Doc-only; SPDX and whitespace
  checks, no Cargo run.
- 2026-11-08: Owner requested one concrete follow-up plan for the three
  discussed topics and explicitly selected ephemeral v4 over stored-state v3.
  Added plan 0047, LAN first, with cache/paging and filesystem disposition.
  Updated DECISIONS/FINDINGS to supersede the original recommendations without
  marking planned repairs fixed. Initial code review remains unchanged.
