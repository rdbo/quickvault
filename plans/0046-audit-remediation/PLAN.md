# Plan 0046 — Security assessment: initial repairs

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-11-08 | 2026-11-08, owner request to fix audit findings | 0004 §1/§4, 0008 §1, 0011 §3, 0013 §1.4, 0014 §6.4 |

## Intent

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
