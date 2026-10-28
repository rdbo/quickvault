# Review — Plan 0018: Archives, local snapshots and `verify`

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-28 | `git diff 2dc7ac5..66474cb` plus owner-authorized uncommitted remediation; see resumed review below |

## Original review — summary (before remediation)

The archive framing, snapshot policy, CLI commands and full vault verification
are implemented, but snapshot publication does not establish that its objects
can be decrypted. A corrupted nonce passes the archive reader and publication
checks even though the full vault verifier rejects it. The archive reader also
omits the header-to-manifest reference-digest comparison. These findings block
approval and phase 1.13b under roadmap 0002's session protocol.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1–2: spec amendments | yes | D6 and owner-approved D1 amendments present; statuses unchanged. |
| 3: bounded header/framing | yes | Explicit version/profile/slot rejection and length bounds. |
| 4: writer/publication | partial | Atomic publication exists; verification accepts undecryptable objects (finding 1). |
| 5: reader/fuzzer | partial | Frame matrix and CI target exist; missing authentication and digest agreement (findings 1–2). |
| 6: full vault verification | yes | Re-hash, record/history authentication, attachment content and floor handling present. |
| 7: core policy | partial | Coalescing, budgets and pinning present; mandatory copies inherit finding 1. |
| 8: CLI | partial | Commands and recovery-copy ordering present; publication success is insufficient evidence for a usable copy. |
| 9: validation | partial | Existing rejection tests omit nonce-only corruption and a valid-MAC wrong reference digest. |
| 10: documentation | yes | Component responsibilities, limits, amendments and implementation records present. |

Out-of-scope changes: no product scope expansion found. The commit includes
the previous phase's review records and the roadmap split. The recorded UTC
day choice, header-only listing, one-object buffering and lack of a slot are
explicit in the implementation records. No external dependency or root
lockfile change; the isolated fuzz package adds an existing workspace crate.

## Findings

1. **[high] Publication accepts an undecryptable recovery snapshot** —
   `crates/qv-store/src/archive.rs:1314` (also lines 734 and 807).
   `object_envelope` checks the ciphertext hash but only checks the nonce's
   length. `read_archive` delegates each object to its sink without AEAD
   authentication, and publication supplies a sink that always succeeds.
   The writer likewise hashes ciphertext without authenticating the nonce.
   A nonce-only corruption therefore survives both passes: the object cannot
   be decrypted, but its snapshot is published as verified. A caller can rely
   on this copy before a destructive operation or prune healthy older copies.
   This falls short of 0004 §3.6's hash-then-AEAD acceptance rule, §6.5's
   re-read-and-verify publication requirement and 0007 §3's recovery purpose.

   Reproduced in production paths with temporary test-only probes:

   - Flip one byte in an object frame's 24-byte nonce, leaving ciphertext,
     manifest and header intact: `read_archive` returns success.
   - Change one stored object's nonce: `verify_all` returns `Integrity`, while
     `SnapshotDir::publish(Recovery, ...)` returns success.
   - Create retained history with two edits of one record; change only the
     historical object's nonce; close and unlock the vault successfully;
     `verify_all` returns `Integrity`, but recovery snapshot publication still
     succeeds. Thus this is observable after an ordinary unlock, not only
     through corruption of a previously cached active head.

   Recommendation: revise plan 0018 with `quickvault-architect` to specify
   bounded, role-aware record/history/chunk authentication during archive
   verification and publication, reusing existing crypto and model checks.
   Preserve the required length/hash-before-decryption order, no SQLite
   ingestion and no second vault write path. Do not change the reference hash
   or archive format to work around the missing verification. Add rejection
   regressions for nonce-only corruption, including retained history and
   attachment chunks, and ensure failed publication cannot authorize deletion
   or pruning based on an unusable new copy.
   Action: escalated; no product fix applied.

2. **[medium] Reader accepts a contradictory reference commitment** —
   `crates/qv-store/src/archive.rs:706`.
   After opening the manifest, the reader compares the configuration digest,
   count and total, but never compares `header.reference_digest()` with
   `manifest.reference_digest()`. A header with a wrong reference digest and
   an otherwise valid MAC is accepted. This violates 0004 §3.5's requirement
   to compare the reference digest to the decrypted manifest. It is a missing
   consistency check, not a demonstrated MAC forgery: the reproduction
   deliberately re-MACs the contradictory header with the fixture's key.

   Reproduction: write a real archive; flip one bit in the header's reference
   digest; re-MAC and encode that header; leave all frames unchanged.
   `read_archive` succeeds, and its returned header digest differs from the
   returned manifest's computed digest. Compare these commitments after
   authenticated manifest validation and before delivering object frames;
   reject the contradiction with `Integrity` and add a regression test.
   Action: escalated for the same remediation revision.

## Fixes applied by reviewer

No product changes. Four diagnostic tests were temporarily added to the
existing archive test module, run successfully to confirm the observed
acceptance bugs, then removed. The source was restored byte-for-byte before
handoff. Probe source and full output are retained in
`/tmp/qv18-review/archive-probes.txt`, `probes.log` and `probe-history.log`;
the reproduction procedures above are the durable record. These are defect
reproductions, not passing rejection/security tests.

## Gates

Full logs: `/tmp/qv18-review/`. Results below are independent reviewer checks.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | Pass (`spdx-final.log`). |
| `cargo fmt --check` | Pass (`fmt-final.log`). |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass (`clippy-final.log`). |
| `cargo test --locked` | Pass with private Xvfb: 560 passed, 0 failed, 2 ignored across 33 reported test groups (`test-xvfb.log`). Initial run failed because Xvfb was absent (`test.log`). |
| `cargo fmt --check --manifest-path fuzz/Cargo.toml` | Pass (`fuzz-fmt.log`). |
| `cargo deny check` / `cargo vet --locked` | Unavailable: Cargo subcommands are not installed (`deny.log`, `vet.log`). No new external dependency/root lockfile change. |
| `unshare -rn cargo test --locked -p qv-cli --test snapshots` | Unavailable: namespace creation fails with `No space left on device`; no test ran (`offline-snapshots.log`). |

The historical Xvfb path from the developer log is absent in this session.
An Alpine `xvfb` package was downloaded and extracted only under
`/tmp/qv18-review/xvfb`; the final run uses
`QV_TEST_XVFB=/tmp/qv18-review/xvfb/usr/bin/Xvfb`. No repository dependency or
system installation changed. No new instrumented fuzz campaign is claimed.
The two ignored tests are the existing development-vector generator and
subprocess helper; private-Xvfb clipboard integration tests ran and passed.
Passing ordinary gates does not resolve the reproduced defects or prove
security (0012).

## Documentation

- [x] CHANGELOG.md: feature entries and limits present; no product fix here.
- [x] ARCHITECTURE.md: current responsibilities and UTC policy documented.
- [x] Spec statuses and Changelogs: approved amendments present, no unsupported promotion.
- [x] Plan ticks/log, plans/README.md row and roadmap: review escalation recorded;
  plan remains `Implemented`, with approval withheld.

## Escalations for the owner

Finding 1 needs a plan revision before more implementation. The archive
reader currently exposes hash-checked envelopes to an arbitrary sink, while
publication treats a no-op sink as complete verification. Specify how the
archive's authenticated manifest roles drive bounded AEAD and semantic
validation of records, retained history and chunks before publication or
restore acceptance; fix finding 2 in the same revision. Phase 1.13b is not
started. No commit, push or branch was made.

## 2026-10-28 — Resumed review of owner-authorized remediation

**Verdict: Approved.** The original findings above remain the historical review
of commit 66474cb. This resumed review checks the uncommitted remediation in the
same session, not an independent fresh-context assessment. Both findings are
addressed: the reader authenticates records/history and ordered chunks, checks
whole attachment content, and compares the reference commitment before any
sink output. Indexed complete-envelope hashes detect frame changes between
passes. Source full verification precedes writing, and age pruning follows
successful publication. Existing head/control checks and chunk AAD are shared;
no format, primitive, schema or dependency change.

Rejection tests now cover nonce-only corruption of every role, corrupt retained
history/chunks after normal unlock, contradictory valid-MAC reference digest and
between-pass frame changes. The core regression preserves expired recovery
material on publication failure. Focused archive (23), core snapshot (15) and
store verify tests pass. SPDX, fmt, Clippy and full locked tests with private
Xvfb pass (565 passed, 0 failed, 2 pre-existing ignored); logs
`/tmp/qv18-review/fix-*.log`. Debug fuzz build/format pass and the non-sanitized
smoke run completes 94,607 executions without a finding; no instrumented or
release-validation claim. Final combined-tree gates after phase 1.13b will
cover subsequent changes. No remaining escalation from these two findings;
plan 0018 is Reviewed. Owner explicitly authorized continuation to 1.13b.
