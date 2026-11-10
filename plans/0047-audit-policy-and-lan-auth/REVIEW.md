# Review — Plan0047: Large-vault views and authenticated LAN enrollment

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved — local implementation; fixes included | 2026-11-09 | `git diff` plus untracked0047 sources, based on780733c |

## Summary

The three owner-selected policies are implemented: bounded cache/pages without
an aggregate searchable-text eligibility cap; ordinary authenticated moves and
copies; and credential-authenticated LAN/2 with one admission. The owner also
approved repairing the SQLite advisory discovered during final verification.
Required local gates pass. This is the implementing agent's source review,
not independent cryptanalysis, D12 approval or device qualification.

## Plan conformance

| Steps | Done | Notes |
|-------|------|-------|
| 1–3 | yes | Exact normative contracts, selected-engine readiness and public-slot/filesystem policy |
| 4–9 | yes | Crypto/codecs, admission, core authorization, verified publication and frontends |
| 10 | yes locally | Source/adversarial review and local D12 package; external gates carried forward |
| 11–14 | yes locally | Compact metadata, bounded pages/consumers and stock67.5 MiB lifecycle on both LAN routes |
| 15 | yes | Final full workspace/native gates, SQLite repair, evidence and documentation |

No unapproved production expansion. The SQLite upgrade and private adapter
compatibility changes were explicitly authorized. Follow-up release evidence is
in [0048](../0048-security-release-validation/PLAN.md); its implementation is
not started. Overall partially implemented/Draft spec statuses are preserved.

## Source review and fixes applied

- Listener ownership closes and joins the acceptor before KEM/credential work.
  No second-hello monitor, listener clone, advertisement or spent-code retry.
- Password authentication uses fresh local registration only after A's exact
  working-slot/head reauthentication. Typed initial/final channels enforce
  KE3→FinishedB→grant. Core snapshot/policy/deadline/sealer checks and one seal
  share a short mutex; no network/UI/KDF wait occurs there. A completed seal
  remains possible disclosure even when output is discarded. B checks the slot
  unwrap/VK equality before bulk and discards password keys.
- Key routes require independent VK, PB before identity/PA, and valid final B
  State before A's final data. No VK grant or extra password gate.
- Enrollment fully verifies source-bound private staging and preflights the
  compact index before no-replace publication. Fixed a grant/staging comparison
  that wrongly expected the grant to contain a local archive ID; the publication
  capability still binds the full staging source. Phrase mode preserves the
  password record and creates fresh local replica/anchor state.
- Fixed cancellation after publication/platform binding: return no unlocked
  session, retain the openable created file and report PublicationIncomplete.
  Barrier tests cover both points and successful local reopen/write.
- Fixed error-send/close ordering and disclosure/commit/receipt reporting.
  Locked results retain only fixed facts. Receipt confirms complete transfer,
  not peer publication. Prompt instance IDs reject stale replies; admission
  clears codes; passwords/form state clear on cancellation.
- Fixed B reveal/KE1 ordering before a comparison UI wait, stale v1 QR fixtures
  and docked-receipt automation. Native success/peer-open/secret-cleanup checks
  remain and pass.
- Compact summaries share ordinary merge rules and retain protected full-content
  digests rather than every conflicted payload. Cache capacities include leased
  readers/query/sort/cursor text. Page selection is bounded, scans release the
  mutex between16-ID batches, and cursors bind session/revision/query/scope.
  Production eager APIs are retired; frontend pages/path output remain bounded.
  Replaced eager title maps/version counts and a missed recovered-sidebar caller.
- Corrected the synthetic1 GiB test's false expectation that raw encoding validates
  budgets. Exact-bound acceptance and +1 rejection are checked by validation,
  decode and sealing. No production limit was changed or assertion weakened.
- SQLite repair pins rusqlite0.41.0/libsqlite3-sys0.39.1 (SQLite3.54.1). Reviewed
  the private `harden(&mut Connection, ...)` compatibility change and callers;
  hardening order, callback budget, compile flags, transactions and formats are
  unchanged. Compiled-version/options, crash, hostile-file and lifecycle tests
  pass. No SQLite advisory exception was added.

Application secret states/outputs use protected containers; Argon2 blocks are
wiped and RNG failure discards every result. Dependency-private scratch and
framework/OS residual copies remain best effort; complete erasure is not claimed.
Public slots expose defined keys0–6 only, preserving encrypted extensions.
Authenticated copies/moves retain ordinary anchor/runtime identity protections;
no persistent directory/inode policy was added.

## Gates

All following checks pass on the final SQLite-updated source/dependency tree:

| Check | Result |
|-------|--------|
| SPDX / fmt / matrix / diff whitespace | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass — complete final run, including all doctests |
| `cargo deny check` | pass with the existing narrowly traced unused crypto-bigint exception |
| `cargo vet --locked` | pass with explicit unaudited development exemptions |
| App native validation | pass —94 unit and3 GTK/WebKit window tests |
| Android crypto all-target check | pass — unchanged selected suite; compilation only |

The final full run uses opt-level1 with debug assertions and overflow checks
explicitly enabled, plus debug symbols disabled in this session's temporary
target directory. No test, KDF/model limit or production profile is reduced.
Main unit totals: core136, crypto133 (+1 existing ignored), model79, protocol29,
store235 and sync46; integration and doc tests also pass. The pre-upgrade debug
run's incorrect fixture assertion and near-full-disk benchmark failure remain
recorded in the execution log; neither is represented as a successful run.
Final logs: `/tmp/qv-0047-test-sqlite-final.log`, `clippy-final.log`,
`native-final.log`, `deny-final.log`, `vet-final.log` with the same qv-0047 prefix.

## Documentation and remaining release gates

Changelog, architecture/diagram, specs/index, CLI/app contracts, assessment
ledger, plan ticks and validation package are updated. No commit, staging,
branch or push was made.

[0048](../0048-security-release-validation/PLAN.md) tracks independent D12,
genuine dependency audits, physical Android/Linux lifecycle/interoperability,
representative and actual1 GiB benchmarks, and the bulk-mutation memory decision.
The67.5 MiB fixture and arithmetic boundary do not prove every1 GiB/device
workload. The64 MiB cache is not an RSS ceiling; bulk mutation preparation has
separate memory costs. These are explicit release/qualification gaps, not hidden
implementation claims or permission to release.
