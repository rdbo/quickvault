# 0012 — Security Validation and Release Gates

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-15 | 0001–0011 |

## Summary

Defines acceptance criteria and evidence that future implementations must
provide before release. This is specification work: no implementation tests,
cryptographic audit or platform validation have been completed here.

## Specification

### 1. Review findings and required evidence

| Finding | Design requirement | Required validation |
|---------|--------------------|---------------------|
| Isolated forks/freeze | 0001, 0005: limited claims, checkpoint comparison | Both forks can pass in isolation; comparison detects incompatibility; frozen head not labeled globally fresh |
| Old-date concurrent edits | 0005: vector causality | Preserve a concurrent edit despite older time |
| Order-dependent merges | 0005: maximal whole-record versions | All permutations, regrouping and duplicate delivery converge |
| Offline commitment mismatch | 0005: remote base separate from working state | Verify remote before merging pending local edits |
| Whole-file rollback | 0004/0005: completeness and external anchors | Delete/replace objects; restore old DB with intact newer anchor; exercise crash recovery |
| Live SQLite copying | 0004/0005: immutable archives built from verified objects | Concurrent writer during archive creation; incomplete archive, external replacement and crash cases |
| Swap/hibernation leaks | 0008: OS prerequisites and reduced-protection mode | Target-platform configuration and native input tests; memory/serialization buffer review |
| Active revoked sessions | 0006: immediate invalidation and commit checks | Revoke with open stream, pending ticket and authorized-but-uncommitted write |
| Incomplete key transport | 0002/0006: complete signed ephemeral transfer | Cross-implementation vectors, transcript mutations, replay, recipient/account/profile substitution and secret erasure |
| Unpinned crypto | 0002: exact profiles and X-Wing draft | Upstream known-answer vectors; wrong hybrid half/label/profile must fail |
| Hostile SQLite/CBOR | 0004: hardening and allocation budgets | Fuzz before/after authentication; malformed schema, lengths, nesting, pages and records |
| Deleted-entry resurrection | 0005/0007: permanent tombstones | Merge a years-old file; concurrent delete/edit remains an explicit conflict |
| Hardware assumptions | 0002/0009: backend-specific wrapping | Real-device algorithm/authentication/backup/reboot/lock/expiry tests; no silent fallback |
| Webview exposure | 0008: native input, CSP and bounded bridge | Remote navigation/asset rejection, HTML/URL/IPC injection and lock-time races |
| Self-referential/incomplete commitments | 0004: separate manifest and exact references | Missing history/chunk, duplicate references, wrong hash/role/configuration |
| Rotation/purge ambiguity | 0002/0007: resumable generations and suppression | Offline old-generation peer, interrupted rotation, old-history reimport and partial purge acknowledgements |
| Authentication complexity | 0006: TLS-bound opaque sessions and fixed OPAQUE profile | No token use on another TLS connection, replayed challenge or weak KSF; RFC OPAQUE vectors |
| Migration coupling | 0002: purpose namespaces | KDF-only upgrade preserves data objects; data upgrade preserves logical causality |
| Mixed credentials | 0005: complete concurrent records | No synthetic username/password/TOTP combination |
| Snapshot disk growth | 0007: coalescing/count/byte budgets | Repeated sync and mandatory recovery copy with full disk |
| Impossible generator | 0010: feasibility and bounded retries | Empty required class, too few positions and exhausted retries yield errors |
| Ambiguous trust boundary | 0008/architecture: explicit trusted client | Review every plaintext allocation, renderer and privileged bridge operation |
| Server-visible record linkage | 0004 §2.2: envelopes carry only object ID/profile/ciphertext | Inspect every server request and stored row: no record/version/attachment ID, chunk index or kind |
| Hostile files from sync folders | 0004 §6: authenticated archives, no SQLite ingestion | Fuzz archive prefix/header/frame lengths; truncated, reordered, extra and substituted frames; no SQLite open on exchange paths |
| Exchange-file password guessing | 0004 §6.4: no password slot by default | Exchange archives contain no slot; self-contained backup requires explicit choice |
| Password-slot partitioning oracle | 0002 §3.2: KEK commitment | Multi-key AEAD slot is rejected as wrong password before decryption |
| Remote rollback without chain | 0005 §5.3: causal acceptance rule | Replay, fork, floor regression and tombstone removal rejected after long offline gaps |
| Anchor crash windows | 0005 §5.4: one-step local head | Crash before/after anchor write; DB two steps ahead or from another install rejected |
| Pairing QR observation | 0006: one request per ticket, comparison code, derived MAC keys | Racing second requester cancels; mismatched code aborts; attacker's QR shows foreign account |
| Account lockout by phished password | 0006: password change needs device/recovery signature | Account session alone cannot change the account password |
| Biometric enrollment bypass | 0002 §5.2: Class 3, invalidated on enrollment | Adding a fingerprint invalidates quick unlock |
| CLI argument leakage | 0011 §3.1: notes prompted, `-i` | Notes never appear in argv; keys zeroized before clipboard countdown |
| Budget inconsistency | 0004 §4.2 | Generated worst-case manifest fits the manifest limit |
| Supply chain | 0001 T8/SG10 | Release gate below |

### 2. Acceptance scenarios

The matrix above specifies observable behavior for future implementation tests.
Each scenario must exercise the relevant production components once they exist,
including persistence, cryptographic verification and lifecycle boundaries where
applicable. Expected outcomes must include rejected inputs and preserved local
data, not only successful operations. Documenting a scenario is not evidence
that it passes or that the proposed protocol is secure.

### 3. Release gates

Before offline vault release, freeze the physical DDL, integer-key CBOR field
registry, profile IDs/parameters, archive format and golden file vectors,
including a worst-case manifest at the maximum budgets (0004 §4.2). Benchmark
KDF and resource budgets on the supported targets. Test transaction/anchor crash
points, permissions, disk-full behavior, malformed SQLite/CBOR and redacted
errors.

Before sync/pairing release, publish byte-level interoperation vectors for every
message, canonical transcript and error transition. Review the complete KEM/
AEAD/signature composition independently, including context binding and ephemeral
secret lifecycle. Test idempotency, compare-and-swap, reference-based GC, scope
checks, generation rotation, challenge consumption and TLS exporter integration.
Do not ship an unreviewed custom protocol merely because its primitives are
reviewed. Unknown required protocol features fail closed.

Before each GUI/mobile release, validate native secret input, CSP/IPC, OS
wrapping, locked-device prerequisites, lifecycle cancellation, verified autofill
matching and clipboard limitations on that actual platform. Disable unsupported
features rather than shipping untested equivalent-security claims.

Record pinned dependencies, applicable audit reports, known limitations and test
results with each release. Supply chain: commit `Cargo.lock`; build with
`--locked`; run `cargo deny` (advisories, licenses, sources) and `cargo vet` (or
equivalent recorded review) for every dependency change; keep security-critical
crates (crypto, CBOR, SQLite bindings, TLS) to a reviewed minimum; sign release
artifacts and publish checksums; work toward reproducible builds so third
parties can verify them. A failed gate blocks the affected feature, not
permission to silently weaken its protocol. Hosted admission, witness services
and a second server DB require their own evidence before enabling them.

## Security Considerations

Specification review cannot establish implementation security. The requirements
above still need independent protocol review and evidence from actual future
implementations. Memory guarantees remain conditional and freshness cannot be
manufactured by additional encryption or a successful response from the same
untrusted server.

## Open Questions

None for the acceptance process. Concrete benchmark/audit results are required
implementation evidence, not claims that this repository already has them.

## Changelog

- 2026-10-15: Initial accepted validation matrix and release requirements.
- 2026-10-15: Keep validation as specification acceptance criteria; remove the
  standalone executable model and claims of completed regression testing.
- 2026-10-15: Add security-review findings and supply-chain release gate.
