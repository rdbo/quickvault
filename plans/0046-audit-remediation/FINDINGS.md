# Assessment disposition — 2026-11-08

Input: the owner's untracked `security-review` symlink, especially
`FINDINGS-REGISTER.md`, the Markdown assessment, remediation plan and packaged
PoCs. The package remains untouched. This is a repair ledger, not an independent
security assessment. "Fixed" below means the specified initial repair is in the
working tree; verification is recorded in PLAN.md/REVIEW.md.

## Initial repair batch

| ID | Disposition | Repair / limit |
|----|-------------|----------------|
| QV-001 | Fixed within the report's wording alternative | Fail closed if git cannot list sources; rejection regression. Describe the vendor check as declared identity metadata, not source provenance. No claim that vendor contents are hash-verified at gate time. |
| QV-002 | Fixed | Cargo forces the committed SQLite compile flags over ambient `LIBSQLITE3_FLAGS`. Existing compile-options test remains the validation; production runtime compile-options assertion is optional follow-up. |
| QV-003 | Fixed | Canonicalize mapped addresses for classification; connection policy, advertisement and QR inspection share the same predicate. Reject unscoped link-local, multicast, unspecified, broadcast and production loopback. |
| QV-007 | Fixed to the existing spec | Explicit typed addresses replace QR hints (0014 §6.4), rather than merely moving ahead in the list. Invalid typed addresses never fall back to a scanned endpoint. |
| QV-008 | Fixed documentation | Replace removed `lan-link` key schedule and session-handshake prose with the implemented `lan-proof` schedule (0014 §2.3). |
| QV-014 | Fixed help/documentation | `verify` does not repair vault contents; opening can complete a pending external-anchor update required by 0005 §5.4. Keep that recovery behavior. |
| QV-018 | Fixed | Command-lifetime no-echo guard, existing prompt semantics and signal handling, input flush before restoration. PTY regression covers type-ahead after Enter during unlock and handled cancellation. SIGKILL cannot execute cleanup. |
| QV-020 | Addressed by the report's documentation option | Explain that raw copies share replica identity and the default anchor, and recommend archive/snapshot export and new-path restore. No anchor-format or copy-detection change. |
| T3-05 | Fixed documentation | State that dependency-owned keyed HKDF/HMAC states are not zeroized on drop, in addition to padded-key stack intermediates. No claim of complete memory erasure. |

## Discussed policies — implemented in 0047, final validation/review running

| ID | Status | Concrete decision / evidence |
|----|--------|------------------------------|
| T3-08 | Implemented in 0047; final validation running | Compact structural index, bounded cache/query text, complete paged search and bounded app/CLI consumption replace aggregate-text eligibility. The stock67.5 MiB fixture uses ordinary saves without changing constants. The 1 GiB referenced-ciphertext budget remains; cache residency is not total RSS. Core preflights private enrollment staging before publication. Bulk-mutation payload vectors remain a separate memory cost. |
| QV-013 | Owner-accepted pre-start identity limitation; docs/tests implemented in 0047 | The owner accepts valid authenticated copies/moves and responsibility for divergent copies. No remembered directory/inode identity or new ancestor restrictions. Retain current permissions, no-follow, open-file identity, authenticated contents and external-anchor rollback checks. Do not describe this as detecting pre-start directory substitution. |
| QV-005 | Implemented in 0047; final review/release gates remain | First valid hello consumes admission and drops all listeners before continuing. Credentials and B’s final-key confirmation precede the atomic password grant; key routes transfer no VK. Reports distinguish sealing, receipt and durable actions. |
| QV-006 | Implemented in 0047 | Sixteen failures apply before admission only. No second-hello monitor survives. Later junk finds no listener and cannot disable the accepted session’s credential/deadline checks. Loopback regression passes. |
| QV-009 | Address and lifecycle fixes implemented; final gates in 0047 | Shared endpoint policy remains; admission owns/drops its listener, joins its acceptor, and preserves the original deadline. Obsolete probe state and observed-code outcome are removed. |

## Plan0050 implementation disposition — 2026-11-10

The fifteen remaining implementation repairs have source changes under the
owner's delegated correctness decisions. Local verification and limitations are
in [0050 validation](../0050-complete-audit-remediation/VALIDATION.md) and its
[completion check](../0050-complete-audit-remediation/REVIEW.md). Android media
qualification is still open; these are implementation dispositions, not an
independent security assessment or release approval.

| ID | Repair and remaining limit |
|----|----------------------------|
| VW-02 | Typed saved/anchor-pending outcome propagates through core and frontends; durable index repair and late-lock tests retain saved state. No cross-process duplicate-operation suppression is claimed. |
| T3-09 | Check each active-head clock union including the actual local resolver before acceptance, commit and new-replica publication. Refuse without truncating causality; existing states remain inspectable/exportable. |
| QV-004 | Encrypted random deletion-operation IDs distinguish independent deletes at identical timestamps. Missing legacy identity restores only the selected group; editor/history paths preserve deletion metadata correctly. |
| QV-016 | Bounded immutable read-only identification precedes mutable hardening; foreign WAL/hot-journal/hardlink rejection preserves bytes. Normal own-journal crash recovery remains tested. |
| QV-017 | Core, CLI and app show anchor-independence warnings for nesting/recognized risky locations. No automatic relocation or new persistent path binding. |
| T3-03 | Track completed X11 text/direct/INCR delivery; report replacement before confirmation separately, without clearing a successor. Android consumption remains unverifiable. |
| T3-07 | OS capacity/quota/file-size exhaustion has a fixed category, distinct from configured budgets, across store and platform outputs/frontends. Opaque provider failures without an errno remain generic failures. Durable outcome takes precedence. |
| T3-10 | Recovery entries carry private file leases; reclassification verifies already-ordinary copies and preserves real errors. Completion uses the mutation outcome path so a late lock does not turn successful completion into cancellation. |
| QV-011 | Core verifies a session/current-head/generation-bound recovery copy before final deletion, history purge, recovery-only baseline adoption and final-tombstone resolution. Stale, damaged, missing and foreign cases refuse unchanged; callers/tests use real copies. |
| QV-019 | Protected bounded range streaming replaces whole-media response vectors. Strict HTTP range/Host/origin/capability tests and native close/lock rejection pass; renderer/kernel copies remain best effort. Android qualification is pending. |
| QV-021 | Directory creation/cleanup coordination and lifetime file leases protect live temporaries. Process inode tracking avoids extra closes on live SQLite descriptors; killed-producer and actual SQLite-lock regressions pass. Orphan journals without a matching base and rotation-owned families are retained conservatively. |
| T3-02 | Audio/video playback and seeking work on real GTK/WebKit; images and large-image opt-in work. Exact loopback CSP/transport is implemented. Isolated Android media APK/test build; no phone is connected, so Android playback is unverified. |
| T3-04 | Display-only escapes cover labels/details/conflicts, paths, autofill candidates and editor display mirrors. Raw editor/copy/storage values and legitimate RTL/joiners remain intact; persistence round-trip regression passes. |
| T3-06 | Damaged external anchors have distinct status/guidance and authenticated read-only inspection; explicit copied baseline adoption preserves both original files until chosen. No blind deletion advice or data-repair claim. |
| QV-012 | Fuzz/product shared versions/checksums align; retained crypto exemptions document roles/debt. Six old versions are necessary delta-audit bases, documented and checked rather than blindly deleted. Desktop builds consume the unchanged verified upstream JS without ambient Bun. Deny/locked vet pass; independent dependency/composition review remains0048 debt. |

QV-015's absolute-deadline repair remains in0047. No supplied external campaign
is represented as rerun by these local regression results.

## Observations that do not warrant a silent behavior change

| ID | Disposition |
|----|-------------|
| QV-010 | Clarified the ciphertext type documentation. Retain the existing authenticated low-order-X25519 rejection; the report calls exact-draft alignment optional and records no oracle or shipped exploit. Changing the primitive wrapper's rejection behavior needs a separate crypto review, not an incidental cleanup. |
| T3-01 | The supplied report explicitly says the shipped app removes the preview element on lock and no preview remains visible. This is a web-engine residual-copy constraint, not a demonstrated shipped lock bypass. Preserve element teardown; route revocation and `no-store` alone cannot erase decoded pixels. Constraint recorded in architecture docs. |

## Verification limits

The package references full audit harnesses, generators and evidence directories
that are not bundled. Do not execute PoCs against real user data or infer that
those external campaigns were rerun. Local regression tests and required gates
validate this repair batch, not the whole report or the product's security.
