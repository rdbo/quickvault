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

## Discussed policies — owner directions selected, implementation pending

| ID | Status | Concrete decision / evidence |
|----|--------|------------------------------|
| T3-08 | Planned in 0047; existing cap unchanged | 64 MiB counts retained index text, not vault size. Owner chose bounded cache residency, on-demand complete search and paged frontend consumption, retaining the 1 GiB ciphertext budget. Stock edits/merges already preflight; the supplied authoring fixture raises the constant, so it is not proof of stock edits crossing the bound. New-device publication-before-index-build remains a source-observed ordering gap, not an execution-reproduced oversized join. Plan 0047 covers that path and ordinary frontends; no raised aggregate-text override is selected. |
| QV-013 | Owner-accepted pre-start identity limitation; docs/tests planned | The owner accepts valid authenticated copies/moves and responsibility for divergent copies. No remembered directory/inode identity or new ancestor restrictions. Retain current permissions, no-follow, open-file identity, authenticated contents and external-anchor rollback checks. Do not describe this as detecting pre-start directory substitution. |
| QV-005 | Planned in 0047; LAN behavior unchanged | Owner selected closure of every listener after one fully valid hello instead of ongoing second-hello detection. The accepted stream must authenticate credentials before any grant; v4 password approval uses password input on both devices. Disclosure, receipt and durable commit are reported separately. |
| QV-006 | Planned in 0047; LAN behavior unchanged | The 16-failure budget will apply only before admission. No detector remains after listener closure; the one accepted stream has independent timeout/cancellation/credential checks. Junk connections must not disable those checks. |
| QV-009 | Partial: address predicates fixed; remaining lifecycle planned in 0047 | Remove obsolete probe behavior with listener closure, join acceptor teardown and define the accepted session's deadline. Existing code is not yet repaired. |

## Remaining repair designs

These remain open. They are not closed by the initial batch or by passing gates.
The owner's repair request authorizes design work; actual payload/format/policy
choices must be made explicit before implementation, as requested.

| ID | Next concrete design / validation |
|----|-----------------------------------|
| VW-02 | Define a committed-but-anchor-pending result all the way from store to core/frontends, repair the in-memory index after durability, and preserve accurate reporting through cancellation. A generic error must not suggest retrying a committed mutation. Re-running `add` as a new process is not inherently idempotent: cross-invocation deduplication requires an explicit operation identity, not equality of titles/payloads. Test real or injected post-COMMIT anchor failure and retry. |
| T3-09 | Design causal-budget consistency before accepting merges. Reducing `MAX_HEADS` alone is insufficient: a small head set can already have a union of 256 writers. At minimum account for the union plus the local resolving writer; arbitrary future writers and previously oversized states need an explicit policy. Never discard causal components. Regression needs diverse full clocks, not only one writer per head. |
| QV-004 | Amend 0003 for a shared random delete-operation identity across one recursive delete, preserving `deleted_at` for display/retention. Define legacy missing-ID behavior and authenticated merge compatibility before changing payloads. Timestamp equality cannot establish operation identity. |
| QV-016 | Add bounded non-mutating vault identification before SQLite's journal-changing hardening. Preserve no-follow/file-identity/sidecar checks and apply hostile-schema limits before parsing. Read-only identification must not recover a foreign hot journal. Test foreign checkpointed WAL bytes and hardlink case unchanged after rejection. |
| QV-017 | Specify warning vs refusal for anchor nesting and recognized sync/network locations; expose the loss-of-rollback-independence warning through core/CLI/app. Do not silently move or reset anchors. |
| T3-03 | Define clipboard ownership-lost outcome separately from successful expiry/cancellation. Track completed direct and INCR transfers; report loss before completion without clearing a new owner's selection. Exercise a second X11 client before and during transfer. |
| T3-07 | Add redacted disk-full/quota classification consistently across SQLite, std I/O and rustix. Keep configured-budget failures separate from ENOSPC/EDQUOT/EFBIG; define CLI code/message and app guidance in the specs. Test each mapping and preserve pre/post-durable outcomes. |
| T3-10 | Make post-commit recovery-snapshot completion tolerate a concurrently reclassified pin when it is already ordinary, without suppressing real I/O/integrity failures or losing a required copy. Review shared-directory locking with QV-021; test two processes and truthful committed-result reporting. |
| QV-011 | Define core-enforced destructive-copy authorization bound to the correct session/state, recovery-only baseline adoption and the tombstone-resolution copy policy. Frontend-only preconditions do not protect future embedders. Do not treat any old snapshot as authorization for any later deletion. |
| QV-015 | Planned in 0047: one absolute bounded joining deadline including candidate attempts, prompts, KDF/transfer and pre-publication work, with safe handling of uninterruptible work and durable outcomes. Per-message idle bounds/cancellation remain. Implementation and tests are pending. |
| QV-019 | The response/provider currently owns an ordinary byte vector; removing `to_vec()` requires a response-ownership/lifetime design across the vendor boundary. Reject malformed/multiple ranges rather than silently serving the full body. Keep memory-lock failure visible; a 10 MiB preview need not fit an 8 MiB OS memlock limit. |
| QV-021 | Reclaim archive/restore/anchor crash temporaries only after proving they are stale; blindly calling a cleanup helper can delete another process's live temp. Define locks/names/age/budget accounting, then test concurrent writers plus SIGKILL leftovers. |
| T3-02 | Decide on functional audio/video transport vs explicitly unsupported media. A `blob:` solution changes the hardened CSP/provider boundary and introduces renderer-owned plaintext, so it needs an explicit design and real WebKit/device tests. |
| T3-04 | Define readable escaping/marking for bidi and invisible controls across GUI lists, details and conflict comparison, preserving legitimate RTL and joined-script text. Isolation alone does not reveal an override embedded in a title. Reuse CLI policy where appropriate without corrupting stored values or editing controls. |
| T3-06 | Partial documentation repair: architecture now states restore requires a healthy unlocked source and corrects which password slot is used. A specific damaged-anchor recovery hint and documented preservation/recovery workflow remain open; never advise blind anchor deletion or claim it repairs damaged vault data. |
| QV-012 | Review exemptions and fuzz/product resolution drift as dependency work; justify notes with actual evidence (not invented audits), remove stale versions using the lockfiles, and define reproducible vendor TypeScript tooling without ambient `bun`. Requires deny/vet, focused vendor tests/provenance review if vendor build behavior changes. A green exemption-based vet result is not an independent dependency audit. |

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
