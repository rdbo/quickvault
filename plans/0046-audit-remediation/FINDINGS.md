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

## Owner explicitly requested discussion before implementation

| ID | Status | Concrete decision / evidence |
|----|--------|------------------------------|
| T3-08 | Open; cap unchanged | 64 MiB counts retained index text, not vault bytes, notes, protected values or attachment bodies. `edit::commit_with` already preflights the resulting index before commit; archive/LAN merge candidates also preflight. The supplied `THIRD-index-cap-unopenable.sh` explicitly builds a modified author with a raised constant. The demonstrated problem is undocumented/interoperability/recovery policy, not proof that stock CLI edits can exceed the cap. Code inspection of `Core::join_new_device` additionally shows publication through `VaultFile::create_from_lan` precedes `self.unlock`, where the index budget is checked: include preflight-before-publication in the design. This join ordering observation has not been reproduced with an oversized peer fixture. Recommend documented default plus explicit bounded larger local policy; design core/CLI/app propagation and recovery before implementation. Never remove bounds outright. |
| QV-013 | Open; filesystem policy unchanged | Descriptor pinning protects in-process operations; it cannot recognize a parent substitution completed before process start. Persisting directory identity beside/in the anchor affects legitimate moves/restores. Alternatively reject untrusted writable ancestors, with explicit sticky-directory and platform policy. Blanket writable-ancestor refusal would reject common `/tmp`-based locations and fixtures; do not apply it without a precise agreed policy. |
| QV-005 | Open; LAN behavior unchanged | Carry second-hello detection through exchange/serve. Decide how closure reports completed grants or durable local acceptance: it cannot undo already delivered keys or committed state. |
| QV-006 | Open; LAN behavior unchanged | Either 16 failures closes the active session too (interruptible by junk connections), or keep an independently bounded detector alive while the accepted session continues. Owner requested discussion of this tradeoff. |
| QV-009 | Partial: address predicates fixed | The 2 s probe timeout vs spec and finished-session teardown remain open with the LAN batch. Do not conflate intentional failure counting with the detector-lifetime defect. |

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
| QV-015 | Specify the total joining deadline, whether candidate connection time counts, and when user confirmation/password input may consume it; then propagate it through transport and creation. Per-message idle bounds and cancellation already exist. Coordinate with the pending LAN policy. |
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
