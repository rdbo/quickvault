# Plan 0016 — Attachments (roadmap phase 1.11)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-27 | 2026-10-27 | 0002 §1/§3/§7; 0003 §6; 0004 §3–5; 0007 §2.2; 0008 §1/§5; 0011 §3–6; 0012 §1–3 |

## Intent

Store and retrieve attachments through core and the CLI without buffering a
whole attachment. Authenticate ordered chunks and the complete content, reuse
the existing manifest/transaction/anchor path, and require explicit consent
before writing plaintext to an external file.

## Scope

**In scope:** empty through 10 MiB attachments; fixed-size encrypted chunks;
bounded streaming add/read; metadata listing; confirmed removal with causal
tombstones; explicit safe file export; CLI `attach add|ls|save|rm`; tests and docs.

**Out of scope:** replacement/edit of attachment content or metadata, automatic
MIME detection, opening files, previews, network fetching, archive/sync/history
commands, format freeze, new dependencies or application unsafe code.

## Spec basis

| Behavior | Spec | Status | Application |
|----------|------|--------|-------------|
| Attachment key, random nonce, canonical AAD | 0002 §1/§3/§7 | Accepted | Existing reviewed primitives/key derivation |
| Metadata, ordered 64 KiB chunks, content SHA-256, 10 MiB maximum | 0003 §6 | Accepted | Existing AttachmentMeta codec |
| Chunk authentication, read verification, allocation and transaction bounds | 0004 §3.3/§3.6/§4/§5 | Accepted | Existing manifest roles and write path |
| Final tombstones, reference-based release | 0007 §2.2 | Accepted | Existing finalization and entry purge |
| Protected buffers and safe local files | 0008 §1/§5 | Draft | Roadmap D5 go-ahead |
| Causal versions, local head/anchor | 0005 §1–2/§5.4 | Draft | Roadmap D5 go-ahead |
| CLI attachments and explicit plaintext-file input/export | 0011 §3–6 | Amendment required | Step 1, exact proposed text below |
| Rejected objects, crash/lock paths, confidential intermediates | 0012 §1–3 | Accepted | Focused and final checks |

**Spec changes required:** amend 0011 §3/§4/§5/§6, its Changelog and index entry
in step 1. No existing spec status is promoted to Implemented. Physical encoding
remains developmental until 1.16; this plan uses existing chunk-length hooks.

## Decisions needed

1. **D1 — Approve the concrete CLI amendment and removal/export semantics.**
   Roadmap D9 already chooses CLI attachments. Recommendation: approve the
   exact proposal below: explicit input/output files, no overwrite or stdout
   export, confirmation for save and permanent removal (`--yes` supported),
   attachment addressing scoped to an entry, and fixed error mapping.
   This is the required concrete 0011 amendment, not a reconsideration of D9.
   Roadmap Session protocol step 4 excludes spec-amending plans from standing
   approval. Alternative: revise these semantics before implementation.
   **Resolution: owner approved on 2026-10-27 ("Looks fine to me").**

## Design

### Proposed normative CLI amendment

Insert an Attachments subsection in 0011 §4, with milestone 1 commands:

| Command | Behavior |
|---------|----------|
| `qvault attach add <entry> <file> [--name <name>] [--mime <mime>]` | Read a regular file, at most 10 MiB, and create a new attachment record owned by the live entry. Name defaults to its UTF-8 basename, MIME to `application/octet-stream`. No type sniffing. Report its `@id`, never contents. |
| `qvault attach ls <entry>` | List current attachment IDs, names, MIME and byte sizes. Surface conflicts explicitly. No contents or content hashes. |
| `qvault attach save <entry> <attachment> <path>` | Confirm plaintext export, verify complete content, then stream into a new owner-only regular file at the exact explicit path. Never derive output directories/names from stored metadata; never overwrite. |
| `qvault attach rm <entry> <attachment>` | Confirm permanent attachment removal; commit a minimal causal tombstone and drop its retained payload/history references. Release chunks only when no retained reference needs them. Explain independent-copy/secure-erasure limits. |

Add to §3.1: attachment content may additionally be imported from the explicit
regular input file of `attach add`. File paths, optional name/MIME and attachment
addresses are metadata visible in argv; bytes never enter argv/environment.
Add to §3.4: `attach save` is an explicit plaintext export under 0008 §3; its
confirmed output path is allowed, but plaintext temporary files remain forbidden.
Confirmation happens before output creation; `--yes` is explicit script consent.

Attachment address: exact name or `@` ID/prefix (at least six hex characters),
restricted to metadata owned by the addressed entry. Duplicate names/prefixes
fail 5 and list escaped matching IDs; absent fails 4. Trashed entries and
finally deleted attachments are unavailable to these commands. A conflicted
entry blocks add/save/rm with 8. Listing can show conflicted attachment metadata
without choosing a head; save/rm of a conflicted attachment fail 8.

Only `ls` accepts `--json`: array of objects with `id` (32 lowercase hex),
`name`, `mime`, `size` (integer bytes), `conflicted` (boolean). For conflicting
metadata, emit one row per head, adding `version_id` so no fabricated combined
metadata appears. Sort by attachment ID then version ID; ordinary rows also
include `version_id` for a consistent schema. Reject JSON for add/save/rm
before unlock. Human vault text uses existing escaping. Save writes no bytes
to stdout and reports success only after complete verification and file sync.

Add save/rm to §5.5 confirmations; `--yes` skips their prompts. Existing
`--password-stdin` is compatible with file input and with confirmed operations
using `--yes`; refuse combinations that still need confirmation before unlock.
Exit codes retain §6: absent 4, ambiguity 5, conflict 8, bound 9, integrity 7,
usage/options/invalid metadata 2, file I/O/unsafe path/existing destination 1.
Cancellation is 1; store/anchor errors keep their current mappings. No error
includes file contents. Add attachments to the code-4 description.

### Components and interfaces

Frontend vault access remains exclusively through qv-core. Extend existing
crates only, with private attachment modules and public exports where needed.

Proposed interface sketch (lifetimes/generic parameters may be made explicit
without changing the contract):

```rust
// qv-crypto: existing DataKey/AeadKey, profile and SecretBytes types.
fn seal_chunk(key: &impl AeadKey, profile: StoredDataProfile,
              aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError>;
fn open_chunk(key: &impl AeadKey, profile: StoredDataProfile,
              aad: &[u8], nonce: &[u8; 24], ciphertext: &[u8])
              -> Result<SecretBytes, CryptoError>;
// ContentHasher: incremental SHA-256; redacted Debug, no Clone, zeroizing
// sha2 state, final digest in SecretArray<32>. Distinct from public ObjectHasher.

// qv-store: bound/check all metadata; insert chunks within this Write only.
Write::stage_attachment(record: RecordId, source: &mut impl std::io::Read,
                        cancelled: &impl Fn() -> bool)
    -> Result<StagedAttachment, StoreError>;
// StagedAttachment owns bounded ordered IDs, measured size and protected hash;
// consume it with put_local attachment metadata before commit, else fail/rollback.
UnlockedVault::verify_attachment(record: RecordId, version: VersionId,
                                 cancelled: &impl Fn() -> bool)
    -> Result<(), StoreError>;
UnlockedVault::read_attachment(record: RecordId, version: VersionId,
                               sink: &mut impl std::io::Write,
                               cancelled: &impl Fn() -> bool)
    -> Result<(), StoreError>;

// qv-core: session-tagged, version-bound AttachmentHandle; redacted views.
Session::attachments(entry: EntryHandle) -> Result<Vec<AttachmentSummary>, CoreError>;
Session::add_attachment(entry: EntryHandle, name: &str, mime: &str,
                        source: &mut impl std::io::Read,
                        cancel: Option<&CancelToken>) -> Result<AttachmentHandle, CoreError>;
Session::verify_attachment(handle: AttachmentHandle,
                           cancel: Option<&CancelToken>) -> Result<(), CoreError>;
Session::save_attachment(handle: AttachmentHandle, sink: &mut impl std::io::Write,
                         cancel: Option<&CancelToken>) -> Result<(), CoreError>;
Session::remove_attachment(handle: AttachmentHandle) -> Result<(), CoreError>;
```

Core summaries use protected Text for metadata, bound view allocations by the
existing 64 MiB budget and return session/version-bound handles, including an
`id_hex` accessor. No raw keys, SQL or object bridge reaches the CLI. Reading
and writing callbacks run while the session call owns its lock; document that
callers must not reenter the session. Check lock/cancellation between chunks and
before commit/output writes. CLI wrappers check signals before each file read/
write; only regular local files are accepted (no pipe/socket/device blocking).
Unknown optional metadata stays preserved through tombstone rules as specified;
no attachment editing API is added.

### Chunk framing and content verification

Reuse the existing XChaCha primitive, nonce generation and attachment-purpose
key derivation. `seal_chunk` accepts 1..=65,536 bytes. Empty attachments have
zero chunks and SHA-256(empty). Every encrypted chunk has exactly
`sealed_len(65_536)` bytes, matching manifest::chunk_ciphertext_len. Use the
existing authenticated four-byte big-endian true-length header, content bytes
and zero padding to this fixed body's length, followed by the existing tag.
Factor shared framing helpers without changing record Padmé canonicality:
open_chunk checks fixed total length, authenticates first, then validates true
length and all zero padding; ordinary open still requires canonical Padmé.
Do not use ordinary open on a padded short final chunk.

Chunk AAD is exactly 0004 §3.3's canonical array with zero-based index,
attachment ID (= metadata record ID), random object ID, vault, generation and
profile. Derive the attachment key from the existing attachment purpose root.
Reference ciphertext length/hash and envelope identity/profile are checked
before AEAD. All non-final plaintext chunks must be exactly 64 KiB; the final
length must equal metadata.size minus preceding full chunks. Enforce ordered
IDs/count, complete byte count and SHA-256 at completion. Nothing is accepted
as complete merely because each individual AEAD passed.

Import reads at most one protected chunk plus one protected overflow probe:
fill across short reads, retry Interrupted, check 10 MiB before further growth,
probe EOF at the boundary and reject oversize. Hash only actual bytes; retain
at most 160 ciphertext references, never all ciphertext/content. Plaintext,
hash state/intermediates and partial-error buffers have zeroizing cleanup and
redacted Debug. Review sha2's enabled zeroize support for the new confidential
hash wrapper; do not reuse the public-ciphertext hash API contract for secrets.

### Transactions, retention and file safety

Begin the existing Write transaction, stage immutable encrypted chunks and
their references, then put one new AttachmentMeta causal version with measured
size/hash/IDs. Validate the owner entry and all policy before staging. Poison
the transaction after any staging error; commit rejects unused staged chunks,
metadata mismatch or staged chunks used under a different attachment ID/index.
Reuse put_local, manifest validation, budget enforcement and commit ordering:
objects/metadata/manifest/head → durable DB → external anchor → success/index.
Refactor core edit::commit minimally to share this path with attachment staging;
preserve its post-durable-commit index update even if anchor advancement fails.
No staging table, sidecar or plaintext DB/temp file. Rollback drops partial rows.

Removal uses existing finalization/history-floor/reference pruning. Entry purge
already tombstones owned attachment records; exercise that with real chunks.
Soft entry deletion keeps attachments encrypted/referenced for restore. A
conflicted attachment cannot be silently purged. Do not delete chunks by owner
ID without consulting the final manifest reference set. Future history/sync
continues to own its own retention policy.

CLI input/output file helpers use safe rustix APIs and no-follow directory walks
anchored to held directory descriptors. Reject symlink components, `..`, invalid
final components and nonregular files; no output name is taken from metadata.
Existing ancestors must be owned by effective UID or root and not writable by
other users (no sticky-directory exception). Output uses exclusive creation,
0600 and no-follow flags; never truncates an existing path. Input need not be
0600, but is opened once, inspected with fstat and measured while reading;
refuse a changed identity/size/time during import. A concurrent same-size edit
cannot be proved absent; import hashes/encrypts the bytes actually read.

Before creating output, confirm and perform a complete verification pass.
Then perform another authenticated streaming read with full end hash/length
check into the held new descriptor, sync it and its parent, and report success.
This prevents preexisting corrupt content from creating a destination and
still detects corruption between passes. Never use a plaintext temp file.
If cancellation/write/second-pass verification fails, leave the explicitly
selected output as incomplete and report that fact; do not unlink by a mutable
path and risk deleting a successor file. Crash/failure may leave partial output,
without any secure-erasure claim. Document this limitation in CLI help/spec
amendment. Core sink APIs may deliver individually authenticated chunks before
the final complete-content check, so callers must not treat partial output as
complete. Failed saves do not mutate accepted vault state.

**Dependencies:** none new. Existing qv-crypto sha2/zeroize, qv-store rusqlite
and existing safe rustix file APIs suffice. No dependency/lockfile change is
intended; any necessary new external dependency triggers a plan revision.

## Steps

### Step 1 — Adopt the approved CLI amendment

- [x] **Do:** After D1, apply the normative proposal above, including partial
  export failure, confirmation, input-file exception and output schema.
- **Files:** `specs/0011-cli.md`, `specs/README.md`, this plan.
- **Done when:** exact command/error/export/removal contracts precede code.
- **Verify:** inspect spec cross-references; `git diff --check`.

### Step 2 — Fixed chunk framing and confidential streaming hash

- [x] **Do:** Add bounded seal/open_chunk and ContentHasher with existing
  reviewed primitives; share framing helpers without changing record behavior.
- **Files:** `crates/qv-crypto/src/{stored_data,primitives,lib}.rs`,
  `crates/qv-model/src/payload/attachment.rs`, focused tests.
- **Done when:** lengths 1/65,535/65,536 have identical ciphertext sizes;
  oversize, bad tag/padding/framing fail; hash matches known SHA-256 vectors
  across fragmented updates; secret types/error paths remain redacted/zeroized.
- **Verify:** `cargo test --locked -p qv-crypto`.

### Step 3 — Stream chunks through the existing store transaction

- [x] **Do:** Add staging/read/verify, attachment key use, bound staged ownership,
  preserve manifest invariants and reference pruning; fail/rollback on any error.
- **Files:** `crates/qv-store/src/{attachment,object,write,vault,manifest,limits,lib}.rs`,
  existing/new attachment and crash tests.
- **Done when:** 0/1/64 KiB boundaries/10 MiB round-trip with bounded working
  memory; missing, swapped, reordered, truncated/oversized chunks, wrong AAD,
  wrong whole hash/length and unconsumed staging fail without accepted-state loss.
- **Verify:** `cargo test --locked -p qv-store attachment`;
  `cargo test --locked -p qv-store crash`.

### Step 4 — Core handles, authorization and lifecycle

- [x] **Do:** Add session-scoped attachment views/operations and share causal
  commit/index maintenance; require current live owners and single-head writes.
- **Files:** `crates/qv-core/src/{attachment,session,index,edit,views,lib}.rs`,
  error mappings if needed within existing variants, attachment integration tests.
- **Done when:** stale/foreign handles, read-only sessions, conflicts and lock/
  cancellation fail correctly; post-commit anchor failure keeps the index aligned;
  entry delete/restore preserves attachments and purge releases eligible chunks.
- **Verify:** `cargo test --locked -p qv-core attachment`;
  `cargo test --locked -p qv-core lock`.

### Step 5 — CLI commands and explicit safe files

- [x] **Do:** Wire commands, entry-scoped name/ID selection, confirmations,
  no-follow file helpers, JSON listing and signal-aware streaming.
- **Files:** `crates/qv-cli/src/{cli,main}.rs`, `src/cmd/{mod,attach}.rs`,
  private `src/attachment_files.rs`, JSON helpers if needed, related tests.
- **Done when:** preflight/refusals occur before secret/file side effects where
  applicable; no payload output/log/argv/temp file; destination never overwritten;
  unsafe paths/symlinks/special files fail; partial export status is explicit.
- **Verify:** `cargo test --locked -p qv-cli attach`.

### Step 6 — Cross-layer rejection, crash and streaming evidence

- [x] **Do:** Test production-binary add/list/save/remove and reopen; capture
  short-read/write failures, disk-full/error injection, staging/commit/anchor
  interruptions, lock races and destination replacement/refusal cases.
- **Files:** existing/new tests under qv-store/qv-core/qv-cli, their scoped fixtures.
- **Done when:** real 10 MiB round-trip; test instrumentation demonstrates
  bounded live chunks/working bytes independent of total attachment size;
  ciphertext role/hash/AEAD mutations fail and old accepted state survives failed
  imports. Save failure leaves no false complete success; removal/purge retains
  tombstones and only deletes unreferenced objects.
- **Verify:** focused attachment tests in all affected crates; existing offline
  production flow, explicitly reporting unavailable network isolation.

### Step 7 — Documentation and final gates

- [x] **Do:** Update component implementation descriptions, CLI docs and plan/
  roadmap records; keep format and assurance limitations explicit.
- **Files:** `ARCHITECTURE.md` §3/§6, `CHANGELOG.md`, affected crate docs,
  this plan, plans index, roadmap phase 1.11/log.
- **Done when:** all steps/evidence complete and final gates pass; leave changes
  uncommitted for the next fresh-context review.
- **Verify:** all gates below; `git diff --check`.

## Test plan

Final gates: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`.
Run deny/vet if dependencies change. Preserve full command output and exit
status in temporary logs. Clipboard integration still requires private Xvfb.
Map to 0012 rows hostile input/budgets, incomplete commitments, swapped role/
context, ambiguous trust boundary, CLI leakage, offline operation and anchor
crash windows. Include boundary lengths 0, 1, 65,535, 65,536, 65,537,
10 MiB and 10 MiB+1; no assertions weakened or ignored to obtain a pass.

## Risks and stop conditions

- D1 is resolved by owner approval; later normative changes still need approval.
- Stop for any unaddressed plaintext intermediate, primitive/dependency change,
  new format/spec requirement beyond the described framing/CLI amendment,
  additional Draft section, ownership ambiguity or nonlocal public API need.
- No complete-content success before full hash/length validation. No plaintext
  staging to make streaming/atomicity easier. Preserve transaction/anchor order.
- Fixed padded chunk parsing must stay separate from ordinary canonical Padmé
  validation; changing ordinary stored-data semantics is outside scope.
- External plaintext export cannot guarantee erasure or atomic completeness
  across process/OS failure; disclose partial output and never silently unlink
  a potentially replaced path. No trusted filename/MIME or automatic execution.

## Documentation

- [x] CHANGELOG Unreleased: attachment support, explicit export/removal limits.
- [x] ARCHITECTURE §3/§6: implemented streaming attachment responsibilities.
- [x] 0011 amendment/Changelog and specs index; no spec completion promotion.
- [x] Crate/CLI API/help docs: secret lifetime, partial sinks/files, error schema.
- [x] Plan/index/roadmap status, verification and handoff.
- AGENTS/workflow conventions: no change.

## Revisions

- 2026-10-27: Include local cleanup of AttachmentMeta.content_hash in the
  existing model: it is an ordinary fixed array today, but real attachment
  content now makes its digest confidential metadata. Add zeroization on drop
  and protect the decoder's pending hash on rejection; no field type/layout, format,
  dependency or normative behavior change. This implements the approved secret-
  cleanup requirement under 0008 §1.1, rather than leaving newly used hash
  intermediates behind. Core summaries copy protected names instead of moving
  fields out of the drop-guarded metadata. Also maintain unsupported-target API
  stubs alongside the new store methods; no new target support is claimed.

## Execution log

- 2026-10-27: Clean-tree next-phase session independently reviewed plan 0015:
  Approved, no code fixes/escalations; all independent gates, deny/vet and private
  Xvfb pass (474 workspace tests, 2 ignored; 12 transport tests). Phase 1.11
  prerequisites are complete. Architect read 0003 §6, 0004 §3–5, relevant crypto/
  memory/CLI/retention requirements and existing model/manifest/store/core paths.
  Prepared this proposal; D9 selects CLI attachments, but the required concrete
  normative CLI amendment invokes roadmap step 4. D1 pending; no implementation,
  spec text/status, dependency or phase checkbox changed. No user data, clipboard,
  phone, commit, push or branch action.

- 2026-10-27: Owner approved plan/D1. Resumed development with the preceding
  review/proposal documentation staged by the owner; no unrelated changes or
  product edits present. Preserve staging; no commit, push or branch.

- 2026-10-27: Steps 1–6 implemented. Applied the approved 0011 amendment and
  index note before product code. Crypto adds fixed chunk framing and a
  confidential SHA-256 wrapper; ordinary record framing stays canonical Padmé.
  The enabled sha2/digest zeroize path was inspected, and a compile-time test
  requires Sha256: ZeroizeOnDrop. Known SHA-256 abc and fragmented updates pass;
  authenticated malformed padding/length and context/size rejection tests pass.
- 2026-10-27: Store stages bounded chunks in its existing Write, measures actual
  content, tracks staged attachment ownership and rejects mismatched/unconsumed
  staging. Any staging failure poisons the transaction. All chunk references,
  per-chunk AEAD, full sizes/hash and cancellation are checked while streaming.
  No total-content allocation, plaintext staging file/table or dependency added.
  Core uses session/version-bound handles and shares the existing causal commit
  and post-durable-commit index update. Permanent removal/entry purge use current
  tombstone/floor/reference pruning; entry soft-delete/restore retains content.
- 2026-10-27: CLI implements scoped name/ID resolution, JSON metadata, consent,
  regular-file import, exclusive explicit export and no-follow directory walks.
  Held source/path identities and size/time changes are checked before commit;
  export verifies fully before creation, then verifies during output and syncs
  file/parent. Destination replacement is detected without unlinking successors.
  Partial plaintext output is explicitly reported, never accepted as complete.
  Source/sink callbacks are synchronous and must not reenter Session. Regular
  file I/O itself is OS-controlled; cancellation is checked between read/write
  calls/chunks and at the core commit boundary, not a hard syscall deadline.
- 2026-10-27: Focused evidence: crypto suite passes (108 unit tests, 1 ignored,
  integration/doctests also pass; /tmp/qv16-crypto-final.log); model attachment
  tests pass (3); store attachment tests pass (4, including eight crash/anchor
  boundaries). Core tests cover 10 MiB/boundaries, short reads/writes, fixed
  per-call chunk bounds, ENOSPC sink errors, cancelled calls, foreign handles,
  read-only/conflict refusal, lock around commit and during streaming, durable
  state/index after anchor failure, entry restore and chunk pruning. Production
  CLI 10 MiB round-trip, zero-length imports, schema/ambiguity, FIFO/symlink/
  traversal and overwrite refusal pass. A final invalid-dot-component path
  guard and regression were added during verification; final tree checks follow.

- 2026-10-27: Step 7 complete; plan Implemented, awaiting fresh-context review.
  Final tree gates pass: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`
  (489 passed, 0 failed, 2 ignored, including doctests). Complete outputs:
  /tmp/qv16-final-{spdx,fmt,clippy3,test2}.log. Full workspace coverage also
  includes the planned store crash/core lock/CLI attachment focused scopes;
  all three existing private-Xvfb clipboard tests pass. Test command uses
  QV_TEST_XVFB=/tmp/qv16-xvfb/usr/bin/Xvfb and
  LD_LIBRARY_PATH=/tmp/qv16-xvfb/usr/lib, without user-display access. The first
  full run also passed; reran after the final path guard/help/doc changes.
  No Cargo manifest, dependency, policy or lockfile change, so no new deny/vet
  run required for this phase. Formatting/lint assertions and tests were not
  weakened. Subsequent status/record changes are Markdown only; code/build
  inputs remain unchanged. Final diff/SPDX checks pass after documentation.
- 2026-10-27: Offline flow passes without account/server configuration, but
  `unshare -rn true` still exits 1 with “No space left on device”
  (/tmp/qv16-final-netns.log). Blocked-network evidence is unavailable, not a
  pass. No spec status promoted to Implemented; passing tests do not prove
  security. All owner staging is preserved and new changes remain unstaged;
  no commit, push or branch. Next phase is 1.12 after owner commit and a fresh
  review of this phase under the roadmap protocol.

Found, not fixed: export crash/failure may leave incomplete plaintext at the
explicit path, and independent copies cannot be erased. Source snapshot absence
of concurrent edits and syscall I/O deadlines are not guaranteed, as documented.
Native Wayland/other clipboard platforms and network namespace isolation remain
outside this phase's completed evidence. No phone or real clipboard operation.
