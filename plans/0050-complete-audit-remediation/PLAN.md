# Plan 0050 — Complete the remaining assessment repairs

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| In progress | 2026-11-09 | 2026-11-09: owner “so fix please”; engineering decisions delegated to correctness; working pre-1.0 compatibility delegated; functional media selected | 0003, 0004, 0005, 0007, 0008, 0009, 0011, 0012 |

## Intent and scope

Address every remaining implementation finding in 0046's ledger. This plan
tracks all fifteen open/partial rows to an actual repair and verification,
rather than closing another subset and losing the remainder. Preserve the
owner's untracked `security-review` symlink and report. No commit/branch/push.

0048's independent audits and attended release evidence remain separate;
implementation cannot manufacture those assurances. 0049's Android file-picker
proposal remains separate and unimplemented.

## Authorization and decisions

- Owner requests fixing the remaining findings, delegates engineering choices
  to correctness, and explicitly does not require legacy support pre-1.0.
- Use current finite clock limits; refuse unsafe/unrepresentable acceptance
  without dropping either side's data. Do not increase limits or erase clocks.
- Add a random deletion-operation identity. For a missing legacy identity,
  restoring a group restores that record only, never timestamp-matched children.
  No migration machinery is required; live legacy payloads may remain readable.
- Audio/video previews must work. Preserve strict origin/capability controls;
  no broad CSP wildcard or unauthenticated local media server.
- Media should load on demand with bounded application buffers. Stream large
  content; do not automatically collect a whole attachment into RAM or add a
  warning to every file. Offer explicit opt-in before an unavoidable large
  full-resolution allocation, with actual size information.

These are concrete engineering decisions under the owner's authorization,
not new owner questions. Amend normative contracts before behavior changes;
retain Draft status of whole specs where only named sections are approved.

## Requirements and repair design

| Finding | Contract / design | Main files |
|---------|-------------------|------------|
| QV-016 | Identify the exact vault schema using a bounded immutable, read-only SQLite connection before journal-changing hardening. Apply defensive configuration/SQL limits/progress budget before catalog reads. A private percent-encoded file URI with `mode=ro&immutable=1` is allowed only for this probe; production read/write connections still forbid URI input. Probe closes before a mutable connection exists. Preserve sidecar/owner/no-follow/identity checks and legitimate own-journal recovery. | store sqlite/schema/vault/fs tests; 0004 §1.2 |
| VW-02 | Add a data-free `StoreError::CommittedAnchorPending` outcome only after durable COMMIT when anchor completion fails. Propagate through core/CLI/app with explicit saved/do-not-repeat guidance; keep in-memory state/index synchronized and prevent cancellation masking durability. Keep existing CLI nonzero general-completion status; no cross-process deduplication claim. | store write/error, core edit/error and mutation callers, CLI/app error views; 0004 §5.2, 0011 §6 |
| T3-07 | Distinguish storage capacity/quota/OS file-size exhaustion from configured budgets. A fixed data-free capacity error covers ENOSPC/EDQUOT/EFBIG and explicit SQLite disk-full; max-page/model limits remain LimitExceeded. Preserve post-durable outcome precedence. | store error and I/O mappings, core/platform mappings, CLI/app guidance; 0011 §6 |
| QV-017 | Warn when anchors are nested in the vault directory or a recognized sync/network location compromises independence. Keep existing refusal of vaults inside the anchor directory; do not add general ancestor/inode binding, move anchors or reject approved authenticated copies. Surface warnings in core/CLI/app. | store warnings, core setup/views, CLI/app; 0004 §1.1, 0009/0011 |
| T3-06 | Separate a damaged external anchor from damaged vault contents in redacted guidance. Preserve both files; direct to explicit authenticated read-only recovery inspection and deliberate baseline adoption, never blind deletion or a claim of data repair. | store anchor/error, core setup, CLI/app docs/help |
| T3-09 | Before accepting a candidate, bound each active-head clock union including the actual local resolving writer, not just each head/count independently. Reject an unrepresentable union atomically. Existing oversized states remain inspectable/exportable; operations that need an unrepresentable clock fail unchanged. Recheck relevant local authoring and merge/restore/enrollment routes without causal truncation. | model clock/record, store/core acceptance; 0004 §4.2, 0005 §1 |
| QV-004 | Store a shared random 128-bit delete-operation identity in encrypted entry/group payloads for one recursive delete. Restore only matching identity within its subtree; clear identity on restore. Distinct operations at identical timestamps stay distinct. Missing legacy ID never uses timestamp grouping. Register exact optional CBOR keys in the spec before code; preserve unknown extensions. | model entry/group codecs and projection, core edit/history/conflict; 0003, 0007 |
| QV-011 | Core creates and validates recovery copies for destructive operations, bound to session, generation and exact pre-mutation head. Do not trust frontend-only call ordering or a stale/foreign snapshot. Restrict baseline adoption to recovery state. Final tombstone resolution uses the same recovery-copy policy. Update all frontend/core callers rather than weakening tests. | core snapshot/session/history/edit/conflict, CLI/app callers; 0007 §3.2 |
| T3-10 / QV-021 | Introduce cooperative cross-process lifetime leases for active recovery copies and temporary files. Directory-scoped creation/cleanup locking covers create→lease acquisition; file leases survive until producer/pin completion. Cleanup locks, verifies identity/name/ownership and removes only unleased known temporaries; never rotation-journal-owned replacements. Reclassification tolerates an authenticated already-ordinary copy and does not hide I/O/integrity errors. SIGKILL releases leases; no age-only stale inference. | store fs/archive/snapshot/creation/inventory/restore; core snapshot; 0004/0007 |
| T3-03 | Clipboard reports ownership loss before completed delivery separately from expiry/cancel. Track direct and INCR completion; never clear a successor's selection. Preserve explicit terminal/platform limitations. | platform clipboard, CLI/app result mapping; 0008 §4.4, 0011 |
| QV-019 / T3-02 | Replace application-owned ordinary preview response vectors with a revocable protected streaming source. Reject malformed/multiple ranges with a bounded 416 response. Deliver audio/video over a browser-compatible authenticated same-app transport with exact origin/CSP bounds, bounded headers/connections/chunks, request cancellation and route revocation. Prefer existing hardened loopback transport over a second server. Load media on explicit action with conservative preload settings. Audit library/renderer copies as best effort. | app preview/documents/UI; maintained desktop hardened/protocol/transport adapter; 0003 §6.4, 0008 §4.4, 0009 |
| T3-04 | Display bidi overrides and hazardous invisible controls as readable fixed escapes in labels, details and conflict comparison. Preserve stored/editable text and legitimate RTL letters/joiners; do not “sanitize” persisted values. Reuse CLI escape classification where applicable. | app display/view helpers and UI, CLI shared policy if appropriate; 0009 |
| QV-012 | Reconcile exact product/fuzz lock resolution and exemption notes; remove stale entries only, never invent audit evidence. Pin/vendor-build TypeScript tooling instead of ambient bun and document actual provenance. Any dependency/tooling delta needs deny/vet and focused maintained-vendor checks; genuine missing audits stay explicit debt in 0048. | supply-chain, fuzz lock/config, third-party build metadata/docs; 0012 §3 |

## Security invariants and interfaces

No new primitive, crypto suite, KDF cost, vault eligibility cap or wire profile.
Keep application secrets in SecretBytes/SecretArray, no secret formatting or
argv, and bound hostile input before allocating/authenticate before payload
parsing. Metadata/preview leases cannot bypass session lock cancellation.

The immutable SQLite probe is identification, not authentication. It reads
only bounded catalog/header metadata and never recovers a journal. Full normal
hardening and authenticated verification still run after identification.

Durable errors are distinguishable from unchanged failures without recursive
error payloads or user content. Update all exhaustive frontend mappings. New
capacity/warning/error wording is fixed and redacted; existing exit categories
are retained unless a later explicit revision records a necessary difference.

For leases, keep creation and stale cleanup within the same directory lock;
an exclusive per-file lock acquired before releasing it prevents the window
where a live new file appears unleased. Pins carry a private lease rather than
merely an archive ID. Core copy authorization carries session/head identity and
is consumed or invalidated by the corresponding mutation. No automatic caller
can delete/restore a snapshot just because its timestamp resembles another.

Preview stream state owns protected chunk buffers and a revocation token;
renderer/kernel copies remain documented limits. No persisted plaintext or
new unrestricted webview bridge. Validate media transport/ranges on actual
WebKit/Android; do not close playback from an HTML-only unit test.

## Execution steps

### Media transport refinement (before step6 adapter edits)

- Extend the existing IPv4 loopback edit listener, preserving its independent
  websocket authentication. Media uses `/preview/<128-bit random token>` and
  never exposes/reuses the websocket client key in a media URL. The app reads
  the process listener's current port through a small native `preview_url`
  helper. Listener restarts update the helper; old preview URLs fail closed and
  the user can reopen a preview. No extra listener, dependency, crypto or unsafe.
- Pass the existing opt-in Preview provider to that listener. A provider returns
  fixed MIME/total and an opaque `PreviewBody` with `write_range` into a writer;
  no response `Vec<u8>` contains plaintext. HTTP and websocket initial work share
  the existing four-connection cap; admit before spawning. Bound the complete
  initial header to8192 bytes, three-second socket reads/writes, and64 headers.
  Read exactly through CRLFCRLF, replaying the bounded prefix to the existing
  tungstenite handshake for websocket requests. Slow HTTP cannot hold the accept
  loop. Request threads/streams own permits through completion.
- Accept only GET/HEAD, origin-form exact token paths, exact numeric loopback
  Host/current port, no body/transfer encoding, and one Range. If Origin is
  supplied it must be the exact bundled Android origin, or the Linux custom
  origin/its opaque `null` serialization; absence is allowed for media engines.
  The unguessable capability is required even with an accepted Origin. No CORS
  grant, redirects, filesystem paths, request/body logging, or persistent cache.
- Strict single ASCII decimal ranges only; malformed/multiple/unsatisfiable
  ranges receive416 and `Content-Range: bytes */<total>`, never a full fallback.
  Valid ranges receive206 (including an explicit whole-file range); HEAD has
  the corresponding headers without content. Responses close, use no-store,
  nosniff/no-referrer, and fixed MIME. Remove the old custom-protocol preview
  response body path. CSP allows only the exact numeric HTTP listener origin
  for img/media plus existing self; websocket connect policy remains separate.
- Preparation verifies the whole content hash by streaming to a sink, then
  retains at most a1 MiB text prefix plus a bounded image header, never the whole
  media. Store/core add authenticated range reads capped at64 KiB, referencing
  the exact session/metadata version; every chunk checks its manifest hash/AEAD,
  role, index and expected length. A full verification precedes preview acceptance;
  ranges are not themselves represented as complete-content verification.
- Active media holds a Weak session and attachment handle, a protected random
  token and revocation/approval atomics, not a detached vault key. `write_range`
  decrypts at most64 KiB into SecretBytes per iteration (at most two input
  chunks for an unaligned range), checks session/revocation before delivery,
  and writes directly to the transport. No session lock is held on socket I/O.
  Closing/navigating/locking revokes and drops source state; in-flight kernel or
  renderer copies remain best effort and no late new chunk may begin.
- Audio/video have no autoplay and preload none; the viewer shows file size.
  Parse bounded PNG/GIF/JPEG/WebP dimension headers. Defer image decoding behind
  explicit "Load image" if RGBA lower-bound size exceeds64 MiB or dimensions
  cannot be established within the bounded header. Show dimensions/estimated
  decode memory where known. This is per-preview consent, revoked on close or
  attachment change, not a warning on every file. Ordinary images load directly.
- Verify actual GTK/WebKit and isolated Android playback/seeking and lock
  revocation. W3C mixed-content rules treat potentially trustworthy loopback URLs
  separately (https://www.w3.org/TR/mixed-content/); Android WebSettings documents
  strict mixed-content defaults (https://developer.android.com/reference/android/webkit/WebSettings).
  These references inform design only: do not weaken Android mixed-content
  settings on speculation and do not claim compatibility before device evidence.

### 1 — Contracts and complete tracking

- [x] Amend the exact spec sections before each changed behavior. Record the
  chosen encrypted deletion fields, durable/capacity outcomes, causal acceptance,
  recovery authorization/leases and preview transport in their owning specs and
  Changelogs/index. Do not promote whole Draft specs.
- Files: specs 0003/0004/0005/0007/0008/0009/0011 as needed; specs/index,
  0046/FINDINGS.md, this plan, Changelog and plans index.
- Done: each of all fifteen IDs has a concrete step and no silent design choice.
- Verify: source/spec trace; update decisions as work exposes actual interfaces.

### 2 — Non-mutating opening, outcome/capacity and recovery guidance

- [x] Implement QV-016 first, then VW-02/T3-07 and QV-017/T3-06. Add targeted
  regressions for foreign WAL/hot-journal/hardlink bytes, real/injected anchor
  failure after COMMIT, cancellation/index repair, OS/SQLite capacity mapping
  and truthful frontend guidance. All existing crash recovery remains.
- Files: store sqlite/schema/vault/fs/write/error/anchor, core setup/edit/error,
  CLI and app error/warning adapters; focused tests/docs.
- Done: rejection does not alter foreign bytes; saved changes never look like
  unchanged generic I/O failure; location/anchor/capacity limits are explicit.
- Verify: focused store/core/CLI/app tests, existing store crash matrix.

### 3 — Causality and deletion identity

- [x] Implement T3-09 and QV-004 under their amended contracts. Test unions of
  diverse full clocks, exact local-writer inclusion, malformed/over-budget input,
  unchanged refused candidates, fixed-time independent deletions and complete
  recursive round trips including missing legacy identity.
- Files: model clock/payload codecs/projection; store/core candidate acceptance,
  core edit/history/conflict and tests.
- Done: retained state is resolvable by the admitted local writer; no discarded
  causality or resurrection of a separate delete operation.
- Verify: model and merge properties, store/core acceptance and deletion tests.

### 4 — Destructive authorization, pins and stale cleanup

- [x] Implement QV-011, T3-10 and QV-021 together so pin/copy lifetime is correct
  across processes. Test foreign/stale/session-mismatched authorization, direct
  core calls, concurrent policy passes/reclassification, live temporary writers,
  SIGKILL leftovers, cancellation and all pre/post-durable results.
- Files: core snapshot/session/edit/history/conflict and callers; store fs,
  archive/restore/creation/inventory/rotation temp interactions and tests.
- Done: core enforces recovery policy; live leases cannot be reclaimed and
  already-completed reclassification cannot misreport a committed operation.
- Verify: focused concurrency/crash tests; existing rotation/archive suites.

### 5 — Clipboard and safe display

- [x] Implement T3-03/T3-04 with actual X11 ownership/INCR tests and GUI display
  regressions for bidi overrides, zero-width hazards, valid RTL and edit fidelity.
- Files: platform clipboard, CLI/app adapters, app display/UI tests.
- Done: no false clipboard completion and no hidden display overrides; valid
  text and stored values remain intact.
- Verify: focused platform/CLI/app tests and native display checks.

### 6 — Protected bounded media transport

- [x] Implement QV-019/T3-02 with the approved functional-preview policy and
  owner-requested on-demand/bounded-memory UX. Complete the exact maintained
  transport/CSP design in this plan before adapter edits. Verify source archive
  hash/provenance per third-party/README.md before vendor changes.
- Files: app preview/documents/UI; maintained desktop hardened/protocol/edits
  as required; third-party README, 0003/0008/0009 and targeted tests.
- Done: image/audio/video function on real engines, malformed ranges fail,
  active/late requests revoke on lock and no whole-file app RAM collection is
  implicit. Explicit opt-in handles unavoidable large full-resolution decoding.
- Verify: protected-source/range/revocation tests; focused vendor tests and actual
  GTK/WebKit/Android playback with isolated synthetic data and memory evidence.
- [x] Source, transport/range tests and real GTK/WebKit playback/seek/consent/revocation.
- [ ] Actual Android playback/seek/consent/revocation: no connected phone; isolated APK and test prepared.

### 7 — Supply-chain baseline, final review and full disposition

- [x] Complete QV-012 without converting exemptions into audits. Run required
  final gates plus deny/vet for any dependency changes and focused vendor checks.
  Apply the repository-required reviewer stage to changed security-sensitive code;
  this is not the separate external D12 review. Update every ledger row to its
  actual outcome, including genuine remaining external/device blockers.
- Files: supply-chain/fuzz/third-party tooling records; this REVIEW.md and
  VALIDATION.md; ledger, architecture boundaries, specs/index, Changelog/plans.
- Done: every repair has evidence and accurate limitations. No unsupported
  “all security addressed” or release assertion from tests alone.
- Verify: SPDX, fmt, all-target locked Clippy, locked workspace tests, matrix;
  deny/vet and focused vendor/native checks as applicable on the final inputs.

## Risks / stop conditions

Stop before a new crypto construction, unsafe code, unapproved dependency,
causal truncation, silent partial mutation, destructive user-data operation,
external reviewer contact/spending, or weakening CSP/authentication/limits.
Unexpected security/data ambiguity needs a documented plan/spec revision.
Owner delegates engineering choices, not permission to hide failed evidence.
Keep temporary fixtures private and never run supplied PoCs on personal vaults.

## Documentation

- [x] All changed normative contracts + Changelogs/spec index.
- [x] All fifteen finding dispositions and actual validation records.
- [x] Architecture §3/diagram for changed preview or storage boundaries.
- [x] Changelog, CLI/app guidance, third-party maintenance details, plan/index.
- [x] REVIEW.md; no AGENTS.md/workflow change unless actually necessary.

## Execution log

- 2026-11-10: Final-tree workspace gates pass:1,000 tests/0 failures/6 intentional
  ignores, fmt, SPDX, matrix and all-target Clippy; desktop/validation app lint,
  locked fuzz build and dependency/artifact baseline pass too. Deny/vet pass
  with unchanged advisory policy; maintained vendor13 tests and ordinary real
  engine3 tests pass. Unsessioned native media was intermittent (including a
  later stage2 timeout); no audio service was running. Final native binary passes
  twice with private D-Bus/PipeWire/null-sink runtime, now reproducible in the
  runner with --private-runtime. Physical speaker and Android media evidence
  remain unverified. Isolated final APK/test IDs/native hashes are checked;
  adb sees no device. All local authorized work is complete; keep In progress
  for actual Android qualification. Validation, local check and ledger updated.

- 2026-11-10: Local completion check caught an unintended parent-alias refusal:
  the short directory flock must follow the existing owner-controlled parent
  policy, not introduce O_NOFOLLOW on a previously permitted directory alias
  (QV-013). Preserve explicit snapshot/anchor-root no-symlink checks, remove
  the extra generic-parent restriction, and add an alias/lease/cleanup regression.
  Annotate new regressions with their exact0012 matrix rows. Rerun affected gates.
- 2026-11-10: All fifteen implementation areas now have source repairs and
  dispositions in0046/FINDINGS.md. Linux media validation passes, including
  video/seek/images/expensive-decode consent/late-capability rejection. Use a
  monotonic deadline and one explicit Audio load in the validation driver;
  retain the failed currentSrc assumption and later timeout as failed evidence.
  Isolated Android media APK/test build under org.quickvault.validation50;
  no phone is connected and no package was installed. Full local gates and the
  completion record are being finalized; Android qualification keeps this plan
  In progress. No independent reviewer/contact, commit, branch or push.

- 2026-11-10: Final sweep extends existing T3-07 file-output mappings through
  platform create/fsync and app/CLI adapters. Display escapes also cover vault
  locations, autofill candidates and editor display mirrors while editable
  controls retain original text. Hidden-document cleanup sends an empty bounded
  input event through the existing typed UI bridge to ClosePreview; renderer
  pause/reset alone does not revoke Rust's capability. No broad new IPC command.
- 2026-11-10: QV-012 correction from actual locked-vet evidence: the six
  apparently stale exemptions are necessary starting points of existing
  imported delta audits. Removing them produces six missing-current-version
  failures. Retain their original versions/criteria with explicit base/debt
  notes and verify their imported references in CI; no replacement exemptions
  or audit claims. This refines the earlier removal proposal based on actual
  policy semantics; see DEPENDENCIES.md and the failed/pass vet logs.
- 2026-11-10: QV-012 tooling refinement: retain the exact prebuilt native_eval.js
  shipped in the hash-verified dioxus-desktop0.7.10 archive (SHA-256
  fc39bfae6f037e44dafa80b9e8ec022dd9f76f7a515dd455a30afb3d5966ca85).
  Remove its ambient lazy-js-bundle/Bun build invocation and build-only dependency;
  ordinary builds consume the checked-in artifact without regeneration/downloads.
  Regeneration is a deliberate future vendor update with fresh provenance review.
  Reconcile fuzz's shared resolution using the product lock as the seed; retain
  only libfuzzer-sys and its fuzz-only dependencies as separate versions. Remove
  exemptions absent from both resolved trees and correct stale exact-version
  notes; add no audit claims or new exemption approvals. Run deny/vet and both
  locked builds after resolution changes.
- 2026-11-10: Resume with developer/architect skills; temporary tools/logs were
  cleared by the environment. Restore a private X server and persist its media
  runner here. Native facts confirm close pauses/detaches the element, removes
  src and resets ready/network state. WebKit retains stale currentSrc (WHATWG
  html issue10410); check actual reset states and reject a fresh closed-capability
  request instead of using that reporting field as evidence of active playback.
- 2026-11-10: Finish step4's descriptor design before code: one process registry
  owns an Arc<File> per leased inode and a Weak lifetime token. Handles drop
  their file Arc before their token; the last token removes/closes the registry
  descriptor under the registry mutex. A dead Weak still present means Locked,
  avoiding acquisition during the closing window. SQLite-capable LockedFile
  cannot be duplicated/reopened. Explicit into_archive_file changes it to opaque;
  archive readers reuse its descriptor with independent positioned I/O cursors.
  Newly opened opaque readers hold shared flock leases, while producers and
  cleanup hold exclusive ones. No extra fd is closed on a live SQLite inode,
  including hardlink aliases. A short directory flock covers temp creation and
  cleanup; filesystem publication uses the registry mutex for local identity
  lookup/open coordination. No new dependency, unsafe code or format change.
- 2026-11-09: Owner asks status with almost no session usage left; record the
  unfinished checkpoint in HANDOFF.md. Nine repair areas have implementation
  and focused evidence; media has unit/transport evidence and native audio
  playback/seek, but fails cleanup stage4. Four repair IDs still need code.
  Final verification/review remains outstanding; no completion/commit claim.
- 2026-11-09: SQLite lease design safety refinement: closing an additional fd
  of an inode can release this process's SQLite POSIX locks, even if a flock
  attempt on it fails. Track live inode guards in a process registry and check
  before opening during cleanup/acquisition; serialize acquisition/publication
  identity lookup with that registry. Opaque archive/journal descriptors are
  explicitly classified, and the private conversion is named into_archive_file;
  their flock survives File ownership but they must never host a SQLite connection.
  Read-only helpers must not open live SQLite inodes under this process either.
  Orphan journals without a matching owned base are retained conservatively;
  journal cleanup happens while its matching base lease is held, before unlinking
  the base. No age or mere path absence establishes a safe live-file deletion.
- 2026-11-09: Step4 interface refinement before implementation: SnapshotEntry
  privately carries an Arc file lease after publication; metadata equality and
  Debug omit that capability. Store removal/reclassification take the directory
  lock and either reuse the owned lease or acquire an exclusive nonblocking
  lease, verifying path identity. Reclassification accepts scope/VK to authenticate
  an already-ordinary target. Producers keep file leases through rename/fsync.
  Shared temp creation/cleanup covers the create→flock window with a directory
  flock; match base-file leases before considering journals.
- 2026-11-09: Core's private recovery pin records sequence/generation and the
  leased entry. A private require_recovery helper fully verifies the copy and
  compares its manifest to the current pre-mutation state before protected
  destructive calls. Frontends keep their existing explicit copy/budget flow;
  missing/stale authorization is rejected. Sequence advancement invalidates it
  for a second mutation. Completion may release/reclassify a consumed pin, and
  uses the mutation outcome path so late lock cannot rewrite completed metadata.
- 2026-11-09: Preview stream/range/revocation and bounded-prefix focused tests
  pass (5 app tests); maintained transport tests pass13 including real TCP
  request/range/Host/origin rejection. Added portable synthetic media fixtures
  for actual WebKit/Android playback and a pixel-budget consent check. The first
  native harness attempt timed out during setup because its generated128 MiB
  WAV exceeded the existing10 MiB attachment limit; corrected to8 MiB and made
  synthetic setup errors explicit. No format/eligibility budget is increased.
- 2026-11-09: Media cleanup refinement: packaged JS pauses media, removes src
  and resets it on DOM removal, form-epoch change and hiding, including detached
  nodes still held by page references. Rust revocation alone cannot stop already
  decoded buffers; decoder/kernel/GPU wiping remains best effort. Native tests
  check pause/reset after close and lock as well as rejected late capabilities.
- 2026-11-09: Execute independent clipboard/display step while the broader
  storage crash suite runs. T3-03 adds fixed `ClipboardReplaced` platform/core
  errors (existing CLI general code1), counting checked X11 direct/INCR text
  delivery only. Android reports observed replacement without pretending its
  API can confirm consumption. No successor selection is cleared.
- 2026-11-09: Step3 focused checks pass: model81 plus doctests, trash6
  (including identical-time independent deletes and missing legacy identity),
  incoming acceptance10 (including local resolver capacity and crash matrix).
  Full gates/review remain pending and no security assurance is inferred.
- 2026-11-09: QV-004 encoding refinement: optional UUIDv4 `DeleteOperationId`
  at entry CBOR key10 and group key6, legal only with deleted_at. Preserve it
  in text-free core projections and chosen conflict payloads; clear it on
  restore, forbid ordinary draft edits to deletion metadata. History restore
  preserves current deletion metadata. No timestamp or migration fallback.
- 2026-11-09: T3-09 interface refinement before implementation: add a model
  `Clock::check_resolution` union/writer budget check and a store manifest
  helper, enforced before candidate object insertion, mutation commit, and new
  replica build/publication. Reads/export retain existing decoding limits and
  do not apply the new admission check. Rotation keeps its actual writer.
- 2026-11-09: QV-016 focused SQLite suite passed (16 tests, one ignored child
  fixture). The initial full store suite reached 228 passing tests and ten
  expected taxonomy mismatches at injected post-COMMIT failures; assertions now
  distinguish durable/pending from pre-commit Internal errors, retaining all
  old/new-state checks. Workspace rerun pending; this is not final validation.
- 2026-11-09: Owner explicitly requests repairs, then delegates engineering
  choices to correctness and legacy handling to the agent; functional audio/video
  previews selected. Owner refines size-warning request to good on-demand UX
  with bounded/streamed memory use. Plan-before-code; existing-contract fixes
  authorized by that request. Initial tree clean except untracked review symlink,
  based on owner commit1075e39. No new-format implementation before spec text.
