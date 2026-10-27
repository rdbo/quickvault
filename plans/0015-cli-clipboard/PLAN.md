# Plan 0015 — CLI clipboard (roadmap phase 1.10c)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-27 | 2026-10-27 | 0011 §1–6; 0008 §1–3; 0010 §6; 0012 §1–3 |

## Intent

Finish the early CLI with `copy`, `totp --copy` and `generate --copy`.
Keep copied values available for a bounded foreground lifetime after dropping
the vault, and release ownership without disturbing a newer clipboard owner.

## Scope

**In scope:** Linux X11 (including an available XWayland server), text clipboard
ownership, sensitive hints, foreground timeout/countdown, signal cleanup,
protected outgoing transport buffers and isolated X-server integration tests.

**Out of scope:** native Wayland, Android/Windows/macOS clipboard backends,
clipboard history management, PRIMARY/SECONDARY selections, images/HTML,
background helpers, qv-platform extraction, and any vault/core/format change.
Native Wayland without usable X11 fails explicitly; no silent helper fallback.

## Spec basis

| Behavior | Spec | Spec status | Notes |
|----------|------|-------------|-------|
| Commands, default first secret field, addressing/output/errors | 0011 §1–2, §4–6 | Accepted | Existing core reveal and generator APIs |
| Keys gone before foreground clipboard wait; timeout and signals | 0011 §3.6 | Accepted | Default 20 s, maximum 300 s |
| Protected application buffers, reduced-protection reporting | 0008 §1 | Draft | Roadmap D5 authorization applies |
| Sensitive/no-history hints and conditional clearing | 0008 §3 | Draft | Hints cannot control clipboard recipients/managers |
| No generator history/persistence | 0010 §6 | Accepted | Copy instead of printing the generated value |
| CLI leakage, offline operation and supply chain evidence | 0012 §1–3 | Accepted | Test production binary against isolated X11 |

**Spec changes required:** None for the recommended design. This proposal does
not extend the GUI framework-copy exception to clipboard libraries.

## Decisions needed

1. **D1 — Replace arboard with a direct X11 adapter and a maintained x11rb
   transport patch.** Recommendation: approve the design below, including
   `x11rb =0.13.2` / `x11rb-protocol =0.13.2`, one vendored x11rb patch using
   the existing qv-crypto protected buffer, and the narrow third-party source
   conventions below. This adds dependency maintenance and X11 protocol
   integration work, but addresses the observed retained plaintext and
   ownership race without a memory-policy exception. Blocks all implementation.

   Alternative: request a revised plan for a narrowly scoped library-buffer
   exception in 0008 plus an ownership-safe adapter. That would require an
   explicit spec amendment and separate approval; stock arboard destruction
   still has the ownership race described below. An exception is not assumed.

   Resolution: owner approved the recommended design on 2026-10-27
   ("Whatever, go ahead"). D1 is resolved; this approval covers the replacement,
   outgoing transport patch and narrow vendor conventions. D2 below was found
   during the required deeper trace, before vendoring or product code changes.

2. **D2 — Extend the existing x11rb patch to bound incoming allocation.**
   The step-2 source trace found that x11rb passes server packet headers to
   x11rb-protocol's `PacketReader::advance`, which resizes from the advertised
   length without a budget. Separately, x11rb reads/enqueues packets until
   WouldBlock, before the adapter's planned 64-event processing limit applies.
   An outgoing-buffer patch and bounded application event batches do not bound
   these preceding allocations. This is an explicit stop condition in the
   approved plan; no product dependency/code has been added.

   **Recommendation:** approve the incoming guard described below in the same
   vendored x11rb package: at most 1 MiB per post-setup server packet, at most
   4 MiB incoming bytes over the dedicated connection's lifetime, and no received
   file descriptors. Keep fixed redacted backend error/exit 1 behavior. No new
   dependency, second vendored crate, core API, crypto or vault format change.
   Alternative: revise the backend design; do not continue with the outgoing
   patch alone. Blocks implementation of the backend and dependent commands.

   Resolution: owner approved the correction on 2026-10-27 and authorized
   necessary correctness fixes within the clipboard scope even when unforeseen
   in the plan. Record these as revisions; do not repeatedly request approval
   for implementation corrections covered by this authorization.

### Source evidence

Source-only inspection on 2026-10-27; archives downloaded from versioned
crates.io endpoints. No clipboard library was executed, installed in the
application workspace or given a secret. Paths below are upstream source paths.

- [arboard 3.6.1](https://crates.io/api/v1/crates/arboard/3.6.1/download),
  SHA-256 `0348a1c054491f4bfe6ab86a7b6ab1e44e45d899005de92f58b3df180b36ddaf`:
  `src/platform/linux/x11.rs` has ordinary `Vec<u8>` in `ClipboardData`
  (191–196), supplied from owned text by `set_text` (967–982), and discarded
  on SelectionClear without wiping. Importantly, dropping the last Clipboard
  calls `ask_clipboard_manager_to_request_our_data` (1082 onwards); that checks
  ownership (around 716) and, for excluded text, calls unconditional `clear`
  (around 748). A new owner can acquire the selection between those requests.
  Merely avoiding the public `clear()` call does not remove that destructor race.
- [x11rb 0.13.2](https://crates.io/api/v1/crates/x11rb/0.13.2/download),
  SHA-256 `9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414`:
  `src/rust_connection/write_buffer.rs` uses an ordinary 16 KiB `VecDeque`.
  Small writes copy into it; successful flush drains without wiping. Large
  direct writes can fall back to that buffer under backpressure.
- [x11rb-protocol 0.13.2](https://crates.io/api/v1/crates/x11rb-protocol/0.13.2/download),
  SHA-256 `ea6fc2961e4ef194dcbfe56bb845534d0dc8098940c7e5c012a258bfec6701bd`:
  `ChangePropertyRequest::serialize` (10283 onwards in
  `src/protocol/xproto.rs`) returns the input data Cow, alongside a separate
  header and zero padding. x11rb's generated `change_property` uses
  `Cow::Borrowed(data)` and vectored slices; that path need not allocate a
  second ordinary plaintext payload. Preserve this borrowed path.

Inspection artifacts are under `/tmp/qv15-clipboard/`; permanent provenance is
the versioned URLs and hashes above. These observations are not an audit or a
proof that other paths are free of copies. Step 2 must trace the resolved path.

## Design

**Components touched:** private qv-cli adapter; one third-party x11rb patch;
workspace dependency/policy files and documented vendor conventions. Frontend
vault access remains exclusively through qv-core. No new public core API,
platform crate, application unsafe code, crypto or storage primitive.

**Private interfaces:**

```rust
struct ClipboardOptions { timeout: std::time::Duration }
fn options(ctx: &Ctx, matches: &clap::ArgMatches)
    -> Result<ClipboardOptions, CliError>;
fn hold(value: qv_core::SecretBytes, options: ClipboardOptions)
    -> Result<(), CliError>;
// Private X11 owner implements Drop by closing its own connection.
// An explicit finish first destroys its own window, flushes, then closes.
```

`copy` resolves the existing entry address, refuses conflicting versions (8),
and chooses the first `FieldKind::Secret` field unless a name is supplied.
A supplied name must identify exactly one field: absent is 4, duplicates are 5
with escaped context. Reveal through core; validate UTF-8 without formatting or
copying to String. Non-UTF-8 is a fixed usage error (2). There is no `--reveal`
requirement: invoking copy is the explicit protected-value action. The value
bound is the model's 256 KiB field limit, checked before allocating adapter
storage. Empty text remains valid. No seed is copied by `totp --copy`.

Build a short-lived scope that returns only the copied SecretBytes (or copies
a generated value directly into a new SecretBytes). Lock and drop Session,
details, drafts, metadata, master password and generated wrappers before calling
`hold`. Thus keys and metadata are already gone when ownership is published and
the countdown begins. Test this boundary by opening/mutating the vault from a
second process while clipboard service is active. No vault write is introduced.

Timeout precedence: `copy --timeout` > config `clipboard_timeout` > 20 seconds;
all explicit/config values must be 1–300. `--copy` variants use config/default.
Validate options/config before unlock. Add `--copy` to totp/generate and
`copy <entry> [<field>] [--timeout <s>]`. Refuse `--json` with any copy mode
(2, before unlock); copy modes write no value to stdout. Human countdown and
generator entropy/strength go to stderr, without copied text. A non-TTY stderr
gets one status line rather than carriage-return countdown updates. Signals use
the existing atomic flag and cancel exit 1; normal expiry/loss of ownership is
success. Backend unavailability/I/O failures are fixed redacted exit 1 errors.

### X11 ownership and transport

Use x11rb's safe RustConnection backend only, without unsafe/XCB, images,
extra-traits, tracing or log features. Connect only to local Unix X11 sockets
from DISPLAY using the upstream display parser and Xauthority helpers; reject
TCP addresses. Establish a nonblocking Unix connection using rustix's safe net
APIs, with a five-second setup deadline. Wrap DefaultStream with a private Stream
implementation that delegates nonblocking reads/vectored writes and polls its
descriptor in at most 100 ms increments. It checks cancellation/deadlines and
returns a non-Interrupted I/O error on cancellation, as Stream requires. Normal
per-request I/O deadline: five seconds, capped by the clipboard lifetime.

Create one otherwise empty owner window, set only CLIPBOARD ownership and
confirm acquisition. Advertise TARGETS, UTF8_STRING, text/plain;charset=utf-8,
text/plain and the X11 KDE password-manager exclusion hint used by arboard
(`x-kde-passwordManagerHint`, value `secret`). Do not advertise SAVE_TARGETS;
refuse SAVE_TARGETS, MULTIPLE and unsupported conversions with property NONE.
No clipboard-manager handover or selection readback. No PRIMARY/SECONDARY use.
Return copied bytes verbatim as UTF-8, never terminal-escaped bytes.

Serve ordinary transfers within the server's maximum request length; use INCR
above that threshold. INCR sends borrowed chunks of at most 16 KiB, further
bounded by the server request limit. Track at most 16 active transfers by
requestor/property and offset, with no duplicate secret payload storage. Refuse
additional transfers, duplicate transfer keys, malformed/unsupported requests
and requestor disappearance without panicking or overwriting unrelated state.
Each transfer has a five-second idle deadline capped by the overall timeout.
Finish with the ICCCM zero-length chunk after the final deletion handshake.
Stop accepting/serving transfers on SelectionClear, cancellation or expiry.
Drain events in bounded batches (at most 64) between deadline/signal checks.

Cleanup sends DestroyWindow for this adapter's own window, never an unconditional
SetSelectionOwner(NONE). Window destruction/connection closure lets the X server
release only selections still attached to that window. A later owner is never
cleared. Use a maximum 250 ms cleanup I/O deadline; if the server stalls, close
the dedicated connection and report cleanup failure. Drop must always close that
connection even when explicit finish fails; no detached worker or process exit
is used to substitute for Rust secret cleanup. Server/manager/recipient copies
remain outside the application's erasure control and are documented.

### Protected transport patch and provenance

Retain x11rb 0.13.2 under `third-party/x11rb`, excluded from the product workspace,
with upstream copyright/license files unchanged and exact upstream archive hash
plus a local patch description in `third-party/README.md`. Pin the protocol crate
to 0.13.2 and use a local Cargo patch for x11rb; no build-time download or mutable
git dependency. No arboard dependency or arboard Windows-license exception is
needed by this design. Third-party source retains upstream licensing/lints;
new QuickVault adapter code retains workspace lints and SPDX requirements.
Amend AGENTS, relevant workflow skills and SPDX checking narrowly for this exact
vendored package; do not blanket-exclude arbitrary third-party source. Validate
package identity/provenance metadata and run its own focused tests as well.

Replace WriteBuffer's payload VecDeque with a fixed 16 KiB
`qv_crypto::SecretBytes`, logical start/length indices and borrowed slices. Add
the existing qv-crypto path dependency to this local package only. Zero consumed
bytes immediately after successful partial/full writes, preserve unwritten
bytes on WouldBlock, wipe the full allocation on error/drop, and never resize or
compact through an ordinary byte vector. Preserve direct large writes and FD
ordering with the existing Stream contract; no payload Debug output. This keeps
the existing process-wide memory-lock reporting meaningful for transport bytes.
No qv-crypto behavior/API changes are required.

Trace the complete resolved borrowed ChangeProperty → request serialization →
vectored writes → Stream path, including partial sends, errors and tracing.
Stop if this trace finds additional plaintext allocations, logging or unbounded
peer-controlled allocation that this plan does not address. Do not claim that
changing one buffer proves the entire dependency safe.

### Incoming guard (D2 approved 2026-10-27)

In the existing vendored x11rb package, extend
`src/rust_connection/packet_reader.rs` to validate the existing fixed 32-byte
packet header **before** the call to `ProtoPacketReader::advance` that can
resize. Retain header fragments in a fixed 32-byte array; use checked arithmetic
for the existing reply/GenericEvent length field. Reject a computed total over
1 MiB before forwarding the completed header to the upstream reader. Check
both partial-header and buffered multi-packet paths. The protocol crate remains
unchanged; this is a framing-budget guard, not a replacement X11 parser.

In the adapter's planned nonblocking Stream wrapper, cap total successful reads
at 4 MiB over the connection's complete lifetime, including setup. Bound each
read slice by the remaining budget; at exhaustion fail closed rather than
letting the library accumulate further packets. Setup's existing 16-bit length
is already bounded by the wire format; check any upstream setup allocation in
the continued trace. Refuse any incoming file descriptor and promptly drop the
received descriptors instead of enqueuing them. No FD-bearing extension is used
by this backend. Each connection has the existing maximum 300-second lifetime.
Together these bounds constrain a single advertised allocation and aggregate
queued traffic before application event processing. They do not rely on the
peer ever yielding WouldBlock.

Extend step 2/3 verification with fragmented headers, `u32::MAX` advertised
reply/GenericEvent lengths, fixed-size events whose unused bytes resemble a
length, exact-boundary packets, several packets in one read, an endless stream
of small events and FD-bearing input. Rejected oversized headers must leave the
protocol reader at its original small capacity without allocating the advertised
payload. Use a memory-limited subprocess for the hostile-length regression so
a broken guard cannot exhaust the test host. Assert lifetime exhaustion and
descriptor cleanup directly. Existing isolated-Xvfb small/INCR transfers must
still pass within these budgets. Stop if the resumed trace finds another
unaddressed allocation or payload-copy path.

**Dependencies:** x11rb/protocol are maintained upstream Rust X11 libraries;
0.13.2 is the source-reviewed baseline, not a claim that it is the newest release.
MIT/Apache licensing is compatible with the existing policy, subject to deny on
the resolved tree. No independent audit is claimed. Check current advisories,
maintenance and transitive releases under 0012 §3 before adding them; justify
and record each vet exemption. Alternatives: stock arboard has the two observed
problems; patched arboard adds another retained data layer; native XCB introduces
native buffering/unsafe bindings; an external clipboard command adds plaintext
IPC and process cleanup without solving those lifetimes. Do not invent X11 wire
serialization or bypass the reviewed library to avoid the patch.

## Steps

### Step 1 — Record decision and provenance conventions

- [x] **Do:** Resolve D1, record explicit approval and the dependency replacement;
  document narrow third-party licensing/lint/provenance rules and checker support.
- **Files:** this plan, roadmap, `AGENTS.md`, `.agents/README.md`, affected role
  skills, `scripts/{check-spdx,test-check-spdx}.sh`, `third-party/README.md`.
- **Done when:** owner-approved scope and exact vendor exception are reviewable;
  ordinary product code remains covered by existing header/lint checks.
- **Verify:** `sh scripts/check-spdx.sh`; checker rejection tests for missing
  product headers and an unrecognized third-party package.

### Step 2 — Protected x11rb transport and dependency review

- [x] **Do:** Retain the pinned upstream source/provenance; add the fixed protected
  buffer patch and dependency pins; trace secret-bearing paths; record deny/vet.
- **Files:** `third-party/x11rb/`, `third-party/README.md`, root and qv-cli Cargo
  manifests/lockfile, `.gitignore`, `supply-chain/config.toml`, this log.
- **Done when:** partial writes, wrap/full buffer, WouldBlock, errors, vectored
  writes and FD ordering retain exact wire bytes; consumed slots are zero before
  reuse, storage is never reallocated, Debug is redacted and drop wipes via the
  existing protected container. No ordinary payload copy on the selected path.
- **Verify:** vendored WriteBuffer tests, `cargo check --locked -p qv-cli`,
  `cargo deny check`, `cargo vet --locked`.

### Step 3 — Bounded X11 selection owner

- [x] **Do:** Implement the private owner, cancellable Stream, request handling,
  INCR, exclusion hint and ownership-safe finish/drop behavior above.
- **Files:** `crates/qv-cli/src/clipboard.rs`, private X11 submodule,
  `crates/qv-cli/src/main.rs`, tests/fixtures for the adapter.
- **Done when:** bounds and state transitions have focused tests, including
  repeated/cancelled transfers and five-second stalled-peer deadlines.
- **Verify:** `cargo test --locked -p qv-cli clipboard`.

### Step 4 — Commands and secret lifetime boundary

- [x] **Do:** Wire copy/default-field resolution, timeout config, copy variants,
  output/preflight and key/metadata destruction before foreground serving.
- **Files:** `src/cli.rs`, `src/config.rs`, `src/cmd/{mod,copy,totp,generate}.rs`
  under qv-cli, related tests.
- **Done when:** flags never accept copied secrets; conflict/duplicate/missing
  field and bad timeout/config/JSON failures are deterministic and do not publish
  a clipboard value; ordinary non-copy output remains covered by existing tests.
- **Verify:** `cargo test --locked -p qv-cli cli`; copy preflight tests.

### Step 5 — Isolated X11 production-binary evidence

- [x] **Do:** Run clipboard tests under a private Xvfb server, with independent
  requestor and successor-owner processes. Add CI provisioning for Xvfb and run
  these tests without touching the user's display/clipboard. Do not silently
  count absence of the isolated server as a passing integration test.
- **Files:** `crates/qv-cli/tests/clipboard.rs`, test helpers, offline dependency
  allowlist/test, `.github/workflows/ci.yml`.
- **Done when:** text/empty/256 KiB round-trips and INCR work; hints/no handover
  observed; expiry and all three signals release the old value; replacing the
  owner before/during cleanup preserves the successor even for identical text;
  stalled/malformed/repeated requests stay bounded; second-process vault
  unlock/edit succeeds during serving; stdout/stderr contain no copied secrets.
- **Verify:** isolated-Xvfb `cargo test --locked -p qv-cli --test clipboard`;
  `cargo test --locked -p qv-cli`, plus the offline test with namespace isolation
  when available, explicitly recording unavailable isolation.

### Step 6 — Documentation and final gates

- [x] **Do:** Document X11 support/limits and patch maintenance, update phase and
  implementation records, and leave changes uncommitted for fresh review.
- **Files:** CHANGELOG, ARCHITECTURE §3/§6, qv-cli docs, plans index/roadmap/this plan.
- **Done when:** all evidence and limitations recorded; no security/spec
  implementation claim from passing tests; plan Implemented, awaiting review.
- **Verify:** final gates below.

## Test plan

Final tree: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`,
`cargo deny check`, `cargo vet --locked`, plus vendored transport checks and
isolated-Xvfb integration. Keep complete output/exit status in temporary logs.
No crypto vectors or store crash primitive changes; read-only copy commands must
leave the vault/anchor unchanged. 0012 rows: CLI argument leakage, ambiguous
trust boundary, swap/buffer review, supply chain and offline use. No assurance
claim about OS/server/recipient/clipboard-manager copies.

## Risks and stop conditions

Stop before implementation until D1 is resolved. Stop for additional dependency,
unsafe, public core API, format or normative behavior needs; an unaddressed
plaintext intermediate; inability to preserve ownership under races; or failure
to bound I/O/transfer state. Do not treat process termination, string comparison,
wrapper wiping, GUI D8 authorization or passing tests as a substitute for the
required clipboard design. If Xvfb cannot be made available, report integration
evidence missing and do not mark this phase complete. Fresh review must inspect
the retained third-party patch as application-maintained code.

## Documentation

- [x] CHANGELOG Unreleased: CLI clipboard and X11-only limitation.
- [x] ARCHITECTURE §3/§6: private CLI adapter, patched transport dependency.
- [x] Specs: no normative amendment or status change in the recommended option.
- [x] AGENTS/role skills/navigation: narrow vendor provenance/license/lint rules.
- [x] Third-party provenance, patch maintenance and test commands.
- [x] Plan/index/roadmap status and retained evidence.

## Revisions

- 2026-10-27: D1 explicitly approved; developer began prerequisite inspection
  with the same session's uncommitted review/planning edits intact. Added D2 and
  a concrete proposed incoming guard after finding a pre-allocation budget gap
  in the plan itself. No implementation step marked complete; the new patch
  scope has not been treated as approved.

## Execution log

- 2026-10-27: Phase 1.10b passed fresh-context review (plan 0014). Architect
  prepared this proposal from the remaining phase, existing core/CLI interfaces
  and versioned dependency sources. Source inspection found that stock arboard's
  destructor also performs ownership-check-then-clear for sensitive text; merely
  dropping it does not resolve the race. Recommended a direct X11 adapter and
  one protected x11rb transport patch. D1 requires owner approval under roadmap
  Session protocol step 4 (new dependency integration and vendor conventions).
  No production code, dependency, normative spec or phase checkbox changed;
  no shared clipboard, phone, commit, push, staging or branch action performed.

- 2026-10-27: Owner approved D1/design and implementation. Status Approved then
  In progress for prerequisite inspection. Checked the tree: all uncommitted
  changes are this session's preceding review/plan records, with no unrelated
  owner source changes. Read the developer workflow and active plan fully.
- 2026-10-27: Step-2 prerequisite trace found D2 before vendoring, dependency
  resolution or code edits. In upstream x11rb 0.13.2,
  `src/rust_connection/packet_reader.rs:63–117` feeds header bytes to
  `ProtoPacketReader::advance`; `src/rust_connection/mod.rs:502–520` reads and
  enqueues until WouldBlock. Upstream x11rb-protocol 0.13.2
  `src/packet_reader.rs:86–95` resizes to `32 + extra_length`, and
  `extra_length` at 110–125 accepts the server's 32-bit length in units of four
  bytes. On this 64-bit target an advertised maximum is approximately 16 GiB.
  No hostile allocation was executed. Source artifacts were extracted from the
  already hashed versioned archives under /tmp/qv15-clipboard; no license or
  barred repository directory was read. Under this plan's explicit stop condition
  and the developer skill, status Blocked pending D2. Proposed fix is specified
  above; no clipboard access, phone action, product dependency/code/spec change, commit,
  push or branch occurred. The plan author's missing input bound is acknowledged.

- 2026-10-27: Completed the independent, D1-approved step-1 vendor conventions
  while D2 remained pending: AGENTS, role skills/navigation, third-party
  provenance/maintenance instructions and narrowly scoped SPDX checker support.
  `sh scripts/test-check-spdx.sh` passes with temporary fixtures covering missing
  product headers, unknown vendor packages, missing/wrong provenance and package
  identity/version, including a misleading dependency version. No upstream
  source is retained yet; no product dependency or Rust code has changed.
  D2 still blocks steps 2–6.
- 2026-10-27: Step 1 complete. `sh scripts/test-check-spdx.sh`,
  `sh scripts/check-spdx.sh`, `sh -n scripts/check-spdx.sh scripts/test-check-spdx.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked` (467 passed, 2 ignored) and `git diff --check` pass.
  Logs `/tmp/qv15-approved-{spdx,fmt,clippy,test}.log` and
  `/tmp/qv15-checker-test.log`. SPDX/fmt/checker tests were rerun after the final
  checker edit; Rust/build inputs were unchanged during these shell/doc edits.
  No dependency change, so no new deny/vet run required for this partial step.
  Status remains Blocked pending D2; steps 2–6 are incomplete and no clipboard
  implementation or security claim is made. Owner question is pending.

- 2026-10-27: Owner authorized doing the correct thing within this task even
  when unforeseen in the plan. D2 approved; resuming implementation. Necessary
  bounds/error-path corrections within the clipboard scope use this continuing
  authorization and are recorded as revisions. Existing no-commit and normative
  spec constraints remain. The preceding uncommitted work is this session’s.

- 2026-10-27: Steps 2–5 implemented under D1/D2 and the owner's continuing
  correctness authorization. Retained the hashed upstream x11rb package; only
  Cargo.toml, packet_reader.rs and write_buffer.rs differ from upstream source
  (excluding the separately maintained test lockfile and provenance metadata).
  Source comparison explicitly excluded license files from reading; they were
  retained unchanged by extraction. The fixed protected ring wipes consumed
  slots/fatal errors, preserves backpressure/FD order and never reallocates.
  The fixed header guard validates lengths before resize. The adapter enforces
  the independent 4 MiB lifetime read budget, drops received FDs, restricts
  connections to local Unix sockets and bounds setup/operation/cleanup I/O.
- 2026-10-27: Payload trace: generated ChangeProperty borrows the protected
  slice into Cow; protocol serialization retains that borrowed payload alongside
  separately allocated public headers/padding; write_all_vectored adjusts slice
  metadata; the maintained ring is the only library-owned payload copy on this
  path. DefaultStream delegates borrowed iovecs to rustix sendmsg, with no
  payload serialization vector in the Stream. No tracing/extra-traits/XCB or
  unsafe feature is enabled. This trace is not an independent audit.
- 2026-10-27: Necessary implementation corrections recorded: missing Xauthority
  is treated as absence of credentials (the X server still decides access);
  other lookup errors fail closed. Obtain server acquisition time and reject
  stale/synthetic requests and synthetic ownership notifications. Surface memory
  lock reduction before publication, not only at command exit; restore a clean
  terminal status line after completion. Ignore only the vendored test output
  directory in .gitignore. These changes stay within the authorized correctness
  scope and add no core API, vault format, dependency or normative spec change.
- 2026-10-27: Dependency review: root lock adds gethostname 1.1.0 and
  x11rb-protocol 0.13.2 plus the local x11rb package; Unix gethostname uses the
  existing rustix uname and handles no vault plaintext. Two versioned vet
  exemptions added and formatted (not audits). Deny passes unchanged policy;
  vet succeeds with 27 fully audited, 6 partially audited, 79 exempted.
  No arboard, Windows clipboard dependency or license exception was added.
  Local x11rb is application-maintained source, not covered by registry vet.
- 2026-10-27: Focused evidence: 12 maintained transport tests pass, including a
  memory-limited subprocess rejecting u32::MAX before allocation, fragmented
  headers, exact bound, ring wrap/wiping, partial/vectored writes, WouldBlock
  and FD ordering. Four adapter unit tests pass (lifetime budget, deadline,
  FD rejection/drop, bounds/UTF-8 before backend). Three production-binary
  clipboard tests pass against private Xvfb: normal/empty/256 KiB INCR text,
  sensitive hint/no SAVE_TARGETS, timeout and all signals, successor ownership
  including identical bytes and near expiry, vault reopen/edit while serving,
  preflight/refusals with preserved sequence, 16-transfer cap, duplicate keys,
  disappearing requestors, synthetic events and idle transfer expiry. Neither
  the user's DISPLAY nor clipboard was accessed. Initial missing-Xauthority
  failure and an invocation without fixture PATH were corrected, not skipped.
- 2026-10-27: CI provisions isolated Xvfb, runs checker rejection tests and the
  locked maintained transport suite, then the normal workspace gates. Here Xvfb
  and its runtime packages were downloaded/extracted under /tmp as an unprivileged
  test fixture; no system install or security-setting change. Host env for tests:
  QV_TEST_XVFB=/tmp/qv15-xvfb-root/usr/bin/Xvfb and matching LD_LIBRARY_PATH.
  Logs /tmp/qv15-{vendor-test,clipboard-unit,clipboard-test,deps-deny,deps-vet}.log.
  Final workspace gates follow; no phase completion is claimed before them.

- 2026-10-27: Step 6 complete. All final root gates pass on finished code/build
  inputs: `sh scripts/check-spdx.sh`, `sh scripts/test-check-spdx.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked` (474 passed, 0 failed, 2 ignored, including doctests),
  `cargo deny --locked --config /tmp/qv15-deny.toml check` and
  `cargo vet --locked`. The temporary deny policy changes only advisory db-path;
  vet uses XDG_CACHE_HOME=/tmp/qv15-cache. CI-pinned deny/vet are installed under
  /tmp/qv-next-tools. Logs /tmp/qv15-final-{spdx,checker,fmt,clippy,test,deny,vet}.log.
  Maintained-source rustfmt and 12 locked transport tests also pass, logs
  /tmp/qv15-final-vendor-{fmt,test}.log. Final log/status edits are Markdown only;
  all code/build/dependency/policy inputs remain unchanged after these checks.
  `git diff --check` passes. No test assertion or policy was weakened.
- 2026-10-27: Network isolation remains unavailable: explicit final probe
  `unshare -rn true` exits 1 with "No space left on device"
  (/tmp/qv15-network-isolation.log). The offline production flow passes without
  an account/server, but the namespace-blocked scenario is recorded as skipped,
  not a pass, regardless of the test runner's successful early return.
- 2026-10-27: Plan Implemented, roadmap 1.10c completed. No spec status promoted,
  no core/crypto/model/store API or vault-format change, no unsafe application
  code or secret-taking argument added. No real clipboard/phone operation,
  commit, staging, push or branch. Next fresh session must review this code and
  the maintained transport patch before the next phase. Passing gates and this
  source trace do not establish security.

Found, not fixed: native Wayland and other OS backends remain outside this
approved scope; clipboard managers/recipients can retain copies despite hints.
The isolated Xvfb evidence does not replace later actual-platform clipboard and
OS configuration validation. Network isolation was unavailable as recorded.
