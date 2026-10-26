# Plan 0002 — Development roadmap

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Approved | 2026-10-25 | 2026-10-25 | All (0001–0012); delivery order from `ARCHITECTURE.md` §7 |

## Intent

Start building QuickVault. Split the work from an empty repository to the
delivery milestones in `ARCHITECTURE.md` §7 into ordered phases. Each phase runs
in its own new session and the roadmap is completed phase by phase.

## Scope

**In scope:**
- The ordered phase list, each phase's goal, spec basis, dependencies,
  deliverables and exit criteria.
- The per-phase session protocol (how a session picks up, executes and hands off).
- Owner decisions that block specific phases.

**Out of scope:**
- Detailed designs, interfaces, dependency choices and step lists. Each phase
  gets its own plan (`plans/NNNN-…`), written by `quickvault-architect` at the
  start of that phase's session, with the context of everything already built.
- The "Later" row of `ARCHITECTURE.md` §7 (automatic sync, third-party
  import/export, hosted admission, iOS/macOS, extensions, BSD). Each needs its
  own spec first.

## Naming

**Milestone N** is delivery phase N of `ARCHITECTURE.md` §7. **Phase N.M**
is one unit of work in this roadmap, sized for one session. Phase 1.3 is the
third phase of milestone 1. The two numbering schemes never mix: "phase 1" in
the specs (e.g. 0011 §4 phase markers) always means milestone 1.

## Session protocol

Each phase runs in a **fresh session** started with **"next phase"**. The
session then works without further prompting:

0. **Check the tree.** If `git status` shows uncommitted work from the previous
   phase, stop and ask the owner to commit it first, so each phase stays a
   separate commit. Sessions never commit, push or branch; the owner does.
1. **Find the phase:** the first unticked phase below whose *Depends on* items
   are done.
2. **Review the previous phase** (`quickvault-reviewer`) unless its plan is
   already `Reviewed`. A fresh context makes the review independent. If the
   review escalates problems, stop and report them.
3. **Plan this phase** (`quickvault-architect`): read the phase entry, the cited
   spec sections and the existing code, and write `plans/NNNN-slug/PLAN.md`.
4. **Standing approval.** The plan is approved without asking the owner
   (status `Approved`, logged as "standing approval, roadmap 0002") unless it:
   - has an unresolved item under *Decisions needed* (a roadmap D-item or a new one);
   - amends a spec;
   - adds a dependency not in this roadmap's candidate table, or uses `unsafe`;
   - deviates from this roadmap's phase entry (scope, crates, order).
   In those cases, stop with a summary and wait for the owner.
5. **Implement** (`quickvault-developer`) until the plan is `Implemented` and
   all gates are green. The developer's stop conditions still apply.
6. **Update this roadmap:** tick the phase, fill in its plan number and append
   an *Execution log* entry. End with a short summary for the owner: what was
   built, gate results and anything deferred. Leave all changes uncommitted.

If a phase is too large for one session, the architect splits it into
N.Ma/N.Mb (as a dated *Revisions* entry here) instead of cramming it in. A
phase with a blocking decision does not start until the owner resolves it.
Phases inside a milestone run in the listed order unless an entry says
otherwise. *Depends on* names the hard prerequisites.

**Standard gates** (every code phase, from 1.1 on):
`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
`cargo test --locked`, and `cargo deny check` + `cargo vet` whenever
dependencies change (0012 §3). "Verify" entries below list only what is added
on top of these.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Threat model, security goals | 0001 | Accepted | Constrains every phase |
| Profiles, key hierarchy, recovery, rotation | 0002 §1–4, §7–8 | Accepted | Milestone 1 |
| Quick unlock / platform wrap | 0002 §5 | Accepted | Phase 2.6; gated per platform |
| Hybrid KEM / signatures, TLS | 0002 §6 | Accepted | Milestones 2 (if the LAN design uses them) and 3 |
| Data model | 0003 | Accepted | Phase 1.5 on |
| Local storage, archives | 0004 | Accepted | Phases 1.6–1.7, 1.13 |
| Offline model, versions, merge, local head/anchor | 0005 §0–2, §5.1, §5.4 | **Draft** | Needed in milestone 1 → D5 |
| File exchange | 0005 §4 | **Draft** | Phase 2.2 → D5 |
| Remote sync, checkpoints | 0005 §3, §5.2–5.6 | **Draft** | Milestone 3 |
| LAN sync | 0005 §6 | **Draft**, not implementable (§6.7) | Phase 2.1 writes the protocol spec |
| Server accounts, enrollment | 0006 | **Draft** | Milestone 3; phase 3.1 finalizes |
| History, trash, snapshots, server retention | 0007 | Accepted (§3 has OQ1) | Phases 1.8, 1.12, 1.13, 3.5 |
| Memory hygiene, side channels, webview | 0008 | **Draft** | §1–3, §5 needed from 1.1 → D5; §4 from 2.4 |
| Clients and platforms | 0009 | **Draft** | §3, §6 in milestone 1 → D5; §1, §4–5 in milestone 2 |
| Password generator | 0010 | Accepted | Phase 1.4 |
| CLI | 0011 | Accepted | Phases 1.10 on |
| Validation matrix, release gates | 0012 | Accepted | Exit criteria of every phase; 1.16, 2.11, 3.9 |

**Spec changes required:** phase 2.1 (LAN protocol amendment to 0005 §6 or a
new spec), phase 3.1 (0006 finalization). D4, D6 and D9 each need a small
amendment once decided. No change is made by this roadmap itself.

## Decisions needed

The owner can answer D1–D6 now, when approving this roadmap. The others come up
at the phase that needs them.

1. **D1 — Toolchain and MSRV** (open per `AGENTS.md`). Options: pin an exact
   stable version in `rust-toolchain.toml` and treat it as the MSRV / float on
   latest stable. Recommendation: pin `1.98.1` (installed here) and bump it
   deliberately in its own commit. Reproducible builds (0012 §3) need a pinned
   toolchain anyway. Blocks: 1.1. Resolution: owner accepted the recommendation on 2026-10-25 (pin 1.98.1 = MSRV).
2. **D2 — CI provider** (open per `AGENTS.md`). The remote is
   `github.com/rdbo/quickvault`. Recommendation: GitHub Actions running the
   standard gates plus `cargo deny`/`cargo vet` on every push and PR, with
   actions pinned by commit SHA. Blocks: 1.1. Resolution: owner accepted the recommendation on 2026-10-25 (GitHub Actions).
3. **D3 — SPDX headers** (open per `AGENTS.md`). Recommendation: yes,
   `// SPDX-License-Identifier: AGPL-3.0-or-later` on every source file,
   checked in CI. It is cheap now and painful to retrofit. Blocks: 1.1.
   Resolution: owner accepted the recommendation on 2026-10-25 (SPDX headers, CI-checked).
4. **D4 — Workspace layout and the canonical-CBOR crate** (open per
   `AGENTS.md`). Recommendation: a virtual workspace with crates under
   `crates/<name>/`, plus a small bottom-level crate `qv-encoding` for bounded
   deterministic CBOR. Both qv-crypto (AAD, HKDF info, transcripts) and
   qv-model need the codec, and crypto must not depend on model. This adds a
   row to `ARCHITECTURE.md` §3. Alternative: put the codec inside qv-crypto
   (no new component, but it mixes concerns). Blocks: 1.1 (layout), 1.2
   (crate). Resolution: owner accepted the recommendation on 2026-10-25 (`crates/<name>/`, `qv-encoding`).
5. **D5 — Go-ahead to implement Draft sections in milestone 1.** Milestone 1
   cannot work without 0005 §0–2 (causal versions and merge), §5.1 and §5.4
   (manifest completeness, local head and anchor), 0008 §1–3 and §5 (memory and
   OS leaks), and 0009 §3 and §6 (CLI unlocking, feasibility spike). These
   sections are stable and the Accepted specs already depend on them.
   Recommendation: grant the go-ahead for exactly these sections and record it
   here. Optionally, also have a short spec phase promote them to Accepted by
   splitting 0005/0008. 0005 §4 (file exchange) needs the same go-ahead by
   phase 2.2. Blocks: 1.1 (0008), 1.5 on. Resolution: owner granted the go-ahead on 2026-10-25 for exactly the listed milestone-1 sections and for 0005 §4 in phase 2.2.
6. **D6 — 0007 OQ1: password slot in local snapshots.** Recommendation (from
   the spec): no slot by default, and offer to delete pre-change snapshots on
   password change. Blocks: 1.13. Resolution: owner accepted the recommendation on 2026-10-25 (no slot by default; offer to delete pre-change snapshots). The 0007 amendment remains the first step of phase 1.13.
7. **D7 — Android benchmark targets and hardware.** 0002 §1.3 and 0004 OQ1
   need named "mid-range" and "low-end" Android devices, plus a physical device
   and the Android SDK/NDK available to sessions. Recommendation: name two
   devices you own or can borrow, and record them in 0009. Blocks: 1.9, 1.16
   (format freeze). Resolution: pending.
8. **D8 — 0008 OQ2 / 0009 OQ3: webview (Dioxus) or native Rust renderer.**
   Phase 1.9 produces the evidence. Recommendation: none yet; decide on the
   spike report. Blocks: 2.4. Resolution: pending.
9. **D9 — Attachments in the CLI.** 0011 §4 lists no attachment commands, but
   0003 §6 makes attachments a v1 model feature, and the manifest format must
   include chunk lists before the format freeze. Options: (A) amend 0011 with
   `qvault attach add|ls|save|rm` in phase 1.11; (B) attachments in core only,
   UI in milestone 2. Recommendation: A, because otherwise the attachment path
   ships to the format freeze untested end to end. Blocks: CLI part of 1.11.
   Resolution: owner accepted option A on 2026-10-25. The 0011 amendment is the first step of phase 1.11.
10. **D10 — 0005 OQ3–OQ6: LAN discovery, trust/session protocol, listening,
    peer removal.** Worked through in phase 2.1 with `quickvault-thinker`.
    Blocks: 2.8–2.10. Resolution: pending.
11. **D11 — 0006 OQ2: per-device signing identities.** Settled in phase 3.1.
    Blocks: 3.2 on. Resolution: pending.
12. **D12 — Independent protocol review.** 0012 §3 requires an external review
    of the LAN and server key-transfer/session compositions before release.
    The owner must choose and engage a reviewer. Lead time is long, so start
    when 2.1 / 3.1 produce a spec. Blocks: 2.11, 3.9 (release only, not
    implementation). Resolution: pending.

## Design

**Components touched:** all of `ARCHITECTURE.md` §3, created as follows. A
crate is created only in the phase that first needs its interface.

| Crate | Created in | Trust boundary |
|-------|-----------|----------------|
| qv-crypto | 1.1 | Trusted client; no frontend deps |
| qv-encoding (per D4) | 1.2 | Hostile-input parser; no deps on other qv crates |
| qv-model | 1.5 | Trusted; no frontend deps |
| qv-store | 1.6 | Trusted; parses hostile SQLite/archives only after hardening and authentication |
| qv-core | 1.8 | Single entry point for every frontend |
| qv-cli | 1.10 (first used in 1.9 only if needed) | Frontend |
| qv-app | 1.9 (spike), 2.4 (real) | Frontend; webview is part of the trusted client (0008 §4) |
| qv-platform | 1.9 (spike), 2.3 (real) | Trusted OS adapters |
| qv-sync | 2.2 | Trusted; consumes hostile peer/server input |
| qv-protocol | 2.8 | Bounded wire types; shared with server |
| qv-server | 3.3 | Untrusted from the client's view; never holds keys |

**Interfaces:** defined per phase plan. Cross-phase invariants that every
phase plan must keep:

- Frontends reach vaults only through `qv-core` (0009 §1.1). No frontend calls
  qv-crypto/qv-store directly, even in the 1.9 spike.
- Secrets live only in zeroizing, non-`Debug` types from qv-crypto's memory
  module (1.1). Nothing secret goes into logs, errors, panics or argv.
- Every parser of untrusted bytes checks bounds before allocating, and
  authenticates before parsing where a key is available (0004 §4, §6).
- **The on-disk format is unstable until 1.16.** Until then the format version
  is a development value, files carry no compatibility promise, and no phase
  publishes vectors as final.

**Data and control flow:** the durability ordering (DB commit → anchor →
report, 0004 §5.2 and 0005 §5.4) is designed once in 1.7. Later write paths
(history, snapshots, rotation, sync) reuse that path, and their phase plans
must not invent a second one.

**Secrets and hostile input:** see the invariants above. Fuzz targets are added
by the phase that introduces each parser (1.2 CBOR, 1.6 SQLite schema
validation, 1.13 archives, 2.9–2.10 LAN messages, 3.x server messages) and run
in CI. 1.16, 2.11 and 3.9 then run extended campaigns.

**Errors:** a redacted error taxonomy is set up in 1.3 and 1.6. It must cover
the "wrong password" vs "integrity error" split (0002 §8) and map 1:1 onto CLI
exit codes 3/7/8/9 (0011 §6).

**Dependencies:** chosen and justified per phase plan. Candidates for the phase
architect to evaluate, not decisions:

| Need | Candidates (to evaluate) | Phase |
|------|--------------------------|-------|
| Zeroize, constant time | `zeroize`, `subtle`; memory locking via `memsec`/`region` or a minimal audited `libc` wrapper | 1.1 |
| CBOR | own strict codec in `qv-encoding` (CBOR is not a crypto primitive) vs `minicbor` with a canonical-check layer | 1.2 |
| AEAD/KDF/MAC/hash | RustCrypto `chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2` | 1.3 |
| RNG | `getrandom` (fail closed) | 1.1 |
| Unicode NFC | `unicode-normalization` | 1.3 |
| SQLite | `rusqlite` with `bundled` (pins the SQLite version and compile options) | 1.6 |
| TOTP | `hmac` + `sha1` (RFC 6238 is a construction, not a new primitive) | 1.5 |
| CLI / TTY / clipboard | `clap`, `rpassword` or `rustix` termios, `arboard` (check the X11/Wayland sensitive hints) | 1.10 |
| Property / fuzz testing | `proptest`, `cargo-fuzz` | 1.2, 1.5 |
| UI | Dioxus 0.7 (per D8) | 1.9 |
| Signatures / KEM | `ed25519-dalek` (strict), RustCrypto `ml-dsa`, X-Wing draft-11 from `libcrux`/`x-wing`; record audit status (likely none for ML-DSA/X-Wing) | 2.8 / 3.x |
| Server / TLS / OPAQUE | `axum`, `tokio`, `rustls` + `aws-lc-rs` (X25519MLKEM768), `opaque-ke` | 3.3–3.4 |

## Steps

Each step is one phase. **Files** names the main paths. The phase plan lists
exact files.

### Milestone 1 — Offline core, early Linux CLI, Android/Linux feasibility

#### Phase 1.1 — Workspace bootstrap and protected memory

- [x] **Plan:** [0003](../0003-workspace-bootstrap/PLAN.md). **Do:** Create the virtual workspace,
  `rust-toolchain.toml`, workspace lints (`unsafe_code = "forbid"` by default,
  `clippy::unwrap_used`/`expect_used` denied outside tests), `deny.toml`,
  `cargo vet init`, the CI workflow and SPDX checks. Create `qv-crypto` with its
  first real interface: the protected-memory module (zeroizing secret buffers,
  redacted `Debug`, memory locking that reports reduced protection instead of
  failing silently, core-dump disabling hook) and a fail-closed OS RNG wrapper.
- **Specs:** 0008 §1 (D5), 0002 §7.1, 0012 §3.
- **Depends on:** D1–D5.
- **Files:** `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `supply-chain/`, CI config, `crates/qv-crypto/`, `AGENTS.md`.
- **Done when:** the CI workflow's commands pass locally (the first hosted run
  is confirmed after the owner pushes). Secret types cannot be printed or cloned
  implicitly (compile-fail tests). A lock failure surfaces as a reduced-protection status.
- **Verify:** standard gates; `cargo deny check`; `cargo vet`; the CI workflow's commands run locally.

#### Phase 1.2 — Bounded deterministic CBOR

- [x] **Plan:** [0004](../0004-canonical-cbor/PLAN.md). **Do:** Write the strict RFC 8949 deterministic codec: shortest-form
  integers, definite lengths, sorted integer map keys, no floats/tags/duplicates,
  valid UTF-8, nesting ≤ 32, length checks before allocation, and noncanonical
  input rejected. Add an API for preserving unknown optional keys and a
  canonical-array builder for AAD/info/transcripts. Set up the fuzz harness.
- **Specs:** 0004 §3.1, §4.1; 0002 §7.2.
- **Depends on:** 1.1, D4.
- **Files:** `crates/qv-encoding/`, `fuzz/`.
- **Done when:** round-trip property tests pass, and every noncanonical form in
  RFC 8949 §4.2 is rejected by a test. The fuzz target runs in CI for a bounded time.
- **Verify:** `cargo test --locked -p qv-encoding`; `cargo +nightly fuzz run cbor_decode -- -max_total_time=60` (or the CI equivalent).

#### Phase 1.3 — Crypto profiles, symmetric primitives and key hierarchy

- [x] **Plan:** [0005](../0005-crypto-key-hierarchy/PLAN.md). **Do:** Build the profile registry (purpose namespaces, `u16` IDs,
  unknown IDs fail closed, explicit transition registry). Add password-kdf/1
  (Argon2id, NFC), KEK derivation, KEK commitment checked in constant time
  before AEAD, password-slot wrap/unwrap, HKDF purpose keys with every label in
  0002 §3.3, per-record and per-attachment keys, stored-data/1 XChaCha with
  Padmé framing, MAC/1, object-hash/1, and the redacted error taxonomy.
  Known-answer vectors from upstream sources, plus QuickVault's own vectors
  marked development-only.
- **Specs:** 0002 §1, §3.1–3.3, §3.6, §7; 0004 §3.2 (padding).
- **Depends on:** 1.2.
- **Files:** `crates/qv-crypto/`, `crates/qv-crypto/tests/vectors/`.
- **Done when:** KATs pass. A multi-key AEAD slot is rejected as a wrong
  password before decryption. A wrong label, profile or AAD field fails.
  An unknown profile fails before any KDF work.
- **Verify:** `cargo test --locked -p qv-crypto`.
- **0012 rows:** Unpinned crypto (symmetric part), Password-slot partitioning oracle.

#### Phase 1.4 — Recovery phrase and password generator

- [x] **Plan:** [0006](../0006-recovery-phrase-generator/PLAN.md). **Do:** Encode and decode VK as 24 BIP-39 words (entropy encoding, not
  the wallet seed; checksum). Implement the 0010 generator: unbiased selection,
  character/passphrase/PIN modes, feasibility checks and bounded retries,
  entropy/strength, warnings, the embedded EFF large word list with its build-time
  SHA-256 check, and secret handling.
- **Specs:** 0002 §4; 0010 (all).
- **Depends on:** 1.3. Independent of 1.5–1.8, so it can be reordered.
- **Files:** `crates/qv-crypto/` (phrase), generator location chosen by the phase plan (likely a `qv-crypto` module or `qv-core`).
- **Done when:** BIP-39 vectors pass. A modified word list fails the build.
  Impossible generator settings return errors. A statistical bias test passes.
- **Verify:** `cargo test --locked -p qv-crypto phrase generator`.
- **0012 rows:** Impossible generator.

#### Phase 1.5 — Data model, version vectors and merge

- [x] **Plan:** [0007](../0007-data-model-merge/PLAN.md). **Do:** Create `qv-model`: ID newtypes (random UUIDv4 only), record kinds
  and payloads (vault_meta, group, entry/fields, attachment_meta,
  password_keyslot) with the integer-key field registry, unknown-key
  preservation, version vectors with the sorted-pair wire form, dominance and
  concurrency, maximal-version merge, the conflict representative, tombstone
  semantics, deterministic group-tree projection, and TOTP code generation.
- **Specs:** 0003; 0005 §1–2 (D5); 0007 §1.2 (floors as data).
- **Depends on:** 1.2, D5.
- **Files:** `crates/qv-model/`.
- **Done when:** property tests show the merge is commutative, associative and
  idempotent under permutation, regrouping and duplicate delivery. No synthetic
  versions. Group projection does not depend on traversal order. RFC 6238 vectors pass.
- **Verify:** `cargo test --locked -p qv-model`.
- **0012 rows:** Order-dependent merges, Old-date concurrent edits, Mixed credentials (model level).

#### Phase 1.6 — Vault file: hardened SQLite, schema, header and keyslots

- [ ] **Do:** Create `qv-store`. Open a vault with every hardening setting in
  0004 §1.2, exact-schema validation, bounded `quick_check` and SQLite limits.
  Enforce file permissions and reject symlinks or replaced paths, warn about
  sync-folder locations, and take the process lock plus file-identity tracking.
  Store the header and keyslots with the header MAC. Implement vault creation
  and unlock to VK (no records yet).
- **Specs:** 0004 §1, §2, §4, §5.1 (first half); 0002 §8.
- **Depends on:** 1.3.
- **Files:** `crates/qv-store/`, `fuzz/` (malformed DB inputs).
- **Done when:** a vault with an unexpected trigger, view, schema version or
  pragma failure refuses to open. Wrong password and integrity errors are
  reported distinctly. A second process gets a lock error.
- **Verify:** `cargo test --locked -p qv-store`; schema-tamper test suite.
- **0012 rows:** Hostile SQLite/CBOR (SQLite half).

#### Phase 1.7 — Objects, manifests, local head, anchor and the write path

- [ ] **Do:** Write object envelopes (unlinkable plaintext, 0004 §2.2), record
  encryption with the canonical AAD, the manifest (heads, history, tombstones,
  floors, chunk lists, sorted references, configuration digest) with its hash
  and reference digest, the authenticated local head, the external anchor in
  private state (location decided in the phase plan), writer ID and counter
  reservation, and the single mutation transaction (0004 §5.2) with test-only
  crash injection at every ordering point. Verify on unlock per 0004 §3.6.
- **Specs:** 0004 §2–3, §5; 0005 §1.3, §5.1, §5.4 (D5).
- **Depends on:** 1.5, 1.6.
- **Files:** `crates/qv-store/`.
- **Done when:** for every crash point, reopening yields the old or the new
  state and the anchor table in 0005 §5.4 behaves as specified. Deleted or
  replaced objects, an old DB with a newer anchor, and a DB two steps ahead
  are all rejected. A generated worst-case manifest at maximum budgets fits 64 MiB.
- **Verify:** `cargo test --locked -p qv-store crash anchor manifest`.
- **0012 rows:** Whole-file rollback, Anchor crash windows, Self-referential/incomplete commitments, Budget inconsistency, Server-visible record linkage (envelope level).

#### Phase 1.8 — qv-core sessions and vault operations

- [ ] **Do:** Create `qv-core`: session lifecycle (unlock, lock, cancellation of
  in-flight work, session-scoped handles), mutation authorization, bounded
  metadata views and search over non-protected fields, on-demand decryption into
  short-lived buffers, entry/group create/edit/move/delete as causal edits, soft
  delete and trash with retention policy and final tombstones, conflict
  surfacing (read-only), and vault settings.
- **Specs:** 0008 §1, §4.1 (D5); 0007 §2; 0003 §4–5; 0005 §2.3–2.5.
- **Depends on:** 1.7.
- **Files:** `crates/qv-core/`.
- **Done when:** integration tests cover full offline create, unlock, edit,
  reopen and lock. Handles are invalid after lock. A late result cannot
  repopulate a locked session. No plaintext search index exists.
- **Verify:** `cargo test --locked -p qv-core`.
- **0012 rows:** Implicit server prerequisite (core level), Deleted-entry resurrection (trash part).

#### Phase 1.9 — Android/Linux shared-UI feasibility spike

- [ ] **Do:** Build a throwaway-quality Dioxus app on Linux and a physical
  Android device. It must show the vault list and entry editing against
  `qv-core`, offline persistence, native secure input for the master password,
  and lifecycle lock/cancellation. Probe keystore/biometric access, the
  clipboard and the autofill service entry point. Benchmark unlock time
  (including password-kdf/1) and memory on the D7 devices. Write a feasibility
  report that answers 0009 §6 and gives evidence for D8. Mark the spike code as
  non-production, or keep it out of the workspace default members.
- **Specs:** 0009 §6 (D5); 0008 OQ2; 0002 OQ1, 0004 OQ1 (benchmarks).
- **Depends on:** 1.8, D7. Independent of 1.10, so it can swap with it.
- **Files:** `spikes/ui-feasibility/` (or as the phase plan decides), `plans/NNNN-…/REPORT.md`.
- **Done when:** the report exists with measured numbers and a recommendation
  for D8. The owner has decided D8, or has asked for a follow-up spike.
- **Verify:** builds for Linux and the Android target; benchmark logs attached to the report.
- **0012 rows:** Mobile deferred behind shared-UI claims (feasibility evidence only).

#### Phase 1.10 — CLI: vault, browse, edit, clipboard, generator

- [ ] **Do:** Create `qv-cli` (`qvault`): vault selection and config, `init`
  (recovery phrase on the alternate screen, confirmation), `info`, `ls`,
  `search`, `show`, `totp`, `add`, `edit`, `mv`, `mkdir`, `rm`, `trash …`,
  `copy` (foreground countdown, sensitive clipboard hints), `generate`,
  `--password-stdin`, `--json`, output escaping, exit codes, core-dump disabling.
- **Specs:** 0011 §1–3, §4 (Vault: init/info; Browsing; Editing; Clipboard and generator), §5–6; 0009 §3.
- **Depends on:** 1.8, 1.4.
- **Files:** `crates/qv-cli/`.
- **Done when:** end-to-end tests drive the binary through a PTY. Secrets never
  appear in argv-capable options. Notes are prompted. Control and ANSI
  sequences in vault text are escaped. Every exit code has a test.
- **Verify:** `cargo test --locked -p qv-cli`.
- **0012 rows:** CLI argument leakage; Implicit server prerequisite (networking blocked).

#### Phase 1.11 — Attachments

- [ ] **Do:** Store attachments in chunks (64 KiB padded chunks, chunk AAD,
  content hash), stream them under the budgets, release chunks by reference,
  and sanitize save paths. Add CLI commands if D9 = A (with the 0011 amendment
  as the first step).
- **Specs:** 0003 §6; 0004 §3.3, §4.1.
- **Depends on:** 1.7 (1.10 for the CLI part), D9.
- **Files:** `crates/qv-store/`, `crates/qv-core/`, `crates/qv-cli/`, `specs/0011-cli.md` (if A).
- **Done when:** reordered, swapped, truncated or oversized chunks are
  rejected. A 10 MiB attachment round-trips without loading all chunks into memory.
- **Verify:** `cargo test --locked -p qv-store attachment`.

#### Phase 1.12 — Entry history, restore and purge

- [ ] **Do:** Implement history retention (N = 10 under budgets), history
  floors with componentwise merge and suppression, explicit purge, and restore
  as a new causal edit. Add the CLI commands `history`, `history show`,
  `restore` and `history purge`.
- **Specs:** 0007 §1; 0011 §4 (History).
- **Depends on:** 1.10.
- **Files:** `crates/qv-model/`, `crates/qv-store/`, `crates/qv-core/`, `crates/qv-cli/`.
- **Done when:** suppressed history cannot be reintroduced. Purge never
  resolves a conflict or drops active heads or tombstones.
- **Verify:** `cargo test --locked -p qv-core history`.
- **0012 rows:** Rotation/purge ambiguity (local part).

#### Phase 1.13 — Archives, local snapshots and `verify`

- [ ] **Do:** Write the archive writer (verified objects only, temp file →
  re-read and verify → fsync → publish under a unique name) and the reader
  (fixed prefix and bounded header → VK → header MAC → manifest hash → frames
  checked in reference order before AEAD). Add snapshot scheduling (hourly,
  first unlock of the day, mandatory pre-operation recovery snapshots), the
  count/byte budgets with pruning, restore into a new path, and the `snapshot
  ls/restore` and `verify` commands. Slot policy per D6, with the 0007 amendment
  as the first step.
- **Specs:** 0004 §6, §3.6; 0007 §3; 0011 §4 (`snapshot`, `verify`).
- **Depends on:** 1.12, D6.
- **Files:** `crates/qv-store/`, `crates/qv-core/`, `crates/qv-cli/`, `fuzz/` (archive reader), `specs/0007-history-and-backups.md`.
- **Done when:** fuzzed prefixes, headers and frame lengths never reach the
  SQLite parser or an unbounded allocation. Truncated, reordered, extra and
  substituted frames are rejected. Archiving during a concurrent writer is
  safe. A full disk aborts the destructive operation.
- **Verify:** `cargo test --locked -p qv-store archive`; archive fuzz target.
- **0012 rows:** Live SQLite copying, Hostile files from sync folders, Exchange-file password guessing, Snapshot disk growth.

#### Phase 1.14 — Password change and recovery flows

- [ ] **Do:** Implement `passwd` (new complete slot plus encrypted keyslot
  record, atomic, weak-password flow per 0011 §5.4), `recovery show` (after
  re-authentication, TTY only, alternate screen) and `recover <path>` (unlock
  with the phrase, set a new password). Handle the KDF-only profile migration
  path (0002 §2.1).
- **Specs:** 0002 §2.1, §3.4, §4; 0011 §4 (Vault), §5.4.
- **Depends on:** 1.13.
- **Files:** `crates/qv-core/`, `crates/qv-cli/`.
- **Done when:** the old password fails and the new one works after a crash at
  any point. A KDF-only upgrade leaves the data objects unchanged.
- **Verify:** `cargo test --locked -p qv-core passwd recover`.
- **0012 rows:** Migration coupling (KDF part).

#### Phase 1.15 — Offline VK rotation

- [ ] **Do:** Implement `recovery rotate` for vaults without remote sync: freeze
  writes, take a recovery snapshot, build the private replacement DB, reencrypt
  with logical IDs and clocks preserved, confirm the new phrase and password,
  write the recovery journal, install with the generation step in the anchor,
  retain the old DB until confirmed, resume or roll back on restart, and
  invalidate quick slots. Out of scope: the server step (3.8) and LAN peer
  re-approval (2.9).
- **Specs:** 0002 §2.2, §3.5 (offline path); 0005 §5.4; 0011 §4 `recovery rotate`.
- **Depends on:** 1.14.
- **Files:** `crates/qv-store/`, `crates/qv-core/`, `crates/qv-cli/`.
- **Done when:** a crash injected at every journal step resumes or rolls back
  correctly. Old-generation archives do not merge automatically.
- **Verify:** `cargo test --locked -p qv-core rotate`.
- **0012 rows:** Rotation/purge ambiguity (interrupted rotation), Migration coupling (data part).

#### Phase 1.16 — Offline hardening, benchmarks and format freeze

- [ ] **Do:** Run the offline release gate (0012 §3). Extended fuzz campaigns
  (CBOR, SQLite, archive). KDF and budget benchmarks on the D7 devices, with the
  profile and budgets adjusted *before* the freeze if needed. Freeze the
  physical DDL, CBOR field registry, profile IDs/parameters and archive format,
  and publish the golden vectors, including the worst-case manifest. Audit
  permissions, disk-full behaviour and redacted errors. Record the dependency
  audit status. Set the specs that are fully implemented to `Implemented`.
- **Specs:** 0012 §1 (offline rows), §3 (offline gate); 0002 OQ1; 0004 OQ1.
- **Depends on:** 1.9 (Android numbers), 1.15.
- **Files:** `tests/vectors/`, specs (status and benchmark results), `CHANGELOG.md`.
- **Done when:** every offline row of the 0012 matrix has a passing test that
  names it. The format version is final. The benchmark report is committed.
- **Verify:** full test suite; fuzz campaign logs; `cargo deny check`; `cargo vet`.

### Milestone 2 — Offline Android and Linux apps, LAN sync, conflicts, archive exchange

#### Phase 2.1 — LAN sync protocol design (spec only)

- [ ] **Do:** With `quickvault-thinker`, settle 0005 OQ3–OQ6 (D10). Then write
  the LAN protocol spec: discovery/addressing, out-of-band enrollment, peer
  identity, session protection, bounded messages, peer-state schema,
  initialization, removal, generation transitions and error transitions. Give
  it its own spec number or a 0005 §6 amendment, at status `Draft` → `Accepted`
  by the owner. Send it to the D12 reviewer.
- **Specs:** 0005 §6, OQ3–6; 0002 §3.5, §6; 0012 §3 (LAN gate).
- **Depends on:** milestone 1 complete (it can start in parallel with 2.2–2.7).
- **Files:** `specs/`, `ARCHITECTURE.md` §3/§6, `specs/README.md`.
- **Done when:** the spec is `Accepted` and lists byte-level messages. The review request has been sent.
- **Verify:** spec review by `quickvault-reviewer`.

#### Phase 2.2 — Conflict resolution and archive exchange

- [ ] **Do:** Create `qv-sync` with the shared merge of incoming manifests and
  objects into a local candidate, committed through the 1.7 write path. Add the
  commands `conflicts`, `resolve`, `merge <archive>` (private copy, same vault
  and generation, authenticate, merge) and `snapshot export [--self-contained]`.
- **Specs:** 0005 §2.3–2.4, §4 (D5); 0004 §6.4; 0011 §4 (phase-2 rows).
- **Depends on:** 1.16.
- **Files:** `crates/qv-sync/`, `crates/qv-core/`, `crates/qv-cli/`.
- **Done when:** merging a years-old archive revives no tombstone or suppressed
  history. A concurrent delete and edit stays a conflict. A reused filename
  with different bytes is an error.
- **Verify:** `cargo test --locked -p qv-sync`.
- **0012 rows:** Deleted-entry resurrection, Order-dependent merges (storage level), Hostile files from sync folders (merge path).

#### Phase 2.3 — Platform adapters: traits and Linux

- [ ] **Do:** Create `qv-platform`: traits injected into core (secure input,
  clipboard, lifecycle/lock signals, keystore, protection-status reporting).
  Linux implementations: logind/D-Bus lock and sleep, clipboard ownership,
  single instance, and swap/hibernation configuration detection. Quick unlock
  stays disabled on Linux unless a backend meets 0002 §5.2.
- **Specs:** 0009 §1.6, §5; 0008 §1.3–1.4, §3.
- **Depends on:** 2.2, D8.
- **Files:** `crates/qv-platform/`, `crates/qv-core/`.
- **Done when:** a screen lock locks the session in an integration test (or a
  documented manual test). The reduced-protection mode is reported.
- **Verify:** `cargo test --locked -p qv-platform`.

#### Phase 2.4 — App foundation and security boundary

- [ ] **Do:** Build the production `qv-app` skeleton on the framework chosen in
  D8. If it is a webview: local assets, CSP, navigation/frame/popup blocking,
  and a typed allowlisted bridge checked in Rust. Add native secure input for
  master password, phrase and protected values on Linux and Android. Flows:
  create (with recovery phrase), unlock, lock, recover. Android adapters:
  lifecycle, FLAG_SECURE, keyboard flags.
- **Specs:** 0008 §4; 0009 §1.6; 0002 §4.2.
- **Depends on:** 2.3, D8.
- **Files:** `crates/qv-app/`, `crates/qv-platform/`, Android packaging.
- **Done when:** injection tests (HTML, URL, IPC) fail safely, remote
  navigation is blocked, and secret text never crosses the bridge.
- **Verify:** `cargo test --locked -p qv-app`; Android instrumented test run recorded.
- **0012 rows:** Webview exposure, Ambiguous trust boundary.

#### Phase 2.5 — App vault workflows

- [ ] **Do:** Shared screens for browsing/search, entry view and edit (reveal
  that expires after 30 s, copy straight from Rust to the OS), generator,
  trash, history, conflicts, snapshots, archive import/export and settings.
  Responsive layouts for touch and desktop. Lock-time race handling.
- **Specs:** 0009 §1; 0008 §3–4; 0007; 0010.
- **Depends on:** 2.4. May split into 2.5a/2.5b.
- **Files:** `crates/qv-app/`.
- **Done when:** the CLI's offline feature set is reachable on both platforms
  from one codebase.
- **Verify:** app test suite; manual test checklist on both platforms in the log.

#### Phase 2.6 — Android quick unlock (gated)

- [ ] **Do:** Implement the Android keystore backend: a nonexportable AES-GCM
  key with per-operation auth, Class 3 biometrics only, invalidation on new
  biometric enrollment, StrongBox preferred, AAD binding, the policy state of
  0002 §5.4, and the device-credential variant labelled reduced protection.
  Disabled unless the device validates.
- **Specs:** 0002 §5.
- **Depends on:** 2.4.
- **Files:** `crates/qv-platform/` (android), `crates/qv-core/`.
- **Done when:** enrolling a new fingerprint invalidates quick unlock. Reboot,
  expiry and three failures require the password. No silent fallback.
- **Verify:** real-device test log.
- **0012 rows:** Biometric enrollment bypass, Hardware assumptions.

#### Phase 2.7 — Android autofill (gated)

- [ ] **Do:** Write the thin Kotlin/JNI `AutofillService` entry point with the
  logic in Rust: verified app signature and web origin (Digital Asset Links),
  conflicted credentials require a choice, handoff to the main app for unlock,
  and an authenticated, scoped IPC channel.
- **Specs:** 0009 §4; 0008 §3.
- **Depends on:** 2.6.
- **Files:** `crates/qv-platform/`, Android packaging.
- **Done when:** label, substring and custom-scheme spoofing tests do not fill.
- **Verify:** real-device test log.

#### Phase 2.8 — Protocol foundation and hybrid primitives

- [ ] **Do:** Create `qv-protocol`: a bounded canonical message framework with
  a version/feature registry that fails closed. Add the hybrid signature
  (strict Ed25519 + ML-DSA-65) and, if the 2.1 spec requires it, X-Wing
  draft-11, all with upstream KATs and negative tests.
- **Specs:** 0002 §6; the 2.1 LAN spec.
- **Depends on:** 2.1 accepted.
- **Files:** `crates/qv-protocol/`, `crates/qv-crypto/`.
- **Done when:** a missing hybrid half, wrong label or wrong profile fails.
  Strict-verification edge vectors pass.
- **Verify:** `cargo test --locked -p qv-protocol -p qv-crypto`.
- **0012 rows:** Unpinned crypto (asymmetric part).

#### Phase 2.9 — LAN enrollment and peer state

- [ ] **Do:** Implement the 2.1 enrollment protocol, local peer-authorization
  storage, new-device initialization, peer removal and the LAN part of rotation
  re-approval.
- **Specs:** the 2.1 LAN spec; 0002 §3.5.5.
- **Depends on:** 2.8.
- **Files:** `crates/qv-sync/`, `crates/qv-store/`, `crates/qv-core/`.
- **Done when:** spoofed advertisements, enrollment races and vault/generation/
  profile substitution release no key and change no accepted state.
- **Verify:** `cargo test --locked -p qv-sync lan_enroll`; interop vectors.
- **0012 rows:** LAN discovery mistaken for trust.

#### Phase 2.10 — LAN exchange, CLI and app

- [ ] **Do:** LAN session and exchange: bounded authenticated manifest and
  object transfer, merge and local commit through the 1.7 path, idempotent
  retry, lock cancellation, manual initiation only, receive availability per
  the 2.1 spec. Add `qvault lan …` and the app UI.
- **Specs:** the 2.1 LAN spec; 0005 §0.5, §6.
- **Depends on:** 2.9, 2.5.
- **Files:** `crates/qv-sync/`, `crates/qv-cli/`, `crates/qv-app/`.
- **Done when:** interrupting at the transfer, commit or acknowledgement
  boundary preserves local edits and the anchor. Both initiation directions
  give the same result. Nothing starts a round without a user action.
- **Verify:** `cargo test --locked -p qv-sync lan`; two-device test with networking to the Internet blocked.
- **0012 rows:** Account-dependent LAN sync, LAN partial acceptance, Unrequested synchronization (LAN).

#### Phase 2.11 — Milestone 2 release evidence

- [ ] **Do:** Run the LAN gate and the per-platform GUI/mobile gates (0012 §3)
  on Linux and Android. Extended LAN fuzzing. Packaging, signed artifacts,
  checksums, and the reproducible-build status. Fold in the D12 review findings.
- **Specs:** 0012 §1 (milestone-2 rows), §3.
- **Depends on:** 2.10, 2.6/2.7 (or those features disabled), D12 review result.
- **Files:** release docs, `CHANGELOG.md`, spec statuses.
- **Done when:** every applicable 0012 row has evidence, and unvalidated features are disabled.
- **Verify:** gate checklist in the phase plan's log.

### Milestone 3 — Optional self-hosted remote server and remote sync

#### Phase 3.1 — Remote protocol finalization (spec only)

- [ ] **Do:** Settle D11 (0006 OQ2, with `quickvault-thinker`). Bring 0005 §3,
  §5.2–5.6 and 0006 to `Accepted`, with byte-level messages and transcripts and
  the error transitions. Send to the D12 reviewer.
- **Specs:** 0005 §3, §5; 0006; 0007 §4.
- **Depends on:** milestone 2 (it can overlap with 2.11).
- **Files:** `specs/0005-…`, `specs/0006-…`, `specs/README.md`, `ARCHITECTURE.md`.
- **Done when:** the specs are `Accepted` and the review request has been sent.
- **Verify:** spec review by `quickvault-reviewer`.

#### Phase 3.2 — Remote client state: checkpoints and acceptance

- [ ] **Do:** Checkpoint encoding and MAC, the "remote never forgets"
  acceptance rule, encrypted `sync_state` (verified base, cursor, pending
  publication), the outbox, and the remembered checkpoint in the local head.
  No network code yet.
- **Specs:** 0005 §5.2–5.4; 0004 §2 (`sync_state`).
- **Depends on:** 3.1.
- **Files:** `crates/qv-sync/`, `crates/qv-store/`, `crates/qv-protocol/`.
- **Done when:** replay, fork, floor regression and tombstone removal are
  rejected after long offline gaps.
- **Verify:** `cargo test --locked -p qv-sync checkpoint`.
- **0012 rows:** Remote rollback without chain, Offline commitment mismatch.

#### Phase 3.3 — Server foundation

- [ ] **Do:** Create `qv-server` (Axum/Tokio, SQLite): TLS 1.3 with mandatory
  X25519MLKEM768 and no 0-RTT, the pinned application server identity, closed
  admission, request bounds and the opaque object store schema.
- **Specs:** 0006 (scope, admission, server identity); 0002 §6.3.
- **Depends on:** 3.1.
- **Files:** `crates/qv-server/`.
- **Done when:** a classical-only TLS handshake is refused, and the stored rows
  hold no record linkage.
- **Verify:** `cargo test --locked -p qv-server`.

#### Phase 3.4 — Accounts and sessions

- [ ] **Do:** OPAQUE registration and login with the pinned profile,
  TLS-exporter-bound sessions, rate limits, fake records for unknown accounts,
  and the client account flows.
- **Specs:** 0006 (OPAQUE, registration, login); 0008 §2.
- **Depends on:** 3.3.
- **Files:** `crates/qv-server/`, `crates/qv-sync/`.
- **Done when:** RFC 9807 vectors pass. A token used on another TLS connection
  or a replayed challenge fails.
- **Verify:** `cargo test --locked -p qv-server account`.
- **0012 rows:** Authentication complexity.

#### Phase 3.5 — Publication, references and retention

- [ ] **Do:** Vault upload, idempotent atomic compare-and-swap checkpoint
  publication, reference lists that pin data, unreferenced-object GC, quotas,
  and purge acknowledgements.
- **Specs:** 0006 (uploading); 0005 §3; 0007 §4.
- **Depends on:** 3.4, 3.2.
- **Files:** `crates/qv-server/`.
- **Done when:** concurrent CAS races give exactly one winner, retries are
  idempotent, and GC never removes pinned objects.
- **Verify:** `cargo test --locked -p qv-server publish gc`.

#### Phase 3.6 — Client remote sync round

- [ ] **Do:** Stage the remote state, verify it against the base, merge into a
  candidate, publish via CAS and query ambiguous outcomes by operation ID, with
  bounded in-operation retries. Add `qvault sync` and `checkpoint show/compare`.
- **Specs:** 0005 §0.3, §0.5, §3, §5.5; 0011 §4.
- **Depends on:** 3.5.
- **Files:** `crates/qv-sync/`, `crates/qv-cli/`.
- **Done when:** any enrolled device can sync without another device online.
  LAN receipt never advances the server base or discharges the outbox.
- **Verify:** `cargo test --locked -p qv-sync remote`; client–server integration tests.
- **0012 rows:** Mixed-mode state confusion, Unrequested synchronization (remote).

#### Phase 3.7 — Device enrollment, grants and revocation

- [ ] **Do:** Pairing per 0006 (QR ticket, comparison code, one request per
  ticket, ephemeral X-Wing transfer of the full payload and the trusted
  checkpoint), grants per generation, atomic revocation, and checks on every
  operation. Add `qvault account …` and `qvault device …`.
- **Specs:** 0006 (adding a device, revocation); 0002 §6.
- **Depends on:** 3.6, 2.8.
- **Files:** `crates/qv-server/`, `crates/qv-sync/`, `crates/qv-cli/`.
- **Done when:** a racing second requester cancels, a mismatched code aborts,
  and a revoked device with an open stream or uncommitted write is cut off.
- **Verify:** `cargo test --locked -p qv-sync pairing revoke`; interop vectors.
- **0012 rows:** Incomplete key transport, Pairing QR observation, Active revoked sessions, Server revocation overclaim.

#### Phase 3.8 — Server recovery, password change and remote rotation

- [ ] **Do:** Server-only recovery (account login plus phrase, unverified
  baseline), the account password change that needs a device or recovery
  signature, and the server step of VK rotation (0002 §3.5.3) on top of 1.15.
- **Specs:** 0006 (recovery, password changes); 0002 §3.5.
- **Depends on:** 3.7.
- **Files:** `crates/qv-server/`, `crates/qv-sync/`, `crates/qv-core/`.
- **Done when:** an account session alone cannot change the account password,
  and an interrupted remote rotation resumes from the journal and the server status.
- **Verify:** `cargo test --locked rotate_remote recovery_remote`.
- **0012 rows:** Account lockout by phished password, Rotation/purge ambiguity (remote).

#### Phase 3.9 — App remote-sync UI and milestone 3 release evidence

- [ ] **Do:** App screens for account, pairing, sync and checkpoint comparison.
  Run the remote and combined-mode gates (0012 §3), including both delivery
  orders. Fold in the D12 review findings. Server deployment docs.
- **Specs:** 0012 §3 (remote, combined); 0009 §1.3.
- **Depends on:** 3.8, D12 review result.
- **Files:** `crates/qv-app/`, release docs.
- **Done when:** every applicable 0012 row has evidence.
- **Verify:** gate checklist in the phase plan's log.

### Milestone 4 — Windows

#### Phase 4.1 — Windows platform and release

- [ ] **Do:** Windows adapters (WTS session notifications, clipboard, secure
  input, an OS-protected quick-unlock backend if one validates), packaging, and
  the per-platform gates. May split.
- **Specs:** 0009 §2, §5; 0002 §5.2; 0012 §3.
- **Depends on:** milestone 2 (milestone 3 is not required).
- **Files:** `crates/qv-platform/`, `crates/qv-app/`, packaging.
- **Done when:** the Windows gate evidence is recorded and unvalidated features are disabled.
- **Verify:** Windows CI target plus a manual gate checklist.

## Test plan

- Unit and property tests: introduced per phase. Merge properties (1.5),
  codec round-trip (1.2) and generator statistics (1.4) are property tests.
- Rejection, malformed-input and crash-path tests: every parser phase adds a
  fuzz target. 1.7 builds the crash-injection harness and later write paths
  (1.12–1.15, 2.2, 2.10, 3.6) reuse it.
- Vectors: development vectors from 1.3, frozen golden vectors in 1.16, and
  protocol interop vectors in 2.8–2.10 and 3.x.
- 0012 §1 matrix rows: mapped per phase above. 1.16, 2.11 and 3.9 check that
  every row applicable to their release has a named passing test.

## Risks and stop conditions

- **Draft specs:** stop if a phase needs behaviour from a Draft section not
  covered by D5 or a later go-ahead.
- **Framework fit (1.9):** if Dioxus cannot meet native secure input or
  lifecycle locking, stop and escalate D8. Do not weaken 0008 or build
  per-OS UIs.
- **KDF/budgets (1.9, 1.16):** if password-kdf/1 misses the Android target,
  the profile changes *before* the freeze. Never lower it below the 64 MiB
  floor, and never ship unbenchmarked parameters.
- **Crate audit status:** ML-DSA, X-Wing and OPAQUE crates may be unaudited.
  Record that honestly (0012 §3). It may block a release; it does not justify
  hand-rolling a primitive.
- **Scope creep:** a phase plan that needs a new crate, a trust boundary or a
  dependency not anticipated here records it in its own plan and in a
  *Revisions* entry here.
- **Format churn:** until 1.16, no data compatibility is promised. A phase
  that wants to preserve old dev vaults must ask first.
- **Session size:** if a phase plan grows past roughly 8–10 steps, split it
  rather than leave half-done steps at a session boundary.

## Documentation

- [x] `CHANGELOG.md` — Unreleased entry for the roadmap
- [x] `ARCHITECTURE.md` — §7: a one-line pointer to this roadmap
- [x] `ARCHITECTURE.md` — §3 row for `qv-encoding` (phase 1.2, when the crate is created)
- [ ] Specs — no change by this plan; amendments happen in the phases named above
- [x] `AGENTS.md` — per-phase session protocol in *Agent workflow*; D1–D4 recorded in *Engineering conventions*
- [ ] `plans/README.md` — index row (done)

## Revisions

- 2026-10-25: Approved by the owner with D1–D6 and D9 accepted as recommended. D1–D4 were recorded in `AGENTS.md` at approval, not in phase 1.1.
- 2026-10-25: Owner direction: one prompt ("next phase") per session, with standing approval of phase plans except under the stop conditions in *Session protocol* step 4. Sessions never commit; the owner commits each phase.
- 2026-10-25 (phase 1.4, plan 0006): 0010 §3.2 (`zxcvbn` for user-typed passwords) and §4.2 (master-password acceptance) land with their first consumer, phase 1.10 (`init`/`passwd`/`recover`), not in 1.4. `zxcvbn` is not in the candidate table, so 1.10 needs the owner's approval for it. The generator lives in `qv-crypto`; `qv-core` exposes it from 1.8.
- 2026-10-25 (phase 1.4, plan 0006): owner approved `ctutils` (RustCrypto, already in the build via `hmac`) as the constant-time crate instead of the candidate-table `subtle`, whose `BSD-3-Clause` licence is outside the allow-list.
- 2026-10-26 (phase 1.5, plan 0007): the CBOR integer-key registry is assigned in `qv-model` as development values; the 1.16 format freeze records the frozen registry in 0003/0004. Generator defaults in vault `settings` (0010 §5.1) land in 1.8 with their first consumer (settings key 2 reserved). The HOTP core lives in `qv-crypto` with the other primitives; `qv-model` parses `otpauth://` URIs.

## Execution log

- 2026-10-25: Roadmap approved. Next: phase 1.1 in a new session ("next phase").
- 2026-10-25: Phase 1.1 implemented as plan 0003 (standing approval). Workspace, toolchain pin, lints, `cargo deny`/`cargo vet`, SPDX check, CI, and `qv-crypto` (protected memory, process hardening, fail-closed RNG). All gates green locally; the first hosted CI run is pending the owner's push. Not reviewed yet: the next session reviews it first. Next: phase 1.2 ("next phase").
- 2026-10-25: Phase 1.1 reviewed (plan 0003, [REVIEW.md](../0003-workspace-bootstrap/REVIEW.md)): Approved, no fixes, nothing escalated. Hosted CI run still to be confirmed by the owner.
- 2026-10-25: Phase 1.2 implemented as plan 0004 (standing approval). New crate `qv-encoding`: allocation-free validator, borrowing decoder, `RawValue` for unknown entries, canonical-only zeroizing encoder, `encode_array`. 14 rejection tests (exact errors), 4 proptest properties, `cbor_decode` fuzz target plus a CI job (pinned nightly). New dev-only dependency `proptest`; fuzz-only `libfuzzer-sys` outside the workspace. All gates, `cargo deny` and `cargo vet` green locally; 60 s local fuzz run clean (musl needs `-use_cmp=0`, CI doesn't). The first hosted fuzz run is pending the owner's push. Not reviewed yet: the next session reviews it first. Next: phase 1.3 ("next phase").
- 2026-10-25: Phase 1.2 reviewed (plan 0004, [REVIEW.md](../0004-canonical-cbor/REVIEW.md)): Approved with minor fixes. The CI fuzz job now checks `fuzz/Cargo.lock` with `cargo fetch --locked`. Nothing escalated. The hosted CI and fuzz runs still need the owner to confirm them.
- 2026-10-25: Phase 1.3 implemented as plan 0005 (standing approval; one stop for the owner: allow `Unicode-3.0` for `unicode-normalization`, approved). `qv-crypto` now has the profile registry, password-kdf/1 with NFC, the KEK and constant-time commitment, password slots (partitioning-oracle test), the nine purpose keys typed by purpose, record and attachment keys, stored-data/1 with canonical Padmé framing, MAC/1, object-hash/1 and `CryptoError`. Upstream KATs pass (RFC 4231, Wycheproof HKDF-SHA-512, FIPS 180-4, XChaCha draft §A.3.1, RFC 9106). The development vectors are independently computed by a stdlib Python script, and the Argon2id vector by OpenSSL. New dependencies are from the candidate table, with 19 vet exemptions (no imported audits for the new RustCrypto majors). All gates, deny and vet green. Notes for later phases are in plan 0005's log (local-state key dual use before 1.7; Padmé's 1 MiB boundary; sequential Argon2 lanes for 1.9/1.16). Not reviewed yet: the next session reviews it first. Next: phase 1.4 ("next phase").
- 2026-10-25: Phase 1.3 reviewed (plan 0005, [REVIEW.md](../0005-crypto-key-hierarchy/REVIEW.md)): Approved with minor fixes. The sealed key-use traits leaked raw key bytes to other crates; a crate-private access token now closes this, with compile-fail doctests. Nothing escalated.
- 2026-10-25: Phase 1.4 implemented as plan 0006 (standing approval; one stop for the owner: `subtle` is `BSD-3-Clause`, outside the allow-list, so the owner chose `ctutils` instead, which is already in the build via `hmac`). `qv-crypto` now has the recovery phrase (VK ↔ 24 BIP-39 words, constant-time lookups and checksum, `confirm_word`; Trezor vectors) and the 0010 generator (characters, passphrase, PIN; validation before any RNG use; rejection sampling; ≤ 10,000 whole-password attempts; exact entropy, labels and warning; deterministic chi-square tests). Both word lists are embedded, with their SHA-256 checked at first use and in tests. `zxcvbn` (0010 §3.2/§4.2) moves to 1.10 (see *Revisions*). All gates, deny and vet green. Not reviewed yet: the next session reviews it first. Next: phase 1.5 ("next phase").
- 2026-10-26: Phase 1.4 reviewed (plan 0006, [REVIEW.md](../0006-recovery-phrase-generator/REVIEW.md)): Approved with minor fixes (a CHANGELOG blank line). The BIP-39 vector file matches a fresh Trezor download. Nothing escalated.
- 2026-10-26: Phase 1.5 implemented as plan 0007 (standing approval; no stop for the owner). New crate `qv-model`: UUIDv4 IDs validated on decode; the record-version plaintext and all five payload kinds as canonical CBOR (development registry, unknown keys preserved, 0004 §4.1 budgets before allocation, unknown kinds/profiles fail closed, undeletable control records); version vectors; the maximal-version merge (identity checks, 256-head limit, live/trash representatives, status); history floors; the group-tree projection with recovered-items placement; TOTP. `qv-crypto` gains `hotp`; new dependency `sha1` (candidate table; one vet exemption). Property tests over generated honest histories (permutation, regrouping, duplicates, brute-force maximal set) and the 0012 rows Order-dependent merges, Old-date concurrent edits, Mixed credentials and Deleted-entry resurrection (model level); RFC 4226/6238 vectors parsed from the fetched RFC texts; new `record_decode` fuzz target (CI step; 60 s local run clean). All gates, deny and vet green (257 tests). Readings recorded in plan 0007 for the reviewer and owner: "deletion visibility" (a record is in trash if any head is soft-deleted or a tombstone is concurrent with a non-final head; a group is deleted for the tree only when no head is live), UUIDv4 rejection on decode, attachment ID = record ID. Not reviewed yet: the next session reviews it first. Next: phase 1.6 ("next phase").
