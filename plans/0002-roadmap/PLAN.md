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

Each phase runs in a **fresh session** started with **"next phase"**.
For context selection, use the roadmap reading guide in
[.agents/README.md](../../.agents/README.md#efficient-reading-without-losing-evidence).
Read the approval rules, decisions, cross-phase constraints and relevant
revisions; unrelated future phase bodies need not be loaded.
The session then works without further prompting:

0. **Check the tree.** If `git status` shows uncommitted work from the previous
   phase, stop and ask the owner to commit it first, so each phase stays a
   separate commit. Sessions never commit, push or branch; the owner does.
1. **Find the phase:** the first unticked phase below whose *Depends on* items
   are done.
2. **Review the previous phase** (`quickvault-reviewer`) unless its plan is
   already `Reviewed`. A fresh context makes the review independent. If the
   review escalates problems, stop and report them. Only implementation
   (code, tests, scripts, CI) gets this review. A spec-only or plan-only
   phase is checked in its own session and needs no separate review session
   (owner direction 2026-10-30). The external D12 protocol review is
   unaffected.
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

Keep implementation steps inside the phase plan. Do not split a phase solely
because of step count or context size; continue the phase across context
handoffs. A phase split needs a concrete delivery boundary or blocking decision
and must be justified in a dated Revisions entry, not added as another routine
level of task numbering (owner direction 2026-10-31). A
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
   (format freeze). Resolution: owner decided on 2026-10-26 not to name
   devices: use a sane default. Recorded in 0009 §2 as the supported Android
   baseline (arm64, Android 10+, ≥ 4 GB RAM); any one such device serves for
   the spike and the 1.16 benchmarks. The SDK/NDK comes from
   `scripts/setup-android.sh` (installed on 2026-10-26; arm64 cross-builds
   work). On-device checks need the owner's phone over `adb`: the session asks
   the owner to bring it when needed (there is no KVM for an emulator).
8. **D8 — 0008 OQ2 / 0009 OQ3: webview (Dioxus) or native Rust renderer.**
   Resolution: owner chose Dioxus with its standard webview input on 2026-10-26.
   Framework/OS memory copies are accepted as a documented best-effort limit,
   not a reason for native dialogs, a fork or a custom engine. Phase 1.9 still
   supplies integration/performance evidence; active-content and OS release
   requirements remain. No production-readiness claim is inferred.
9. **D9 — Attachments in the CLI.** 0011 §4 lists no attachment commands, but
   0003 §6 makes attachments a v1 model feature, and the manifest format must
   include chunk lists before the format freeze. Options: (A) amend 0011 with
   `qvault attach add|ls|save|rm` in phase 1.11; (B) attachments in core only,
   UI in milestone 2. Recommendation: A, because otherwise the attachment path
   ships to the format freeze untested end to end. Blocks: CLI part of 1.11.
   Resolution: owner accepted option A on 2026-10-25. The 0011 amendment is the first step of phase 1.11.
10. **D10 — 0005 OQ3–OQ6: LAN discovery, trust/session protocol, listening,
    peer removal.** Worked through in phase 2.1 with `quickvault-thinker`.
    Blocks: 2.8–2.10. Resolution: the owner delegated on 2026-10-30
    ("whatever you think is best"). Chosen in plan 0025, spec 0013:
    - QR or manual endpoints, with discovery only in a receive window;
    - pairwise link keys from an out-of-band pairing (existing profiles
      only, no device signing identities);
    - explicit time-boxed receive windows;
    - local generation-bound link removal, with rotation for compromise.

    0013 was accepted the same day, also by owner delegation.
11. **D11 — 0006 OQ2: per-device signing identities.** Settled in phase 3.1.
    Blocks: 3.2 on. Resolution: pending.
12. **D12 — Independent protocol review.** 0012 §3 requires an external review
    of the LAN and server key-transfer/session compositions before release.
    The owner must choose and engage a reviewer. Lead time is long, so start
    when 2.1 / 3.1 produce a spec. Blocks: 2.11, 3.9 (release only, not
    implementation). Resolution: pending.
13. **D13 — Owner architecture review before the GUI.** The owner wants to
    re-verify the architecture (`ARCHITECTURE.md`, component boundaries, D8
    and the app/platform phases 2.3–2.5) before any production GUI work. The
    session that reaches phase 2.4 stops before planning it. It reminds the
    owner, summarizes the current architecture and what has changed since D8,
    and waits for the owner's explicit go-ahead. Blocks: 2.4 (and so 2.5–2.7).
    Resolution: pending.

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
- Application-controlled Rust secrets use qv-crypto's protected memory module
  (1.1). Dioxus input/bridge intermediates follow 0008 §1.1/§4.4 with bounds,
  prompt protected conversion, cleanup and documented framework/OS limits.
  Nothing secret goes into logs, errors, panics or argv.
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

- [x] **Plan:** [0008](../0008-vault-file-sqlite/PLAN.md). **Do:** Create `qv-store`. Open a vault with every hardening setting in
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

- [x] **Plan:** [0009](../0009-objects-manifest-anchor/PLAN.md). **Do:** Write object envelopes (unlinkable plaintext, 0004 §2.2), record
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

- [x] **Plan:** [0010](../0010-core-sessions/PLAN.md). **Do:** Create `qv-core`: session lifecycle (unlock, lock, cancellation of
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

- [x] **Do:** Build a throwaway-quality Dioxus app on Linux and a physical
  Android device. It must show the vault list and entry editing against
  `qv-core`, offline persistence, Dioxus password input with bounded cleanup,
  and lifecycle lock/cancellation. Probe keystore/biometric access, the
  clipboard and the autofill service entry point. Benchmark unlock time
  (including password-kdf/1) and memory on the D7 devices. Write a feasibility
  report that answers 0009 §6 and records evidence for the selected Dioxus UI. Mark the spike code as
  non-production, or keep it out of the workspace default members.
- **Specs:** 0009 §6 (D5); 0008 OQ2; 0002 OQ1, 0004 OQ1 (benchmarks).
- **Depends on:** 1.8, D7. Independent of 1.10, so it can swap with it.
- **Files:** `spikes/ui-feasibility/` (or as the phase plan decides), `plans/NNNN-…/REPORT.md`.
- **Done when:** the report exists with measured numbers and integration gaps.
  D8 is already decided (Dioxus); no repeated framework-choice approval is needed.
  Record failed/unavailable evidence accurately; selection is not validation.
- **Verify:** builds for Linux and the Android target; benchmark logs attached to the report.
- **0012 rows:** Mobile deferred behind shared-UI claims (feasibility evidence only).

#### Phase 1.10 — CLI: vault, browse, edit, clipboard, generator

Split on 2026-10-26 (see *Revisions*) into **1.10a** (foundation, `init`, `info`, browsing, `generate`; the
  rest of this entry except editing, trash and clipboard) and **1.10b** (`add`, `edit`, `mv`, `mkdir`, `rm`,
  `trash …`, notes and `-i`, signal handling) and **1.10c** (clipboard `copy`
  and `--copy` variants; split approved 2026-10-27). 1.10b depends on 1.10a;
  1.10c follows 1.10b and needs its own approved clipboard integration design.
- [x] **1.10a plan:** [0011](../0011-cli-foundation-read/PLAN.md) (done).
- [x] **1.10b plan:** [0014](../0014-cli-edit-trash/PLAN.md) (done, Reviewed).
- [x] **1.10c plan:** [0015](../0015-cli-clipboard/PLAN.md) (done; fresh review pending).
- **Do:** Create `qv-cli` (`qvault`): vault selection and config, `init`
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

- [x] **Plan:** [0016](../0016-attachments/PLAN.md). **Do:** Store attachments in chunks (64 KiB padded chunks, chunk AAD,
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

- [x] **Plan:** [0017](../0017-entry-history/PLAN.md) (Reviewed). **Do:** Implement history retention (N = 10 under budgets), history
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

Split on 2026-10-28 (see *Revisions*) into **1.13a** (the archive
writer/reader, the `verify` pass, snapshot policy and pruning, and the
`snapshot ls`/`verify` commands) and **1.13b** (`snapshot restore` into a new
vault path).
- [x] **1.13a plan:** [0018](../0018-archives-snapshots-verify/PLAN.md) (Reviewed after owner-authorized remediation).
- [x] **1.13b plan:** [0019](../0019-snapshot-restore/PLAN.md) (Reviewed after owner-authorized exit-code correction).
- **Do:** Write the archive writer (verified objects only, temp file →
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

- [x] **Plan:** [0020](../0020-password-recovery/PLAN.md) (Reviewed). **Do:** Implement `passwd` (new complete slot plus encrypted keyslot
  record, atomic, weak-password flow per 0011 §5.4), `recovery show` (after
  re-authentication, TTY only, alternate screen) and `recover <path>` (unlock
  with the phrase, set a new password). Handle the KDF-only profile migration
  path (0002 §2.1).
- **Specs:** 0002 §2.1, §3.4, §4; 0011 §4 (Vault), §5.4.
- **Depends on:** 1.13.
- **Files:** `crates/qv-core/`, `crates/qv-cli/`, `crates/qv-store/` (necessary transaction support; revision 2026-10-29).
- **Done when:** the old password fails and the new one works after a crash at
  any point. A KDF-only upgrade leaves the data objects unchanged.
- **Verify:** `cargo test --locked -p qv-core credentials`; `cargo test --locked -p qv-store credentials`; `cargo test --locked -p qv-cli --test credentials`.
- **0012 rows:** Migration coupling (KDF part).

#### Phase 1.15 — Offline VK rotation

Split 2026-10-29 under the session-size rule: **1.15a** builds the bounded
rotation journal/MACs and ordinary-open/create/restore safeguards; **1.15b**
builds the replacement, snapshot inventory, installation/restart workflow and
CLI, after fresh-context review of 1.15a. The whole-rotation criteria below
remain required before 1.16.

- [x] **1.15a plan:** [0021](../0021-offline-key-rotation/PLAN.md) (Reviewed).
- [x] **1.15b plan:** [0022](../0022-rotation-replacement/PLAN.md) (Reviewed) — verified private replacement and cross-generation snapshot inventory (split 2026-10-29).
- [x] **1.15c plan:** [0023](../0023-rotation-install/PLAN.md) (Reviewed) — journal installation, restart/rollback, anchor generation step, inventory-aware snapshot policy, core lifecycle, `recovery rotate` CLI and crash injection at every journal step.
- **Do:** Implement `recovery rotate` for vaults without remote sync: freeze
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

#### Phase 1.16 — Offline hardening and benchmarks

Owner decision 2026-10-30: QuickVault is pre-1.0, and every format stays
volatile until the owner declares it ready and has user-tested it. The
format freeze therefore leaves this phase:
- the physical DDL, CBOR registry, profile IDs/parameters, archive and
  journal formats, and final format numbers;
- golden vectors, including the worst-case manifest;
- closing 0002 OQ1/0004 OQ1;
- `Implemented` statuses.

They move to an unscheduled pre-1.0 release step, as do the supported-device
KDF benchmarks, whose only purpose is tuning before the freeze. The planned
1.16b is dropped. The 0012 §3 offline gate still applies before that
release; it is not weakened.

- [x] **1.16 plan:** [0024](../0024-offline-release-evidence/PLAN.md) (Reviewed) — offline matrix tags and checker, mode/write-failure/redaction audits, networking-blocked CI requirement, fuzz campaigns (local runs plus a weekly CI job), Linux budget benchmarks, dependency audit status. Android benchmarks are deferred to the release step.
- **Do:** Collect the offline hardening evidence that does not depend on a
  frozen format:
  - every offline 0012 row tied to a named test;
  - permission, write-failure and redacted-error audits;
  - fuzzing in CI;
  - Linux budget benchmarks;
  - the dependency audit status.
- **Specs:** 0012 §1 (offline rows), §3 (offline gate, evidence part); 0004 §4.
- **Depends on:** 1.15.
- **Files:** `scripts/`, `tests/`, crate tests, `crates/qv-core/examples/`,
  `.github/workflows/`, the plan's report, `CHANGELOG.md`.
- **Done when:** every offline row of the 0012 matrix has a passing test that
  names it, the audits pass, and the benchmark report is in the plan.
- **Verify:** full test suite; `sh scripts/check-matrix.sh`; fuzz summaries;
  `cargo deny check`; `cargo vet`.

### Milestone 2 — Offline Android and Linux apps, LAN sync, conflicts, archive exchange

#### Phase 2.1 — LAN sync protocol design (spec only)

- [x] **Plan:** [0025](../0025-lan-protocol-spec/PLAN.md) (Reviewed): spec
  [0013](../../specs/0013-lan-sync-protocol.md) **Accepted** 2026-10-30 by
  owner delegation, with its amendments applied. Not done: the owner has
  not sent the D12 review request (text in plan 0025). D12 blocks only the
  2.11 release evidence.
- **Do:** With `quickvault-thinker`, settle 0005 OQ3–OQ6 (D10). Then write
  the LAN protocol spec: discovery/addressing, out-of-band enrollment, peer
  identity, session protection, bounded messages, peer-state schema,
  initialization, removal, generation transitions and error transitions. Give
  it its own spec number or a 0005 §6 amendment, at status `Draft` → `Accepted`
  by the owner. Send it to the D12 reviewer.
- **Specs:** 0005 §6, OQ3–6; 0002 §3.5, §6; 0012 §3 (LAN gate).
- **Depends on:** milestone 1 complete (it can start in parallel with 2.2–2.7).
- **Files:** `specs/`, `ARCHITECTURE.md` §3/§6, `specs/README.md`.
- **Done when:** the spec is `Accepted` and lists byte-level messages. The review request has been sent.
- **Verify:** spec check by `quickvault-reviewer` in the same session
  (done, plan 0025 REVIEW.md; no separate session, owner direction
  2026-10-30).

#### Phase 2.2a — Verified archive input and shared merge candidates

- [x] **Plan:** [0026](../0026-conflicts-archive-exchange/PLAN.md) (Reviewed).
- **Do:** Create qv-sync's bounded whole-record candidate merge and qv-store's
  private fully authenticated stable archive input. No incoming publication yet.
- **Specs:** 0005 §1–2, §4 (owner go-ahead); 0004 §3–4, §6; 0007 §1–2.
- **Depends on:** 1.16.
- **Files:** `crates/qv-sync/`, `crates/qv-store/`, workspace metadata.
- **Done when:** candidate merge preserves concurrent deletion/edit, monotonic
  floors and tombstones; malformed/private-copy inputs fail closed.
- **Verify:** `cargo test --locked -p qv-sync`, incoming store tests.
- **0012 rows:** Deleted-entry resurrection, Order-dependent merges,
  Hostile files from sync folders (candidate/input coverage only).

#### Phase 2.2b — Atomic incoming acceptance and filename receipts

- [x] **Plan:** [0027](../0027-archive-receipt-state/PLAN.md) (Reviewed).
- **Do:** Sealed receipt state and lifecycle, safe source paths and verified
  candidate/object staging through the existing write/anchor path. Preserve
  all permanent tombstones, including dominated floor-covered ones.
- **Specs:** 0004 §2–6; 0005 §2, §4, §5.4; 0007 §1–3.
- **Depends on:** 2.2a (Reviewed and committed).
- **Files:** qv-store, qv-sync, existing LocalState AEAD use, specs, tests/fuzz/CI.
- **Done when:** atomic acceptance/redelivery/restart converges; changed reused
  filenames fail; old input revives neither tombstones nor suppressed history;
  full acceptance crash matrix and all gates pass.
- **Verify:** store/sync suites and required gates.

#### Phase 2.2c — Conflict resolution and archive-exchange commands

- [x] **Plan:** [0028](../0028-archive-exchange-commands/PLAN.md) (Implemented;
  complete combined C phase).
- **Do:** Core/CLI `conflicts`, `resolve`, `merge <archive>` and `snapshot export
  <directory> [--self-contained]`; complete versions, selected-slot proof,
  mandatory recovery snapshots, bounded views, lock races and durable outcomes.
- **Specs:** 0005 §2.3–2.6, §4–5.4; 0004 §5–6; 0007 §3; 0011 §3–6.
- **Depends on:** 2.2b (Reviewed and committed). Owner explicitly authorized
  completing both former C parts on the current staged tree without a boundary.
- **Files:** qv-store, qv-core, qv-cli, specs, workspace metadata.
- **Done when:** original 2.2 requirements pass: old archives revive no suppressed
  history/tombstones, concurrent deletion/edit remains explicit, reused filenames
  reject, complete selected versions resolve causally, slots require proof and
  self-contained exports require warned consent.
- **Verify:** affected crate tests, required gates and affected fuzz compilation.

#### Phase 2.3 — Platform adapters: traits and Linux

- [ ] **Do:** Create `qv-platform`: traits injected into core (secure input,
  clipboard, lifecycle/lock signals, keystore, protection-status reporting).
  Linux implementations: logind/D-Bus lock and sleep, clipboard ownership,
  single instance, and swap/hibernation configuration detection. Quick unlock
  stays disabled on Linux unless a backend meets 0002 §5.2.
- **Specs:** 0009 §1.6, §5; 0008 §1.3–1.4, §3.
- **Depends on:** 2.2c, D8.
- **Files:** `crates/qv-platform/`, `crates/qv-core/`.
- **Done when:** a screen lock locks the session in an integration test (or a
  documented manual test). The reduced-protection mode is reported.
- **Verify:** `cargo test --locked -p qv-platform`.

#### Phase 2.4 — App foundation and security boundary

- [ ] **Do:** Build the production `qv-app` skeleton on the framework chosen in
  D8. If it is a webview: local assets, CSP, navigation/frame/popup blocking,
  and a typed allowlisted bridge checked in Rust. Use standard Dioxus input for
  master password, phrase and protected values with 0008's bounded cleanup. Flows:
  create (with recovery phrase), unlock, lock, recover. Android adapters:
  lifecycle, FLAG_SECURE, keyboard flags.
- **Specs:** 0008 §4; 0009 §1.6; 0002 §4.2.
- **Depends on:** 2.3, D8, **D13 (owner architecture review: stop and remind
  the owner before planning this phase)**.
- **Files:** `crates/qv-app/`, `crates/qv-platform/`, Android packaging.
- **Done when:** injection tests (HTML, URL, IPC) fail safely, remote
  navigation is blocked, and secret input is bounded, converted promptly and cleared on submit/lock.
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
- **Framework integration (1.9):** Dioxus is selected. Record lifecycle,
  active-content or OS integration gaps without complete-erasure claims.
  Framework/OS copies alone do not require native dialogs or a custom engine.
  Do not weaken unrelated 0008 requirements or build separate per-OS UIs.
- **KDF/budgets (1.9, 1.16):** if password-kdf/1 misses the Android target,
  the profile changes *before* the freeze. Never lower it below the 64 MiB
  floor, and never ship unbenchmarked parameters.
- **Crate audit status:** ML-DSA, X-Wing and OPAQUE crates may be unaudited.
  Record that honestly (0012 §3). It may block a release; it does not justify
  hand-rolling a primitive.
- **Scope creep:** a phase plan that needs a new crate, a trust boundary or a
  dependency not anticipated here records it in its own plan and in a
  *Revisions* entry here.
- **Format churn:** until 1.0, no data compatibility is promised (owner
  decision 2026-10-30; the freeze is a pre-1.0 release step, not 1.16). A
  phase that wants to preserve old dev vaults must ask first.
- **Session size:** step count alone is not a reason to split phases. Preserve
  a durable execution log and continue the approved phase to completion.

## Documentation

- [x] `CHANGELOG.md` — Unreleased entry for the roadmap
- [x] `ARCHITECTURE.md` — §7: a one-line pointer to this roadmap
- [x] `ARCHITECTURE.md` — §3 row for `qv-encoding` (phase 1.2, when the crate is created)
- [ ] Specs — no change by this plan; amendments happen in the phases named above
- [x] `AGENTS.md` — per-phase session protocol in *Agent workflow*; D1–D4 recorded in *Engineering conventions*
- [ ] `plans/README.md` — index row (done)

## Revisions

- 2026-10-31: Owner rejected the excessive c1/c2 split and requested both now.
  Recombine as 2.2c in 0028; continue on staged c1 without intermediate commit
  or fresh review. Remove the automatic 8–10-step splitting rule. Future plans
  keep implementation detail inside the phase and use a split only for a real
  delivery boundary/blocker. The next fresh session reviews the complete C work.

- 2026-10-31: Architect sized combined 2.2c at roughly sixteen steps (archive
  codec/publication, serialized recovery policy, candidate-index preflight,
  core and CLI commands, plus per-kind conflict handles/views, selected-slot
  proof, resolution and adversarial evidence). Split under the session-size
  rule into 2.2c1 archive exchange/export (0028, eight steps) and 2.2c2 conflict
  inspection/resolution. Original scope retained; 2.3 waits for c2. Prior 0026
  delegation covers exact amendments; keep owner-commit/fresh-review boundaries.

- 2026-10-30: Owner: “Do both Bs already.” Recombine b1/b2 as 2.2b,
  continuing 0027 on the staged tree in this session. This explicitly overrides
  the intermediate commit/fresh-review/session split; C remains separate.

- 2026-10-30: Split 2.2b before implementation under the session-size rule:
  b1 (0027) establishes sealed receipt storage/head/lifecycle; b2 publishes
  incoming candidates with atomic receipts and the acceptance crash matrix.
  Together these exceed 8–10 implementation steps. The receipt design and
  normative amendment are covered by owner delegation in 0026. Each code
  subphase retains the owner commit and fresh-context review boundary.

- 2026-10-30 (plan 0026, before code): owner approved the receipt/CLI
  recommendations and delegated remaining choices (“Just do whatever you feel
  is right and go ahead”). Split 2.2 under the session-size rule into 2.2a
  (verified archive input/shared candidates), 2.2b (atomic acceptance/receipts),
  2.2c (core/CLI resolution/export). The original nine steps hid independent
  schema/head/generation-transition and selected-slot reauthentication work.
  Original overall scope retained; keep owner-commit/fresh-review boundaries.

- 2026-10-30 (owner direction): the fresh-context review in *Session
  protocol* step 2 applies only to implementation (code, tests, scripts,
  CI). Spec-only and plan-only phases are checked in their own session.
  The external protocol review (D12) and every release gate are unchanged.

- 2026-10-30 (owner decision, during phase 1.16): pre-1.0, everything is
  volatile, and there is no format freeze until the owner declares the
  product ready and has user-tested it. Removed from 1.16 and moved to an
  unscheduled pre-1.0 release step:
  - the freeze and its final format numbers;
  - the golden vectors;
  - closing 0002 OQ1/0004 OQ1;
  - `Implemented` statuses;
  - supported-device KDF benchmarks.

  1.16b is dropped, and plan 0024 is the whole of 1.16. This supersedes the
  1.16 split entry below. No spec change: 0012 §3 requires the freeze only
  before an offline release.

- 2026-10-30 (phase 1.16, plan 0024): split 1.16 under the session-size
  rule. **1.16a** collects the evidence and changes no format, parameter or
  spec: matrix row tags and `scripts/check-matrix.sh`, CLI audits (modes,
  write failure under a file-size limit, canary redaction), the
  networking-blocked test required in CI, 7 × 30-minute fuzz campaigns plus
  a weekly CI job, and the `budget_bench` example measured on Linux and the
  owner's phone. **1.16b** freezes the formats and records the benchmarks
  in the specs; its spec amendments need the owner's approval. No
  dependency or `unsafe`. Keep the fresh-review and owner-commit boundary
  between them.

- 2026-10-30: Owner request: remind the owner and wait for an architecture
  re-verification before the production GUI starts. Added D13, which blocks
  phase 2.4, so standing approval cannot skip it. No other scope, order or
  approval change.

- 2026-10-29 (phase 1.15b, plan 0022): split the remaining rotation work again
  under the session-size rule (about 12 steps). **1.15b** builds and verifies the
  private replacement generation from persisted bytes, reserves `.qvrotate`
  names for ordinary opens, and adds the per-generation snapshot inventory
  (codec, MAC, directory operations, fuzz target). Nothing is published.
  **1.15c** publishes through the 1.15a journal: installation and restart,
  anchor advancement, inventory-aware policy, core and CLI, and the
  whole-rotation *Done when*. Same crates; no dependency, spec amendment or
  `unsafe`. Keep the owner-commit and fresh-review boundary between them.
  Development values for the 1.16 freeze: the inventory format, its
  `qv/snapshot-inventory/v1` label, the `inventory-<vault>-<gen>.qvinv` name
  and its 1 MiB / 4096-row bounds.

- 2026-10-29: Owner delegated plan 0021 D1 choice; selected A and amended 0002
  §3.5.1 to defer offline-only recovery public-key derivation until needed.
  Split 1.15 into 1.15a (journal/open safeguards) and 1.15b (replacement,
  installation, snapshot accounting and CLI) before code, using the explicit
  session-size split rule. Keep the commit/fresh-review boundary between them.

- 2026-10-29: Owner requested fixing 0019 and implementing phase 1.14 without
  an intervening commit. Plan 0020 includes the necessary existing qv-store
  transaction/credential internals in addition to the core/CLI list for 1.14;
  no new component, dependency, format or write path.

- 2026-10-28 (phase 1.13, plan 0018): split 1.13 into **1.13a** and **1.13b**.
  1.13a: the D6 0007 amendment, the 0011 `snapshot ls`/`verify` amendment
  (owner-approved D1 on 2026-10-28), the archive header/writer/reader in
  `qv-store` with the `archive_read` fuzz target and CI wiring, the full
  `verify` pass, snapshot policy/coalescing/budgets/pruning and authenticated
  listing in `qv-core`, and the CLI `snapshot ls`, `verify` and the mandatory
  recovery snapshot of `trash empty`. 1.13b: `snapshot restore <id> <path>` —
  building a new vault file from a verified archive (fresh replica, head and
  anchor), its CLI contract and the restore-path evidence for the remaining
  0012 rows — planned as 0019 in its own session. Development values for the
  1.16 freeze from 1.13a: the archive magic `QVSNAP\0`/format version, header
  field set, frame layout, the `qv/archive-header/v1` label, the snapshot
  directory (`$XDG_STATE_HOME/quickvault/snapshots`), the local filename scheme
  and the 30-day/48-snapshot/512 MiB budgets. 1.13a adds no dependency, no
  `unsafe` and no new write path.

- 2026-10-27: Owner explicitly requested fixing phase 1.11 review findings,
  finishing that review and starting phase 1.12 in the same session without an
  intervening owner commit. This authorizes that specific continuation; future
  phases retain the usual clean-tree/owner-commit/fresh-context protocol.

- 2026-10-27: Owner approved plan 0014 D1 option A: 1.10b implements editing,
  trash and signal cleanup; 1.10c separately designs and implements clipboard
  commands. Previously approved arboard/license choices are candidates for
  1.10c, not approval to ignore the documented buffer/ownership requirements.

- 2026-10-26: Added targeted context-reading guidance for agent efficiency;
  phase scope/order, standing approval and fresh-context review are unchanged.
- 2026-10-25: Approved by the owner with D1–D6 and D9 accepted as recommended. D1–D4 were recorded in `AGENTS.md` at approval, not in phase 1.1.
- 2026-10-25: Owner direction: one prompt ("next phase") per session, with standing approval of phase plans except under the stop conditions in *Session protocol* step 4. Sessions never commit; the owner commits each phase.
- 2026-10-25 (phase 1.4, plan 0006): 0010 §3.2 (`zxcvbn` for user-typed passwords) and §4.2 (master-password acceptance) land with their first consumer, phase 1.10 (`init`/`passwd`/`recover`), not in 1.4. `zxcvbn` is not in the candidate table, so 1.10 needs the owner's approval for it. The generator lives in `qv-crypto`; `qv-core` exposes it from 1.8.
- 2026-10-25 (phase 1.4, plan 0006): owner approved `ctutils` (RustCrypto, already in the build via `hmac`) as the constant-time crate instead of the candidate-table `subtle`, whose `BSD-3-Clause` licence is outside the allow-list.
- 2026-10-26 (phase 1.5, plan 0007): the CBOR integer-key registry is assigned in `qv-model` as development values; the 1.16 format freeze records the frozen registry in 0003/0004. Generator defaults in vault `settings` (0010 §5.1) land in 1.8 with their first consumer (settings key 2 reserved). The HOTP core lives in `qv-crypto` with the other primitives; `qv-model` parses `otpauth://` URIs.
- 2026-10-26 (phase 1.6, plan 0008): the vault file's header/keyslot layouts, the `qv/header-mac/v1` transcript, the application ID (`0x5156_4C54`), the development schema and the size cap and SQLite limits are development values; the 1.16 format freeze records them in 0002/0004. 1.7 adds its tables to the schema (bumping the development `user_version`) and confirms the SQLite `LENGTH` limit against the manifest envelope. The SQLite build options live in `.cargo/config.toml`, checked by a `qv-store` test.

- 2026-10-26 (phase 1.7, plan 0009): the owner approved a 0004 amendment (the plan amends a spec, so standing approval did not apply): an aggregate budget of 1,048,576 clock components per manifest (D-A; 256 writers per clock over 250,000 objects made the §4.2 worst case about 1.6 GiB), and writer state plus the anchor's name in a local-only `replica` row (D-B). The anchor location is per-replica files in `$XDG_STATE_HOME/quickvault/anchors` on Linux; Android's comes with 2.3/2.6. Development values for the 1.16 freeze: schema 2 (`0x7FFF_0002`), the manifest, head and anchor registries and formats, the labels `qv/record/v1`, `qv/manifest/v1`, `qv/config/v1`, `qv/local-head/v1`. Notes for later phases are in plan 0009's log (manifest clone per write, one decryption pass for views in 1.8, `put_local` takes local edits only until 2.2, chunks from 1.11, history retention from 1.12). Encrypting sync state with the `local-state` key, which this phase uses only for the head MAC, is still the owner's call when sync state arrives (plan 0005 note).
- 2026-10-26 (phase 1.8, plan 0010): development values for the 1.16 freeze: the generator-defaults layout at vault settings key 2 (`qv-model`), the 64 MiB metadata-view budget and the 10-minute clock-anomaly tolerance (`qv-core`). Trash expiry is never automatic: `expired_trash` lists what the retention period offers and frontends confirm `purge` (1.10 `trash empty`). Mutations of conflicted records are refused until conflict resolution (2.2). Notes for later phases are in plan 0010's log.
- 2026-10-26 (phase 1.10, plan 0011): the owner approved splitting 1.10 into 1.10a/1.10b and decisions D-1–D-6 of plan 0011 as recommended: `zxcvbn 3.1.1` in `qv-core` (0010 §3.2); `clap 4.6.7` builder API only; for 1.10b, `signal-hook 0.4.5` and `arboard 3.6.1` (X11 only, no image support) with per-crate `BSL-1.0` exceptions for `clipboard-win` and `error-code`; the recovery-phrase skip (0002 §4.2) recorded as vault settings key 3 `recovery_skipped_at` (development value for the 1.16 freeze). These dependencies are now approved for 1.10b's standing approval. Raised, not decided: 0011 has no command to adopt a vault with a missing or mismatched anchor (suggested for 1.13/1.14).

## Execution log

- 2026-10-30: Owner explicitly requested both Bs without the intermediate
  split. Continued 0027 on the staged tree and recombined **2.2b, Implemented**:
  atomic storage-level incoming acceptance, capability-bound safe normalized
  paths, durable encrypted filename receipts, independent conservative
  candidate and encrypted object/chunk validation, idempotent redelivery,
  unchanged working slots/counters/checkpoints and the existing commit/anchor
  path. Permanent tombstones have explicit role markers and survive covered
  dominated history, purge, later final deletion, restore and rotation;
  payload-history views omit their non-restorable metadata. Volatile manifest
  format is 0x7FFF0002; schema/header stays 0x7FFF0003, no migration.
  Eight acceptance tests cover nine crash points, cancellation, restart,
  changed filenames, bounds, malicious candidates and operational slots;
  real archive acceptance converges in all six orders with concurrent
  deletion/edit and attachments. Final SPDX/matrix/fmt/Clippy/locked suite pass:
  **679 passed, 0 failed, 2 pre-existing ignored**, private Xvfb. Affected fuzz
  compile/format pass. No dependency/unsafe/primitive change or release claim.
  C remains separate as originally scoped; no further B work is deferred.
  Changes remain uncommitted, original staged index preserved. Fresh review
  of the complete B implementation is still due before C under the ordinary
  roadmap protocol; no intermediate B review/commit was requested.

- 2026-10-30: Clean-tree next-phase session reviewed committed 0026
  (5b3462f), **Approved**, no code fixes/blocking findings. Independent gates
  pass (663 passed, 0 failed, 2 existing ignored), including matrix/deny/vet.
  Split 2.2b under the session-size rule before code. **2.2b1 implemented as
  0027**, under owner delegation preserved in 0026: bounded protected receipt
  metadata, canonical envelope/AAD and normative storage contracts, sealed
  singleton/head binding, restart/write preservation and restore/rotation
  resets. Volatile schema/header is 0x7FFF0003; older dev files reject without
  migration. No dependency, unsafe or primitive change. Six new tests plus
  parser fuzz target/CI; final SPDX/matrix/fmt/Clippy/locked tests pass:
  **669 passed, 0 failed, 2 pre-existing ignored**, private Xvfb. Fuzz build,
  format and 10,000-input uninstrumented smoke pass; no release claim.
  Actual incoming acceptance/filename recording, safe source-path traversal
  and tombstone-representation implications remain 2.2b2. Next: owner commit,
  fresh-context review of 0027, then plan b2. Changes remain uncommitted.

- 2026-10-30: Owner approved plan 0026's receipt/CLI recommendations and
  delegated remaining design choices. Before code, split 2.2 into a/b/c under
  the session-size rule. **2.2a implemented as 0026:** bounded authenticated
  private archive input, validated manifest assembly and qv-sync's shared
  whole-record candidate merge. Preserves complete versions, conflicts,
  monotonic floors and referenced attachment chunks without accepted-state
  changes or receive-time re-encryption/counters. A covered dominated final
  tombstone fails closed rather than being forgotten; see 0026's limitation.
  Fourteen new tests include real encrypted archive/store integration,
  convergence, identity/role collisions, resource bounds and private-copy
  filesystem/rejection paths. Final SPDX/fmt/Clippy/locked tests, matrix and
  deny/vet pass: **663 passed, 0 failed, 2 pre-existing ignored**, private
  Xvfb. No new external dependency, unsafe, format or normative spec change.
  Next: owner commit, fresh-context review of 0026, then 2.2b (atomic
  acceptance/filename receipts). Core/CLI resolution/export remain 2.2c.
  All changes uncommitted; no independent review or release claim.

- 2026-10-30: Clean-tree next-phase session selected 2.2. Previous phase 2.1
  (0025) is Reviewed and spec-only. Wrote Proposed plan 0026 after inspecting
  existing merge/storage/archive/core interfaces. Standing approval withheld:
  durable filename-reuse detection needs a local-state schema/head amendment,
  and conflict/merge/export commands need precise CLI contracts. Plan D1–D3
  contain recommendations for owner approval. No implementation or normative
  amendment; phase remains unticked.

- 2026-10-30: Clean-tree next-phase session (1.16 committed as `210c86c`).
  - **Reviewed 0024** with fresh context: Approved with minor fixes, see its
    REVIEW.md. The networking-blocked offline CLI test now also runs
    `recover` (the 0012 "Implicit server prerequisite" row names recovery).
    The canary audit gained the planned new-password canary. Final gates
    pass: 649 passed, 0 failed, 2 pre-existing ignored, private Xvfb.
  - **Phase 2.1:** `quickvault-thinker` laid out the D10 options. The owner
    delegated the choice ("whatever you think is best"). Plan 0025 records
    the choice: pairwise link keys, QR or manual endpoints with
    window-only discovery, explicit receive windows, and local
    generation-bound removal.
  - **Wrote Draft spec 0013**: messages, key schedule, bounds, exchange,
    peer state, windows, errors, rotation, and §13 with the exact
    amendments to 0001, 0002, 0004 and 0005 to apply on acceptance.
  - **Self-check:** four fixes, the main one being B's confirmation before
    joining in new-device mode. SPDX passes and `git diff --check` is
    clean.
  - **The phase stays unticked.** Its *Done when* needs the owner's
    acceptance of 0013 and the D12 review request (text drafted in plan
    0025). Owner direction (same day): spec-only and plan-only work needs
    no separate fresh-context review session; only implementation does.
    The session protocol now says so.
  - **0013 accepted** by owner delegation ("whatever you feel is best").
    The §13 amendments to 0001, 0002, 0004 and 0005 are applied with
    Changelog lines, and phase 2.1 is ticked. The D12 request (drafted in
    plan 0025) is the owner's to send. The next phase is 2.2. Phases 2.2–2.3 can proceed in parallel
    (2.1 entry). Changes are uncommitted.

- 2026-10-30: Clean-tree next-phase session (1.15c committed as
  `c7b6c1d`).
  - **Reviewed 0023** with fresh context: Approved with minor fixes, see
    its REVIEW.md. A failed directory fsync after the journal's rename is
    now reported as published; three hostile restart tests added; one stale
    doc comment corrected.
  - **Planned 1.16 as 0024** with standing approval. It was first split
    into 1.16a/1.16b. During the phase the owner decided there is no
    format freeze before 1.0, so 1.16b and the Android benchmarks moved to
    an unscheduled pre-1.0 release step (see *Revisions*).

  **Phase 1.16 implemented as plan 0024:**
  - all 23 offline 0012 rows have tagged passing tests, checked in CI;
  - mode, write-failure and canary audits pass;
  - the networking-blocked test is required in CI;
  - eight clean 30-minute fuzz runs and a weekly CI campaign;
  - Linux budget benchmarks at the record and ciphertext caps;
  - the dependency audit status is recorded.

  Final gates pass: 649 passed, 0 failed, 2 pre-existing ignored, private
  Xvfb. No dependency, `unsafe`, format or spec change. Next: a fresh
  review of 0024, then phase 2.1. Changes are uncommitted.

- 2026-10-30: Next-phase session. The tree held only the owner's
  uncommitted D13 roadmap revision (not phase work). It reviewed committed
  phase 1.15b (`5fe3495`, plan 0022) with fresh context: **Approved with
  minor fixes**, see its REVIEW.md. Fixes: two missing replacement tests
  (anchor mismatch, unknown extension fields) and two misplaced doc
  comments. Independent gates pass (621 passed, 0 failed, 2 ignored,
  private Xvfb). One clipboard Xvfb startup timeout in the first final run
  passed on rerun; it is recorded in that review. Phase 1.15c was planned
  as **0023** (9 steps; no decision, amendment, dependency, `unsafe` or
  deviation), with standing approval.
  **Phase 1.15c implemented as plan 0023:**
  - journal installation with crash points I1–I9: no-replace renames and
    one anchor generation step;
  - authenticated restart: each copy with its own password, both journal
    MACs and the anchor, then complete or roll back (rollback refused once
    committed);
  - removal of pre-journal leftovers;
  - inventory-aware snapshot budgets that fail closed without an
    inventory;
  - the core `Rotation` lifecycle: pinned recovery snapshot, session
    consumed, three phrase words;
  - `qvault recovery rotate` for new and resumed rotations;
  - the crash matrix at every installation step and at second-level
    crashes during completion and rollback.

  Final SPDX, fmt, Clippy and locked tests pass: 645 passed, 0 failed,
  2 pre-existing ignored, private Xvfb. No dependency, `unsafe`, profile,
  schema or spec amendment. This completes the whole-rotation scope of
  roadmap 1.15. Phase 1.16 follows after the fresh-context review of 0023
  and an owner commit. Network isolation is unavailable and not counted as
  a pass. Changes are uncommitted.

- 2026-10-29: The clean-tree next-phase session reviewed committed phase
  1.15a (`9c25a6a`, plan 0021): **Approved**, no fixes, no escalations; see
  its REVIEW.md. Independent SPDX, fmt, Clippy and locked tests pass
  (603 passed, 0 failed, 2 ignored, private Xvfb). Phase 1.15b was planned
  as **0022** and split again under the session-size rule (1.15c:
  installation, restart, core, CLI), then given standing approval.
  **Phase 1.15b implemented as plan 0022:**
  - ordinary opens refuse reserved `.qvrotate` names;
  - `prepare_rotation` builds the next generation privately: a new VK,
    phrase and slot; every object resealed under fresh IDs; logical state
    preserved; one causal keyslot edit; head +1/+1 naming the old digest;
  - it is verified again from persisted bytes as an unwritable,
    never-anchored Candidate, with a full logical and attachment comparison;
  - the per-generation MAC'd snapshot inventory, with hash-checked removal,
    an independent vector and a fuzz target (local 61 s campaign:
    473,987 runs, clean, no ASan).

  Final SPDX, fmt, Clippy and locked tests pass: 619 passed, 0 failed,
  2 pre-existing ignored, private Xvfb. No dependency, `unsafe`, profile,
  schema or spec amendment. Network isolation is unavailable and not counted
  as a pass. Nothing installs a replacement yet. The next fresh session
  reviews 0022 before planning 1.15c. Changes are uncommitted.

- 2026-10-29: Owner delegated D1; selected A and applied the narrow 0002
  offline public-key timing amendment. Split 1.15 under the session-size rule
  before code. **Phase 1.15a implemented as plan 0021**: bounded canonical
  transition journal with independent generation MACs, redacted fixed-size
  metadata and ordinary open/create/restore/write exclusion for `.qvrotate`
  markers. Refusals preserve DB/anchors, including absent-active rename gaps,
  late markers and pending-anchor retry. No production marker writer,
  replacement construction, snapshot inventory or rotation CLI yet: those
  remain **1.15b**, planned next fresh session after 0021 review and owner
  commit. No new dependency, unsafe, crypto profile or SQLite schema change.
  Independent complete development vector and journal fuzz target/CI added;
  local instrumented campaign clean (179,938 runs in 61 seconds, without ASan).
  Required SPDX/fmt/Clippy/locked tests pass: 603 passed, 0 failed, 2 pre-existing
  ignored, including private Xvfb. Logs `/tmp/qv21/`; network isolation remains
  unavailable, not a pass. Same-context implementation inspection only; preserve
  fresh-context review before 1.15b. Changes uncommitted; no commit/push/branch.

- 2026-10-29: Clean-tree next-phase session reviewed committed phase 1.14
  (`acc1021`, plan 0020): **Approved with minor fixes**, correcting only the
  plan's stale status table. No blocking product finding. Independent SPDX,
  fmt, Clippy and locked tests pass (591 passed, 0 failed, 2 pre-existing
  ignored), including private Xvfb; network namespace unavailable, not a pass.
  See 0020 REVIEW.md and `/tmp/qv21-review/` logs. Phase 1.15 planned as
  **0021, Proposed**. D1 asks whether to defer offline recovery public-key
  derivation with a narrow 0002 amendment (recommended) or bring signature
  dependencies/qv-crypto work forward. Standing approval is withheld under
  Session protocol step 4 (spec amendment or component/order deviation).
  No production code, dependencies or normative specs changed; phase unticked.
  Changes remain uncommitted; no commit, push or branch.

- 2026-10-29: Owner requested fixing the 0019 finding and implementing the
  phase without a commit boundary. Slot-bearing archives now fail integrity
  exit 7; the retained CLI regression verifies source/anchor preservation.
  Resumed fresh-context review of 0019 is Approved, plan Reviewed. Phase
  **1.14 implemented as plan 0020**: atomic complete slot/keyslot-record/header
  MAC replacement through the existing transaction/anchor path, protected
  `passwd`, reauthenticated alternate-screen `recovery show` and phrase-based
  `recover <existing.qvault>`. Missing/mismatched anchors require explicit
  baseline consent and a mandatory verified recovery snapshot. Pre-change
  snapshot deletion is offered after success with separate consent and copied-
  key/erasure limits. Lock races preserve completed password/deletion outcomes.
  Crash tests cover all nine slot/transaction/anchor boundaries; rewrap tests
  preserve entry/history/attachment ciphertext and generation. Final SPDX,
  fmt, Clippy and full locked tests pass: 591 passed, 0 failed, 2 pre-existing
  ignored, including private Xvfb. Namespace isolation unavailable, not a pass.
  No dependency, profile, format, schema or spec amendment. Standalone phrase/
  archive import and VK rotation remain deferred. All changes uncommitted;
  next fresh session reviews 0020 before phase 1.15, preserving the owner
  commit boundary and independent review requirement.

- 2026-10-28: Clean-tree next-phase session reviewed committed phase 1.13b
  (plan 0019, `f0e60d2`): **Changes requested**, see its
  [REVIEW.md](../0019-snapshot-restore/REVIEW.md). A selected slot-bearing
  snapshot is safely refused but returns exit 1 instead of spec 0011's exit 7.
  Reproduced through production CLI; no destination or source change. No
  product fixes. Plan remains Implemented with approval withheld; stopped
  under Session protocol step 2 before planning or implementing phase 1.14.

- 2026-10-28: Owner requested “fix and then implement 1.13b”, authorizing
  remediation and continuation without an intervening commit. Revised plan
  0018, fixed both review findings and completed resumed same-session review:
  Approved (not a new independent review). Archives authenticate all roles and
  attachment content before sink delivery/publication; complete-envelope
  commitments protect seek passes; failed publication preserves older copies.
  Phase **1.13b implemented as plan 0019**: `snapshot restore <id> <new-path>`,
  fresh local replica/writer/head/anchor, archived password slot and complete
  history/floor/chunk preservation, source vault/anchor unchanged. Restore
  defers pruning until input is safely restored and reports publication
  correctly when lock races with completion. Store/core/CLI, hostile-input,
  cancellation and creation-crash tests pass. Final SPDX/fmt/Clippy/locked tests
  pass: 574 passed, 0 failed, 2 pre-existing ignored, including private Xvfb;
  fuzz formatting/build pass. Network namespace isolation is unavailable, not
  a pass. No dependency/schema/format/spec change or security-proof claim.
  All changes uncommitted. Next fresh session reviews 0019 before phase 1.14;
  preserve that independent review requirement and owner commit boundary.

- 2026-10-28: Clean-tree next-phase session reviewed committed phase 1.13a
  (plan 0018, `66474cb`): **Re-plan needed**, see its
  [REVIEW.md](../0018-archives-snapshots-verify/REVIEW.md). Reproduced acceptance
  of nonce-corrupted archive objects and publication of an undecryptable
  recovery snapshot, including corrupt retained history after normal unlock.
  Also reproduced a valid-MAC header reference digest inconsistent with its
  manifest being accepted. No product fixes; plan remains Implemented with
  approval withheld. Stopped under session protocol step 2 for architect
  remediation; phase 1.13b is not planned or implemented. Reviewer checks and
  environment limitations are recorded in the review. Changes are uncommitted;
  no commit, push or branch.

- 2026-10-27: Phase 1.12 implemented as owner-approved plan 0017. Added safe
  bounded history retention/floors, authenticated history views and explicit
  reveal, whole-record causal restore with conflict consent, and floor-only
  purge preserving active heads/tombstones. CLI history/show/restore/purge and
  approved 0011 amendment complete. All final gates pass: 510 tests passed,
  0 failed, 2 ignored, including private-Xvfb integration/doctests. Focused
  history production tests also pass network-blocked with PTY cancellation/
  signals; store crash and core lock suites pass. No dependencies or format
  changes; no secure-erasure/security-proof claim. Changes uncommitted, owner
  staging preserved. Next session reviews 0017 with fresh context after owner
  commit, then plans 1.13; do not skip that review.

- 2026-10-27: Phase 1.12 started in architect role; plan 0017 Proposed with six
  steps for retention/floors, bounded history views, restore and purge. Concrete
  CLI version selection, JSON/diff attribution and explicit conflict-restoration
  consent require an 0011 amendment. D1 requests approval of the exact proposal;
  standing approval does not cover it. No history implementation/spec amendment
  applied; owner decision needed before development. Phase remains unticked.

- 2026-10-27: Phase 1.11 review findings resolved under owner-requested
  architect/developer remediation; resumed review approved plan 0016. All
  reviewer gates pass (490 passed, 2 ignored), including private Xvfb; blocked-
  network production offline and attachment suites pass. Rust 1.98.1 Cargo/
  Clippy components restored, no MSRV/dependency changes. Starting phase 1.12
  per the owner's explicit continuation instruction; no commit/push/branch.

- 2026-10-27: Owner approved plan 0016 D1 and phase 1.11 is Implemented:
  streamed fixed-size authenticated attachment chunks, measured content hashes,
  bounded staging inside the existing transaction/anchor path, core scoped
  handles/lifecycle and `attach add|ls|save|rm`. Applied the approved 0011 file
  import/export/removal amendment first. Added local model hash cleanup under
  0008; no dependency, lockfile, primitive or schema change. Final SPDX, fmt,
  Clippy and locked tests pass (489 passed, 2 ignored), including private-Xvfb
  regression coverage. New tests cover 10 MiB and chunk boundaries, corrupt
  roles/hash/length, staged rollback, eight crash points, lock/anchor failure,
  file changes, unsafe paths and overwrite/successor refusal. Namespace-blocked
  networking remains unavailable, explicitly not a pass. Changes uncommitted;
  next fresh session reviews 0016 before phase 1.12. No security proof or spec
  completion status claimed.

- 2026-10-27: Clean-tree next-phase session reviewed phase 1.10c (plan 0015):
  Approved, no code fixes/escalations. Independent root gates, deny/vet, patched
  vendor formatting and 12 transport tests pass; 474 workspace tests pass with
  2 ignored, including all private-Xvfb tests. Archive hash and exact source
  changes verified. Network namespace isolation remains unavailable, not a pass.
  Architect prepared [0016](../0016-attachments/PLAN.md) for phase 1.11, Proposed:
  streaming authenticated chunks, core lifecycle and `attach add|ls|save|rm`.
  D9 already chooses CLI attachments; the concrete 0011 amendment includes
  explicit plaintext save and confirmed permanent attachment removal semantics.
  Session protocol step 4 requires owner approval for this spec-amending plan.
  D1 pending; no implementation, normative amendment, dependency change or
  phase 1.11 tick. Review/planning changes remain uncommitted.

- 2026-10-27: Phase 1.10c implemented as owner-approved plan 0015 (D1/D2 and
  authorization for necessary correctness fixes). Added `copy`, `totp --copy`,
  `generate --copy`, config/timeout preflight, foreground countdown and signal
  cleanup with vault keys/metadata dropped before serving. Private Linux X11
  adapter (including usable XWayland) uses sensitive hints, bounded INCR/I/O,
  server timestamps and ownership-safe window release. Maintained x11rb 0.13.2
  source uses SecretBytes for outgoing buffering and validates incoming lengths
  before allocation; lifetime input is capped and FDs rejected. No arboard or
  Windows license exception needed; two recorded vet exemptions. CI runs private
  Xvfb, checker regressions and locked transport tests. All root gates, deny/vet
  pass (474 tests, 2 ignored); 12 transport tests pass. Network-namespace
  isolation remains unavailable and explicitly skipped. Native Wayland/other OS
  adapters and recipient/manager erasure guarantees are not claimed. Changes
  remain uncommitted. Next fresh session reviews plan 0015 and its local patch
  before phase 1.11; no new phase begun.

- 2026-10-27: Owner approved plan 0015 D1 and implementation. Prerequisite
  source trace then found an input-allocation gap in that plan: x11rb's reader
  forwards unbounded server length fields to a resizing protocol buffer, and
  its read/enqueue loop precedes the planned application event-batch limit.
  The plan explicitly requires stopping for this finding. Plan 0015 records
  proposed D2: extend the same vendor patch with a 1 MiB packet limit and a
  4 MiB lifetime read budget, rejecting incoming FDs. Status Blocked pending
  this correction; no product code/dependency/spec change or clipboard action.
  Independently completed the D1-approved vendor conventions/header checker
  groundwork; checker rejection tests and all root gates pass (467 passed,
  2 ignored). No vendor source or clipboard backend retained yet; D2 remains
  pending, phase unticked.

- 2026-10-27: Next-phase session reviewed committed phase 1.10b (plan 0014):
  Approved, no code fixes or escalations. Independent SPDX, fmt, Clippy, locked
  tests (467 passed, 2 ignored), deny and vet pass; see REVIEW.md. Architect
  prepared plan 0015 for 1.10c. Source inspection also found stock arboard's
  sensitive-data destructor checks ownership then unconditionally clears, so
  dropping it alone has a successor-owner race. D1 proposes direct X11 with a
  protected x11rb transport patch and narrow vendor conventions; explicit owner
  approval is required. No new phase implementation, spec/dependency change or
  checkbox completion; no shared clipboard or phone operation.

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
- 2026-10-26: Phase 1.5 reviewed (plan 0007, [REVIEW.md](../0007-data-model-merge/REVIEW.md)): Approved, no fixes. One low finding carried into phase 1.6: `qv-crypto` IDs with public fields can be encoded without the v4 bits, and decode rejects them. Nothing blocking escalated.
- 2026-10-26: Phase 1.6 implemented as plan 0008 (standing approval; no stop for the owner). New crate `qv-store`: owner-only file checks (symlinks, nonregular files, group/other modes and unsafe parent directories refused, never repaired), a `flock` process lock on the vault file's own descriptor, file identity (`Replaced`), location warnings (sync folders, network filesystems, removable media), SQLite opened with every 0004 §1.2 setting read back plus limits, an execution-step budget and a 2 GiB cap before parsing, `quick_check(1)`, exact-schema validation and independent row checks, the header (canonical CBOR, unknown keys fail closed) and the local password slot (the `qv_model::Keyslot` descriptor) under the header MAC, atomic `create` (temp file, `RENAME_NOREPLACE`, directory fsync) and `open` → `unlock` (wrong password only from the slot; a header-MAC failure is always `Integrity`). New dependency `rusqlite 0.40.2` with bundled SQLite 3.53.2 (candidate table; 0.41.0 was too new). New transitive crates were pinned to releases at least two weeks old (`cc 1.8.0`, `smallvec 1.16.3`, `find-msvc-tools 0.1.14`), with 5 vet exemptions. `rustix` gains `fs`. `.cargo/config.toml` trims the SQLite compile options (no FTS, R-Tree, dbstat, JSON, extension loading or URI filenames), and a test checks them. The plan 0007 review finding is fixed: `qv-model` no longer encodes non-v4 `qv-crypto` IDs, and it gains a public keyslot codec. Tests: tamper suite through the public API (every rejected open leaves the file byte-identical), second-process lock, wrong password vs integrity on the same file, hardening failures; new `vault_open` fuzz target plus a CI step (60 s local run clean, 855,970 runs). All gates, deny and vet green (314 tests). Notes for later phases are in plan 0008's log (heuristic warnings, development limits, stale `.tmp-` files after a crash, the non-Linux stub compiled only on Linux). Not reviewed yet: the next session reviews it first. Next: phase 1.7 ("next phase").
- 2026-10-26: Phase 1.6 reviewed (plan 0008, [REVIEW.md](../0008-vault-file-sqlite/REVIEW.md)): **Changes requested**, one high finding escalated. A hot `-journal` planted next to the vault by another user is rolled back by SQLite before validation and can destroy the vault. The plan's parent-directory rule (sticky or own-GID group-writable parents allowed) is looser than 0004 §1.1. Phase 1.7 waits until the owner chooses the directory rule and the fix lands in plan 0008. Three low findings were noted for 1.7/1.10.
- 2026-10-26: Owner chose both remedies for the plan 0008 finding; fixed within plan 0008 (parent rule per 0004 §1.1, SQLite sidecar checks, a refused `-wal`/`-shm`, tamper tests), 319 tests green. Plan 0008 `Reviewed`. Next: phase 1.7.
- 2026-10-26: Phase 1.7 implemented as plan 0009 (owner approval, not standing approval: the plan amends 0004; D-A and D-B accepted as recommended). 0004 §2/§4.1/§4.2 amended (aggregate clock-component budget, `replica` row). `qv-store`: unlinkable object envelopes and record encryption with the canonical AAD; the encrypted manifest (heads, history, floors, chunk lists, sorted references, configuration digest, control-record IDs) with streamed envelope hash and reference digest, bounded and validated before allocation; the MAC'd local head; per-replica external anchors with atomic replacement; writer ID and counters in the `replica` row, reserved in the using transaction; schema 2; `create` with the three control records; unlock verification per 0004 §3.6 and the 0005 §5.4 anchor table, failing closed (`Rollback`, `NoAnchor`) with `unlock_for_recovery` + `adopt_baseline` as explicit recovery; the single mutation transaction with the head re-read inside `BEGIN IMMEDIATE`; `SQLITE_FULL` told apart from a full disk. `qv-crypto`: `local-state` is a MAC key; `qv-model`: public clock codec. Tests: a test-only crash harness at all 8 mutation points and both create points (old or new state as specified; a page-cache-spilling transaction exercises a real hot-journal rollback), rollback suites (old DB + newer anchor, two ahead, fork, other installation), tamper suites, a DB-wide linkage scan, `put_local` rules, a property test, and the generated worst-case manifest (50.0 MiB sealed of 64 MiB). New `manifest_decode` fuzz target plus a CI step (60 s local run clean, 34.8 M runs; `vault_open` re-run clean). No dependency change. Gates: SPDX, fmt, clippy `-D warnings`, `cargo test --locked` (361 passed, 2 ignored). Not reviewed yet: the next session reviews it first, and should look again at the plan 0008 follow-up fix (`fs.rs`, sidecar tests) as that review asked. Next: phase 1.8 ("next phase").
- 2026-10-26: Phase 1.7 reviewed (plan 0009, [REVIEW.md](../0009-objects-manifest-anchor/REVIEW.md)): Approved with minor fixes. `adopt_baseline` skipped the pending-anchor retry, so a recovery after a failed anchor write could leave the DB two commits ahead of its anchor (a false `Rollback`); fixed with a test. The plan 0008 follow-up (`fs.rs`, sidecar tests) was re-checked with no findings. Carried forward: redact or never log the manifest types' `Debug` (1.8), and refuse an anchor directory next to the vault (1.10). Nothing escalated.
- 2026-10-26: Phase 1.8 implemented as plan 0010 (standing approval; no stop for the owner). New crate `qv-core`: `Core` (process hardening and a protection report, create with the recovery phrase, unlock, recovery unlock with `adopt_baseline`), `Session` (serialized calls, `lock` cancels running work, zeroizes and is final, random-tag handles that other sessions cannot use), the metadata index (non-protected metadata only, 64 MiB budget, rebuilt from every head and refreshed per commit), listings over the repaired group tree with recovered items, trash, read-only conflicts, search over titles, group names and non-protected text/URL/e-mail fields (no search index), on-demand details, reveal and TOTP, drafts with base versions for entries, groups and settings, moves, recursive soft delete, restore, explicit final deletion with attachment tombstones, and the expiry report with clock-anomaly detection. `qv-store`: a final tombstone drops history and advances the floor, and the manifest types print a redacted `Debug` (review 0009 finding 3). `qv-model`: generator defaults at settings key 2. Tests: lifecycle, lock races at three pause points, refusals that write nothing, trash flows, a public-API offline lifecycle test and a random-operations property test (index after edits = index after reopen). No new external dependency (dev-only use of the workspace crate `qv-encoding`). All gates, `cargo deny` and `cargo vet` green (400 tests). Notes for later phases are in plan 0010's log. Not reviewed yet: the next session reviews it first. Next: phase 1.9 (needs D7, Android devices and SDK) or 1.10, which the roadmap lets swap with 1.9 ("next phase").
- 2026-10-26: Phase 1.8 reviewed (plan 0010, [REVIEW.md](../0010-core-sessions/REVIEW.md)): Approved, no fixes. One low finding carried forward: saving new generator defaults over a key-2 value this version cannot read fails with `DuplicateKey` (fails closed as `InvalidInput`); 1.10 may fix it, 2.5 must. Nothing escalated.
- 2026-10-26: Phase 1.10 planned as [plan 0011](../0011-cli-foundation-read/PLAN.md) (1.10a, `Proposed`). Stopped for the owner, since standing approval doesn't apply: new dependencies outside the candidate table (`zxcvbn`; `signal-hook` and the BSL-1.0 licence of arboard's Windows backend, both for 1.10b), where the recovery-phrase skip is recorded (0002 §4.2), and the proposed split into 1.10a/1.10b. Phase 1.9 still waits for D7.
- 2026-10-26: Phase 1.10a implemented as plan 0011 (owner approval, not standing approval: new dependencies, D-5 and the split; D-1–D-6 accepted as recommended, and D-7 found during step 2 and resolved by the owner: a zxcvbn estimate at its 64-bit ceiling counts as Strong, 0010 §3.2 amended). New crate `qv-cli` (`qvault`): `init` (suggested passphrase, zxcvbn verdict with the 5-second weak-password confirmation, recovery phrase on the alternate screen, three-word check or a recorded skip at settings key 3), `info` (unverified header; `--full`), `ls`, `search`, `show`, `totp`, `generate`; config (strict TOML subset), vault selection, `--password-stdin`, `--json`, no-echo raw-mode prompts, escaping of all vault text, zeroizing output written straight to the descriptor, exit codes. `qv-core`: `harden`, `inspect`, `password_strength`, `confirmation_positions`, `id_hex`/`find_id`, `record_recovery_skip`, and the anchor-location refusal (review 0009 finding 2). `qv-model`: the review 0010 finding 1 fix. New dependencies `clap 4.6.7` (builder) and `zxcvbn 3.1.1` (its wasm32-only dependencies also enter the lockfile); `deranged` pinned to 0.5.8. Gates green (453 tests), `cargo deny` and `cargo vet` green. The networking-blocked offline test is skipped in this sandbox (no user namespaces); it is logged as not a pass. Not reviewed yet: the next session reviews it first. Next: phase 1.10b (editing, trash, clipboard; D-3/D-4 already approved) or 1.9 once D7 is resolved ("next phase").
- 2026-10-26: D7 resolved by the owner: no named devices; the supported Android baseline (arm64, Android 10+, ≥ 4 GB RAM) is recorded in 0009 §2. Phase 1.9 is no longer blocked by D7, but needs the Android SDK/NDK and a connected device for its on-device parts.
- 2026-10-26: `scripts/setup-android.sh` added and run: command-line tools (SHA-256 pinned), platform 35, build-tools 35.0.0, NDK r27 (27.3.13750724), Rust targets `aarch64-linux-android` and `x86_64-linux-android`. In the agent sandbox `$HOME` is read-only, so the SDK lives in the git-ignored `.android-sdk/`. `qv-core` and `qvault` cross-compile for arm64 Android (API 29). For on-device work, the session asks the owner to connect their phone.

- 2026-10-26: Next-phase session reviewed phase 1.10a (plan 0011): **Changes requested**, [REVIEW.md](../0011-cli-foundation-read/REVIEW.md). Escalated EOF-CR password parsing and recursive-listing resource handling. Stopped under session protocol step 2; no new phase plan or implementation started.

- 2026-10-26: Owner authorized remediation of plan 0011's review findings.
  Fixed EOF-CR handling, recursive listing and retained path prefixes, with
  regression tests and incremental listing/search output. Phase 1.10a fixes
  await fresh-context review; no new phase started. See plan 0011's log for gates.

- 2026-10-26: Fresh-context review approved plan 0011 remediation; phase
  1.10a is Reviewed. EOF-CR and deep-traversal findings resolved, no further
  code fixes or escalations. Independent SPDX, fmt, Clippy and locked tests
  passed (456 passed, 2 ignored); network isolation remains unverified here.

- 2026-10-26: Plan [0012](../0012-cli-edit-trash/PLAN.md) proposes editing,
  trash and signal cleanup as a revised 1.10b, with clipboard in 1.10c.
  Source inspection found ordinary non-zeroizing plaintext buffers in
  arboard's X11 storage and x11rb's outgoing transport. Existing arboard
  approval does not settle that integration issue. Stopped for owner D1
  (scope split); standing approval does not apply. No implementation or
  phase checkbox change. Phase 1.9 still needs physical-device access.

- 2026-10-26: Owner corrected the session's phase selection: proceed with
  unfinished phase 1.9, not 1.10b. Unapproved plan 0012 is Abandoned; its
  proposed split never took effect. Phone is now reachable via the owner's
  adb server at localhost:5037. Read-only model/API/ABI/RAM queries confirm
  the D7 baseline (model 2412DPC0AG, API 35, arm64, about 11 GiB RAM).
  Owner requires device work to be limited to the locally built spike and
  relevant diagnostics; no rooting, personal-data access, security-setting
  changes or deletion of existing apps/data. No APK installed yet.

- 2026-10-26: Phase 1.9 planned as [0013](../0013-ui-feasibility/PLAN.md),
  Proposed. Phone access resolved; prerequisite evidence is in REPORT.md.
  Standing approval does not apply yet: direct GTK/JNI bindings are outside
  the candidate table, and Draft 0008 §4 is outside D5's named sections.
  D1/D2 need the owner's go-ahead. No implementation, install or phase tick.

- 2026-10-26: Owner resolved D8: use Dioxus and standard webview input; stop
  treating inability to wipe every framework copy as a blocker. Approved
  amendments to 0008/0009 and matching cross-references in 0002/0012,
  architecture, agent guidance and plan 0013. Application Rust secret handling,
  lock/cancellation, no-log/persistence, OS prerequisites and active-content
  requirements remain. No GTK/JNI input workaround, fork or custom engine.

- 2026-10-26: Plan 0013 revision implements the owner's Dioxus input decision
  in specs/docs and starts the isolated spike. Controller tests and host UI
  compilation/Clippy pass, but four upstream dependency advisories fail the
  unchanged advisory policy. D3 requests their disposition for the disposable
  spike; no ignores added. GUI linking also needs libxdo development files;
  device/runtime/benchmark evidence remains pending. Phase 1.9 stays unticked,
  plan Blocked. No phone install or personal-data/settings operation.

- 2026-10-27: Phase 1.9 continues under plan 0013. Owner installed libxdo and
  authorized the documented spike-only advisory exceptions. Linux runtime and
  five full-profile unlock samples observed; root/spike gates and isolated
  deny/vet pass. Android arm64 APK builds and is inspected. Phone installation
  succeeded after owner resolved its restriction, but initial UI was white:
  restored Dioxus-required Android socket permission and loopback-only network
  policy omitted by the custom manifest. Rebuild/reinspection and fresh install
  follow owner uninstall request. Device flow/measurements remain pending;
  phase stays unticked. No phone settings or personal data touched by the agent.

- 2026-10-27: Phase 1.9 Implemented (plan 0013). Owner confirmed physical
  Android create/edit/reopen, Home/background lock, screenshot refusal and API
  availability probe. Retained five full-profile unlock samples per platform:
  Linux median408ms, Android median865ms. Actual app-only RSS samples and limits
  in REPORT.md. Restored Dioxus loopback packaging and canonical app root without
  weakening store checks. All final root/spike gates plus deny/vet pass. Adapter,
  webview release-hardening and broader-device gaps remain documented; this is
  feasibility, not production validation. Next session reviews with fresh context.

- 2026-10-27: Phase 1.9 fresh-context review approved (plan 0013,
  REVIEW.md): all independent root/spike gates pass, no fixes or new blocking
  feasibility findings. Reviewed retained device evidence; no new phone actions.
  Next remaining phase is 1.10b. Architect prepared plan 0014, Proposed:
  editing/trash/signals first, clipboard in a separately designed 1.10c.
  Reconfirmed arboard plaintext retention, x11rb write-buffer copies and
  unconditional clear semantics; no application clipboard code exists yet.
  Owner decision D1 is pending; the scope split is not applied or approved.
  Session protocol step 4 prevents implementation until that decision. No phase
  checkbox, dependency policy, production code or spec changed for this proposal.

- 2026-10-27: Owner approved plan 0014 D1 option A: split remaining CLI into
  1.10b editing/trash/signals and 1.10c clipboard; implement 0014 now.

- 2026-10-27: Phase 1.10b implemented as owner-approved plan 0014: add/edit,
  prompted notes/protected values and -i, mkdir -p/mv/rm, trash ls/restore/empty,
  safe SIGINT/TERM/HUP flag handling, bounded input polling and terminal/alternate-
  screen restoration. All gates including deny/vet pass; 467 tests pass with
  2 ignored. PTY persistence/refusal/signal tests and offline write/restore flow
  pass; blocked-network namespace check remains unavailable and is reported as
  skipped. Only approved signal-hook/registry added, with two recorded initial
  vet exemptions. Core/crypto/model/store APIs and formats unchanged; no spec
  promoted to Implemented. Changes uncommitted. Next fresh session reviews
  plan 0014, then plans 1.10c clipboard integration and its remaining decisions.

- 2026-10-27: Next-phase session began with a clean tree at `b42c5ed`.
  Fresh-context review of phase 1.11 (plan 0016) requests changes: confidential
  content-hash comparisons lack a constant-time contract (0008 §2). Independent
  SPDX passes, but fmt/Clippy/tests cannot start because the pinned Rust 1.98.1
  musl Cargo component is unavailable following a component-install conflict.
  See plan 0016 REVIEW.md and /tmp/opencode/qv17-review/ logs. Session protocol
  step 2 stops progression; phase 1.12 was not planned or started. No product
  code, dependency or spec changed; no commit, push or branch.

- 2026-10-28: Next-phase session began with a clean tree at `2dc7ac5`
  ("phase 1.12"). Fresh-context review of phase 1.12 (plan 0017) approved
  (`plans/0017-entry-history/REVIEW.md`): retention/suppression floors, purge
  and restore semantics re-derived from the code, one write path confirmed,
  five low and one informational findings, none blocking. All gates passed;
  `cargo test --locked` 510 passed / 0 failed / 2 ignored with the private
  Xvfb (the two clipboard failures without it are environmental). Plan 0017
  and the index moved to `Reviewed`. Architect planned phase 1.13 as plan 0018
  and split it (see *Revisions*); the concrete 0011 `snapshot`/`verify`
  amendment needed owner approval (D1), which the owner gave as written on
  2026-10-28. Phase 1.13b remains for a later session.

- 2026-10-28: Phase 1.13a implemented (plan 0018, `Implemented`): 0007 §3 D6
  amendment and the 0011 snapshot/verify contracts; `qv-store` archive header
  codec, writer with the temp → re-read/verify → fsync → no-replace publish
  protocol, the bounded authenticate-then-parse reader in the 0004 §6.3 order,
  the `archive_read` fuzz target (CI-wired, 73,982 local runs, no finding) and
  `verify_all`; `qv-core` snapshot policy (hourly/first-of-day, 30 d / 48 /
  512 MiB pruning, pinned pre-destruction copy, authenticated listing) and
  `verify`; CLI `snapshot ls`, `verify` and the `trash empty` recovery-snapshot
  ordering; named evidence for the four 0012 rows. All gates pass with 560
  passed / 0 failed / 2 ignored; no dependency, `unsafe`, schema or MSRV
  change and no second write path. `snapshot restore` is deferred to 1.13b.

- 2026-10-31: Clean next-phase tree at 4eeb787. Fresh-context 0027 review Approved: independent required gates and affected fuzz compilation pass, 679 tests passed / 0 failed / 2 ignored. Plan 0028 starts archive commands under prior explicit 0026 delegation; c2 retains conflict/slot resolution.

- 2026-10-31: Phase 2.2c1 Implemented (0028). Core/CLI merge and immutable
  export now enforce mandatory serialized recovery copies, view preflight,
  preserved conflicts/working slots and explicit self-contained consent. Exact
  optional header-slot/CLI contracts amended under the prior 0026 delegation.
  All final root gates, deny/vet and affected fuzz compilation pass: 689 passed,
  0 failed, 2 ignored. Only internal dependency edges changed in root/prototype
  locks; prototype GUI was not built. Next fresh session reviews 0028, then
  plans 2.2c2 conflict/slot resolution after the owner's commit. Uncommitted;
  no release/security claim or D13 change.

- 2026-10-31: Owner-directed combined phase 2.2c Implemented (0028). Complete
  archive exchange/export, all-kind masked conflict inspection and complete
  version resolution, selected-slot proof/atomic adoption, bounded attachment
  restaging and working-source-slot snapshot recovery. No C subphase remains.
  All final gates, deny/vet and affected fuzz compilation pass: 699 tests passed,
  0 failed, 2 pre-existing ignored. Owner's staged index preserved; continuation
  remains unstaged/uncommitted. Next fresh session reviews all of 0028 before
  phase 2.3. D13 and release gates remain unchanged.
