# Plan 0021 — Rotation journal and open safeguards (roadmap 1.15a)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-29 | 2026-10-29 (owner: use best judgment; D1 A) | 0002 §2.2/§3.5/§4; 0003 §2; 0004 §1–5; 0005 §5.4 (D5); 0007 §3; 0008 §1–3/§5 (D5); 0011 §3–6; 0012 §1 |

## Intent

Build the bounded rotation journal and ordinary-access safeguards for an
interrupted generation transition. This is the independently reviewable
foundation for `qvault recovery rotate`; replacement construction and the
user-facing workflow follow in roadmap 1.15b. Review phase 1.14 first.

## Scope

**Revision 2026-10-29:** split roadmap 1.15 into 1.15a (this plan: spec
amendment, bounded journal codec/MACs, normal-open/create/restore exclusion,
fuzzing and rejection evidence) and 1.15b (a fresh-session plan for replacement
construction, snapshot inventory, durable installation/restart and the CLI).
The earlier full design below is retained as follow-up design context, not
permission to execute the deferred installation or inventory steps here.
No production API writes a rotation journal in 1.15a, and `recovery rotate`
remains unavailable until 1.15b. This split uses the roadmap's explicit
architect authority to split a phase that is too large for one session.

Original whole-rotation scope (1.15a + 1.15b):

In scope: mandatory recovery snapshot, serialized rotation, replacement DB,
protected new-password/phrase confirmation, durable journal, explicit restart
recovery, ordinary-open refusal during an unfinished transition, one-step
anchor advancement, cancellation/crash/concurrent-open tests and documentation.

Out of scope: remote publication, LAN enrollment, old-generation edit salvage,
quick-unlock implementations, profile changes, compatibility migration of old
development vaults and erasure of historical copies. Reject configured remote
state rather than stripping it or treating it as an offline transition.

## Spec basis

| Behaviour | Spec | Status | Notes |
|-----------|------|--------|-------|
| New VK/generation, stable logical IDs/clocks | 0002 §2.2/§3.5 | Accepted | Checked increment; preserve retained data |
| Independent recovery signing seeds | 0002 §3.3/§3.5 | Accepted | Public-key derivation timing needs D1 |
| Full replacement verification and journal | 0002 §3.5.2/§3.5.4 | Accepted | Both credentials may be needed after restart |
| Head/anchor generation step | 0005 §5.4 | Draft, D5 authorized | Same replica anchor, sequence +1 |
| Snapshot pin and disk limits | 0007 §3 | Accepted | Durable pin survives process exit |
| Protected prompts and typed confirmation | 0011 §3/§4/§5.5; 0010 §4.2 | Accepted | `--yes` never bypasses rotation confirmation |
| Secret and hostile-input handling | 0008 §1–3/§5; 0004 §4 | Draft/D5; Accepted | No plaintext keys in durable state |

Spec changes under owner-approved D1 A: amend 0002 §3.5.1 as described
below, with its Changelog and specs index updated. Step 1 records the approved amendment. Implementation scope is phase 1.15a
only, as revised below; the installation design remains follow-up context.

## Decisions needed

1. **D1 — Timing of recovery public-key derivation.** 0002 §3.5.1 currently
   requires generating recovery public keys even for an offline-only rotation.
   The implementation has the two independent purpose-key derivations
   (`qv-crypto/src/keys.rs`), but no signature implementation or stored recovery
   public-key interface. Roadmap 0002 schedules signature dependencies for
   2.8/3.x; phase 1.15 lists store/core/CLI only.

   **A (recommended):** amend the final sentence of 0002 §3.5.1 to:

   > Generate new VK, generation number (previous + 1), recovery phrase and
   > password slot. Recovery signing seeds remain independent derivations of
   > the new VK under §3.3. Derive their public keys before any operation that
   > publishes or uses recovery identities; an offline-only vault with no
   > configured sync may defer public-key derivation until such configuration.

   This plan then uses existing dependencies only. It does not authorize LAN
   or remote transitions, replace the signature profile or weaken independent
   device approval. The new generation replaces both derived seeds regardless
   of whether their public keys are materialized.

   **B:** retain the spec unchanged and bring recovery public-key derivation
   forward into `qv-crypto` now. Before development, revise this plan with exact
   `ed25519-dalek`/RustCrypto `ml-dsa` versions/features, their transitive inputs,
   secret-buffer lifecycle, upstream vectors and deny/vet evidence. These are
   roadmap candidates, not already approved dependencies or audit evidence.
   No signature or KEM primitive may be written locally.

   Blocks: step 1 and implementation approval. Resolution: owner delegated
   the choice on 2026-10-29 ("Whatever you feel is best"); selected A.

## Design

### Current phase 1.15a

Add platform-independent `qv_store::{RotationJournal, RotationJournalBody,
RotationSide, MAX_ROTATION_JOURNAL_BYTES}`. Body fields are fixed-size public
non-secret metadata (redacted Debug): operation UUIDv4, vault UUIDv4, replica
ID, old/new generation and local sequence, old/new local-head digests, random
16-byte filename suffix, recovery snapshot ID and snapshot-inventory digest.
`RotationJournal::sign(body, &old_vk, &new_vk)` validates structural bounds
and computes both MACs; `decode(&[u8])` checks the 4096-byte cap before parsing
and is explicitly untrusted until `verify(&vk, side)` succeeds. `body()` borrows
the body; `encode()` produces exact canonical bytes. These APIs cannot publish,
rename, delete, adopt an anchor or establish another generation's authenticity.
Both independent copies and the external anchor remain prerequisites in 1.15b.

Wire: canonical map keys 0–14: format 1; operation ID; vault ID; replica ID;
old generation; new generation; old sequence; new sequence; old head digest;
new head digest; suffix; snapshot ID; inventory digest; old MAC; new MAC.
Each MAC uses that generation's existing local-state key, MAC/1 and canonical
`["qv/rotation-journal/v1", body]`, where body is the canonical map of keys
0–12. MACs cover identical body bytes; old/new generation and sequence must
be positive checked increments, and generation fits u32. Reject unknown keys
or format, malformed IDs/lengths, noncanonical/trailing data, excessive input,
and transitions with identical head digests. Replica/suffix/snapshot IDs are
opaque 16-byte identifiers, not paths. No new dependency/profile/unsafe.

At every ordinary `VaultFile::open`, lstat `<path>.qvrotate` before and after
acquiring the existing inode lock, before SQLite opens it. Any existing marker
(including symlink, directory or malformed bytes) returns Integrity; other
lstat errors propagate redacted. Creation and archive restoration refuse the
marker before any source parsing, output allocation, anchor write or publish;
repeat immediately before publication. Recheck locked-file identity before
SQLite ingestion. Source mutations must refuse a marker if one appears after
unlock; use existing identity checks to cover reads/writes centrally. Existing
restore/no-replace and process-lock protections remain in force. Core and CLI
map the refusal through existing Integrity/exit 7; no new exit code or public
error variant is needed in this foundation phase.

Tests exercise actual entry points with byte-identical source/anchor evidence,
existing/missing/malformed vaults, symlink/directory/empty marker, interrupted
replacement (active path absent), late marker creation before a write and the
second check after locking. Fuzz decode/encode equality and both MAC rejection
paths using fixed test keys, a deterministic valid seed and hostile bytes.

### Whole-rotation follow-up design (phase 1.15b; not current scope)

Components: qv-store owns replacement construction, the bounded journal and
filesystem installation; qv-core owns exclusive session authorization,
mandatory snapshot/pin and lifecycle; qv-cli owns protected prompts. No new
product crate. Existing record/chunk encryption and head/anchor signing are
reused. Replacement construction shares hardened creation helpers with restore;
do not create a second implementation of SQLite security settings or schemas.

### Interfaces

Names can follow existing conventions; contracts and ownership are fixed:

```rust
// qv-store; these types have redacted Debug, no Clone or key accessors.
pub struct PreparedRotation { /* old/new locked copies and protected keys */ }
pub enum RotationChoice { Complete, RollBack }
impl UnlockedVault {
    pub fn prepare_rotation(
        self, password: &MasterPassword, cancelled: &dyn Fn() -> bool,
    ) -> Result<PreparedRotation, StoreError>;
}
impl PreparedRotation {
    pub fn phrase(&self) -> &RecoveryPhrase;
    // Reauthenticates the persisted replacement before making a journal.
    pub fn verify_password(&self, password: &MasterPassword)
        -> Result<(), StoreError>;
    // Only after core has recorded explicit phrase confirmation.
    pub fn install(self, cancelled: &dyn Fn() -> bool)
        -> Result<(), StoreError>;
}
// qv-core: consumes the session's Open state, invalidates handles and freezes
// ordinary calls; errors cannot leave a session referring to a replaced inode.
pub struct Rotation { /* prepared store operation plus recovery-copy guard */ }
impl Session {
    pub fn prepare_rotation(
        &self, new_password: &MasterPassword, allow_snapshot_over_budget: bool,
        cancel: Option<&CancelToken>,
    ) -> Result<Rotation, CoreError>;
}
impl Rotation {
    pub fn phrase(&self) -> &RecoveryPhrase;
    pub fn confirm_word(&self, position: usize, input: &[u8])
        -> Result<bool, CoreError>;
    pub fn finish(self, password: &MasterPassword, cancel: Option<&CancelToken>)
        -> Result<(), CoreError>;
}
```

Core also exposes `resume_rotation(path, old_password, new_password, choice,
cancel)` through Core. It opens only the exact files identified by the bounded
journal, verifies each available copy and the anchor, and applies the state
table below. Credentials stay `MasterPassword`; neither path nor journal
contents are a source of credentials. No arbitrary DB path/SQL/key bridge is
exposed to frontends. Returning a Rotation closes the original session to all
ordinary APIs; a new unlock is required after completion or safe cancellation.
Store's `SnapshotDir::inventory(&UnlockedVault)` returns bounded authenticated
inventory rows; `remove_inventory_entry(&UnlockedVault, archive_id)` verifies
the recorded file hash, removes it durably and atomically updates that inventory.
Rows expose only the aggregate-policy fields above and have redacted Debug;
core never receives a raw MAC key or an arbitrary deletion path.

### Replacement state

- Require a current verified anchor and no remote checkpoint/configuration.
  Fully verify every head, retained history version and attachment before use.
  Refuse unresolved control-record conflicts (ordinary entry conflicts remain).
- Take and durably pin a mandatory verified recovery snapshot before building.
  Snapshot failure, insufficient space or declined over-budget permission
  aborts rotation. A restart must never reclassify this pin as an ordinary copy
  while the transition journal exists.
- Preserve budget enforcement across generations: the current snapshot policy
  authenticates only the active generation, so it cannot simply be reused after
  dropping the old VK. Before installation, build a private authenticated
  inventory of retained older snapshots from headers verified with the old VK
  and the previous verified inventory. Each row contains archive ID, generation,
  authenticated creation time, size, ordinary/recovery classification and the
  streamed SHA-256 of the complete archive. No old VK is retained. Bound the
  inventory to 4096 rows/1 MiB; overflow aborts before publication.
  MAC its canonical body with the new local-state key over
  `["qv/snapshot-inventory/v1", body]`, storing it beside the journal under the
  same owner-only/atomic rules. Include its whole-file digest in the rotation
  journal and publish it before anchor advancement. Snapshot policy includes
  these rows in per-vault count/byte/age budgets, verifies file identity/hash
  before removal, and never attempts automatic old-generation restore/merge.
  Missing/corrupt inventory fails snapshot policy closed with a visible warning;
  it never authorizes pruning or unlimited new snapshots. Updates are atomic;
  stale rows for already removed files are harmless. Rotation carries forward
  and reauthenticates this inventory; the typed CLI warns that retained old
  copies need their old phrase. The in-progress recovery copy is excluded from
  ordinary pruning until anchor-confirmed completion.
- Check generation and local-sequence addition for overflow before work.
  Generate a fresh VK, fresh password slot and fresh object IDs/nonces.
  Preserve record/version IDs, clocks, modification times, tombstones, floors,
  unknown optional fields and all currently retained history. No incidental
  retention pruning during rotation.
- Stream attachment chunks through existing protected chunk paths; update
  encrypted chunk references and hashes consistently. Use a bounded mapping
  from old object IDs to new IDs (at most the manifest object budget), reusing
  one new object for each shared old object. New manifest references match
  exactly the rebuilt roles and chunks.
- Replace the current encrypted keyslot descriptor and its operational row
  together, retaining the logical keyslot head ID/clock within the new
  generation. Historical descriptors remain historical payloads; they cannot
  wrap the new VK. Changing generation permits rebuilding immutable envelopes.
- Retain replica ID/writer/counter so the same external anchor protects the
  transition. New head: generation +1, local_seq +1, previous_digest = old
  head digest; no remote checkpoint. Sign with the new local-state key.
  Invalidate old quick slots; the current schema has none and rejects unknown
  slot types. Never silently retain an unrecognized device/key-bearing feature.
- Commit the replacement using shared creation/transaction helpers, close its
  SQLite connection, fsync and reopen hardened. Run full verification from
  persisted bytes, compare complete logical state, and successfully unlock its
  password slot using the replacement password. Confirm three random words
  through the existing protected phrase machinery before journal publication.

### Journal and installation

Use owner-only regular siblings of the active vault. Generated names are
`<vault-name>.qvrotate`, `<vault-name>.qvrotate-old-<32 hex>` and
`<vault-name>.qvrotate-new-<32 hex>`. No user-provided alternate directory and
no absolute or traversing path inside the journal. Journal size cap: 4096 bytes.
Creation uses exclusive/no-follow opens, parent checks, atomic replacement and
file plus directory fsync. A canonical CBOR map contains format 1, operation
UUIDv4, vault ID, replica ID, old/new generation and sequence, old/new head
  digests, generated suffix, recovery snapshot ID, snapshot-inventory digest
  and two MACs. All fields are
required; unknown fields/versions, bad lengths and noncanonical data fail closed.
MAC each exact body with its corresponding generation's local-state key over
canonical `["qv/rotation-journal/v1", body]`. Neither MAC alone authorizes
accepting the other generation; each retained DB independently authenticates
the matching digest and must relate to the external anchor.

Installation ordering:

1. Fully built/verified replacement and confirmed phrase/password; fsync its
   directory entry. Until this point cancellation drops private output and
   keeps the active vault and anchor unchanged.
2. Publish and fsync the journal, including the durable recovery pin, before
   changing the active name. From here a failure/cancellation leaves a
   recoverable transition and blocks ordinary writes. Keep both inode locks.
3. Move active to the unique old name with no replacement; fsync directory.
4. Move replacement to active with no replacement; fsync directory. If either
   destination already exists or identities differ, stop without overwriting.
5. Verify active new head and advance the existing replica anchor using the
   same anchor storage and one-step comparison used by ordinary commits.
6. Only after the new anchor is durable, remove the retained old DB, fsync the
   directory, release the recovery pin, then remove/fsync the journal last.
   Snapshot cleanup failure is reported as committed rotation with retained
   recovery material, never a rolled-back operation.

All ordinary opens, including `recover`, inspect the rotation marker before
and after acquiring the vault lock, before SQLite ingestion or anchor repair.
Preexisting opens hold the active inode lock and prevent rotation; installers
hold old/new locks across renames. A stale opener must recheck inode identity
before opening SQLite. Missing active path plus a marker means interrupted
rotation, not permission to create/restore a different vault there. New-vault
creation/restore also refuse the marker and reserved destinations. Recovery
serializes on the journal file and rechecks its identity before mutating.

Restart state table (filenames alone never establish identity):

| Verified files/anchor | Complete | Roll back |
|-----------------------|----------|-----------|
| Old active + new sibling, old anchor | Install verified new copy | Remove private candidate and journal; old stays active |
| Active missing + old/new siblings, old anchor | Install verified new copy | Restore verified old copy |
| New active + old sibling, old anchor | Advance anchor, then cleanup | Restore old copy before advancing any anchor |
| New active, new anchor | Finish cleanup only | Refuse generation regression |
| Missing required copy, wrong digest/MAC, other anchor | Integrity error; preserve evidence | Integrity error; preserve evidence |

Recovery requires both old/new credentials while both copies participate.
After new-anchor confirmation, the new credential suffices for cleanup by
independently verifying that anchor/head; unverified journal claims cannot
authorize deletion of arbitrary files. An orphaned private candidate from
before journal publication is never automatically installed or opened.

### CLI, secrets, errors and dependencies

`recovery rotate` rejects JSON and password-stdin before secrets, requires TTY
input/output and always asks the user to type `rotate`, even with `--yes`.
Authenticate the existing vault, show the copied-key/history limits, choose a
new password with existing strength/delay rules, and confirm the new phrase
on the alternate screen. An existing journal presents explicit complete or
rollback choices and prompts for necessary credentials; there is no silent
baseline adoption or automatic rollback. No fixed-duration promise.

All keys/passwords/plaintext/chunks use existing protected containers. Check
cancellation around KDF and between bounded objects. No key/phrase/plaintext,
user metadata or credentials enter journals, logs, argv or error payloads.
Malformed transition state is integrity exit 7; lock/replacement is 6;
control conflict 8; bounds/overflow 9; wrong credentials 3; usage 2; I/O and
cancellation 1. Post-install errors explicitly state that rotation may already
have committed and direct the user back to the journal recovery workflow.

Dependencies: none under D1 A. Existing CBOR, crypto, SQLite and rustix
interfaces suffice; no unsafe or new crypto profile. D1 B requires a revised
dependency review before approval. New development journal layout is frozen
only in phase 1.16, alongside other formats.

## Steps

### Step 1 — Resolve scope and amend the spec

- [x] **Do:** record D1; under A apply the exact 0002 amendment above plus
  Changelog/index. Under B revise this plan before code.
- **Files:** `specs/0002-cryptography.md`, `specs/README.md`, this plan/roadmap.
- **Done when:** owner approval explicitly covers the chosen scope.
- **Verify:** `git diff --check`; compare amendment against D1.

### Step 2 — Bounded journal and independent MACs

- [x] **Do:** implement the current-phase codec/API above and rejection tests.
- **Files:** qv-store/src/{rotation_journal,lib}.rs.
- **Done when:** both generation keys independently verify only their own
  tag; every byte-level rule is tested; decoded data is never trusted for I/O.
- **Verify:** `cargo test --locked -p qv-store rotation_journal`.

### Step 3 — Ordinary-open and mutation safeguards

- [x] **Do:** marker checks before/after locks, before SQLite, create/restore
  publication and mutations; preserve existing redacted Integrity mapping.
- **Files:** qv-store/src/{rotation_guard,vault,restore,write,lib}.rs; focused store
  tests; qv-cli/tests/credentials.rs for production exit classification.
- **Done when:** every marker form blocks the operation with no database,
  snapshot or anchor mutation, including an absent active path; valid unrelated
  vaults still work. Late marker creation cannot permit a new mutation.
- **Verify:** `cargo test --locked -p qv-store rotation_guard`;
  `cargo test --locked -p qv-cli --test credentials`.

### Step 4 — Journal fuzzing

- [x] **Do:** add target, deterministic valid seed generation, CI command,
  bounded hostile-input/round-trip/MAC checks and short local campaign.
- **Files:** fuzz/Cargo.toml, fuzz/fuzz_targets/rotation_journal.rs,
  .github/workflows/ci.yml, qv-store/tests/vectors/{rotation_journal.py,
  rotation-journal.cbor}, journal tests for independent corpus comparison.
- **Done when:** fuzz formatting/locked build and a 60 s campaign pass;
  no crash, allocation from unbounded input or accepted mutation under a
  foreign generation key. Dependency inputs unchanged.
- **Verify:** `cargo fmt --check --manifest-path fuzz/Cargo.toml`;
  `python3 -I crates/qv-store/tests/vectors/rotation_journal.py`;
  `cargo fetch --locked --manifest-path fuzz/Cargo.toml`;
  `cargo +nightly fuzz run rotation_journal -- -max_total_time=60 -max_len=8192`.

### Step 5 — Gates and foundation handoff

- [x] **Do:** final gates; document foundation coverage and remaining 1.15b;
  update roadmap split/checkmarks, index, architecture and changelog.
- **Files:** ARCHITECTURE.md §3, CHANGELOG.md, plans, crate docs.
- **Done when:** 1.15a is Implemented with independent review left for next
  fresh session; 1.15b stays unticked and unimplemented. No commit/push/branch.
- **Verify:** all AGENTS gates and `git diff --check`.

## Test plan

Current 1.15a evidence: focused journal and guard tests plus the production
CLI credential tests, then final SPDX, fmt, all-target locked Clippy with
warnings denied and full locked tests with private Xvfb. Keep logs/exit status
in `/tmp/qv21/`. Fuzz formatting, locked build and a 60-second coverage-guided
journal campaign are required. No dependency inputs change, so deny/vet are
not required. The independent transcript vector uses public zero/one BIP-39
entropy vectors, a separate CBOR encoder and Python stdlib HKDF/HMAC; its
reproduction script is `/tmp/qv21/journal-vector.py` and its public seed is
`crates/qv-store/tests/vectors/rotation-journal.cbor`. The reproduction script
is retained at `crates/qv-store/tests/vectors/rotation_journal.py`; Rust tests
compare their complete encoding against that independently generated fixture.
These are development vectors, not format freeze.

Test malformed lengths/keys/versions/UUIDs, overflow, every-byte mutations,
independent old/new tags and wrong-generation/foreign keys. Guard tests must
exercise actual open/create/restore/write/unlock entry points, source/anchor
preservation, missing-active rename gaps and marker races before/after locking
and before durable commit/anchor retry. 0012 rows partially addressed:
Rotation/purge ambiguity (open exclusion only), Anchor crash windows (refusal
of pending-anchor repair while intent exists), Hostile SQLite/CBOR (journal
parser) and Whole-file rollback (no implicit baseline). The full generation
transition, migration, disk-full installation and snapshot budget evidence
remain 1.15b; do not claim the rotation release criteria are met here.
Network isolation unavailable is recorded, never counted as passed.

## Risks and stop conditions

Stop on unresolved D1, an ambiguous journal state, inability to preserve
logical causality or chunk sharing, new dependency/unsafe/profile, secret
durable output, conflicting spec, unsound inode-lock ordering, or any need to
guess remote/LAN configuration. Do not hand-roll signatures, wrap new VK with
old VK, bypass anchor mismatch, downgrade a confirmed generation or claim
revocation/erasure of historical copies. A required split beyond this plan
needs a dated roadmap revision before implementation, preserving independent
review and owner commit boundaries.

## Documentation

- [x] `CHANGELOG.md` — Unreleased behavior/evidence/limits.
- [x] `ARCHITECTURE.md` §3/§7 — foundation coverage, journal boundary and split.
- [x] Specs — D1 amendment and Changelog/index; statuses remain accurate.
- [x] `AGENTS.md` — no conventions/layout change.
- [x] Plans — execution evidence, roadmap checkbox/plan and index status.

## Revisions

2026-10-29: Split 1.15 into 1.15a/1.15b before production code. The full
rotation design crosses filesystem replacement, dual-copy recovery and
cross-generation snapshot accounting; review its foundation independently
before installing keys/data. Completed step 1 is unchanged. Replaced only
remaining steps with the bounded foundation work; retained full design as
follow-up context. No additional normative amendment or dependency.

## Execution log

2026-10-29: Owner delegated D1 choice; selected A as recommended. Explicit
approval covers implementation and the narrow spec amendment. Step 1 done:
0002 §3.5.1, its Changelog and spec index amended; no new dependency. Existing
review/planning documentation edits are this session's own work and retained.

2026-10-29: Clean tree at `acc1021` (phase 1.14). Prepared this phase plan
after fresh-context review of 0020 (Approved with minor fixes; independent
gates green, 591 passed/2 ignored). D1 prevents standing approval:
the recommended path amends an Accepted spec; the alternative brings forward
signature work outside the phase's component/order scope. No production code,
dependency, schema or normative spec text changed. Await owner decision before
step 1 or development. Review result/evidence recorded separately in plan 0020.

2026-10-29: Architect revision applied: execute 1.15a only under the roadmap
split authority and owner-delegated judgment. 1.15b receives its own fresh-
session plan after foundation review and the owner commit boundary.

2026-10-29: Steps 2–3 implemented. Platform-independent 4096-byte journal
codec with fixed-size fields, strict positive one-step generation/sequence
bounds, redacted types and separate old/new MACs. Four focused journal tests
pass, including independent Python vector, all prefixes/every-byte mutations,
wrong tags/keys, bad IDs/types/lengths/versions and integer overflow. No journal
method can publish state or adopt an anchor.

Seven focused marker guard tests pass (`guard-final.log`): all marker kinds,
missing active path, second check after inode lock, create/restore refusal
before output/input consumption, late marker before unlock/mutation, rollback
of a staged write and pending-anchor retry exclusion. Added checks before
SQLite ingestion, after opening/at unlock, before writes/commit and before
create/restore anchor/publication. Production CLI credential tests pass all
seven (`cli-credentials.log`); strengthened marker/phrase test rerun passes
(`cli-marker.log`). No source or anchor changes on refusals. Existing same-
context review documentation for 0020 is retained.

2026-10-29: Step 4 complete. Fuzz target handles raw hostile bytes and mutations
of a deterministic valid seed; every accepted input reencodes identically and
modified seed bytes cannot retain both valid generation tags. CI adds the
60-second target under the existing pinned nightly, without dependency changes.
Fuzz format and locked fetch/build pass. This environment has no nightly or
cargo-fuzz, so local coverage uses the pinned stable compiler with explicit
`--target x86_64-unknown-linux-musl` (keeps host build scripts uninstrumented)
and `RUSTFLAGS='--cfg fuzzing -Cpasses=sancov-module
-Cllvm-args=-sanitizer-coverage-level=4
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters
-Cllvm-args=-sanitizer-coverage-pc-table
-Cllvm-args=-sanitizer-coverage-trace-compares' cargo build --locked
--manifest-path fuzz/Cargo.toml --bin rotation_journal --target
x86_64-unknown-linux-musl`. Direct libFuzzer run:
`fuzz/target/x86_64-unknown-linux-musl/debug/rotation_journal
/tmp/qv21/journal-corpus -max_total_time=60 -max_len=8192 -use_cmp=0
-artifact_prefix=/tmp/qv21/journal-artifacts/`.

Coverage-instrumented 61-second campaign passes **179,938 runs**, coverage
1635/features 4372, 32 MiB RSS, no finding (`fuzz-run.log`). It is not an ASan
run: missing sanitizer stack/death callback warnings are retained, and the
musl run disables the comparison-guidance option. CI uses ordinary cargo-fuzz
with its pinned nightly. Initial un-targeted instrumentation failed to link
host build scripts; fixed by explicit target, not by changing product code.
All output retained under `/tmp/qv21/`. Independent Python vector check passes
and its script/complete binary fixture are retained in qv-store/tests/vectors.

Initial final SPDX/fmt/Clippy checks pass. Full locked workspace tests with
private Xvfb are running on the final source tree; only documentation changes
follow while awaiting their result. No dependency/profile or SQLite format
change. The bounded journal is a new development local-state format, not a
frozen wire protocol or authorization to install data.

2026-10-29: Step 5 complete; plan Implemented (phase 1.15a only). Same-context
implementation inspection checked field bounds before decode, exact canonical
MAC body, separate generation keys, constant-time MAC verification, redacted
metadata, no publication authority in codec APIs, marker checks before SQLite,
mutation rollback and pending-anchor exclusion. No additional issue found.
This is not a fresh-context approval: keep plan Implemented for independent
review at the next roadmap session before phase 1.15b.

Final required gates pass on the final product/test inputs: SPDX
(`final-spdx.log`), `cargo fmt --check` (`final-fmt.log`),
`cargo clippy --all-targets --locked -- -D warnings` (`final-clippy.log`),
`QV_TEST_XVFB=/tmp/qv21-review/xvfb/usr/bin/Xvfb cargo test --locked`
(`final-test.log`): **603 passed, 0 failed, 2 pre-existing ignored**, 34 groups.
Only documentation was edited while/after that run; Rust/test/fixture inputs
are unchanged. Fuzz format, locked fetch and final locked build pass;
independent vector check passes. Full logs in `/tmp/qv21/`; final documentation
handoff repeats SPDX/fmt/Clippy and whitespace checks. No dependency changes,
so deny/vet not required. Network namespace probe is still unavailable
(`/tmp/qv21-review/network-namespace.log`), not a networking-blocked pass.

Documented the accepted D1 amendment, architecture §3/§7, roadmap split/status,
changelog, index and retained development vector. Do not claim the complete
rotation workflow, restart installation, snapshot inventory/budgets across
rotations, new-device approval, independent audit or security proof. All
changes remain uncommitted. The owner commits this completed phase; the next
fresh session reviews it before planning/implementing 1.15b.
