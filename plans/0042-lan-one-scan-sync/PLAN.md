# Plan 0042 — One-scan LAN sync, no device links

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-11-06 | 2026-11-06 | 0014 (Accepted); amends 0013, 0002 §3.3/§3.5, 0004 §2, 0005 §5.4/§6.2, 0009 §1.7, 0011, 0012 §1 |

## Intent

The owner, testing sync on the phone (2026-11-06): "Not sure I see the point
in pairing devices when there is no identity. Maybe scanning = 1 sync only,
and thats it." Then: "I think we should focus on that". They also asked why
a scan does not visibly fill the form. Replace stored links with a one-use
code per sync. Keep the comparison code only where VK is handed over (new
device). Make scanning act at once.

## Scope

**In scope:**
- Spec 0014 acceptance and its §9 amendments.
- Protocol: sync mode (0014 §2), new-device grant without `link_id`, the
  `lan-proof` purpose key; removal of links, the §5 session handshake,
  receive windows and the address-only QR.
- Storage: every commit writes the empty link set; old rows clear on the
  next commit; no format change.
- `qv-core` LAN API, `qvault lan open|sync|join`, the app's Devices screen,
  locked-screen Join, scan-starts behaviour, camera frame skipping.
- Regenerated interop vectors and their Python cross-check.
- The device checklist rewritten for the new flows.

**Out of scope:**
- DNS-SD (still deferred, roadmap 2.10 owner decision).
- Server sync (0006) and its device identities.
- Opening the ordinary-package camera gate (roadmap 2.11, after device
  evidence).
- A vault format change (0014 §5 keeps the format).
- The D12 independent review (a release gate, still required).

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Sync windows, sync mode, proofs | 0014 §1–§2 | Draft | Needs owner acceptance (D1) |
| New-device mode | 0013 §4.5, §4.7, §10; 0014 §3 | Accepted / Draft | Grant and row changes only |
| Pairing hello/accept, record layer, exchange | 0013 §4.1–§4.4, §6, §7 | Accepted | Unchanged |
| Stored link state | 0014 §5; 0004 §2; 0005 §5.4 | Draft / Accepted | Kept in the format, always empty |
| App scanning and typing | 0014 §6; 0009 §1.7 | Draft | Replaces "scan never starts a network operation" |
| CLI | 0014 §7; 0011 LAN contracts | Draft / Accepted | |
| Explicit initiation | 0005 §0.5; 0009 §1.5 | Draft | A scan is the explicit action |

**Spec changes required:** 0014 is the Draft. Step 1 applies its §9
amendments after acceptance.

## Decisions needed

1. **Accept Draft 0014?** Options: accept as written / adjust. Blocks: every
   step. Resolution: the owner accepted 0014 as written on 2026-11-06
   ("Accepted, go ahead"). This is a protocol and key-schedule
   change, so the developer must not start before it is recorded.

Delegated by the owner (standing, 2026-11-02), recorded here:

2. **Stored state:** A) keep the format, write the empty link set on every
   commit; B) bump the format and drop `lan_link`. Chose A: existing
   development vaults (the owner's included) keep opening. B would make
   them unsupported with no migration path today. Removal waits for the
   next format change.
3. **One window kind** accepts both modes (sync and new device). Rejected:
   separate "add a device" and "sync" windows (two buttons for one code
   shape; the hello already carries the mode).
4. **No confirmation on A in sync mode.** A's user approved by opening the
   window, and the proof needs VK. Rejected: a "Sync with this device?"
   prompt (no identity to show, so it would be a reflexive yes).
5. **Purpose label** `lan-link` → `lan-proof`. The root no longer derives
   links; the name should say what it does. Pre-1.0, no compatibility kept.
6. **CLI names** `lan open | sync | join`. Rejected: keeping `lan pair` (no
   pairing remains) and `lan receive` (no receive window).
7. **Scan behaviour:** a QR with endpoints starts the action at once; one
   without asks for the address and shows "✓ Code from QR". This answers
   the owner's "why not fill the form" without putting the code in the DOM.

## Design

**Components touched** (trust boundaries per `ARCHITECTURE.md` §3):
- `qv-crypto` (key schedule): `lan.rs`.
- `qv-protocol` (hostile-input wire layer): `lan.rs`, the QR payloads.
- `qv-store` (local durable state): `write.rs`, `restore.rs`, `lan_store.rs`,
  `vault.rs` (unchanged digest check).
- `qv-sync` (network): `lan/approver.rs`, `lan/joiner.rs`, `lan/qr.rs`,
  `lan/vectors.rs`, `lan/mod.rs`; delete `lan/session.rs`,
  `lan/receiver.rs`, `lan/initiator.rs`; trim `lan/window.rs` and
  `lan/steps.rs`.
- `qv-core` (frontend API): `lan.rs`.
- Frontends: `qv-cli` `cmd/lan.rs`; `qv-app` `lan.rs`, `controller.rs`,
  `workspace.rs`, `qr.rs`, `android.rs`, `ui/pages.rs`, `ui/mod.rs`,
  Android tests and flows.

**Interfaces** (sketch; keep existing names where not listed):

```rust
// qv-crypto::lan
pub struct ProofRoot(PurposeKey<purpose::LanProof>);      // was LinkRoot
impl ProofRoot {
    pub fn derive(vk: &VaultKey, vault_id: &VaultId, generation: KeyGeneration) -> Result<Self, CryptoError>;
    pub fn proof(&self, th: &[u8; 32], role: ProofRole, vault_id: &VaultId, generation: KeyGeneration) -> Result<MacTag, CryptoError>;
    pub fn verify_proof(&self, th: &[u8; 32], role: ProofRole, vault_id: &VaultId, generation: KeyGeneration, tag: &MacTag) -> Result<(), CryptoError>;
}
// Removed: LinkRoot::link_key, LinkKey, SessionAuth, session_record_keys,
// LinkRow, seal_link_row, open_link_row, valid_link_label, LINK_LABEL_MAX.

// qv-protocol::lan
pub enum JoinMode { NewDevice = 0, Sync = 1 }               // Link renamed
pub struct PairGrant<'a> { vault_id, key_generation, vk }   // no link_id
pub struct PairProved { pub proof: [u8; 32] }               // no link_id
// Removed: SyncHello, SyncAccept, session_th_input, Confirm, the address QR.

// qv-sync::lan
pub struct SyncWindow;                     // was PairingWindow; one session
impl SyncWindow { pub fn open(..); pub fn qr(..); pub fn manual_code(..);
                  pub fn run(self, vault: &dyn OfferVault, confirm: &mut dyn Confirm, ..) -> Result<Served, LanError>; }
pub enum Served { Synced(RoundReport), Joined { peer_confirmed: bool } }
pub fn sync_with_code(code: &PairingSecret, endpoints: &[SocketAddr], vault: &dyn ExchangeVault, ..) -> Result<RoundReport, LanError>;
pub fn join_new_device(..);                // unchanged apart from no link row
// OfferVault = ApproverVault without commit_link; grant() without link_id.

// qv-core
impl Session {
    pub fn open_sync_window(&self, options: SyncWindowOptions) -> Result<SyncWindow, CoreError>;
    pub fn sync_with_code(&self, code: &SecretBytes, endpoints: &[SocketAddr], options: SyncOptions) -> Result<SyncReport, CoreError>;
}
// Removed: join_link, open_receive_window, sync_lan, lan_links,
// remove_lan_link, LanLinkHandle, LanLinkSummary, ReceiveWindow and its
// types, JoinOptions::label, PairingOptions::peer_label.
```

**Data and control flow:**
- Sync mode (0014 §2.3) reuses today's link-mode path in the approver and
  joiner, with the SAS step and both link commits removed. The proof order
  is a hard requirement: A verifies `prove` before it computes or sends
  `proved`; B verifies `proved` before sending `State`.
- New-device mode: today's path minus `commit_link` and `link_id`. B's
  §10 creation writes no row.
- **Writes** (0014 §5): in `qv-store::write`, the commit always runs
  `DELETE FROM lan_link` and writes `lan_links_digest = empty_digest()`
  inside the same transaction as the head. No new crash point: the rows
  and the head change atomically, as today when `links` is `Some`.
  `vault.rs`'s open-time digest check stays, so an old file with rows
  still opens and verifies; its next commit clears them.
- Rotation and restore already write the empty set; restore drops its
  row insert.

**Secrets and hostile input:**
- `K_proof` lives in `PurposeKey`, as `LinkRoot` did. Proof tags are
  compared in constant time (existing `verify_proof`).
- `P` and the pairing keys are unchanged (`PairingSecret`, 0013 §9.4).
- The app keeps scanned and typed codes in `SecretBytes`; no code reaches
  the DOM (0008 §1.1). Endpoints may be rendered.
- Decoders reject the removed labels as unknown (fail closed). Pre-auth
  bounds and the 4096-byte frame limit are unchanged.
- Camera frames: a decode error or ambiguity skips that frame; a decoded
  payload failing `inspect_lan_qr` ends the scan (0014 §6.6).

**Errors:**
- `vault_mismatch` (sync mode) maps to "The other device has a different
  vault or key generation."
- A refused or closed window maps to "No device answered with this code.
  Open a new code on the other device."
- CLI: exit codes 4/5 for links go away; other LAN mappings unchanged; exit
  10 when a window closes without a session.

**Dependencies:** none added or removed.

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| — | — | — | — |

## Steps

### Step 1 — Accept 0014 and apply its amendments

- [x] **Do:** After the owner accepts (D1): set 0014 to Accepted with its
  Changelog line. Apply 0014 §9 to 0013, 0002, 0004, 0005, 0009, 0011 and
  0012, each with a Changelog line. In 0013, delete §5 and §8.5, renumber,
  and fix every cross-reference (`rg -n '§5|§8.5' specs/`). Update
  `specs/README.md` (index row and a paragraph).
- **Files:** `specs/0013-lan-sync-protocol.md`, `specs/0014-lan-one-scan-sync.md`,
  `specs/0002-cryptography.md`, `specs/0004-local-storage.md`,
  `specs/0005-synchronization.md`, `specs/0009-clients-and-platforms.md`,
  `specs/0011-cli.md`, `specs/0012-security-validation.md`, `specs/README.md`.
- **Done when:** no spec text still describes links, receive windows,
  SyncHello or the address QR as current behaviour (Changelogs excepted).
- **Verify:** `rg -n -i 'link key|lan_link|receive window|SyncHello|lan-addr-qr|lan-link' specs/`
  shows only Changelog lines and 0014 §5 / 0004 / 0005 compatibility notes.

### Step 2 — Key schedule

- [x] **Do:** Rename the purpose to `LanProof` with label `lan-proof`.
  Replace `LinkRoot` with `ProofRoot` (derive, proof, verify_proof).
  Delete link-key, session-auth, session record-key and link-row code with
  their tests. Keep `PairingSecret`, `PairingKeys`, `PairNonce`, `Sas`, the
  record layer and `transcript_hash`. Add tests: a proof for role `a` fails
  as `b`; a different `th`, vault ID or generation fails; constant-time
  comparison is the existing `MacTag` path.
- **Files:** `crates/qv-crypto/src/lan.rs`, `crates/qv-crypto/src/keys.rs`
  (the `LanLink` purpose).
- **Done when:** no `LinkKey`/`SessionAuth`/`seal_link_row` remains;
  `cargo test -p qv-crypto` passes.
- **Verify:** `cargo test --locked -p qv-crypto`

### Step 3 — Wire messages

- [x] **Do:** `JoinMode::Link` → `JoinMode::Sync` (code 1). `PairGrant`
  without `link_id` (4 elements after the label: vault_id, key_generation,
  vk). `PairProved` with only `proof`. Delete `SyncHello`, `SyncAccept`,
  `session_th_input`, `Confirm` and the address-only QR payload with their
  decoders. Add rejection tests for the old 5-element grant, the old
  `proved` with `link_id`, and each removed label.
- **Files:** `crates/qv-protocol/src/lan.rs` (and its QR payload code).
- **Done when:** decoders reject the old shapes and labels; fuzz targets
  that covered removed messages are deleted or retargeted (keep the
  others building).
- **Verify:** `cargo test --locked -p qv-protocol`

### Step 4 — Storage: always-empty link set

- [x] **Do:** Remove `Writer::add_lan_link` and `remove_lan_link`. Every
  commit deletes all `lan_link` rows and writes the empty-set digest, in
  the head transaction. Restore inserts no row. Keep `lan_store::digest`,
  `empty_digest` and the open-time check. Delete link-row sealing helpers
  that only served links. Test: build a file with two rows through a
  test-only path (or a fixture written with raw SQL plus a matching head
  digest), open it (verifies), commit an unrelated edit, reopen: no rows
  and the empty digest. A row planted after that commit fails open
  (integrity), as before.
- **Files:** `crates/qv-store/src/write.rs`, `restore.rs`, `lan_store.rs`,
  `lan_store_tests.rs`, `lan_staging.rs` (if it references rows).
- **Done when:** no production path writes a non-empty link set.
- **Verify:** `cargo test --locked -p qv-store`

### Step 5 — Sync windows and sync mode

- [x] **Do:**
  - Approver → offerer: `SyncWindow` serves one session. New-device mode
    keeps reveal, SAS and `Confirm`; sync mode skips them and follows 0014
    §2.3 steps 2, 3 and 5 (A as responder of the exchange).
  - Joiner: `sync_with_code` runs hello/accept with `JoinMode::Sync`,
    sends `prove`, verifies `proved`, then the exchange as initiator.
    `join_new_device` loses its link row and label.
  - Delete `session.rs`, `receiver.rs`, `initiator.rs` and the receive-window
    parts of `window.rs` and `steps.rs`.
  - `qr.rs`: only the pairing QR kind remains.
  - Regenerate `tests/vectors/qv-dev-lan-pairing.txt` (sync mode: hello,
    accept, `th`, `K_proof`, both proofs, `proved`; new device: grant).
    Update `crosscheck_lan.py` to recompute `K_proof` and both proofs and
    to drop session and address-QR values.
  - Port the existing link-mode and session tests to sync mode. Add the
    0014 *Testing Requirements* rows: proof binding (wrong VK, vault ID,
    generation on either side), proof ordering, relay across sessions,
    raced code, one use, removed messages, and generation. Keep every
    `// 0012 §1:` label on tests that still cover their row.
- **Files:** `crates/qv-sync/src/lan/*.rs`, `crates/qv-sync/tests/vectors/*`.
- **Done when:** both modes pass end to end over loopback; every
  Testing Requirements row has a test; vectors cross-check.
- **Verify:** `cargo test --locked -p qv-sync lan` and
  `python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py`

### Step 6 — Core API

- [x] **Do:** Implement the `qv-core` sketch: `open_sync_window` (reports
  `Served`), `sync_with_code`, `join_new_device` without a label. Remove the
  link, receive and session APIs. Map `vault_mismatch` and refused
  connections to `CoreError` variants that frontends render as in 0014 §8.
  Port `lan_tests.rs`, including lock cancellation during a sync window and
  during a sync session (0005 §6.5).
- **Files:** `crates/qv-core/src/lan.rs`, `crates/qv-core/src/lan_tests.rs`,
  `crates/qv-core/src/lib.rs` (exports).
- **Done when:** no link or receive API remains public.
- **Verify:** `cargo test --locked -p qv-core lan`

### Step 7 — CLI

- [x] **Do:** Implement 0014 §7 (`lan open`, `lan sync`, `lan join`) and
  remove `pair`, `receive`, `links` and `unlink`. Keep the no-echo code
  prompt and the alternate screen. Port `tests/lan.rs`: both modes, a
  wrong code, a used window (exit mapping), `--json` refused before
  unlock.
- **Files:** `crates/qv-cli/src/cmd/lan.rs`, `crates/qv-cli/src/` (command
  table), `crates/qv-cli/tests/lan.rs`, `crates/qv-cli/README.md`.
- **Done when:** the CLI help lists only the three commands.
- **Verify:** `cargo test --locked -p qv-cli lan`

### Step 8 — App

- [x] **Do:**
  - Run kinds: `LanKind::{Window, Sync, Join}`.
  - Devices screen: "Sync with another device" opens a window (QR, code,
    endpoints, countdown; comparison and confirmation for a new-device
    hello). "Scan a code" (Android, when the camera gate is open) and
    "Type a code" (code + address, then Sync). Remove the linked-device
    list, link labels, `WsAction::LanRemove`, `ConfirmKind::RemoveLink`,
    the Receive button and the address QR.
  - Scanning (0014 §6.2–§6.3): with endpoints, start the action as soon as
    the payload is accepted. Without endpoints, show "✓ Code from QR" in
    the code field (no value rendered) and focus the address.
  - Locked-screen Join: drop the label field; a scan with endpoints
    connects at once, then shows the comparison.
  - Replace the `QR_SCANNED` notice text accordingly (keep `View::notice`).
  - Update `flow.js`, Android `flows.js`, `QrTest` (optical check: the
    synthetic fixture has no endpoints, so expect "✓ Code from QR" and an
    empty address field) and the app README LAN paragraphs.
- **Files:** `crates/qv-app/src/{lan.rs,lan_tests.rs,controller.rs,workspace.rs,qr.rs,ui/pages.rs,ui/mod.rs,views.rs,bin/flow.js}`,
  `crates/qv-app/android/tests/{QrTest.java,flows.js}`, `crates/qv-app/README.md`.
- **Done when:** the real-engine flows sync two app instances over
  loopback with a typed code, and a scanned code with endpoints starts
  without another click (core-level test with the scan entry point);
  no code value appears in the DOM (existing redaction checks).
- **Verify:** `QV_TEST_XVFB=… RUST_TEST_THREADS=1 cargo test --locked -p qv-app --features validation`
  and the Android clippy builds (`mobile`, `mobile,validation`).

### Step 9 — Camera frames

- [x] **Do:** In `android::capture_qr`, a `decode_frame` error (extraction
  failure or several codes) skips the frame and continues within the
  attempt and time limits; an accepted payload that fails `apply_qr`
  validation ends the scan with its error. Unit-test the policy with a
  host-side function that classifies decode results (no JNI in tests).
- **Files:** `crates/qv-app/src/android.rs`, `crates/qv-app/src/qr.rs`.
- **Done when:** the noted 2026-11-06 finding in
  `plans/0039-lan-qr/DEVICE-VALIDATION.md` is closed.
- **Verify:** `cargo test --locked -p qv-app qr` and the Android clippy builds.

### Step 10 — Records and documentation

- [x] **Do:** Rewrite the pending rows of
  `plans/0039-lan-qr/DEVICE-VALIDATION.md` for the new flows (scan to sync
  both ways, new-device join with comparison, Internet blocked,
  interruption, window one-use and expiry); keep past results as history.
  Add a roadmap revision: 2.10/2.10b/2.11 evidence now refers to sync
  windows and 0014. Update `ARCHITECTURE.md` §3 rows for qv-crypto,
  qv-store, qv-protocol, qv-sync, qv-core and qv-cli/qv-app. Add the
  `CHANGELOG.md` entry. Set this plan to Implemented and update
  `plans/README.md`.
- **Files:** as listed, plus `plans/0002-roadmap/PLAN.md`.
- **Done when:** no document describes links as current behaviour.
- **Verify:** `rg -n -i 'link key|lan links|linked device|receive window' ARCHITECTURE.md crates/*/README.md plans/0002-roadmap/PLAN.md`
  shows only history.

## Test plan

- Final verification: all `AGENTS.md` gates on the final tree, plus the
  Android clippy builds, the validation-feature app tests and the vector
  cross-check. Step checks are focused.
- Unit and property tests: proof derivation and verification per role,
  `th`, vault and generation; message encode/decode round trips; empty
  link set after any commit.
- Rejection, malformed-input and crash-path tests: old and removed message
  shapes; wrong VK/vault/generation on each side; missing or reordered
  `prove`/`proved`; a second hello; a used window; interruption at every
  exchange boundary (ported 0013 tests); lock during window and session;
  an old file with link rows opens and clears.
- Vectors: regenerated `qv-dev-lan-pairing.txt`, checked by
  `crosscheck_lan.py`.
- 0012 §1 matrix rows addressed: LAN discovery mistaken for trust,
  Account-dependent LAN sync, LAN partial acceptance, Unrequested
  synchronization (LAN). "Peer state rollback" (0013 testing table) is
  replaced by "No peer state".

## Risks and stop conditions

- Stop if any step needs a vault format change (it should not; 0014 §5).
- Stop if the proof ordering cannot be enforced in the existing state
  machines without weakening another 0013 check.
- Stop if removing §5 breaks an exchange property that 0013 §5.4 claimed
  and §4.4's pairing keys do not provide (expected none: both use fresh
  X-Wing, transcript-bound keys and per-direction labels). Record the
  comparison in the log either way.
- Stop if a removed API turns out to be used outside LAN code.
- Do not claim the new composition is secure; it goes to D12.
- Device runs (both directions, Internet blocked) need the owner's phone.

## Documentation

- [x] `CHANGELOG.md` — Unreleased entry (step 10).
- [x] `ARCHITECTURE.md` — §3 component rows (step 10).
- [x] Specs — 0014 Accepted; §9 amendments with Changelog lines (step 1).
- [x] `AGENTS.md` — no change.
- [x] `crates/qv-app/README.md` — LAN section (there is no `crates/qv-cli/README.md`).
- [x] `plans/0039-lan-qr/DEVICE-VALIDATION.md`, `plans/0002-roadmap/PLAN.md`.

## Revisions

None.

## Execution log

- 2026-11-06: Plan written with Draft 0014 after the owner's direction.
  Context: the owner's first typed-code sync attempt on the phone failed
  (details not yet reported). Phone-to-Linux TCP on a test port worked;
  Linux also has a ProtonVPN address (`10.2.0.2`) that a typed endpoint
  must avoid.
- 2026-11-06: Owner: "Accepted, go ahead". D1 resolved; plan Approved and
  In progress.
- 2026-11-06: Step 1 done. Applied 0014 §9 to 0013, 0002, 0004, 0005, 0009,
  0011 and 0012 with Changelog lines; 0014 Accepted; `specs/README.md`
  updated. **Deviation:** 0013's §5, §8.5 and §12.1 are kept as short stubs
  instead of being deleted and renumbered. Code comments throughout the
  workspace cite 0013 section numbers, and renumbering would make them
  wrong. The 0013 §5 stub lists the retired labels. Verify: the plan's `rg`
  shows only Changelog lines, stubs, 0014 and the compatibility notes.
- 2026-11-06: Step 2 done. `LanProof` purpose (`lan-proof`), `ProofRoot`;
  link keys, session auth/record keys and link-row sealing removed. Test
  `lan_proofs_match_and_bind_their_context` adds the other-VK case.
  `cargo test --locked -p qv-crypto`: 162 passed; clippy clean.
- 2026-11-06: Step 3 done. `JoinMode::Sync`; grant (arity 4) and proved
  (arity 2) without `link_id`; SyncHello, SyncAccept, Confirm, PairDone,
  `session_th_input` and the address QR removed; the fuzz targets
  `lan_message` and `lan_oob` follow. `PairDone` is also retired (0014 says
  sync mode does not send it, and new-device mode never did). New tests
  refuse the retired labels and the old grant/proved shapes.
  `cargo test --locked -p qv-protocol`: pass; clippy clean.
- 2026-11-06: Step 4 done. Every commit writes the empty link set (the
  writer starts with `links = Some(empty)` when the file still has rows,
  reusing the existing atomic DELETE + digest + crash point). Restore and
  new-device creation write no row; `add/remove_lan_link`, `NewLanLink`,
  `LanLinkRow`, row sealing and `lan_links`/`lan_link_key` removed.
  `UnlockedVault::retired_lan_links()` reports leftover rows (used by the
  sync tests to show nothing is stored). Tests: an older file with rows
  opens and its next commit clears them; planted/modified/foreign/deleted
  rows stay integrity errors; clearing crash points leave old or new
  state; rows never enter archives. `cargo test --locked -p qv-store`: 238
  passed; clippy clean.
- 2026-11-06: Step 5 done. The window serves one session: new-device mode
  unchanged apart from the grant; sync mode verifies B's proof before
  sending its own, then exchanges as responder. `sync_with_code` proves
  first and exchanges only after verifying A's proof (B maps a bad proof
  to `vault_mismatch`). `session.rs`, `receiver.rs` and `initiator.rs`
  deleted; `LanQrKind` removed (one QR kind). Kept the internal names
  `PairingWindow`, `Approved` and `ApproverVault` (now an enum `Approved`
  with `Joined`/`Synced`) to limit churn; the sketch's `SyncWindow`/`Served`
  were names only. Ported tests plus new ones: proof binding (wrong VK,
  other generation, reflected role), no proof before a valid one, an
  exchange message instead of a proof, a relayed proof, a window without
  the vault (B sends nothing after a bad proof), one use (the code fails
  after its session), expiry. Vectors regenerated (`sync_*`, `k_proof`,
  proofs, `prove`/`proved` and their records; no link/session/address
  values); `crosscheck_lan.py` recomputes 29 values: OK.
  `cargo test --locked -p qv-sync`: 41 passed; clippy clean.
  - One assertion relaxed with a reason: when a new device rejects the
    comparison code, A may see the closed connection instead of the
    `cancelled` record (A is sending the grant). The old suite only
    tested rejection in link mode. A still fails and stores nothing.
- 2026-11-06: Step 6 done. `Session::open_sync_window` (`SyncWindow`,
  `WindowCode`, `Served::{Joined, Synced}`), `Session::sync_with_code`, and
  `Core::join_new_device` taking `SyncOptions` (no label). `ApproverUi`
  loses the mode. Link, receive-window and session APIs removed. Tests
  ported and extended: no peer state after join and sync, another vault
  fails on both sides, a lock closes a waiting window promptly, recovery
  sessions can neither offer nor sync, rotation makes an old copy fail
  with `vault_mismatch` and joining again works. `cargo test --locked -p
  qv-core lan`: 12 passed.
- 2026-11-06: Step 7 done. `qvault lan open|sync|join` per 0011; `lan sync`
  now prompts for the code at the no-echo prompt (so, like the others, it
  refuses `--password-stdin`). `open` reports an expired code as exit 10
  with its own message. `cargo test --locked -p qv-cli --test lan`: 4
  passed (open serves one sync with the code only on the alternate screen;
  sync prompts and prints the sync lines without echo; usage and exit
  codes, including the removed commands; new-device join). There is no
  `crates/qv-cli/README.md`; the plan's mention of it was wrong.
- 2026-11-06: Step 8 done. App: `LanKind::{Window, Sync, Join}`;
  `WsAction::{LanOffer, LanSync}`; the label field, link list, link
  removal (and its confirmation), Receive and the address QR are gone. The
  Devices screen offers "Show a code", "Scan a code" (Android) and "Type a
  code"; the locked screen's Join has no label. `accept_qr` reports whether
  the code names endpoints. The scan thread releases the worker, then
  `start_scanned` starts the sync or join. Without endpoints the form shows
  "Code from the QR code" (`lan-code-scanned`; the code is never rendered)
  and asks for the address. **Deviation, recorded here:** when the
  reduced-protection acknowledgement is still pending, a scanned join does
  not start; it waits with "Code scanned. Choose Join to continue.", because
  Join shows that notice first (`Controller::protection_ack_needed`). The
  real-engine flow (`flow.js`) and `QrTest` follow the new controls. Tests:
  `qr_codes_fill_only_devices_and_say_whether_they_can_start`, the
  extended locked-screen QR test (including the acknowledgement wait),
  `lan_app_new_device_join_then_sync_with_a_typed_code`,
  `lan_app_scanned_codes_start_the_join_and_the_sync`, cancel/lock and input
  bounds. `cargo test -p qv-app --features validation --lib -- lan qr`: 13
  passed.
- 2026-11-06: Step 9 done. `qr::scan_frame` skips a frame without a
  readable code or with several codes; `android::capture_qr` uses it, so
  one noisy frame no longer ends the scan. A decoded foreign code still ends
  the scan through `apply_qr`. Closes the 2026-11-06 finding in
  `plans/0039-lan-qr/DEVICE-VALIDATION.md`.
- 2026-11-06: Step 10 done. `ARCHITECTURE.md` (§3 rows, the LAN narrative,
  the 2.10b QR note and the technology table), the app README's LAN
  section, `CHANGELOG.md`, the roadmap revision, and the device checklist's
  pending rows rewritten for one-use codes (past results kept as history).
  The plan's stale-docs `rg` shows only history paragraphs followed by the
  0042 replacement note.
- 2026-11-06: Final gates on this tree:
  - `cargo fmt --check`, `sh scripts/check-spdx.sh`, `sh
    scripts/check-matrix.sh`, `git diff --check`: pass;
  - `cargo clippy --all-targets --locked -- -D warnings`: pass after adding
    `clippy::panic` to the new core test file's allow list (the first run
    caught it); validation and Android `mobile` / `mobile,validation`
    clippy: pass;
  - `cargo test --locked -p qv-app --features validation` (Xvfb, including
    the real-engine flows): 74 passed;
  - `cargo test --locked` (whole workspace): 905 passed, 0 failed, 2
    ignored; after the clippy allow, `cargo test --locked -p qv-core`: 118
    passed;
  - `python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py`: 29 values
    OK.
  No dependency change, so no deny/vet run. Not done here: the attended
  phone run (needs the owner), the fresh-context review, and D12.
- 2026-11-06: Owner decision: test the camera with their real vault before
  typing codes. Added `QV_APP_QR_CAMERA=1` to
  `crates/qv-app/scripts/build-android.sh`; it opens the QR camera gate in an
  ordinary package and the build prints that it did. The default build is
  unchanged (closed). Built and installed on the owner's phone (SHA-256
  `9de22a4d…0bac8f`); recorded in `plans/0039-lan-qr/DEVICE-VALIDATION.md`.
- 2026-11-06: Owner-reported bugs on the phone, fixed:
  - **Permission prompt:** granting camera permission returned to the lock
    screen, because the prompt pauses the activity and the pause both
    cancelled the scan and locked. Now the scan holds the platform's
    background deferral (as the document picker does), a pause while the
    permission request is pending keeps the scan, and the camera opens after
    resume (`handler.post`). Any other pause still ends the scan; a deferred
    lock fires when the scan ends in the background. 0009 §1.7 amended (with
    a Changelog line), app README updated.
  - **Countdown:** the window's "Closes in" stayed at 10:00 because the
    panel's props did not change; `lan_seconds` is now part of the shell
    view and the panel's props.
  - **Messages:** every LAN failure showed the generic "vault operation
    could not be completed". `AppError::message` now maps each `LanError`
    to fixed text (0014 §8), e.g. no device answered (address, network,
    firewall or VPN), different vault or generation, timeout, expired code.
  - Phone-to-computer TCP was checked again and works; the computer also has
    a ProtonVPN address (`10.2.0.2`) that the QR lists, which costs a
    connect timeout when tried first. Found, not fixed: windows advertise
    point-to-point tunnel addresses.
  - Checks: fmt, SPDX, diff check, app clippy (validation and Android
    `mobile`), `cargo test -p qv-app --features validation --lib -- lan qr`:
    13 passed. Rebuilt with `QV_APP_QR_CAMERA=1` and installed (SHA-256
    `edfa6efc…7fdda`).
- 2026-11-06: Owner: the window showed only the VPN address. Cause: the
  route probes target fixed private destinations, and the owner's
  ProtonVPN policy routing sends all of them through its tunnel table, so
  every probe returned `10.2.0.2`; the LAN `192.168.15.7` is only on the
  main table's attached `192.168.15.0/24`. Fix (qv-platform `net`): probe
  one address inside each attached IPv4 network of `/proc/net/route` first
  (bounded 64 KiB read; up, no gateway, prefix 1–30, not `lo`), then the
  fixed probes. On this host: `[192.168.15.7, 10.2.0.2, 2a07:b944::2:2]`.
  Where `/proc/net/route` is unreadable (Android), only the fixed probes
  run. Deviation from plan 0038 decision 3 ("no interface list is read"):
  the route table is read, still no interface enumeration or dependency.
  Test `net_attached_networks_come_from_the_main_route_table`.
- 2026-11-06: The camera deferral is now taken before `qvQrStart`, so a fast
  permission prompt cannot pause the app first. LAN form input errors are
  `AppError::LanInput` ("Type the code … and its address as ip:port");
  `InvalidInput` now only means a stale form, which helps tell the two
  apart if the owner's "Check the input bounds" report recurs (its cause was
  not reproduced). Checks: fmt, clippy (app validation, platform, Android
  `mobile`), app `lan qr` tests 13 passed, platform tests 30 passed.
  Installed `QV_APP_QR_CAMERA=1` build `d84b6a11…ec969f7`.
- 2026-11-06: Owner: the first real Linux/phone join and sync worked ("it
  worked now ... The vault synced nicely"), but the comparison code on the
  phone was "a bit too hidden". The new device now shows it in the same
  large code box as the offering device (`lan-sas-wait`), with "Check that
  the other device shows this code" and a cancel hint, instead of inside the
  status line. The app test checks both screens show the same code before
  approval. App `lan` tests 8 passed; clippy clean. Installed with
  `QV_APP_QR_CAMERA=1`.
- 2026-11-06: Owner: the test suite takes too long (~30 min). Measured:
  parallel threads did not help, because every test unlock took one
  process-wide KDF mutex (256 MiB Argon2id each), so all KDF work ran one
  at a time. Replaced the mutex in the qv-cli, qv-core, qv-store and qv-sync
  test helpers with a bounded slot count, `QV_TEST_KDF_JOBS` (default half
  the CPUs, 1–4): `qv-cli --test edit` 25 s → 11 s. The qv-app lock is kept,
  because its LAN tests also use it to guard the shared `TEST_LOOPBACK`
  switch. The local gate script no longer forces `RUST_TEST_THREADS=1`
  except for the app's validation (Xvfb) run; the whole-workspace `cargo
  test --locked` took 352 s instead of ~25–30 min. AGENTS.md notes the
  setting.
  - The faster runs exposed a real ordering bug: the sync window closed a
    refused hello's connection before counting it and going idle, so a
    client reconnecting at once could be refused uncounted and 16 bad
    hellos did not always close the window (0013 §8.3). It now counts and
    goes idle first.
  - Two tests assumed one timing: the sync-window attempt-limit test now
    keeps connecting until the window closes, and the new-device rejection
    test accepts both valid outcomes (window error, or "did not finish"
    after the user's approval released VK). qv-sync suite: 8 of 8 runs pass.
- 2026-11-06: Final gates on this tree (479 s in total): fmt, SPDX, matrix,
  diff check, clippy (host, validation, Android `mobile` and
  `mobile,validation`) pass; app validation tests (Xvfb) 74 passed; `cargo
  test --locked --no-fail-fast` 906 passed, 0 failed, 2 ignored;
  `crosscheck_lan.py` 29 values OK.

