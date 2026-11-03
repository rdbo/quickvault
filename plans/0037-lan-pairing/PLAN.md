# Plan 0037 — LAN pairing, link storage and new-device initialization (roadmap 2.9)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-11-02 | 2026-11-02 | 0013 §1–4, §7.2–7.7 (new-device subset), §8–12; 0002 §3.3, §3.5; 0004 §2, §5–6; 0005 §5.4; 0008 §1; 0012 §1 |

## Intent

Make two devices able to pair over the LAN under spec 0013. Pairing creates a
pairwise link key, and a new device can be set up from an approving device.
Rotation and removal invalidate links. This is the second LAN phase:
- phase 2.10 adds sync sessions, receive windows, discovery, the CLI and the
  app;
- this phase delivers the trusted core that 2.10 drives.

## Scope

**In scope:**
- `qv-crypto::lan`, the 0013 §4 key schedule:
  - the pairing secret `P`, `pairing_id`, `K_hello`/`K_accept`;
  - transcript hashes and the pairing record keys;
  - the commitment and the comparison code (SAS);
  - the new `lan-link` purpose key (`K_lan`), link keys and link-mode proofs;
  - VK transfer for the grant;
  - sealing and opening of `lan_link` rows.

  A `test-vectors` cargo feature exposes derandomized X-Wing for vectors only.
- `qv-protocol`:
  - typed codecs for the pairing messages (§4), the exchange messages the
    new-device exchange uses (§7.2–7.5, §7.7) and the error record (§11);
  - the out-of-band QR payload and the 26-character manual code (§4.2).
- `qv-store`, local peer state (§9):
  - `lan_link` and `lan_hint` tables;
  - mandatory head key 8 `lan_links_digest`, checked on open;
  - link insert/remove through the single write path;
  - empty link state on create, restore and rotation;
  - serving reads of the manifest and object envelopes;
  - private new-device staging as an archive;
  - `VaultFile::create_from_lan`, the 1.13b creation protocol plus the first
    link row.

  The development format moves to `0x7FFF0004`, with no migration.
- `qv-sync::lan`:
  - cancellable, time-bounded framed transport and the record channel;
  - pure pairing steps;
  - the approver (A) and joiner (B) drivers for both modes;
  - the new-device exchange: A serves, B receives (§4.7, §10);
  - the TCP pairing window (listener, one session at a time, failure count,
    second-hello detection, time limit, cancellation);
  - the endpoint policy (§1.4).
- `qv-core`: `Session::open_pairing_window` and `PairingWindow::run` (A),
  `Core::join_new_device` (B, new device), `Session::join_link` (B, link mode),
  `Session::lan_links`, `Session::remove_lan_link`, and `CoreError::Lan`.
- Development interoperability vectors for every pairing derivation and
  message, independently recomputed by a Python stdlib script.
- Fuzzing: typed decoders added to `lan_message`; new `lan_oob` target.
- Spec clarifications in 0013 and 0004 (step 1), and documentation.

**Out of scope (phase 2.10):**
- the session handshake (§5) and receive windows;
- the general exchange with merge and commit (§7.6), including the ordinary
  exchange that follows link-mode pairing (§4.8, last paragraph). In this
  phase both sides close after `PairDone`. §4.8 already treats a failed
  follow-up exchange as "links stay, the user syncs later";
- DNS-SD advertising and browsing (§3.2–3.4), and the `p=` tag;
- local interface-address enumeration. Callers pass addresses for the QR;
  2.10 adds the platform adapter;
- hint updates after sessions;
- `qvault lan …` and the app UI;
- mapping LAN errors onto 0011 exit codes.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Profile `lan / 1`, encoding, frames, endpoints, loopback only when enabled | 0013 §1 | Accepted | step 1 clarifies confirmation-wait timeouts |
| Roles, Aborted state, erase ephemeral secrets | 0013 §2, §9.4 | Accepted | |
| Endpoints are untrusted hints | 0013 §3.1 | Accepted | discovery (§3.2–3.4) deferred to 2.10; "discovery off" is a permitted mode |
| Pairing: opening, OOB code, PairHello checks and order, single hello, PairAccept, reveal/SAS, link derivation, new-device grant, link mode | 0013 §4.1–4.9 | Accepted | |
| Exchange messages for the new-device run | 0013 §7.1–7.5, §7.7 | Accepted | step 1 clarifies the Want/Object turn |
| Pairing window lifecycle and abuse limits | 0013 §8.1–8.3 | Accepted | step 1 clarifies reading one hello from an extra connection |
| `lan_link` / `lan_hint`, digest in the head, excluded from archives | 0013 §9.1–9.3; 0004 §2; 0005 §5.4 | Accepted | step 1 records development layouts in 0004 §2 |
| New-device initialization order | 0013 §10 | Accepted | |
| Error codes; nothing sent before authentication | 0013 §11 | Accepted | |
| Removal is local; rotation drops links | 0013 §12; 0002 §3.5 | Accepted | |
| `lan-link` purpose label | 0002 §3.3 | Accepted | |
| Single write path, anchor ordering | 0004 §5; 0005 §5.4 | Accepted | |
| New-path creation (1.13b restore path) | 0004 §5; 0007 §3.4 | Accepted | |
| Protected containers, no secret Debug/logs | 0008 §1 | Draft (D5 go-ahead) | |
| Matrix rows | 0012 §1 | Accepted | LAN discovery mistaken for trust; Peer state rollback (0013 testing) |

**Spec changes required (step 1):** clarifications only, applied under the
owner's standing delegation (2026-11-02). Each gets a Changelog line.
- **0013:**
  - §1.3 timeouts: the 10 s limit covers each cleartext handshake message and
    the reveal. Reads that wait on the peer's user (grant, prove, proved)
    are bounded by the pairing window limit. Connection attempts are bounded
    by 10 s.
  - §7.1 turn order: one side sends all its `Want` messages, the last with
    `last = true`, before the other sends any `Object`. An empty request is
    one `Want` with no IDs and `last = true`.
  - §8.3: while a pairing on one connection has accepted a valid hello, A
    may read one handshake frame from another connection, never answer it
    and close it. A valid hello with different bytes aborts the window
    (§4.3); an identical one is refused. Anything else counts as a failed
    attempt.
- **0004:**
  - §2.3: head key 8 is mandatory `lan_links_digest`;
  - §2: new development DDL and envelope layouts for `lan_link`/`lan_hint`
    (schema/header `0x7FFF0004`, no migration).

## Decisions needed

None pending. All of the following were chosen under the owner's standing
delegation (2026-11-02: "dont ask me to approve stuff, just pick whatever is
the best option"). That delegation also covers the spec clarifications and
the phase-boundary choices that would otherwise stop under roadmap step 4.

1. **Boundary with 2.10.** 2.9 includes the exchange messages only as far as
   the new-device grant needs them (A serves, B receives an empty-to-full
   transfer). The general exchange with merge, the post-link-mode exchange,
   sessions and discovery stay in 2.10.
   - Rejected: the full §7 exchange now. It pulls merge acceptance for
     partial object sets and the §5 handshake into this phase, which is the
     2.10 entry.
   - Rejected: deferring new-device initialization. The 2.9 entry names it.
2. **Discovery off in 2.9.** Windows run without DNS-SD (§3.2 explicitly
   allows that mode), so the QR `instance` is empty. The entry's "spoofed
   advertisements" criterion is tested as hostile responders and endpoints
   at hinted addresses: any endpoint source is an untrusted hint (§3.1).
   - Rejected: adding an mDNS dependency now. The crate choice and the
     Android NSD glue belong with receive windows and the platform adapter
     in 2.10.
3. **New-device staging is a private archive.** B writes the received
   manifest envelope and the objects into an unlinked private file in exact
   0004 §6 archive format:
   - B requests every reference in sorted order, so objects arrive in frame
     order;
   - B MACs the archive header with the received VK.

   The existing hardened `read_archive` then authenticates everything, and
   the existing new-path creation protocol (1.13b restore) builds the vault,
   with the first link row added in the first head.
   - Header minimum profiles: the grant carries no header configuration. B
     uses the only registered values (stored-data/1, derivation/1), and the
     manifest's configuration digest must match; otherwise `unsupported`.
   - Rejected: a new staging format with a second verifier.
4. **Timeouts** (per the step 1 clarification). Defaults: message 10 s,
   exchange idle 60 s, confirmation wait 10 min, connect 10 s, probe 2 s.
   `LanTimeouts` may only shorten them (tests do), never lengthen them.
5. **Prompt cancellation.** Sockets use 100 ms read/write timeout slices. A
   wrapper reader retries across slices, checks cancellation/lock and the
   deadline between them, and never loses frame bytes. Cancellation
   therefore takes effect within about 100 ms, even during the 10-minute
   confirmation wait.
6. **Window threading.** `PairingWindow::run` runs on the caller's thread
   with one scoped acceptor thread:
   - the acceptor polls a non-blocking listener every ≤ 25 ms;
   - it hands connections to the protocol loop one at a time;
   - while a valid hello is in progress, it probes extra connections per
     decision 4 and the §8.3 clarification;
   - other extra connections close immediately, unanswered.
7. **Bind scope.** `ListenScope::AllInterfaces` binds `[::]:port`, falling
   back to `0.0.0.0:port`. `LoopbackForTests` binds `127.0.0.1:port` and is
   the only way loopback endpoints appear in a QR. On the joining side,
   loopback endpoints are refused unless `allow_loopback` is set
   (0013 §1.4). Unspecified, multicast and broadcast endpoints and port 0
   are always refused.
8. **Labels.**
   - A passes the peer label when opening the window; B passes it when
     joining.
   - A label is 1–64 bytes of UTF-8 with no control characters; anything
     else is `InvalidInput`.
   - `created_at` is the core time source in milliseconds.
9. **Hints.** B stores the endpoint it authenticated as the link's first
   hint, in the same commit as the link. A stores none. Removal deletes the
   hint. Hints are read best-effort: an invalid hint is treated as absent.
10. **Deterministic X-Wing for vectors.** A non-default `test-vectors`
    feature on qv-crypto makes the existing derandomized constructors
    public. Only qv-sync's `[dev-dependencies]` enables it; resolver 3 keeps
    it out of normal builds.
    - Rejected: vectors without the real composition code (they would not
      prove what the drivers send).
11. **Peer errors.** After the pairing keys exist:
    - a local failure sends one best-effort error record with the mapped
      code, then closes;
    - frame-level errors (`FrameTooLarge`, truncation, I/O) close without
      sending (reviewed 0036 mapping);
    - before authentication nothing is sent.

    A received error record maps to the matching `LanError`. `cancelled`
    becomes `PeerCancelled`.
12. **Stale temporary files** (§10.5). Before building, `create_from_lan`
    removes the exact `.<name>.tmp-<16 hex>` (and `-journal`) siblings of
    the destination. Only regular files owned by the current user, checked
    with `lstat`, are removed. Stale staging temp names in the anchor
    directory get the same cleanup. No other file is removed.

## Design

**Components touched** (trust boundary):
- `qv-crypto::lan` (trusted crypto) and `keys.rs` (new purpose).
- `qv-protocol::{lan, oob}`: hostile-input codecs, key-free.
- `qv-store`: `schema.rs`, `head.rs`, `header.rs` (format), the new
  `lan_store.rs` and `lan_staging.rs`, `write.rs`, `vault.rs`, `restore.rs`,
  `rotation.rs`, `creation.rs`, `crash.rs`, `fs.rs`. Trusted, with hostile
  bytes only after authentication.
- `qv-sync::lan` (trusted orchestration of hostile peer input) and its new
  dependencies `qv-protocol` and `qv-encoding` (workspace crates; no new
  external dependency).
- `qv-core::lan` (session policy, lock and cancel).
- `fuzz/`, `.github/workflows/`.

LAN code in qv-store, qv-sync and qv-core is compiled on Linux and Android
only, as `exchange.rs` is. Non-Linux qv-core gets public stubs that return
`StoreError::Unsupported`.

**Interfaces** (signatures are the contract; private helpers are free):

```rust
// ---- qv-crypto/src/keys.rs ----
purposes! { …, /// Root of pairwise LAN link keys (0002 §3.3, 0013 §4.6).
            LanLink = "lan-link"; }
// PurposeKey<LanLink> is neither AeadKey nor MacKey; only lan.rs uses it.
impl VaultKey {
    /// Writes VK as a 32-byte bstr into a grant under construction (0013 §4.7).
    pub fn encode_for_transfer(&self, e: &mut qv_encoding::Encoder);
    /// VK from a received grant field: exactly 32 bytes, else LimitExceeded.
    pub fn from_transfer(bytes: &[u8]) -> Result<VaultKey, CryptoError>;
    /// Constant-time equality (B checks the password slot's VK).
    pub fn ct_eq(&self, other: &VaultKey) -> bool;
}

// ---- qv-crypto/src/lan.rs (additions; labels exactly as in 0013) ----
pub const PAIRING_SECRET_LEN: usize = 16;
pub struct PairingSecret(SecretArray<16>);          // P; Debug redacted, no Clone
impl PairingSecret {
    pub fn generate() -> Result<Self, CryptoError>;
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>; // != 16 → LimitExceeded
    pub fn expose_secret(&self) -> &[u8; 16];           // QR/manual display only
    /// pairing_id, K_hello, K_accept (§4.1).
    pub fn keys(self) -> Result<PairingKeys, CryptoError>;
}
pub struct PairingKeys { /* P, pairing_id, K_hello, K_accept */ }
impl PairingKeys {
    pub fn pairing_id(&self) -> &[u8; 16];
    pub fn hello_mac(&self, body: &[u8]) -> Result<MacTag, CryptoError>;
    pub fn verify_hello(&self, body: &[u8], tag: &MacTag) -> Result<(), CryptoError>;   // CT
    pub fn accept_mac(&self, transcript: &[u8]) -> Result<MacTag, CryptoError>;
    pub fn verify_accept(&self, transcript: &[u8], tag: &MacTag) -> Result<(), CryptoError>;
    /// (k_b2a, k_a2b) = HKDF(ss ‖ P, th, ["qv/lan-pair-key/v1", "b2a"|"a2b"]).
    pub fn record_keys(&self, ss: &XWingSharedSecret, th: &[u8; 32])
        -> Result<(RecordKey, RecordKey), CryptoError>;
}
/// H(x): SHA-256 of an already canonical encoding (0013 §1.2).
pub fn transcript_hash(canonical: &[u8]) -> [u8; 32];
/// nonce_B, secret until the reveal.
pub struct PairNonce(SecretArray<32>);
impl PairNonce { pub fn generate() -> Result<Self, CryptoError>;
                 pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError>;
                 pub fn expose_secret(&self) -> &[u8; 32];
                 /// H(["qv/lan-pair-commit/v1", nonce_B]).
                 pub fn commitment(&self) -> Result<[u8; 32], CryptoError>;
                 /// Constant-time check of a revealed nonce against commit_B.
                 pub fn matches(&self, commit: &[u8; 32]) -> Result<bool, CryptoError>; }
/// u32be(first 4 bytes of H(["qv/lan-pair-sas/v1", th, nonce_B])) mod 1e6.
#[derive(Clone, Copy, PartialEq, Eq)] pub struct Sas(u32);
impl Sas { pub fn compute(th: &[u8; 32], nonce_b: &PairNonce) -> Result<Sas, CryptoError>;
           pub fn digits(&self) -> [u8; 6] /* ASCII, zero padded */; }   // Debug prints "Sas(..)"
/// The generation's link root (purpose key `lan-link`).
pub struct LinkRoot(PurposeKey<purpose::LanLink>);
impl LinkRoot {
    pub fn derive(vk: &VaultKey, vault: VaultId, generation: KeyGeneration,
                  profile: DerivationProfile) -> Result<Self, CryptoError>;
    /// §4.6: HKDF(K_lan ‖ ss, H(["qv/lan-link-salt/v1", th, nonce_B, link_id]),
    ///            ["qv/lan-link/v1", vault_id, key_generation, link_id]).
    pub fn link_key(&self, ss: &XWingSharedSecret, th: &[u8; 32], nonce_b: &PairNonce,
                    link_id: &[u8; 16], vault: VaultId, generation: KeyGeneration)
        -> Result<LinkKey, CryptoError>;
    /// §4.8: MAC/1(K_lan, ["qv/lan-pair-prove/v1", th, role, vault_id, key_generation]).
    pub fn proof(&self, th: &[u8; 32], role: ProofRole, vault: VaultId,
                 generation: KeyGeneration) -> Result<MacTag, CryptoError>;
    pub fn verify_proof(&self, th: &[u8; 32], role: ProofRole, vault: VaultId,
                        generation: KeyGeneration, tag: &MacTag) -> Result<(), CryptoError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ProofRole { A, B }   // "a" / "b"
pub struct LinkKey(SecretArray<32>);                // Debug redacted, no Clone
pub const LINK_LABEL_MAX: usize = 64;
pub const LINK_ROW_CIPHERTEXT_MAX: usize = 512;
/// §9.1 sealed row: plaintext [link_key, label, created_at],
/// AAD ["qv/lan-link-row/v1", vault_id, key_generation, link_id].
pub fn seal_link_row(key: &PurposeKey<purpose::LocalState>, profile: StoredDataProfile,
                     vault: VaultId, generation: KeyGeneration, link_id: &[u8; 16],
                     link: &LinkKey, label: &str, created_at: u64) -> Result<Sealed, CryptoError>;
pub struct LinkRow { pub key: LinkKey, pub label: SecretBytes, pub created_at: u64 }
pub fn open_link_row(key: &PurposeKey<purpose::LocalState>, profile: StoredDataProfile,
                     vault: VaultId, generation: KeyGeneration, link_id: &[u8; 16],
                     nonce: &[u8; 24], ciphertext: &[u8]) -> Result<LinkRow, CryptoError>;
// RecordKey::from_secret stays pub(crate); record_keys() is the public path.

// ---- qv-crypto/src/xwing.rs ----
// from_test_seed / encapsulate_derand: #[cfg(any(test, feature = "test-vectors"))] pub.
// qv-crypto/Cargo.toml: [features] test-vectors = []
```

```rust
// ---- qv-protocol/src/lan.rs (typed messages; all bounded, borrowed) ----
pub const MAX_WANT_IDS: usize = 4096;
pub const MAX_MANIFEST_PART: usize = 1 << 20;
pub const MAX_MANIFEST_LENGTH: u64 = 64 << 20;
pub const MAX_FEATURES: usize = 16;
pub const MAX_OBJECT_ENVELOPE: usize = 1_048_576 + 512;
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum JoinMode { NewDevice, Link } // 0, 1
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Outcome { Unchanged, Merged, MergedWithConflicts } // 0..2
pub struct PairHello<'a> { pub profile: u64, pub pairing_id: [u8; 16], pub mode: JoinMode,
                           pub commit: [u8; 32], pub ek: &'a [u8; 1216], pub mac: [u8; 32] }
impl<'a> PairHello<'a> {
    pub fn encode_body(profile: LanProfile, pairing_id: &[u8; 16], mode: JoinMode,
                       commit: &[u8; 32], ek: &[u8; 1216]) -> Result<Zeroizing<Vec<u8>>, ProtocolError>;
    /// body ++ [mac] as one 7-element array (re-encodes body items; ≤ 4096).
    pub fn encode(body: &[u8], mac: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, ProtocolError>;
    /// Exact shape only; profile is returned raw for the caller's ordered checks.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError>;
}
pub struct PairAccept<'a> { pub nonce_a: [u8; 32], pub ct: &'a [u8; 1120], pub mac: [u8; 32] }
// encode(nonce_a, ct, mac) / decode; accept_transcript(hello_hash, nonce_a, ct) → canonical
//   ["qv/lan-pair-accept/v1", H(hello), nonce_A, ct]
pub fn pair_th(hello_hash: &[u8; 32], accept_hash: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, ProtocolError>;
//   canonical ["qv/lan-pair-th/v1", H(hello), H(accept)]; the caller hashes it
pub struct PairReveal { pub nonce_b: Zeroizing<[u8; 32]> }
pub struct PairGrant<'a> { pub vault_id: [u8; 16], pub key_generation: u32, pub vk: &'a [u8], pub link_id: [u8; 16] }
// grant encode takes `write_vk: impl FnOnce(&mut Encoder)`; key_generation must be 1..=u32::MAX
pub struct PairProve { pub vault_id: [u8; 16], pub key_generation: u32, pub proof: [u8; 32] }
pub struct PairProved { pub link_id: [u8; 16], pub proof: [u8; 32] }
pub struct PairDone;
pub struct State { pub vault_id: [u8; 16], pub key_generation: u32, pub manifest_hash: [u8; 32],
                   pub manifest_length: u64, pub features: Vec<u64> /* ≤ MAX_FEATURES */ }
pub struct ManifestPart<'a> { pub offset: u64, pub bytes: &'a [u8] /* ≤ MAX_MANIFEST_PART */ }
pub struct Want { pub ids: Vec<[u8; 16]> /* ≤ MAX_WANT_IDS */, pub last: bool }
pub struct ObjectMsg<'a> { pub envelope: &'a [u8] /* ≤ MAX_OBJECT_ENVELOPE */ }
pub struct Done { pub outcome: Outcome, pub manifest_hash: [u8; 32] }
pub struct ErrorMsg { pub code: ErrorCode }
// Each has `encode(...) -> Result<Zeroizing<Vec<u8>>, ProtocolError>` and
// `decode(&[u8]) -> Result<Self, ProtocolError>` built on MessageReader /
// write_message, plus `Received::decode(bytes, expected: Label)` returning
// either the expected message or ErrorMsg.

// ---- qv-protocol/src/oob.rs (§4.2) ----
pub const QR_LABEL: &str = "qv/lan-pair-qr/v1";
pub const MAX_QR_BYTES: usize = 1024;
pub const MAX_QR_ENDPOINTS: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct WireEndpoint { pub addr: std::net::IpAddr, pub port: u16 }
pub struct QrPayload<'a> { pub profile: u64, pub secret: &'a [u8; 16],
                           pub endpoints: Vec<WireEndpoint>, pub instance: &'a str }
pub fn encode_qr(profile: LanProfile, secret: &[u8; 16], endpoints: &[WireEndpoint],
                 instance: &str) -> Result<Zeroizing<Vec<u8>>, ProtocolError>;
/// Canonical shape; addr bstr 4|16; port 1..=65535; ≤ 8 endpoints; instance
/// empty or "qv-" + 16 lowercase hex.
pub fn decode_qr(bytes: &[u8]) -> Result<QrPayload<'_>, ProtocolError>;
/// RFC 4648 base32, no padding: 26 characters, uppercase, groups of five
/// joined with '-'.
pub fn encode_manual(secret: &[u8; 16]) -> Zeroizing<String>;
/// Ignores case, spaces and '-'; input ≤ 64 bytes; exactly 26 symbols; the 2
/// unused trailing bits must be zero.
pub fn decode_manual(text: &str) -> Result<Zeroizing<[u8; 16]>, ProtocolError>;
```

```rust
// ---- qv-store (Linux/Android) ----
pub const MAX_LAN_LINKS: usize = 64;
pub const MAX_LAN_HINT_ENDPOINTS: usize = 4;
pub struct LanLinkRow { pub link_id: [u8; 16], pub label: SecretBytes, pub created_at: Timestamp } // Debug redacted
impl UnlockedVault {
    /// Decrypts every row (≤ 64); any failure is Integrity.
    pub fn lan_links(&self) -> Result<Vec<LanLinkRow>, StoreError>;
    /// Best-effort hint; invalid or absent → empty.
    pub fn lan_hint(&self, link_id: &[u8; 16]) -> Vec<std::net::SocketAddr>;
    /// The current head's manifest envelope and reference index, for serving.
    pub fn lan_serve_state(&self) -> Result<LanServeState, StoreError>;
    /// The archive-format object envelope of a reference of `state`; the
    /// ciphertext hash is rechecked. Missing row → NotFound.
    pub fn lan_object_envelope(&self, state: &LanServeState, id: ObjectId)
        -> Result<Vec<u8>, StoreError>;
}
pub struct LanServeState { /* vault_id, generation, manifest_hash, envelope, refs: BTreeMap<ObjectId, len> */ }
impl LanServeState { pub fn vault_id(&self) -> VaultId; pub fn key_generation(&self) -> KeyGeneration;
                     pub fn manifest_hash(&self) -> &[u8; 32]; pub fn envelope(&self) -> &[u8];
                     pub fn contains(&self, id: ObjectId) -> bool; pub fn object_count(&self) -> usize; }
impl Write<'_> {
    /// 64-row limit (LimitExceeded), fresh link_id (InvalidEdit), label rule
    /// (InvalidEdit); applied by commit, with the hint, as one change.
    pub fn add_lan_link(&mut self, link_id: [u8; 16], key: &LinkKey, label: &str,
                        created_at: Timestamp, hint: &[std::net::SocketAddr]) -> Result<(), StoreError>;
    /// Deletes the row and its hint; NotFound if absent.
    pub fn remove_lan_link(&mut self, link_id: &[u8; 16]) -> Result<(), StoreError>;
}
/// B's private staging archive (decision 3).
pub struct LanStaging { /* unlinked File, header, manifest, wanted, next, total */ }
impl LanStaging {
    /// Order: envelope length ≤ MAX_ARCHIVE_MANIFEST_FRAME → SHA-256 ==
    /// manifest_hash → envelope generation/profile → manifest AEAD/decode/
    /// validate (0004 §4.1–4.2) → configuration digest with the minima
    /// stored-data/1, derivation/1 (else Unsupported) → reference budgets
    /// (count ≤ MAX_OBJECTS, total ≤ MAX_ARCHIVE_TOTAL_LENGTH) → write prefix,
    /// header (MAC under vk) and manifest frame into an unlinked file in
    /// `private_dir` (checked private).
    pub fn begin(private_dir: &Path, vk: &VaultKey, vault: VaultId, generation: KeyGeneration,
                 manifest_hash: &[u8; 32], envelope: &[u8], cancelled: &dyn Fn() -> bool)
        -> Result<Self, StoreError>;
    /// The object IDs to request, in sorted reference order.
    pub fn wanted(&self) -> &[ObjectId];
    /// The next expected object: decode the envelope, check its ID is the
    /// next wanted (else NotFound), generation, profile, exact length and
    /// SHA-256 against the reference before anything else (Integrity), then
    /// append the frame.
    pub fn add_object(&mut self, envelope: &[u8]) -> Result<(), StoreError>;
    /// Every wanted object received (else Integrity); sync, rewind, then the
    /// full `read_archive` authentication (every role and attachment, exact EOF).
    pub fn finish(self, vk: &VaultKey, cancelled: &dyn Fn() -> bool)
        -> Result<VerifiedLanStaging, StoreError>;
}
pub enum StagedKeyslot { Unique, Missing, Conflicted }
pub struct VerifiedLanStaging { /* file, opened archive */ }
impl VerifiedLanStaging {
    pub fn manifest(&self) -> &Manifest;
    pub fn keyslot(&mut self, vk: &VaultKey) -> Result<StagedKeyslot, StoreError>;
    /// The vault name of the meta record's head (the first in sorted version
    /// order when conflicted); display only.
    pub fn vault_name(&mut self, vk: &VaultKey) -> Result<SecretBytes, StoreError>;
    /// Unlocks the unique keyslot's password slot and requires its VK to equal
    /// `vk` in constant time (WrongPassword otherwise).
    pub fn verify_password(&mut self, vk: &VaultKey, password: &MasterPassword)
        -> Result<PasswordProof, StoreError>;
}
pub struct PasswordProof { /* the verified slot body; not constructible outside qv-store */ }
pub struct NewLanLink<'a> { pub link_id: [u8; 16], pub key: &'a LinkKey, pub label: &'a str,
                            pub created_at: Timestamp, pub hint: &'a [std::net::SocketAddr] }
impl VaultFile {
    /// §10.5: the 1.13b creation protocol (private temp, verify, fsync, anchor,
    /// no-replace rename) with a fresh replica/writer, the adopted slot, the
    /// staged objects and manifest, and the link row in the first head.
    pub fn create_from_lan(path: &Path, staging: VerifiedLanStaging, proof: PasswordProof,
                           vk: &VaultKey, anchors: &AnchorDir, link: NewLanLink<'_>,
                           cancelled: &dyn Fn() -> bool) -> Result<(), StoreError>;
}
```

```rust
// ---- qv-sync/src/lan/ (Linux/Android) ----
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanError {
    NoPeer,          // no candidate authenticated (wrong code, unreachable, removed link)
    Timeout,         // an authenticated peer stopped responding
    Cancelled,       // local cancel or lock
    PeerCancelled,   // peer sent `cancelled` (mismatch or cancel there)
    CodeObserved,    // a second valid pairing hello (§4.3)
    TooManyAttempts, // 16 failed attempts (§8.3)
    WindowExpired,   // time limit (§8.2)
    VaultMismatch, Unsupported, Limit, Integrity, Busy, StateChanged, Keyslot, Protocol,
    Io,              // bind/accept/connect failure
    Store(StoreError),
}
pub struct LanTimeouts { pub message: Duration, pub idle: Duration, pub confirm: Duration,
                         pub connect: Duration, pub probe: Duration }  // Default = spec values
impl LanTimeouts { pub fn validate(&self) -> Result<(), LanError> /* none above default, none zero */; }
pub enum ListenScope { AllInterfaces, LoopbackForTests }
pub struct EndpointPolicy { pub allow_loopback: bool }
// Pure pairing steps (pub(crate)), used by the drivers and the vector test:
//   hello_for(keys, mode, nonce_b, ek) → (hello bytes, hello hash)
//   check_hello(keys, bytes) → CheckedHello{mode, commit, ek, hash} | Reject (ordered as §4.3)
//   accept_for(keys, hello_hash, nonce_a, ct) → (accept bytes, accept hash)
//   check_accept(keys, hello_hash, bytes) → (nonce_a, ct, accept hash)
//   th(hello_hash, accept_hash)
// Drivers (pub, used by qv-core) take traits implemented by qv-core:
pub trait ApproverVault {               // A's session, reached with short calls
    fn context(&self) -> Result<ApproverContext, LanError>;  // vault id, generation, name, LinkRoot
    fn commit_link(&self, link_id: [u8; 16], key: &LinkKey) -> Result<(), LanError>;
    fn grant(&self, sealer: &mut RecordSealer, link_id: &[u8; 16]) -> Result<Vec<u8>, LanError>; // sealed grant record
    fn serve_state(&self) -> Result<LanServeState, LanError>;
    fn object(&self, state: &LanServeState, id: ObjectId) -> Result<Vec<u8>, LanError>;
}
pub trait Confirm { fn confirm(&mut self, sas: &Sas, mode: JoinMode, vault_name: &str) -> bool; }
pub struct PairingWindow { /* listener, PairingKeys, scope, limit, label policy */ }
impl PairingWindow {
    pub fn open(scope: ListenScope, port: Option<u16>, limit: Duration) -> Result<Self, LanError>;
    pub fn port(&self) -> u16;
    pub fn qr(&self, addrs: &[IpAddr]) -> Result<Zeroizing<Vec<u8>>, LanError>;
    pub fn manual_code(&self) -> Zeroizing<String>;
    pub fn expires_at(&self) -> Instant;
    pub fn run(self, vault: &dyn ApproverVault, confirm: &mut dyn Confirm, timeouts: &LanTimeouts,
               cancelled: &(dyn Fn() -> bool + Sync)) -> Result<Approved, LanError>;
}
pub struct Approved { pub mode: JoinMode, pub link_id: [u8; 16], pub peer_confirmed: bool }
pub struct JoinCode { /* PairingSecret, endpoints from the QR */ }
impl JoinCode { pub fn from_qr(bytes: &[u8]) -> Result<Self, LanError>;
                pub fn from_manual(text: &str) -> Result<Self, LanError>; }
pub trait JoinerUi {
    fn show_code(&mut self, sas: &Sas) -> bool;            // link mode: user confirms; new device: displayed, false cancels
    fn confirm_vault(&mut self, vault_name: &str, sas: &Sas) -> bool;   // §10.4
    fn master_password(&mut self) -> Option<MasterPassword>;             // None cancels; asked again after WrongPassword
}
pub fn join_new_device(code: JoinCode, extra: &[SocketAddr], policy: EndpointPolicy,
                       private_dir: &Path, ui: &mut dyn JoinerUi, timeouts: &LanTimeouts,
                       cancelled: &(dyn Fn() -> bool + Sync)) -> Result<JoinedNewDevice, LanError>;
pub struct JoinedNewDevice { pub vk: VaultKey, pub staging: VerifiedLanStaging, pub proof: PasswordProof,
                             pub link_id: [u8; 16], pub link_key: LinkKey, pub endpoint: SocketAddr }
pub trait JoinerVault { fn context(&self) -> Result<JoinerContext, LanError>;  // vault id, generation, LinkRoot
                        fn commit_link(&self, link_id: [u8; 16], key: &LinkKey, endpoint: SocketAddr) -> Result<(), LanError>; }
pub fn join_link(code: JoinCode, extra: &[SocketAddr], policy: EndpointPolicy, vault: &dyn JoinerVault,
                 ui: &mut dyn JoinerUi, timeouts: &LanTimeouts,
                 cancelled: &(dyn Fn() -> bool + Sync)) -> Result<[u8; 16], LanError>;
```

```rust
// ---- qv-core/src/lan.rs ----
pub use qv_sync::lan::{JoinCode, JoinMode, LanError, LanTimeouts, ListenScope, Sas};
pub enum CoreError { …, Lan(LanError) }   // exit-code mapping arrives in 2.10 (0013 §11)
pub struct PairingOptions { pub peer_label: String, pub scope: ListenScope, pub port: Option<u16>,
                            pub limit: Duration /* ≤ 10 min */, pub timeouts: LanTimeouts }
pub struct JoinOptions { pub label: String, pub extra_endpoints: Vec<SocketAddr>,
                         pub allow_loopback: bool /* tests only */, pub timeouts: LanTimeouts }
pub struct LanLinkHandle { /* session tag + link id */ }  pub struct LanLinkSummary { pub handle, pub label: Text, pub created_at: Timestamp }
pub struct PairingCode { pub manual: Zeroizing<String>, pub qr: SecretBytes, pub port: u16 }
pub struct ApproveReport { pub mode: JoinMode, pub link: LanLinkHandle, pub peer_confirmed: bool }
pub trait ApproverUi { fn confirm(&mut self, sas: &str, mode: JoinMode, vault_name: &str) -> bool; }
impl Session {
    /// Refuses read-only (recovery) sessions and invalid options before binding.
    pub fn open_pairing_window(&self, options: PairingOptions) -> Result<CorePairingWindow, CoreError>;
    pub fn join_link(&self, code: JoinCode, options: JoinOptions, ui: &mut dyn JoinerUi,
                     cancel: Option<&CancelToken>) -> Result<LanLinkHandle, CoreError>;
    pub fn lan_links(&self) -> Result<Vec<LanLinkSummary>, CoreError>;
    pub fn remove_lan_link(&self, link: &LanLinkHandle) -> Result<(), CoreError>;
}
impl CorePairingWindow {
    pub fn code(&self, local_addrs: &[IpAddr]) -> Result<PairingCode, CoreError>;
    pub fn expires_at(&self) -> Instant;
    /// Blocks; holds the session mutex only for short calls; a lock or `cancel`
    /// closes the window within ~100 ms (except inside `ui.confirm`, which the
    /// frontend must end on cancel).
    pub fn run(self, session: &Session, ui: &mut dyn ApproverUi,
               cancel: Option<&CancelToken>) -> Result<ApproveReport, CoreError>;
}
impl Core {
    /// §10: pair, receive, confirm, password, create at `destination` (new path),
    /// then unlock it.
    pub fn join_new_device(&self, code: JoinCode, destination: &Path, options: JoinOptions,
                           ui: &mut dyn JoinerUi, cancel: Option<&CancelToken>) -> Result<Session, CoreError>;
}
```

**Data and control flow.**

*Approver (A), per connection* (§4; `run`):
1. Acceptor → worker. Read one handshake frame with the message timeout.
2. Decode `PairHello`, then check in exactly this order: profile
   (`LanProfile::from_id`), `pairing_id` (constant time), MAC over
   `body_without_last` (constant time), `XWingEncapsKey::from_bytes`. Any
   failure closes the connection, sends nothing and counts a failed attempt.
   At 16 attempts the window closes (`TooManyAttempts`).
3. A valid hello is final for the window. The window records it (`Used`) and
   keeps its bytes for the acceptor's comparison.
4. Encapsulate, draw `nonce_A`, send `PairAccept`, compute `th`, then the
   record keys: A seals with `k_a2b` and opens with `k_b2a`.
5. Read `PairReveal` (message timeout) and check the commitment (constant
   time; failure → error `protocol`). Compute the SAS.
6. `confirm.confirm(sas, mode, vault_name)`. A rejection sends `cancelled`
   and aborts with `Cancelled`. If the acceptor flagged `CodeObserved`, the
   pairing aborts before or after the confirmation, before any release.
7. **New device:**
   - draw `link_id`, derive `link_key` (`LinkRoot` from the session) and
     commit the link row;
   - send the grant record;
   - run the responder side of the new-device exchange: read B's `State`
     (generation/vault must match, else `vault_mismatch`; hash all-zero,
     length 0 and features `[]` required, else `protocol`/`unsupported`);
   - send `State` from `serve_state`, then `Manifest` parts (≤ 1 MiB each,
     contiguous);
   - read `Want`s until `last` (≤ 4,096 IDs each, ≤ 250,000 in total, each in
     the served state, no duplicates, else `protocol`);
   - send one `Object` per ID in request order. A missing row is
     `state_changed`; a hash mismatch is `integrity`;
   - send `Want([], last = true)`;
   - read B's `Done` (idle timeout), then send `Done(Unchanged, A's hash)`.

   `peer_confirmed` is true only when B's `Done` arrived (§4.7). Its absence
   after the link commit yields `Approved { peer_confirmed: false }`.
8. **Link mode:**
   - read `PairProve` (confirmation timeout). The vault and generation must
     match, and the proof must verify with A's `LinkRoot` (role B). Any
     failure sends `vault_mismatch` and aborts with nothing stored;
   - draw `link_id`, derive `link_key`, commit the row, then send
     `PairProved` (role A);
   - read `PairDone` (message timeout). No `PairDone` gives
     `peer_confirmed: false`;
   - close.
9. Any abort zeroizes P/keys/nonces/`ss` (drop). Aborts after authentication
   send one error record (decision 11). The window always closes after a
   valid hello.

*Acceptor while `Used`* (§8.3 clarification): read one handshake frame from
an extra connection (probe timeout) and close it. Bytes equal to the
accepted hello are refused. A different hello that passes the full step-2
checks sets `CodeObserved`, aborting the pairing and closing the window.
Anything else counts a failed attempt. Each step also checks time limit,
cancellation and lock.

*Joiner (B):*
- Candidates: QR endpoints plus extra endpoints, deduplicated, at most 16,
  filtered by the endpoint policy.
- For each candidate:
  - draw a fresh `nonce_B` and X-Wing pair;
  - connect (connect timeout) and send the hello;
  - read the accept (message timeout).

  A wrong MAC or a closed connection moves on to the next candidate. The
  first valid accept authenticates A; later failures abort, with no retry.
  No candidate authenticated → `NoPeer`.
- Decapsulate (failure → `Integrity`, abort) and derive `th`, then the
  record keys: B seals with `k_b2a` and opens with `k_a2b`. Send
  `PairReveal`, compute the SAS, then `ui.show_code(sas)`. A false return
  sends `cancelled` and aborts.
- **New device:**
  - read the grant (confirmation timeout) or an error. The grant fields
    give the vault, generation, VK (`from_transfer`) and `link_id`;
  - derive `LinkRoot` and `link_key`;
  - send `State` (zeros, length 0, `[]`);
  - read A's `State`: the vault and generation must equal the grant
    (`vault_mismatch`); length 0 or above 64 MiB is `protocol` or `limit`,
    checked before allocating; features are checked;
  - read the manifest parts into a buffer reserved once at
    `manifest_length` (contiguous offsets, total exact), then
    `LanStaging::begin`;
  - send `Want`s for `wanted()` (4,096 per message, the last flagged), then
    read one `Object` per ID into `add_object`;
  - read A's `Want`, which must be `[]` with `last = true`;
  - `finish()` (`Integrity` → send `integrity`), then `keyslot()`: `Missing`
    or `Conflicted` sends `keyslot` and aborts;
  - send `Done(Merged, A's hash)` and read A's `Done`, best-effort (bounded
    by the message timeout);
  - close the connection;
  - `ui.confirm_vault(name, sas)` (false → `Cancelled`), then
    `ui.master_password()` until `verify_password` succeeds or the UI
    returns `None`;
  - return `JoinedNewDevice`. Core then calls `create_from_lan` and unlocks.
- **Link mode** (after `show_code` returned true):
  - send `PairProve` (role B);
  - read `PairProved` (confirmation timeout) or an error;
  - verify proof A (failure sends `protocol` and aborts; nothing stored);
  - commit the link row with the hint;
  - send `PairDone`;
  - close.

*Store writes:*
- **Link insert/remove:** the ordinary `Write` path. Rows staged in the
  transaction, then the manifest, then the head whose key 8 is the new
  digest, then `COMMIT`, then the anchor (0004 §5.2). A new crash point
  `LanLinksWritten` sits after the row change, before the manifest and head.
  A crash before `COMMIT` leaves the old rows and head; after it, the
  anchor advances on the next open.
- **Digest:** `lan_links_digest = SHA-256(canonical ["qv/lan-links/v1",
  [[link_id, SHA-256(sealed)], …] sorted by link_id])`. An empty set still
  hashes the empty list.
- **On open:**
  - the row count is at most 64 (`LimitExceeded`), checked before any value
    is read;
  - each `link_id` is 16 bytes, `key_generation` is the header's, and
    `sealed` is a blob of at most `LINK_ROW_ENVELOPE_MAX`; otherwise
    `Integrity`;
  - the recomputed digest must equal head key 8 (`Integrity`).

  Rows are decrypted only by `lan_links`/`add`/`remove`. Hints are
  shape-checked lazily.
- **Create, restore and rotation:** zero rows with the empty digest. An
  archive never carries rows, and restore creates none.
- **`create_from_lan`:** the restore protocol with one extra fill step (the
  link row and hint inserted in the same transaction, with digest key 8 in
  the first head):
  1. stale temp cleanup;
  2. temp build;
  3. reopen, verify, and compare the persisted manifest with the staged one;
  4. fsync;
  5. anchor;
  6. no-replace rename and directory fsync.

  Nothing appears at `path` before step 6. An existing `path` is `Exists`.

**Secrets and hostile input:**
- **Protected containers:**
  - `PairingSecret`, `PairingKeys`, `PairNonce` (until reveal),
    `XWingDecapsKey`, `XWingSharedSecret`, `RecordKey`, `LinkRoot`,
    `LinkKey` and VK all live in `SecretArray`;
  - grant plaintext is built only in `Zeroizing` encoder buffers and opened
    into `SecretBytes`;
  - the manual code and QR bytes are `Zeroizing` or `SecretBytes`, since
    they display P;
  - labels and vault names are `SecretBytes`.

  None of these has `Debug` content or `Clone`. `Sas` shows only through
  `digits()`.
- **Hostile bytes:**
  - frames are bounded by phase (4096 for cleartext handshake frames, the
    session bound for records);
  - typed decoders check exact shapes and lengths;
  - nothing is decrypted, decapsulated or derived before the hello MAC;
  - B checks the accept MAC before decapsulating;
  - manifest length is checked against 64 MiB before allocating, and each
    part against 1 MiB;
  - object count and staging bytes are bounded by store budgets before
    writing;
  - each object's length and SHA-256 are checked against the authenticated
    reference before it is written to staging;
  - full AEAD and role authentication happen before `Done`, and nothing
    reaches SQLite before then (staging is an archive file, not SQLite).
- **Constant time:** every MAC/proof/commitment comparison, and `pairing_id`
  matching.
- **No secret** in errors, `LanError`, logs or argv. No `unwrap`/`expect` on
  peer data, and no `unsafe`.

**Errors:** `LanError` is data-free. Local→wire codes:

| Failure | Code sent (after keys) |
|---|---|
| vault or generation mismatch, link proof B | `vault_mismatch` |
| unknown required feature | `unsupported` |
| manifest > 64 MiB, store budgets | `limit` |
| staging, AEAD or hash failure | `integrity` |
| user reject, cancel, lock | `cancelled` |
| `Changed`/`Locked` during commit or serving | `busy` |
| object row gone | `state_changed` |
| keyslot missing or conflicted | `keyslot` |
| everything else | `protocol` |

Core wraps it as `CoreError::Lan`. Store errors from local operations
(commit, create) surface as `CoreError::Store`.

**Dependencies:** none new. `qv-sync` adds workspace `qv-protocol` and
`qv-encoding`. `qv-crypto` adds the dev-dependency `qv-protocol` only if the
key-schedule tests need it (prefer not). The `test-vectors` feature is
enabled only by qv-sync's dev-dependencies. `cargo deny`/`vet` must still
pass; `Cargo.lock` changes only for the new path edges.

## Steps

### Step 1 — Spec clarifications

- [x] **Do:**
  - apply the 0013 §1.3, §7.1 and §8.3 clarifications and the 0004 §2/§2.3
    layouts, each with a Changelog line ("owner-delegated, standing
    2026-11-02; plan 0037");
  - add a one-line note to the `specs/README.md` LAN paragraph.

  0004 dev layouts:
  - `CREATE TABLE lan_link (link_id BLOB PRIMARY KEY CHECK (length(link_id) = 16), key_generation INTEGER NOT NULL, sealed BLOB NOT NULL) STRICT, WITHOUT ROWID`;
  - `CREATE TABLE lan_hint (link_id BLOB PRIMARY KEY CHECK (length(link_id) = 16), sealed BLOB NOT NULL) STRICT, WITHOUT ROWID`;
  - sealed envelope `[1, data_profile, nonce: bstr24, ciphertext]` for both;
    ciphertext ≤ 512 bytes;
  - hint plaintext `[endpoints: [[addr: bstr4|16, port: uint]] (≤ 4),
    last_success_at: uint (ms, 0 = never)]`, AAD
    `["qv/lan-hint/v1", vault_id, key_generation, link_id]`;
  - head key 8 mandatory;
  - schema/header `0x7FFF0004`.
- **Files:** `specs/0013-lan-sync-protocol.md`, `specs/0004-local-storage.md`, `specs/README.md`.
- **Done when:** the text says exactly the clarifications above; statuses
  unchanged (Accepted).
- **Verify:** `rg -n 'lan_links_digest|0x7FFF0004|last = true' specs/`.

### Step 2 — qv-crypto key schedule

- [x] **Do:** implement the qv-crypto interface above: the `LanLink`
  purpose, the `lan.rs` additions, the `VaultKey` transfer/ct_eq and the
  `test-vectors` feature. Tests:
  - every derivation against an independent in-test construction of the
    canonical info/salt bytes;
  - every MAC and proof verifies; each fails with a swapped role, vault,
    generation, `th`, `link_id` or label;
  - `PairNonce::matches` rejects a one-bit change;
  - SAS: digits are zero-padded; a changed `nonce_B` or `th` changes the
    value (fixed inputs);
  - link rows: round trip; wrong AAD element, label > 64 bytes and
    tampering fail; plaintext bounded;
  - redacted `Debug` for each new type;
  - `from_transfer` with 31/33 bytes → `LimitExceeded`.
- **Files:** `crates/qv-crypto/{Cargo.toml,src/lan.rs,src/keys.rs,src/xwing.rs,src/lib.rs}`.
- **Done when:** the tests pass; no new public constructor of `RecordKey`.
- **Verify:** `cargo test --locked -p qv-crypto lan`; `cargo clippy --locked -p qv-crypto --all-targets --features test-vectors -- -D warnings`.

### Step 3 — qv-protocol typed messages and out-of-band codes

- [x] **Do:** implement `lan.rs` and `oob.rs` per the interface, on
  `MessageReader`/`write_message`. Tests:
  - every message: round trip, wrong label, wrong arity, out-of-range
    enums (mode 2, outcome 3, generation 0 or > u32), oversized bytes and
    arrays → `Malformed`;
  - `Received::decode` returns `ErrorMsg` for error records;
  - QR: round trip; 9 endpoints, a 5-byte address, port 0 or 65536, a bad
    instance, the wrong label, trailing bytes → `Malformed`;
  - manual code: RFC 4648 known vectors (as 16-byte cases), case/space/dash
    tolerance, 25 or 27 symbols, non-zero pad bits, invalid symbols and
    oversized input → `Malformed`;
  - proptest no-panic over both decoders.
- **Files:** `crates/qv-protocol/src/{lib.rs,lan.rs,oob.rs}`.
- **Done when:** the tests pass; still no qv dependency besides qv-encoding.
- **Verify:** `cargo test --locked -p qv-protocol`.

### Step 4 — qv-store link state and serving reads

- [x] **Do:**
  - bump `FORMAT` to `0x7FFF0004`;
  - add both tables to `TABLES`/`EXPECTED` (no autoindex rows) and head key
    8 (mandatory; update the docs table and golden);
  - add `lan_store.rs` (digest, shape checks, row seal/open through
    qv-crypto, hint seal/open, reads);
  - open-time checks in `load_state`;
  - `Write::add_lan_link`/`remove_lan_link` integrated into
    `commit_cancellable` with crash point `LanLinksWritten`;
  - empty link state in `vault.rs` create, `restore.rs` and `rotation.rs`;
  - `lan_links`, `lan_hint`, `lan_serve_state`, `lan_object_envelope`
    (reusing the archive writer's envelope encoding and hash check).

  Tests:
  - head round trip/golden, missing key 8 → `Integrity`;
  - add/remove commits, digest changes, lists;
  - **0012 §1 Peer state rollback** (tagged only if the checker lists it;
    otherwise untagged): planting a removed row back by SQL, modifying
    `sealed`, a row with another generation, 65 rows → open fails with
    `Integrity`/`LimitExceeded`;
  - 64-link limit and duplicate `link_id`;
  - a crash at each of `LanLinksWritten`, `HeadWritten` and `Committed`
    reopens to the old or the new state with the anchor consistent;
  - archives and restore carry no links; the rotation replacement has none;
  - serving: the envelope hash equals the head's manifest hash, an object
    envelope matches the archive frame bytes, a missing row → `NotFound`;
  - a corrupt hint reads as empty.
- **Files:** `crates/qv-store/src/{schema.rs,head.rs,header.rs,lan_store.rs,write.rs,vault.rs,restore.rs,rotation.rs,crash.rs,lib.rs}` and their test modules.
- **Done when:** all qv-store tests pass, including the existing
  schema/golden tests updated for the new format.
- **Verify:** `cargo test --locked -p qv-store`.

### Step 5 — qv-store new-device staging and creation

- [x] **Do:**
  - `lan_staging.rs` with `LanStaging`, `VerifiedLanStaging`,
    `StagedKeyslot` and `PasswordProof`;
  - `VaultFile::create_from_lan` built on the restore internals (extend
    `restore.rs`'s `build` with an optional link fill; do not copy it);
  - `fs::remove_stale_temps` per decision 12.

  Tests:
  - stage a real vault's served state and objects, then finish,
    `verify_password` and create; the unlocked result equals the source
    manifest and has exactly one link;
  - wrong `manifest_hash`, a manifest under another VK, wrong configuration
    minima → `Unsupported`; an out-of-order or unrequested object →
    `NotFound`; a flipped ciphertext byte, a wrong length or a missing last
    object → `Integrity`;
  - over-budget count/length → `LimitExceeded` before any staging write;
  - a conflicted or missing keyslot → `Conflicted`/`Missing`;
  - a wrong password → `WrongPassword`;
  - an existing destination → `Exists`;
  - crash at `CreateBuilt` or `CreateAnchored` → nothing at `path`; the
    next attempt removes the stale temp and succeeds;
  - an unrelated dot-file is never removed.
- **Files:** `crates/qv-store/src/{lan_staging.rs,restore.rs,fs.rs,lib.rs}`.
- **Done when:** the tests pass.
- **Verify:** `cargo test --locked -p qv-store lan`.

### Step 6 — qv-sync LAN transport, pairing and new-device exchange

- [x] **Do:**
  - `crates/qv-sync/src/lan/{mod.rs,transport.rs,steps.rs,approver.rs,joiner.rs,exchange.rs,window.rs,endpoint.rs}`
    per the interface and control flow;
  - add the qv-protocol/qv-encoding dependencies and the qv-crypto
    `test-vectors` dev-dependency feature.

  Tests (`lan_enroll_*` names, loopback with short `LanTimeouts`; test-only
  in-memory `ApproverVault`/`JoinerVault` built on a real `UnlockedVault`):
  - both modes complete; both sides derive the same link key (compare via
    the record layer, never by exposing keys);
  - new device ends with a verified staging whose manifest equals A's;
  - **0012 §1 LAN discovery mistaken for trust:**
    - a spoofed endpoint first in the candidate list (a listener that
      replies with a garbage or wrong-MAC accept) → B moves on to the real
      A and pairs; the spoof only ever saw the hello;
    - a wrong code → A sends nothing, B → `NoPeer`, the failure is counted;
    - a raced second valid hello → `CodeObserved`, no grant, no link row;
    - an identical replayed hello on a new connection → refused;
    - profile 2, a swapped `pairing_id` or a flipped mode → closed silently
      and counted;
    - a grant or state with another vault/generation → `VaultMismatch`;
    - a link-mode proof from another generation's `LinkRoot`, or a reflected
      role (A's proof sent as B's) → `VaultMismatch` or `Protocol`; nothing
      stored;
    - a reveal not matching the commitment → aborts (the ordering test);
    - user rejection on either side → `Cancelled`/`PeerCancelled`;
  - abuse limits: 16 bad hellos → `TooManyAttempts`; window time limit →
    `WindowExpired`; an oversized (5000-byte) handshake frame is refused
    with no reply and nothing allocated; a silent peer → bounded by the
    message timeout;
  - cancellation: cancel during the confirmation wait returns within 1 s,
    with no link committed;
  - exchange negatives: a `Want` ID outside the state, a duplicate ID,
    4,097 IDs → `protocol`; an unrequested or out-of-order `Object` →
    `protocol`; a manifest length over 64 MiB → `limit` before allocation;
    non-contiguous parts → `protocol`; a missing object row on A →
    `state_changed`;
  - B never sends `Done` → A reports `peer_confirmed: false` and keeps the
    link.
- **Files:** `crates/qv-sync/{Cargo.toml,src/lib.rs,src/lan/*}`, `Cargo.lock`.
- **Done when:** `cargo test --locked -p qv-sync lan_enroll` passes.
- **Verify:** `cargo test --locked -p qv-sync lan_enroll`; `cargo clippy --locked -p qv-sync --all-targets -- -D warnings`.

### Step 7 — qv-core LAN API

- [x] **Do:** `crates/qv-core/src/lan.rs` per the interface:
  - `ApproverVault`/`JoinerVault` over `Session` (short `read`/`mutate`
    calls; the grant is sealed inside a `read` closure);
  - `CoreError::Lan`;
  - lock or cancel wiring (`session.locking` plus `CancelToken`);
  - non-Linux stubs;
  - re-exports in `lib.rs`.

  Tests (two Core instances with separate anchor dirs, loopback):
  - new device end to end: B gets a `Session` whose overview equals A's;
    both have one link;
  - link mode between two copies of one vault (a restored snapshot);
  - A's session lock during the confirmation → `Cancelled`, window closed,
    no link;
  - a read-only (recovery) session refuses to open a window;
  - remove a link: gone, and a new link-mode attempt with the old link has
    nothing left to verify. Removal preserves the vault contents;
  - **generation transitions:** after rotation the replacement lists no
    links, and the old `LinkRoot` proof fails against the new generation;
  - archive export/restore carries no links;
  - B's older-generation file (same vault ID) is byte-identical after a
    new-device join to another path.
- **Files:** `crates/qv-core/{Cargo.toml?,src/lan.rs,src/lan_tests.rs,src/lib.rs,src/error.rs}`.
- **Done when:** the tests pass; the `Debug` impls of reports and handles
  are redacted.
- **Verify:** `cargo test --locked -p qv-core lan`.

### Step 8 — Interoperability vectors

- [x] **Do:**
  - write `crates/qv-sync/tests/vectors/qv-dev-lan-pairing.txt` (header:
    development-only, regenerated freely until the freeze) from one
    deterministic run of the pure steps with fixed inputs:
    - P = 00..0f; `nonce_B` = 0x11×32; `nonce_A` = 0x22×32;
    - B's X-Wing pair from draft-11 vector 1's seed, and A's encapsulation
      from vector 1's eseed;
    - `link_id` = 0x33×16; VK = 0x44×32; vault ID = 0x55×16; generation 1;
  - list each value as hex:
    - `pairing_id`, `K_hello`, `K_accept`;
    - hello body, hello, H(hello);
    - accept transcript, accept, H(accept), th;
    - `k_b2a`, `k_a2b`, commit, SAS;
    - `K_lan`, link salt, link key, proof A, proof B;
    - grant plaintext, the link-row AAD, and the links digest for {link_id};
    - the reveal and grant records for sequence numbers 0 and 1 (checked in
      Rust only);
  - a Rust test regenerates and compares them (`QV_WRITE_VECTORS=1`
    rewrites);
  - `crates/qv-sync/tests/vectors/crosscheck_lan.py` (stdlib: hashlib,
    hmac; own canonical CBOR and HKDF) recomputes every non-AEAD,
    non-X-Wing value from the inputs plus the vector's `ss`/`ct`, and
    exits non-zero on mismatch.
- **Files:** as listed.
- **Done when:** the Rust test passes and `python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py` prints OK.
- **Verify:** both commands.

### Step 9 — Fuzzing and CI

- [x] **Do:**
  - extend `fuzz/fuzz_targets/lan_message.rs` to call every typed decoder
    (and `Received::decode`) on each frame body;
  - add `fuzz/fuzz_targets/lan_oob.rs` (first byte selects QR or manual;
    `decode_qr`, `decode_manual`);
  - register `lan_oob` in `fuzz/Cargo.toml`;
  - add it to the `ci.yml` smoke list and the `fuzz-extended.yml` matrix
    (`max_len` 1024).
- **Files:** `fuzz/{Cargo.toml,Cargo.lock,fuzz_targets/lan_message.rs,fuzz_targets/lan_oob.rs}`, `.github/workflows/{ci.yml,fuzz-extended.yml}`.
- **Done when:** both targets build and a bounded local run is clean.
- **Verify:** `cargo +nightly-2026-10-01 fuzz run -s none <target> -- -max_total_time=60 -use_cmp=0` for both (musl notes); `cargo fetch --locked --manifest-path fuzz/Cargo.toml`.

### Step 10 — Documentation

- [x] **Do:**
  - `ARCHITECTURE.md` §3:
    - qv-crypto, qv-protocol, qv-store, qv-sync and qv-core rows;
    - a roadmap 2.9 paragraph;
    - replace the stale "Exact discovery, enrollment and session protocols
      remain open in 0005 §6" sentence with a 0013 reference (review
      pending, D12);
  - `CHANGELOG.md` Unreleased;
  - roadmap tick/plan link/log;
  - the `plans/README.md` row.
- **Files:** as listed.
- **Done when:** the documentation-duties table is satisfied.
- **Verify:** `sh scripts/check-spdx.sh`.

## Test plan

- **Final verification:**
  - all `AGENTS.md` gates on the final tree (SPDX, matrix, fmt, workspace
    Clippy, `cargo test --locked` with the private Xvfb);
  - `cargo deny check` and `cargo vet --locked` (lockfile edges change);
  - app validation-feature Clippy/tests (qv-app links qv-core);
  - Android arm64 Clippy for qv-core/qv-sync/qv-store/qv-crypto/qv-protocol
    and qv-app (`mobile`, `mobile,validation`);
  - the fuzz smoke runs for both targets;
  - the Python crosscheck.
- **Unit and property tests:** steps 2–5. Proptest no-panic over the new
  decoders.
- **Rejection and crash paths:** steps 4–7 (the listed negatives; link
  commit and creation crash points).
- **Vectors:** draft-11 X-Wing KATs (existing); new development LAN pairing
  vectors with an independent Python check (step 8).
- **0012 §1 rows:**
  - "LAN discovery mistaken for trust": steps 6–7, tagged on at least the
    spoof, raced-hello and substitution tests;
  - 0013's "Peer state rollback" and "Generation transitions" testing rows:
    steps 4 and 7;
  - "Hostile SQLite/CBOR": extended by fuzzing.

  The offline matrix list is unchanged.

## Risks and stop conditions

- **Stop if:**
  - any 0013 requirement cannot be met as written apart from the step 1
    clarifications (for example, the hello check order or nothing sent
    before authentication);
  - the archive reader cannot authenticate a staged archive without
    weakening a check;
  - the restore path cannot take the link fill step without a second
    creation path.
- **Never:**
  - send anything before the hello/accept MAC verifies;
  - decapsulate before the MAC;
  - insert peer bytes into SQLite before full verification;
  - expose VK or a link key outside protected containers or `Zeroizing`
    buffers.
- **Threads and blocking reads:** keep the acceptor bounded (one probe at a
  time). If cancellation cannot be made prompt with timeout slices on some
  platform, stop.
- **Format bump:** existing development vaults become unreadable
  (`Unsupported`). This is accepted pre-1.0 (no-freeze direction) and must
  be stated in the CHANGELOG.
- **Not a security proof:** no independent review exists (D12), and no LAN
  release is implied.

## Documentation

- [x] `CHANGELOG.md`: Unreleased entry, including the format bump
- [x] `ARCHITECTURE.md`: §3 rows and 2.9 paragraph; stale LAN sentence; §6 LAN row (sockets: std::net; discovery still 2.10)
- [x] Specs: 0013 §1.3/§7.1/§8.3 clarifications, 0004 §2/§2.3 layouts, Changelogs, `specs/README.md` note; statuses unchanged
- [x] `AGENTS.md`: no change
- [x] Roadmap 0002: tick 2.9, plan link, execution log; `plans/README.md` row

## Revisions

None.

## Execution log

- 2026-11-02: Planned in the next-phase session after the fresh-context
  review of 0036 (Approved with minor fixes). Approved under the roadmap's
  standing approval together with the owner's standing delegation
  (2026-11-02). The delegation covers the spec clarifications (step 1) and the
  documented 2.9/2.10 boundary (decisions 1–2). No new external dependency,
  no `unsafe`.

- 2026-11-02: Step 1 done. 0013 §1.3/§7.1/§8.3 clarifications, 0004 §2.4
  layouts and key-8 text, `specs/README.md` note. Changelog lines in both
  specs; statuses unchanged (Accepted).

- 2026-11-02: Step 2 done. `LanLink` purpose; `VaultKey::{encode_for_transfer,
  from_transfer, ct_eq}`; `lan.rs`: `PairingSecret`, `PairingKeys`,
  `PairNonce`, `Sas`, `LinkRoot`, `LinkKey`, `LinkRow`, row seal/open,
  `transcript_hash`, `valid_link_label`; `test-vectors` feature for the
  existing derandomized X-Wing constructors.
  - Tests recompute every derivation from hand-built CBOR with direct
    `hkdf`/`hmac`/`sha2` calls, and cover context binding and reflection.
  - Additions beyond the sketch: `PairingKeys::secret` and
    `matches_pairing_id` (constant-time window match), `LinkKey::ct_eq`,
    `valid_link_label`.
  - Checks: `cargo test -p qv-crypto lan` 9/9; Clippy passes with and
    without the feature.

- 2026-11-02: Step 3 done. `qv-protocol::lan` holds typed codecs for every
  pairing message, `State`/`Manifest`/`Want`/`Object`/`Done` and the error
  record; `qv-protocol::oob` holds the QR payload and RFC 4648 manual code.
  - Interface details:
    - `PairHello::body`/`encode` take the fields, and the caller MACs the
      body;
    - `ErrorMsg::peek` replaces the sketched `Received::decode`;
    - `pair_th_input` returns the canonical `th` array.
  - 22/22 qv-protocol tests pass (RFC 4648 vectors, range and shape
    refusals, proptest no-panic). Clippy is clean.

- 2026-11-02: Step 4 done.
  - Format `0x7FFF0004`, with the `lan_link`/`lan_hint` tables and mandatory
    head key 8.
  - `lan_store.rs` holds the digest, shape-first reads, row and hint
    sealing, and the `UnlockedVault::{lan_links, lan_link_key, lan_hint,
    lan_serve_state, lan_object_envelope}` reads.
  - `Write::{add_lan_link, remove_lan_link}` are applied in
    `commit_cancellable` before the manifest/head, at the new crash point
    `LanLinksWritten`. `begin` re-reads the link rows against the session
    state.
  - Create, restore and rotation write the empty digest.
  - Additions: `lan_link_key` (for 2.10's handshake). An unreferenced ID in
    `lan_object_envelope` returns `InvalidEdit`, which callers map to
    `protocol`.
  - Two existing tests changed for the format:
    - the golden header bytes;
    - the corrupt-page test, which now locates the header root page instead
      of assuming page 3 (the new tables shift root pages).
  - New `lan_store_tests.rs`, 8 tests:
    - planted-back, modified, foreign-generation and deleted rows →
      `Integrity`;
    - 65 rows → `LimitExceeded`;
    - the limits, and no change on invalid edits;
    - crash points;
    - archive/restore excludes links;
    - serving bytes equal the archive frames;
    - a corrupt hint reads as absent.

    qv-store Clippy is clean.

- 2026-11-02: Step 5 done.
  - `lan_staging.rs` (`LanStaging`, `VerifiedLanStaging`, `StagedKeyslot`,
    `PasswordProof`, `NewLanLink`).
  - `ArchiveHeader::for_staging`; `fs::remove_stale_temps`.
  - `VaultFile::create_from_lan` shares the restore path through
    `create_from_archive_inner` with an optional link fill. The proof must
    equal the staged keyslot body.
  - Tests:
    - identical manifest, one link with its hint, a fresh replica, `Exists`;
    - wrong password → `WrongPassword`; a foreign VK → `Integrity`;
    - bad hash, envelope, VK, generation or vault, oversize, and a
      world-writable dir are refused, with nothing left behind;
    - out-of-order, duplicate and extra objects → `NotFound`; tampered or
      malformed objects → `Integrity`; incomplete → `Integrity`;
    - `CreateBuilt`/`CreateAnchored` crashes publish nothing, and the retry
      removes only the exact stale temp name.
  - Deviation: the conflicted-keyslot case needs the qv-sync merge to build
    a conflicted keyslot, so it moves to the step 6/7 tests.
  - `check_private_dir` keeps its existing meaning: owned and not writable
    by others.

- 2026-11-02: Step 6 done. `qv-sync::lan` modules:
  - `mod.rs`: `LanError`, `LanTimeouts`, the wire mapping and the staging
    error mapping;
  - `transport` (`Conn` with 100 ms slices, deadline and cancel; `Channel`
    with best-effort error records, never answering a peer's error record);
  - `steps` (pure); `approver` (`PairingWindow` plus the scoped acceptor);
    `joiner`; `exchange`; `endpoint`.
  - The lockfile gained only the qv-sync→qv-protocol/zeroize edges.
  - Interface details beyond the sketch:
    - `Approved.failure` reports why a post-commit exchange failed;
    - `PairingWindow::port` returns `Result`;
    - `ApproverVault::grant` takes a send callback;
    - `Confirm`/`JoinerUi` receive the vault name as bytes.
  - 15 `lan_enroll_*` tests on loopback; stable over three repeat runs:
    - both modes end to end, with equal SAS and link keys;
    - a spoofed first endpoint; a wrong code (`NoPeer`, no answer);
    - hostile hellos (profile 2, a swapped ID, mode 2, a wrong key,
      garbage) counted to `TooManyAttempts`, plus an oversized frame
      refused without a reply;
    - a raced second hello → `CodeObserved` with no grant; an identical
      replay is refused, not observed;
    - a reveal/commitment mismatch; rejections on either side;
    - prompt cancellation (< 2 s) during the confirmation wait; window
      expiry;
    - exchange negatives on the approver side (unknown or duplicate IDs,
      a missing `Done` keeps the link) and on the joiner side through a
      hostile approver (vault mismatch, > 64 MiB → `limit` before
      allocation, a non-contiguous part, a tampered manifest, out-of-order
      objects, a non-empty request, a peer `cancelled`).

    4,097 IDs cannot be encoded (step 3 covers the decoder).
  - Clippy is clean.

- 2026-11-02: Step 7 done. `qv-core::lan` (Linux/Android):
  - `Session::{open_pairing_window, join_link, lan_links, remove_lan_link}`,
    `PairingWindow::{code, expires_at, run}`, `Core::join_new_device`;
  - `CoreError::Lan` (cfg-gated);
  - `Session::tag` (crate);
  - `JoinedNewDevice` also returns the verified password, so core unlocks
    the new vault without asking again.
  - Deviations:
    - no non-Linux stubs: the API's types come from the Linux/Android-only
      `qv-sync::lan`, and nothing builds for other targets before
      milestone 4;
    - archive exclusion of links is covered by the store test, not
      repeated in core.
  - Six `lan_core_*` tests:
    - new device end to end (B's session matches A's; one link each with
      its own label);
    - local removal: `NotFound`, then `StaleHandle` from another session;
    - link mode between replicas, with equal codes shown;
    - a lock during the confirmation → `Cancelled` with no link, and the
      joiner gets `PeerCancelled` with nothing at the destination;
    - invalid labels, limits and timeouts, and a recovery session refused;
    - rotation drops links; an old-generation proof fails under the new
      generation; re-pairing works; the old copy is byte-identical;
    - a conflicted keyslot (two concurrent password changes merged) →
      `Keyslot` on the joiner, and A reports the failure with its link
      kept.
  - Workspace Clippy is clean.

- 2026-11-02: Step 8 done.
  - `qv-sync::lan::vectors` renders one deterministic pairing through the
    driver step functions into `tests/vectors/qv-dev-lan-pairing.txt`
    (development-only). It uses X-Wing draft-11 vector 1 and checks that
    the decapsulation agrees.
  - Key bytes come from `qv_crypto::lan::vectors`, which exists only under
    `test`/`test-vectors`. This extends decision 10, for the same reason.
  - `crosscheck_lan.py` (stdlib) recomputes 21 values independently and
    prints OK. Record lengths are checked; records and X-Wing are not.
  - The links digest is not in the vector: the store test covers it, and
    the function is store-private.

- 2026-11-02: Step 9 done.
  - `lan_message` now also runs every typed LAN decoder.
  - The new `lan_oob` target (QR and manual code) checks that decoded codes
    round-trip.
  - Both targets are wired into `ci.yml` (smoke) and `fuzz-extended.yml`.
  - `cargo fetch --locked` on the fuzz crate passes, with no fuzz-lockfile
    change.
  - Local runs (`-s none`, `-use_cmp=0`, musl, 60 s each):
    - `lan_oob`: 65,009,510 runs, no crash;
    - `lan_message`: 5,482,004 runs, no crash.

- 2026-11-02: All steps done; status Implemented. Final gates on the final
  tree:
  - SPDX, matrix, fmt and workspace Clippy pass;
  - app validation Clippy passes;
  - `cargo test --locked` (private Xvfb): 830 passed, 0 failed, 2 ignored
    (pre-existing);
  - `cargo test -p qv-app --features validation`: 31 passed;
  - `cargo deny check` and `cargo vet --locked` pass (94/11/457, unchanged);
  - fuzz-crate deny (CI form) passes;
  - Android arm64 Clippy (`mobile`, `mobile,validation`; app, core, sync,
    store, crypto, protocol, platform) passes;
  - fuzz smoke as in step 9;
  - `crosscheck_lan.py`: OK.

  After the gate run, `vectors.rs` was reformatted (whitespace only); fmt,
  qv-sync Clippy and the qv-sync tests (27/27) were rerun and pass.
  - Found, not fixed:
    - `ApproverUi::confirm` cannot be interrupted by core: a frontend must
      end its own prompt on cancel (documented);
    - while A's user compares codes, a peer cancel is only seen after the
      prompt returns.

    Both are UX items for 2.10. No physical-device run was needed (no
    Android glue changed). No commit, push or branch.
