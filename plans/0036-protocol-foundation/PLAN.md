# Plan 0036 — Protocol foundation and X-Wing (roadmap 2.8)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-11-02 | 2026-11-02 | 0002 §1, §6.1, §7; 0013 §1, §2, §6, §11; 0004 §4; 0012 §1–3 |

## Intent

Give the LAN phases (2.9 enrollment, 2.10 exchange) the shared pieces they
need:
- the pinned X-Wing KEM with upstream known-answer tests;
- the 0013 record layer;
- a bounded, fail-closed wire framework: frames, message labels, profile
  and feature registry, and exact-shape readers.

## Scope

**In scope:**
- `qv-crypto::xwing`: X-Wing draft-11 key generation, encapsulation-key
  validation, encapsulation and decapsulation, all through libcrux-kem. It
  includes draft-11 vectors and negative tests.
- `qv-crypto::lan`: the 0013 §6 record layer. It has a per-direction record
  key, counter nonces, sequence AAD, plaintext bounds, the 2³² limit and
  abort-on-failure poisoning.
- New crate `qv-protocol` (no qv dependencies except `qv-encoding`):
  - u32 frames with handshake/session bounds checked before allocation;
  - the `lan / 1` profile and v1 feature registry;
  - the wire label registry and per-label arity;
  - an exact-shape message reader and writer;
  - error codes (0013 §11).
- Fuzz target `lan_message` (frames and message reader) with CI wiring.
- Dependency addition: `libcrux-kem =0.0.10` (and its locked tree), plus
  deny/vet records.
- Documentation: ARCHITECTURE §3 rows, CHANGELOG, roadmap Revision/tick/log,
  plan index.

**Out of scope:**
- The hybrid signature (strict Ed25519 + ML-DSA-65). It is deferred to the
  first milestone-3 phase that consumes it (decision 1).
- The LAN key schedule (pairing/session HKDF derivations, MAC'd hello/accept,
  SAS, link keys), the state machines, windows, sockets and timeouts. These
  belong to phases 2.9 and 2.10.
- Message structs for individual LAN messages beyond the label/arity
  registry; 2.9/2.10 add typed messages on top of the reader.
- TLS, OPAQUE and anything server-side.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| X-Wing draft-11, exact validation, KATs, no hand-composed combiner | 0002 §6.1 | Accepted | |
| `lan / 1` profile: X-Wing, HKDF-SHA-512, MAC/1, XChaCha20-Poly1305 counter nonces, SHA-256 | 0002 §1 table, 0013 §1.1 | Accepted | unknown profile fails closed |
| Canonical CBOR arrays led by a label; exact shapes; unknown labels rejected | 0013 §1.2, 0004 §3.1 | Accepted | |
| Frames: u32 BE, 4096 / 1,052,672 bounds before allocation | 0013 §1.3 | Accepted | |
| Record layer: nonce, AAD, sequence, abort, 2³² limit, plaintext ≤ 1,048,576 + 1,024 | 0013 §6 | Accepted | |
| Error codes; unknown code → `protocol` | 0013 §11 | Accepted | |
| Unknown features required → `unsupported`; v1 sends `[]` | 0013 §7.2 | Accepted | registry only here |
| Fail-closed RNG; no secret in Debug/errors | 0002 §7.1, 0008 §1–2 | Accepted / Draft (D5) | |
| Bounds before allocation | 0004 §4 | Accepted | |
| Upstream KATs; wrong half/label/profile fails | 0012 §1 "Unpinned crypto" | Accepted | asymmetric part |
| Dependency review, audit status recorded | 0012 §3 | Accepted | |

**Spec changes required:** None.

## Decisions needed

None pending. Chosen under the owner's standing delegation (2026-11-02, "dont
ask me to approve stuff, just pick whatever is the best option"). The delegation
also covers the roadmap stop conditions this plan triggers: a dependency
outside the candidate table and a deviation from the phase entry.

1. **Defer the hybrid signature.** The phase entry lists strict Ed25519 +
   ML-DSA-65 unconditionally. 0013 authenticates with symmetric link keys and
   uses no signature. The only consumers are milestone-3 device/server
   identities, and their shape depends on D11 (0006 OQ2, open until 3.1).

   Chosen: defer it to the first milestone-3 phase that consumes it, recorded
   as a roadmap Revision. Rejected: implementing it now. That would add
   unused cryptography and dependencies to the D12 review surface. It would
   also need new BSD-3-Clause licence exceptions for `ed25519-dalek` and
   `curve25519-dalek`. (`subtle` already has one, for the UI stack since plan
   0030.)

2. **X-Wing implementation: `libcrux-kem =0.0.10`.**
   - Facts checked at plan time:
     - its `XWingKemDraft06` API implements draft-06;
     - the draft-11 change log since draft-06 is editorial only (an ASN.1
       module, PEM header, the SHAKE length written in bits, the
       implementations list);
     - the test vectors in draft-06 and draft-11 are byte-identical (all 210
       hex blocks, checked during planning);
     - the seed-based private key matches draft §5.2, and
       `PublicKey::decode` runs the ML-KEM §7.2 encapsulation-key check that
       the draft requires;
     - HACL* X25519 rejects an all-zero shared secret.
   - The whole new tree is Apache-2.0 or MIT/Apache, so `deny.toml` needs no
     change. ML-KEM is Cryspen's formally verified implementation; X25519 and
     SHA-3 are HACL*-derived.
   - We know of no independent audit of the X-Wing composition crate, and we
     claim none.
   - Rejected:
     - RustCrypto `x-wing 0.1.1`: draft-06 as well; its X25519 is
       `x25519-dalek`/`curve25519-dalek` (BSD-3-Clause, two new licence
       exceptions for crates that would ship).
     - Composing ML-KEM + X25519 + SHA3 ourselves: forbidden by 0002 §6.1.
   - Known limits, documented in the module:
     - libcrux does not zeroize its internal intermediates (the expanded
       ML-KEM key, the X25519 scalar, the combiner input buffer, the
       `XWingSharedSecret` struct);
     - `Ss::encode` returns a `Vec` that we wipe ourselves;
     - `XWingKemDraft06PrivateKey.seed` is a public field that we zeroize
       after each use.

3. **Randomness.** Use only libcrux's derandomized entry points
   (`key_gen_derand`, `encapsulate_derand`), with seeds drawn by
   `qv_crypto::fill_random` (getrandom, fail-closed, 0002 §7.1). Production
   and KATs then run the same code path, and libcrux's `rand` is compiled but
   never called. Rejected: passing a `rand_core` RNG adapter (a second RNG
   path to review).

4. **Record layer lives in `qv-crypto::lan`, framing in `qv-protocol`.** The
   record layer handles keys and AEAD, so it stays in the trusted crypto
   crate. `qv-protocol` stays key-free ("bounded wire types; shared with
   server", ARCHITECTURE §3) and depends only on `qv-encoding`. The roadmap
   entry names only the framework; the record layer is included because it
   is common to pairing (§4.4) and sessions (§5) and has no other natural
   phase.

5. **Synchronous `std::io` framing.** `read_frame`/`write_frame` take
   `std::io::Read`/`Write`. Socket timeouts (0013 §1.3) are set by 2.9/2.10 on
   the `TcpStream`. No async runtime in milestone 2.

## Design

**Components touched:**
- `qv-crypto` (`xwing.rs`, `lan.rs`, `lib.rs`, `Cargo.toml`): trusted
  client crypto.
- `qv-protocol` (new): hostile-input wire parser, key-free, no frontend
  dependencies.
- `fuzz/`: new target.
- Workspace `Cargo.toml`, `Cargo.lock`, `supply-chain/`, CI workflows.

**Interfaces:**

```rust
// qv-crypto/src/xwing.rs  (0002 §6.1, draft-connolly-cfrg-xwing-kem-11)
pub const XWING_ENCAPS_KEY_LEN: usize = 1216;
pub const XWING_CIPHERTEXT_LEN: usize = 1120;

/// Decapsulation key: the 32-byte draft seed, locked; no Debug content.
pub struct XWingDecapsKey(SecretArray<32>);
/// A validated encapsulation key (length + ML-KEM §7.2 check). Public.
#[derive(Clone, PartialEq, Eq)] pub struct XWingEncapsKey(Box<[u8; 1216]>);
/// A ciphertext of exact length (any bytes; ML-KEM rejects implicitly). Public.
#[derive(Clone, PartialEq, Eq)] pub struct XWingCiphertext(Box<[u8; 1120]>);
/// The 32-byte shared secret, locked.
pub struct XWingSharedSecret(SecretArray<32>);

impl XWingDecapsKey {
    /// Fresh seed from the OS CSPRNG, expanded with key_gen_derand.
    pub fn generate() -> Result<(Self, XWingEncapsKey), CryptoError>;
    pub fn decapsulate(&self, ct: &XWingCiphertext) -> Result<XWingSharedSecret, CryptoError>;
    #[cfg(test)] fn from_seed(seed: [u8; 32]) -> Result<(Self, XWingEncapsKey), CryptoError>;
}
impl XWingEncapsKey {
    /// Exact length, then libcrux PublicKey::decode (includes the ML-KEM check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
    pub fn as_bytes(&self) -> &[u8; 1216];
    /// 64 fresh bytes (ML-KEM m ‖ X25519 ek, libcrux order) → encapsulate_derand.
    pub fn encapsulate(&self) -> Result<(XWingSharedSecret, XWingCiphertext), CryptoError>;
    #[cfg(test)] fn encapsulate_derand(&self, eseed: &[u8; 64]) -> Result<(XWingSharedSecret, XWingCiphertext), CryptoError>;
}
impl XWingCiphertext { pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>; pub fn as_bytes(&self) -> &[u8; 1120]; }
impl XWingSharedSecret { pub fn expose_secret(&self) -> &[u8; 32]; }
// Debug for XWingDecapsKey/XWingSharedSecret: "<redacted>"; for keys/cts: type name and length only.
```

Error mapping:
- a wrong length is `LimitExceeded`;
- an encapsulation key that fails decoding or the ML-KEM check is `Integrity`;
- a libcrux key-generation, encapsulation or decapsulation error (including
  the HACL all-zero X25519 output) is `Integrity`;
- an RNG failure is `Rng`.

Nothing is partially returned. Plan-time check: the libcrux draft-06 order for
`encapsulate_derand` is `eseed[0..32]` for ML-KEM and `eseed[32..64]` for
X25519. Step 2 must confirm that this matches draft-11 `EncapsulateDerand`
using the draft vectors. If it does not, stop.

```rust
// qv-crypto/src/lan.rs  (0013 §6)
pub const RECORD_PLAINTEXT_MAX: usize = 1_048_576 + 1_024;
pub const RECORD_OVERHEAD: usize = 16;                // Poly1305 tag
pub const RECORDS_PER_DIRECTION: u64 = 1 << 32;

/// One direction's record key (k_a2b, k_b2a, k_i2r or k_r2i).
pub struct RecordKey(SecretArray<32>);
impl RecordKey {
    /// Used by 2.9's key schedule; crate-visible constructor.
    pub(crate) fn from_secret(key: SecretArray<32>) -> Self;
    #[cfg(any(test, feature = "test-vectors"))] pub fn from_test_bytes(bytes: [u8; 32]) -> Self; // see note
}
pub struct RecordSealer { key: RecordKey, seq: u64, failed: bool }
pub struct RecordOpener { key: RecordKey, seq: u64, failed: bool }
impl RecordSealer {
    pub fn new(key: RecordKey) -> Self;
    /// ciphertext ‖ tag; plaintext > RECORD_PLAINTEXT_MAX or seq == 2^32 → LimitExceeded (poisons).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
impl RecordOpener {
    pub fn new(key: RecordKey) -> Self;
    /// Length checked first (16 ≤ len ≤ MAX + 16, else LimitExceeded) before
    /// any allocation; then decrypt with the expected seq. Any failure poisons
    /// the opener; every later call returns Integrity.
    pub fn open(&mut self, record: &[u8]) -> Result<SecretBytes, CryptoError>;
}
// nonce = [0u8; 16] ‖ u64be(seq); aad = canonical ["qv/lan-record/v1", seq]
// seq increments only after a successful seal/open.
```

`from_test_bytes`: do **not** add a public test constructor or feature.
qv-crypto's own tests construct keys through `from_secret`. 2.9 adds the
public derivation functions, which become the only way to build a
`RecordKey` from outside the crate. Until then the record layer has no
external caller, which is fine for public items.

```rust
// qv-protocol/src/lib.rs
pub mod frame; pub mod registry; pub mod message; pub mod error;
pub use error::ProtocolError;

// error.rs — redacted, data-free
#[non_exhaustive] pub enum ProtocolError {
    Closed,          // clean EOF before a frame header
    Truncated,       // EOF inside a header or body
    FrameTooLarge,   // length above the phase bound (nothing allocated)
    EmptyFrame,      // length 0
    Io,              // other transport error (kind not exposed)
    Malformed,       // not one canonical CBOR array of the exact shape
    UnknownLabel,
    UnexpectedLabel, // known label, not the one expected now
    Unsupported,     // unknown lan profile or required feature
}
impl ProtocolError { pub fn wire_code(self) -> Option<ErrorCode>; } // Unsupported → Unsupported, Malformed/Unknown/Unexpected → Protocol, transport → None

// frame.rs  (0013 §1.3)
pub const HANDSHAKE_FRAME_MAX: usize = 4096;
pub const SESSION_FRAME_MAX: usize = 1_052_672;
#[derive(Clone, Copy)] pub enum FramePhase { Handshake, Session }
impl FramePhase { pub const fn max(self) -> usize; }
pub fn write_frame(w: &mut impl std::io::Write, phase: FramePhase, body: &[u8]) -> Result<(), ProtocolError>;
/// Reads exactly one frame into `buf` (cleared first; grown only after the
/// bound check). Reads at most the 4-byte header plus the body (never ahead).
pub fn read_frame(r: &mut impl std::io::Read, phase: FramePhase, buf: &mut Vec<u8>) -> Result<(), ProtocolError>;

// registry.rs  (0002 §1, 0013 §1.1, §7.2, §11)
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum LanProfile { V1 }
impl LanProfile { pub const fn id(self) -> u64 /* 1 */; pub fn from_id(id: u64) -> Result<Self, ProtocolError> /* else Unsupported */; }
/// v1 knows no features; any listed feature is required and unknown.
pub fn check_features(features: &[u64]) -> Result<(), ProtocolError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)] #[repr(u64)]
pub enum ErrorCode { VaultMismatch = 1, Unsupported = 2, Limit = 3, Integrity = 4, Cancelled = 5,
                     Busy = 6, StateChanged = 7, Keyslot = 8, Protocol = 9 }
impl ErrorCode { pub fn from_wire(code: u64) -> Self /* unknown → Protocol */; }

// message.rs  (0013 §1.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Label { PairHello, PairAccept, PairReveal, PairGrant, PairProve, PairProved, PairDone,
                 Hello, Accept, Confirm, State, Manifest, Want, Object, Done, Error }
impl Label {
    pub const fn as_str(self) -> &'static str;   // "qv/lan-pair-hello/v1", …
    pub fn from_str(s: &str) -> Option<Self>;     // exact, case-sensitive
    /// Total element count including the label and any trailing MAC.
    pub const fn arity(self) -> u64;
}
/// Exact-shape reader over one canonical message.
pub struct MessageReader<'a> { /* Decoder, label, remaining */ }
impl<'a> MessageReader<'a> {
    /// Canonical CBOR (qv-encoding), one array, first element a known label
    /// equal to `expected`, element count == expected.arity(), no trailing bytes.
    pub fn open(bytes: &'a [u8], expected: Label) -> Result<Self, ProtocolError>;
    /// Like `open` but accepts any of `expected` (e.g. Want/Object/Error).
    pub fn open_any(bytes: &'a [u8], expected: &[Label]) -> Result<Self, ProtocolError>;
    pub fn label(&self) -> Label;
    pub fn uint(&mut self) -> Result<u64, ProtocolError>;
    pub fn bool(&mut self) -> Result<bool, ProtocolError>;
    pub fn bytes_exact<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError>;
    pub fn bytes_max(&mut self, max: usize) -> Result<&'a [u8], ProtocolError>;
    pub fn text_max(&mut self, max: usize) -> Result<&'a str, ProtocolError>;
    /// Array header with a length ≤ max; the caller then reads its items.
    pub fn array_max(&mut self, max: u64) -> Result<u64, ProtocolError>;
    /// The canonical bytes of the message up to (excluding) the last element,
    /// re-encoded as an array of arity-1 (the MAC'd `body` of §4.3/§5.1).
    pub fn body_without_last(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolError>;
    /// Every element consumed and nothing left.
    pub fn finish(self) -> Result<(), ProtocolError>;
}
/// Builds a message: label first, then the caller's fields; checks the count
/// against `label.arity()` and the result against `max` bytes.
pub fn write_message(label: Label, max: usize, f: impl FnOnce(&mut Encoder)) -> Result<Zeroizing<Vec<u8>>, ProtocolError>;
```

Label arities, from 0013, including the label and any trailing MAC:

| Label | Elements | Source |
|-------|----------|--------|
| PairHello | 7 | §4.3 body (6) + MAC |
| PairAccept | 4 | §4.4 body (3) + MAC |
| PairReveal | 2 | §4.5 |
| PairGrant | 5 | §4.7 |
| PairProve | 4 | §4.8 |
| PairProved | 3 | §4.8 |
| PairDone | 1 | §4.8 |
| Hello | 5 | §5.1 body (4) + MAC |
| Accept | 4 | §5.2 body (3) + MAC |
| Confirm | 2 | §5.3 |
| State | 6 | §7.2 |
| Manifest | 3 | §7.3 |
| Want | 3 | §7.4 |
| Object | 2 | §7.5 |
| Done | 3 | §7.7 |
| Error | 2 | §11 |

Labels that are only KDF/MAC/AAD/storage contexts are **not** wire labels and
are not in `Label`. Examples are `pair-id`, `pair-mac`, `pair-key`,
`pair-commit`, `pair-th`, `pair-sas`, `pair-tag`, `pair-qr`, `auth`,
`session`, `th`, `record`, `link`, `link-salt`, `link-row`, `links` and
`hint`. The QR payload `pair-qr` is decoded from a camera or typed input,
not from a frame. 2.9 adds its own reader using `qv-encoding` directly, or
extends the registry with a separate `OutOfBand` label set.

`body_without_last` rationale: §4.3 and §5.1 MAC `canonical(body)`, where
`hello = body ++ [mac]`. Re-encoding the first `arity − 1` elements from the
canonical decoder is exact, because canonical CBOR has one encoding per value.

**Data and control flow:** none persistent. No write path, no storage, no
anchor (0004 §5 unaffected).

**Secrets and hostile input:**
- `XWingDecapsKey` and `XWingSharedSecret` live in locked `SecretArray`s.
- Seeds are drawn into `SecretArray`s (`SecretArray::try_init` +
  `fill_random`). The libcrux private-key struct is built per call and its
  `seed` field is zeroized before drop. `Ss::encode()`'s `Vec` is copied into
  a `SecretArray` and zeroized.
- Record plaintext is returned as `SecretBytes`, since grants carry VK
  (§4.7). The sealer's output is ciphertext. Failed opens wipe the buffer
  (the existing `xchacha_open_in_place` behaviour).
- `qv-protocol` never sees keys. Message bytes that may carry secrets (grant
  plaintext) are borrowed from the caller's `SecretBytes`. `write_message`
  returns `Zeroizing<Vec<u8>>`.
- Frame reader: the length is checked against the phase bound and checked for
  non-zero **before** `buf.reserve`/`resize`. A body read is `read_exact` into
  the resized buffer. `buf` is cleared on every error.
- Message reader: the qv-encoding `Decoder` enforces canonical form, depth
  and allocation-free borrowing. `bytes_max`/`text_max`/`array_max` check
  declared lengths before returning. Integers above `u64` cannot occur
  (CBOR). Negative integers, floats, tags, maps, `null` and indefinite
  lengths are `Malformed`.
- No `unwrap`/`expect`/`panic` outside tests. No `unsafe`.

**Errors:** fixed, data-free variants (`CryptoError`, `ProtocolError`). The
`wire_code` mapping follows 0013 §11 exactly. Before authentication, 2.9/2.10
send nothing; that policy belongs to the callers.

**Dependencies:**

| Crate | Why | Alternatives | Status |
|-------|-----|--------------|--------|
| `libcrux-kem =0.0.10` (`default-features = false`, `features = ["std"]`; no `codec`) | X-Wing (decision 2) | RustCrypto `x-wing` (BSD-3 deps); own composition (forbidden) | Cryspen, Apache-2.0, pre-1.0. Formally verified ML-KEM; HACL*-derived X25519/SHA-3. No independent audit of the composition known; record honestly in 0012 §3 evidence |
| transitive: `libcrux-{ml-kem 0.0.11, curve25519 0.0.9, ecdh 0.0.9, p256 0.0.9, sha3 0.0.11, sha2 0.0.9, traits 0.0.9, secrets 0.0.7, intrinsics 0.0.9, platform 0.0.4, hacl-rs 0.0.6, macros 0.0.4}`, `rand 0.10.3` | locked tree | — | all Apache-2.0 or MIT/Apache |

The p256 code is pulled in through `libcrux-ecdh` and never called. Record
that in the vet notes. Each new crate gets a `cargo vet` exemption
(`safe-to-deploy`) unless an imported audit covers it. That is the project's
existing pattern: 427 exemptions, with imports from Google, Mozilla, ISRG,
zcash and others. `cargo deny check` must pass with no `deny.toml` change.
If deny reports a licence outside the allow-list, or a duplicate that `bans`
denies, stop.

## Steps

### Step 1 — Dependency and module skeletons
- [x] **Do:**
  - add `libcrux-kem = { version = "=0.0.10", default-features = false,
    features = ["std"] }` to `[workspace.dependencies]` and to qv-crypto;
  - create `crates/qv-protocol/` (Cargo.toml with workspace package fields,
    `[lints] workspace = true`, dependency `qv-encoding`, dev-dependency
    `proptest`) and add `qv-protocol` to `[workspace.dependencies]`;
  - empty `xwing.rs`/`lan.rs` modules with docs;
  - run `cargo deny check` and `cargo vet`, adding exemptions as needed.
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/qv-crypto/{Cargo.toml,src/lib.rs,src/xwing.rs,src/lan.rs}`, `crates/qv-protocol/{Cargo.toml,src/lib.rs}`, `supply-chain/{config.toml,audits.toml,imports.lock}`.
- **Done when:** workspace builds; deny passes without a `deny.toml` change;
  vet passes.
- **Verify:** `cargo build --locked -p qv-crypto -p qv-protocol`;
  `cargo deny check`; `cargo vet --locked` (scratch CARGO_HOME, memory
  `sandbox-cargo-tools`); Android arm64 `cargo check -p qv-crypto --target aarch64-linux-android`.

### Step 2 — X-Wing wrapper and vectors
- [x] **Do:**
  - implement `xwing.rs` per the interface;
  - add `tests/vectors/xwing-draft-11.txt`: the three draft-11 test vectors
    (`seed`, `sk`, `pk`, `eseed`, `ct`, `ss`), transcribed from Appendix C of
    `draft-connolly-cfrg-xwing-kem-11` with a header citing the URL, the
    retrieval date and SHA-256 of the draft text;
  - a vector test that, for each vector:
    - `from_seed(seed)` gives `pk`;
    - `encapsulate_derand(eseed)` gives `(ss, ct)`;
    - `decapsulate(ct)` gives `ss`.
  - Negative tests:
    - encapsulation key of 1215/1217/0 bytes → `LimitExceeded`;
    - an ML-KEM part with one coefficient ≥ q (set the first 12-bit
      coefficient to 0xFFF) → `Integrity`;
    - ciphertext lengths 1119/1121 → `LimitExceeded`;
    - a flipped ML-KEM ciphertext byte gives a different, deterministic
      shared secret (implicit rejection; the 2.9 MAC/confirm catches it);
    - an X25519 ciphertext half of all zeros (low order) → `Integrity`;
    - a key from one pair cannot decapsulate the other pair's ciphertext
      (different secret);
    - missing halves: an encapsulation key that is only the 1184-byte ML-KEM
      key, or only the 32-byte X25519 key, and a 1088-byte ML-KEM-only
      ciphertext → `LimitExceeded`;
    - `Debug` redaction.
  - Tag the vector test and the missing-half test
    `// 0012 §1: Unpinned crypto` only if `check-matrix.sh` accepts the row;
    otherwise leave them untagged and mention them in the evidence. The row
    is in 0012 §1; check `tests/matrix-offline.txt`.
- **Files:** `crates/qv-crypto/src/{xwing.rs,lib.rs}`, `crates/qv-crypto/tests/vectors/xwing-draft-11.txt`, `crates/qv-crypto/src/kat.rs` (if the vector parser lives there).
- **Done when:** all draft-11 vectors pass through the production wrapper, and
  every negative case fails as specified.
- **Verify:** `cargo test --locked -p qv-crypto xwing`.
- **Stop if:** any vector mismatches, `encapsulate_derand` seed order differs
  from draft-11, or libcrux accepts a key failing the ML-KEM check.

### Step 3 — Record layer
- [x] **Do:** implement `lan.rs` per the interface. Tests:
  - round trip of empty, 1-byte and `RECORD_PLAINTEXT_MAX` plaintexts;
  - `MAX + 1` → `LimitExceeded` with nothing allocated beyond the bound
    check;
  - independent construction check: decrypt a sealed record with
    `xchacha_open_in_place` using a nonce and AAD built in the test from the
    spec text (16 zero bytes ‖ u64be(seq); canonical
    `["qv/lan-record/v1", seq]`) for seq 0 and 1;
  - replay (opening record 0 twice), reorder (1 before 0), gap, truncated
    (< 16 bytes) and flipped records → error, then the opener is poisoned and
    even a valid next record fails;
  - a record sealed under the other direction's key fails;
  - the sequence limit: with a test-only setter for `seq`, 2³²−1 seals once
    and 2³² fails `LimitExceeded`; the opener likewise;
  - the opener's output is `SecretBytes`.
- **Files:** `crates/qv-crypto/src/lan.rs`, `crates/qv-crypto/src/lib.rs`.
- **Done when:** the tests above pass.
- **Verify:** `cargo test --locked -p qv-crypto lan`.

### Step 4 — qv-protocol frames, registry and messages
- [x] **Do:** implement `error.rs`, `frame.rs`, `registry.rs`, `message.rs`
  per the interface. Tests:
  - **Frames:**
    - round trip at 1, 4096 (handshake) and 1,052,672 (session);
    - 4097 (handshake) and 1,052,673 (session) refused by both writer and
      reader, and the reader refuses before allocating: use a reader that
      yields only the header and assert `buf.capacity()` is unchanged;
    - length 0 → `EmptyFrame`;
    - EOF before a header → `Closed`, EOF inside a header or body →
      `Truncated`;
    - the reader consumes exactly one frame from a stream holding two
      (read-ahead bound).
  - **Registry:**
    - profile 1 → `V1`; 0, 2 and `u64::MAX` → `Unsupported`;
    - `check_features(&[])` is OK, `&[1]` → `Unsupported`;
    - `ErrorCode::from_wire` for 1–9, and 0, 10 and `u64::MAX` → `Protocol`;
    - `wire_code` mapping.
  - **Messages:**
    - every label round trips `as_str`/`from_str`, and arities match the
      table;
    - wrong label → `UnexpectedLabel`, unknown label (`"qv/lan-hello/v2"`,
      `"QV/LAN-HELLO/V1"`) → `UnknownLabel`;
    - extra or missing elements, a non-array top level, trailing bytes,
      non-canonical encodings (a non-minimal length, an indefinite array), a
      map/tag/float/negative/null in a field → `Malformed`;
    - `bytes_exact::<16>` on 15/17 → `Malformed`; `bytes_max`/`text_max`/
      `array_max` beyond bounds → `Malformed`;
    - `finish` with unread elements → `Malformed`;
    - `body_without_last` of a Hello equals the independently encoded body;
    - `write_message` with the wrong field count → `Malformed`, and with an
      oversize result → `FrameTooLarge`;
    - a proptest: arbitrary bytes never panic in `open_any` over all labels.
- **Files:** `crates/qv-protocol/src/{lib,error,frame,registry,message}.rs`.
- **Done when:** the tests above pass; no qv dependency other than
  `qv-encoding`.
- **Verify:** `cargo test --locked -p qv-protocol`; `cargo tree -p qv-protocol -e normal --depth 1`.

### Step 5 — Fuzz target and CI
- [x] **Do:**
  - add `fuzz/fuzz_targets/lan_message.rs`: split input into a phase byte
    and a stream; loop `read_frame` up to 4 frames; for each body, `open_any`
    over all labels and consume fields generically (`array_max(4096)` and
    so on);
  - register it in `fuzz/Cargo.toml` (qv-protocol path dependency) and
    update `fuzz/Cargo.lock` (`cargo fetch --manifest-path fuzz/Cargo.toml`;
    the new qv-crypto dependency also enters it);
  - add the target to the CI fuzz smoke and `fuzz-extended.yml` matrices
    beside the existing targets.
- **Files:** `fuzz/{Cargo.toml,Cargo.lock,fuzz_targets/lan_message.rs}`, `.github/workflows/{ci.yml,fuzz-extended.yml}`.
- **Done when:** the target builds and a bounded local smoke run is clean.
- **Verify:** `cargo +nightly-2026-10-01 fuzz build lan_message` and
  `cargo +nightly-2026-10-01 fuzz run -s none lan_message -- -runs=100000 -use_cmp=0`
  (musl host, memory `sandbox-cargo-tools`); `cargo fetch --locked --manifest-path fuzz/Cargo.toml`.

### Step 6 — Documentation
- [x] **Do:** update the following:
  - `ARCHITECTURE.md` §3: a new qv-protocol row; the qv-crypto row (X-Wing,
    LAN record layer); dependency notes if §6 lists crypto crates;
  - `CHANGELOG.md` Unreleased;
  - roadmap: the decision-1 Revision, the tick and the execution log;
  - the `plans/README.md` row.
- **Files:** as listed.
- **Done when:** the documentation duties table is satisfied.
- **Verify:** `sh scripts/check-spdx.sh`.

## Test plan

- Final verification:
  - all `AGENTS.md` gates on the final tree, plus `cargo deny check` and
    `cargo vet --locked` (the dependency changed) and `check-matrix.sh`;
  - Android arm64 Clippy for qv-crypto/qv-protocol (and qv-app, which now
    links libcrux through qv-crypto);
  - the fuzz build and smoke run.
- Unit and property tests: as in steps 2–4; proptest no-panic for the message
  reader.
- Rejection tests:
  - wrong lengths and missing halves, invalid ML-KEM keys, low-order X25519;
  - replay, reorder, gap and truncation of records, the sequence limit;
  - oversized and empty frames, unknown or unexpected labels, wrong arity,
    non-canonical encodings, unknown profile and feature.
- Vectors: draft-11 Appendix C (upstream). No QuickVault development vectors.
- 0012 §1 rows: "Unpinned crypto" (asymmetric part: X-Wing KATs and
  wrong-half/profile/label failures). "Hostile SQLite/CBOR" is extended by
  the fuzz target. No offline-matrix row is added unless the checker lists
  it.

## Risks and stop conditions

- Stop if:
  - a draft-11 vector fails;
  - the derand seed order disagrees with the draft;
  - libcrux accepts an invalid ML-KEM key, or a decapsulation error becomes
    a silent success.
- Stop if `cargo deny` needs a licence or ban change, or if libcrux fails to
  build for `aarch64-linux-android` or on the pinned 1.98.1 toolchain.
- Never hand-roll any part of X-Wing. Never add a signature crate in this
  phase (decision 1).
- libcrux is pre-1.0 and its internal intermediates are not zeroized. Record
  this in the module docs and the 0012 §3 evidence; do not claim complete
  erasure.
- The roadmap still lists the hybrid signature under 2.8. The Revision in step
  6 must move it so that no later phase assumes it exists.

## Documentation

- [x] `CHANGELOG.md`: Unreleased entry
- [x] `ARCHITECTURE.md`: §3 qv-protocol and qv-crypto rows
- [x] Specs: no change
- [x] `AGENTS.md`: no change
- [x] `plans/0002-roadmap/PLAN.md`: Revision (signature deferral, libcrux), tick, log
- [x] `plans/README.md`: index row

## Revisions

- 2026-11-02 (developer, owner standing delegation): `cargo deny` failed on two
  crates that the libcrux tree locks but never compiles. The plan said to
  stop on any `deny.toml` change; the delegation covers this narrow
  deviation:
  - `bindgen` 0.72.1 (BSD-3-Clause) is a build dependency of `crabgrind`,
    which `libcrux-secrets` uses only under `cfg(valgrind_ct_test)`;
  - `proc-macro-error2` (RUSTSEC-2026-0173, unmaintained, no vulnerability)
    comes via `hax-lib-macros` under `cfg(hax)`.

  `cargo tree --target` for musl, gnu and Android shows that neither is in
  any real build graph. Added a version-pinned licence exception and an
  advisory ignore, each with its reason. Rejected: restricting deny's
  `[graph] targets` (it would narrow checking for every crate).
- 2026-11-02 (developer, interface detail):
  - `Label::parse` instead of `from_str` (avoids shadowing `FromStr`), and
    `Label::ALL`;
  - `body_without_last` is a free function;
  - the generic `array_max` became two typed, count-bounded readers
    (`uint_array_max` for `features`, `bytes_array_exact::<N>` for `Want` IDs),
    so callers cannot desynchronize the element count. These are the only
    nested shapes in 0013's wire messages.

  Semantics are unchanged.
- 2026-11-02: corrected decision 1. `subtle` already has a BSD-3-Clause
  exception (plan 0030); the signature deferral rests on there being no
  consumer and on D11, plus two new exceptions (`ed25519-dalek`,
  `curve25519-dalek`).

## Execution log

- 2026-11-02: Planned after the fresh-context reviews of 0034 (Approved with
  minor fixes) and 0035 (Approved). Approved under the owner's standing
  delegation, which covers this plan's out-of-table dependency (libcrux-kem)
  and its phase-entry deviation (signature deferral). No spec amendment, no
  `unsafe`.

- 2026-11-02: Steps 1–6 implemented.
  - **Step 1:** `libcrux-kem =0.0.10` (std only) in qv-crypto; new
    `qv-protocol` (qv-encoding + zeroize). `cargo deny check` passes after the
    revision above. `cargo vet --locked` passes with 36 new exemptions (94
    fully audited, 11 partially, 457 exempted), with notes separating the
    shipped libcrux tree from never-compiled verification tooling. The
    shipped `itertools` is the existing 0.14; 0.13 is bindgen's.
  - **Step 2:** `xwing.rs`. `kat_xwing_draft_11` passes all three draft-11
    vectors through the production wrapper (keygen, derand encapsulation,
    decapsulation), which confirms libcrux's derand seed order. Tests cover:
    - missing halves and off-by-one lengths (`LimitExceeded`);
    - the ML-KEM coefficient ≥ q check (`Integrity`);
    - implicit rejection;
    - a low-order X25519 half (`Integrity`);
    - another pair's ciphertext;
    - fresh randomness;
    - redacted `Debug`.

    Tagged `// 0012 §1: Unpinned crypto`.
  - **Step 3:** `lan.rs`. Covered: round trips at 0, 1 and the maximum;
    oversize and short records; nonce/AAD rebuilt independently from the
    spec text; replay, reorder, gap, tamper, truncation and the other
    direction's key, all followed by poisoning; the 2³² limit.
  - **Step 4:** qv-protocol frames, registry and messages; 12 tests,
    including a no-allocation oversize check (`capacity() == 0`) and a
    proptest no-panic.
  - **Step 5:** `lan_message` fuzz target, wired into `ci.yml` and
    `fuzz-extended.yml`; the fuzz lockfile only gained packages.
    `cargo fetch --locked`, fuzz fmt and the fuzz-crate deny check pass.
    `cargo +nightly-2026-10-01 fuzz run -s none lan_message --
    -max_total_time=120 -use_cmp=0`: 28,360,252 runs, no crash (cov 219). This
    is an uninstrumented-sanitizer smoke run, not the extended campaign.
  - **Step 6:** ARCHITECTURE §3 rows and tech table, CHANGELOG, roadmap and
    index.

  Android arm64 Clippy (`mobile`, `mobile,validation`; app, platform, core,
  store, crypto, protocol) passes with libcrux compiled for Android.
  Found, not fixed: libcrux does not zeroize its internal intermediates
  (documented in `xwing.rs`); p256 code is linked through libcrux-ecdh but
  never called.
  The normal and validation APK and instrumentation builds pass with libcrux
  linked for arm64 Android, and the build script's manifest checks pass.
