# Plan 0005 — Crypto profiles, symmetric primitives and key hierarchy

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-25 | 2026-10-25 | 0002 §1, §3.1–3.3, §3.6, §7, §8; 0004 §3.2, §4.1; 0008 §1–2; 0012 §1 |

## Intent

Roadmap 0002 phase 1.3. Give `qv-crypto` the symmetric half of spec 0002. That
means the profile registry, password-kdf/1 with NFC, the KEK with its
commitment, password-slot wrap/unwrap, HKDF purpose keys and per-record and
per-attachment keys, stored-data/1 (XChaCha20-Poly1305 with Padmé framing),
MAC/1, object-hash/1 and the redacted crypto error taxonomy. Every primitive
comes from a pinned, reviewed RustCrypto crate and is checked against upstream
known-answer vectors. QuickVault's own composite vectors are cross-checked by an
independent stdlib implementation and marked development-only.

## Scope

**In scope:**
- `crates/qv-crypto`: modules `error`, `ids`, `profile`, `primitives`
  (crate-private wrappers), `stored_data`, `keys`, `password`, `slot`.
- Upstream KATs (RFC 4231, Wycheproof HKDF-SHA-512, FIPS 180 SHA-256,
  draft-irtf-cfrg-xchacha-03 §A.3.1, RFC 9106 §5.3). Development-only
  QuickVault vectors under `crates/qv-crypto/tests/vectors/`, plus a stdlib-only
  Python cross-check script.
- New dependencies from the roadmap candidate table, plus `qv-encoding` as a
  dependency of `qv-crypto` (D4: crypto builds AAD/info with the codec).

**Out of scope:**
- Record, chunk and manifest AAD contents (0004 §3.2–3.4) and their envelopes:
  phase 1.7. This phase seals and opens with caller-supplied AAD bytes.
- Fixed 64 KiB chunk padding (0004 §3.3): phase 1.11. It reuses the framing
  built here.
- Slot encoding to CBOR or SQLite, the header MAC message and header/minimum
  enforcement: phase 1.6. This phase gives typed structs and profile checks.
- Recovery phrase (VK ↔ words) and the generator: phase 1.4.
- VK rotation (0002 §3.5): phase 1.15. Platform wrap (§5): phase 2.6.
  Hybrid/asymmetric profiles (§6): 2.8 / 3.x.
- Uses of the local-state, device-storage and recovery purpose keys. This
  phase derives them only (see *Risks*: local-state is used for both AEAD and
  MAC).
- Benchmarking password-kdf/1 (0002 §1.3, OQ1): phases 1.9 / 1.16.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Profile IDs `u16` per namespace, unknown fails closed, explicit transition registry, no numeric ordering | 0002 §1.1, §1.4 | Accepted | One Rust enum per namespace |
| Initial profiles: password-kdf/1, stored-data/1, password-wrap/1, derivation/1, MAC/1, object-hash/1 | 0002 §1.2 | Accepted | Signature, enrollment, account-auth and platform-wrap come with their phases |
| NFC; Argon2id MK; KEK = HKDF-SHA-512(MK, salt = vault ID, info `["qv/kek/v1", kdf_profile]`) | 0002 §3.1 | Accepted | |
| Slot AAD, KEK commitment checked in constant time before AEAD; wrap key = HKDF(KEK, info `["qv/kek-wrap/v1"]`) | 0002 §3.2 | Accepted | The spec gives no salt for the wrap key, so HKDF runs with none (RFC 5869 default) |
| Purpose keys and all nine labels | 0002 §3.3 | Accepted | |
| Record and attachment keys | 0002 §3.6 | Accepted | |
| Random 24-byte nonces; RNG failure aborts | 0002 §7.1 | Accepted | `qv_crypto::fill_random` |
| Canonical CBOR arrays for AAD/info | 0002 §7.2 | Accepted | `qv_encoding::encode_array` |
| Constant-time MAC/tag comparison, reviewed crates, KATs recorded | 0002 §7.3, 0008 §2 | Accepted / Draft (D5) | |
| Commitment or slot AEAD failure → wrong password only; integrity errors distinct | 0002 §8 | Accepted | |
| Padmé padding with authenticated length framing; validate the length against the buffer and budget | 0004 §3.2 | Accepted | The framing layout is designed here (the format is unstable until 1.16) |
| Bounds before allocation (1 MiB padded record ciphertext, etc.) | 0004 §4.1 | Accepted | Callers pass the budget; checked before decryption |
| Zeroizing buffers, redacted `Debug`, library intermediates audited | 0008 §1.1–1.2 | Draft (D5) | |
| Exit-code classes 3/7/9 | 0011 §6 | Accepted | Documented on `CryptoError`; the CLI maps them in 1.10 |

**Spec changes required:** None.

## Decisions needed

None. The roadmap candidate table lists every new external crate, the
`qv-crypto → qv-encoding` edge is D4, no `unsafe` is needed, and the scope
matches roadmap phase 1.3. The choices below are made by this plan. Each
follows from the specs or fills a format detail that is unstable until 1.16.
None of them is an open question:

- **Field encodings in AAD/info.** Labels are CBOR text. IDs (vault, slot,
  record, attachment) are 16-byte CBOR byte strings. The KDF salt is a
  32-byte byte string. Profiles and key generation are CBOR unsigned
  integers. HKDF salts are the raw 16 ID bytes.
- **Slot ID is a 128-bit random ID**, like every object ID (0003 §1.1).
- **Padmé framing** (0004 §3.2 fixes the intent, not the bytes):
  `framed = u32_be(L) ‖ plaintext ‖ zeros`, total length `P = padme(4 + L)`,
  ciphertext length `P + 16`. On open, after the tag verifies: `4 + L ≤ P`,
  `padme(4 + L) == P`, and all padding bytes are zero, otherwise `Integrity`.
  So exactly one framing is accepted.
- **KeyGeneration is `u32`.** It is only a bound on the Rust side; the wire
  form is a CBOR uint.
- **The subtle crate is not a direct dependency.** All secret comparisons are
  MAC verifications through `hmac`'s constant-time `verify_truncated_left`
  (the KEK commitment is a MAC/1 tag).

## Design

**Components touched:** `qv-crypto` (trusted client; no frontend dependencies)
gains a dependency on `qv-encoding`. No new crate. No trust boundary changes.

**Interfaces** (`lib.rs` re-exports everything public):

```rust
// error.rs — no data in any variant; Display is a fixed string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    WrongPassword,  // KEK commitment or password-slot AEAD failed (0002 §8). CLI 3.
    Integrity,      // AEAD tag, MAC or framing failed on authenticated data. CLI 7.
    UnknownProfile, // profile ID unknown to this build; fails before any work. CLI 1.
    LimitExceeded,  // a size budget would be exceeded; nothing decrypted/produced. CLI 9.
    InvalidPassword,// master password is not valid UTF-8. CLI 1.
    Rng,            // OS RNG failed (0002 §7.1). CLI 1.
    Internal,       // a fixed-shape encoding failed: a bug. CLI 1.
}
impl From<RngError> for CryptoError { /* Rng */ }

// ids.rs — public, non-secret identifiers. Derive Clone, Copy, Debug, Eq, Ord, Hash.
pub struct VaultId(pub [u8; 16]);
pub struct SlotId(pub [u8; 16]);
pub struct RecordId(pub [u8; 16]);
pub struct AttachmentId(pub [u8; 16]);
pub struct KeyGeneration(pub u32);

// profile.rs — one enum per namespace (0002 §1.1). Each has:
//   pub const fn id(self) -> u16;
//   pub fn from_id(id: u16) -> Result<Self, CryptoError>; // UnknownProfile
//   pub fn accepts(self, minimum: Self) -> bool; // self == minimum, or reachable
//                                                // from minimum in TRANSITIONS
// plus a private `const TRANSITIONS: &[(u16, u16)] = &[];` per namespace.
#[non_exhaustive] pub enum PasswordKdfProfile { V1 }
#[non_exhaustive] pub enum StoredDataProfile { V1 }
#[non_exhaustive] pub enum PasswordWrapProfile { V1 }
#[non_exhaustive] pub enum DerivationProfile { V1 }
#[non_exhaustive] pub enum MacProfile { V1 }
#[non_exhaustive] pub enum ObjectHashProfile { V1 }
// private: fn reachable(table: &[(u16, u16)], from: u16, to: u16) -> bool
//          (iterative, bounded by table.len() steps, no allocation)

// keys.rs
pub struct VaultKey { /* SecretArray<32> */ }          // Debug: VaultKey(<redacted>)
impl VaultKey {
    pub fn generate() -> Result<Self, CryptoError>;     // SecretArray::random
    pub fn purpose_key<P: KeyPurpose>(&self, vault: VaultId, generation: KeyGeneration,
        profile: DerivationProfile) -> Result<PurposeKey<P>, CryptoError>;
}
pub mod purpose {  // uninhabited marker types; sealed trait KeyPurpose { const LABEL: &str }
    pub enum Record {}          // "record"
    pub enum Attachment {}      // "attachment"
    pub enum HeaderMac {}       // "header-mac"
    pub enum Manifest {}        // "manifest"
    pub enum StateCommit {}     // "state-commit"
    pub enum LocalState {}      // "local-state"
    pub enum DeviceStorage {}   // "device-storage"
    pub enum RecoveryEd25519 {} // "recovery-ed25519"
    pub enum RecoveryMlDsa65 {} // "recovery-mldsa65"
}
pub trait KeyPurpose: sealed::Sealed { const LABEL: &'static str; }
pub struct PurposeKey<P: KeyPurpose> { /* SecretArray<32>, PhantomData<fn() -> P> */ }
impl PurposeKey<purpose::Record> {
    pub fn record_key(&self, vault: VaultId, record: RecordId) -> Result<DataKey, CryptoError>;
}
impl PurposeKey<purpose::Attachment> {
    pub fn attachment_key(&self, vault: VaultId, attachment: AttachmentId)
        -> Result<DataKey, CryptoError>;
}
pub struct DataKey { /* SecretArray<32> */ }          // per-record / per-attachment
pub trait AeadKey: sealed::Sealed {}  // DataKey, PurposeKey<Manifest>
pub trait MacKey: sealed::Sealed {}   // PurposeKey<HeaderMac>, PurposeKey<StateCommit>
pub struct MacTag([u8; 32]);          // public value; no PartialEq (use verify_mac)
impl MacTag { pub fn from_bytes(b: [u8; 32]) -> Self; pub fn as_bytes(&self) -> &[u8; 32]; }
pub fn mac(key: &impl MacKey, profile: MacProfile, msg: &[u8]) -> MacTag;
pub fn verify_mac(key: &impl MacKey, profile: MacProfile, msg: &[u8], tag: &MacTag)
    -> Result<(), CryptoError>;                       // Integrity; constant time

// stored_data.rs
pub struct Sealed { pub nonce: [u8; 24], pub ciphertext: Vec<u8> } // ciphertext incl. tag
pub fn seal(key: &impl AeadKey, profile: StoredDataProfile, aad: &[u8], plaintext: &[u8],
    max_ciphertext: usize) -> Result<Sealed, CryptoError>;
pub fn open(key: &impl AeadKey, profile: StoredDataProfile, aad: &[u8], nonce: &[u8; 24],
    ciphertext: &[u8], max_ciphertext: usize) -> Result<SecretBytes, CryptoError>;
pub fn sealed_len(plaintext_len: usize) -> Option<usize>; // padme(4 + L) + 16

// object hash (in primitives.rs, re-exported)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]  // hash of public ciphertext: plain Eq is fine
pub struct ObjectHash(pub [u8; 32]);
pub fn object_hash(profile: ObjectHashProfile, data: &[u8]) -> ObjectHash;
pub struct ObjectHasher { /* sha2::Sha256 */ }   // streaming (0004 §4.1)
impl ObjectHasher { pub fn new(p: ObjectHashProfile) -> Self; pub fn update(&mut self, d: &[u8]);
                    pub fn finalize(self) -> ObjectHash; }

// password.rs
pub struct MasterPassword { /* SecretBytes (capacity 3·input), len */ } // Debug redacted
impl MasterPassword { pub fn from_utf8(password: &[u8]) -> Result<Self, CryptoError>; } // NFC
// crate-private: MasterKey, Kek (SecretArray<32> newtypes);
//   derive_master_key(&MasterPassword, &[u8; 32] salt, PasswordKdfProfile) -> Result<MasterKey>
//   derive_kek(&MasterKey, VaultId, PasswordKdfProfile) -> Result<Kek>
//   kek_commit(&Kek, VaultId, KeyGeneration, SlotId) -> Result<MacTag>
//   wrap_key(&Kek) -> Result<SecretArray<32>>

// slot.rs — no Debug, no Clone (a slot enables offline guessing, 0004 §6.4)
pub struct PasswordSlot {
    pub slot_id: SlotId,
    pub kdf_profile: PasswordKdfProfile,
    pub kdf_salt: [u8; 32],
    pub wrap_profile: PasswordWrapProfile,
    pub kek_commit: MacTag,
    pub nonce: [u8; 24],
    pub wrapped_vk: [u8; 48], // 32-byte VK ciphertext ‖ 16-byte tag
}
impl PasswordSlot {
    pub fn create(password: &MasterPassword, vk: &VaultKey, vault: VaultId,
        generation: KeyGeneration, slot_id: SlotId, kdf: PasswordKdfProfile,
        wrap: PasswordWrapProfile) -> Result<Self, CryptoError>;
    pub fn unlock(&self, password: &MasterPassword, vault: VaultId,
        generation: KeyGeneration) -> Result<VaultKey, CryptoError>;
}
```

The developer may add private helpers and test-only (`#[cfg(test)]`)
constructors, such as fixed-nonce sealing and `VaultKey` from fixed bytes.
Any widening of the public API is logged.

**Labels and contexts** (exact strings, all `encode_array` arrays):

| Use | HKDF IKM / MAC key | Salt | Info / message / AAD |
|-----|--------------------|------|----------------------|
| MK | Argon2id(NFC password, kdf_salt), 256 MiB, t=3, p=4, v1.3, 32 B | — | — |
| KEK | MK | vault ID | `["qv/kek/v1", kdf_profile]` |
| Commitment | MAC/1 key = KEK | — | `["qv/kek-commit/v1", vault_id, key_generation, slot_id]` |
| Wrap key | KEK | none | `["qv/kek-wrap/v1"]` |
| Slot AEAD | wrap key | — | AAD `["qv/password-slot/v1", vault_id, key_generation, slot_id, kdf_profile, kdf_salt, wrap_profile]` |
| Purpose key | VK | vault ID | `["qv/purpose/v1", label, key_generation, derivation_profile]` |
| Record key | record purpose key | vault ID | `["qv/record-key/v1", record_id]` |
| Attachment key | attachment purpose key | vault ID | `["qv/attachment-key/v1", attachment_id]` |
| MAC/1 | 32-byte key | — | first 32 bytes of HMAC-SHA-512 |

**Data and control flow:**
- `PasswordSlot::unlock` checks in this exact order: (1) the profiles are
  already typed, because the caller parsed `u16`s with `from_id` and unknown
  IDs never reach the KDF; (2) NFC password → Argon2id → MK; (3) KEK; (4)
  recompute the commitment and compare it in constant time (`verify_mac`
  path): a mismatch returns `WrongPassword` and **no AEAD is attempted**; (5)
  wrap key; (6) decrypt in place into a `SecretArray<32>` with the slot AAD:
  failure → `WrongPassword` (0002 §8), with the buffer wiped.
- `open` checks `ciphertext.len()` against `max_ciphertext` and the minimum
  (`4 + 16`) **before** allocating or decrypting. It copies into a
  `SecretBytes`, decrypts in place (detached tag), validates the framing, then
  copies the `L` plaintext bytes into an exact-size `SecretBytes`. The padded
  buffer is wiped on drop on every path.
- `seal` computes `sealed_len` and checks it against `max_ciphertext` first.
  It frames into a `SecretBytes`, takes a fresh nonce from `random_array`
  (RNG failure → `Rng`, nothing returned), encrypts in place and appends the
  tag into the output `Vec`.
- No writes to disk; no durability ordering in this phase.

**Secrets and hostile input:**
- Secret-holding types: `VaultKey`, `PurposeKey<P>`, `DataKey`,
  `MasterPassword`, `MasterKey`, `Kek`, the wrap key, framing buffers and
  decrypted plaintext. All are backed by `SecretArray`/`SecretBytes`, so they
  are locked, wiped on drop and not `Clone`. Each `Debug` prints
  `Type(<redacted>)`; there is no `Display` and no `PartialEq`.
- Library intermediates (0008 §1.1). Enable the `zeroize` features of
  `chacha20poly1305`, `hmac`, `sha2` and `argon2`. Pass keys by reference
  (`&[u8; 32]` → `&Key`) to avoid stack copies where the API allows it.
  Argon2 runs with **our own** block buffer (`hash_password_into_with_memory`)
  that we zeroize afterwards. 256 MiB is far beyond `RLIMIT_MEMLOCK`, so it is
  not locked; the crate docs say so. `unicode-normalization` holds
  intermediate chars in its own small buffers, which we cannot wipe; the docs
  say this as well. The execution log lists every residual copy found.
- NFC output goes into a pre-sized locked buffer of `3 × input` bytes and is
  never reallocated. The 3× bound holds because NFC ≤ NFD in length and every
  scalar value's NFD is at most 3× its UTF-8 length. An exhaustive test over
  all scalar values checks this. Overflow still fails closed (`Internal`).
- Hostile input in this phase is only ciphertext and slot fields. Length is
  checked before allocation, authentication comes before framing is parsed,
  and fixed-size arrays make slot field lengths a parse-time concern for
  1.6.

**Errors:** `CryptoError` as above. Its rustdoc includes the 0011 §6
exit-code table. The variants carry no data. `DecodeError`/`EncodeError` from
`qv-encoding` map to `Internal` here (fixed shapes only); decoding
authenticated payloads is 1.5+.

**Dependencies** (pin exact versions in `[workspace.dependencies]`; if a newer
patch release exists at implementation time, take it and log it):

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| `chacha20poly1305 =0.11.0` (`default-features = false`, `zeroize`) | stored-data/1, password-wrap/1 | `orion` (more surface), `ring` (no XChaCha) | RustCrypto. NCC audited an older line in 2020; that audit does not carry to 0.11. Record any `cargo vet` imports, else exempt |
| `argon2 =0.6.0` (`default-features = false`, `zeroize`) | password-kdf/1 | `rust-argon2` (less maintained), C reference via FFI (needs `unsafe`/build) | RustCrypto; no known third-party audit |
| `hkdf =0.13.0` | derivation/1 | — | RustCrypto |
| `hmac =0.13.0` (`zeroize`) | MAC/1, constant-time verify | — | RustCrypto |
| `sha2 =0.11.1` (`default-features = false`, `zeroize`) | SHA-512 for HKDF/HMAC, SHA-256 object hash | — | RustCrypto |
| `unicode-normalization =0.1.26` (`default-features = false` if NFC works without `std`, else default) | NFC (0002 §3.1) | `icu_normalizer` (larger tree) | unicode-rs; widely used |
| `qv-encoding` (path, `version = "=0.0.0"`) | AAD/info arrays | — | ours |

Expected new transitive crates (the developer lists the actual set): `aead`,
`poly1305`, `universal-hash`, `cipher`, `crypto-common`, `inout`,
`hybrid-array`, `typenum`, `digest`, `block-buffer`, `blake2`, `tinyvec`,
`tinyvec_macros`. Licenses must be in the existing allow-list. Shipped crates
get `safe-to-deploy` exemptions where no imported audit covers them. Write no
audits and add no publisher trust.

Build profile: add `[profile.dev.package.argon2]` and
`[profile.dev.package.blake2]` with `opt-level = 3` to the root `Cargo.toml`,
so tests at the full 256 MiB profile finish in seconds. This does not affect
release builds.

## Steps

### Step 1 — Dependencies, errors, IDs and the profile registry

- [x] **Do:** Add the dependencies above to `[workspace.dependencies]` and to
  `crates/qv-crypto/Cargo.toml` (plus `proptest` as a dev-dependency), and
  add the profile overrides. Write `error.rs`, `ids.rs` and `profile.rs` as
  sketched. Use a small private macro for the six enums if it reads better.
  Run `cargo deny check`, then `cargo vet` (`regenerate imports`, add
  exemptions, `prune`).
  Tests: `from_id` for 0, 1, 2 and `u16::MAX` in every namespace (only 1 is
  accepted); `id()` round trip; `reachable` on synthetic tables (`[(1,3),(3,2)]`:
  1→2 is reachable, 2→1 and 3→1 are not, a cycle terminates, and a self-pair
  is not needed for `from == to`). This shows there is no numeric ordering.
  Error `Display` strings are fixed; `From<RngError>`.
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/qv-crypto/{Cargo.toml,src/lib.rs,src/error.rs,src/ids.rs,src/profile.rs}`, `supply-chain/*`.
- **Done when:** tests pass; `cargo deny check` and `cargo vet --locked` pass;
  the log lists every new crate with its license and vet status.
- **Verify:** `cargo test --locked -p qv-crypto profile error`; `cargo deny check`; `cargo vet --locked`.

### Step 2 — Primitive wrappers and upstream KATs

- [x] **Do:** `primitives.rs` (crate-private except the object hash):
  `hkdf_sha512(ikm, salt: Option<&[u8]>, info, out: &mut [u8; 32])`;
  `mac1(key: &[u8; 32], msg) -> MacTag`; `mac1_verify(key, msg, &MacTag)`
  via `verify_truncated_left`; `ObjectHash`/`ObjectHasher`/`object_hash`;
  `xchacha_seal_in_place(key, nonce, aad, buf) -> [u8; 16]` and
  `xchacha_open_in_place(key, nonce, aad, buf, tag) -> Result<(), CryptoError>`.
  Write a test-only vector-file parser (`src/kat.rs`, `#[cfg(test)]`). The
  format is blank-line-separated records of `name = hex` lines, with `#`
  comments. Fetch the upstream vectors and save them with a `# source:` line
  (URL plus section or tcId):
  - `rfc4231-hmac-sha512.txt`: RFC 4231 cases 1–4, 6, 7. Check the full
    64 bytes against a test-only untruncated helper, and check `mac1` equals
    the first 32 bytes.
  - `wycheproof-hkdf-sha512.txt`: at least 6 valid cases with 32-byte output
    (tcIds recorded), including empty salt and empty info.
  - `sha256.txt`: FIPS 180-4 examples (`""`, `"abc"`, the 448-bit message).
    Also check the streaming hasher with every split point of `"abc…"`.
  - `xchacha20poly1305.txt`: draft-irtf-cfrg-xchacha-03 §A.3.1. Opening with a
    flipped bit in the tag, ciphertext, AAD or nonce fails.
- **Files:** `crates/qv-crypto/src/{primitives.rs,kat.rs,lib.rs}`, `crates/qv-crypto/tests/vectors/{rfc4231-hmac-sha512,wycheproof-hkdf-sha512,sha256,xchacha20poly1305}.txt`.
- **Done when:** every upstream vector passes. `mac1_verify` rejects a tag
  with any single byte changed (all 32 positions).
- **Verify:** `cargo test --locked -p qv-crypto primitives kat`

### Step 3 — Padmé framing and stored-data/1

- [x] **Do:** `stored_data.rs`: private `padme(n) -> Option<usize>`
  (`E = ⌊log2 n⌋`, `S = ⌊log2 E⌋ + 1`, mask `(1 << (E − S)) − 1`, round up;
  `None` on overflow; only called with `n ≥ 4`), `sealed_len`, the
  `AeadKey` sealed trait, `Sealed`, `seal`, `open` and a test-only
  `seal_with_nonce`. Follow the flow in *Design*. `DataKey` and the `AeadKey`
  trait live in `keys.rs` (step 4); until then, test with a `#[cfg(test)]`
  key type that implements the sealed trait.
  Tests:
  - padme values `4→4, 8→8, 9→10, 100→104, 1000→1024, 1025→1088` (the
    step 7 script cross-checks these). Proptest: `padme(n) ≥ n`, idempotent,
    monotone, and overhead ≤ `n / 2^(⌊log2 ⌊log2 n⌋⌋ + 1)` (≈ 12 % at
    1 KiB).
  - Round trip for lengths 0, 1, 59, 60, 1000 and 1 MiB − framing.
    `ciphertext.len() == sealed_len(L)`.
  - Wrong key, AAD, nonce or profile-bound AAD; any flipped ciphertext bit →
    `Integrity`.
  - Malformed frames, sealed by the test helper under a valid tag: `L` too
    large, a non-canonical `P` (extra padding block), a non-zero padding
    byte, `P < 4` → `Integrity`.
  - `open` with `ciphertext.len() > max_ciphertext` or `< 20` →
    `LimitExceeded`/`Integrity` **without** decrypting. Check this with a
    tag-invalid input, which would otherwise be `Integrity`.
  - `seal` over the limit → `LimitExceeded`.
  - Proptest: random bytes into `open` → `Err`, never a panic.
- **Files:** `crates/qv-crypto/src/{stored_data.rs,lib.rs}`.
- **Done when:** tests pass; no `unwrap`/`expect`/`panic` outside tests.
- **Verify:** `cargo test --locked -p qv-crypto stored_data`

### Step 4 — Vault key, purpose keys, record and attachment keys, MAC/1

- [x] **Do:** `keys.rs` as sketched. Every info array is built with
  `qv_encoding::encode_array`; each `EncodeError` maps to `Internal`. HKDF
  output is written directly into `SecretArray::try_init`. `mac`/`verify_mac`
  take `MacProfile` and match it, so adding a profile forces a compile error.
  Tests:
  - The nine labels are exactly the 0002 §3.3 strings and are distinct.
  - The nine purpose keys from one VK are pairwise distinct. Changing
    `vault`, `generation` or the derivation profile ID in the info (via the
    test-only raw-ID helper) changes the key.
  - The record keys of two record IDs differ. A record key and an attachment
    key with the same 16 ID bytes differ.
  - A MAC made with the header-mac key fails `verify_mac` under the
    state-commit key → `Integrity`.
  - Data sealed under one record key fails to open under another.
  - `compile_fail` doctests, each paired with a passing doctest:
    `PurposeKey<HeaderMac>` passed to `seal` (E0277); `record_key` on a
    `PurposeKey<Manifest>` (E0599); `VaultKey`/`DataKey` `.clone()` (E0599);
    `MacTag == MacTag` (E0369).
  - Redacted `Debug` for every key type.
- **Files:** `crates/qv-crypto/src/{keys.rs,stored_data.rs,lib.rs}`.
- **Done when:** tests and doctests pass.
- **Verify:** `cargo test --locked -p qv-crypto keys && cargo test --locked -p qv-crypto --doc`

### Step 5 — Master password, password-kdf/1, KEK and commitment

- [x] **Do:** `password.rs` as sketched. `MasterPassword::from_utf8` runs
  `core::str::from_utf8` (no copy; `InvalidPassword` on failure), then writes
  `nfc()` chars with `encode_utf8` into a `SecretBytes::zeroed(3 × len)`,
  tracking `len`. Argon2: `Params::new(262_144, 3, 4, Some(32))`,
  `Algorithm::Argon2id`, `Version::V0x13`, own `Vec<Block>` of
  `params.block_count()` blocks, zeroized after use on every path, and output
  into `SecretArray::try_init`. Then `derive_kek`, `kek_commit` and `wrap_key`
  per the label table. Keep a crate-private `params(PasswordKdfProfile)` so
  tests can assert the exact parameters.
  Tests:
  - NFC: `"e\u{301}"` and `"é"` give identical normalized bytes, as do
    `"\u{212b}"` and `"\u{c5}"`, and decomposed Hangul and the precomposed
    syllable. Invalid UTF-8 → `InvalidPassword`. Exhaustive: for every `char`,
    the UTF-8 length of its NFD is at most 3 × its own.
  - Upstream: the RFC 9106 §5.3 Argon2id vector run through the pinned crate
    directly (`Argon2::new_with_secret`, `ParamsBuilder::data`). This checks
    the crate; our profile adds no secret or associated data.
  - `params(V1)` equals (262,144 KiB, t = 3, p = 4, 32 bytes, Argon2id, v1.3).
  - **One** full-profile test (`derive_master_key`) checks a dev vector (step
    7) for a decomposed password, so NFC is covered end to end. Measure its
    debug-test time and log it.
  - The KEK, commitment and wrap key from a fixed MK (no Argon2) are pairwise
    distinct and change with vault, generation and slot (commitment) and
    with the kdf profile ID in the info (raw-ID helper).
- **Files:** `crates/qv-crypto/src/{password.rs,lib.rs}`, `crates/qv-crypto/tests/vectors/rfc9106-argon2id.txt`.
- **Done when:** tests pass; the full-profile test takes under 15 s in a
  debug `cargo test` here (log the number).
- **Verify:** `cargo test --locked -p qv-crypto password`

### Step 6 — Password slots and the partitioning-oracle test

- [x] **Do:** `slot.rs` as sketched, in the exact order given under *Data
  and control flow*. Split it into crate-private
  `create_with_master_key`/`unlock_with_master_key` (MK in) so most tests
  skip Argon2. The public functions add only NFC+Argon2 on top. `create` takes
  the salt and nonce from the OS RNG.
  Tests (MK-level unless stated):
  - Round trip; the unlocked VK derives the same purpose keys as the original.
  - A wrong MK → `WrongPassword`.
  - **Partitioning oracle (0012 row):** build a slot whose `wrapped_vk` is
    encrypted under the wrap key of KEK_B but whose `kek_commit` is
    KEK_A's. Unlocking with MK_B → `WrongPassword`, although the AEAD would
    succeed under B. A test-only `wrap_and_open_ok` check shows the AEAD alone
    opens, which proves the commitment gate runs first and rejects. Unlocking
    with MK_A → `WrongPassword` (its AEAD fails).
  - Each AAD field altered (vault, generation, slot ID, kdf_salt, each
    profile ID via the raw-ID helper) → `WrongPassword`, never `Integrity`
    and never a VK.
  - Tampered `wrapped_vk`, nonce or commitment → `WrongPassword`.
  - Unknown profile: `PasswordKdfProfile::from_id(2)` and
    `PasswordWrapProfile::from_id(0)` → `UnknownProfile`. A doc comment on
    `PasswordSlot` states that the typed fields make "unknown profile before
    KDF" a parse-time guarantee for phase 1.6.
  - **One** end-to-end test of the public `create` + `unlock` with a real
    password (full profile), plus `unlock` with the NFC-equivalent spelling
    → same VK, and a different password → `WrongPassword`. Reuse one slot so
    there are three Argon2 runs in total.
- **Files:** `crates/qv-crypto/src/{slot.rs,lib.rs}`.
- **Done when:** tests pass. A comment and the test name tie the
  partitioning test to the 0012 row.
- **Verify:** `cargo test --locked -p qv-crypto slot`

### Step 7 — Development vectors and the independent cross-check

- [x] **Do:** Generate `qv-dev-keys.txt` (fixed VK, MK, vault/slot/record/
  attachment IDs, generation 1: KEK, commitment, wrap key, slot AAD, all
  nine purpose keys, record key, attachment key, MAC/1 of a fixed message,
  and info/AAD bytes), `qv-dev-stored-data.txt` (fixed key/nonce/AAD; lengths
  0, 1, 60, 1000; `P` and ciphertext), `qv-dev-password-kdf.txt` (the step 5
  case) and `qv-dev-padme.txt`. Each file starts with
  `# status: development-only; regenerated freely until roadmap phase 1.16`.
  Unit tests in `kat.rs` check the Rust code against each file.
  Write `crates/qv-crypto/tests/vectors/crosscheck.py`: Python 3 stdlib only
  (`hmac`, `hashlib`), SPDX header, hand-encoded CBOR for these flat arrays.
  It recomputes every HKDF/MAC/info/AAD/padme value in `qv-dev-keys.txt` and
  `qv-dev-padme.txt` and exits non-zero on any mismatch. It cannot check
  XChaCha or Argon2: say so in its header; those rely on the step 2 and step 5
  upstream KATs. It is run by hand (not in CI) with
  `python3 -I crates/qv-crypto/tests/vectors/crosscheck.py`.
- **Files:** `crates/qv-crypto/tests/vectors/{qv-dev-keys,qv-dev-stored-data,qv-dev-password-kdf,qv-dev-padme}.txt`, `crates/qv-crypto/tests/vectors/crosscheck.py`, `crates/qv-crypto/src/kat.rs`.
- **Done when:** the Rust tests pass against the files, and the Python script
  exits 0 (with its output summary in the log).
- **Verify:** `cargo test --locked -p qv-crypto kat && python3 -I crates/qv-crypto/tests/vectors/crosscheck.py`

### Step 8 — Crate docs and documentation

- [x] **Do:** Update the `qv-crypto` crate docs: the modules, the label
  table, the error-to-exit-code table, and the residual intermediate copies
  (Argon2 memory not locked, normalization buffers, any found in steps 2–6).
  Update the files under *Documentation*. Run the full gates. Set the plan to
  `Implemented`.
- **Files:** `crates/qv-crypto/src/lib.rs`, see *Documentation*.
- **Done when:** the docs match the tree and all gates are green.
- **Verify:** `sh scripts/check-spdx.sh && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && cargo deny check && cargo vet --locked`

## Test plan

- **Unit and property tests:** the profile registry and reachability; Padmé
  properties; seal/open round trips; key separation across labels, IDs,
  generations and profiles; NFC equivalence and the exhaustive 3× bound.
- **Rejection, malformed-input and crash-path tests:** tampered tag,
  ciphertext, AAD and nonce; malformed frames under a valid tag; limits
  checked before decryption; random bytes into `open`; wrong password,
  tampered slot and altered AAD fields, all reported as `WrongPassword`;
  unknown profile IDs; type-level misuse as `compile_fail` doctests. No
  durability paths in this phase.
- **Vectors:** upstream RFC 4231, Wycheproof HKDF-SHA-512, FIPS 180-4
  SHA-256, XChaCha draft §A.3.1 and RFC 9106 §5.3. QuickVault development
  vectors are cross-checked by the stdlib script (HKDF/MAC/CBOR/padme). They
  are development-only until 1.16.
- **0012 §1 matrix rows addressed:** "Unpinned crypto" (symmetric part:
  exact profiles, upstream KATs, wrong label/profile/AAD fails); "Password-slot
  partitioning oracle" (step 6). The hybrid half of "Unpinned crypto" comes
  in 2.8.

## Risks and stop conditions

- **Supply chain:** if a crate pulls in a license outside the allow-list, an
  advisory with no clean fix, or a second `digest`/`cipher` generation that
  cannot be unified, stop and ask. Do not widen `deny.toml`.
- **API mismatch:** if `chacha20poly1305 0.11` has no in-place detached
  API on `&mut [u8]`, or `argon2 0.6` cannot run with caller-owned memory, or
  `hmac 0.13` has no constant-time truncated verify, stop and ask. Do not
  fall back to allocating APIs, a non-constant-time compare or hand-rolled code.
- **Upstream vectors:** if a vector source cannot be fetched, stop and ask.
  Do not substitute self-generated values for an upstream KAT.
- **Test time:** if the full-profile Argon2 tests exceed the step 5 bound even
  with the opt-level override, stop and ask. Do not lower the profile
  parameters in tests or add a test-only profile.
- **Local-state key, noted and not decided:** 0002 §3.3 has the local-state
  purpose key both encrypt sync/outbox state and MAC the local head (two
  primitives, one key). This phase only derives it. Phase 1.7 must raise it
  with the owner before using it for both, or use it as the spec says. That
  is the owner's call (possible subkeys would be a 0002 amendment).
- **Scope:** anything that needs record/manifest AAD contents, slot
  encoding or header logic belongs to 1.6/1.7. Log it and don't build it.
- Never weaken a test, or turn an exact error variant into "is_err", to make
  it pass.

## Documentation

- [x] `CHANGELOG.md` — Unreleased/Added: crypto profiles, key hierarchy, password slots, stored-data/1, MAC/1, object-hash/1, KATs
- [x] `ARCHITECTURE.md` — §3 "Implemented so far" gains the `qv-crypto` symmetric primitives and key hierarchy; §6 only if a tech choice differs from it (check)
- [x] Specs — no change. 0002 stays Accepted, not fully implemented (§2, §3.5, §4–6 remain)
- [x] `AGENTS.md` — *Current state* line mentions the key hierarchy
- [x] `plans/README.md` — index row; roadmap 0002: tick 1.3, plan number, execution log

## Revisions

None.

## Execution log

- 2026-10-25: Approved (standing approval, roadmap 0002): no open decisions, no spec amendment, dependencies only from the candidate table (`chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`, `unicode-normalization`; `subtle` not needed directly) plus the D4 edge `qv-crypto → qv-encoding`, no `unsafe`, matches phase 1.3.
- 2026-10-25: Step 1, stop condition hit (supply chain). `unicode-normalization 0.1.26` is licensed `(MIT OR Apache-2.0) AND Unicode-3.0`, and `Unicode-3.0` is not in the `deny.toml` allow-list (`cargo deny check`: licenses FAILED; advisories, bans and sources ok). Every NFC implementation embeds the Unicode Character Database under this license (`icu_normalizer 2.4.0` is `Unicode-3.0` alone), so changing crates does not avoid it. `deny.toml` is not widened. Question for the owner: allow `Unicode-3.0`? Recommendation: yes. It is a permissive, OSI-approved data license compatible with AGPL-3.0-or-later. Steps 2–4 do not depend on the answer and continue. Step 5 (NFC) and the final deny gate wait.
- 2026-10-25: Step 1 done (apart from the `cargo deny` licenses item above). Pins as planned: `argon2 =0.6.0`, `chacha20poly1305 =0.11.0` (both `default-features = false`, `zeroize`), `hkdf =0.13.0`, `hmac =0.13.0` (`zeroize`), `sha2 =0.11.1` (`default-features = false`, `zeroize`), `unicode-normalization =0.1.26` (`default-features = false`), plus `qv-encoding` as a workspace path dependency and `proptest` as a dev-dependency. `[profile.dev.package.{argon2,blake2}] opt-level = 3`. New transitive crates (all `MIT OR Apache-2.0` except as noted): aead 0.6.1, base64ct 1.8.3 (argon2 needs it even without `password-hash`), blake2 0.11.0, block-buffer 0.12.1, cipher 0.5.2, cmov 0.5.4, crypto-common 0.2.2, ctutils 0.4.5, digest 0.11.3, hybrid-array 0.4.15, inout 0.2.5, poly1305 0.9.1, tinyvec 1.13.3 (`Zlib OR Apache-2.0 OR MIT`), typenum 1.20.1, universal-hash 0.6.1. chacha20 0.10.2 and cpufeatures 0.3.1 were already locked (via proptest). There is one `digest`/`cipher` generation, so no duplicates. `cargo vet`: imported audits cover only the older RustCrypto lines (e.g. sha2 0.10.9, hmac 0.12.1, chacha20poly1305 0.10.x); none cover the new majors. 19 new `safe-to-deploy` exemptions: aead, argon2, base64ct, blake2, block-buffer, chacha20poly1305, cipher, cmov, crypto-common, ctutils, digest, hkdf, hmac, hybrid-array, inout, poly1305, sha2, typenum, universal-hash. Imports cover chacha20, tinyvec and unicode-normalization. No existing entry changed; no audits written; no publisher trust. Result: 12 fully audited, 33 exempted. Code: `error.rs` (`CryptoError`, fixed strings, `From<RngError>`; a `#[cfg(test)]` `rng::test_error()` helper), `ids.rs`, `profile.rs` (one macro for the six enums; `reachable` uses a fixed 64-entry array and fails closed for a larger registry). Tests: unknown IDs 0/2/3/0x100/u16::MAX in all six namespaces; round trips; reachability with chains, a cycle, branches and no numeric order.
- 2026-10-25: Step 2 done. `primitives.rs`: `hkdf_sha512` (32 bytes) over `hkdf_sha512_into` (any length; the KATs need other sizes) runs `Hkdf::extract` itself and wipes the PRK that `Hkdf::new` would drop; `mac1`/`mac1_verify` (`verify_truncated_left`, constant time via `ctutils`); `xchacha_{seal,open}_in_place` via `AeadInOut::{encrypt,decrypt}_inout_detached` on `&mut [u8]`, with the buffer wiped on open failure; `ObjectHash`/`ObjectHasher`/`object_hash`; and the public `MacTag` (no `PartialEq`, `Debug` prints `MacTag(..)`). Deviation: `mac1` returns `Result` (`Internal`), so `mac()` will too, unlike the sketch. `Hmac::new_from_slice` is fallible in the API, and an infallible wrapper would need either `expect` or a silent fallback key; failing closed is the honest option. Upstream vectors, saved with source lines: RFC 4231 cases 1–4, 6, 7 (full 64 bytes, and truncation for 32-byte keys); Wycheproof HKDF-SHA-512 tcIds 7 (empty info, non-32-byte output), 73 (empty salt), 74–79; FIPS 180-4 SHA-256 (empty, "abc", 448-bit; values also checked against Python `hashlib`); XChaCha draft-03 §A.3.1, with tag, ciphertext, AAD and nonce flips rejected. RFC 4231 test case 3 has a known typo (`Key` without `=`), which the extraction script handles. Residual intermediates found: `hmac 0.13` builds its padded-key block on the stack in `new_from_slice` and does not wipe it; `verify_truncated_left` leaves the full untruncated tag unwiped (a MAC output, not a key). The library `dead_code` lint for helpers used by steps 3–6 remains until those steps (the same as plan 0004). Note: the plan's multi-filter Verify commands need the form `cargo test -p qv-crypto --lib -- f1 f2`.
- 2026-10-25: Step 3 done. `stored_data.rs`: `padme`, `sealed_len`, `seal`/`open` and the internal `seal_framed`/`unframe`, following the *Design* flow (budget checked first; framing built and decrypted only inside `SecretBytes`; padding checked with an OR-fold, not an early exit). The sealed `AeadKey` trait is in `keys.rs` with a `#[cfg(test)]` `TestKey`, as planned. Plan correction: the plan's example `padme(5) → 6` (in `sealed_len(1)`) was wrong. By the Padmé formula, E = 2 and S = 2, so nothing is rounded, padme(5) = 5, and `sealed_len(1) = 21`. The listed values (4, 8, 9, 100, 1000, 1025) are unchanged; step 7 cross-checks them independently. Finding for 1.7: near 1 MiB, Padmé rounds to 16 KiB steps, so the largest record plaintext under the 1 MiB padded-ciphertext budget is 1 MiB − 16 KiB − 4 bytes (a boundary test pins this). Tests: values; padme properties (≥ n, idempotent, monotone, overhead < n/2^S); round trip at 0, 1, 59, 60, 1000 and the maximum; fresh nonces; wrong key, AAD or nonce, and every bit flip (0x01 and 0x80 at each byte), truncation and extension → `Integrity`; non-canonical frames under a valid tag (L too large, L = u32::MAX, an extra padding block, L too small for P, a non-zero padding byte) → `Integrity`; over-budget open → `LimitExceeded` on tag-invalid input, which proves no decryption happens; < 20 bytes → `Integrity`; over-budget seal → `LimitExceeded`; random bytes into `open` → `Err`.
- 2026-10-25: Step 4 done. `keys.rs` as sketched: `VaultKey` (`generate`, `purpose_key`, crate-private `from_secret`), the `purpose` markers built by a macro (labels exactly as in 0002 §3.3), `PurposeKey<P>` (`PhantomData<fn() -> P>`), `DataKey`, sealed `AeadKey` (DataKey, `PurposeKey<Manifest>`) and `MacKey` (`PurposeKey<HeaderMac|StateCommit>`), and `mac`/`verify_mac`, which return `Result` (see step 2). Info arrays come from `cbor_array` (`encode_array`, `EncodeError` → `Internal`); HKDF writes straight into `SecretArray::try_init`. Debug prints `VaultKey(<redacted>)`, `PurposeKey<label>(<redacted>)` and `DataKey(<redacted>)`. Tests: labels; nine pairwise-distinct keys, none equal to VK; vault, generation, raw profile ID (2) and VK each change all nine; the public path equals the raw path with ID 1; record keys separated by ID and vault, and from attachment keys; a header-mac tag fails under the state-commit key; record-key ciphertext fails under another record key. Five `compile_fail` doctests, each with a paired positive: HeaderMac → seal (E0277), Manifest → `record_key` (E0599), `VaultKey`/`DataKey` `.clone()` (E0599), `MacTag ==` (E0369). Stable rustdoc does not check error codes, which is why each has a passing twin. Deviation (test-only, outside the listed files): the new unit tests made a pre-existing `memory` test fail intermittently (`memory_multi_page_buffer_registers_every_page`: the registry count was 3, expected 2). The `memory` tests assert the global page-registry count, and their comment already requires every secret-allocating test to hold their lock. So that lock is now a crate-wide `#[cfg(test)]` `RwLock` in `memory.rs`: the registry tests take it exclusively, and the other modules' tests take `memory::secrets_test_guard()` shared. No production code changed. Three consecutive runs green (48 lib tests).
- 2026-10-25: Status `Blocked` before step 5 on the `Unicode-3.0` license question (step 1 entry). Steps 5–6 need NFC.
- 2026-10-25: Owner decision: allow `Unicode-3.0` (the recommended option). `deny.toml` allow-list gains `Unicode-3.0`, with a comment naming the reason and this plan. Status back to `In progress`.
- 2026-10-25: Step 5 done. `password.rs`: `MasterPassword::from_utf8` (`str::from_utf8`, then `nfc()` chars encoded straight into a `SecretBytes` of 3× the input length, never reallocated; overflow → `Internal`); crate-private `MasterKey`/`Kek`, `params`, `derive_master_key` (Argon2id v1.3 via `hash_password_into_with_memory` on our own `Vec<Block>`, each block zeroized on every path before the free), `derive_kek`, `kek_commit`, `verify_kek_commit` and `wrap_key` (HKDF with no salt), per the label table. Independent cross-check (an improvement over the plan's self-generated dev vector): this host's OpenSSL 3.5.6 implements Argon2id. So `qv-dev-password-kdf.txt` holds an MK computed by `openssl kdf ... ARGON2ID` (256 MiB, t=3, p=4) over the NFC bytes, with the NFC form from Python `unicodedata`; the input mixes a decomposed "é" and U+212B. Tests: NFC equivalences (é, U+212B, A+ring, Hangul jamo, and the U+0958 composition exclusion that expands), invalid UTF-8 → `InvalidPassword`, an exhaustive scan of all scalar values (NFD ≤ 3×, NFC ≤ NFD; the bound is tight at 3×), redacted `Debug`, exact V1 parameters, RFC 9106 §5.3 through the pinned crate (with secret and AD), the full-profile OpenSSL match, and separation of the KEK, commitment and wrap key (commitment binds vault, generation and slot; KEK binds vault and the KDF profile ID). The full-profile test takes **0.48 s** wall time in a debug `cargo test` here (opt-level 3 override for argon2/blake2). Argon2 runs its four lanes sequentially (no `parallel` feature); that matters for the 1.9/1.16 Android benchmark, not here.
- 2026-10-25: Step 6 done. `slot.rs`: `PasswordSlot` (public fields as sketched, no `Debug`/`Clone`), `create`/`unlock` (salt and nonce from the OS RNG; one KDF each) over crate-private `create_with_master_key`/`unlock_with_master_key`. Order: KEK → constant-time commitment check (a mismatch → `WrongPassword`, no AEAD) → wrap key → in-place AEAD into a `SecretArray<32>` (failure → `WrongPassword`, buffer wiped by `try_init`). `wrong_password()` maps only `Integrity` and lets `Rng`/`Internal` pass through. VK reaches the wrap buffer through a new crate-private `VaultKey::expose_secret`. One justified `#[allow(clippy::too_many_arguments)]` on the eight-input crate-private constructor. Tests: round trip (same VK and same purpose keys); wrong MK; **partitioning oracle** (commitment for A, VK wrapped for B: `open_with_kek(B)` alone succeeds, the real path with MK_B → `WrongPassword` at the gate, MK_A → `WrongPassword` at the AEAD); vault, generation, slot ID and salt bound; profile IDs in the AAD (2/1, 1/2, 0/1, 1/65535) → `WrongPassword`, with a positive control using IDs 1/1; every byte of `wrapped_vk`, the nonce and the commitment tampered → `WrongPassword`; unknown profile IDs → `UnknownProfile` at parse time; fresh salt and nonce per slot; end to end with real passwords (decomposed and precomposed spellings unlock the same VK; a different password → `WrongPassword`; three full Argon2 runs, 1.29 s for the whole slot module).
- 2026-10-25: Step 7 done. Deviation (stronger than planned): instead of Rust generating `qv-dev-keys.txt` and `qv-dev-padme.txt` for Python to check, `crosscheck.py --write` computes them independently with the Python stdlib (`hmac`, `hashlib`, a hand-written CBOR encoder for the flat arrays), and the Rust tests (`kat::dev`) must reproduce every value. They did on the first run: KEK, commitment message and tag, wrap info and key, slot AAD, nine purpose infos and keys, record/attachment infos and keys, and MAC/1. The info/AAD builders were split into crate-private functions (`purpose_info`, `data_key_info`, `kek_info`, `commit_message`, `wrap_info`, `slot_aad`; `padme` made crate-visible), so the tests check the exact bytes the derivations use. `qv-dev-stored-data.txt` (L = 0, 1, 60, 1000) comes from the `#[ignore]`d generator test `kat_generate_dev_stored_data` and is a Rust regression pin; Python checks only its lengths (= padme(4 + L) + 16). `qv-dev-password-kdf.txt` is the OpenSSL vector from step 5; the script re-runs `openssl kdf ... ARGON2ID` when available, and checks NFC with `unicodedata`. Integers in vector files are big-endian hex (generation: 4 bytes, padme: 8 bytes), as stated in the script and file headers. `python3 -I crates/qv-crypto/tests/vectors/crosscheck.py`: all four files ok, exit 0.
- 2026-10-25: Step 8 done; plan `Implemented`. The `qv-crypto` crate docs are rewritten: its only QuickVault dependency is now `qv-encoding`, plus profiles, the key-hierarchy table, primitives, errors and the known residual copies. Docs: `CHANGELOG.md`, `ARCHITECTURE.md` §3 "Implemented so far" (§6 already names XChaCha20-Poly1305 and Argon2id/HKDF-SHA-512; no change), `AGENTS.md` current state, `deny.toml` (`Unicode-3.0`, owner-approved), and roadmap 0002 (1.3 ticked, log). Specs unchanged: 0002 stays Accepted, not fully implemented (§2, §3.4–3.5, §4–6 remain). Final gates: SPDX ok; fmt ok (root and `fuzz/`); clippy `-D warnings` clean; `cargo test --locked` 137 passed, 0 failed, 1 ignored (the stored-data vector generator); `cargo doc -p qv-crypto` with no warnings; `cargo deny check` ok; fuzz-crate deny (advisories, bans, sources) ok; `cargo vet --locked` ok (12 audited, 33 exempted); `cargo fetch --locked` for `fuzz/` ok; `crosscheck.py` exit 0.
  Found, not fixed: (1) The new RustCrypto majors (chacha20poly1305 0.11, hmac/hkdf 0.13, sha2 0.11, argon2 0.6) have no imported `cargo vet` audits; 19 `safe-to-deploy` exemptions record that honestly (0012 §3). The older audited lines exist if the owner prefers audited versions over current ones. (2) `hmac` leaves its padded-key block on the stack (upstream behaviour; documented). (3) For phase 1.7: the local-state purpose key is specified for both AEAD and MAC (0002 §3.3). This phase only derives it; using one key for two primitives is the owner's call before 1.7 uses it. (4) For phase 1.7 budgets: with Padmé, the largest record plaintext under the 1 MiB padded-ciphertext budget is 1 MiB − 16 KiB − 4 bytes. (5) Argon2 lanes run sequentially (no `parallel`/rayon); revisit with the 1.9/1.16 Android benchmark.
- 2026-10-25: Reviewed ([REVIEW.md](REVIEW.md)): Approved with minor fixes. The reviewer fixed one medium secret-handling gap: other crates could read raw key bytes through the sealed `AeadKey`/`MacKey` accessors via a generic bound. Those accessors now need a crate-private `sealed::Token`, and `compile_fail` doctests pin it. Also fixed: `wrap_vk` uses `copy_from_slice`. Notes for 1.7 (profile in the stored-data AAD) and 1.10 (password length bound). Status `Reviewed`.
