// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN sync record layer (spec 0013 §6, profile `lan / 1`).
//!
//! Each direction of a pairing or session connection has its own
//! [`RecordKey`] and a 64-bit sequence number that starts at 0 and is never
//! sent. A record is
//!
//! ```text
//! XChaCha20-Poly1305(key, nonce = 16 zero bytes ‖ u64be(seq),
//!                    aad = canonical(["qv/lan-record/v1", seq]),
//!                    plaintext = one canonical message)
//! ```
//!
//! sent as ciphertext ‖ tag. The receiver opens with the sequence number it
//! expects next, so a failed tag, gap, reordering or replay fails, and any
//! failure poisons that direction: the session must abort (0013 §2). A
//! direction stops at 2³² records. Keys are unique per session and direction,
//! so counter nonces never repeat.
//!
//! Record keys come only from the key schedule below:
//! [`PairingKeys::record_keys`] for pairing (§4.4), and the session keys of
//! §5.2 in phase 2.10.
//!
//! # Pairing key schedule (0013 §4)
//!
//! Every derivation is HKDF-SHA-512 with a canonical CBOR info array. The
//! labels are exactly those of 0013:
//!
//! | Value | IKM | Salt | Info / input |
//! |-------|-----|------|--------------|
//! | `pairing_id` (16 bytes) | `P` | empty | `["qv/lan-pair-id/v1"]` |
//! | `K_hello`, `K_accept` | `P` | `pairing_id` | `["qv/lan-pair-mac/v1", "hello"|"accept"]` |
//! | `k_b2a`, `k_a2b` | `ss ‖ P` | `th` | `["qv/lan-pair-key/v1", "b2a"|"a2b"]` |
//! | `commit_B` | — | — | `H(["qv/lan-pair-commit/v1", nonce_B])` |
//! | SAS | — | — | `u32be(H(["qv/lan-pair-sas/v1", th, nonce_B])[..4]) mod 10⁶` |
//! | `K_lan` | VK | vault ID | purpose `lan-link` (0002 §3.3) |
//! | link key | `K_lan ‖ ss` | `H(["qv/lan-link-salt/v1", th, nonce_B, link_id])` | `["qv/lan-link/v1", vault_id, key_generation, link_id]` |
//! | proof | MAC/1 under `K_lan` | — | `["qv/lan-pair-prove/v1", th, "a"|"b", vault_id, key_generation]` |
//!
//! `H` is SHA-256 of a canonical encoding ([`transcript_hash`]). The wire
//! messages that `th` covers are built by `qv-protocol`; this module only
//! sees their canonical bytes. Every key and nonce here lives in locked
//! memory and has a redacted `Debug`. Every check is constant time.
//!
//! Link rows (0013 §9.1, 0004 §2.4) are sealed here because their plaintext
//! holds the link key: `[link_key, label, created_at]` under the
//! `local-state` key with AAD `["qv/lan-link-row/v1", vault_id,
//! key_generation, link_id]`.

use crate::error::CryptoError;
use crate::ids::{KeyGeneration, VaultId};
use crate::keys::{PurposeKey, VaultKey, cbor_array, derive_secret, purpose};
use crate::memory::{SecretArray, SecretBytes};
use crate::primitives::{
    MacTag, NONCE_LEN, TAG_LEN, hkdf_sha512_into, mac1, mac1_verify, sha256, xchacha_open_in_place,
    xchacha_seal_in_place,
};
use crate::profile::{DerivationProfile, StoredDataProfile};
use crate::stored_data::Sealed;
use crate::xwing::XWingSharedSecret;

/// Largest record plaintext: one message of 1 MiB plus 1 KiB (0013 §6.2).
pub const RECORD_PLAINTEXT_MAX: usize = 1_048_576 + 1_024;
/// Bytes a record adds to its plaintext (the Poly1305 tag).
pub const RECORD_OVERHEAD: usize = TAG_LEN;
/// Records per direction; reaching it aborts the session (0013 §6.1).
pub const RECORDS_PER_DIRECTION: u64 = 1 << 32;

/// One direction's record key (`k_a2b`, `k_b2a`, `k_i2r` or `k_r2i`).
pub struct RecordKey(SecretArray<32>);

impl RecordKey {
    /// Wraps a key derived by this crate's LAN key schedule.
    pub(crate) fn from_secret(key: SecretArray<32>) -> Self {
        Self(key)
    }
}

impl core::fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordKey(<redacted>)")
    }
}

fn nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[16..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn aad(seq: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text("qv/lan-record/v1");
        a.uint(seq);
    })
}

/// The sending half of one direction.
pub struct RecordSealer {
    key: RecordKey,
    seq: u64,
    failed: bool,
}

impl RecordSealer {
    /// Starts a direction at sequence number 0.
    pub fn new(key: RecordKey) -> Self {
        Self {
            key,
            seq: 0,
            failed: false,
        }
    }

    /// Seals the next record. An oversized plaintext or an exhausted
    /// direction fails with [`CryptoError::LimitExceeded`] and poisons the
    /// sealer; nothing is produced.
    ///
    /// The plaintext is copied into the output buffer and encrypted in place
    /// there, so the unlocked output briefly holds it; the buffer is sized
    /// once and never reallocates.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.failed
            || plaintext.len() > RECORD_PLAINTEXT_MAX
            || self.seq >= RECORDS_PER_DIRECTION
        {
            self.failed = true;
            return Err(CryptoError::LimitExceeded);
        }
        let aad = aad(self.seq)?;
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        match xchacha_seal_in_place(self.key.0.expose_secret(), &nonce(self.seq), &aad, &mut out) {
            Ok(tag) => {
                out.extend_from_slice(&tag);
                self.seq += 1;
                Ok(out)
            }
            Err(e) => {
                zeroize::Zeroize::zeroize(&mut out);
                self.failed = true;
                Err(e)
            }
        }
    }

    #[cfg(test)]
    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }
}

/// The receiving half of one direction.
pub struct RecordOpener {
    key: RecordKey,
    seq: u64,
    failed: bool,
}

impl RecordOpener {
    /// Starts a direction at sequence number 0.
    pub fn new(key: RecordKey) -> Self {
        Self {
            key,
            seq: 0,
            failed: false,
        }
    }

    /// Opens the next expected record into locked memory.
    ///
    /// The length is checked before anything is allocated
    /// ([`CryptoError::LimitExceeded`]); a failed tag is
    /// [`CryptoError::Integrity`]. Any failure poisons the opener, and every
    /// later call returns [`CryptoError::Integrity`].
    pub fn open(&mut self, record: &[u8]) -> Result<SecretBytes, CryptoError> {
        if self.failed {
            return Err(CryptoError::Integrity);
        }
        let result = self.open_next(record);
        match result {
            Ok(_) => self.seq += 1,
            Err(_) => self.failed = true,
        }
        result
    }

    fn open_next(&self, record: &[u8]) -> Result<SecretBytes, CryptoError> {
        if record.len() < TAG_LEN
            || record.len() > RECORD_PLAINTEXT_MAX + TAG_LEN
            || self.seq >= RECORDS_PER_DIRECTION
        {
            return Err(CryptoError::LimitExceeded);
        }
        let (body, tag) = record.split_at(record.len() - TAG_LEN);
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::Internal)?;
        let aad = aad(self.seq)?;
        SecretBytes::try_init(body.len(), |out| {
            out.copy_from_slice(body);
            xchacha_open_in_place(self.key.0.expose_secret(), &nonce(self.seq), &aad, out, tag)
        })
    }

    #[cfg(test)]
    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }
}

// ---- Pairing key schedule (0013 §4) ----

/// Length of the pairing secret `P`.
pub const PAIRING_SECRET_LEN: usize = 16;
/// Longest link label in bytes (0013 §9.1).
pub const LINK_LABEL_MAX: usize = 64;
/// Largest sealed link-row ciphertext (0004 §2.4).
pub const LINK_ROW_CIPHERTEXT_MAX: usize = 512;

/// `H(x)`: SHA-256 of an already canonical encoding (0013 §1.2).
pub fn transcript_hash(canonical: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sha256(canonical, &mut out);
    out
}

/// `H` of a canonical array built here; the encoding may hold secrets and is
/// wiped on drop.
fn hash_array(f: impl FnOnce(&mut qv_encoding::Encoder)) -> Result<[u8; 32], CryptoError> {
    Ok(transcript_hash(&cbor_array(f)?))
}

/// HKDF-SHA-512 with a 32-byte output over the concatenation `a ‖ b`, built
/// in locked memory.
fn derive_concat<const N: usize>(
    a: &[u8],
    b: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<SecretArray<32>, CryptoError> {
    if a.len() + b.len() != N {
        return Err(CryptoError::Internal);
    }
    let ikm = SecretArray::<N>::try_init(|ikm| {
        ikm[..a.len()].copy_from_slice(a);
        ikm[a.len()..].copy_from_slice(b);
        Ok::<(), CryptoError>(())
    })?;
    derive_secret(ikm.expose_secret(), Some(salt), info)
}

/// The pairing secret `P` (0013 §4.1): 16 random bytes, shown out of band.
pub struct PairingSecret(SecretArray<PAIRING_SECRET_LEN>);

impl PairingSecret {
    /// A fresh secret from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(SecretArray::random()?))
    }

    /// A secret read from a QR payload or a typed code: exactly 16 bytes,
    /// else [`CryptoError::LimitExceeded`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PAIRING_SECRET_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        Ok(Self(SecretArray::try_init(|out| {
            out.copy_from_slice(bytes);
            Ok::<(), CryptoError>(())
        })?))
    }

    /// The secret bytes, only for encoding the QR payload or manual code.
    pub fn expose_secret(&self) -> &[u8; PAIRING_SECRET_LEN] {
        self.0.expose_secret()
    }

    /// Derives `pairing_id`, `K_hello` and `K_accept` (0013 §4.1).
    pub fn keys(self) -> Result<PairingKeys, CryptoError> {
        let p = self.0.expose_secret();
        let mut pairing_id = [0u8; 16];
        hkdf_sha512_into(
            p,
            Some(&[]),
            &cbor_array(|a| a.text("qv/lan-pair-id/v1"))?,
            &mut pairing_id,
        )?;
        let mac_key = |role: &str| {
            derive_secret(
                p,
                Some(&pairing_id),
                &cbor_array(|a| {
                    a.text("qv/lan-pair-mac/v1");
                    a.text(role);
                })?,
            )
        };
        let hello = mac_key("hello")?;
        let accept = mac_key("accept")?;
        Ok(PairingKeys {
            secret: self,
            pairing_id,
            hello,
            accept,
        })
    }
}

impl core::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairingSecret(<redacted>)")
    }
}

/// The keys of one pairing window or attempt (0013 §4.1, §4.4).
pub struct PairingKeys {
    secret: PairingSecret,
    pairing_id: [u8; 16],
    hello: SecretArray<32>,
    accept: SecretArray<32>,
}

impl PairingKeys {
    /// `pairing_id`, which names the window in every hello.
    pub fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    /// The pairing secret, for the QR payload or manual code.
    pub fn secret(&self) -> &PairingSecret {
        &self.secret
    }

    /// Constant-time comparison of a received `pairing_id`.
    pub fn matches_pairing_id(&self, id: &[u8; 16]) -> bool {
        use ctutils::CtEq;
        self.pairing_id[..].ct_eq(&id[..]).to_bool()
    }

    /// `MAC/1(K_hello, canonical(body))` (0013 §4.3).
    pub fn hello_mac(&self, body: &[u8]) -> Result<MacTag, CryptoError> {
        mac1(self.hello.expose_secret(), body)
    }

    /// Verifies a hello MAC in constant time ([`CryptoError::Integrity`]).
    pub fn verify_hello(&self, body: &[u8], tag: &MacTag) -> Result<(), CryptoError> {
        mac1_verify(self.hello.expose_secret(), body, tag)
    }

    /// `MAC/1(K_accept, canonical(["qv/lan-pair-accept/v1", H(hello),
    /// nonce_A, ct]))` (0013 §4.4); `transcript` is that canonical array.
    pub fn accept_mac(&self, transcript: &[u8]) -> Result<MacTag, CryptoError> {
        mac1(self.accept.expose_secret(), transcript)
    }

    /// Verifies an accept MAC in constant time ([`CryptoError::Integrity`]).
    pub fn verify_accept(&self, transcript: &[u8], tag: &MacTag) -> Result<(), CryptoError> {
        mac1_verify(self.accept.expose_secret(), transcript, tag)
    }

    /// `(k_b2a, k_a2b)`, each `HKDF(ss ‖ P, th, ["qv/lan-pair-key/v1",
    /// role])` (0013 §4.4).
    pub fn record_keys(
        &self,
        ss: &XWingSharedSecret,
        th: &[u8; 32],
    ) -> Result<(RecordKey, RecordKey), CryptoError> {
        let key = |role: &str| -> Result<RecordKey, CryptoError> {
            let info = cbor_array(|a| {
                a.text("qv/lan-pair-key/v1");
                a.text(role);
            })?;
            Ok(RecordKey::from_secret(derive_concat::<48>(
                ss.expose_secret(),
                self.secret.expose_secret(),
                th,
                &info,
            )?))
        };
        Ok((key("b2a")?, key("a2b")?))
    }
}

impl core::fmt::Debug for PairingKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairingKeys(<redacted>)")
    }
}

/// `nonce_B` (0013 §4.3): secret until the reveal.
pub struct PairNonce(SecretArray<32>);

impl PairNonce {
    /// A fresh nonce from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(SecretArray::random()?))
    }

    /// A revealed nonce: exactly 32 bytes, else [`CryptoError::LimitExceeded`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::LimitExceeded);
        }
        Ok(Self(SecretArray::try_init(|out| {
            out.copy_from_slice(bytes);
            Ok::<(), CryptoError>(())
        })?))
    }

    /// The nonce bytes, for the reveal message.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// `commit_B = H(["qv/lan-pair-commit/v1", nonce_B])`.
    pub fn commitment(&self) -> Result<[u8; 32], CryptoError> {
        hash_array(|a| {
            a.text("qv/lan-pair-commit/v1");
            a.bytes(self.0.expose_secret());
        })
    }

    /// Whether this (revealed) nonce opens `commit`, compared in constant time.
    pub fn matches(&self, commit: &[u8; 32]) -> Result<bool, CryptoError> {
        use ctutils::CtEq;
        Ok(self.commitment()?[..].ct_eq(&commit[..]).to_bool())
    }
}

impl core::fmt::Debug for PairNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairNonce(<redacted>)")
    }
}

/// The six-digit comparison code (0013 §4.5).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas(u32);

impl Sas {
    /// `u32be(first 4 bytes of H(["qv/lan-pair-sas/v1", th, nonce_B])) mod
    /// 1,000,000`.
    pub fn compute(th: &[u8; 32], nonce_b: &PairNonce) -> Result<Self, CryptoError> {
        let h = hash_array(|a| {
            a.text("qv/lan-pair-sas/v1");
            a.bytes(th);
            a.bytes(nonce_b.expose_secret());
        })?;
        Ok(Self(
            u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000,
        ))
    }

    /// The code as six zero-padded ASCII digits.
    pub fn digits(&self) -> [u8; 6] {
        let mut out = [b'0'; 6];
        let mut n = self.0;
        for d in out.iter_mut().rev() {
            *d = b'0' + (n % 10) as u8;
            n /= 10;
        }
        out
    }
}

impl core::fmt::Debug for Sas {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sas(..)")
    }
}

/// Which side a link-mode proof speaks for (0013 §4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofRole {
    /// The approving device, `"a"`.
    A,
    /// The joining device, `"b"`.
    B,
}

impl ProofRole {
    fn label(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

/// `K_lan`: the generation's link root (0013 §4.6). Only holders of this
/// generation's VK can derive it.
pub struct LinkRoot(PurposeKey<purpose::LanLink>);

impl LinkRoot {
    /// The `lan-link` purpose key of VK for this vault and generation.
    pub fn derive(
        vk: &VaultKey,
        vault: VaultId,
        generation: KeyGeneration,
        profile: DerivationProfile,
    ) -> Result<Self, CryptoError> {
        Ok(Self(vk.purpose_key::<purpose::LanLink>(
            vault, generation, profile,
        )?))
    }

    /// The pairwise link key (0013 §4.6).
    pub fn link_key(
        &self,
        ss: &XWingSharedSecret,
        th: &[u8; 32],
        nonce_b: &PairNonce,
        link_id: &[u8; 16],
        vault: VaultId,
        generation: KeyGeneration,
    ) -> Result<LinkKey, CryptoError> {
        let salt = hash_array(|a| {
            a.text("qv/lan-link-salt/v1");
            a.bytes(th);
            a.bytes(nonce_b.expose_secret());
            a.bytes(link_id);
        })?;
        let info = cbor_array(|a| {
            a.text("qv/lan-link/v1");
            a.bytes(&vault.0);
            a.uint(generation.0.into());
            a.bytes(link_id);
        })?;
        Ok(LinkKey(derive_concat::<64>(
            self.0.expose_secret(),
            ss.expose_secret(),
            &salt,
            &info,
        )?))
    }

    fn proof_input(
        th: &[u8; 32],
        role: ProofRole,
        vault: VaultId,
        generation: KeyGeneration,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
        cbor_array(|a| {
            a.text("qv/lan-pair-prove/v1");
            a.bytes(th);
            a.text(role.label());
            a.bytes(&vault.0);
            a.uint(generation.0.into());
        })
    }

    /// A link-mode proof for `role` (0013 §4.8).
    pub fn proof(
        &self,
        th: &[u8; 32],
        role: ProofRole,
        vault: VaultId,
        generation: KeyGeneration,
    ) -> Result<MacTag, CryptoError> {
        mac1(
            self.0.expose_secret(),
            &Self::proof_input(th, role, vault, generation)?,
        )
    }

    /// Verifies a link-mode proof in constant time ([`CryptoError::Integrity`]).
    pub fn verify_proof(
        &self,
        th: &[u8; 32],
        role: ProofRole,
        vault: VaultId,
        generation: KeyGeneration,
        tag: &MacTag,
    ) -> Result<(), CryptoError> {
        mac1_verify(
            self.0.expose_secret(),
            &Self::proof_input(th, role, vault, generation)?,
            tag,
        )
    }
}

impl core::fmt::Debug for LinkRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LinkRoot(<redacted>)")
    }
}

/// A pairwise link key (0013 §4.6, §9.1). Phase 2.10 derives the session
/// authentication keys from it.
pub struct LinkKey(SecretArray<32>);

impl LinkKey {
    /// Constant-time equality, for tests and duplicate checks.
    pub fn ct_eq(&self, other: &LinkKey) -> bool {
        self.0.ct_eq(other.0.expose_secret())
    }
}

impl core::fmt::Debug for LinkKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LinkKey(<redacted>)")
    }
}

/// A decrypted link row (0013 §9.1).
pub struct LinkRow {
    /// The link key.
    pub key: LinkKey,
    /// The user-chosen label (UTF-8, at most [`LINK_LABEL_MAX`] bytes).
    pub label: SecretBytes,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at: u64,
}

impl core::fmt::Debug for LinkRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LinkRow(<redacted>)")
    }
}

/// A link label: 1–64 bytes of UTF-8 without control characters.
pub fn valid_link_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= LINK_LABEL_MAX && !label.chars().any(char::is_control)
}

fn link_row_aad(
    vault: VaultId,
    generation: KeyGeneration,
    link_id: &[u8; 16],
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text("qv/lan-link-row/v1");
        a.bytes(&vault.0);
        a.uint(generation.0.into());
        a.bytes(link_id);
    })
}

/// Seals a link row under the `local-state` key (0013 §9.1, 0004 §2.4). An
/// invalid label is [`CryptoError::LimitExceeded`].
#[allow(clippy::too_many_arguments)] // the row's fields and its AAD context
pub fn seal_link_row(
    key: &PurposeKey<purpose::LocalState>,
    profile: StoredDataProfile,
    vault: VaultId,
    generation: KeyGeneration,
    link_id: &[u8; 16],
    link: &LinkKey,
    label: &str,
    created_at: u64,
) -> Result<Sealed, CryptoError> {
    if !valid_link_label(label) {
        return Err(CryptoError::LimitExceeded);
    }
    let plaintext = cbor_array(|a| {
        a.bytes(link.0.expose_secret());
        a.text(label);
        a.uint(created_at);
    })?;
    crate::stored_data::seal(
        key,
        profile,
        &link_row_aad(vault, generation, link_id)?,
        &plaintext,
        LINK_ROW_CIPHERTEXT_MAX,
    )
}

/// Authenticates and decodes a sealed link row. Any failure after the bound
/// check is [`CryptoError::Integrity`].
pub fn open_link_row(
    key: &PurposeKey<purpose::LocalState>,
    profile: StoredDataProfile,
    vault: VaultId,
    generation: KeyGeneration,
    link_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<LinkRow, CryptoError> {
    let plaintext = crate::stored_data::open(
        key,
        profile,
        &link_row_aad(vault, generation, link_id)?,
        nonce,
        ciphertext,
        LINK_ROW_CIPHERTEXT_MAX,
    )?;
    let bad = |_| CryptoError::Integrity;
    let mut d = qv_encoding::Decoder::new(plaintext.expose_secret()).map_err(bad)?;
    if d.array().map_err(bad)? != 3 {
        return Err(CryptoError::Integrity);
    }
    let raw = d.bytes().map_err(bad)?;
    if raw.len() != 32 {
        return Err(CryptoError::Integrity);
    }
    let key = LinkKey(SecretArray::try_init(|out| {
        out.copy_from_slice(raw);
        Ok::<(), CryptoError>(())
    })?);
    let text = d.text().map_err(bad)?;
    if !valid_link_label(text) {
        return Err(CryptoError::Integrity);
    }
    let label = SecretBytes::try_init(text.len(), |out| {
        out.copy_from_slice(text.as_bytes());
        Ok::<(), CryptoError>(())
    })?;
    let created_at = d.uint().map_err(bad)?;
    d.finish().map_err(bad)?;
    Ok(LinkRow {
        key,
        label,
        created_at,
    })
}

/// Key bytes for the interoperability vectors only (plan 0037 step 8). The
/// `test-vectors` feature is enabled only by dev-dependencies.
#[cfg(any(test, feature = "test-vectors"))]
pub mod vectors {
    use super::{LinkKey, LinkRoot, PairingKeys, RecordKey};

    /// `K_hello` and `K_accept`.
    pub fn pairing_mac_keys(k: &PairingKeys) -> ([u8; 32], [u8; 32]) {
        (*k.hello.expose_secret(), *k.accept.expose_secret())
    }
    /// A record key.
    pub fn record_key(k: &RecordKey) -> [u8; 32] {
        *k.0.expose_secret()
    }
    /// `K_lan`.
    pub fn link_root(k: &LinkRoot) -> [u8; 32] {
        *k.0.expose_secret()
    }
    /// A link key.
    pub fn link_key(k: &LinkKey) -> [u8; 32] {
        *k.0.expose_secret()
    }
}

impl core::fmt::Debug for RecordSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordSealer(<redacted>)")
    }
}
impl core::fmt::Debug for RecordOpener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordOpener(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn key(b: u8) -> RecordKey {
        RecordKey::from_secret(
            SecretArray::try_init(|k| {
                k.fill(b);
                Ok::<(), CryptoError>(())
            })
            .unwrap(),
        )
    }
    fn pair(b: u8) -> (RecordSealer, RecordOpener) {
        (RecordSealer::new(key(b)), RecordOpener::new(key(b)))
    }

    #[test]
    fn lan_records_round_trip_within_bounds() {
        let (mut s, mut o) = pair(1);
        for len in [0, 1, RECORD_PLAINTEXT_MAX] {
            let msg = vec![0x5a; len];
            let rec = s.seal(&msg).unwrap();
            assert_eq!(rec.len(), len + RECORD_OVERHEAD);
            assert_eq!(o.open(&rec).unwrap().expose_secret(), &msg[..]);
        }
        assert_eq!(
            s.seal(&vec![0; RECORD_PLAINTEXT_MAX + 1]),
            Err(CryptoError::LimitExceeded)
        );
        // A refused seal poisons the direction.
        assert_eq!(s.seal(b"x"), Err(CryptoError::LimitExceeded));
        // Oversized and short records are refused before decrypting.
        let (_, mut o) = pair(1);
        assert!(matches!(
            o.open(&vec![0; RECORD_PLAINTEXT_MAX + RECORD_OVERHEAD + 1]),
            Err(CryptoError::LimitExceeded)
        ));
        let (_, mut o) = pair(1);
        assert!(matches!(o.open(&[0; 15]), Err(CryptoError::LimitExceeded)));
    }

    #[test]
    fn lan_record_nonce_and_aad_follow_the_spec() {
        let (mut s, _) = pair(2);
        for seq in 0u64..2 {
            let msg = format!("message {seq}");
            let rec = s.seal(msg.as_bytes()).unwrap();
            // Built independently from the 0013 §6.1 text.
            let mut nonce = [0u8; 24];
            nonce[16..].copy_from_slice(&seq.to_be_bytes());
            let mut aad = vec![0x82, 0x70];
            aad.extend_from_slice(b"qv/lan-record/v1");
            aad.push(u8::try_from(seq).unwrap());
            let (body, tag) = rec.split_at(rec.len() - 16);
            let mut buf = body.to_vec();
            xchacha_open_in_place(&[2; 32], &nonce, &aad, &mut buf, tag.try_into().unwrap())
                .unwrap();
            assert_eq!(buf, msg.as_bytes());
        }
    }

    #[test]
    fn lan_records_refuse_replay_reorder_gap_and_tamper_then_poison() {
        let (mut s, _) = pair(3);
        let r0 = s.seal(b"zero").unwrap();
        let r1 = s.seal(b"one").unwrap();
        let r2 = s.seal(b"two").unwrap();
        // Replay.
        let (_, mut o) = pair(3);
        o.open(&r0).unwrap();
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        assert_eq!(o.open(&r1).unwrap_err(), CryptoError::Integrity);
        // Reorder and gap.
        for first in [&r1, &r2] {
            let (_, mut o) = pair(3);
            assert_eq!(o.open(first).unwrap_err(), CryptoError::Integrity);
            assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        }
        // Tamper and truncation.
        let mut bad = r0.clone();
        bad[0] ^= 1;
        let (_, mut o) = pair(3);
        assert_eq!(o.open(&bad).unwrap_err(), CryptoError::Integrity);
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        let (_, mut o) = pair(3);
        assert!(o.open(&r0[..r0.len() - 1]).is_err());
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        // The other direction's key does not open it.
        let (_, mut o) = pair(4);
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
    }

    // ---- key schedule ----

    /// Hand-built canonical CBOR, independent of qv-encoding.
    fn head(major: u8, n: usize) -> Vec<u8> {
        match n {
            0..=23 => vec![major << 5 | n as u8],
            24..=255 => vec![major << 5 | 24, n as u8],
            _ => {
                let mut v = vec![major << 5 | 25];
                v.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
                v
            }
        }
    }
    fn t(s: &str) -> Vec<u8> {
        [head(3, s.len()), s.as_bytes().to_vec()].concat()
    }
    fn b(x: &[u8]) -> Vec<u8> {
        [head(2, x.len()), x.to_vec()].concat()
    }
    fn arr(items: &[Vec<u8>]) -> Vec<u8> {
        [head(4, items.len()), items.concat()].concat()
    }
    fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        hkdf::Hkdf::<sha2::Sha512>::new(Some(salt), ikm)
            .expand(info, &mut out)
            .unwrap();
        out
    }
    fn sha(x: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(x).into()
    }
    fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        use hmac::{KeyInit, Mac};
        let mut m = <hmac::Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key).unwrap();
        m.update(msg);
        m.finalize().into_bytes()[..32].try_into().unwrap()
    }
    const P: [u8; 16] = [7; 16];
    const TH: [u8; 32] = [8; 32];
    const VAULT: VaultId = VaultId([0x55; 16]);
    const GEN: KeyGeneration = KeyGeneration(3);
    const LINK: [u8; 16] = [0x33; 16];
    fn ss(byte: u8) -> XWingSharedSecret {
        crate::xwing::tests_support::shared_secret([byte; 32])
    }
    fn nonce(byte: u8) -> PairNonce {
        PairNonce::from_bytes(&[byte; 32]).unwrap()
    }
    fn root() -> LinkRoot {
        LinkRoot::derive(
            &VaultKey::from_bytes([0x44; 32]),
            VAULT,
            GEN,
            DerivationProfile::V1,
        )
        .unwrap()
    }

    #[test]
    fn lan_pairing_keys_match_an_independent_construction() {
        let keys = PairingSecret::from_bytes(&P).unwrap().keys().unwrap();
        let id = hkdf(&P, &[], &arr(&[t("qv/lan-pair-id/v1")]), 16);
        assert_eq!(keys.pairing_id(), &id[..]);
        assert!(keys.matches_pairing_id(&id.clone().try_into().unwrap()));
        assert!(!keys.matches_pairing_id(&[0; 16]));
        let k_hello = hkdf(&P, &id, &arr(&[t("qv/lan-pair-mac/v1"), t("hello")]), 32);
        let k_accept = hkdf(&P, &id, &arr(&[t("qv/lan-pair-mac/v1"), t("accept")]), 32);
        assert_eq!(&keys.hello.expose_secret()[..], &k_hello[..]);
        assert_eq!(&keys.accept.expose_secret()[..], &k_accept[..]);
        let tag = keys.hello_mac(b"body").unwrap();
        assert_eq!(tag.as_bytes(), &mac(&k_hello, b"body"));
        keys.verify_hello(b"body", &tag).unwrap();
        assert_eq!(
            keys.verify_hello(b"bodY", &tag),
            Err(CryptoError::Integrity)
        );
        // The accept key is not the hello key.
        assert_eq!(
            keys.verify_accept(b"body", &tag),
            Err(CryptoError::Integrity)
        );
        let tag = keys.accept_mac(b"t").unwrap();
        keys.verify_accept(b"t", &tag).unwrap();

        // Record keys: HKDF(ss ‖ P, th, ["qv/lan-pair-key/v1", role]).
        let (b2a, a2b) = keys.record_keys(&ss(9), &TH).unwrap();
        let ikm = [[9u8; 32].as_slice(), &P].concat();
        let want = |role| hkdf(&ikm, &TH, &arr(&[t("qv/lan-pair-key/v1"), t(role)]), 32);
        assert_eq!(&b2a.0.expose_secret()[..], &want("b2a")[..]);
        assert_eq!(&a2b.0.expose_secret()[..], &want("a2b")[..]);
        assert_ne!(b2a.0.expose_secret(), a2b.0.expose_secret());
    }

    #[test]
    fn lan_commitment_and_comparison_code() {
        let n = nonce(0x11);
        let commit = n.commitment().unwrap();
        assert_eq!(
            commit,
            sha(&arr(&[t("qv/lan-pair-commit/v1"), b(&[0x11; 32])]))
        );
        assert!(n.matches(&commit).unwrap());
        let mut flipped = [0x11; 32];
        flipped[31] ^= 1;
        assert!(
            !PairNonce::from_bytes(&flipped)
                .unwrap()
                .matches(&commit)
                .unwrap()
        );
        assert_eq!(
            PairNonce::from_bytes(&[0; 31]).err(),
            Some(CryptoError::LimitExceeded)
        );

        let h = sha(&arr(&[t("qv/lan-pair-sas/v1"), b(&TH), b(&[0x11; 32])]));
        let want = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
        let sas = Sas::compute(&TH, &n).unwrap();
        assert_eq!(sas.digits(), *format!("{want:06}").as_bytes());
        assert_ne!(Sas::compute(&TH, &nonce(0x12)).unwrap(), sas);
        assert_ne!(Sas::compute(&[9; 32], &n).unwrap(), sas);
        assert_eq!(Sas(7).digits(), *b"000007");
        assert_eq!(Sas(999_999).digits(), *b"999999");
        assert_eq!(format!("{sas:?}"), "Sas(..)");
    }

    #[test]
    fn lan_link_key_and_proofs_match_and_bind_their_context() {
        let vk = VaultKey::from_bytes([0x44; 32]);
        let root = root();
        // K_lan is the "lan-link" purpose key.
        let info = arr(&[t("qv/purpose/v1"), t("lan-link"), vec![3], vec![1]]);
        let k_lan = hkdf(&vk.bytes(), &VAULT.0, &info, 32);
        assert_eq!(&root.0.expose_secret()[..], &k_lan[..]);

        let link = root
            .link_key(&ss(9), &TH, &nonce(0x11), &LINK, VAULT, GEN)
            .unwrap();
        let salt = sha(&arr(&[
            t("qv/lan-link-salt/v1"),
            b(&TH),
            b(&[0x11; 32]),
            b(&LINK),
        ]));
        let info = arr(&[t("qv/lan-link/v1"), b(&VAULT.0), vec![3], b(&LINK)]);
        let want = hkdf(&[k_lan.as_slice(), &[9; 32]].concat(), &salt, &info, 32);
        assert_eq!(&link.0.expose_secret()[..], &want[..]);
        // Each input changes the key.
        for other in [
            root.link_key(&ss(8), &TH, &nonce(0x11), &LINK, VAULT, GEN),
            root.link_key(&ss(9), &[0; 32], &nonce(0x11), &LINK, VAULT, GEN),
            root.link_key(&ss(9), &TH, &nonce(0x12), &LINK, VAULT, GEN),
            root.link_key(&ss(9), &TH, &nonce(0x11), &[0; 16], VAULT, GEN),
            root.link_key(&ss(9), &TH, &nonce(0x11), &LINK, VaultId([0; 16]), GEN),
            root.link_key(&ss(9), &TH, &nonce(0x11), &LINK, VAULT, KeyGeneration(4)),
        ] {
            assert!(!other.unwrap().ct_eq(&link));
        }

        let proof = root.proof(&TH, ProofRole::B, VAULT, GEN).unwrap();
        let input = arr(&[
            t("qv/lan-pair-prove/v1"),
            b(&TH),
            t("b"),
            b(&VAULT.0),
            vec![3],
        ]);
        assert_eq!(proof.as_bytes(), &mac(&k_lan, &input));
        root.verify_proof(&TH, ProofRole::B, VAULT, GEN, &proof)
            .unwrap();
        // Reflection, other vault, generation, transcript or root all fail.
        let fails = [
            root.verify_proof(&TH, ProofRole::A, VAULT, GEN, &proof),
            root.verify_proof(&TH, ProofRole::B, VaultId([0; 16]), GEN, &proof),
            root.verify_proof(&TH, ProofRole::B, VAULT, KeyGeneration(4), &proof),
            root.verify_proof(&[0; 32], ProofRole::B, VAULT, GEN, &proof),
            LinkRoot::derive(&vk, VAULT, KeyGeneration(4), DerivationProfile::V1)
                .unwrap()
                .verify_proof(&TH, ProofRole::B, VAULT, GEN, &proof),
        ];
        for f in fails {
            assert_eq!(f, Err(CryptoError::Integrity));
        }
    }

    #[test]
    fn lan_link_rows_round_trip_and_bind_their_aad() {
        let vk = VaultKey::from_bytes([0x44; 32]);
        let local = vk
            .purpose_key::<purpose::LocalState>(VAULT, GEN, DerivationProfile::V1)
            .unwrap();
        let link = root()
            .link_key(&ss(9), &TH, &nonce(0x11), &LINK, VAULT, GEN)
            .unwrap();
        let p = StoredDataProfile::V1;
        let sealed = seal_link_row(&local, p, VAULT, GEN, &LINK, &link, "Phone", 1234).unwrap();
        assert!(sealed.ciphertext.len() <= LINK_ROW_CIPHERTEXT_MAX);
        let row = open_link_row(
            &local,
            p,
            VAULT,
            GEN,
            &LINK,
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .unwrap();
        assert!(row.key.ct_eq(&link));
        assert_eq!(row.label.expose_secret(), b"Phone");
        assert_eq!(row.created_at, 1234);
        assert_eq!(
            format!("{row:?} {link:?}"),
            "LinkRow(<redacted>) LinkKey(<redacted>)"
        );
        // The AAD binds vault, generation and link ID.
        for (v, g, l) in [
            (VaultId([0; 16]), GEN, LINK),
            (VAULT, KeyGeneration(4), LINK),
            (VAULT, GEN, [0; 16]),
        ] {
            assert_eq!(
                open_link_row(&local, p, v, g, &l, &sealed.nonce, &sealed.ciphertext).err(),
                Some(CryptoError::Integrity)
            );
        }
        let mut bad = sealed.ciphertext.clone();
        bad[0] ^= 1;
        assert!(open_link_row(&local, p, VAULT, GEN, &LINK, &sealed.nonce, &bad).is_err());
        // Labels: 1–64 bytes, no control characters.
        for label in ["", "a\nb", &"x".repeat(65)] {
            assert_eq!(
                seal_link_row(&local, p, VAULT, GEN, &LINK, &link, label, 0).err(),
                Some(CryptoError::LimitExceeded)
            );
        }
        assert!(seal_link_row(&local, p, VAULT, GEN, &LINK, &link, &"é".repeat(32), 0).is_ok());
    }

    #[test]
    fn lan_secret_inputs_are_bounded_and_redacted() {
        assert_eq!(
            PairingSecret::from_bytes(&[0; 15]).err(),
            Some(CryptoError::LimitExceeded)
        );
        assert_eq!(
            PairingSecret::from_bytes(&[0; 17]).err(),
            Some(CryptoError::LimitExceeded)
        );
        for len in [31, 33] {
            assert_eq!(
                VaultKey::from_transfer(&vec![0; len]).err(),
                Some(CryptoError::LimitExceeded)
            );
        }
        let vk = VaultKey::from_bytes([0x44; 32]);
        let mut e = qv_encoding::Encoder::new();
        vk.encode_for_transfer(&mut e);
        let bytes = e.finish().unwrap();
        let back = VaultKey::from_transfer(&bytes[2..]).unwrap();
        assert!(back.ct_eq(&vk));
        assert!(!back.ct_eq(&VaultKey::from_bytes([0x45; 32])));
        let secret = PairingSecret::generate().unwrap();
        let keys = PairingSecret::from_bytes(secret.expose_secret())
            .unwrap()
            .keys()
            .unwrap();
        assert_eq!(
            format!("{secret:?} {keys:?} {:?} {:?}", nonce(1), root()),
            "PairingSecret(<redacted>) PairingKeys(<redacted>) PairNonce(<redacted>) LinkRoot(<redacted>)"
        );
    }

    #[test]
    fn lan_direction_stops_at_two_to_the_thirty_two() {
        let (mut s, mut o) = pair(5);
        s.set_seq(RECORDS_PER_DIRECTION - 1);
        o.set_seq(RECORDS_PER_DIRECTION - 1);
        let last = s.seal(b"last").unwrap();
        assert_eq!(o.open(&last).unwrap().expose_secret(), b"last");
        assert_eq!(s.seal(b"more"), Err(CryptoError::LimitExceeded));
        assert_eq!(o.open(&last).unwrap_err(), CryptoError::LimitExceeded);
        assert_eq!(
            format!("{s:?} {o:?}"),
            "RecordSealer(<redacted>) RecordOpener(<redacted>)"
        );
    }
}
