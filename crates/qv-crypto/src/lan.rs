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
//! [`PairingKeys::record_keys`] for each one-use pairing connection (§4.4).
//! Sync uses the same connection after transcript-bound vault-key proofs
//! (0014 §2.3); there is no stored link or separate session handshake.
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
//! | `K_proof` | VK | vault ID | purpose `lan-proof` (0002 §3.3, 0014 §2.3) |
//! | proof | MAC/1 under `K_proof` | — | `["qv/lan-pair-prove/v1", th, "a"|"b", vault_id, key_generation]` |
//!
//! `H` is SHA-256 of a canonical encoding ([`transcript_hash`]). The wire
//! messages that `th` covers are built by `qv-protocol`; this module only
//! sees their canonical bytes. Every key and nonce here lives in locked
//! memory and has a redacted `Debug`. Every check is constant time.
//!
//! No peer key or link row is retained after the exchange (0013 §9.1).

#[path = "lan_v2.rs"]
pub mod v2;

use crate::error::CryptoError;
use crate::ids::{KeyGeneration, VaultId};
use crate::keys::{PurposeKey, VaultKey, cbor_array, derive_secret, purpose};
use crate::memory::{SecretArray, SecretBytes};
use crate::primitives::{
    MacTag, NONCE_LEN, TAG_LEN, hkdf_sha512_into, mac1, mac1_verify, sha256, xchacha_open_in_place,
    xchacha_seal_in_place,
};
use crate::profile::DerivationProfile;
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

/// Which side a sync-mode proof speaks for (0013 §4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofRole {
    /// The offering device, `"a"`.
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

/// `K_proof`: the generation's LAN proof key (0013 §4.6). Only holders of
/// this generation's VK can derive it.
pub struct ProofRoot(PurposeKey<purpose::LanProof>);

impl ProofRoot {
    /// The `lan-proof` purpose key of VK for this vault and generation.
    pub fn derive(
        vk: &VaultKey,
        vault: VaultId,
        generation: KeyGeneration,
        profile: DerivationProfile,
    ) -> Result<Self, CryptoError> {
        Ok(Self(vk.purpose_key::<purpose::LanProof>(
            vault, generation, profile,
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

    /// A sync-mode proof for `role` (0013 §4.8).
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

    /// Verifies a sync-mode proof in constant time ([`CryptoError::Integrity`]).
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

impl core::fmt::Debug for ProofRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProofRoot(<redacted>)")
    }
}

/// Key bytes for the interoperability vectors only (plan 0037 step 8). The
/// `test-vectors` feature is enabled only by dev-dependencies.
#[cfg(any(test, feature = "test-vectors"))]
pub mod vectors {
    use super::{PairingKeys, ProofRoot, RecordKey};

    /// `K_hello` and `K_accept`.
    pub fn pairing_mac_keys(k: &PairingKeys) -> ([u8; 32], [u8; 32]) {
        (*k.hello.expose_secret(), *k.accept.expose_secret())
    }
    /// A record key.
    pub fn record_key(k: &RecordKey) -> [u8; 32] {
        *k.0.expose_secret()
    }
    /// `K_proof`.
    pub fn proof_root(k: &ProofRoot) -> [u8; 32] {
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
    fn ss(byte: u8) -> XWingSharedSecret {
        crate::xwing::tests_support::shared_secret([byte; 32])
    }
    fn nonce(byte: u8) -> PairNonce {
        PairNonce::from_bytes(&[byte; 32]).unwrap()
    }
    fn root() -> ProofRoot {
        ProofRoot::derive(
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
    fn lan_proofs_match_and_bind_their_context() {
        let vk = VaultKey::from_bytes([0x44; 32]);
        let root = root();
        // K_proof is the "lan-proof" purpose key.
        let info = arr(&[t("qv/purpose/v1"), t("lan-proof"), vec![3], vec![1]]);
        let k_proof = hkdf(&vk.bytes(), &VAULT.0, &info, 32);
        assert_eq!(&root.0.expose_secret()[..], &k_proof[..]);

        let proof = root.proof(&TH, ProofRole::B, VAULT, GEN).unwrap();
        let input = arr(&[
            t("qv/lan-pair-prove/v1"),
            b(&TH),
            t("b"),
            b(&VAULT.0),
            vec![3],
        ]);
        assert_eq!(proof.as_bytes(), &mac(&k_proof, &input));
        root.verify_proof(&TH, ProofRole::B, VAULT, GEN, &proof)
            .unwrap();
        // The two roles give different proofs.
        assert_ne!(
            root.proof(&TH, ProofRole::A, VAULT, GEN)
                .unwrap()
                .as_bytes(),
            proof.as_bytes()
        );
        // Reflection, other vault, generation, transcript or VK all fail.
        let fails = [
            root.verify_proof(&TH, ProofRole::A, VAULT, GEN, &proof),
            root.verify_proof(&TH, ProofRole::B, VaultId([0; 16]), GEN, &proof),
            root.verify_proof(&TH, ProofRole::B, VAULT, KeyGeneration(4), &proof),
            root.verify_proof(&[0; 32], ProofRole::B, VAULT, GEN, &proof),
            ProofRoot::derive(&vk, VAULT, KeyGeneration(4), DerivationProfile::V1)
                .unwrap()
                .verify_proof(&TH, ProofRole::B, VAULT, GEN, &proof),
            ProofRoot::derive(
                &VaultKey::from_bytes([0x45; 32]),
                VAULT,
                GEN,
                DerivationProfile::V1,
            )
            .unwrap()
            .verify_proof(&TH, ProofRole::B, VAULT, GEN, &proof),
        ];
        for f in fails {
            assert_eq!(f, Err(CryptoError::Integrity));
        }
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
            "PairingSecret(<redacted>) PairingKeys(<redacted>) PairNonce(<redacted>) ProofRoot(<redacted>)"
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
