// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential-bound LAN schedules and explicit record epochs (0013 §15).
//! The old profile is retained only while callers migrate; this module never
//! decrypts with a previous epoch or derives final keys from a code alone.
use qv_encoding::{EncodeError, Encoder, encode_array};
use std::marker::PhantomData;
use zeroize::Zeroizing;

use super::{
    PairNonce, PairingSecret, RECORD_PLAINTEXT_MAX, RECORDS_PER_DIRECTION, Sas, transcript_hash,
};
use crate::lan_auth::AuthSecret;
use crate::primitives::{
    MacTag, NONCE_LEN, TAG_LEN, hkdf_sha512_into, mac1, mac1_verify, xchacha_open_in_place,
    xchacha_seal_in_place,
};
use crate::{
    CryptoError, KeyGeneration, SecretArray, SecretBytes, VaultId, VaultKey, XWingSharedSecret,
};

/// The only valid method/intent combinations. Password/sync is unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    /// Enter the password on both devices to enroll a new copy.
    PasswordEnrollment,
    /// Enroll using an independently decoded recovery key.
    KeyEnrollment,
    /// Sync two independently unlocked copies.
    KeySync,
}
impl AuthMode {
    /// Exact J array, also used by the key-free protocol encoder.
    pub fn encode(self, a: &mut Encoder) -> Result<(), EncodeError> {
        a.array(|j| {
            j.uint(2);
            j.uint(u64::from(self == Self::PasswordEnrollment));
            j.uint(u64::from(self != Self::PasswordEnrollment));
            j.uint(u64::from(self == Self::KeySync));
            Ok(())
        })
    }
}
mod epoch_sealed {
    pub trait Sealed {}
}
/// Closed epoch namespace. Callers cannot implement additional epochs.
pub trait Epoch: epoch_sealed::Sealed {
    /// Fixed wire epoch number.
    const NUMBER: u8;
}
/// Outer code/KEM keys; cannot be used where a final grant channel is required.
pub struct InitialEpoch;
/// Credential-bound final keys, available only through OuterSchedule::complete.
pub struct FinalEpoch;
impl epoch_sealed::Sealed for InitialEpoch {}
impl epoch_sealed::Sealed for FinalEpoch {}
impl Epoch for InitialEpoch {
    const NUMBER: u8 = 0;
}
impl Epoch for FinalEpoch {
    const NUMBER: u8 = 1;
}

/// The local transport role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Offering device A.
    Offerer,
    /// Connecting device B.
    Joiner,
}
#[derive(Clone, Copy)]
enum Direction {
    A2b,
    B2a,
}
impl Direction {
    fn label(self) -> &'static str {
        match self {
            Self::A2b => "a2b",
            Self::B2a => "b2a",
        }
    }
}

fn array(
    f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    encode_array(f).map_err(|_| CryptoError::Internal)
}
fn derive<const N: usize>(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<SecretArray<N>, CryptoError> {
    SecretArray::try_init(|out| hkdf_sha512_into(ikm, Some(salt), info, out))
}
fn hash(f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>) -> Result<[u8; 32], CryptoError> {
    Ok(transcript_hash(&array(f)?))
}

/// Private per-window/attempt P and independent hello/accept MAC keys.
pub struct PairingKeys {
    secret: PairingSecret,
    id: [u8; 16],
    hello: SecretArray<32>,
    accept: SecretArray<32>,
}
impl core::fmt::Debug for PairingKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairingKeysV2(<redacted>)")
    }
}
impl PairingKeys {
    /// Derive the profile2 admission keys from one out-of-band code.
    pub fn new(secret: PairingSecret) -> Result<Self, CryptoError> {
        let id_info = array(|a| {
            a.text("qv/lan-pair-id/v2");
            Ok(())
        })?;
        let mut id = [0; 16];
        hkdf_sha512_into(secret.expose_secret(), Some(&[]), &id_info, &mut id)?;
        let mac = |role: &str| {
            derive(
                secret.expose_secret(),
                &id,
                &array(|a| {
                    a.text("qv/lan-pair-mac/v2");
                    a.text(role);
                    Ok(())
                })?,
            )
        };
        let hello = mac("hello")?;
        let accept = mac("accept")?;
        Ok(Self {
            secret,
            id,
            hello,
            accept,
        })
    }
    /// Pairing identifier for the authenticated hello.
    pub fn pairing_id(&self) -> &[u8; 16] {
        &self.id
    }
    /// Constant-time comparison of a received window identifier.
    pub fn matches_pairing_id(&self, id: &[u8; 16]) -> bool {
        use ctutils::CtEq;
        self.id[..].ct_eq(&id[..]).to_bool()
    }
    /// The protected code retained only for this window/session.
    pub fn secret(&self) -> &PairingSecret {
        &self.secret
    }
    /// Code-authentication tag over the complete canonical hello body.
    pub fn hello_mac(&self, body: &[u8]) -> Result<MacTag, CryptoError> {
        mac1(self.hello.expose_secret(), body)
    }
    /// Verify the hello before KEM work or admission.
    pub fn verify_hello(&self, body: &[u8], tag: &MacTag) -> Result<(), CryptoError> {
        mac1_verify(self.hello.expose_secret(), body, tag)
    }
    /// Code-authentication tag over the complete accept transcript input.
    pub fn accept_mac(&self, body: &[u8]) -> Result<MacTag, CryptoError> {
        mac1(self.accept.expose_secret(), body)
    }
    /// Verify the accept before decapsulation.
    pub fn verify_accept(&self, body: &[u8], tag: &MacTag) -> Result<(), CryptoError> {
        mac1_verify(self.accept.expose_secret(), body, tag)
    }
    /// Discovery tag; hints have no authority.
    pub fn discovery_tag(&self) -> Result<[u8; 4], CryptoError> {
        let info = array(|a| {
            a.text("qv/lan-pair-tag/v2");
            Ok(())
        })?;
        let mut tag = [0; 4];
        hkdf_sha512_into(self.secret.expose_secret(), Some(&self.id), &info, &mut tag)?;
        Ok(tag)
    }
    /// Consume admitted P and KEM output into the one outer schedule. Admission
    /// listeners must already be gone. Initial channels cannot release a grant.
    pub fn begin(
        self,
        shared: XWingSharedSecret,
        mode: AuthMode,
        t0: [u8; 32],
    ) -> Result<(OuterSchedule, TrafficKeys<InitialEpoch>), CryptoError> {
        let ikm = SecretArray::<48>::try_init(|out| {
            out[..32].copy_from_slice(shared.expose_secret());
            out[32..].copy_from_slice(self.secret.expose_secret());
            Ok::<_, CryptoError>(())
        })?;
        let channels = traffic::<InitialEpoch>(ikm.expose_secret(), mode, t0, t0)?;
        Ok((
            OuterSchedule {
                secret: self.secret,
                shared,
                mode,
                t0,
            },
            channels,
        ))
    }
}

/// P and ss retained only until the final credential-bound schedule is made.
pub struct OuterSchedule {
    secret: PairingSecret,
    shared: XWingSharedSecret,
    mode: AuthMode,
    t0: [u8; 32],
}
impl core::fmt::Debug for OuterSchedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OuterSchedule(<redacted>)")
    }
}
impl OuterSchedule {
    /// Consume the credential result and outer secrets. Role/method/context
    /// substitution fails before returning any final channels.
    pub fn complete(
        self,
        auth: AuthSecret,
        ta: [u8; 32],
    ) -> Result<(TrafficKeys<FinalEpoch>, FinishedKey), CryptoError> {
        if auth.mode != self.mode || auth.t0 != self.t0 {
            return Err(CryptoError::Integrity);
        }
        let ikm = SecretArray::<112>::try_init(|out| {
            out[..32].copy_from_slice(self.shared.expose_secret());
            out[32..48].copy_from_slice(self.secret.expose_secret());
            out[48..].copy_from_slice(auth.key.expose_secret());
            Ok::<_, CryptoError>(())
        })?;
        let channels = traffic::<FinalEpoch>(ikm.expose_secret(), self.mode, self.t0, ta)?;
        let info = array(|a| {
            a.text("qv/lan-finished-key/v2");
            self.mode.encode(a)?;
            a.text("b");
            a.bytes(&ta);
            Ok(())
        })?;
        let key = derive(ikm.expose_secret(), &ta, &info)?;
        Ok((
            channels,
            FinishedKey {
                key,
                mode: self.mode,
                ta,
            },
        ))
    }
}

/// Initial or final directional keys. Only the schedule constructs this type;
/// splitting consumes it and starts each direction's independent counter at0.
pub struct TrafficKeys<E: Epoch> {
    a2b: SecretArray<32>,
    b2a: SecretArray<32>,
    mode: AuthMode,
    _epoch: PhantomData<E>,
    outer: [u8; 32],
    transcript: [u8; 32],
}
fn traffic<E: Epoch>(
    ikm: &[u8],
    mode: AuthMode,
    outer: [u8; 32],
    transcript: [u8; 32],
) -> Result<TrafficKeys<E>, CryptoError> {
    let key = |d: Direction| {
        derive(
            ikm,
            &transcript,
            &array(|a| {
                a.text("qv/lan-key/v2");
                mode.encode(a)?;
                a.uint(E::NUMBER.into());
                a.text(d.label());
                a.bytes(&transcript);
                Ok(())
            })?,
        )
    };
    Ok(TrafficKeys {
        a2b: key(Direction::A2b)?,
        b2a: key(Direction::B2a)?,
        mode,
        _epoch: PhantomData,
        outer,
        transcript,
    })
}
impl<E: Epoch> TrafficKeys<E> {
    /// Obtain the sending and receiving halves for this local role.
    pub fn split(self, role: Role) -> (RecordSealer<E>, RecordOpener<E>) {
        let (send, recv, direction) = match role {
            Role::Offerer => (self.a2b, self.b2a, Direction::A2b),
            Role::Joiner => (self.b2a, self.a2b, Direction::B2a),
        };
        let opposite = match direction {
            Direction::A2b => Direction::B2a,
            Direction::B2a => Direction::A2b,
        };
        (
            RecordSealer {
                key: send,
                mode: self.mode,
                _epoch: PhantomData,
                outer: self.outer,
                transcript: self.transcript,
                direction,
                seq: 0,
                failed: false,
            },
            RecordOpener {
                key: recv,
                mode: self.mode,
                _epoch: PhantomData,
                outer: self.outer,
                transcript: self.transcript,
                direction: opposite,
                seq: 0,
                failed: false,
            },
        )
    }
}
impl<E: Epoch> core::fmt::Debug for TrafficKeys<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TrafficKeysV2(<redacted>)")
    }
}

/// The separate FinishedB key; no raw-byte accessor is exposed.
pub struct FinishedKey {
    key: SecretArray<32>,
    mode: AuthMode,
    ta: [u8; 32],
}
impl FinishedKey {
    fn input(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        array(|a| {
            a.text("qv/lan-finished-mac/v2");
            self.mode.encode(a)?;
            a.text("b");
            a.bytes(&self.ta);
            Ok(())
        })
    }
    /// B's explicit confirmation before A may seal a grant.
    pub fn tag(&self) -> Result<MacTag, CryptoError> {
        mac1(self.key.expose_secret(), &self.input()?)
    }
    /// A verifies B's composed traffic keys, independent of successful KE3.
    pub fn verify(&self, tag: &MacTag) -> Result<(), CryptoError> {
        mac1_verify(self.key.expose_secret(), &self.input()?, tag)
    }
}
impl core::fmt::Debug for FinishedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FinishedKey(<redacted>)")
    }
}

fn aad(
    mode: AuthMode,
    epoch: u8,
    direction: Direction,
    transcript: &[u8; 32],
    seq: u64,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    array(|a| {
        a.text("qv/lan-record/v2");
        mode.encode(a)?;
        a.uint(epoch.into());
        a.text(direction.label());
        a.bytes(transcript);
        a.uint(seq);
        Ok(())
    })
}
fn nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    nonce[16..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// One profile2 sending direction, permanently fixed to one epoch/context.
pub struct RecordSealer<E: Epoch> {
    key: SecretArray<32>,
    mode: AuthMode,
    _epoch: PhantomData<E>,
    outer: [u8; 32],
    transcript: [u8; 32],
    direction: Direction,
    seq: u64,
    failed: bool,
}
impl<E: Epoch> RecordSealer<E> {
    /// Public outer-session binding for core's captured grant authorization.
    /// These are transcript identifiers, not key bytes or an authorization by themselves.
    pub fn binding(&self) -> (AuthMode, [u8; 32]) {
        (self.mode, self.outer)
    }
    /// The next sequence, so a password grant can require A's first final record.
    pub fn next_sequence(&self) -> u64 {
        self.seq
    }
    /// Seal the next record. Every error poisons this direction; no retry or counter rewind.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if self.failed {
            return Err(CryptoError::Integrity);
        }
        let result = self.seal_next(plaintext);
        if result.is_ok() {
            self.seq += 1;
        } else {
            self.failed = true;
        }
        result
    }
    fn seal_next(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if self.seq >= RECORDS_PER_DIRECTION || plaintext.len() > RECORD_PLAINTEXT_MAX {
            return Err(CryptoError::LimitExceeded);
        }
        let aad = aad(
            self.mode,
            E::NUMBER,
            self.direction,
            &self.transcript,
            self.seq,
        )?;
        let mut out = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
        out.extend_from_slice(plaintext);
        let tag =
            xchacha_seal_in_place(self.key.expose_secret(), &nonce(self.seq), &aad, &mut out)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }
}
impl<E: Epoch> core::fmt::Debug for RecordSealer<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordSealerV2(<redacted>)")
    }
}

/// One profile2 receiving direction; no previous-key trial decrypt is possible.
pub struct RecordOpener<E: Epoch> {
    key: SecretArray<32>,
    mode: AuthMode,
    _epoch: PhantomData<E>,
    outer: [u8; 32],
    transcript: [u8; 32],
    direction: Direction,
    seq: u64,
    failed: bool,
}
impl<E: Epoch> RecordOpener<E> {
    /// Public outer-session binding; useful for rejecting mixed driver state.
    pub fn binding(&self) -> (AuthMode, [u8; 32]) {
        (self.mode, self.outer)
    }
    /// Open exactly the next expected record into protected storage.
    pub fn open(&mut self, record: &[u8]) -> Result<SecretBytes, CryptoError> {
        if self.failed {
            return Err(CryptoError::Integrity);
        }
        let result = self.open_next(record);
        if result.is_ok() {
            self.seq += 1;
        } else {
            self.failed = true;
        }
        result
    }
    fn open_next(&self, record: &[u8]) -> Result<SecretBytes, CryptoError> {
        if self.seq >= RECORDS_PER_DIRECTION
            || record.len() < TAG_LEN
            || record.len() > RECORD_PLAINTEXT_MAX + TAG_LEN
        {
            return Err(CryptoError::LimitExceeded);
        }
        let (body, tag) = record.split_at(record.len() - TAG_LEN);
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::Internal)?;
        let aad = aad(
            self.mode,
            E::NUMBER,
            self.direction,
            &self.transcript,
            self.seq,
        )?;
        SecretBytes::try_init(body.len(), |out| {
            out.copy_from_slice(body);
            xchacha_open_in_place(self.key.expose_secret(), &nonce(self.seq), &aad, out, tag)
        })
    }
}
impl<E: Epoch> core::fmt::Debug for RecordOpener<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordOpenerV2(<redacted>)")
    }
}

/// Independently held VK proves first; MAC and final-schedule keys are separate.
pub struct KeyAuthentication {
    mac: SecretArray<32>,
    auth: AuthSecret,
}
impl KeyAuthentication {
    /// Only key enrollment or key sync is valid for this constructor.
    pub fn new(vk: &VaultKey, mode: AuthMode, t0: [u8; 32]) -> Result<Self, CryptoError> {
        if mode == AuthMode::PasswordEnrollment {
            return Err(CryptoError::Integrity);
        }
        let info = |purpose: &str| {
            array(|a| {
                a.text("qv/lan-key-auth/v2");
                mode.encode(a)?;
                a.text(purpose);
                a.bytes(&t0);
                Ok(())
            })
        };
        let mac = derive(vk.expose_secret(), &t0, &info("mac")?)?;
        let key = derive(vk.expose_secret(), &t0, &info("schedule")?)?;
        Ok(Self {
            mac,
            auth: AuthSecret { key, mode, t0 },
        })
    }
    /// B's role-bound proof, containing no request for vault metadata.
    pub fn joiner_proof(&self) -> Result<MacTag, CryptoError> {
        mac1(
            self.mac.expose_secret(),
            &proof_input(self.auth.mode, &self.auth.t0, None)?,
        )
    }
    /// A must consume a valid B proof before obtaining the capability to reply.
    pub fn accept_joiner(self, proof: &MacTag) -> Result<VerifiedJoiner, CryptoError> {
        mac1_verify(
            self.mac.expose_secret(),
            &proof_input(self.auth.mode, &self.auth.t0, None)?,
            proof,
        )?;
        Ok(VerifiedJoiner(self))
    }
    /// B verifies the offered identity/proof before obtaining a final secret.
    /// Existing copies additionally compare identity with their local vault.
    pub fn accept_offerer(
        self,
        vault: VaultId,
        generation: KeyGeneration,
        proof: &MacTag,
    ) -> Result<AuthSecret, CryptoError> {
        mac1_verify(
            self.mac.expose_secret(),
            &proof_input(self.auth.mode, &self.auth.t0, Some((vault, generation)))?,
            proof,
        )?;
        Ok(self.auth)
    }
}
impl core::fmt::Debug for KeyAuthentication {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyAuthentication(<redacted>)")
    }
}
/// A can construct its identity proof only after B's proof was accepted.
pub struct VerifiedJoiner(KeyAuthentication);
impl VerifiedJoiner {
    /// Produce A's identity-bound proof and consume the capability into Z.
    pub fn offer(
        self,
        vault: VaultId,
        generation: KeyGeneration,
    ) -> Result<(MacTag, AuthSecret), CryptoError> {
        let tag = mac1(
            self.0.mac.expose_secret(),
            &proof_input(self.0.auth.mode, &self.0.auth.t0, Some((vault, generation)))?,
        )?;
        Ok((tag, self.0.auth))
    }
}
impl core::fmt::Debug for VerifiedJoiner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedJoiner(<redacted>)")
    }
}
fn proof_input(
    mode: AuthMode,
    t0: &[u8; 32],
    identity: Option<(VaultId, KeyGeneration)>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let identity_hash = identity
        .map(|(vault, generation)| {
            hash(|a| {
                a.bytes(&vault.0);
                a.uint(generation.0.into());
                Ok(())
            })
        })
        .transpose()?;
    array(|a| {
        a.text("qv/lan-key-proof/v2");
        mode.encode(a)?;
        a.text(if identity.is_some() { "a" } else { "b" });
        a.bytes(t0);
        if let Some(h) = identity_hash {
            a.bytes(&h);
        }
        Ok(())
    })
}

/// Profile2 nonce commitment, checked before offering-device approval.
pub fn nonce_commitment(nonce: &PairNonce) -> Result<[u8; 32], CryptoError> {
    hash(|a| {
        a.text("qv/lan-pair-commit/v2");
        a.bytes(nonce.expose_secret());
        Ok(())
    })
}
/// Six digits bound to J, T0 and B's committed nonce.
pub fn comparison_code(
    mode: AuthMode,
    t0: &[u8; 32],
    nonce: &PairNonce,
) -> Result<Sas, CryptoError> {
    let h = hash(|a| {
        a.text("qv/lan-pair-sas/v2");
        mode.encode(a)?;
        a.bytes(t0);
        a.bytes(nonce.expose_secret());
        Ok(())
    })?;
    let value = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    Ok(Sas(value))
}

#[cfg(test)]
#[path = "lan_v2_tests.rs"]
mod tests;
