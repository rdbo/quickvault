// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure pairing computations (0013 §4.3–4.5): message construction, the
//! approver's ordered hello checks, the joiner's accept check and the
//! transcript. No I/O and no randomness: the drivers draw the nonces and
//! X-Wing keys, and the interoperability vectors replay fixed ones.

use qv_crypto::lan::{PairNonce, PairingKeys, RecordKey, transcript_hash};
use qv_crypto::{MacTag, XWingCiphertext, XWingDecapsKey, XWingEncapsKey, XWingSharedSecret};
use qv_protocol::lan::{JoinMode, PairAccept, PairHello, pair_th_input};
use qv_protocol::message::body_without_last;
use qv_protocol::registry::LanProfile;
use zeroize::Zeroizing;

use super::LanError;

/// One joining attempt: the hello B sends and the secrets behind it.
pub(crate) struct JoinAttempt {
    pub(crate) nonce_b: PairNonce,
    pub(crate) dk: XWingDecapsKey,
    pub(crate) hello: Zeroizing<Vec<u8>>,
    pub(crate) hello_hash: [u8; 32],
}

/// Builds `PairHello` for `mode` from fixed inputs (0013 §4.3).
pub(crate) fn join_attempt(
    keys: &PairingKeys,
    mode: JoinMode,
    nonce_b: PairNonce,
    dk: XWingDecapsKey,
    ek: &XWingEncapsKey,
) -> Result<JoinAttempt, LanError> {
    let commit = nonce_b.commitment().map_err(|_| LanError::Protocol)?;
    let body = PairHello::body(
        LanProfile::V1,
        keys.pairing_id(),
        mode,
        &commit,
        ek.as_bytes(),
    )
    .map_err(|_| LanError::Protocol)?;
    let mac = keys.hello_mac(&body).map_err(|_| LanError::Protocol)?;
    let hello = PairHello::encode(
        LanProfile::V1,
        keys.pairing_id(),
        mode,
        &commit,
        ek.as_bytes(),
        mac.as_bytes(),
    )
    .map_err(|_| LanError::Protocol)?;
    let hello_hash = transcript_hash(&hello);
    Ok(JoinAttempt {
        nonce_b,
        dk,
        hello,
        hello_hash,
    })
}

/// Why a hello was refused; nothing is ever sent for it (0013 §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    Shape,
    Profile,
    PairingId,
    Mac,
    Key,
}

/// A hello that passed every check.
pub(crate) struct CheckedHello {
    pub(crate) mode: JoinMode,
    pub(crate) commit: [u8; 32],
    pub(crate) ek: XWingEncapsKey,
    pub(crate) hash: [u8; 32],
}

/// The approver's checks, in the order of 0013 §4.3: exact shape, profile,
/// `pairing_id`, MAC (constant time), X-Wing key validity.
pub(crate) fn check_hello(keys: &PairingKeys, bytes: &[u8]) -> Result<CheckedHello, Refused> {
    let hello = PairHello::decode(bytes).map_err(|_| Refused::Shape)?;
    LanProfile::from_id(hello.profile).map_err(|_| Refused::Profile)?;
    if !keys.matches_pairing_id(&hello.pairing_id) {
        return Err(Refused::PairingId);
    }
    let body = body_without_last(bytes).map_err(|_| Refused::Shape)?;
    keys.verify_hello(&body, &MacTag::from_bytes(hello.mac))
        .map_err(|_| Refused::Mac)?;
    let ek = XWingEncapsKey::from_bytes(hello.ek).map_err(|_| Refused::Key)?;
    Ok(CheckedHello {
        mode: hello.mode,
        commit: hello.commit,
        ek,
        hash: transcript_hash(bytes),
    })
}

/// `PairAccept` and its hash (0013 §4.4).
pub(crate) fn accept_for(
    keys: &PairingKeys,
    hello_hash: &[u8; 32],
    nonce_a: &[u8; 32],
    ct: &XWingCiphertext,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), LanError> {
    let transcript = PairAccept::transcript(hello_hash, nonce_a, ct.as_bytes())
        .map_err(|_| LanError::Protocol)?;
    let mac = keys
        .accept_mac(&transcript)
        .map_err(|_| LanError::Protocol)?;
    let accept = PairAccept::encode(nonce_a, ct.as_bytes(), mac.as_bytes())
        .map_err(|_| LanError::Protocol)?;
    let hash = transcript_hash(&accept);
    Ok((accept, hash))
}

/// The joiner's check of an accept: shape, then the MAC in constant time.
/// Returns the ciphertext and the accept's hash.
pub(crate) fn check_accept(
    keys: &PairingKeys,
    hello_hash: &[u8; 32],
    bytes: &[u8],
) -> Result<(XWingCiphertext, [u8; 32]), LanError> {
    let accept = PairAccept::decode(bytes).map_err(|_| LanError::NoPeer)?;
    let transcript = PairAccept::transcript(hello_hash, &accept.nonce_a, accept.ct)
        .map_err(|_| LanError::NoPeer)?;
    keys.verify_accept(&transcript, &MacTag::from_bytes(accept.mac))
        .map_err(|_| LanError::NoPeer)?;
    let ct = XWingCiphertext::from_bytes(accept.ct).map_err(|_| LanError::NoPeer)?;
    Ok((ct, transcript_hash(bytes)))
}

/// `th = H(["qv/lan-pair-th/v1", H(hello), H(accept)])`.
pub(crate) fn th(hello_hash: &[u8; 32], accept_hash: &[u8; 32]) -> Result<[u8; 32], LanError> {
    Ok(transcript_hash(
        &pair_th_input(hello_hash, accept_hash).map_err(|_| LanError::Protocol)?,
    ))
}

/// The pairing record keys: `(k_b2a, k_a2b)`.
pub(crate) fn record_keys(
    keys: &PairingKeys,
    ss: &XWingSharedSecret,
    th: &[u8; 32],
) -> Result<(RecordKey, RecordKey), LanError> {
    keys.record_keys(ss, th).map_err(|_| LanError::Protocol)
}
