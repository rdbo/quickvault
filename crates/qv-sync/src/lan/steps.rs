// SPDX-License-Identifier: AGPL-3.0-or-later

//! Historical profile1 vector computations, compiled only for tests: the
//! approver's ordered hello checks, the joiner's accept check and the
//! transcript. No I/O and no randomness: fixtures provide the nonces and
//! X-Wing keys, and the interoperability vectors replay fixed ones.

use qv_crypto::lan::{PairNonce, PairingKeys, RecordKey, transcript_hash};
use qv_crypto::{XWingCiphertext, XWingDecapsKey, XWingEncapsKey, XWingSharedSecret};
use qv_protocol::lan::{JoinMode, PairAccept, PairHello, pair_th_input};
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
