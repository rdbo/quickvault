// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure session-handshake computations (0013 §5): the initiator's hello and
//! accept check, the responder's ordered hello checks and accept, the
//! transcript and the session keys. No I/O and no randomness: the drivers
//! draw the nonces and X-Wing keys, and the interoperability vectors replay
//! fixed ones.

use qv_crypto::lan::{LinkKey, RecordKey, SessionAuth, session_record_keys, transcript_hash};
use qv_crypto::{MacTag, XWingCiphertext, XWingDecapsKey, XWingEncapsKey, XWingSharedSecret};
use qv_protocol::lan::{SyncAccept, SyncHello, session_th_input};
use qv_protocol::message::body_without_last;
use qv_protocol::registry::LanProfile;
use zeroize::Zeroizing;

use super::LanError;
use super::steps::Refused;

/// One initiating attempt: the hello I sends and the secret behind it.
pub(crate) struct SyncAttempt {
    pub(crate) dk: XWingDecapsKey,
    pub(crate) hello: Zeroizing<Vec<u8>>,
    pub(crate) hello_hash: [u8; 32],
}

/// Builds `SyncHello` under `auth` from fixed inputs (0013 §5.1).
pub(crate) fn sync_attempt(
    auth: &SessionAuth,
    nonce_i: &[u8; 32],
    dk: XWingDecapsKey,
    ek: &XWingEncapsKey,
) -> Result<SyncAttempt, LanError> {
    let body =
        SyncHello::body(LanProfile::V1, nonce_i, ek.as_bytes()).map_err(|_| LanError::Protocol)?;
    let mac = auth.hello_mac(&body).map_err(|_| LanError::Protocol)?;
    let hello = SyncHello::encode(LanProfile::V1, nonce_i, ek.as_bytes(), mac.as_bytes())
        .map_err(|_| LanError::Protocol)?;
    let hello_hash = transcript_hash(&hello);
    Ok(SyncAttempt {
        dk,
        hello,
        hello_hash,
    })
}

/// A sync hello that passed every check.
pub(crate) struct CheckedSyncHello {
    /// The index of the link whose `K_i` verified the tag.
    pub(crate) link: usize,
    pub(crate) nonce_i: [u8; 32],
    pub(crate) ek: XWingEncapsKey,
    pub(crate) hash: [u8; 32],
}

/// The responder's checks, in order: exact shape, profile, the tag under
/// every link's `K_i` (each in constant time, all of them, §5.1), X-Wing key
/// validity. No KEM work happens before a tag verifies.
pub(crate) fn check_sync_hello(
    auths: &[SessionAuth],
    bytes: &[u8],
) -> Result<CheckedSyncHello, Refused> {
    let hello = SyncHello::decode(bytes).map_err(|_| Refused::Shape)?;
    LanProfile::from_id(hello.profile).map_err(|_| Refused::Profile)?;
    let body = body_without_last(bytes).map_err(|_| Refused::Shape)?;
    let tag = MacTag::from_bytes(hello.mac);
    let mut matched = None;
    for (i, auth) in auths.iter().enumerate() {
        if auth.verify_hello(&body, &tag).is_ok() && matched.is_none() {
            matched = Some(i);
        }
    }
    let link = matched.ok_or(Refused::Mac)?;
    let ek = XWingEncapsKey::from_bytes(hello.ek).map_err(|_| Refused::Key)?;
    Ok(CheckedSyncHello {
        link,
        nonce_i: hello.nonce_i,
        ek,
        hash: transcript_hash(bytes),
    })
}

/// `SyncAccept` and its hash (0013 §5.2).
pub(crate) fn sync_accept_for(
    auth: &SessionAuth,
    hello_hash: &[u8; 32],
    nonce_r: &[u8; 32],
    ct: &XWingCiphertext,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), LanError> {
    let transcript = SyncAccept::transcript(hello_hash, nonce_r, ct.as_bytes())
        .map_err(|_| LanError::Protocol)?;
    let mac = auth
        .accept_mac(&transcript)
        .map_err(|_| LanError::Protocol)?;
    let accept = SyncAccept::encode(nonce_r, ct.as_bytes(), mac.as_bytes())
        .map_err(|_| LanError::Protocol)?;
    let hash = transcript_hash(&accept);
    Ok((accept, hash))
}

/// The initiator's check of an accept: shape, then the `K_r` tag in
/// constant time. Returns the ciphertext and the accept's hash.
pub(crate) fn check_sync_accept(
    auth: &SessionAuth,
    hello_hash: &[u8; 32],
    bytes: &[u8],
) -> Result<(XWingCiphertext, [u8; 32]), LanError> {
    let accept = SyncAccept::decode(bytes).map_err(|_| LanError::NoPeer)?;
    let transcript = SyncAccept::transcript(hello_hash, &accept.nonce_r, accept.ct)
        .map_err(|_| LanError::NoPeer)?;
    auth.verify_accept(&transcript, &MacTag::from_bytes(accept.mac))
        .map_err(|_| LanError::NoPeer)?;
    let ct = XWingCiphertext::from_bytes(accept.ct).map_err(|_| LanError::NoPeer)?;
    Ok((ct, transcript_hash(bytes)))
}

/// `th = H(["qv/lan-th/v1", H(hello), H(accept)])`.
pub(crate) fn session_th(
    hello_hash: &[u8; 32],
    accept_hash: &[u8; 32],
) -> Result<[u8; 32], LanError> {
    Ok(transcript_hash(
        &session_th_input(hello_hash, accept_hash).map_err(|_| LanError::Protocol)?,
    ))
}

/// The session record keys: `(k_i2r, k_r2i)`.
pub(crate) fn session_keys(
    ss: &XWingSharedSecret,
    link: &LinkKey,
    th: &[u8; 32],
) -> Result<(RecordKey, RecordKey), LanError> {
    session_record_keys(ss, link, th).map_err(|_| LanError::Protocol)
}
