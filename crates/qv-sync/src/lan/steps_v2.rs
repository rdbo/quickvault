// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure lan/2 outer handshake. MAC validation precedes all KEM work.
use qv_crypto::lan::v2::{self as crypto, PairingKeys};
use qv_crypto::lan::{PairNonce, transcript_hash};
use qv_crypto::{MacTag, XWingCiphertext, XWingDecapsKey, XWingEncapsKey};
use qv_protocol::lan::v2::{self as wire, AuthMode, PairAccept, PairHello};
use zeroize::Zeroizing;

use super::LanError;
#[derive(Debug)]
pub(crate) enum Refused {
    Shape,
    PairingId,
    Mac,
    Key,
}

pub(crate) fn crypto_mode(mode: AuthMode) -> crypto::AuthMode {
    match mode {
        AuthMode::PasswordEnrollment => crypto::AuthMode::PasswordEnrollment,
        AuthMode::KeyEnrollment => crypto::AuthMode::KeyEnrollment,
        AuthMode::KeySync => crypto::AuthMode::KeySync,
    }
}
pub(crate) struct JoinAttempt {
    pub(crate) nonce: PairNonce,
    pub(crate) dk: XWingDecapsKey,
    pub(crate) hello: Zeroizing<Vec<u8>>,
    pub(crate) hash: [u8; 32],
}
pub(crate) fn join_attempt(
    keys: &PairingKeys,
    mode: AuthMode,
    nonce: PairNonce,
    dk: XWingDecapsKey,
    ek: &XWingEncapsKey,
) -> Result<JoinAttempt, LanError> {
    let mut msg = PairHello {
        profile: 2,
        pairing_id: *keys.pairing_id(),
        mode,
        commit: crypto::nonce_commitment(&nonce).map_err(|_| LanError::Protocol)?,
        ek: ek.as_bytes(),
        mac: [0; 32],
    };
    msg.mac = *keys
        .hello_mac(&msg.body().map_err(|_| LanError::Protocol)?)
        .map_err(|_| LanError::Protocol)?
        .as_bytes();
    let hello = msg.encode().map_err(|_| LanError::Protocol)?;
    let hash = transcript_hash(&hello);
    Ok(JoinAttempt {
        nonce,
        dk,
        hello,
        hash,
    })
}
pub(crate) struct CheckedHello {
    pub(crate) mode: AuthMode,
    pub(crate) commit: [u8; 32],
    pub(crate) ek: XWingEncapsKey,
    pub(crate) hash: [u8; 32],
}
pub(crate) fn check_hello(keys: &PairingKeys, bytes: &[u8]) -> Result<CheckedHello, Refused> {
    let msg = PairHello::decode(bytes).map_err(|_| Refused::Shape)?;
    if !keys.matches_pairing_id(&msg.pairing_id) {
        return Err(Refused::PairingId);
    }
    keys.verify_hello(
        &msg.body().map_err(|_| Refused::Shape)?,
        &MacTag::from_bytes(msg.mac),
    )
    .map_err(|_| Refused::Mac)?;
    let ek = XWingEncapsKey::from_bytes(msg.ek).map_err(|_| Refused::Key)?;
    Ok(CheckedHello {
        mode: msg.mode,
        commit: msg.commit,
        ek,
        hash: transcript_hash(bytes),
    })
}
pub(crate) fn accept_for(
    keys: &PairingKeys,
    hello: &CheckedHello,
    nonce: [u8; 32],
    ct: &XWingCiphertext,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), LanError> {
    let mut msg = PairAccept {
        profile: 2,
        mode: hello.mode,
        nonce,
        ct: ct.as_bytes(),
        mac: [0; 32],
    };
    msg.mac = *keys
        .accept_mac(&msg.mac_input(&hello.hash).map_err(|_| LanError::Protocol)?)
        .map_err(|_| LanError::Protocol)?
        .as_bytes();
    let encoded = msg.encode().map_err(|_| LanError::Protocol)?;
    let hash = transcript_hash(&encoded);
    Ok((encoded, hash))
}
pub(crate) fn check_accept(
    keys: &PairingKeys,
    mode: AuthMode,
    hello: &[u8; 32],
    bytes: &[u8],
) -> Result<(XWingCiphertext, [u8; 32]), LanError> {
    let msg = PairAccept::decode(bytes).map_err(|_| LanError::NoPeer)?;
    if msg.mode != mode {
        return Err(LanError::NoPeer);
    }
    keys.verify_accept(
        &msg.mac_input(hello).map_err(|_| LanError::NoPeer)?,
        &MacTag::from_bytes(msg.mac),
    )
    .map_err(|_| LanError::NoPeer)?;
    Ok((
        XWingCiphertext::from_bytes(msg.ct).map_err(|_| LanError::NoPeer)?,
        transcript_hash(bytes),
    ))
}
pub(crate) fn outer_transcript(
    mode: AuthMode,
    hello: &[u8; 32],
    accept: &[u8; 32],
) -> Result<[u8; 32], LanError> {
    Ok(transcript_hash(
        &wire::outer_transcript(mode, hello, accept).map_err(|_| LanError::Protocol)?,
    ))
}
pub(crate) fn auth_transcript(
    mode: AuthMode,
    t0: &[u8; 32],
    first: &[u8],
    second: &[u8],
    third: Option<&[u8]>,
) -> Result<[u8; 32], LanError> {
    Ok(transcript_hash(
        &wire::auth_transcript(mode, t0, first, second, third).map_err(|_| LanError::Protocol)?,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use qv_crypto::lan::PairingSecret;
    use std::collections::BTreeMap;
    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn driver_steps_match_independent_v2_wire_vectors_and_reject_legacy_admission() {
        let mut rows = Vec::new();
        let mut row = BTreeMap::new();
        for line in include_str!("../../../qv-crypto/tests/vectors/qv-dev-lan-v2-wire.txt").lines()
        {
            if line.starts_with('#') {
                continue;
            }
            if line.is_empty() {
                if !row.is_empty() {
                    rows.push(std::mem::take(&mut row));
                }
                continue;
            }
            let (name, value) = line.split_once(" = ").unwrap();
            row.insert(name, unhex(value));
        }
        if !row.is_empty() {
            rows.push(row);
        }
        assert_eq!(rows.len(), 3);
        let seed = include_str!("../../../qv-crypto/tests/vectors/xwing-draft-11.txt")
            .lines()
            .find_map(|line| line.strip_prefix("seed = "))
            .map(unhex)
            .unwrap();
        let seed: [u8; 32] = seed.try_into().unwrap();
        for row in rows {
            let mode =
                AuthMode::from_codes(row["method"][0].into(), row["intent"][0].into()).unwrap();
            let keys =
                PairingKeys::new(PairingSecret::from_bytes(&row["pairing"]).unwrap()).unwrap();
            let (dk, ek) = XWingDecapsKey::from_test_seed(&seed).unwrap();
            let nonce =
                PairNonce::from_bytes(&core::array::from_fn::<_, 32, _>(|i| (16 + i) as u8))
                    .unwrap();
            let attempt = join_attempt(&keys, mode, nonce, dk, &ek).unwrap();
            assert_eq!(attempt.hello.as_slice(), row["hello"]);
            assert_eq!(attempt.hash.as_slice(), row["hello_hash"]);
            let checked = check_hello(&keys, &attempt.hello).unwrap();
            assert_eq!(checked.mode, mode);
            let accept = PairAccept::decode(&row["accept"]).unwrap();
            let ct = XWingCiphertext::from_bytes(accept.ct).unwrap();
            let (encoded, hash) = accept_for(
                &keys,
                &checked,
                core::array::from_fn(|i| (48 + i) as u8),
                &ct,
            )
            .unwrap();
            assert_eq!(encoded.as_slice(), row["accept"]);
            let (decoded_ct, decoded_hash) =
                check_accept(&keys, mode, &attempt.hash, &encoded).unwrap();
            assert_eq!(decoded_hash, hash);
            assert_eq!(decoded_ct.as_bytes(), ct.as_bytes());
            let t0 = outer_transcript(mode, &attempt.hash, &hash).unwrap();
            assert_eq!(t0.as_slice(), row["t0"]);
            let last = row.get("f").map(Vec::as_slice);
            let ta = auth_transcript(mode, &t0, &row["r"], &row["s"], last).unwrap();
            assert_eq!(ta.as_slice(), row["ta"]);
            let legacy_keys = PairingSecret::from_bytes(&row["pairing"])
                .unwrap()
                .keys()
                .unwrap();
            let (dk, ek) = XWingDecapsKey::from_test_seed(&seed).unwrap();
            let legacy = super::super::steps::join_attempt(
                &legacy_keys,
                qv_protocol::lan::JoinMode::Sync,
                PairNonce::from_bytes(&[16; 32]).unwrap(),
                dk,
                &ek,
            )
            .unwrap();
            assert!(check_hello(&keys, &legacy.hello).is_err());
            let other = if mode == AuthMode::KeySync {
                AuthMode::KeyEnrollment
            } else {
                AuthMode::KeySync
            };
            assert!(check_accept(&keys, other, &attempt.hash, &encoded).is_err());
        }
    }
}
