// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent canonical wire fixtures and bounded hostile-input checks.
#![allow(clippy::unwrap_used)] // All expected bytes are fixed synthetic fixtures.
use super::*;
use std::collections::BTreeMap;

fn records() -> Vec<BTreeMap<&'static str, Vec<u8>>> {
    let mut records = Vec::new();
    let mut record = BTreeMap::new();
    for line in include_str!("../../qv-crypto/tests/vectors/qv-dev-lan-v2-wire.txt").lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !record.is_empty() {
                records.push(std::mem::take(&mut record));
            }
            continue;
        }
        let (name, value) = line.split_once(" = ").unwrap();
        let bytes = (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect();
        record.insert(name, bytes);
    }
    if !record.is_empty() {
        records.push(record);
    }
    records
}
fn fixed<const N: usize>(r: &BTreeMap<&str, Vec<u8>>, name: &str) -> [u8; N] {
    r[name].as_slice().try_into().unwrap()
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn v2_wire_messages_and_complete_transcripts_match_independent_canonical_vectors() {
    let records = records();
    assert_eq!(records.len(), 3);
    for r in records {
        let mode = AuthMode::from_codes(r["method"][0].into(), r["intent"][0].into()).unwrap();
        let hello = PairHello::decode(&r["hello"]).unwrap();
        assert_eq!(hello.mode, mode);
        assert_eq!(hello.encode().unwrap().as_slice(), r["hello"]);
        assert_eq!(hello.body().unwrap().as_slice(), r["hello_body"]);
        let accept = PairAccept::decode(&r["accept"]).unwrap();
        assert_eq!(accept.mode, mode);
        assert_eq!(accept.encode().unwrap().as_slice(), r["accept"]);
        assert_eq!(accept.body().unwrap().as_slice(), r["accept_body"]);
        assert_eq!(
            accept
                .mac_input(&fixed(&r, "hello_hash"))
                .unwrap()
                .as_slice(),
            r["accept_input"]
        );
        assert_eq!(
            outer_transcript(mode, &fixed(&r, "hello_hash"), &fixed(&r, "accept_hash"))
                .unwrap()
                .as_slice(),
            r["outer_input"]
        );
        let f = r.get("f").map(Vec::as_slice);
        assert_eq!(
            auth_transcript(mode, &fixed(&r, "t0"), &r["r"], &r["s"], f)
                .unwrap()
                .as_slice(),
            r["auth_input"]
        );
        if mode == AuthMode::PasswordEnrollment {
            assert_eq!(
                PakeStart::decode(&r["r"])
                    .unwrap()
                    .encode()
                    .unwrap()
                    .as_slice(),
                r["r"]
            );
            assert_eq!(
                PakeResponse::decode(&r["s"])
                    .unwrap()
                    .encode()
                    .unwrap()
                    .as_slice(),
                r["s"]
            );
            assert_eq!(
                PakeFinish::decode(&r["f"])
                    .unwrap()
                    .encode()
                    .unwrap()
                    .as_slice(),
                r["f"]
            );
            assert_eq!(
                Finished::decode(&r["finished"])
                    .unwrap()
                    .encode()
                    .unwrap()
                    .as_slice(),
                r["finished"]
            );
            let g = PairGrant::decode(&r["grant"]).unwrap();
            let encoded = PairGrant::encode_with_key(
                &g.vault_id,
                g.generation,
                g.descriptor,
                &g.control_record,
                &g.head_version,
                &g.head_object,
                &g.head_hash,
                |a| {
                    a.bytes(g.key);
                },
            )
            .unwrap();
            assert_eq!(encoded.as_slice(), r["grant"]);
            assert!(
                PairGrant::encode_with_key(
                    &g.vault_id,
                    g.generation,
                    g.descriptor,
                    &g.control_record,
                    &g.head_version,
                    &g.head_object,
                    &g.head_hash,
                    |a| {
                        a.text("wrong key type");
                    }
                )
                .is_err()
            );
        } else {
            assert_eq!(
                KeyProve::decode(&r["r"])
                    .unwrap()
                    .encode()
                    .unwrap()
                    .as_slice(),
                r["r"]
            );
            assert_eq!(
                KeyProved::decode(&r["s"])
                    .unwrap()
                    .encode()
                    .unwrap()
                    .as_slice(),
                r["s"]
            );
        }
        assert_eq!(
            ErrorMsg::encode(ErrorMsg::decode(&r["error"]).unwrap().code)
                .unwrap()
                .as_slice(),
            r["error"]
        );
        let qr = crate::oob::decode_qr_v2(&r["qr"]).unwrap();
        assert_eq!(qr.profile, 2);
        assert_eq!(qr.secret.as_slice(), r["pairing"]);
        let qr =
            crate::oob::encode_qr(LanProfile::V2, qr.secret, &qr.endpoints, qr.instance).unwrap();
        assert_eq!(qr.as_slice(), r["qr"]);
    }
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn v2_wire_refuses_legacy_modes_lengths_arity_trailing_and_credential_substitution() {
    assert!(AuthMode::from_codes(0, 1).is_err());
    assert!(AuthMode::from_codes(2, 0).is_err());
    let r = records().remove(0);
    let mut hello = PairHello::decode(&r["hello"]).unwrap();
    hello.profile = 1;
    assert!(hello.body().is_err());
    assert!(hello.encode().is_err());
    let old = crate::lan::PairHello::encode(
        LanProfile::V1,
        &hello.pairing_id,
        crate::lan::JoinMode::NewDevice,
        &hello.commit,
        hello.ek,
        &hello.mac,
    )
    .unwrap();
    assert!(PairHello::decode(&old).is_err());
    let old = crate::oob::encode_qr(LanProfile::V1, &[0; 16], &[], "").unwrap();
    assert!(crate::oob::decode_qr_v2(&old).is_err());
    let mut trailing = r["r"].clone();
    trailing.push(0);
    assert!(PakeStart::decode(&trailing).is_err());
    let short = write_message(Label::PakeResponse, CREDENTIAL_MAX, |a| {
        a.bytes(&[0; 319]);
        Ok(())
    })
    .unwrap();
    assert!(PakeResponse::decode(&short).is_err());
    let long = write_message(Label::PakeResponse, CREDENTIAL_MAX, |a| {
        a.bytes(&[0; 321]);
        Ok(())
    })
    .unwrap();
    assert!(PakeResponse::decode(&long).is_err());
    assert!(PakeResponse::decode(&r["f"]).is_err());
    assert!(
        auth_transcript(
            AuthMode::PasswordEnrollment,
            &fixed(&r, "t0"),
            &r["r"],
            &r["s"],
            None
        )
        .is_err()
    );
    assert!(
        auth_transcript(
            AuthMode::KeyEnrollment,
            &fixed(&r, "t0"),
            &r["r"],
            &r["s"],
            Some(&r["f"])
        )
        .is_err()
    );
    let wrong_arity = array(|a| {
        a.text(Label::PakeFinish.as_str());
        a.bytes(&[0; 64]);
        a.uint(0);
        Ok(())
    })
    .unwrap();
    assert!(PakeFinish::decode(&wrong_arity).is_err());
    let invalid_generation = write_message(Label::KeyProved, CREDENTIAL_MAX, |a| {
        a.bytes(&[0; 16]);
        a.uint(0);
        a.bytes(&[0; 32]);
        Ok(())
    })
    .unwrap();
    assert!(KeyProved::decode(&invalid_generation).is_err());
    let oversized = vec![0; CREDENTIAL_MAX + 1];
    assert_eq!(
        PakeResponse::decode(&oversized).err(),
        Some(ProtocolError::FrameTooLarge)
    );
    assert_eq!(
        PairGrant::decode(&oversized).err(),
        Some(ProtocolError::FrameTooLarge)
    );
    assert_eq!(
        auth_transcript(AuthMode::KeySync, &[0; 32], &oversized, &[], None).err(),
        Some(ProtocolError::FrameTooLarge)
    );
}

proptest::proptest! {
    // 0012 §1: Hostile SQLite/CBOR
    #[test]
    fn v2_hostile_credential_and_admission_decoders_never_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..5000)) {
        let _ = PairHello::decode(&bytes); let _ = PairAccept::decode(&bytes);
        let _ = PakeStart::decode(&bytes); let _ = PakeResponse::decode(&bytes);
        let _ = PakeFinish::decode(&bytes); let _ = Finished::decode(&bytes);
        let _ = KeyProve::decode(&bytes); let _ = KeyProved::decode(&bytes);
        let _ = PairGrant::decode(&bytes); let _ = ErrorMsg::decode(&bytes);
        let _ = crate::oob::decode_qr_v2(&bytes);
    }
}

// 0012 §1: Hostile SQLite/CBOR
#[test]
fn error_peek_does_not_apply_the_small_credential_bound_to_bulk_objects() {
    let object = super::super::ObjectMsg::encode(&vec![0; CREDENTIAL_MAX + 1]).unwrap();
    assert!(ErrorMsg::peek(&object).unwrap().is_none());
    let oversized = qv_encoding::encode_array(|a| {
        a.text(Label::ErrorV2.as_str());
        a.bytes(&vec![0; CREDENTIAL_MAX]);
        Ok(())
    })
    .unwrap();
    assert!(ErrorMsg::peek(&oversized).is_err());
}
