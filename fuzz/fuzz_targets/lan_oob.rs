// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile out-of-band pairing codes (spec 0013 §4.2; plan 0037): the QR
//! payload from a camera and the typed manual code. The first byte selects
//! the decoder. Errors are expected; any panic is a finding, and a decoded
//! code must round-trip.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qv_protocol::oob::{decode_manual, decode_qr, encode_manual, encode_qr};
use qv_protocol::registry::LanProfile;

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    if which & 1 == 0 {
        if let Ok(qr) = decode_qr(rest)
            && qr.profile == 1
        {
            let again = encode_qr(LanProfile::V1, qr.secret, &qr.endpoints, qr.instance)
                .expect("a decoded payload re-encodes");
            assert_eq!(&again[..], rest);
        }
    } else if let Ok(text) = core::str::from_utf8(rest)
        && let Ok(secret) = decode_manual(text)
    {
        assert_eq!(
            *decode_manual(&encode_manual(&secret)).expect("round trip"),
            *secret
        );
    }
});
