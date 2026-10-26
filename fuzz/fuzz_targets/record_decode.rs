// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile bytes into the record decoder (spec 0003 §2.2, 0004 §3.1, §4.1).
//!
//! Records are authenticated before they are parsed, but any holder of the
//! vault key can author them, so the decoder must reject every malformed or
//! oversized input without panicking. Every accepted input must re-encode to
//! exactly the same bytes: one canonical encoding per value, with unknown
//! keys preserved. Any panic or mismatch is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qv_model::RecordVersion;

fuzz_target!(|data: &[u8]| {
    if let Ok(version) = RecordVersion::decode(data) {
        let again = version.encode().expect("an accepted record re-encodes");
        assert_eq!(again.as_slice(), data);
    }
});
