// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile bytes into the manifest decoder (spec 0004 §3.4, §4.1–4.2).
//!
//! Manifests are authenticated before they are parsed, but any holder of
//! the vault key can author one, so the decoder must reject every
//! malformed, inconsistent or over-budget input without panicking or
//! allocating from unchecked counts. Every accepted input must re-encode to
//! exactly the same bytes. Any panic or mismatch is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qv_store::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = Manifest::decode(data) {
        let again = manifest.encode().expect("an accepted manifest re-encodes");
        assert_eq!(again.as_slice(), data);
    }
});
