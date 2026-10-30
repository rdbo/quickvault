// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded plaintext receipt schema, independent of envelope authentication.
#![no_main]
use libfuzzer_sys::fuzz_target;
use qv_store::ArchiveReceipts;

fn check(data: &[u8]) {
    if let Ok(rows) = ArchiveReceipts::decode(data) {
        assert_eq!(
            rows.encode()
                .expect("accepted receipts encode")
                .expose_secret(),
            data
        );
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    // Independent canonical [1, [[b"/a", bstr32(7)]]] seed reaches row checks.
    let mut seed = vec![0x82, 1, 0x81, 0x82, 0x42, b'/', b'a', 0x58, 0x20];
    seed.extend_from_slice(&[7; 32]);
    check(&seed);
    for bytes in data.chunks_exact(2) {
        let offset = usize::from(bytes[0]) % seed.len();
        seed[offset] ^= bytes[1];
    }
    check(&seed);
});
