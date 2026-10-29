// SPDX-License-Identifier: AGPL-3.0-or-later

//! Untrusted snapshot inventories, canonical round trips and the MAC.
#![no_main]
use libfuzzer_sys::fuzz_target;
use qv_crypto::{KeyGeneration, VaultId, VaultKey};
use qv_store::SnapshotInventory;
use std::sync::OnceLock;

fn vault() -> VaultId {
    let mut id = [0x22; 16];
    id[6] = (id[6] & 15) | 64;
    id[8] = (id[8] & 63) | 128;
    VaultId(id)
}

/// The independent development vector (public all-one BIP-39 key).
fn fixture() -> &'static (VaultKey, Vec<u8>) {
    static FIXTURE: OnceLock<(VaultKey, Vec<u8>)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let key = VaultKey::from_recovery_phrase(format!("{}vote", "zoo ".repeat(23)).as_bytes())
            .expect("public all-one BIP-39 vector");
        let bytes = include_bytes!("../../crates/qv-store/tests/vectors/snapshot-inventory.cbor");
        // The seed must verify, or mutations would never reach the MAC.
        SnapshotInventory::decode(bytes)
            .and_then(|i| i.verify(vault(), KeyGeneration(2), &key))
            .expect("valid vector");
        (key, bytes.to_vec())
    })
}

fn check(data: &[u8]) -> bool {
    let (key, _) = fixture();
    let Ok(unverified) = SnapshotInventory::decode(data) else {
        return false;
    };
    match unverified.verify(vault(), KeyGeneration(2), key) {
        Ok(inventory) => {
            assert_eq!(
                inventory.encode().expect("accepted inventory encodes"),
                data
            );
            true
        }
        Err(_) => false,
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    // Mutating the valid seed reaches rows and the MAC past the CBOR head.
    let (_, seed) = fixture();
    let mut mutated = seed.clone();
    for bytes in data.chunks_exact(3) {
        let offset = usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) % mutated.len();
        mutated[offset] ^= bytes[2];
    }
    assert_eq!(check(&mutated), mutated == *seed);
});
