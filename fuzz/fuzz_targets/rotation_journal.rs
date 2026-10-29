// SPDX-License-Identifier: AGPL-3.0-or-later

//! Untrusted rotation journals, canonical round trips and independent MACs.
#![no_main]
use libfuzzer_sys::fuzz_target;
use qv_crypto::{KeyGeneration, VaultId, VaultKey};
use qv_store::{RotationJournal, RotationJournalBody, RotationSide};
use std::sync::OnceLock;

fn fixture() -> &'static (VaultKey, VaultKey, Vec<u8>) {
    static FIXTURE: OnceLock<(VaultKey, VaultKey, Vec<u8>)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let old =
            VaultKey::from_recovery_phrase(format!("{}art", "abandon ".repeat(23)).as_bytes())
                .expect("public all-zero BIP-39 vector");
        let new = VaultKey::from_recovery_phrase(format!("{}vote", "zoo ".repeat(23)).as_bytes())
            .expect("public all-one BIP-39 vector");
        let id = |b: u8| {
            let mut bytes = [b; 16];
            bytes[6] = (bytes[6] & 15) | 64;
            bytes[8] = (bytes[8] & 63) | 128;
            bytes
        };
        let journal = RotationJournal::sign(
            RotationJournalBody {
                operation_id: id(0x11),
                vault_id: VaultId(id(0x22)),
                replica_id: [0x33; 16],
                old_generation: KeyGeneration(1),
                new_generation: KeyGeneration(2),
                old_sequence: 7,
                new_sequence: 8,
                old_digest: [0x66; 32],
                new_digest: [0x77; 32],
                suffix: [0x44; 16],
                snapshot_id: [0x55; 16],
                inventory_digest: [0x88; 32],
            },
            &old,
            &new,
        )
        .expect("valid test intent");
        (old, new, journal.encode().expect("test intent encodes"))
    })
}
fn check(data: &[u8]) {
    if let Ok(journal) = RotationJournal::decode(data) {
        assert_eq!(journal.encode().expect("accepted journal encodes"), data);
        let (old, new, _) = fixture();
        let _ = journal.verify(old, RotationSide::Old);
        let _ = journal.verify(new, RotationSide::New);
    }
}
fuzz_target!(|data: &[u8]| {
    check(data);
    // Mutation of a known valid intent reaches authenticated fields and MACs
    // even when raw fuzz bytes would otherwise fail at the CBOR head.
    let (old, new, seed) = fixture();
    let mut mutated = seed.clone();
    for bytes in data.chunks_exact(3) {
        let offset = usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) % mutated.len();
        mutated[offset] ^= bytes[2];
    }
    check(&mutated);
    if let Ok(journal) = RotationJournal::decode(&mutated) {
        let both = journal.verify(old, RotationSide::Old).is_ok()
            && journal.verify(new, RotationSide::New).is_ok();
        assert_eq!(both, mutated == *seed);
    }
});
