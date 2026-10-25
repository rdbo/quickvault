// SPDX-License-Identifier: AGPL-3.0-or-later

//! Known-answer tests against the files in `tests/vectors/`.
//!
//! Format: records separated by blank lines; each line is `name = hex`
//! (possibly empty); `#` starts a comment line. Upstream files carry a
//! `# source:` line; QuickVault's own files are marked development-only.

use crate::primitives::{
    hkdf_sha512_into, hmac_sha512_full, mac1, xchacha_open_in_place, xchacha_seal_in_place,
};
use crate::{ObjectHashProfile, object_hash};

/// One record: `(name, bytes)` pairs in file order.
pub(crate) struct Record(Vec<(String, Vec<u8>)>);

impl Record {
    pub(crate) fn get(&self, name: &str) -> &[u8] {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
            .unwrap_or_else(|| panic!("missing field {name}"))
    }

    pub(crate) fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        self.get(name)
            .try_into()
            .unwrap_or_else(|_| panic!("field {name} is not {N} bytes"))
    }
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub(crate) fn parse(text: &str) -> Vec<Record> {
    let mut records = Vec::new();
    let mut current = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !current.is_empty() {
                records.push(Record(std::mem::take(&mut current)));
            }
            continue;
        }
        let (name, value) = line.split_once('=').expect("name = hex");
        current.push((name.trim().to_owned(), hex(value.trim())));
    }
    if !current.is_empty() {
        records.push(Record(current));
    }
    records
}

macro_rules! vectors {
    ($file:literal) => {
        parse(include_str!(concat!("../tests/vectors/", $file)))
    };
}

#[test]
fn kat_parser_handles_empty_values_and_comments() {
    let r = parse("# c\na = 00ff\nb =\n\n# d\n\nc = 01\n");
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].get("a"), [0x00, 0xff]);
    assert_eq!(r[0].get("b"), [0u8; 0]);
    assert_eq!(r[1].get("c"), [1]);
}

#[test]
fn kat_rfc4231_hmac_sha512() {
    let records = vectors!("rfc4231-hmac-sha512.txt");
    assert_eq!(records.len(), 6);
    for r in &records {
        let full = hmac_sha512_full(r.get("key"), r.get("data"));
        assert_eq!(full, r.get("mac"));
        // MAC/1 is the first 32 bytes; it takes 32-byte keys only.
        if let Ok(key) = <[u8; 32]>::try_from(r.get("key")) {
            assert_eq!(mac1(&key, r.get("data")).unwrap().as_bytes(), &full[..32]);
        }
    }
}

#[test]
fn kat_mac1_truncates_rfc4231_style_outputs() {
    // RFC 4231 has no 32-byte key; check truncation for 32-byte keys
    // against the untruncated HMAC-SHA-512 of the same input.
    for key in [[0u8; 32], [0xaa; 32], core::array::from_fn(|i| i as u8)] {
        let full = hmac_sha512_full(&key, b"QuickVault MAC/1");
        assert_eq!(
            mac1(&key, b"QuickVault MAC/1").unwrap().as_bytes(),
            &full[..32]
        );
    }
}

#[test]
fn kat_wycheproof_hkdf_sha512() {
    let records = vectors!("wycheproof-hkdf-sha512.txt");
    assert!(records.len() >= 6);
    let mut saw_empty_salt = false;
    let mut saw_empty_info = false;
    for r in &records {
        let salt = r.get("salt");
        saw_empty_salt |= salt.is_empty();
        saw_empty_info |= r.get("info").is_empty();
        let expected = r.get("okm");
        let mut out = vec![0u8; expected.len()];
        hkdf_sha512_into(r.get("ikm"), Some(salt), r.get("info"), &mut out).unwrap();
        assert_eq!(out, expected);
    }
    assert!(saw_empty_salt && saw_empty_info);
}

#[test]
fn kat_sha256() {
    let records = vectors!("sha256.txt");
    assert_eq!(records.len(), 3);
    for r in &records {
        assert_eq!(
            object_hash(ObjectHashProfile::V1, r.get("message")).0,
            r.get("digest")
        );
    }
}

#[test]
fn kat_xchacha20poly1305_draft_a_3_1() {
    let records = vectors!("xchacha20poly1305.txt");
    let r = &records[0];
    let key: [u8; 32] = r.array("key");
    let nonce: [u8; 24] = r.array("nonce");
    let aad = r.get("aad");
    let mut buf = r.get("plaintext").to_vec();
    let tag = xchacha_seal_in_place(&key, &nonce, aad, &mut buf).unwrap();
    assert_eq!(buf, r.get("ciphertext"));
    assert_eq!(tag, r.get("tag"));

    let ct = r.get("ciphertext");
    let good_tag: [u8; 16] = r.array("tag");
    let mut ok = ct.to_vec();
    xchacha_open_in_place(&key, &nonce, aad, &mut ok, &good_tag).unwrap();
    assert_eq!(ok, r.get("plaintext"));

    // A flipped bit anywhere fails.
    let mut bad_tag = good_tag;
    bad_tag[15] ^= 1;
    assert!(xchacha_open_in_place(&key, &nonce, aad, &mut ct.to_vec(), &bad_tag).is_err());
    let mut bad_ct = ct.to_vec();
    bad_ct[0] ^= 0x80;
    assert!(xchacha_open_in_place(&key, &nonce, aad, &mut bad_ct, &good_tag).is_err());
    let mut bad_aad = aad.to_vec();
    bad_aad[3] ^= 1;
    assert!(xchacha_open_in_place(&key, &nonce, &bad_aad, &mut ct.to_vec(), &good_tag).is_err());
    let mut bad_nonce = nonce;
    bad_nonce[23] ^= 1;
    assert!(xchacha_open_in_place(&key, &bad_nonce, aad, &mut ct.to_vec(), &good_tag).is_err());
}

// --- QuickVault development vectors (unstable until roadmap phase 1.16) ---

mod dev {
    use super::{Record, parse};
    use crate::ids::{AttachmentId, KeyGeneration, RecordId, SlotId, VaultId};
    use crate::keys::test_key::TestKey;
    use crate::keys::{KeyPurpose, VaultKey, data_key_info, mac, purpose, purpose_info};
    use crate::password::{
        MasterKey, commit_message, derive_kek, kek_commit, kek_info, wrap_info, wrap_key,
    };
    use crate::profile::{DerivationProfile, MacProfile, PasswordKdfProfile, StoredDataProfile};
    use crate::slot::slot_aad;
    use crate::stored_data::{open, padme, seal_with_nonce};

    fn u64_be(b: &[u8]) -> u64 {
        u64::from_be_bytes(b.try_into().unwrap())
    }

    fn purpose_key<P: KeyPurpose>(vk: &VaultKey, vault: VaultId, g: KeyGeneration) -> [u8; 32] {
        vk.purpose_key::<P>(vault, g, DerivationProfile::V1)
            .unwrap()
            .bytes()
    }

    /// Every value in qv-dev-keys.txt (computed by crosscheck.py with the
    /// Python standard library) is reproduced by the Rust code.
    #[test]
    fn kat_dev_keys_match_the_independent_python_values() {
        let _guard = crate::memory::secrets_test_guard();
        let records = vectors!("qv-dev-keys.txt");
        let r: &Record = &records[0];
        let vk = VaultKey::from_bytes(r.array("vk"));
        let mk = MasterKey::from_bytes(r.array("mk"));
        let vault = VaultId(r.array("vault_id"));
        let slot = SlotId(r.array("slot_id"));
        let g = KeyGeneration(u32::from_be_bytes(r.array("generation")));
        let salt: [u8; 32] = r.array("kdf_salt");

        assert_eq!(kek_info(1).unwrap().as_slice(), r.get("kek_info"));
        let kek = derive_kek(&mk, vault, PasswordKdfProfile::V1).unwrap();
        assert_eq!(kek.bytes(), r.get("kek"));
        assert_eq!(
            commit_message(vault, g, slot).unwrap().as_slice(),
            r.get("kek_commit_msg")
        );
        assert_eq!(
            kek_commit(&kek, vault, g, slot).unwrap().as_bytes(),
            r.get("kek_commit")
        );
        assert_eq!(wrap_info().unwrap().as_slice(), r.get("wrap_info"));
        assert_eq!(wrap_key(&kek).unwrap().expose_secret(), r.get("wrap_key"));
        assert_eq!(
            slot_aad(vault, g, slot, 1, &salt, 1).unwrap().as_slice(),
            r.get("slot_aad")
        );

        macro_rules! check_purpose {
            ($($p:ident => $field:literal),+) => {$(
                assert_eq!(
                    purpose_info(purpose::$p::LABEL, g, 1).unwrap().as_slice(),
                    r.get(concat!("purpose_info_", $field)),
                );
                assert_eq!(
                    purpose_key::<purpose::$p>(&vk, vault, g),
                    r.get(concat!("purpose_", $field)),
                );
            )+};
        }
        check_purpose!(
            Record => "record",
            Attachment => "attachment",
            HeaderMac => "header_mac",
            Manifest => "manifest",
            StateCommit => "state_commit",
            LocalState => "local_state",
            DeviceStorage => "device_storage",
            RecoveryEd25519 => "recovery_ed25519",
            RecoveryMlDsa65 => "recovery_mldsa65"
        );

        let record = RecordId(r.array("record_id"));
        let attachment = AttachmentId(r.array("attachment_id"));
        assert_eq!(
            data_key_info("qv/record-key/v1", &record.0)
                .unwrap()
                .as_slice(),
            r.get("record_key_info")
        );
        assert_eq!(
            data_key_info("qv/attachment-key/v1", &attachment.0)
                .unwrap()
                .as_slice(),
            r.get("attachment_key_info")
        );
        let records_key = vk
            .purpose_key::<purpose::Record>(vault, g, DerivationProfile::V1)
            .unwrap();
        let attachments_key = vk
            .purpose_key::<purpose::Attachment>(vault, g, DerivationProfile::V1)
            .unwrap();
        assert_eq!(
            records_key.record_key(vault, record).unwrap().bytes(),
            r.get("record_key")
        );
        assert_eq!(
            attachments_key
                .attachment_key(vault, attachment)
                .unwrap()
                .bytes(),
            r.get("attachment_key")
        );
        let header = vk
            .purpose_key::<purpose::HeaderMac>(vault, g, DerivationProfile::V1)
            .unwrap();
        assert_eq!(
            mac(&header, MacProfile::V1, r.get("mac_msg"))
                .unwrap()
                .as_bytes(),
            r.get("mac_header")
        );
    }

    #[test]
    fn kat_dev_padme() {
        let records = vectors!("qv-dev-padme.txt");
        assert!(records.len() >= 10);
        for r in &records {
            let n = usize::try_from(u64_be(r.get("n"))).unwrap();
            let p = usize::try_from(u64_be(r.get("padded"))).unwrap();
            assert_eq!(padme(n), Some(p), "padme({n})");
        }
    }

    /// Regression pin for stored-data/1 (Rust-generated; the XChaCha
    /// primitive itself is covered by the upstream draft vector).
    #[test]
    fn kat_dev_stored_data() {
        let _guard = crate::memory::secrets_test_guard();
        let records = vectors!("qv-dev-stored-data.txt");
        assert_eq!(records.len(), 4);
        for r in &records {
            let key = TestKey(r.array("key"));
            let nonce: [u8; 24] = r.array("nonce");
            let s = seal_with_nonce(&key, nonce, r.get("aad"), r.get("plaintext"));
            assert_eq!(s.ciphertext, r.get("ciphertext"));
            let pt = open(
                &key,
                StoredDataProfile::V1,
                r.get("aad"),
                &nonce,
                r.get("ciphertext"),
                1 << 20,
            )
            .unwrap();
            assert_eq!(pt.expose_secret(), r.get("plaintext"));
        }
    }

    /// Prints qv-dev-stored-data.txt. Run with
    /// `cargo test -p qv-crypto --lib -- --ignored --nocapture kat_generate_dev_stored_data`.
    #[test]
    #[ignore = "generator, not a test"]
    fn kat_generate_dev_stored_data() {
        let _guard = crate::memory::secrets_test_guard();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8);
        let aad = b"[\"qv/record/v1\", development]";
        let mut out = String::from(
            "# status: development-only; regenerated freely until roadmap phase 1.16\n\
             # stored-data/1 (XChaCha20-Poly1305, Padme framing u32_be(L) || pt || zeros),\n\
             # generated by the ignored test kat_generate_dev_stored_data (a regression pin).\n",
        );
        for len in [0usize, 1, 60, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let s = seal_with_nonce(&TestKey(key), nonce, aad, &pt);
            out += &format!(
                "\nkey = {}\nnonce = {}\naad = {}\nplaintext = {}\nciphertext = {}\n",
                hex(&key),
                hex(&nonce),
                hex(aad),
                hex(&pt),
                hex(&s.ciphertext)
            );
        }
        print!("{out}");
    }
}
