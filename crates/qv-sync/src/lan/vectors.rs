// SPDX-License-Identifier: AGPL-3.0-or-later

//! Development interoperability vectors for LAN pairing and sessions (0013
//! Testing Requirements; plan 0037 step 8, plan 0038 step 7).
//!
//! One deterministic pairing and one deterministic session handshake run
//! through the same step functions the drivers use, with fixed inputs. X-Wing uses draft-11 vector 1's seeds
//! through the `test-vectors` feature. The test renders every message,
//! derivation and transcript and compares them with
//! `tests/vectors/qv-dev-lan-pairing.txt`; `QV_WRITE_VECTORS=1` rewrites the
//! file. `tests/vectors/crosscheck_lan.py` recomputes every value except the
//! AEAD records and X-Wing itself (draft KATs cover X-Wing).

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;

use qv_crypto::lan::{
    LinkRoot, PairNonce, PairingSecret, ProofRole, RecordOpener, RecordSealer, Sas, vectors,
};
use qv_crypto::{DerivationProfile, KeyGeneration, VaultId, VaultKey, XWingDecapsKey};
use qv_protocol::lan::{Confirm, ErrorMsg, JoinMode, PairAccept, PairReveal, SyncAccept};
use qv_protocol::message::body_without_last;
use qv_protocol::oob::{encode_addr_qr, parse_endpoint};
use qv_protocol::registry::{ErrorCode, LanProfile};

use super::exchange::grant_plaintext;
use super::session::{session_keys, session_th, sync_accept_for, sync_attempt};
use super::steps::{accept_for, join_attempt, record_keys, th};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/qv-dev-lan-pairing.txt"
);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The first X-Wing draft-11 vector's `seed` and `eseed`.
fn xwing_seeds() -> ([u8; 32], [u8; 64]) {
    let text = include_str!("../../../qv-crypto/tests/vectors/xwing-draft-11.txt");
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k} = ")))
            .map(unhex)
            .unwrap()
    };
    (
        get("seed").try_into().unwrap(),
        get("eseed").try_into().unwrap(),
    )
}

fn render() -> String {
    let p: [u8; 16] = core::array::from_fn(|i| i as u8);
    let vault = VaultId([0x55; 16]);
    let generation = KeyGeneration(1);
    let link_id = [0x33; 16];
    let (seed, eseed) = xwing_seeds();

    let keys = PairingSecret::from_bytes(&p).unwrap().keys().unwrap();
    let (k_hello, k_accept) = vectors::pairing_mac_keys(&keys);
    let (dk, ek) = XWingDecapsKey::from_test_seed(&seed).unwrap();
    let nonce_b = PairNonce::from_bytes(&[0x11; 32]).unwrap();
    let attempt = join_attempt(&keys, JoinMode::NewDevice, nonce_b, dk, &ek).unwrap();
    let (ss, ct) = ek.encapsulate_derand(&eseed).unwrap();
    // B recovers the same secret.
    assert_eq!(
        attempt.dk.decapsulate(&ct).unwrap().expose_secret(),
        ss.expose_secret()
    );
    let nonce_a = [0x22; 32];
    let transcript = PairAccept::transcript(&attempt.hello_hash, &nonce_a, ct.as_bytes()).unwrap();
    let (accept, accept_hash) = accept_for(&keys, &attempt.hello_hash, &nonce_a, &ct).unwrap();
    let th = th(&attempt.hello_hash, &accept_hash).unwrap();
    let (b2a, a2b) = record_keys(&keys, &ss, &th).unwrap();
    let (kb2a, ka2b) = (vectors::record_key(&b2a), vectors::record_key(&a2b));
    let commit = attempt.nonce_b.commitment().unwrap();
    let sas = Sas::compute(&th, &attempt.nonce_b).unwrap();

    let vk = VaultKey::from_transfer(&[0x44; 32]).unwrap();
    let root = LinkRoot::derive(&vk, vault, generation, DerivationProfile::V1).unwrap();
    let link = root
        .link_key(&ss, &th, &attempt.nonce_b, &link_id, vault, generation)
        .unwrap();
    let proof_a = root.proof(&th, ProofRole::A, vault, generation).unwrap();
    let proof_b = root.proof(&th, ProofRole::B, vault, generation).unwrap();

    let reveal = PairReveal::encode(attempt.nonce_b.expose_secret()).unwrap();
    let grant = grant_plaintext(&vk, vault, generation, &link_id).unwrap();
    let error = ErrorMsg::encode(ErrorCode::Integrity).unwrap();
    let reveal_record = RecordSealer::new(b2a).seal(&reveal).unwrap();
    let mut a_sealer = RecordSealer::new(a2b);
    let grant_record = a_sealer.seal(&grant).unwrap();
    let error_record = a_sealer.seal(&error).unwrap();
    // The records open under freshly derived keys, in order.
    let (b2a, a2b) = record_keys(&keys, &ss, &th).unwrap();
    RecordOpener::new(b2a).open(&reveal_record).unwrap();
    let mut a_opener = RecordOpener::new(a2b);
    a_opener.open(&grant_record).unwrap();
    a_opener.open(&error_record).unwrap();

    // The session handshake (§5) under a fixed link key, with the same
    // X-Wing vector for I's key pair and R's encapsulation.
    let session_link = vectors::link_key_from([0x66; 32]).unwrap();
    let auth = session_link.session_auth().unwrap();
    let (k_i, k_r) = vectors::session_auth(&auth);
    let (dk_i, ek_i) = XWingDecapsKey::from_test_seed(&seed).unwrap();
    let nonce_i = [0x77; 32];
    let sync_hello = sync_attempt(&auth, &nonce_i, dk_i, &ek_i).unwrap();
    let (s_ss, s_ct) = ek_i.encapsulate_derand(&eseed).unwrap();
    let nonce_r = [0x88; 32];
    let sync_transcript =
        SyncAccept::transcript(&sync_hello.hello_hash, &nonce_r, s_ct.as_bytes()).unwrap();
    let (sync_accept, sync_accept_hash) =
        sync_accept_for(&auth, &sync_hello.hello_hash, &nonce_r, &s_ct).unwrap();
    let s_th = session_th(&sync_hello.hello_hash, &sync_accept_hash).unwrap();
    let (i2r, r2i) = session_keys(&s_ss, &session_link, &s_th).unwrap();
    let confirm = Confirm::encode(&s_th).unwrap();
    let addr_qr = encode_addr_qr(
        LanProfile::V1,
        &[
            parse_endpoint("192.0.2.10:7777").unwrap(),
            parse_endpoint("[2001:db8::10]:7777").unwrap(),
        ],
    )
    .unwrap();

    let mut out = String::from(
        "# QuickVault LAN interoperability vectors (spec 0013 §4-§6, §8.5, §11).\n\
         # status: development-only; regenerated freely until the format freeze\n\
         # (plans 0037, 0038). Pairing inputs: P, nonce_b, nonce_a, the X-Wing\n\
         # draft-11 vector 1 seed/eseed, vk, vault_id, key_generation (4-byte hex),\n\
         # link_id; mode 0. Session inputs: session_link_key, nonce_i, nonce_r and\n\
         # the same X-Wing vector (ek_b, ct, ss). The address QR names\n\
         # 192.0.2.10:7777 and [2001:db8::10]:7777.\n\
         # Checked independently by crosscheck_lan.py except the *_record values\n\
         # (XChaCha20-Poly1305) and X-Wing (draft-11 KATs).\n\n",
    );
    let mut put = |k: &str, v: &[u8]| {
        writeln!(out, "{k} = {}", hex(v)).unwrap();
    };
    put("p", &p);
    put("nonce_b", &[0x11; 32]);
    put("nonce_a", &nonce_a);
    put("xwing_seed", &seed);
    put("xwing_eseed", &eseed);
    put("vk", &[0x44; 32]);
    put("vault_id", &vault.0);
    put("key_generation", &generation.0.to_be_bytes());
    put("link_id", &link_id);
    put("ek_b", ek.as_bytes());
    put("ct", ct.as_bytes());
    put("ss", ss.expose_secret());
    put("pairing_id", keys.pairing_id());
    put("k_hello", &k_hello);
    put("k_accept", &k_accept);
    put("commit_b", &commit);
    put("hello_body", &body_without_last(&attempt.hello).unwrap());
    put("hello", &attempt.hello);
    put("hello_hash", &attempt.hello_hash);
    put("accept_transcript", &transcript);
    put("accept", &accept);
    put("accept_hash", &accept_hash);
    put("th", &th);
    put("k_b2a", &kb2a);
    put("k_a2b", &ka2b);
    put("sas", &sas.digits());
    put("k_lan", &vectors::link_root(&root));
    put("link_key", &vectors::link_key(&link));
    put("proof_a", proof_a.as_bytes());
    put("proof_b", proof_b.as_bytes());
    put("reveal", &reveal);
    put("grant", &grant);
    put("error_integrity", &error);
    put("reveal_record", &reveal_record);
    put("grant_record", &grant_record);
    put("error_record", &error_record);
    put("session_link_key", &[0x66; 32]);
    put("nonce_i", &nonce_i);
    put("nonce_r", &nonce_r);
    put("k_i", &k_i);
    put("k_r", &k_r);
    put(
        "sync_hello_body",
        &body_without_last(&sync_hello.hello).unwrap(),
    );
    put("sync_hello", &sync_hello.hello);
    put("sync_hello_hash", &sync_hello.hello_hash);
    put("sync_accept_transcript", &sync_transcript);
    put("sync_accept", &sync_accept);
    put("sync_accept_hash", &sync_accept_hash);
    put("session_th", &s_th);
    put("k_i2r", &vectors::record_key(&i2r));
    put("k_r2i", &vectors::record_key(&r2i));
    put("confirm", &confirm);
    put("addr_qr", &addr_qr);
    out
}

#[test]
fn lan_enroll_interoperability_vectors() {
    let text = render();
    if std::env::var_os("QV_WRITE_VECTORS").is_some() {
        std::fs::write(PATH, &text).unwrap();
    }
    let stored = std::fs::read_to_string(PATH).unwrap();
    assert_eq!(
        stored, text,
        "regenerate with QV_WRITE_VECTORS=1 and re-run crosscheck_lan.py"
    );
    // Deterministic: a second run renders the same bytes.
    assert_eq!(render(), text);
}
