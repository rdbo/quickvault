// SPDX-License-Identifier: AGPL-3.0-or-later

//! Development interoperability vectors for LAN sessions (0013 Testing
//! Requirements; plans 0037 step 8, 0038 step 7, 0042 step 5).
//!
//! Historical profile1 new-device and sync-mode fixtures remain for prior
//! primitive/encoding regressions only; runtime uses strict profile2. Fixed
//! inputs. X-Wing uses draft-11 vector 1's seeds
//! through the `test-vectors` feature. The test renders every message,
//! derivation and transcript and compares them with
//! `tests/vectors/qv-dev-lan-pairing.txt`; `QV_WRITE_VECTORS=1` rewrites the
//! file. `tests/vectors/crosscheck_lan.py` recomputes every value except the
//! AEAD records and X-Wing itself (draft KATs cover X-Wing).

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;

use qv_crypto::lan::{
    PairNonce, PairingSecret, ProofRole, ProofRoot, RecordOpener, RecordSealer, Sas, vectors,
};
use qv_crypto::{DerivationProfile, KeyGeneration, VaultId, VaultKey, XWingDecapsKey};
use qv_protocol::lan::{ErrorMsg, JoinMode, PairAccept, PairProve, PairProved, PairReveal};
use qv_protocol::message::body_without_last;
use qv_protocol::registry::ErrorCode;

use super::exchange::grant_plaintext;
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

    let reveal = PairReveal::encode(attempt.nonce_b.expose_secret()).unwrap();
    let grant = grant_plaintext(&vk, vault, generation).unwrap();
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

    // A sync-mode handshake (§4.8) with the same inputs and X-Wing vector:
    // mode 1, so another hello, transcript and record keys.
    let (dk_s, _) = XWingDecapsKey::from_test_seed(&seed).unwrap();
    let nonce_s = PairNonce::from_bytes(&[0x11; 32]).unwrap();
    let sync = join_attempt(&keys, JoinMode::Sync, nonce_s, dk_s, &ek).unwrap();
    let sync_transcript =
        PairAccept::transcript(&sync.hello_hash, &nonce_a, ct.as_bytes()).unwrap();
    let (sync_accept, sync_accept_hash) =
        accept_for(&keys, &sync.hello_hash, &nonce_a, &ct).unwrap();
    let sync_th = super::steps::th(&sync.hello_hash, &sync_accept_hash).unwrap();
    let (s_b2a, s_a2b) = record_keys(&keys, &ss, &sync_th).unwrap();
    let root = ProofRoot::derive(&vk, vault, generation, DerivationProfile::V1).unwrap();
    let proof_a = root
        .proof(&sync_th, ProofRole::A, vault, generation)
        .unwrap();
    let proof_b = root
        .proof(&sync_th, ProofRole::B, vault, generation)
        .unwrap();
    let prove = PairProve::encode(&vault.0, generation.0, proof_b.as_bytes()).unwrap();
    let proved = PairProved::encode(proof_a.as_bytes()).unwrap();
    let prove_record = RecordSealer::new(s_b2a).seal(&prove).unwrap();
    let proved_record = RecordSealer::new(s_a2b).seal(&proved).unwrap();
    let (s_b2a, s_a2b) = record_keys(&keys, &ss, &sync_th).unwrap();
    RecordOpener::new(s_b2a).open(&prove_record).unwrap();
    RecordOpener::new(s_a2b).open(&proved_record).unwrap();

    let mut out = String::from(
        "# QuickVault LAN interoperability vectors (spec 0013 §4, §6, §11).\n\
         # status: development-only; regenerated freely until the format freeze\n\
         # (plans 0037, 0038, 0042). Inputs: P, nonce_b, nonce_a, the X-Wing\n\
         # draft-11 vector 1 seed/eseed, vk, vault_id, key_generation (4-byte hex).\n\
         # The first handshake is new-device mode (0); the sync_* handshake is\n\
         # sync mode (1) with the same inputs, and its proofs use K_proof.\n\
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
    put("reveal", &reveal);
    put("grant", &grant);
    put("error_integrity", &error);
    put("reveal_record", &reveal_record);
    put("grant_record", &grant_record);
    put("error_record", &error_record);
    put("sync_hello_body", &body_without_last(&sync.hello).unwrap());
    put("sync_hello", &sync.hello);
    put("sync_hello_hash", &sync.hello_hash);
    put("sync_accept_transcript", &sync_transcript);
    put("sync_accept", &sync_accept);
    put("sync_accept_hash", &sync_accept_hash);
    put("sync_th", &sync_th);
    put("k_proof", &vectors::proof_root(&root));
    put("proof_a", proof_a.as_bytes());
    put("proof_b", proof_b.as_bytes());
    put("prove", &prove);
    put("proved", &proved);
    put("prove_record", &prove_record);
    put("proved_record", &proved_record);
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
