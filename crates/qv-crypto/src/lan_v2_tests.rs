// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent primitive/CBOR vectors plus epoch, role and proof rejection tests.
#![allow(clippy::unwrap_used)] // All inputs are fixed synthetic fixtures.
use super::*;

fn secret<const N: usize>(value: &[u8]) -> SecretArray<N> {
    SecretArray::try_init(|out| {
        out.copy_from_slice(value);
        Ok::<_, CryptoError>(())
    })
    .unwrap()
}
fn auth(mode: AuthMode, t0: [u8; 32]) -> AuthSecret {
    AuthSecret {
        key: secret(&[9; 64]),
        mode,
        t0,
    }
}
fn outer(mode: AuthMode, t0: [u8; 32]) -> (OuterSchedule, TrafficKeys<InitialEpoch>) {
    PairingKeys::new(PairingSecret::from_bytes(&[8; 16]).unwrap())
        .unwrap()
        .begin(
            crate::xwing::tests_support::shared_secret([7; 32]),
            mode,
            t0,
        )
        .unwrap()
}

// 0012 §1: Unpinned crypto
#[test]
fn v2_schedules_frames_and_key_proofs_match_independent_python_libraries() {
    let _guard = crate::memory::secrets_test_guard();
    let records = crate::kat::parse(include_str!("../tests/vectors/qv-dev-lan-v2.txt"));
    assert_eq!(records.len(), 3);
    for r in records {
        let mode = match r.get("mode") {
            [0] => AuthMode::PasswordEnrollment,
            [1] => AuthMode::KeyEnrollment,
            [2] => AuthMode::KeySync,
            _ => unreachable!(),
        };
        let j = array(|a| mode.encode(a)).unwrap();
        // `array` wraps another array; inspect the actual J separately.
        let mut d = qv_encoding::Decoder::new(&j).unwrap();
        assert_eq!(d.array().unwrap(), 1);
        let raw = d.raw_item().unwrap();
        assert_eq!(raw, r.get("j"));
        let pairing =
            PairingKeys::new(PairingSecret::from_bytes(r.get("pairing")).unwrap()).unwrap();
        assert_eq!(pairing.pairing_id(), &r.array("pairing_id"));
        assert_eq!(pairing.hello.expose_secret(), &r.array("hello_key"));
        assert_eq!(pairing.accept.expose_secret(), &r.array("accept_key"));
        assert_eq!(pairing.discovery_tag().unwrap(), r.array("discovery_tag"));
        let nonce = PairNonce::from_bytes(r.get("nonce")).unwrap();
        assert_eq!(nonce_commitment(&nonce).unwrap(), r.array("commitment"));
        assert_eq!(
            comparison_code(mode, &r.array("t0"), &nonce)
                .unwrap()
                .digits()
                .as_slice(),
            r.get("sas")
        );
        let (schedule, initial) = pairing
            .begin(
                crate::xwing::tests_support::shared_secret(r.array("ss")),
                mode,
                r.array("t0"),
            )
            .unwrap();
        assert_eq!(initial.a2b.expose_secret(), &r.array("key_0_a2b"));
        assert_eq!(initial.b2a.expose_secret(), &r.array("key_0_b2a"));
        assert_eq!(
            aad(mode, 0, Direction::A2b, &r.array("t0"), 0)
                .unwrap()
                .as_slice(),
            r.get("aad_0_a2b")
        );
        let (mut sender, _) = initial.split(Role::Offerer);
        assert_eq!(
            sender.seal(b"qv-v2 synthetic frame").unwrap().as_slice(),
            r.get("frame_0_a2b")
        );
        let auth = if mode == AuthMode::PasswordEnrollment {
            AuthSecret {
                key: secret(r.get("z")),
                mode,
                t0: r.array("t0"),
            }
        } else {
            let key = VaultKey::from_bytes(r.array("vk"));
            let receiver = KeyAuthentication::new(&key, mode, r.array("t0")).unwrap();
            assert_eq!(receiver.mac.expose_secret(), &r.array("key_mac"));
            assert_eq!(receiver.auth.key.expose_secret(), &r.array("z"));
            let pb = receiver.joiner_proof().unwrap();
            assert_eq!(pb.as_bytes().as_slice(), r.get("proof_b"));
            let sender = KeyAuthentication::new(&key, mode, r.array("t0"))
                .unwrap()
                .accept_joiner(&pb)
                .unwrap();
            let (pa, a_secret) = sender
                .offer(VaultId(r.array("vault_id")), KeyGeneration(1))
                .unwrap();
            assert_eq!(pa.as_bytes().as_slice(), r.get("proof_a"));
            let b_secret = receiver
                .accept_offerer(VaultId(r.array("vault_id")), KeyGeneration(1), &pa)
                .unwrap();
            assert!(a_secret.key.ct_eq(b_secret.key.expose_secret()));
            a_secret
        };
        let (traffic, finished) = schedule.complete(auth, r.array("ta")).unwrap();
        assert_eq!(traffic.a2b.expose_secret(), &r.array("key_1_a2b"));
        assert_eq!(traffic.b2a.expose_secret(), &r.array("key_1_b2a"));
        assert_eq!(
            aad(mode, 1, Direction::B2a, &r.array("ta"), 0)
                .unwrap()
                .as_slice(),
            r.get("aad_1_b2a")
        );
        let (mut sender, _) = traffic.split(Role::Joiner);
        assert_eq!(
            sender.seal(b"qv-v2 synthetic frame").unwrap().as_slice(),
            r.get("frame_1_b2a")
        );
        if mode == AuthMode::PasswordEnrollment {
            assert_eq!(finished.key.expose_secret(), &r.array("finished_key"));
            assert_eq!(
                finished.tag().unwrap().as_bytes().as_slice(),
                r.get("finished_tag")
            );
            finished.verify(&finished.tag().unwrap()).unwrap();
        }
    }
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn v2_final_channels_reject_old_epoch_reflection_replay_context_and_exhaustion() {
    let _guard = crate::memory::secrets_test_guard();
    let mode = AuthMode::PasswordEnrollment;
    let t0 = [1; 32];
    let ta = [2; 32];
    let (a, initial) = outer(mode, t0);
    let (mut old, _) = initial.split(Role::Joiner);
    let old_frame = old.seal(b"KE3").unwrap();
    let (a_keys, finished_a) = a.complete(auth(mode, t0), ta).unwrap();
    let (b, _) = outer(mode, t0);
    let (b_keys, finished_b) = b.complete(auth(mode, t0), ta).unwrap();
    finished_a.verify(&finished_b.tag().unwrap()).unwrap();
    let (mut a_send, mut a_recv) = a_keys.split(Role::Offerer);
    let (mut b_send, mut b_recv) = b_keys.split(Role::Joiner);
    let frame = b_send.seal(b"FinishedB").unwrap();
    assert_eq!(a_recv.open(&frame).unwrap().expose_secret(), b"FinishedB");
    assert!(a_recv.open(&frame).is_err());
    assert!(a_recv.open(&old_frame).is_err());
    // A fresh epoch1 opener rejects epoch0 outright, without an old-key trial.
    let (s, _) = outer(mode, t0);
    let (_, mut fresh) = s
        .complete(auth(mode, t0), ta)
        .unwrap()
        .0
        .split(Role::Offerer);
    assert!(fresh.open(&old_frame).is_err());
    let grant = a_send.seal(b"synthetic grant").unwrap();
    assert_eq!(
        b_recv.open(&grant).unwrap().expose_secret(),
        b"synthetic grant"
    );
    assert!(b_recv.open(&frame).is_err()); // Reflected opposite-direction record.
    let (s, _) = outer(mode, t0);
    assert!(s.complete(auth(AuthMode::KeyEnrollment, t0), ta).is_err());
    let (s, _) = outer(mode, t0);
    assert!(s.complete(auth(mode, [3; 32]), ta).is_err());
    let (s, _) = outer(mode, t0);
    let (mut send, _) = s
        .complete(auth(mode, t0), ta)
        .unwrap()
        .0
        .split(Role::Offerer);
    send.seq = RECORDS_PER_DIRECTION - 1;
    assert!(send.seal(b"last").is_ok());
    assert_eq!(
        send.seal(b"overflow").err(),
        Some(CryptoError::LimitExceeded)
    );
    assert_eq!(send.seal(b"retry").err(), Some(CryptoError::Integrity));
    let (s, _) = outer(mode, t0);
    let (_, mut recv) = s
        .complete(auth(mode, t0), ta)
        .unwrap()
        .0
        .split(Role::Offerer);
    assert_eq!(
        recv.open(&[0; TAG_LEN - 1]).err(),
        Some(CryptoError::LimitExceeded)
    );
    assert_eq!(recv.open(&frame).err(), Some(CryptoError::Integrity));
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn v2_key_proofs_bind_role_method_outer_transcript_and_identity_before_response() {
    let _guard = crate::memory::secrets_test_guard();
    let vk = VaultKey::from_bytes([4; 32]);
    let mode = AuthMode::KeyEnrollment;
    let t0 = [5; 32];
    let new = || KeyAuthentication::new(&vk, mode, t0).unwrap();
    let proof = new().joiner_proof().unwrap();
    assert!(
        KeyAuthentication::new(&vk, AuthMode::KeySync, t0)
            .unwrap()
            .accept_joiner(&proof)
            .is_err()
    );
    assert!(
        KeyAuthentication::new(&vk, mode, [6; 32])
            .unwrap()
            .accept_joiner(&proof)
            .is_err()
    );
    assert!(
        KeyAuthentication::new(&VaultKey::from_bytes([7; 32]), mode, t0)
            .unwrap()
            .accept_joiner(&proof)
            .is_err()
    );
    let vault = VaultId([8; 16]);
    let (a, _) = new()
        .accept_joiner(&proof)
        .unwrap()
        .offer(vault, KeyGeneration(1))
        .unwrap();
    assert!(new().accept_joiner(&a).is_err());
    assert!(
        new()
            .accept_offerer(vault, KeyGeneration(1), &proof)
            .is_err()
    );
    assert!(new().accept_offerer(vault, KeyGeneration(2), &a).is_err());
    assert!(
        new()
            .accept_offerer(VaultId([9; 16]), KeyGeneration(1), &a)
            .is_err()
    );
    assert!(new().accept_offerer(vault, KeyGeneration(1), &a).is_ok());
}
