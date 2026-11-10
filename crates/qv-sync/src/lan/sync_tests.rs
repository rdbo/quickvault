// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sync-mode suites (plans 0038 step 5, 0042 step 5; 0013 §4.8, §7, §8;
//! 0012 §1 rows "Account-dependent LAN sync" (loopback part), "LAN partial
//! acceptance" and "LAN discovery mistaken for trust"). Two replicas of one
//! vault sync through one-use windows on loopback, which is enabled
//! explicitly (0013 §1.4). Nothing about either device is stored.

use std::sync::atomic::AtomicUsize;

use qv_crypto::lan::ProofRole;
use qv_crypto::{KeyGeneration, RecordId};
use qv_model::{Clock, Entry, Extensions, Payload, RecordBody, RecordVersion, Text, VersionId};
use qv_protocol::lan::MAX_WANT_MESSAGES;

use super::*;

/// Commits one edit of `record` on `d` (a new entry if it does not exist).
fn edit(d: &Device, record: RecordId, title: &str) {
    let mut u = d.u();
    let root = u.manifest().root_group_id();
    let mut w = u.write().unwrap();
    let counter = w.reserve_counter().unwrap();
    let v = RecordVersion {
        version_id: VersionId::generate().unwrap(),
        clock: Clock::for_edit(&w.head_clocks(record), w.writer_id(), counter).unwrap(),
        modified_at: Timestamp(1),
        body: RecordBody::Live(Payload::Entry(Entry {
            group: root,
            type_hint: Text::new("login").unwrap(),
            title: Text::new(title).unwrap(),
            fields: Vec::new(),
            notes: None,
            icon: None,
            expires_at: None,
            created_at: Timestamp(1),
            modified_at: Timestamp(1),
            deleted_at: None,
            delete_operation: None,
            ext: Extensions::new(),
        })),
        ext: Extensions::new(),
    };
    w.put_local(record, v).unwrap();
    w.commit().unwrap();
}

fn record() -> RecordId {
    <RecordId as RandomId>::generate().unwrap()
}

fn seq(d: &Device) -> u64 {
    d.u().local_seq()
}

/// Two replicas of one vault and generation.
fn replicas() -> (Device, Device) {
    let a = Device::personal();
    let b = a.replica();
    (a, b)
}

/// Runs a sync window for `r` while `f` gets its address and code. The
/// window ends by itself after its one session; if `f` started none, it is
/// cancelled once `f` returns.
fn with_window<T: Send, V: CredentialApprover>(
    r: &V,
    f: impl FnOnce(SocketAddr, &str) -> T + Send,
) -> (Result<Approved, LanError>, T) {
    let (w, addr, code) = window();
    let done = AtomicBool::new(false);
    let cancel = || done.load(Ordering::SeqCst);
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(r, &mut Approve::yes(), &fast(), &cancel));
        let out = f(addr, &code);
        // The joiner can return before the window reads its last frame; give
        // a finished session a bounded chance to report before cancelling.
        let deadline = Instant::now() + Duration::from_secs(3);
        while !h.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        done.store(true, Ordering::SeqCst);
        (h.join().unwrap(), out)
    })
}

/// One sync-mode session from `b` with the window at `addr`.
fn sync_to(b: &dyn JoinerVault, addr: SocketAddr, code: &str) -> Result<RoundReport, LanError> {
    sync_with_code(
        JoinCode::from_manual(code).unwrap(),
        &[addr],
        LOOPBACK,
        b,
        &fast(),
        &never,
    )
}

fn merged(d: &Device) -> qv_store::Manifest {
    d.u().manifest().clone()
}

// 0012 §1: Account-dependent LAN sync
#[test]
fn lan_sync_converges_from_either_side_and_retries_are_idempotent() {
    let (a, b) = replicas();
    // Diverged edits on both sides; B shows the code, A scans it.
    edit(&a, record(), "on a");
    edit(&b, record(), "on b");
    let (window, sent) = with_window(&b, |addr, code| sync_to(&a, addr, code));
    let sent = sent.unwrap();
    let got = synced(window).unwrap();
    assert_eq!(
        (sent.local, sent.peer),
        (Outcome::Merged, Some(Outcome::Merged))
    );
    assert_eq!(
        (got.local, got.peer),
        (Outcome::Merged, Some(Outcome::Merged))
    );
    assert_eq!(sent.failure, None);
    assert_eq!(merged(&a), merged(&b));
    // The other direction: A shows the code, B scans it.
    edit(&a, record(), "again on a");
    edit(&b, record(), "again on b");
    let (window, sent) = with_window(&a, |addr, code| sync_to(&b, addr, code));
    assert_eq!(sent.unwrap().local, Outcome::Merged);
    assert_eq!(synced(window).unwrap().local, Outcome::Merged);
    assert_eq!(merged(&a), merged(&b));
    // A retry finds nothing new and commits nothing on either side.
    let (sa, sb) = (seq(&a), seq(&b));
    let (window, sent) = with_window(&a, |addr, code| sync_to(&b, addr, code));
    let sent = sent.unwrap();
    assert_eq!(
        (sent.local, sent.peer),
        (Outcome::Unchanged, Some(Outcome::Unchanged))
    );
    assert_eq!(synced(window).unwrap().local, Outcome::Unchanged);
    assert_eq!((seq(&a), seq(&b)), (sa, sb));
    // No session stored anything about the other device (0013 §9.1).
    assert_eq!(a.links() + b.links(), 0);
}

#[test]
fn lan_sync_concurrent_edits_surface_as_conflicts() {
    let (a, b) = replicas();
    let shared = record();
    edit(&a, shared, "base");
    let (_, r) = with_window(&b, |addr, code| sync_to(&a, addr, code));
    assert_eq!(r.unwrap().local, Outcome::Unchanged);
    edit(&a, shared, "edited on a");
    edit(&b, shared, "edited on b");
    let (window, r) = with_window(&b, |addr, code| sync_to(&a, addr, code));
    assert_eq!(r.unwrap().local, Outcome::MergedWithConflicts);
    assert_eq!(synced(window).unwrap().local, Outcome::MergedWithConflicts);
    let m = merged(&a);
    assert_eq!(m.record(shared).unwrap().heads().len(), 2);
    assert_eq!(m, merged(&b));
}

/// A vault that delegates to a device and can fail or cancel at one step,
/// for the interruption suites.
struct Faulty<'d> {
    inner: &'d Device,
    fail_accept: bool,
    stop_at_stage: Option<&'d AtomicBool>,
    fail_object: bool,
}
impl<'d> Faulty<'d> {
    fn new(inner: &'d Device) -> Self {
        Self {
            inner,
            fail_accept: false,
            stop_at_stage: None,
            fail_object: false,
        }
    }
}
impl ExchangeVault for Faulty<'_> {
    fn scope(&self) -> Result<(qv_crypto::VaultId, qv_crypto::KeyGeneration), LanError> {
        self.inner.scope()
    }
    fn serve_state(&self) -> Result<LanServeState, LanError> {
        self.inner.serve_state()
    }
    fn object(&self, state: &LanServeState, id: ObjectId) -> Result<Vec<u8>, LanError> {
        if self.fail_object {
            return Err(LanError::StateChanged);
        }
        self.inner.object(state, id)
    }
    fn stage(&self, hash: &[u8; 32], envelope: &[u8]) -> Result<qv_store::LanStaging, LanError> {
        if let Some(stop) = self.stop_at_stage {
            stop.store(true, Ordering::SeqCst);
        }
        self.inner.stage(hash, envelope)
    }
    fn stage_local(&self, staging: &mut qv_store::LanStaging) -> Result<(), LanError> {
        self.inner.stage_local(staging)
    }
    fn accept(&self, staging: qv_store::LanStaging) -> Result<Accepted, LanError> {
        if self.fail_accept {
            return Err(LanError::Integrity);
        }
        self.inner.accept(staging)
    }
}
impl ApproverVault for Faulty<'_> {
    fn context(&self) -> Result<ApproverContext, LanError> {
        ApproverVault::context(self.inner)
    }
}
impl CredentialApprover for Faulty<'_> {
    type Authorization = TestAuthorization;
    fn authenticate_password(
        &self,
        p: MasterPassword,
        t0: &[u8; 32],
        ke1: &[u8],
    ) -> Result<(PasswordAuthServer, SecretBytes, TestAuthorization), LanError> {
        self.inner.authenticate_password(p, t0, ke1)
    }
    fn check_authorization(&self, a: &TestAuthorization) -> Result<(), LanError> {
        self.inner.check_authorization(a)
    }
    fn key_auth(
        &self,
        mode: crypto::AuthMode,
        t0: [u8; 32],
    ) -> Result<KeyAuthentication, LanError> {
        CredentialApprover::key_auth(self.inner, mode, t0)
    }
    fn authorized_grant(
        &self,
        a: TestAuthorization,
        sealer: &mut crypto::RecordSealer<FinalEpoch>,
    ) -> Result<SealedGrant, LanError> {
        self.inner.authorized_grant(a, sealer)
    }
}
impl JoinerVault for Faulty<'_> {
    fn key_auth(&self, t0: [u8; 32]) -> Result<KeyAuthentication, LanError> {
        JoinerVault::key_auth(self.inner, t0)
    }
    fn context(&self) -> Result<JoinerContext, LanError> {
        JoinerVault::context(self.inner)
    }
}

// 0012 §1: LAN partial acceptance
#[test]
fn lan_sync_failures_before_acceptance_change_nothing_and_after_it_keep_the_commit() {
    let (a, b) = replicas();
    edit(&a, record(), "a's change");
    edit(&b, record(), "b's change");
    let (sa, sb) = (seq(&a), seq(&b));

    // The window's side fails while serving: neither side accepts anything.
    let mut faulty = Faulty::new(&b);
    faulty.fail_object = true;
    let (window, r) = with_window(&faulty, |addr, code| sync_to(&a, addr, code));
    assert_eq!(r.unwrap_err(), LanError::StateChanged);
    assert_eq!(window.unwrap_err(), LanError::StateChanged);
    assert_eq!((seq(&a), seq(&b)), (sa, sb));

    // A cancel (or lock) during the round: nothing accepted anywhere.
    let stop = AtomicBool::new(false);
    let mut faulty_a = Faulty::new(&a);
    faulty_a.stop_at_stage = Some(&stop);
    let cancel = || stop.load(Ordering::SeqCst);
    let (window, r) = with_window(&b, |addr, code| {
        sync_with_code(
            JoinCode::from_manual(code).unwrap(),
            &[addr],
            LOOPBACK,
            &faulty_a,
            &fast(),
            &cancel,
        )
    });
    assert_eq!(r.unwrap_err(), LanError::Cancelled);
    assert_eq!(window.unwrap_err(), LanError::Timeout);
    assert_eq!((seq(&a), seq(&b)), (sa, sb));

    // The window's side fails at its own acceptance, after the joiner
    // committed: the joiner keeps its commit and reports no receipt.
    let mut faulty = Faulty::new(&b);
    faulty.fail_accept = true;
    let (window, r) = with_window(&faulty, |addr, code| sync_to(&a, addr, code));
    let first = r.unwrap();
    assert_eq!(first.local, Outcome::Merged);
    assert_eq!(first.peer, None);
    assert!(first.failure.is_some());
    assert_eq!(seq(&a), sa + 1);
    assert_eq!(seq(&b), sb);
    assert_eq!(window.unwrap_err(), LanError::Integrity);
}

#[test]
fn lan_sync_retry_after_a_lost_acknowledgement_completes_the_other_side() {
    let (a, b) = replicas();
    edit(&a, record(), "a's change");
    edit(&b, record(), "b's change");
    let mut faulty = Faulty::new(&b);
    faulty.fail_accept = true;
    let (_, r) = with_window(&faulty, |addr, code| sync_to(&a, addr, code));
    assert_eq!(r.unwrap().local, Outcome::Merged);
    let sa = seq(&a);
    // The retry with a new code: A has B's change already; B takes A's.
    let (window, r) = with_window(&b, |addr, code| sync_to(&a, addr, code));
    let r = r.unwrap();
    assert_eq!(
        (r.local, r.peer),
        (Outcome::Unchanged, Some(Outcome::Merged))
    );
    assert_eq!(synced(window).unwrap().local, Outcome::Merged);
    assert_eq!(seq(&a), sa);
    assert_eq!(merged(&a), merged(&b));
}

/// A manual sync-mode joiner: pairs with `code` up to the record channel
/// and returns it with the transcript, before any proof.
fn manual_sync<'c>(addr: SocketAddr, code: &str) -> Manual<'c> {
    manual(addr, &keys_of(code), JoinMode::Sync, None)
}

/// `d`'s proof for `th`, as role `role`, for `generation` (normally its own).
fn proof_of(d: &Device, th: &[u8; 32], role: ProofRole, generation: KeyGeneration) -> [u8; 32] {
    let u = d.u();
    let h = u.header();
    // PB deliberately carries no identity/generation. A nonlocal generation
    // argument selects the cross-method negative fixture instead.
    let mode = if generation == h.key_generation {
        crypto::AuthMode::KeySync
    } else {
        crypto::AuthMode::KeyEnrollment
    };
    let auth = KeyAuthentication::new(u.vault_key(), mode, *th).unwrap();
    let proof = auth.joiner_proof().unwrap();
    if role == ProofRole::B {
        *proof.as_bytes()
    } else {
        *auth
            .accept_joiner(&proof)
            .unwrap()
            .offer(h.vault_id, h.key_generation)
            .unwrap()
            .0
            .as_bytes()
    }
}
fn send_prove(m: &mut Manual<'_>, _d: &Device, _generation: KeyGeneration, proof: &[u8; 32]) {
    m.ch.send(
        &KeyProve { mac: proof }.encode().unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_sync_window_sends_no_proof_before_a_valid_one_and_accepts_nothing() {
    let (a, b) = replicas();
    let generation = a.u().header().key_generation;
    let other = Device::from(template("Other"));
    let sb = seq(&b);
    type Script<'s> = Box<dyn FnOnce(&mut Manual<'_>) + Send + 's>;
    let cases: Vec<(&str, LanError, Script<'_>)> = vec![
        // A proof from another vault's key, under b's vault ID.
        (
            "wrong VK",
            LanError::Integrity,
            Box::new(|m| {
                let p = proof_of(&other, &m.th, ProofRole::B, generation);
                send_prove(m, &a, generation, &p);
            }),
        ),
        // Another generation's proof and generation.
        (
            "cross-mode proof",
            LanError::Integrity,
            Box::new(|m| {
                let g = KeyGeneration(generation.0 + 1);
                let p = proof_of(&a, &m.th, ProofRole::B, g);
                send_prove(m, &a, g, &p);
            }),
        ),
        // The window's own role (reflection).
        (
            "role",
            LanError::Integrity,
            Box::new(|m| {
                let p = proof_of(&a, &m.th, ProofRole::A, generation);
                send_prove(m, &a, generation, &p);
            }),
        ),
        // An exchange message before any proof.
        (
            "no prove",
            LanError::Integrity,
            Box::new(|m| {
                let (vault, g) = a.scope().unwrap();
                m.ch.send(
                    &State::encode(&vault.0, g.0, &[0; 32], 1).unwrap(),
                    Duration::from_secs(5),
                )
                .unwrap();
            }),
        ),
    ];
    for (name, expected, script) in cases {
        let (window, answer) = with_window(&b, |addr, code| {
            let mut m = manual_sync(addr, code);
            script(&mut m);
            // The window answers with an error record, never a `proved`.
            m.ch.recv(Duration::from_secs(5), None).map(|r| r.len())
        });
        assert_eq!(answer.err(), Some(LanError::Timeout), "{name}");
        assert_eq!(window.unwrap_err(), expected, "{name}");
    }
    assert_eq!(seq(&b), sb);
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_sync_a_proof_from_another_session_is_refused() {
    let (a, b) = replicas();
    // Session 1: a valid proof for its transcript, never sent.
    let (_, relayed) = with_window(&b, |addr, code| {
        let m = manual_sync(addr, code);
        let generation = a.u().header().key_generation;
        proof_of(&a, &m.th, ProofRole::B, generation)
    });
    // Session 2 (a new code): the relayed proof does not match its `th`.
    let (window, answer) = with_window(&b, |addr, code| {
        let mut m = manual_sync(addr, code);
        let generation = a.u().header().key_generation;
        send_prove(&mut m, &a, generation, &relayed);
        m.ch.recv(Duration::from_secs(5), None).map(|r| r.len())
    });
    assert_eq!(answer.err(), Some(LanError::Timeout));
    assert_eq!(window.unwrap_err(), LanError::Integrity);
}

/// A window that proves itself with `proof` instead of its own (B's
/// protection against a code shown by a device without the vault).
fn hostile_window(b: &Device, bad_proof: [u8; 32]) -> (LanError, Option<LanError>) {
    let secret = PairingSecret::generate().unwrap();
    let code = qv_protocol::oob::encode_manual(secret.expose_secret()).to_string();
    let keys = PairingKeys::new(secret).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let (mut ch, _, hello, _) = accept_initial(stream, keys);
            let t = Duration::from_secs(5);
            KeyProve::decode(ch.recv(t, None).unwrap().expose_secret()).unwrap();
            let (vault, generation) = b.scope().unwrap();
            ch.send(
                &KeyProved {
                    vault_id: vault.0,
                    generation: generation.0,
                    mac: bad_proof,
                }
                .encode()
                .unwrap(),
                t,
            )
            .unwrap();
            assert_eq!(hello.mode, AuthMode::KeySync);
            // Credential failures close without a distinct error oracle.
            ch.recv(t, None).err()
        });
        let r = sync_to(b, addr, &code).unwrap_err();
        (r, h.join().unwrap())
    })
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_sync_joiner_refuses_a_window_without_the_vault() {
    let b = Device::personal();
    let sb = seq(&b);
    let (joiner, window) = hostile_window(&b, [0x42; 32]);
    assert_eq!(joiner, LanError::Integrity);
    assert_eq!(window, Some(LanError::Timeout));
    assert_eq!(seq(&b), sb);
}

#[test]
fn lan_sync_windows_serve_one_session_and_close_on_failures_and_expiry() {
    let (a, b) = replicas();
    // Repeated garbage hellos close the window. A connection that arrives
    // while the previous one is still being checked is closed uncounted
    // (0013 §8.3), so keep sending until the listener is gone; the exact
    // count of 16 is checked one connection at a time in
    // `lan_enroll_hostile_hellos_are_silent_and_close_the_window`.
    let (window, sent) = with_window(&b, |addr, _| {
        let mut sent = 0;
        while sent < 64 {
            let Ok(stream) = TcpStream::connect(addr) else {
                break;
            };
            let mut conn = Conn::new(stream, &never).unwrap();
            conn.within(Duration::from_secs(3), None);
            let _ = conn.send_frame(FramePhase::Handshake, b"garbage");
            let mut buf = Vec::new();
            assert!(conn.recv_frame(FramePhase::Handshake, &mut buf).is_err());
            sent += 1;
        }
        sent
    });
    assert_eq!(window.unwrap_err(), LanError::TooManyAttempts);
    assert!((16..64).contains(&sent), "{sent}");
    // Expiry.
    let w = PairingWindow::open(
        ListenScope::LoopbackForTests,
        None,
        Duration::from_millis(300),
    )
    .unwrap();
    let started = Instant::now();
    assert_eq!(
        w.run(&b, &mut Approve::yes(), &fast(), &never).unwrap_err(),
        LanError::WindowExpired
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    // One use: a connection during the session gets nothing, and after the
    // session the window is gone.
    let extra = AtomicUsize::new(0);
    edit(&a, record(), "first");
    let (window, after) = with_window(&b, |addr, code| {
        let m = manual_sync(addr, code);
        if !poke(addr, b"anything") {
            extra.fetch_add(1, Ordering::SeqCst);
        }
        drop(m);
        // Wait for the window to end, then try its code again.
        std::thread::sleep(Duration::from_millis(300));
        sync_to(&a, addr, code)
    });
    assert!(window.is_err());
    assert_eq!(extra.load(Ordering::SeqCst), 1);
    assert_eq!(after.unwrap_err(), LanError::NoPeer);
}

#[test]
fn lan_sync_cancel_during_a_connection_attempt_is_prompt() {
    let a = Device::personal();
    let stop = AtomicBool::new(false);
    let cancel = || stop.load(Ordering::SeqCst);
    // TEST-NET-1 is never routed to a host: the connect blocks until its
    // limit unless the network refuses it at once.
    let blackhole = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);
    let code = qv_protocol::oob::encode_manual(&[3; 16]).to_string();
    let started = Instant::now();
    let r = std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(200));
            stop.store(true, Ordering::SeqCst);
        });
        let slow = LanTimeouts {
            connect: Duration::from_secs(10),
            ..fast()
        };
        sync_with_code(
            JoinCode::from_manual(&code).unwrap(),
            &[blackhole],
            EndpointPolicy::default(),
            &a,
            &slow,
            &cancel,
        )
    });
    // Cancelled while blocked, or refused at once by this host's network;
    // never blocked for the 10 s limit.
    assert!(
        matches!(r, Err(LanError::Cancelled | LanError::NoPeer)),
        "{r:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

/// A sync-mode joiner past both proofs, for exchange-level scripts.
fn proved_session<'c>(a: &Device, addr: SocketAddr, code: &str) -> Manual<'c> {
    let mut m = manual_sync(addr, code);
    let generation = a.u().header().key_generation;
    let p = proof_of(a, &m.th, ProofRole::B, generation);
    send_prove(&mut m, a, generation, &p);
    let second = m.ch.recv(Duration::from_secs(5), None).unwrap();
    let proved = KeyProved::decode(second.expose_secret()).unwrap();
    let auth = JoinerVault::key_auth(a, m.th)
        .unwrap()
        .accept_offerer(
            qv_crypto::VaultId(proved.vault_id),
            KeyGeneration(proved.generation),
            &qv_crypto::MacTag::from_bytes(proved.mac),
        )
        .unwrap();
    let first = KeyProve { mac: &p }.encode().unwrap();
    let ta = auth_transcript(
        AuthMode::KeySync,
        &m.th,
        &first,
        second.expose_secret(),
        None,
    )
    .unwrap();
    let (keys, finished) = m.schedule.take().unwrap().complete(auth, ta).unwrap();
    drop(finished);
    m.ch.finish(keys);
    m.ch.final_channel().begin_exchange();
    m
}

/// Runs `script` after both proofs and returns the window's answer.
fn window_answer(
    a: &Device,
    b: &Device,
    script: impl FnOnce(&mut Channel<'_>) + Send,
) -> (Result<SecretBytes, LanError>, Result<Approved, LanError>) {
    let (window, answer) = with_window(b, |addr, code| {
        let mut m = proved_session(a, addr, code);
        script(&mut m.ch);
        // Skip the window's ordinary turns until its refusal; error records
        // come back as `Err`.
        loop {
            match m.ch.recv(Duration::from_secs(5), None) {
                Ok(_) => continue,
                other => break other,
            }
        }
    });
    (answer, window)
}

#[test]
fn lan_sync_window_refuses_bad_states_and_requests() {
    let (a, b) = replicas();
    edit(&b, record(), "something to request");
    let a_state = a.serve_state().unwrap();
    let (vault, generation) = a.scope().unwrap();
    let t = Duration::from_secs(5);
    let send_state = |ch: &mut Channel<'_>, v: &[u8; 16], len: u64| {
        ch.send(
            &State::encode(v, generation.0, a_state.manifest_hash(), len).unwrap(),
            t,
        )
        .unwrap();
    };
    let manifest = |ch: &mut Channel<'_>| {
        ch.send(&ManifestPart::encode(0, a_state.envelope()).unwrap(), t)
            .unwrap();
    };
    let len = a_state.envelope().len() as u64;
    type Script<'s> = Box<dyn FnOnce(&mut Channel<'_>) + Send + 's>;
    let cases: Vec<(LanError, Script<'_>)> = vec![
        // Another vault.
        (
            LanError::VaultMismatch,
            Box::new(|ch| send_state(ch, &[9; 16], len)),
        ),
        // A manifest above 64 MiB, refused before allocation.
        (
            LanError::Limit,
            Box::new(|ch| send_state(ch, &vault.0, (64 << 20) + 1)),
        ),
        // Length 0 outside a new-device grant.
        (
            LanError::Protocol,
            Box::new(|ch| send_state(ch, &vault.0, 0)),
        ),
        // An ID outside the served state.
        (
            LanError::Protocol,
            Box::new(|ch| {
                send_state(ch, &vault.0, len);
                manifest(ch);
                ch.send(&Want::encode(&[[0xee; 16]], true).unwrap(), t)
                    .unwrap();
            }),
        ),
        // An empty Want that is not the last.
        (
            LanError::Protocol,
            Box::new(|ch| {
                send_state(ch, &vault.0, len);
                manifest(ch);
                ch.send(&Want::encode(&[], false).unwrap(), t).unwrap();
            }),
        ),
    ];
    for (case, (expected, script)) in cases.into_iter().enumerate() {
        let (answer, window) = window_answer(&a, &b, script);
        // The first three cases have no valid first final-key State. A must
        // close silently. Bad Wants follow a valid State and may report errors.
        let expected_peer = if case < 3 {
            LanError::Timeout
        } else {
            expected
        };
        assert_eq!(answer.err(), Some(expected_peer));
        assert_eq!(window.unwrap_err(), expected);
    }
}

#[test]
fn lan_sync_window_refuses_a_63rd_want_message() {
    let (a, b) = replicas();
    for i in 0..MAX_WANT_MESSAGES {
        edit(&b, record(), &format!("entry {i}"));
    }
    let a_state = a.serve_state().unwrap();
    let (vault, generation) = a.scope().unwrap();
    let ids: Vec<[u8; 16]> = b
        .u()
        .manifest()
        .references()
        .iter()
        .map(|r| r.object_id().to_bytes())
        .collect();
    assert!(ids.len() > MAX_WANT_MESSAGES);
    let t = Duration::from_secs(5);
    let (answer, window) = window_answer(&a, &b, |ch| {
        ch.send(
            &State::encode(
                &vault.0,
                generation.0,
                a_state.manifest_hash(),
                a_state.envelope().len() as u64,
            )
            .unwrap(),
            t,
        )
        .unwrap();
        ch.send(&ManifestPart::encode(0, a_state.envelope()).unwrap(), t)
            .unwrap();
        // 63 non-final Wants of one distinct ID each.
        for id in &ids[..=MAX_WANT_MESSAGES] {
            if ch.send(&Want::encode(&[*id], false).unwrap(), t).is_err() {
                break;
            }
        }
    });
    assert_eq!(answer.err(), Some(LanError::Protocol));
    assert_eq!(window.unwrap_err(), LanError::Protocol);
}

// 0012 §1: LAN partial acceptance
#[test]
fn lan_sync_expiry_closes_an_authenticated_connection_and_listener() {
    let (a, b) = replicas();
    edit(&a, record(), "must not arrive after expiry");
    let before = seq(&b);
    let w = PairingWindow::open(
        ListenScope::LoopbackForTests,
        None,
        Duration::from_millis(700),
    )
    .unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), w.port().unwrap());
    let code = w.manual_code().to_string();
    let started = Instant::now();
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&b, &mut Approve::yes(), &fast(), &never));
        let mut m = proved_session(&a, addr, &code);
        // The authenticated peer stalls before its State. The long
        // per-message timeout must not extend the shorter window.
        let r = h.join().unwrap();
        assert!(r.is_err(), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(
            TcpStream::connect(addr).is_err(),
            "listener dropped at expiry"
        );
        let late = super::super::exchange::exchange(
            m.ch.final_channel(),
            super::super::exchange::Role::Initiator,
            &a,
            None,
            &fast(),
        );
        assert!(late.is_err());
    });
    assert_eq!(seq(&b), before);
}
