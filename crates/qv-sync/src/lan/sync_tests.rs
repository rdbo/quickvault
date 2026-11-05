// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sync-round suites (plan 0038 step 5; 0013 §5, §7, §8; 0012 §1 rows
//! "Account-dependent LAN sync" (loopback part), "LAN partial acceptance"
//! and "LAN discovery mistaken for trust" for sessions). Two linked replicas
//! run on loopback, which is enabled explicitly (0013 §1.4).

use std::sync::atomic::AtomicUsize;

use qv_crypto::RecordId;
use qv_crypto::lan::SessionAuth;
use qv_model::{Clock, Entry, Extensions, Payload, RecordBody, RecordVersion, Text, VersionId};
use qv_protocol::lan::{Confirm, MAX_WANT_MESSAGES, SyncAccept};

use super::super::session::{check_sync_accept, session_keys, session_th, sync_attempt};
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

/// Two replicas of one vault, linked through link-mode pairing.
fn linked() -> (Device, Device, [u8; 16]) {
    let a = Device::personal();
    let b = a.replica();
    let (w, addr, code) = window();
    let mut approve = Approve::yes();
    let mut join = Join::yes();
    let (approved, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let joined = join_link(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &b,
            &mut join,
            &fast(),
            &never,
        );
        (h.join().unwrap(), joined)
    });
    let id = joined.unwrap().link_id;
    assert_eq!(approved.unwrap().link_id, id);
    (a, b, id)
}

fn key(d: &Device, id: &[u8; 16]) -> LinkKey {
    d.u().lan_link_key(id).unwrap()
}

fn receiver(stay: bool) -> (ReceiveWindow, SocketAddr) {
    let w = ReceiveWindow::open(
        ListenScope::LoopbackForTests,
        None,
        Duration::from_secs(30),
        stay,
    )
    .unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), w.port().unwrap());
    (w, addr)
}

type Rounds = Vec<([u8; 16], Result<RoundReport, LanError>)>;

/// Runs a receive window for `r` while `f` runs, then closes it (as a
/// cancel) if it is still open; returns both results.
fn with_window<T: Send>(
    r: &dyn ResponderVault,
    stay: bool,
    f: impl FnOnce(SocketAddr) -> T + Send,
) -> (WindowEnd, Rounds, T) {
    let (w, addr) = receiver(stay);
    let done = AtomicBool::new(false);
    let reported = AtomicBool::new(false);
    let cancel = || done.load(Ordering::SeqCst);
    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let mut rounds = Vec::new();
            let end = w
                .run(r, &fast(), &cancel, &mut |id, res| {
                    rounds.push((id, res));
                    reported.store(true, Ordering::SeqCst);
                })
                .unwrap();
            (end, rounds)
        });
        let out = f(addr);
        // The initiator can return before the responder reads its last frame
        // (for example a Cancel). Closing the window at once would race that
        // read, so a one-round window first gets a bounded chance to report.
        if !stay {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !reported.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        done.store(true, Ordering::SeqCst);
        let (end, rounds) = h.join().unwrap();
        (end, rounds, out)
    })
}

fn merged(d: &Device) -> qv_store::Manifest {
    d.u().manifest().clone()
}

// 0012 §1: Account-dependent LAN sync
#[test]
fn lan_sync_converges_from_either_initiator_and_retries_are_idempotent() {
    let (a, b, id) = linked();
    // Diverged edits on both sides; B receives, A initiates.
    edit(&a, record(), "on a");
    edit(&b, record(), "on b");
    let (end, rounds, sent) = with_window(&b, false, |addr| {
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never)
    });
    let sent = sent.unwrap();
    assert_eq!(end, WindowEnd::Completed);
    assert_eq!(rounds.len(), 1);
    assert_eq!(rounds[0].0, id);
    let got = rounds[0].1.unwrap();
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
    // The other direction: A receives, B initiates.
    edit(&a, record(), "again on a");
    edit(&b, record(), "again on b");
    let (end, _, sent) = with_window(&a, false, |addr| {
        sync(&key(&b, &id), &[addr], LOOPBACK, &b, &fast(), &never)
    });
    assert_eq!(end, WindowEnd::Completed);
    assert_eq!(sent.unwrap().local, Outcome::Merged);
    assert_eq!(merged(&a), merged(&b));
    // A retry finds nothing new and commits nothing on either side.
    let (sa, sb) = (seq(&a), seq(&b));
    let (_, rounds, sent) = with_window(&a, false, |addr| {
        sync(&key(&b, &id), &[addr], LOOPBACK, &b, &fast(), &never)
    });
    let sent = sent.unwrap();
    assert_eq!(
        (sent.local, sent.peer),
        (Outcome::Unchanged, Some(Outcome::Unchanged))
    );
    assert_eq!(rounds[0].1.unwrap().local, Outcome::Unchanged);
    assert_eq!((seq(&a), seq(&b)), (sa, sb));
}

#[test]
fn lan_sync_concurrent_edits_surface_as_conflicts() {
    let (a, b, id) = linked();
    let shared = record();
    edit(&a, shared, "base");
    let (_, _, r) = with_window(&b, false, |addr| {
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never)
    });
    assert_eq!(r.unwrap().local, Outcome::Unchanged);
    edit(&a, shared, "edited on a");
    edit(&b, shared, "edited on b");
    let (_, rounds, r) = with_window(&b, false, |addr| {
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never)
    });
    assert_eq!(r.unwrap().local, Outcome::MergedWithConflicts);
    assert_eq!(rounds[0].1.unwrap().local, Outcome::MergedWithConflicts);
    let m = merged(&a);
    assert_eq!(m.record(shared).unwrap().heads().len(), 2);
    assert_eq!(m, merged(&b));
}

/// An exchange vault that delegates to a device and can fail or cancel at
/// one step, for the interruption suites.
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
impl ResponderVault for Faulty<'_> {
    fn links(&self) -> Result<Vec<([u8; 16], LinkKey)>, LanError> {
        ResponderVault::links(self.inner)
    }
    fn has_link(&self, link_id: &[u8; 16]) -> Result<bool, LanError> {
        self.inner.has_link(link_id)
    }
}

// 0012 §1: LAN partial acceptance
#[test]
fn lan_sync_failures_before_acceptance_change_nothing_and_after_it_keep_the_commit() {
    let (a, b, id) = linked();
    edit(&a, record(), "a's change");
    edit(&b, record(), "b's change");
    let (sa, sb) = (seq(&a), seq(&b));

    // The responder fails while serving: neither side accepts anything.
    let mut faulty = Faulty::new(&b);
    faulty.fail_object = true;
    let (_, rounds, r) = with_window(&faulty, false, |addr| {
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never)
    });
    assert_eq!(r.unwrap_err(), LanError::StateChanged);
    assert_eq!(rounds[0].1.unwrap_err(), LanError::StateChanged);
    assert_eq!((seq(&a), seq(&b)), (sa, sb));

    // A cancel (or lock) during the round: nothing accepted anywhere.
    let stop = AtomicBool::new(false);
    let mut faulty_a = Faulty::new(&a);
    faulty_a.stop_at_stage = Some(&stop);
    let cancel = || stop.load(Ordering::SeqCst);
    let (_, rounds, r) = with_window(&b, false, |addr| {
        sync(
            &key(&a, &id),
            &[addr],
            LOOPBACK,
            &faulty_a,
            &fast(),
            &cancel,
        )
    });
    assert_eq!(r.unwrap_err(), LanError::Cancelled);
    assert_eq!(rounds[0].1.unwrap_err(), LanError::PeerCancelled);
    assert_eq!((seq(&a), seq(&b)), (sa, sb));

    // The responder fails at its own acceptance, after the initiator
    // committed: the initiator keeps its commit and reports no receipt.
    let mut faulty = Faulty::new(&b);
    faulty.fail_accept = true;
    let (end, rounds, r) = with_window(&faulty, false, |addr| {
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never)
    });
    let first = r.unwrap();
    assert_eq!(first.local, Outcome::Merged);
    assert_eq!(first.peer, None);
    assert!(first.failure.is_some());
    assert_eq!(seq(&a), sa + 1);
    assert_eq!(seq(&b), sb);
    assert_eq!(rounds[0].1.unwrap_err(), LanError::Integrity);
    // A failed round leaves the window open until it is closed.
    assert_eq!(end, WindowEnd::Cancelled);
}

#[test]
fn lan_sync_retry_after_a_lost_acknowledgement_completes_the_other_side() {
    let (a, b, id) = linked();
    edit(&a, record(), "a's change");
    edit(&b, record(), "b's change");
    let mut faulty = Faulty::new(&b);
    faulty.fail_accept = true;
    let (_, _, r) = with_window(&faulty, false, |addr| {
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never)
    });
    assert_eq!(r.unwrap().local, Outcome::Merged);
    let sa = seq(&a);
    // The retry: A has B's change already; B now takes A's.
    let (_, rounds, r) = with_window(&b, false, |addr| {
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never)
    });
    let r = r.unwrap();
    assert_eq!(
        (r.local, r.peer),
        (Outcome::Unchanged, Some(Outcome::Merged))
    );
    assert_eq!(rounds[0].1.unwrap().local, Outcome::Merged);
    assert_eq!(seq(&a), sa);
    assert_eq!(merged(&a), merged(&b));
}

/// A manual initiator: the handshake under `auth`/`link` with an optional
/// wrong confirm, up to the record channel.
fn manual_initiator<'c>(
    addr: SocketAddr,
    link: &LinkKey,
    confirm: Option<[u8; 32]>,
) -> Option<Channel<'c>> {
    let auth = link.session_auth().unwrap();
    let nonce = qv_crypto::random_array::<32>().unwrap();
    let (dk, ek) = XWingDecapsKey::generate().unwrap();
    let attempt = sync_attempt(&auth, &nonce, dk, &ek).unwrap();
    let mut conn = Conn::new(TcpStream::connect(addr).unwrap(), &never).unwrap();
    conn.within(Duration::from_secs(5), None);
    conn.send_frame(FramePhase::Handshake, &attempt.hello)
        .unwrap();
    let mut buf = Vec::new();
    conn.recv_frame(FramePhase::Handshake, &mut buf).ok()?;
    let (ct, accept_hash) = check_sync_accept(&auth, &attempt.hello_hash, &buf).unwrap();
    let ss = attempt.dk.decapsulate(&ct).unwrap();
    let th = session_th(&attempt.hello_hash, &accept_hash).unwrap();
    let (i2r, r2i) = session_keys(&ss, link, &th).unwrap();
    let mut ch = Channel::new(conn, RecordSealer::new(i2r), RecordOpener::new(r2i));
    ch.send(
        &Confirm::encode(&confirm.unwrap_or(th)).unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
    Some(ch)
}

fn random_link() -> LinkKey {
    qv_crypto::lan::vectors::link_key_from(qv_crypto::random_array::<32>().unwrap()).unwrap()
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_sync_refuses_unauthenticated_replayed_and_unconfirmed_initiators() {
    let (a, b, id) = linked();
    let sb = seq(&b);
    let (end, rounds, _) = with_window(&b, false, |addr| {
        // A wrong link: no reply at all.
        assert_eq!(
            sync(&random_link(), &[addr], LOOPBACK, &a, &fast(), &never).unwrap_err(),
            LanError::NoPeer
        );
        // A replayed hello: the first is answered, the identical second not.
        let auth = key(&a, &id).session_auth().unwrap();
        let (dk, ek) = XWingDecapsKey::generate().unwrap();
        let hello = sync_attempt(&auth, &[0x5a; 32], dk, &ek).unwrap().hello;
        assert!(poke(addr, &hello));
        assert!(!poke(addr, &hello));
        // A wrong confirm: closed without a reply.
        let mut ch = manual_initiator(addr, &key(&a, &id), Some([0; 32])).unwrap();
        assert!(ch.recv(Duration::from_secs(3), None).is_err());
    });
    assert_eq!(end, WindowEnd::Cancelled);
    assert!(rounds.is_empty(), "no round passed the handshake");
    assert_eq!(seq(&b), sb);
}

#[test]
fn lan_sync_a_removed_link_stops_working_in_an_open_window() {
    let (a, b, id) = linked();
    let (end, rounds, _) = with_window(&b, false, |addr| {
        {
            let mut u = b.u();
            let mut w = u.write().unwrap();
            w.remove_lan_link(&id).unwrap();
            w.commit().unwrap();
        }
        assert_eq!(
            sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never).unwrap_err(),
            LanError::NoPeer
        );
    });
    assert_eq!(end, WindowEnd::Cancelled);
    assert!(rounds.is_empty());
}

#[test]
fn lan_sync_initiator_skips_spoofed_and_reflecting_responders() {
    let (a, b, id) = linked();
    let link = key(&a, &id);
    // A responder that reflects the hello's own tag in its accept (K_i
    // instead of K_r) and one that answers garbage.
    let reflect = TcpListener::bind("127.0.0.1:0").unwrap();
    let garbage = TcpListener::bind("127.0.0.1:0").unwrap();
    let (ra, ga) = (reflect.local_addr().unwrap(), garbage.local_addr().unwrap());
    let auth: SessionAuth = link.session_auth().unwrap();
    let (end, _, r) = std::thread::scope(|s| {
        s.spawn(|| {
            let (stream, _) = reflect.accept().unwrap();
            let mut conn = Conn::new(stream, &never).unwrap();
            conn.within(Duration::from_secs(5), None);
            let mut buf = Vec::new();
            conn.recv_frame(FramePhase::Handshake, &mut buf).unwrap();
            let hash = qv_crypto::lan::transcript_hash(&buf);
            let ct = [2u8; 1120];
            let t = SyncAccept::transcript(&hash, &[1; 32], &ct).unwrap();
            let mac = auth.hello_mac(&t).unwrap();
            let accept = SyncAccept::encode(&[1; 32], &ct, mac.as_bytes()).unwrap();
            let _ = conn.send_frame(FramePhase::Handshake, &accept);
        });
        s.spawn(|| {
            let (stream, _) = garbage.accept().unwrap();
            let mut conn = Conn::new(stream, &never).unwrap();
            conn.within(Duration::from_secs(5), None);
            let mut buf = Vec::new();
            let _ = conn.recv_frame(FramePhase::Handshake, &mut buf);
            let _ = conn.send_frame(FramePhase::Handshake, b"\x80");
        });
        with_window(&b, false, |addr| {
            sync(&link, &[ra, ga, addr], LOOPBACK, &a, &fast(), &never)
        })
    });
    assert_eq!(end, WindowEnd::Completed);
    assert_eq!(r.unwrap().local, Outcome::Unchanged);
}

/// Sends `msgs` after the handshake and returns what the responder answers.
fn responder_answer(
    b: &Device,
    link: &LinkKey,
    script: impl FnOnce(&mut Channel<'_>) + Send,
) -> (Result<SecretBytes, LanError>, Rounds) {
    let (_, rounds, answer) = with_window(b, false, |addr| {
        let mut ch = manual_initiator(addr, link, None).unwrap();
        script(&mut ch);
        // Skip the responder's ordinary turns until its refusal; error
        // records come back as `Err`.
        loop {
            match ch.recv(Duration::from_secs(5), None) {
                Ok(_) => continue,
                other => break other,
            }
        }
    });
    (answer, rounds)
}

#[test]
fn lan_sync_responder_refuses_bad_states_and_requests() {
    let (a, b, id) = linked();
    edit(&b, record(), "something to request");
    let link = key(&a, &id);
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
    for (expected, script) in cases {
        let (answer, rounds) = responder_answer(&b, &link, script);
        assert_eq!(answer.err(), Some(expected));
        assert_eq!(rounds[0].1.unwrap_err(), expected);
    }
}

#[test]
fn lan_sync_responder_refuses_a_63rd_want_message() {
    let (a, b, id) = linked();
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
    let (answer, rounds) = responder_answer(&b, &key(&a, &id), |ch| {
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
    assert_eq!(rounds[0].1.unwrap_err(), LanError::Protocol);
}

#[test]
fn lan_sync_windows_close_on_failures_and_expiry_and_serve_one_session_at_a_time() {
    let (a, b, id) = linked();
    // 16 garbage hellos close the window.
    let (end, rounds, _) = with_window(&b, true, |addr| {
        for _ in 0..16 {
            assert!(!poke(addr, b"garbage"));
        }
        // Let the window see the 16th failure before it is closed.
        std::thread::sleep(Duration::from_millis(300));
    });
    assert_eq!(end, WindowEnd::TooManyAttempts);
    assert!(rounds.is_empty());
    // Expiry.
    let w = ReceiveWindow::open(
        ListenScope::LoopbackForTests,
        None,
        Duration::from_millis(300),
        false,
    )
    .unwrap();
    let started = Instant::now();
    assert_eq!(
        w.run(&b, &fast(), &never, &mut |_, _| {}).unwrap(),
        WindowEnd::Expired
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    // Stay open: two rounds; a connection during a round is closed unread.
    let extra = AtomicUsize::new(0);
    let (end, rounds, _) = with_window(&b, true, |addr| {
        edit(&a, record(), "first");
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never).unwrap();
        let ch = manual_initiator(addr, &key(&a, &id), None).unwrap();
        // While that session runs, another connection gets nothing.
        if !poke(addr, b"anything") {
            extra.fetch_add(1, Ordering::SeqCst);
        }
        ch.conn.close();
        edit(&a, record(), "second");
        sync(&key(&a, &id), &[addr], LOOPBACK, &a, &fast(), &never).unwrap();
    });
    assert_eq!(end, WindowEnd::Cancelled);
    assert_eq!(extra.load(Ordering::SeqCst), 1);
    let ok = rounds.iter().filter(|(_, r)| r.is_ok()).count();
    assert_eq!(ok, 2);
    assert_eq!(merged(&a), merged(&b));
}

#[test]
fn lan_sync_cancel_during_a_connection_attempt_is_prompt() {
    let (a, _b, id) = linked();
    let stop = AtomicBool::new(false);
    let cancel = || stop.load(Ordering::SeqCst);
    // TEST-NET-1 is never routed to a host: the connect blocks until its
    // limit unless the network refuses it at once.
    let blackhole = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);
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
        sync(
            &key(&a, &id),
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

// 0012 §1: LAN partial acceptance
#[test]
fn lan_sync_expiry_closes_an_authenticated_connection_and_listener() {
    let (a, b, id) = linked();
    edit(&a, record(), "must not arrive after expiry");
    let before = seq(&b);
    let w = ReceiveWindow::open(
        ListenScope::LoopbackForTests,
        None,
        Duration::from_millis(700),
        false,
    )
    .unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), w.port().unwrap());
    let started = Instant::now();
    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let mut rounds = Vec::new();
            let end = w
                .run(&b, &fast(), &never, &mut |_, r| rounds.push(r))
                .unwrap();
            (end, rounds)
        });
        let mut ch = manual_initiator(addr, &key(&a, &id), None).unwrap();
        // The authenticated peer stalls before its State. The long per-message
        // timeout must not extend the shorter window.
        let (end, rounds) = h.join().unwrap();
        assert_eq!(end, WindowEnd::Expired);
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0], Err(LanError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(
            TcpStream::connect(addr).is_err(),
            "listener dropped at expiry"
        );
        let late = super::super::exchange::exchange(
            &mut ch,
            super::super::exchange::Role::Initiator,
            &a,
            &fast(),
        );
        assert!(late.is_err());
    });
    assert_eq!(seq(&b), before);
}
