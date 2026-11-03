// SPDX-License-Identifier: AGPL-3.0-or-later

//! The approving device's pairing window (0013 §4, §8; plan 0037 decision 6).
//!
//! [`PairingWindow::run`] runs the protocol on the caller's thread. One
//! scoped acceptor thread polls the listener and hands it one connection at
//! a time.
//! - While a hello is being checked, other connections close at once,
//!   unanswered.
//! - Once a valid hello was accepted, the window is used. The acceptor reads
//!   one frame from each extra connection, never answers, and closes it.
//!   Identical bytes are refused. A different valid hello means the code was
//!   observed, so the pairing aborts. Anything else counts as a failed
//!   attempt.
//! - The window closes at 16 failed attempts, at its time limit, on cancel
//!   or lock, or when the pairing completes or aborts.

use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use qv_crypto::lan::{
    LinkKey, LinkRoot, PairNonce, PairingKeys, PairingSecret, ProofRole, RecordOpener,
    RecordSealer, Sas,
};
use qv_crypto::{KeyGeneration, MacTag, SecretBytes, VaultId, random_array};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::{JoinMode, PairProve, PairProved, PairReveal};
use qv_protocol::oob::{WireEndpoint, encode_manual, encode_qr};
use qv_protocol::registry::LanProfile;
use qv_store::LanServeState;
use zeroize::Zeroizing;

use super::endpoint::{ListenScope, advertisable, bind_addrs};
use super::steps::{accept_for, check_hello, record_keys, th};
use super::transport::{Channel, Conn, guarded};
use super::{LanError, LanTimeouts, PAIRING_WINDOW_MAX, exchange};

/// Failed attempts that close a window (0013 §8.3).
const MAX_FAILURES: u32 = 16;
/// Acceptor poll interval.
const POLL: Duration = Duration::from_millis(25);

/// What the approving vault provides.
pub struct ApproverContext {
    /// The vault ID.
    pub vault_id: VaultId,
    /// The key generation.
    pub key_generation: KeyGeneration,
    /// The vault's name, shown with the comparison code.
    pub vault_name: SecretBytes,
    /// `K_lan` of this generation.
    pub root: LinkRoot,
}

/// The approving device's vault, reached through short calls (qv-core
/// implements it over a session).
pub trait ApproverVault: Sync {
    /// The vault's identity and link root.
    fn context(&self) -> Result<ApproverContext, LanError>;
    /// Commits the new link row (0013 §9.1).
    fn commit_link(&self, link_id: [u8; 16], key: &LinkKey) -> Result<(), LanError>;
    /// Builds the grant plaintext ([`super::grant_plaintext`]) and passes it
    /// to `send`, which seals and sends it at once.
    fn grant(
        &self,
        link_id: &[u8; 16],
        send: &mut dyn FnMut(&[u8]) -> Result<(), LanError>,
    ) -> Result<(), LanError>;
    /// The committed state to serve.
    fn serve_state(&self) -> Result<LanServeState, LanError>;
    /// One object envelope of `state`.
    fn object(&self, state: &LanServeState, id: qv_model::ObjectId) -> Result<Vec<u8>, LanError>;
}

/// Shows the comparison code and waits for the user (0013 §4.5).
pub trait Confirm {
    /// `true` once the user confirmed that both devices show `sas`. It must
    /// return promptly when the frontend's cancellation fires.
    fn confirm(&mut self, sas: &Sas, mode: JoinMode, vault_name: &[u8]) -> bool;
}

/// A completed pairing on the approving side.
#[derive(Debug)]
pub struct Approved {
    /// The joiner's mode.
    pub mode: JoinMode,
    /// The committed link.
    pub link_id: [u8; 16],
    /// Whether the joiner confirmed completion (new device: its `Done`; link
    /// mode: its `PairDone`). Otherwise the pairing may be incomplete on the
    /// other device; the link stays (0013 §4.7).
    pub peer_confirmed: bool,
    /// Why the exchange after the link commit failed, if it did.
    pub failure: Option<LanError>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for a connection.
    Idle,
    /// Checking a hello.
    Checking,
    /// A valid hello was accepted.
    Used,
}

struct Shared {
    phase: Mutex<(Phase, Zeroizing<Vec<u8>>)>,
    failures: AtomicU32,
    observed: AtomicBool,
    finished: AtomicBool,
}

impl Shared {
    fn phase(&self) -> Phase {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner).0
    }
    fn set(&self, p: Phase, hello: Option<&[u8]>) {
        let mut g = self.phase.lock().unwrap_or_else(PoisonError::into_inner);
        g.0 = p;
        if let Some(h) = hello {
            g.1 = Zeroizing::new(h.to_vec());
        }
    }
    fn fail(&self) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }
}

/// An open pairing window for one unlocked vault (0013 §8.1).
pub struct PairingWindow {
    listener: TcpListener,
    keys: PairingKeys,
    scope: ListenScope,
    expires: Instant,
}

impl core::fmt::Debug for PairingWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairingWindow(<redacted>)")
    }
}

impl PairingWindow {
    /// Draws `P` and listens on `port` (or an OS-chosen one) for at most
    /// `limit` (≤ 10 minutes).
    pub fn open(scope: ListenScope, port: Option<u16>, limit: Duration) -> Result<Self, LanError> {
        if limit.is_zero() || limit > PAIRING_WINDOW_MAX {
            return Err(LanError::Protocol);
        }
        let keys = PairingSecret::generate()
            .and_then(PairingSecret::keys)
            .map_err(|_| LanError::Io)?;
        let listener = bind_addrs(scope, port.unwrap_or(0))
            .into_iter()
            .find_map(|a| TcpListener::bind(a).ok())
            .ok_or(LanError::Io)?;
        listener.set_nonblocking(true).map_err(|_| LanError::Io)?;
        Ok(Self {
            listener,
            keys,
            scope,
            expires: Instant::now() + limit,
        })
    }

    /// The listening port.
    pub fn port(&self) -> Result<u16, LanError> {
        Ok(self.listener.local_addr().map_err(|_| LanError::Io)?.port())
    }

    /// When the window closes.
    pub fn expires_at(&self) -> Instant {
        self.expires
    }

    /// The QR payload naming up to 8 of `addrs` with this window's port.
    /// Addresses the scope cannot serve are skipped. Discovery is off, so
    /// the instance is empty.
    pub fn qr(&self, addrs: &[IpAddr]) -> Result<Zeroizing<Vec<u8>>, LanError> {
        let port = self.port()?;
        let endpoints: Vec<WireEndpoint> = addrs
            .iter()
            .filter(|ip| advertisable(self.scope, ip))
            .take(qv_protocol::oob::MAX_QR_ENDPOINTS)
            .map(|&addr| WireEndpoint { addr, port })
            .collect();
        encode_qr(
            LanProfile::V1,
            self.keys.secret().expose_secret(),
            &endpoints,
            "",
        )
        .map_err(|_| LanError::Protocol)
    }

    /// The 26-character manual code, in groups of five.
    pub fn manual_code(&self) -> Zeroizing<String> {
        encode_manual(self.keys.secret().expose_secret())
    }

    /// Runs the window until a pairing completes or the window closes.
    pub fn run(
        self,
        vault: &dyn ApproverVault,
        confirm: &mut dyn Confirm,
        timeouts: &LanTimeouts,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Approved, LanError> {
        timeouts.validate()?;
        let shared = Shared {
            phase: Mutex::new((Phase::Idle, Zeroizing::new(Vec::new()))),
            failures: AtomicU32::new(0),
            observed: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        };
        let (tx, rx) = sync_channel::<TcpStream>(1);
        let keys = &self.keys;
        let expires = self.expires;
        let listener = &self.listener;
        std::thread::scope(|s| {
            s.spawn(|| acceptor(listener, keys, &shared, &tx, timeouts, expires, cancelled));
            let r = worker(
                keys, &shared, &rx, vault, confirm, timeouts, expires, cancelled,
            );
            shared.finished.store(true, Ordering::SeqCst);
            r
        })
    }
}

fn closing(shared: &Shared, expires: Instant, cancelled: &dyn Fn() -> bool) -> Option<LanError> {
    if shared.observed.load(Ordering::SeqCst) {
        Some(LanError::CodeObserved)
    } else if cancelled() {
        Some(LanError::Cancelled)
    } else if shared.failures.load(Ordering::SeqCst) >= MAX_FAILURES {
        Some(LanError::TooManyAttempts)
    } else if Instant::now() >= expires {
        Some(LanError::WindowExpired)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)] // the window's shared state
fn acceptor(
    listener: &TcpListener,
    keys: &PairingKeys,
    shared: &Shared,
    tx: &SyncSender<TcpStream>,
    t: &LanTimeouts,
    expires: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
) {
    while !shared.finished.load(Ordering::SeqCst) && closing(shared, expires, cancelled).is_none() {
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(_) => {
                std::thread::sleep(POLL);
                continue;
            }
        };
        match shared.phase() {
            Phase::Idle => {
                shared.set(Phase::Checking, None);
                if tx.try_send(stream).is_err() {
                    shared.set(Phase::Idle, None);
                }
            }
            Phase::Checking => drop(stream),
            Phase::Used => probe(stream, keys, shared, t, cancelled),
        }
    }
}

/// Reads one frame from an extra connection while the window is used
/// (0013 §8.3 clarification); never answers.
fn probe(
    stream: TcpStream,
    keys: &PairingKeys,
    shared: &Shared,
    t: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) {
    let Ok(mut conn) = Conn::new(stream, cancelled) else {
        return;
    };
    conn.within(t.probe, None);
    let mut buf = Vec::new();
    let read = conn.recv_frame(FramePhase::Handshake, &mut buf);
    conn.close();
    if read.is_err() {
        shared.fail();
        return;
    }
    let same = {
        let g = shared.phase.lock().unwrap_or_else(PoisonError::into_inner);
        g.1.as_slice() == buf.as_slice()
    };
    if same {
        return;
    }
    if check_hello(keys, &buf).is_ok() {
        shared.observed.store(true, Ordering::SeqCst);
    } else {
        shared.fail();
    }
}

#[allow(clippy::too_many_arguments)] // the window's shared state and the caller's hooks
fn worker(
    keys: &PairingKeys,
    shared: &Shared,
    rx: &Receiver<TcpStream>,
    vault: &dyn ApproverVault,
    confirm: &mut dyn Confirm,
    t: &LanTimeouts,
    expires: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<Approved, LanError> {
    loop {
        if let Some(e) = closing(shared, expires, cancelled) {
            return Err(e);
        }
        let stream = match rx.recv_timeout(POLL) {
            Ok(s) => s,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return Err(LanError::Io),
        };
        let Ok(mut conn) = Conn::new(stream, cancelled) else {
            shared.set(Phase::Idle, None);
            continue;
        };
        conn.within(t.message, Some(expires));
        let mut buf = Vec::new();
        let hello = conn
            .recv_frame(FramePhase::Handshake, &mut buf)
            .ok()
            .and_then(|()| check_hello(keys, &buf).ok());
        let Some(hello) = hello else {
            // Close, send nothing, count it (§4.3).
            conn.close();
            shared.fail();
            shared.set(Phase::Idle, None);
            continue;
        };
        shared.set(Phase::Used, Some(&buf));
        return pair(
            conn, keys, shared, hello, vault, confirm, t, expires, cancelled,
        );
    }
}

#[allow(clippy::too_many_arguments)] // one pairing's state and the caller's hooks
fn pair(
    mut conn: Conn<'_>,
    keys: &PairingKeys,
    shared: &Shared,
    hello: super::steps::CheckedHello,
    vault: &dyn ApproverVault,
    confirm: &mut dyn Confirm,
    t: &LanTimeouts,
    expires: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<Approved, LanError> {
    let observed = || {
        if shared.observed.load(Ordering::SeqCst) {
            Err(LanError::CodeObserved)
        } else {
            Ok(())
        }
    };
    // Encapsulate only after every hello check passed (§5.1's rule holds
    // here too: no KEM work before the MAC).
    let (ss, ct) = hello.ek.encapsulate().map_err(|_| LanError::Io)?;
    let nonce_a = random_array::<32>().map_err(|_| LanError::Io)?;
    let (accept, accept_hash) = accept_for(keys, &hello.hash, &nonce_a, &ct)?;
    conn.within(t.message, Some(expires));
    conn.send_frame(FramePhase::Handshake, &accept)?;
    let th = th(&hello.hash, &accept_hash)?;
    let (b2a, a2b) = record_keys(keys, &ss, &th)?;
    let mut ch = Channel::new(conn, RecordSealer::new(a2b), RecordOpener::new(b2a));
    let mode = hello.mode;
    let ctx = vault.context();
    let pre = guarded(&mut ch, |ch| {
        let ctx = ctx?;
        let msg = ch.recv(t.message, Some(expires))?;
        let reveal = PairReveal::decode(msg.expose_secret()).map_err(|_| LanError::Protocol)?;
        let nonce_b = PairNonce::from_bytes(&*reveal.nonce_b).map_err(|_| LanError::Protocol)?;
        if !nonce_b
            .matches(&hello.commit)
            .map_err(|_| LanError::Protocol)?
        {
            return Err(LanError::Protocol);
        }
        let sas = Sas::compute(&th, &nonce_b).map_err(|_| LanError::Protocol)?;
        observed()?;
        let ok = confirm.confirm(&sas, mode, ctx.vault_name.expose_secret());
        observed()?;
        if cancelled() {
            return Err(LanError::Cancelled);
        }
        if Instant::now() >= expires {
            return Err(LanError::WindowExpired);
        }
        if !ok {
            return Err(LanError::Cancelled);
        }
        Ok((ctx, nonce_b))
    })?;
    let (ctx, nonce_b) = pre;
    match mode {
        JoinMode::NewDevice => {
            let link_id = random_array::<16>().map_err(|_| LanError::Io)?;
            let link = ctx
                .root
                .link_key(
                    &ss,
                    &th,
                    &nonce_b,
                    &link_id,
                    ctx.vault_id,
                    ctx.key_generation,
                )
                .map_err(|_| LanError::Protocol);
            guarded(&mut ch, |ch| {
                observed()?;
                vault.commit_link(link_id, &link?)?;
                vault.grant(&link_id, &mut |plaintext| ch.send(plaintext, t.message))
            })?;
            drop(ss);
            let failure = guarded(&mut ch, |ch| {
                exchange::serve(ch, vault, ctx.vault_id, ctx.key_generation, t)
            })
            .err();
            Ok(Approved {
                mode,
                link_id,
                peer_confirmed: failure.is_none(),
                failure,
            })
        }
        JoinMode::Link => {
            let link_id = random_array::<16>().map_err(|_| LanError::Io)?;
            guarded(&mut ch, |ch| {
                let msg = ch.recv(t.confirm, Some(expires))?;
                let prove =
                    PairProve::decode(msg.expose_secret()).map_err(|_| LanError::Protocol)?;
                if prove.vault_id != ctx.vault_id.0 || prove.key_generation != ctx.key_generation.0
                {
                    return Err(LanError::VaultMismatch);
                }
                ctx.root
                    .verify_proof(
                        &th,
                        ProofRole::B,
                        ctx.vault_id,
                        ctx.key_generation,
                        &MacTag::from_bytes(prove.proof),
                    )
                    .map_err(|_| LanError::VaultMismatch)?;
                observed()?;
                let link = ctx
                    .root
                    .link_key(
                        &ss,
                        &th,
                        &nonce_b,
                        &link_id,
                        ctx.vault_id,
                        ctx.key_generation,
                    )
                    .map_err(|_| LanError::Protocol)?;
                vault.commit_link(link_id, &link)?;
                Ok(())
            })?;
            drop(ss);
            // The link is committed: a later failure leaves it (§4.8).
            let failure = guarded(&mut ch, |ch| {
                let proof = ctx
                    .root
                    .proof(&th, ProofRole::A, ctx.vault_id, ctx.key_generation)
                    .map_err(|_| LanError::Protocol)?;
                ch.send(
                    &PairProved::encode(&link_id, proof.as_bytes())
                        .map_err(|_| LanError::Protocol)?,
                    t.message,
                )?;
                let msg = ch.recv(t.idle, None)?;
                qv_protocol::lan::PairDone::decode(msg.expose_secret())
                    .map_err(|_| LanError::Protocol)?;
                // The post-pairing exchange arrives in phase 2.10.
                ch.conn.close();
                Ok(())
            })
            .err();
            Ok(Approved {
                mode,
                link_id,
                peer_confirmed: failure.is_none(),
                failure,
            })
        }
    }
}
