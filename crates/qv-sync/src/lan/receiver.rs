// SPDX-License-Identifier: AGPL-3.0-or-later

//! The receive window (0013 §5, §8; plan 0038 decision 7).
//!
//! A receive window listens for one unlocked vault, with the shared
//! acceptor of `window`. One session runs at a time; other connections
//! close at once, unanswered (no probe exception, unlike pairing). For each
//! connection the window:
//! 1. reads one hello;
//! 2. checks its shape and profile, then the tag under every link's `K_i`;
//! 3. refuses a `nonce_I` it has already seen;
//! 4. rechecks that the matched link still exists;
//! 5. checks the X-Wing key.
//!
//! Any failure there closes the connection, sends nothing and counts one
//! attempt. Then it answers, requires `Confirm(th)` as the first record (a
//! bad or missing confirm also counts as a failure, without a reply), and
//! runs one exchange as responder.
//!
//! The window closes at its limit (default 2 minutes, at most 15), on
//! cancel or lock, at 16 failed attempts, or after the first completed
//! round unless it stays open.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use qv_crypto::lan::{LinkKey, RecordOpener, RecordSealer, SessionAuth};
use qv_crypto::random_array;
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::Confirm;
use qv_protocol::oob::{WireEndpoint, encode_addr_qr};
use qv_protocol::registry::LanProfile;

use super::endpoint::{ListenScope, advertisable, bind_addrs};
use super::exchange::{ExchangeVault, Role, RoundReport, exchange};
use super::session::{
    CheckedSyncHello, check_sync_hello, session_keys, session_th, sync_accept_for,
};
use super::transport::{Channel, Conn, guarded};
use super::window::{POLL, Phase, Shared, acceptor, closing};
use super::{LanError, LanTimeouts};

/// The longest receive window (0013 §8.2).
pub const RECEIVE_WINDOW_MAX: Duration = Duration::from_secs(15 * 60);
/// The default receive window (0013 §8.2, Open Question 1).
pub const RECEIVE_WINDOW_DEFAULT: Duration = Duration::from_secs(2 * 60);

/// The responding vault: an exchange vault with its links.
pub trait ResponderVault: ExchangeVault {
    /// Every link of the vault (at most 64), decrypted for this window.
    fn links(&self) -> Result<Vec<([u8; 16], LinkKey)>, LanError>;
    /// Whether `link_id` is still a link of the vault.
    fn has_link(&self, link_id: &[u8; 16]) -> Result<bool, LanError>;
}

/// Why a receive window closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowEnd {
    /// A round completed and the window was not kept open.
    Completed,
    /// The time limit passed.
    Expired,
    /// A cancel or lock closed it.
    Cancelled,
    /// 16 failed attempts closed it (0013 §8.3).
    TooManyAttempts,
    /// The listener failed.
    Io,
}

/// An open receive window for one unlocked vault (0013 §8.1).
pub struct ReceiveWindow {
    listener: TcpListener,
    scope: ListenScope,
    expires: Instant,
    stay_open: bool,
}

impl core::fmt::Debug for ReceiveWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReceiveWindow(..)")
    }
}

impl ReceiveWindow {
    /// Listens on `port` (or an OS-chosen one) for at most `limit` (at most
    /// 15 minutes). With `stay_open`, the window serves further rounds
    /// within its limit.
    pub fn open(
        scope: ListenScope,
        port: Option<u16>,
        limit: Duration,
        stay_open: bool,
    ) -> Result<Self, LanError> {
        if limit.is_zero() || limit > RECEIVE_WINDOW_MAX {
            return Err(LanError::Protocol);
        }
        let listener = bind_addrs(scope, port.unwrap_or(0))
            .into_iter()
            .find_map(|a| TcpListener::bind(a).ok())
            .ok_or(LanError::Io)?;
        listener.set_nonblocking(true).map_err(|_| LanError::Io)?;
        Ok(Self {
            listener,
            scope,
            expires: Instant::now() + limit,
            stay_open,
        })
    }

    /// The listening port.
    pub fn port(&self) -> Result<u16, LanError> {
        Ok(self.listener.local_addr().map_err(|_| LanError::Io)?.port())
    }

    /// When the window closes on its own.
    pub fn expires_at(&self) -> Instant {
        self.expires
    }

    /// Up to 8 of `addrs` that this window serves, with its port.
    pub fn endpoints(&self, addrs: &[IpAddr]) -> Result<Vec<SocketAddr>, LanError> {
        let port = self.port()?;
        Ok(addrs
            .iter()
            .filter(|ip| advertisable(self.scope, ip))
            .take(qv_protocol::oob::MAX_QR_ENDPOINTS)
            .map(|&ip| SocketAddr::new(ip, port))
            .collect())
    }

    /// The address-only code (0013 §8.5) naming [`Self::endpoints`]. With no
    /// usable address there is no code ([`LanError::Io`]): the user types
    /// the address.
    pub fn qr(&self, addrs: &[IpAddr]) -> Result<Vec<u8>, LanError> {
        let endpoints: Vec<WireEndpoint> = self
            .endpoints(addrs)?
            .into_iter()
            .map(|a| WireEndpoint {
                addr: a.ip(),
                port: a.port(),
            })
            .collect();
        if endpoints.is_empty() {
            return Err(LanError::Io);
        }
        encode_addr_qr(LanProfile::V1, &endpoints).map_err(|_| LanError::Protocol)
    }

    /// Runs the window until it closes. `on_round` sees each round that
    /// passed the handshake: the link and the round's result. A failed
    /// round leaves the window open within its limit.
    pub fn run(
        self,
        vault: &dyn ResponderVault,
        timeouts: &LanTimeouts,
        cancelled: &(dyn Fn() -> bool + Sync),
        on_round: &mut dyn FnMut([u8; 16], Result<RoundReport, LanError>),
    ) -> Result<WindowEnd, LanError> {
        timeouts.validate()?;
        let links = vault.links()?;
        let mut auths = Vec::with_capacity(links.len());
        for (_, key) in &links {
            auths.push(key.session_auth().map_err(|_| LanError::Protocol)?);
        }
        let shared = Shared::new();
        let (tx, rx) = sync_channel::<TcpStream>(1);
        let expires = self.expires;
        let listener = self.listener;
        let window = Worker {
            shared: &shared,
            rx: &rx,
            vault,
            links: &links,
            auths: &auths,
            t: timeouts,
            expires,
            stay_open: self.stay_open,
            cancelled,
        };
        std::thread::scope(|s| {
            let shared_ref = &shared;
            s.spawn(move || acceptor(&listener, shared_ref, &tx, expires, cancelled, &drop));
            let end = window.run(on_round);
            shared.finished.store(true, Ordering::SeqCst);
            Ok(end)
        })
    }
}

struct Worker<'w> {
    shared: &'w Shared,
    rx: &'w Receiver<TcpStream>,
    vault: &'w dyn ResponderVault,
    links: &'w [([u8; 16], LinkKey)],
    auths: &'w [SessionAuth],
    t: &'w LanTimeouts,
    expires: Instant,
    stay_open: bool,
    cancelled: &'w (dyn Fn() -> bool + Sync),
}

/// How one authenticated-hello connection ended.
enum Served {
    /// The initiator never proved itself (accept send or confirm failed).
    Unconfirmed,
    /// A round ran.
    Round(Result<RoundReport, LanError>),
}

impl Worker<'_> {
    fn run(&self, on_round: &mut dyn FnMut([u8; 16], Result<RoundReport, LanError>)) -> WindowEnd {
        let mut seen = BTreeSet::new();
        loop {
            if let Some(e) = closing(self.shared, self.expires, self.cancelled) {
                return match e {
                    LanError::Cancelled => WindowEnd::Cancelled,
                    LanError::TooManyAttempts => WindowEnd::TooManyAttempts,
                    LanError::WindowExpired => WindowEnd::Expired,
                    _ => WindowEnd::Io,
                };
            }
            let stream = match self.rx.recv_timeout(POLL) {
                Ok(s) => s,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    // The acceptor owns the listener and drops its sender on
                    // expiry/cancel. Classify that closure on the next loop.
                    if closing(self.shared, self.expires, self.cancelled).is_some() {
                        continue;
                    }
                    return WindowEnd::Io;
                }
            };
            let Ok(mut conn) = Conn::new(stream, self.cancelled) else {
                self.shared.set(Phase::Idle, None);
                continue;
            };
            conn.cap(self.expires);
            conn.within(self.t.message, Some(self.expires));
            let mut buf = Vec::new();
            let hello = conn
                .recv_frame(FramePhase::Handshake, &mut buf)
                .ok()
                .and_then(|()| check_sync_hello(self.auths, &buf).ok())
                .filter(|h| seen.insert(h.nonce_i))
                .filter(|h| self.vault.has_link(&self.links[h.link].0).unwrap_or(false));
            let Some(hello) = hello else {
                // Close, send nothing, count it (§5.1).
                conn.close();
                self.shared.fail();
                self.shared.set(Phase::Idle, None);
                continue;
            };
            self.shared.set(Phase::Used, None);
            let link_id = self.links[hello.link].0;
            match self.respond(conn, hello) {
                Served::Unconfirmed => self.shared.fail(),
                Served::Round(result) => {
                    let ok = result.is_ok();
                    on_round(link_id, result);
                    if ok && !self.stay_open {
                        return WindowEnd::Completed;
                    }
                }
            }
            self.shared.set(Phase::Idle, None);
        }
    }

    fn respond(&self, mut conn: Conn<'_>, hello: CheckedSyncHello) -> Served {
        let (link, auth) = (&self.links[hello.link].1, &self.auths[hello.link]);
        let keys = (|| {
            let (ss, ct) = hello.ek.encapsulate().map_err(|_| LanError::Io)?;
            let nonce_r = random_array::<32>().map_err(|_| LanError::Io)?;
            let (accept, accept_hash) = sync_accept_for(auth, &hello.hash, &nonce_r, &ct)?;
            conn.within(self.t.message, Some(self.expires));
            conn.send_frame(FramePhase::Handshake, &accept)?;
            let th = session_th(&hello.hash, &accept_hash)?;
            let (i2r, r2i) = session_keys(&ss, link, &th)?;
            Ok::<_, LanError>((th, i2r, r2i))
        })();
        let Ok((th, i2r, r2i)) = keys else {
            conn.close();
            return Served::Unconfirmed;
        };
        let mut ch = Channel::new(conn, RecordSealer::new(r2i), RecordOpener::new(i2r));
        // I's first record must be Confirm(th) (§5.3); nothing is answered
        // otherwise. `th` is public, so a plain comparison suffices.
        let confirmed = ch
            .recv(self.t.message, Some(self.expires))
            .ok()
            .and_then(|m| Confirm::decode(m.expose_secret()).ok())
            .is_some_and(|c| c.th == th);
        if !confirmed {
            ch.conn.close();
            return Served::Unconfirmed;
        }
        let round = guarded(&mut ch, |ch| {
            exchange(ch, Role::Responder, self.vault, self.t)
        });
        ch.conn.close();
        Served::Round(round)
    }
}
