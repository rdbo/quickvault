// SPDX-License-Identifier: AGPL-3.0-or-later

//! The offering device's sync window (0013 §4, §8; plans 0037 decision 6,
//! 0042).
//!
//! Admission is consumed by the first fully valid hello. The listener closes
//! before the accepted session proceeds; later sockets cannot interrupt it.

use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use qv_crypto::lan::v2::{PairingKeys, Role as CryptoRole};
use qv_crypto::lan::{PairNonce, PairingSecret, Sas};
use qv_crypto::{KeyGeneration, MacTag, SecretBytes, VaultId, random_array};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::v2::{
    AuthMode, Finished, KeyProve, KeyProved, PakeFinish, PakeResponse, PakeStart,
};
use qv_protocol::oob::{WireEndpoint, encode_manual, encode_qr};
use qv_protocol::registry::LanProfile;
use zeroize::Zeroizing;

use super::endpoint::{ListenScope, advertisable, bind_addrs};
use super::exchange::{ExchangeVault, Role, RoundReport};
use super::steps_v2::{accept_for, auth_transcript, check_hello, crypto_mode, outer_transcript};
use super::transport::{Conn, V2Channel};
use super::window::{POLL, Phase, Shared, acceptor, closing};
use super::{LanError, LanTimeouts, PAIRING_WINDOW_MAX, exchange};

/// What the offering vault provides.
pub struct ApproverContext {
    /// The vault ID.
    pub vault_id: VaultId,
    /// The key generation.
    pub key_generation: KeyGeneration,
    /// The vault's name, shown with the comparison code.
    pub vault_name: SecretBytes,
}

/// The offering device's vault, reached through short calls (qv-core
/// implements it over a session).
pub trait ApproverVault: ExchangeVault {
    /// The vault's identity and proof key.
    fn context(&self) -> Result<ApproverContext, LanError>;
}

/// Credential-authenticated vault boundary (0013 §15). The implementation
/// owns its private one-use authorization; the network driver cannot forge it.
pub trait CredentialApprover: ApproverVault {
    /// Private snapshot/authorization type owned by the core implementation.
    type Authorization;
    /// Reauthenticate locally, then create a fresh one-shot server outside
    /// the session mutex. A local WrongPassword may be corrected without
    /// sending a network response or creating a second remote attempt.
    fn authenticate_password(
        &self,
        password: qv_crypto::MasterPassword,
        t0: &[u8; 32],
        ke1: &[u8],
    ) -> Result<
        (
            qv_crypto::lan_auth::PasswordAuthServer,
            SecretBytes,
            Self::Authorization,
        ),
        LanError,
    >;
    /// Rechecks the captured slot/head/session before emitting KE2.
    fn check_authorization(&self, authorization: &Self::Authorization) -> Result<(), LanError>;
    /// Independent key proof state, derived under a short session read.
    fn key_auth(
        &self,
        mode: qv_crypto::lan::v2::AuthMode,
        t0: [u8; 32],
    ) -> Result<qv_crypto::lan::v2::KeyAuthentication, LanError>;
    /// Consumes authorization and seals exactly once with the bound final
    /// sealer under the same mutex as all policy/head/slot checks.
    fn authorized_grant(
        &self,
        authorization: Self::Authorization,
        sealer: &mut qv_crypto::lan::v2::RecordSealer<qv_crypto::lan::v2::FinalEpoch>,
    ) -> Result<SealedGrant, LanError>;
}

/// A completed seal counts as possible disclosure even if its pending frame
/// was discarded. This result must never be converted into a pre-grant error.
pub enum SealedGrant {
    /// Ready to send once; still check cancellation/deadline before I/O.
    Ready(Zeroizing<Vec<u8>>),
    /// Sealing completed, but cancellation/expiry discarded the output.
    Discarded(LanError),
}

/// Shows a new device's comparison code and waits for the user (0013 §4.5).
/// Sync mode never calls it.
pub trait Confirm {
    /// Admission is consumed and every listener has been dropped. Clear the
    /// displayed code; this event does not establish credential authentication.
    fn admitted(&mut self) {}
    /// `true` once the user confirmed that both devices show `sas`. It must
    /// return promptly when the frontend's cancellation fires.
    fn confirm(&mut self, sas: &Sas, vault_name: &[u8]) -> bool;
    /// Protected password entry after comparison approval. `retry` reports a
    /// local typo only; no remote credential retry is permitted.
    fn password(
        &mut self,
        sas: &Sas,
        vault_name: &[u8],
        retry: bool,
    ) -> Option<qv_crypto::MasterPassword>;
}

/// The window's one session, completed on the offering side.
#[derive(Debug)]
pub enum Approved {
    /// A new device joined (0013 §4.7).
    Joined {
        /// A password grant was sealed; delivery may remain unknown.
        key_disclosed: bool,
        /// Whether the new device sent its `Done`. Otherwise it may not
        /// have finished joining.
        peer_confirmed: bool,
        /// Why the transfer failed after the grant, if it did.
        failure: Option<LanError>,
    },
    /// One sync with a copy of this vault (0013 §4.8).
    Synced(RoundReport),
}

/// An open sync window for one unlocked vault (0013 §8.1).
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
            .and_then(PairingKeys::new)
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
            LanProfile::V2,
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

    /// Runs the window until its one session ends or the window closes.
    pub fn run<V: CredentialApprover>(
        self,
        vault: &V,
        confirm: &mut dyn Confirm,
        timeouts: &LanTimeouts,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Approved, LanError> {
        timeouts.validate()?;
        let shared = Shared::new();
        let (tx, rx) = sync_channel::<TcpStream>(1);
        let keys = &self.keys;
        let expires = self.expires;
        let listener = self.listener;
        let (conn, hello) = std::thread::scope(|s| {
            let shared_ref = &shared;
            s.spawn(move || acceptor(listener, shared_ref, &tx, expires, cancelled));
            let result = admit(keys, &shared, &rx, timeouts, expires, cancelled);
            shared.finished.store(true, Ordering::SeqCst);
            result
        })?;
        confirm.admitted();
        // The scope has joined the listener owner. No listener (or clone)
        // remains when any KEM/credential/session work starts.
        pair(
            conn, self.keys, hello, vault, confirm, timeouts, expires, cancelled,
        )
    }
}

#[allow(clippy::too_many_arguments)] // the window's shared state and the caller's hooks
fn admit<'c>(
    keys: &PairingKeys,
    shared: &Shared,
    rx: &Receiver<TcpStream>,
    t: &LanTimeouts,
    expires: Instant,
    cancelled: &'c (dyn Fn() -> bool + Sync),
) -> Result<(Conn<'c>, super::steps_v2::CheckedHello), LanError> {
    loop {
        if let Some(e) = closing(shared, expires, cancelled) {
            return Err(e);
        }
        let stream = match rx.recv_timeout(POLL) {
            Ok(s) => s,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(closing(shared, expires, cancelled).unwrap_or(LanError::Io));
            }
        };
        let Ok(mut conn) = Conn::new(stream, cancelled) else {
            shared.set(Phase::Idle);
            continue;
        };
        conn.cap(expires);
        conn.within(t.message, Some(expires));
        let mut buf = Vec::new();
        let hello = conn
            .recv_frame(FramePhase::Handshake, &mut buf)
            .ok()
            .and_then(|()| check_hello(keys, &buf).ok());
        let Some(hello) = hello else {
            // Count it, then close and send nothing (§4.3). Counting and going
            // idle first means a client that reconnects at once is checked,
            // not refused uncounted while this one is still `Checking`.
            shared.fail();
            shared.set(Phase::Idle);
            conn.close();
            continue;
        };
        return Ok((conn, hello));
    }
}

#[allow(clippy::too_many_arguments)] // One accepted connection, original deadline and caller hooks.
fn pair<V: CredentialApprover>(
    mut conn: Conn<'_>,
    keys: PairingKeys,
    hello: super::steps_v2::CheckedHello,
    vault: &V,
    confirm: &mut dyn Confirm,
    t: &LanTimeouts,
    expires: Instant,
    _cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<Approved, LanError> {
    let mode = hello.mode;
    let (ss, ct) = hello.ek.encapsulate().map_err(|_| LanError::Io)?;
    let nonce = random_array::<32>().map_err(|_| LanError::Io)?;
    let (accept, accept_hash) = accept_for(&keys, &hello, nonce, &ct)?;
    conn.within(t.message, Some(expires));
    conn.send_frame(FramePhase::Handshake, &accept)?;
    let t0 = outer_transcript(mode, &hello.hash, &accept_hash)?;
    let (schedule, initial) = keys
        .begin(ss, crypto_mode(mode), t0)
        .map_err(|_| LanError::Integrity)?;
    let mut ch = V2Channel::initial(conn, initial, CryptoRole::Offerer);
    let ctx = vault.context()?;
    match mode {
        AuthMode::PasswordEnrollment => {
            let r = ch.recv(t.confirm, None)?;
            let start = PakeStart::decode(r.expose_secret()).map_err(|_| LanError::Integrity)?;
            let nonce = PairNonce::from_bytes(&start.nonce).map_err(|_| LanError::Integrity)?;
            if qv_crypto::lan::v2::nonce_commitment(&nonce).map_err(|_| LanError::Integrity)?
                != hello.commit
            {
                return Err(LanError::Integrity);
            }
            let sas = qv_crypto::lan::v2::comparison_code(crypto_mode(mode), &t0, &nonce)
                .map_err(|_| LanError::Integrity)?;
            let mut retry = false;
            let (server, ke2, authorization) = loop {
                ch.check()?;
                let password = confirm
                    .password(&sas, ctx.vault_name.expose_secret(), retry)
                    .ok_or(LanError::Cancelled)?;
                ch.check()?;
                match vault.authenticate_password(password, &t0, start.ke1) {
                    Ok(result) => break result,
                    Err(LanError::Store(qv_store::StoreError::WrongPassword)) => retry = true,
                    Err(error) => return Err(error),
                }
            };
            let s = PakeResponse {
                ke2: ke2
                    .expose_secret()
                    .try_into()
                    .map_err(|_| LanError::Integrity)?,
            }
            .encode()
            .map_err(|_| LanError::Protocol)?;
            drop(ke2);
            vault.check_authorization(&authorization)?;
            ch.send(&s, t.message)?;
            let f = ch.recv(t.message, None)?;
            let finish = PakeFinish::decode(f.expose_secret()).map_err(|_| LanError::Integrity)?;
            let auth = server.finish(finish.ke3).map_err(|_| LanError::Integrity)?;
            let ta = auth_transcript(mode, &t0, r.expose_secret(), &s, Some(f.expose_secret()))?;
            drop((r, s, f));
            ch.check()?;
            let (final_keys, finished_key) = schedule
                .complete(auth, ta)
                .map_err(|_| LanError::Integrity)?;
            let mut ch = ch.finish(final_keys)?;
            let message = ch.recv(t.message, None)?;
            let finished =
                Finished::decode(message.expose_secret()).map_err(|_| LanError::Integrity)?;
            finished_key
                .verify(&MacTag::from_bytes(*finished.mac))
                .map_err(|_| LanError::Integrity)?;
            drop((message, finished_key));
            ch.check()?;
            let sealed = vault.authorized_grant(authorization, &mut ch.sealer)?;
            // From this point every outcome must report possible disclosure.
            let failure = match sealed {
                SealedGrant::Discarded(error) => Some(error),
                SealedGrant::Ready(record) => ch.send_sealed(&record, t.message).err(),
            };
            if let Some(error) = failure {
                ch.conn.close();
                return Ok(Approved::Joined {
                    key_disclosed: true,
                    peer_confirmed: false,
                    failure: Some(error),
                });
            }
            let result = (|| {
                let first =
                    exchange::first_state(&mut ch, ctx.vault_id, ctx.key_generation, true, t)?;
                exchange::serve(&mut ch, vault, ctx.vault_id, ctx.key_generation, first, t)
            })();
            let failure = result.err().map(|error| ch.abort(error));
            ch.conn.close();
            Ok(Approved::Joined {
                key_disclosed: true,
                peer_confirmed: failure.is_none(),
                failure,
            })
        }
        AuthMode::KeyEnrollment | AuthMode::KeySync => {
            let first = ch.recv(
                if mode == AuthMode::KeyEnrollment {
                    t.confirm
                } else {
                    t.message
                },
                None,
            )?;
            let proof = KeyProve::decode(first.expose_secret()).map_err(|_| LanError::Integrity)?;
            let verified = vault
                .key_auth(crypto_mode(mode), t0)?
                .accept_joiner(&MacTag::from_bytes(*proof.mac))
                .map_err(|_| LanError::Integrity)?;
            let (mac, auth) = verified
                .offer(ctx.vault_id, ctx.key_generation)
                .map_err(|_| LanError::Integrity)?;
            let second = KeyProved {
                vault_id: ctx.vault_id.0,
                generation: ctx.key_generation.0,
                mac: *mac.as_bytes(),
            }
            .encode()
            .map_err(|_| LanError::Protocol)?;
            let ta = auth_transcript(mode, &t0, first.expose_secret(), &second, None)?;
            ch.send(&second, t.message)?;
            drop((first, second));
            let (final_keys, finished) = schedule
                .complete(auth, ta)
                .map_err(|_| LanError::Integrity)?;
            drop(finished);
            let mut ch = ch.finish(final_keys)?;
            let first = exchange::first_state(
                &mut ch,
                ctx.vault_id,
                ctx.key_generation,
                mode == AuthMode::KeyEnrollment,
                t,
            )?;
            let result = if mode == AuthMode::KeySync {
                exchange::exchange(&mut ch, Role::Responder, vault, Some(first), t)
                    .map(Approved::Synced)
            } else {
                let result =
                    exchange::serve(&mut ch, vault, ctx.vault_id, ctx.key_generation, first, t);
                Ok(Approved::Joined {
                    key_disclosed: false,
                    peer_confirmed: result.is_ok(),
                    failure: result.err(),
                })
            };
            let result = result.map_err(|error| ch.abort(error));
            ch.conn.close();
            result
        }
    }
}
