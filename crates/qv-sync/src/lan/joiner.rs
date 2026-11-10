// SPDX-License-Identifier: AGPL-3.0-or-later

//! The joining device (0013 §3.3, §4, §10): new-device mode and sync mode.
//!
//! Explicit caller endpoints replace QR hints. Candidates are deduplicated,
//! at most 16, and filtered by the [`EndpointPolicy`]. Each attempt uses a fresh
//! `nonce_B` and X-Wing key pair. A candidate that does not answer with a
//! valid accept MAC is skipped. A wrong responder has seen only a hello,
//! which holds nothing reusable. The first valid accept proves code possession; independent password/key
//! authentication follows. Later failures abort without candidate fallback.

use std::net::SocketAddr;
use std::path::Path;

use qv_crypto::lan::v2::{
    InitialEpoch, KeyAuthentication, OuterSchedule, PairingKeys, Role as CryptoRole,
};
use qv_crypto::lan::{PairNonce, PairingSecret, Sas};
use qv_crypto::lan_auth::PasswordAuthClient;
use qv_crypto::{
    KeyGeneration, MacTag, MasterPassword, SecretBytes, VaultId, VaultKey, XWingDecapsKey,
};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::v2::{
    AuthMode, Finished, KeyProve, KeyProved, PairGrant, PakeFinish, PakeResponse, PakeStart,
};
use qv_protocol::oob::{decode_manual, decode_qr_v2};
use qv_store::{LanEnrollmentProof, LanPasswordGrant, VerifiedLanStaging};
use std::time::Instant;

use super::endpoint::EndpointPolicy;
use super::exchange::{ExchangeVault, Role, RoundReport};
use super::steps_v2::{auth_transcript, check_accept, crypto_mode, join_attempt, outer_transcript};
use super::transport::{Conn, V2Channel, connect as open_conn};
use super::{LanError, LanTimeouts, PAIRING_WINDOW_MAX, exchange};

/// A scanned or typed pairing code.
pub struct JoinCode {
    secret: PairingSecret,
    endpoints: Vec<SocketAddr>,
}

impl core::fmt::Debug for JoinCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JoinCode(<redacted>)")
    }
}

impl JoinCode {
    /// A QR payload (0013 §4.2). An unknown profile is
    /// [`LanError::Unsupported`]; any other defect is [`LanError::Protocol`].
    pub fn from_qr(bytes: &[u8]) -> Result<Self, LanError> {
        let qr = decode_qr_v2(bytes).map_err(|error| {
            if error == qv_protocol::ProtocolError::Unsupported {
                LanError::Unsupported
            } else {
                LanError::Protocol
            }
        })?;
        Ok(Self {
            secret: PairingSecret::from_bytes(qr.secret).map_err(|_| LanError::Protocol)?,
            endpoints: qr
                .endpoints
                .iter()
                .map(|e| SocketAddr::new(e.addr, e.port))
                .collect(),
        })
    }

    /// A typed manual code; endpoints come separately.
    pub fn from_manual(text: &str) -> Result<Self, LanError> {
        let secret = decode_manual(text).map_err(|_| LanError::Protocol)?;
        Ok(Self {
            secret: PairingSecret::from_bytes(&*secret).map_err(|_| LanError::Protocol)?,
            endpoints: Vec::new(),
        })
    }

    pub(crate) fn candidates(
        &self,
        extra: &[SocketAddr],
        policy: EndpointPolicy,
    ) -> Vec<SocketAddr> {
        let selected = if extra.is_empty() {
            &self.endpoints
        } else {
            extra
        };
        super::candidates(selected, policy)
    }
}

/// Credentials independently supplied on the receiving device. Never Debug or
/// serialization; the driver drops them before the bulk exchange begins.
pub enum EnrollmentCredential {
    /// The vault password, checked by the one-shot password protocol.
    Password(MasterPassword),
    /// Bounded recovery words; decoded locally and immediately discarded.
    RecoveryPhrase(SecretBytes),
}
/// The joining user's local decisions. Prompts must honor frontend cancellation.
pub trait JoinerUi {
    /// All blocking prompts must honor this original absolute operation
    /// deadline. Nonblocking/headless hooks may use the default.
    fn set_deadline(&mut self, _expires: Instant) {}
    /// Shows the password route's committed comparison code.
    fn show_code(&mut self, sas: &Sas) -> bool;
    /// Final received-name/destination confirmation on the password route.
    fn confirm_vault(&mut self, vault_name: &[u8], sas: &Sas) -> bool;
    /// Protected password input, before connecting/authentication.
    fn master_password(&mut self) -> Option<MasterPassword>;
    /// Select password or recovery words before connecting. Existing callers
    /// default to the password route; frontends expose both choices.
    fn credentials(&mut self) -> Option<EnrollmentCredential> {
        self.master_password().map(EnrollmentCredential::Password)
    }
    /// Key enrollment has no comparison code or additional password gate.
    fn confirm_recovered_vault(&mut self, _vault_name: &[u8]) -> bool {
        false
    }
}
/// Complete verified transfer. No typed password survives authentication.
pub struct JoinedNewDevice {
    /// Independently obtained or credential-authenticated VK.
    pub vk: VaultKey,
    /// Fully verified private staging.
    pub staging: VerifiedLanStaging,
    /// Source/method-bound publication capability.
    pub proof: LanEnrollmentProof,
    /// Original absolute operation deadline, including local publication.
    pub expires: Instant,
}
impl core::fmt::Debug for JoinedNewDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JoinedNewDevice(<redacted>)")
    }
}

/// An unlocked vault syncing with a code.
pub struct JoinerContext {
    /// The vault ID.
    pub vault_id: VaultId,
    /// The key generation.
    pub key_generation: KeyGeneration,
}

/// The joining device's unlocked vault in sync mode.
pub trait JoinerVault: ExchangeVault {
    /// The vault's identity and proof key.
    fn context(&self) -> Result<JoinerContext, LanError>;
    /// Derives independent key proof state without exporting VK.
    fn key_auth(&self, t0: [u8; 32]) -> Result<KeyAuthentication, LanError>;
}

/// Initial channel after the first code-authenticated accept. It has no bulk
/// transfer keys until credential authentication completes.
struct Paired<'c> {
    ch: V2Channel<'c, InitialEpoch>,
    nonce: PairNonce,
    schedule: OuterSchedule,
    t0: [u8; 32],
}
fn check(expires: Instant, cancelled: &dyn Fn() -> bool) -> Result<(), LanError> {
    if cancelled() {
        Err(LanError::Cancelled)
    } else if Instant::now() >= expires {
        Err(LanError::Timeout)
    } else {
        Ok(())
    }
}
fn connect<'c>(
    keys: PairingKeys,
    mode: AuthMode,
    candidates: &[SocketAddr],
    t: &LanTimeouts,
    expires: Instant,
    cancelled: &'c (dyn Fn() -> bool + Sync),
) -> Result<Paired<'c>, LanError> {
    for &endpoint in candidates {
        check(expires, cancelled)?;
        let remaining = expires.saturating_duration_since(Instant::now());
        let Some(stream) = open_conn(endpoint, t.connect.min(remaining), cancelled)? else {
            continue;
        };
        check(expires, cancelled)?;
        let nonce = PairNonce::generate().map_err(|_| LanError::Io)?;
        let (dk, ek) = XWingDecapsKey::generate().map_err(|_| LanError::Io)?;
        let attempt = join_attempt(&keys, mode, nonce, dk, &ek)?;
        let mut conn = Conn::new(stream, cancelled)?;
        conn.cap(expires);
        conn.within(t.message, None);
        let mut buf = Vec::new();
        let answered = conn
            .send_frame(FramePhase::Handshake, &attempt.hello)
            .and_then(|()| {
                conn.within(t.message, None);
                conn.recv_frame(FramePhase::Handshake, &mut buf)
            });
        match answered {
            Err(LanError::Cancelled) => return Err(LanError::Cancelled),
            Err(_) => {
                conn.close();
                continue;
            }
            Ok(()) => {}
        }
        let Ok((ct, accept_hash)) = check_accept(&keys, mode, &attempt.hash, &buf) else {
            conn.close();
            continue;
        };
        let ss = attempt
            .dk
            .decapsulate(&ct)
            .map_err(|_| LanError::Integrity)?;
        drop(attempt.dk);
        let t0 = outer_transcript(mode, &attempt.hash, &accept_hash)?;
        let (schedule, initial) = keys
            .begin(ss, crypto_mode(mode), t0)
            .map_err(|_| LanError::Integrity)?;
        let ch = V2Channel::initial(conn, initial, CryptoRole::Joiner);
        return Ok(Paired {
            ch,
            nonce: attempt.nonce,
            schedule,
            t0,
        });
    }
    check(expires, cancelled)?;
    Err(LanError::NoPeer)
}
/// Authenticate credentials before receiving any vault key or bulk data.
#[allow(clippy::too_many_arguments)] // Explicit code/endpoints/staging/UI/deadline hooks.
pub fn join_new_device(
    code: JoinCode,
    extra: &[SocketAddr],
    policy: EndpointPolicy,
    private_dir: &Path,
    ui: &mut dyn JoinerUi,
    timeouts: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<JoinedNewDevice, LanError> {
    enroll_until(
        code,
        extra,
        policy,
        private_dir,
        ui,
        timeouts,
        cancelled,
        Instant::now() + PAIRING_WINDOW_MAX,
    )
}
#[allow(clippy::too_many_arguments)] // Explicit hooks plus the one absolute operation deadline.
fn enroll_until(
    code: JoinCode,
    extra: &[SocketAddr],
    policy: EndpointPolicy,
    private_dir: &Path,
    ui: &mut dyn JoinerUi,
    timeouts: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
    expires: Instant,
) -> Result<JoinedNewDevice, LanError> {
    timeouts.validate()?;
    check(expires, cancelled)?;
    ui.set_deadline(expires);
    let credential = ui.credentials();
    check(expires, cancelled)?;
    let credential = credential.ok_or(LanError::Cancelled)?;
    let candidates = code.candidates(extra, policy);
    let keys = PairingKeys::new(code.secret).map_err(|_| LanError::Io)?;
    let (mut ch, vk, grant, sas, vault, generation) = match credential {
        EnrollmentCredential::Password(password) => {
            let mode = AuthMode::PasswordEnrollment;
            let mut p = connect(keys, mode, &candidates, timeouts, expires, cancelled)?;
            let (client, ke1) =
                PasswordAuthClient::start(&password, &p.t0).map_err(|_| LanError::Integrity)?;
            let r = PakeStart {
                nonce: *p.nonce.expose_secret(),
                ke1: ke1
                    .expose_secret()
                    .try_into()
                    .map_err(|_| LanError::Integrity)?,
            }
            .encode()
            .map_err(|_| LanError::Protocol)?;
            drop(ke1);
            let sas = qv_crypto::lan::v2::comparison_code(crypto_mode(mode), &p.t0, &p.nonce)
                .map_err(|_| LanError::Integrity)?;
            p.ch.send(&r, timeouts.message)?;
            if !ui.show_code(&sas) {
                return Err(LanError::Cancelled);
            }
            let s = p.ch.recv(timeouts.confirm, None)?;
            let response =
                PakeResponse::decode(s.expose_secret()).map_err(|_| LanError::Integrity)?;
            let (ke3, auth) = client
                .finish(&password, response.ke2)
                .map_err(|_| LanError::Integrity)?;
            p.ch.check()?;
            let f = PakeFinish {
                ke3: ke3
                    .expose_secret()
                    .try_into()
                    .map_err(|_| LanError::Integrity)?,
            }
            .encode()
            .map_err(|_| LanError::Protocol)?;
            drop(ke3);
            let ta = auth_transcript(mode, &p.t0, &r, s.expose_secret(), Some(&f))?;
            p.ch.send(&f, timeouts.message)?;
            drop((r, s, f));
            let (keys, finished) = p
                .schedule
                .complete(auth, ta)
                .map_err(|_| LanError::Integrity)?;
            let mut ch = p.ch.finish(keys)?;
            let mac = finished.tag().map_err(|_| LanError::Integrity)?;
            ch.send(
                &Finished {
                    mac: mac.as_bytes(),
                }
                .encode()
                .map_err(|_| LanError::Protocol)?,
                timeouts.message,
            )?;
            drop(finished);
            let message = ch.recv(timeouts.message, None)?;
            let grant =
                PairGrant::decode(message.expose_secret()).map_err(|_| LanError::Integrity)?;
            let vk = VaultKey::from_transfer(grant.key).map_err(|_| LanError::Integrity)?;
            let proof = LanPasswordGrant::verify(
                &vk,
                &password,
                grant.vault_id,
                grant.generation,
                grant.descriptor,
                grant.control_record,
                grant.head_version,
                grant.head_object,
                grant.head_hash,
                ta,
            )
            .map_err(|_| LanError::Integrity)?;
            let vault = VaultId(grant.vault_id);
            let generation = KeyGeneration(grant.generation);
            drop((password, message));
            ch.check()?;
            (ch, vk, Some(proof), Some(sas), vault, generation)
        }
        EnrollmentCredential::RecoveryPhrase(phrase) => {
            let vk = VaultKey::from_recovery_phrase(phrase.expose_secret())
                .map_err(|_| LanError::Integrity)?;
            drop(phrase);
            let p = connect(
                keys,
                AuthMode::KeyEnrollment,
                &candidates,
                timeouts,
                expires,
                cancelled,
            )?;
            let auth = KeyAuthentication::new(&vk, crypto_mode(AuthMode::KeyEnrollment), p.t0)
                .map_err(|_| LanError::Integrity)?;
            let (ch, vault, generation) = key_authenticate(p, auth, None, timeouts)?;
            (ch, vk, None, None, vault, generation)
        }
    };
    ch.begin_exchange();
    let result = exchange::receive(
        &mut ch,
        private_dir,
        &vk,
        vault,
        generation,
        timeouts,
        &|| cancelled() || Instant::now() >= expires,
    );
    let mut staging = result.map_err(|error| ch.abort(error))?;
    let proof = staging
        .verify_enrollment(&vk, grant)
        .map_err(LanError::from_staging)?;
    check(expires, cancelled)?;
    let name = staging.vault_name(&vk).map_err(LanError::Store)?;
    let approved = match &sas {
        Some(sas) => ui.confirm_vault(name.expose_secret(), sas),
        None => ui.confirm_recovered_vault(name.expose_secret()),
    };
    check(expires, cancelled)?;
    if !approved {
        return Err(LanError::Cancelled);
    }
    Ok(JoinedNewDevice {
        vk,
        staging,
        proof,
        expires,
    })
}
fn key_authenticate<'c>(
    mut p: Paired<'c>,
    auth: KeyAuthentication,
    known: Option<(VaultId, KeyGeneration)>,
    t: &LanTimeouts,
) -> Result<(V2Channel<'c>, VaultId, KeyGeneration), LanError> {
    let mode = if known.is_some() {
        AuthMode::KeySync
    } else {
        AuthMode::KeyEnrollment
    };
    let proof = auth.joiner_proof().map_err(|_| LanError::Integrity)?;
    let first = KeyProve {
        mac: proof.as_bytes(),
    }
    .encode()
    .map_err(|_| LanError::Protocol)?;
    p.ch.send(&first, t.message)?;
    let second = p.ch.recv(t.message, None)?;
    let proved = KeyProved::decode(second.expose_secret()).map_err(|_| LanError::Integrity)?;
    let vault = <VaultId as qv_model::RandomId>::from_bytes(proved.vault_id)
        .map_err(|_| LanError::Integrity)?;
    let generation = KeyGeneration(proved.generation);
    if known.is_some_and(|scope| scope != (vault, generation)) {
        return Err(LanError::VaultMismatch);
    }
    let auth = auth
        .accept_offerer(vault, generation, &MacTag::from_bytes(proved.mac))
        .map_err(|_| LanError::Integrity)?;
    let ta = auth_transcript(mode, &p.t0, &first, second.expose_secret(), None)?;
    let (keys, finished) = p
        .schedule
        .complete(auth, ta)
        .map_err(|_| LanError::Integrity)?;
    drop(finished);
    let ch = p.ch.finish(keys)?;
    Ok((ch, vault, generation))
}
/// Existing-copy sync: independent key proof, final keys, then one exchange.
pub fn sync_with_code(
    code: JoinCode,
    extra: &[SocketAddr],
    policy: EndpointPolicy,
    vault: &dyn JoinerVault,
    timeouts: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<RoundReport, LanError> {
    let expires = Instant::now() + PAIRING_WINDOW_MAX;
    timeouts.validate()?;
    let ctx = vault.context()?;
    let candidates = code.candidates(extra, policy);
    let keys = PairingKeys::new(code.secret).map_err(|_| LanError::Io)?;
    let p = connect(
        keys,
        AuthMode::KeySync,
        &candidates,
        timeouts,
        expires,
        cancelled,
    )?;
    let auth = vault.key_auth(p.t0)?;
    let (mut ch, _, _) =
        key_authenticate(p, auth, Some((ctx.vault_id, ctx.key_generation)), timeouts)?;
    ch.begin_exchange();
    let result = exchange::exchange(&mut ch, Role::Initiator, vault, None, timeouts);
    let result = result.map_err(|error| ch.abort(error));
    ch.conn.close();
    result
}

#[cfg(test)]
mod deadline_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::net::TcpListener;
    use std::time::Duration;
    struct Slow {
        expires: Option<Instant>,
        calls: usize,
    }
    impl JoinerUi for Slow {
        fn set_deadline(&mut self, expires: Instant) {
            self.expires = Some(expires);
        }
        fn master_password(&mut self) -> Option<MasterPassword> {
            self.calls += 1;
            std::thread::sleep(Duration::from_millis(40));
            Some(MasterPassword::from_utf8(b"synthetic deadline test password").unwrap())
        }
        fn show_code(&mut self, _: &Sas) -> bool {
            panic!("expired before a connection")
        }
        fn confirm_vault(&mut self, _: &[u8], _: &Sas) -> bool {
            panic!("expired before a connection")
        }
    }
    // 0012 §1: Unrequested synchronization
    #[test]
    fn lan_joiner_prompt_time_consumes_original_deadline_and_expiry_never_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let code = qv_protocol::oob::encode_manual(&[47; 16]);
        let expires = Instant::now() + Duration::from_millis(20);
        let mut ui = Slow {
            expires: None,
            calls: 0,
        };
        let result = enroll_until(
            JoinCode::from_manual(&code).unwrap(),
            &[endpoint],
            EndpointPolicy {
                allow_loopback: true,
            },
            Path::new("/unused"),
            &mut ui,
            &LanTimeouts::default(),
            &|| false,
            expires,
        );
        assert_eq!(result.err(), Some(LanError::Timeout));
        assert_eq!(ui.expires, Some(expires));
        assert_eq!(ui.calls, 1);
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let result = enroll_until(
            JoinCode::from_manual(&code).unwrap(),
            &[endpoint],
            EndpointPolicy {
                allow_loopback: true,
            },
            Path::new("/unused"),
            &mut ui,
            &LanTimeouts::default(),
            &|| false,
            expires,
        );
        assert_eq!(result.err(), Some(LanError::Timeout));
        assert_eq!(ui.calls, 1, "an already expired operation must not prompt");
    }
}
