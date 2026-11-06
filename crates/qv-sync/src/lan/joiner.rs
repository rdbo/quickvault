// SPDX-License-Identifier: AGPL-3.0-or-later

//! The joining device (0013 §3.3, §4, §10): new-device mode and sync mode.
//!
//! Candidates are the QR endpoints plus the caller's, deduplicated, at most
//! 16, and filtered by the [`EndpointPolicy`]. Each attempt uses a fresh
//! `nonce_B` and X-Wing key pair. A candidate that does not answer with a
//! valid accept MAC is skipped. A wrong responder has seen only a hello,
//! which holds nothing reusable. The first valid accept authenticates the
//! approver, and later failures abort.

use std::net::SocketAddr;
use std::path::Path;

use qv_crypto::lan::{
    PairNonce, PairingKeys, PairingSecret, ProofRole, ProofRoot, RecordOpener, RecordSealer, Sas,
};
use qv_crypto::{KeyGeneration, MacTag, MasterPassword, VaultId, VaultKey, XWingDecapsKey};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::{JoinMode, PairGrant, PairProve, PairProved, PairReveal};
use qv_protocol::oob::{decode_manual, decode_qr};
use qv_protocol::registry::LanProfile;
use qv_store::{PasswordProof, StoreError, VerifiedLanStaging};

use super::endpoint::EndpointPolicy;
use super::exchange::{ExchangeVault, Role, RoundReport};
use super::steps::{JoinAttempt, check_accept, join_attempt, record_keys, th};
use super::transport::{Channel, Conn, connect as open_conn, guarded};
use super::{LanError, LanTimeouts, exchange};

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
        let qr = decode_qr(bytes).map_err(|_| LanError::Protocol)?;
        LanProfile::from_id(qr.profile).map_err(|_| LanError::Unsupported)?;
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
        let all: Vec<SocketAddr> = self.endpoints.iter().chain(extra).copied().collect();
        super::candidates(&all, policy)
    }
}

/// The joining user's decisions in new-device mode (0013 §4.5, §10.4).
pub trait JoinerUi {
    /// Shows the comparison code during the transfer; `false` cancels.
    fn show_code(&mut self, sas: &Sas) -> bool;
    /// New device (§10 step 4): `true` to join the vault named `vault_name`.
    fn confirm_vault(&mut self, vault_name: &[u8], sas: &Sas) -> bool;
    /// New device: the vault's master password, asked again after a wrong
    /// one; `None` cancels.
    fn master_password(&mut self) -> Option<MasterPassword>;
}

/// A verified new-device transfer, ready for the local creation step.
pub struct JoinedNewDevice {
    /// The received VK.
    pub vk: VaultKey,
    /// The verified staging archive.
    pub staging: VerifiedLanStaging,
    /// The checked master password's proof.
    pub proof: PasswordProof,
    /// The checked master password, to unlock the new vault.
    pub password: MasterPassword,
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
    /// `K_proof` of this generation.
    pub root: ProofRoot,
}

/// The joining device's unlocked vault in sync mode.
pub trait JoinerVault: ExchangeVault {
    /// The vault's identity and proof key.
    fn context(&self) -> Result<JoinerContext, LanError>;
}

/// An authenticated pairing connection on the joiner's side. The shared
/// secret is dropped once the record keys exist.
struct Paired<'c> {
    ch: Channel<'c>,
    attempt: JoinAttempt,
    th: [u8; 32],
}

/// Tries each candidate until one authenticates (§3.3, §4.3–4.4).
fn connect<'c>(
    keys: &PairingKeys,
    mode: JoinMode,
    candidates: &[SocketAddr],
    t: &LanTimeouts,
    cancelled: &'c (dyn Fn() -> bool + Sync),
) -> Result<Paired<'c>, LanError> {
    for &endpoint in candidates {
        if cancelled() {
            return Err(LanError::Cancelled);
        }
        let Some(stream) = open_conn(endpoint, t.connect, cancelled)? else {
            continue;
        };
        let nonce = PairNonce::generate().map_err(|_| LanError::Io)?;
        let (dk, ek) = XWingDecapsKey::generate().map_err(|_| LanError::Io)?;
        let attempt = join_attempt(keys, mode, nonce, dk, &ek)?;
        let mut conn = Conn::new(stream, cancelled)?;
        conn.within(t.message, None);
        let mut buf = Vec::new();
        let answered = conn
            .send_frame(FramePhase::Handshake, &attempt.hello)
            .and_then(|()| conn.recv_frame(FramePhase::Handshake, &mut buf));
        match answered {
            Err(LanError::Cancelled) => return Err(LanError::Cancelled),
            Err(_) => {
                conn.close();
                continue;
            }
            Ok(()) => {}
        }
        let Ok((ct, accept_hash)) = check_accept(keys, &attempt.hello_hash, &buf) else {
            conn.close();
            continue;
        };
        // Authenticated: from here every failure aborts.
        let ss = attempt.dk.decapsulate(&ct).map_err(|_| {
            conn.close();
            LanError::Integrity
        })?;
        let th = th(&attempt.hello_hash, &accept_hash)?;
        let (b2a, a2b) = record_keys(keys, &ss, &th)?;
        drop(ss);
        let ch = Channel::new(conn, RecordSealer::new(b2a), RecordOpener::new(a2b));
        return Ok(Paired { ch, attempt, th });
    }
    Err(LanError::NoPeer)
}

/// Sends the reveal and shows the code (§4.5).
fn reveal(p: &mut Paired<'_>, ui: &mut dyn JoinerUi, t: &LanTimeouts) -> Result<Sas, LanError> {
    let (attempt, th) = (&p.attempt, p.th);
    guarded(&mut p.ch, |ch| {
        let msg =
            PairReveal::encode(attempt.nonce_b.expose_secret()).map_err(|_| LanError::Protocol)?;
        ch.send(&msg, t.message)?;
        let sas = Sas::compute(&th, &attempt.nonce_b).map_err(|_| LanError::Protocol)?;
        if ui.show_code(&sas) {
            Ok(sas)
        } else {
            Err(LanError::Cancelled)
        }
    })
}

/// New-device mode (§4.7, §10 steps 1–4). Returns the verified transfer;
/// the caller creates the vault (step 5).
#[allow(clippy::too_many_arguments)] // the code, endpoints, staging and the caller's hooks
pub fn join_new_device(
    code: JoinCode,
    extra: &[SocketAddr],
    policy: EndpointPolicy,
    private_dir: &Path,
    ui: &mut dyn JoinerUi,
    timeouts: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<JoinedNewDevice, LanError> {
    timeouts.validate()?;
    let candidates = code.candidates(extra, policy);
    let keys = code.secret.keys().map_err(|_| LanError::Io)?;
    let mut p = connect(&keys, JoinMode::NewDevice, &candidates, timeouts, cancelled)?;
    let sas = reveal(&mut p, ui, timeouts)?;
    let (vk, mut staging) = guarded(&mut p.ch, |ch| {
        let msg = ch.recv(timeouts.confirm, None)?;
        let grant = PairGrant::decode(msg.expose_secret()).map_err(|_| LanError::Protocol)?;
        let vk = VaultKey::from_transfer(grant.vk).map_err(|_| LanError::Protocol)?;
        let vault = VaultId(grant.vault_id);
        let generation = KeyGeneration(grant.key_generation);
        drop(msg);
        let staging =
            exchange::receive(ch, private_dir, &vk, vault, generation, timeouts, cancelled)?;
        Ok((vk, staging))
    })?;
    // §10 step 4, local: confirm the vault, then the master password.
    let name = staging.vault_name(&vk).map_err(LanError::Store)?;
    if cancelled() || !ui.confirm_vault(name.expose_secret(), &sas) {
        return Err(LanError::Cancelled);
    }
    let (proof, password) = loop {
        if cancelled() {
            return Err(LanError::Cancelled);
        }
        let Some(password) = ui.master_password() else {
            return Err(LanError::Cancelled);
        };
        match staging.verify_password(&vk, &password) {
            Ok(proof) => break (proof, password),
            Err(StoreError::WrongPassword) => {}
            Err(e) => return Err(LanError::Store(e)),
        }
    };
    Ok(JoinedNewDevice {
        vk,
        staging,
        proof,
        password,
    })
}

/// Sync mode (§4.8): proves this unlocked copy to the code's window,
/// verifies the window's proof, then runs one exchange as initiator over the
/// pairing keys. Nothing about the peer is stored.
pub fn sync_with_code(
    code: JoinCode,
    extra: &[SocketAddr],
    policy: EndpointPolicy,
    vault: &dyn JoinerVault,
    timeouts: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<RoundReport, LanError> {
    timeouts.validate()?;
    let ctx = vault.context()?;
    let candidates = code.candidates(extra, policy);
    let keys = code.secret.keys().map_err(|_| LanError::Io)?;
    let mut p = connect(&keys, JoinMode::Sync, &candidates, timeouts, cancelled)?;
    let th = p.th;
    guarded(&mut p.ch, |ch| {
        let proof = ctx
            .root
            .proof(&th, ProofRole::B, ctx.vault_id, ctx.key_generation)
            .map_err(|_| LanError::Protocol)?;
        ch.send(
            &PairProve::encode(&ctx.vault_id.0, ctx.key_generation.0, proof.as_bytes())
                .map_err(|_| LanError::Protocol)?,
            timeouts.message,
        )?;
        let msg = ch.recv(timeouts.message, None)?;
        let proved = PairProved::decode(msg.expose_secret()).map_err(|_| LanError::Protocol)?;
        // No exchange message before A's proof verifies (§4.8).
        ctx.root
            .verify_proof(
                &th,
                ProofRole::A,
                ctx.vault_id,
                ctx.key_generation,
                &MacTag::from_bytes(proved.proof),
            )
            .map_err(|_| LanError::VaultMismatch)?;
        if cancelled() {
            return Err(LanError::Cancelled);
        }
        Ok(())
    })?;
    let round = guarded(&mut p.ch, |ch| {
        exchange::exchange(ch, Role::Initiator, vault, timeouts)
    });
    p.ch.conn.close();
    round
}
