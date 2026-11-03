// SPDX-License-Identifier: AGPL-3.0-or-later

//! The joining device (0013 §3.3, §4, §10).
//!
//! Candidates are the QR endpoints plus the caller's, deduplicated, at most
//! 16, and filtered by the [`EndpointPolicy`]. Each attempt uses a fresh
//! `nonce_B` and X-Wing key pair. A candidate that does not answer with a
//! valid accept MAC is skipped. A wrong responder has seen only a hello,
//! which holds nothing reusable. The first valid accept authenticates the
//! approver, and later failures abort.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;

use qv_crypto::lan::{
    LinkKey, LinkRoot, PairNonce, PairingKeys, PairingSecret, ProofRole, RecordOpener,
    RecordSealer, Sas,
};
use qv_crypto::{
    KeyGeneration, MacTag, MasterPassword, VaultId, VaultKey, XWingDecapsKey, XWingSharedSecret,
};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::{JoinMode, PairDone, PairGrant, PairProve, PairProved, PairReveal};
use qv_protocol::oob::{decode_manual, decode_qr};
use qv_protocol::registry::LanProfile;
use qv_store::{PasswordProof, StoreError, VerifiedLanStaging};

use super::endpoint::EndpointPolicy;
use super::steps::{JoinAttempt, check_accept, join_attempt, record_keys, th};
use super::transport::{Channel, Conn, guarded};
use super::{LanError, LanTimeouts, exchange};

/// Most candidate endpoints tried per action (0013 §3.3).
const MAX_CANDIDATES: usize = 16;

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
        let mut out: Vec<SocketAddr> = Vec::new();
        for a in self.endpoints.iter().chain(extra) {
            if policy.accepts(a) && !out.contains(a) && out.len() < MAX_CANDIDATES {
                out.push(*a);
            }
        }
        out
    }
}

/// The joining user's decisions (0013 §4.5, §10.4).
pub trait JoinerUi {
    /// Shows the comparison code. In link mode, `true` confirms that both
    /// screens match. In new-device mode the code is shown during the
    /// transfer; `false` cancels.
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
    /// The link to write in the first head.
    pub link_id: [u8; 16],
    /// Its key.
    pub link_key: LinkKey,
    /// The approver's endpoint, as the first hint.
    pub endpoint: SocketAddr,
}

impl core::fmt::Debug for JoinedNewDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JoinedNewDevice(<redacted>)")
    }
}

/// An unlocked vault joining in link mode.
pub struct JoinerContext {
    /// The vault ID.
    pub vault_id: VaultId,
    /// The key generation.
    pub key_generation: KeyGeneration,
    /// `K_lan` of this generation.
    pub root: LinkRoot,
}

/// The joining device's unlocked vault in link mode.
pub trait JoinerVault {
    /// The vault's identity and link root.
    fn context(&self) -> Result<JoinerContext, LanError>;
    /// Commits B's link row, with the approver's endpoint as its hint.
    fn commit_link(
        &self,
        link_id: [u8; 16],
        key: &LinkKey,
        endpoint: SocketAddr,
    ) -> Result<(), LanError>;
}

/// An authenticated pairing connection on the joiner's side.
struct Paired<'c> {
    ch: Channel<'c>,
    attempt: JoinAttempt,
    ss: XWingSharedSecret,
    th: [u8; 32],
    endpoint: SocketAddr,
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
        let Ok(stream) = TcpStream::connect_timeout(&endpoint, t.connect) else {
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
        let ch = Channel::new(conn, RecordSealer::new(b2a), RecordOpener::new(a2b));
        return Ok(Paired {
            ch,
            attempt,
            ss,
            th,
            endpoint,
        });
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
    let (attempt, ss, th) = (&p.attempt, &p.ss, p.th);
    let (vk, vault, generation, link_id, link_key, mut staging) = guarded(&mut p.ch, |ch| {
        let msg = ch.recv(timeouts.confirm, None)?;
        let grant = PairGrant::decode(msg.expose_secret()).map_err(|_| LanError::Protocol)?;
        let vk = VaultKey::from_transfer(grant.vk).map_err(|_| LanError::Protocol)?;
        let vault = VaultId(grant.vault_id);
        let generation = KeyGeneration(grant.key_generation);
        let link_id = grant.link_id;
        drop(msg);
        // The derivation profile of 0002 §3.3 is the only registered one.
        let root = LinkRoot::derive(&vk, vault, generation, qv_crypto::DerivationProfile::V1)
            .map_err(|_| LanError::Protocol)?;
        let link_key = root
            .link_key(ss, &th, &attempt.nonce_b, &link_id, vault, generation)
            .map_err(|_| LanError::Protocol)?;
        let staging =
            exchange::receive(ch, private_dir, &vk, vault, generation, timeouts, cancelled)?;
        Ok((vk, vault, generation, link_id, link_key, staging))
    })?;
    let _ = (vault, generation);
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
        link_id,
        link_key,
        endpoint: p.endpoint,
    })
}

/// Link mode (§4.8): pairs an unlocked copy of the same vault and generation.
/// Returns the committed link ID.
pub fn join_link(
    code: JoinCode,
    extra: &[SocketAddr],
    policy: EndpointPolicy,
    vault: &dyn JoinerVault,
    ui: &mut dyn JoinerUi,
    timeouts: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<[u8; 16], LanError> {
    timeouts.validate()?;
    let ctx = vault.context()?;
    let candidates = code.candidates(extra, policy);
    let keys = code.secret.keys().map_err(|_| LanError::Io)?;
    let mut p = connect(&keys, JoinMode::Link, &candidates, timeouts, cancelled)?;
    reveal(&mut p, ui, timeouts)?;
    let (attempt, ss, th, endpoint) = (&p.attempt, &p.ss, p.th, p.endpoint);
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
        let msg = ch.recv(timeouts.confirm, None)?;
        let proved = PairProved::decode(msg.expose_secret()).map_err(|_| LanError::Protocol)?;
        ctx.root
            .verify_proof(
                &th,
                ProofRole::A,
                ctx.vault_id,
                ctx.key_generation,
                &MacTag::from_bytes(proved.proof),
            )
            .map_err(|_| LanError::Protocol)?;
        if cancelled() {
            return Err(LanError::Cancelled);
        }
        let link = ctx
            .root
            .link_key(
                ss,
                &th,
                &attempt.nonce_b,
                &proved.link_id,
                ctx.vault_id,
                ctx.key_generation,
            )
            .map_err(|_| LanError::Protocol)?;
        vault.commit_link(proved.link_id, &link, endpoint)?;
        // PairDone only after the commit is durable (§4.8).
        ch.send(
            &PairDone::encode().map_err(|_| LanError::Protocol)?,
            timeouts.message,
        )?;
        // The post-pairing exchange arrives in phase 2.10.
        ch.conn.close();
        Ok(proved.link_id)
    })
}
