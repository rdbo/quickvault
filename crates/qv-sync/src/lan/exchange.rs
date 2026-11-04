// SPDX-License-Identifier: AGPL-3.0-or-later

//! The exchange (0013 §7) and its new-device form (§4.7, §10).
//!
//! The general round follows §7.1 as clarified:
//! 1. I `State`, R `State`. Equal manifest hashes: both send `Done(0)` and
//!    the round ends.
//! 2. I's manifest parts, then R's.
//! 3. I's `Want`s, then R's `Object`s in request order.
//! 4. R's `Want`s, then I's `Object`s.
//! 5. Each side verifies, merges and commits through its vault.
//! 6. I `Done`, R `Done`.
//!
//! Each side stages the peer's state as a private archive. Objects it holds
//! with an identical reference are copied from its own rows; only the
//! others are requested (plan 0038 decision 5). Nothing is accepted before
//! every object is staged and the whole archive is authenticated. A
//! failure before this side's commit changes nothing. After the commit, a
//! failure is reported in [`RoundReport::failure`], and the commit stays
//! (§7.7).
//!
//! In the new-device exchange the joiner B starts empty and stages
//! everything. Its `Done` reports receipt, not a commit (§10 step 3).

use std::collections::BTreeSet;
use std::path::Path;

use qv_crypto::{KeyGeneration, VaultId, VaultKey};
use qv_model::{ObjectId, RandomId};
use qv_protocol::lan::{
    Done, MAX_MANIFEST_LENGTH, MAX_MANIFEST_PART, MAX_WANT_IDS, MAX_WANT_MESSAGES, ManifestPart,
    ObjectMsg, Outcome, PairGrant, State, Want,
};
use qv_protocol::registry::check_features;
use qv_store::{
    LanServeState, LanStaging, MAX_OBJECTS, Planned, StagedKeyslot, VerifiedLanStaging,
};
use zeroize::Zeroizing;

use super::transport::Channel;
use super::{LanError, LanTimeouts};

fn bad<E>(_: E) -> LanError {
    LanError::Protocol
}

/// The grant plaintext `["qv/lan-pair-grant/v1", vault_id, key_generation,
/// vk, link_id]` (0013 §4.7), in a wiped buffer to be sealed at once.
pub fn grant_plaintext(
    vk: &VaultKey,
    vault: VaultId,
    generation: KeyGeneration,
    link_id: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>, LanError> {
    PairGrant::encode(
        &vault.0,
        generation.0,
        |e| vk.encode_for_transfer(e),
        link_id,
    )
    .map_err(bad)
}

/// What one vault offers an exchange. qv-core implements it over a session
/// with short calls; VK never leaves the session.
pub trait ExchangeVault: Sync {
    /// The vault ID and key generation that `State` names.
    fn scope(&self) -> Result<(VaultId, KeyGeneration), LanError>;
    /// The committed state to serve.
    fn serve_state(&self) -> Result<LanServeState, LanError>;
    /// One object envelope of `state` (a missing row is `StateChanged`).
    fn object(&self, state: &LanServeState, id: ObjectId) -> Result<Vec<u8>, LanError>;
    /// Verifies the peer's manifest envelope and starts the staging.
    fn stage(&self, manifest_hash: &[u8; 32], envelope: &[u8]) -> Result<LanStaging, LanError>;
    /// Appends the next planned local object.
    fn stage_local(&self, staging: &mut LanStaging) -> Result<(), LanError>;
    /// Finishes (full authentication), merges and commits; or commits
    /// nothing if the peer brought nothing new.
    fn accept(&self, staging: LanStaging) -> Result<Accepted, LanError>;
}

/// One side's acceptance: the outcome its `Done` reports and its new
/// manifest hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// Unchanged (no commit), merged, or merged with conflicts.
    pub outcome: Outcome,
    /// The manifest hash after acceptance.
    pub manifest_hash: [u8; 32],
}

/// This side's role in a round (0013 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// It connected.
    Initiator,
    /// It had the window open.
    Responder,
}

/// One round's result. Local acceptance is reported separately from the
/// peer's receipt (0005 §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundReport {
    /// What this side accepted.
    pub local: Outcome,
    /// The peer's `Done` outcome, if it arrived.
    pub peer: Option<Outcome>,
    /// This side's manifest hash after the round.
    pub manifest_hash: [u8; 32],
    /// A failure after this side's commit (the commit stays).
    pub failure: Option<LanError>,
}

fn send_state(
    ch: &mut Channel<'_>,
    id: VaultId,
    generation: KeyGeneration,
    hash: &[u8; 32],
    length: usize,
    t: &LanTimeouts,
) -> Result<(), LanError> {
    let length = u64::try_from(length).map_err(|_| LanError::Limit)?;
    ch.send(
        &State::encode(&id.0, generation.0, hash, length).map_err(bad)?,
        t.idle,
    )
}

/// Receives the peer's `State` and checks it against this vault (§7.2).
/// `empty` allows (and requires) the new-device form.
fn recv_state(
    ch: &mut Channel<'_>,
    id: VaultId,
    generation: KeyGeneration,
    empty: bool,
    t: &LanTimeouts,
) -> Result<State, LanError> {
    let msg = ch.recv(t.idle, None)?;
    let s = State::decode(msg.expose_secret()).map_err(bad)?;
    if s.vault_id != id.0 || s.key_generation != generation.0 {
        return Err(LanError::VaultMismatch);
    }
    check_features(&s.features).map_err(|_| LanError::Unsupported)?;
    if empty {
        if s.manifest_hash != [0; 32] || s.manifest_length != 0 {
            return Err(LanError::Protocol);
        }
        return Ok(s);
    }
    if s.manifest_length > MAX_MANIFEST_LENGTH {
        return Err(LanError::Limit);
    }
    if s.manifest_length == 0 {
        return Err(LanError::Protocol);
    }
    Ok(s)
}

fn send_manifest(ch: &mut Channel<'_>, envelope: &[u8], t: &LanTimeouts) -> Result<(), LanError> {
    let mut offset = 0u64;
    for part in envelope.chunks(MAX_MANIFEST_PART) {
        ch.send(&ManifestPart::encode(offset, part).map_err(bad)?, t.idle)?;
        offset += u64::try_from(part.len()).map_err(|_| LanError::Limit)?;
    }
    Ok(())
}

/// Receives contiguous manifest parts into a buffer reserved once at the
/// announced, already bounded length (§7.3).
fn recv_manifest(ch: &mut Channel<'_>, length: u64, t: &LanTimeouts) -> Result<Vec<u8>, LanError> {
    let length = usize::try_from(length).map_err(|_| LanError::Limit)?;
    let mut envelope = Vec::new();
    envelope
        .try_reserve_exact(length)
        .map_err(|_| LanError::Limit)?;
    while envelope.len() < length {
        let msg = ch.recv(t.idle, None)?;
        let part = ManifestPart::decode(msg.expose_secret()).map_err(bad)?;
        if part.offset != envelope.len() as u64
            || part.bytes.is_empty()
            || part.bytes.len() > length - envelope.len()
        {
            return Err(LanError::Protocol);
        }
        envelope.extend_from_slice(part.bytes);
    }
    Ok(envelope)
}

/// Sends this side's requests: 4,096 IDs per message, the last flagged, and
/// one empty final message when there is nothing to request.
fn send_wants(ch: &mut Channel<'_>, ids: &[ObjectId], t: &LanTimeouts) -> Result<(), LanError> {
    let ids: Vec<[u8; 16]> = ids.iter().map(RandomId::to_bytes).collect();
    if ids.is_empty() {
        return ch.send(&Want::encode(&[], true).map_err(bad)?, t.idle);
    }
    let chunks = ids.chunks(MAX_WANT_IDS).count();
    for (i, chunk) in ids.chunks(MAX_WANT_IDS).enumerate() {
        ch.send(&Want::encode(chunk, i + 1 == chunks).map_err(bad)?, t.idle)?;
    }
    Ok(())
}

/// Receives the peer's requests against `state` (§7.4): each ID in the
/// served manifest, no duplicates, an empty `Want` only as the last, at
/// most 62 messages and 250,000 IDs.
fn recv_wants(
    ch: &mut Channel<'_>,
    state: &LanServeState,
    t: &LanTimeouts,
) -> Result<Vec<ObjectId>, LanError> {
    let mut requested = Vec::new();
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_WANT_MESSAGES {
        let msg = ch.recv(t.idle, None)?;
        let want = Want::decode(msg.expose_secret()).map_err(bad)?;
        if want.ids.is_empty() && !want.last {
            return Err(LanError::Protocol);
        }
        for raw in want.ids {
            let id = ObjectId::from_bytes(raw).map_err(bad)?;
            if !state.contains(id) || !seen.insert(id) {
                return Err(LanError::Protocol);
            }
            if requested.len() >= MAX_OBJECTS {
                return Err(LanError::Limit);
            }
            requested.push(id);
        }
        if want.last {
            return Ok(requested);
        }
    }
    Err(LanError::Protocol)
}

fn serve_objects(
    ch: &mut Channel<'_>,
    vault: &dyn ExchangeVault,
    state: &LanServeState,
    ids: Vec<ObjectId>,
    t: &LanTimeouts,
) -> Result<(), LanError> {
    for id in ids {
        let envelope = vault.object(state, id)?;
        ch.send(&ObjectMsg::encode(&envelope).map_err(bad)?, t.idle)?;
    }
    Ok(())
}

/// Fills the staging in plan order: local rows for local entries, the next
/// `Object` for peer entries. Each object is checked against its reference
/// before it is written (§7.5).
fn receive_objects(
    ch: &mut Channel<'_>,
    vault: Option<&dyn ExchangeVault>,
    staging: &mut LanStaging,
    t: &LanTimeouts,
) -> Result<(), LanError> {
    while let Some(next) = staging.next() {
        match (next, vault) {
            (Planned::Local, Some(v)) => v.stage_local(staging)?,
            (Planned::Local, None) => return Err(LanError::Protocol),
            (Planned::Peer, _) => {
                let msg = ch.recv(t.idle, None)?;
                let object = ObjectMsg::decode(msg.expose_secret()).map_err(bad)?;
                staging
                    .add_object(object.envelope)
                    .map_err(LanError::from_staging)?;
            }
        }
    }
    Ok(())
}

fn send_done(
    ch: &mut Channel<'_>,
    outcome: Outcome,
    hash: &[u8; 32],
    t: &LanTimeouts,
) -> Result<(), LanError> {
    ch.send(&Done::encode(outcome, hash).map_err(bad)?, t.idle)
}

fn recv_done(ch: &mut Channel<'_>, t: &LanTimeouts) -> Result<Done, LanError> {
    let msg = ch.recv(t.idle, None)?;
    Done::decode(msg.expose_secret()).map_err(bad)
}

/// One general round as `role` (0013 §7). `Err` means nothing was
/// committed here; see the module docs.
pub(crate) fn exchange(
    ch: &mut Channel<'_>,
    role: Role,
    vault: &dyn ExchangeVault,
    t: &LanTimeouts,
) -> Result<RoundReport, LanError> {
    let (id, generation) = vault.scope()?;
    let mine = vault.serve_state()?;
    let (my_hash, my_len) = (*mine.manifest_hash(), mine.envelope().len());
    let peer = match role {
        Role::Initiator => {
            send_state(ch, id, generation, &my_hash, my_len, t)?;
            recv_state(ch, id, generation, false, t)?
        }
        Role::Responder => {
            let peer = recv_state(ch, id, generation, false, t)?;
            send_state(ch, id, generation, &my_hash, my_len, t)?;
            peer
        }
    };
    if peer.manifest_hash == my_hash {
        let done = match role {
            Role::Initiator => {
                send_done(ch, Outcome::Unchanged, &my_hash, t)?;
                recv_done(ch, t)
            }
            Role::Responder => {
                let done = recv_done(ch, t);
                if done.is_ok() {
                    send_done(ch, Outcome::Unchanged, &my_hash, t)?;
                }
                done
            }
        };
        return Ok(RoundReport {
            local: Outcome::Unchanged,
            peer: done.as_ref().ok().map(|d| d.outcome),
            manifest_hash: my_hash,
            failure: done.err(),
        });
    }
    let peer_envelope = match role {
        Role::Initiator => {
            send_manifest(ch, mine.envelope(), t)?;
            recv_manifest(ch, peer.manifest_length, t)?
        }
        Role::Responder => {
            let envelope = recv_manifest(ch, peer.manifest_length, t)?;
            send_manifest(ch, mine.envelope(), t)?;
            envelope
        }
    };
    let mut staging = vault.stage(&peer.manifest_hash, &peer_envelope)?;
    drop(peer_envelope);
    match role {
        Role::Initiator => {
            send_wants(ch, &staging.requested(), t)?;
            receive_objects(ch, Some(vault), &mut staging, t)?;
            let theirs = recv_wants(ch, &mine, t)?;
            serve_objects(ch, vault, &mine, theirs, t)?;
        }
        Role::Responder => {
            let theirs = recv_wants(ch, &mine, t)?;
            serve_objects(ch, vault, &mine, theirs, t)?;
            send_wants(ch, &staging.requested(), t)?;
            receive_objects(ch, Some(vault), &mut staging, t)?;
        }
    }
    drop(mine);
    let accepted = vault.accept(staging)?;
    // Committed (or unchanged): from here a failure only loses the receipt.
    let done = match role {
        Role::Initiator => send_done(ch, accepted.outcome, &accepted.manifest_hash, t)
            .and_then(|()| recv_done(ch, t)),
        Role::Responder => recv_done(ch, t).and_then(|d| {
            send_done(ch, accepted.outcome, &accepted.manifest_hash, t)?;
            Ok(d)
        }),
    };
    Ok(RoundReport {
        local: accepted.outcome,
        peer: done.as_ref().ok().map(|d| d.outcome),
        manifest_hash: accepted.manifest_hash,
        failure: done.err(),
    })
}

/// A's side, after the grant: serve the committed state to an empty joiner.
/// `Ok` once B's `Done` (outcome 1, A's hash) arrived and A answered.
pub(crate) fn serve(
    ch: &mut Channel<'_>,
    vault: &dyn ExchangeVault,
    id: VaultId,
    generation: KeyGeneration,
    t: &LanTimeouts,
) -> Result<(), LanError> {
    // B's state: this vault, empty, no features (§7.2).
    recv_state(ch, id, generation, true, t)?;
    let state: LanServeState = vault.serve_state()?;
    send_state(
        ch,
        id,
        generation,
        state.manifest_hash(),
        state.envelope().len(),
        t,
    )?;
    // B has no manifest to send; A's parts.
    send_manifest(ch, state.envelope(), t)?;
    // B's requests, then the objects in request order.
    let requested = recv_wants(ch, &state, t)?;
    serve_objects(ch, vault, &state, requested, t)?;
    // A wants nothing from an empty joiner.
    send_wants(ch, &[], t)?;
    let done = recv_done(ch, t)?;
    if done.outcome != Outcome::Merged || done.manifest_hash != *state.manifest_hash() {
        return Err(LanError::Protocol);
    }
    ch.send(
        &Done::encode(Outcome::Unchanged, state.manifest_hash()).map_err(bad)?,
        t.message,
    )?;
    ch.conn.close();
    Ok(())
}

/// B's side, after the grant: receive and fully verify the approver's state
/// into private staging (0013 §10 steps 1–3).
pub(crate) fn receive(
    ch: &mut Channel<'_>,
    private_dir: &Path,
    vk: &VaultKey,
    id: VaultId,
    generation: KeyGeneration,
    t: &LanTimeouts,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<VerifiedLanStaging, LanError> {
    send_state(ch, id, generation, &[0; 32], 0, t)?;
    let s = recv_state(ch, id, generation, false, t)?;
    let envelope = recv_manifest(ch, s.manifest_length, t)?;
    let mut staging = LanStaging::begin(
        private_dir,
        vk,
        id,
        generation,
        &s.manifest_hash,
        &envelope,
        cancelled,
    )
    .map_err(LanError::from_staging)?;
    drop(envelope);
    send_wants(ch, &staging.requested(), t)?;
    receive_objects(ch, None, &mut staging, t)?;
    // A's requests from an empty joiner: exactly none.
    let msg = ch.recv(t.idle, None)?;
    let want = Want::decode(msg.expose_secret()).map_err(bad)?;
    if !want.ids.is_empty() || !want.last {
        return Err(LanError::Protocol);
    }
    let mut verified = staging
        .finish(vk, cancelled)
        .map_err(LanError::from_staging)?;
    match verified.keyslot(vk).map_err(LanError::from_staging)? {
        StagedKeyslot::Unique => {}
        StagedKeyslot::Missing | StagedKeyslot::Conflicted => return Err(LanError::Keyslot),
    }
    // §10 step 3: Done reports receipt, not a commit.
    send_done(ch, Outcome::Merged, &s.manifest_hash, t)?;
    // A's Done is informational; B's remaining steps are local.
    let _ = ch.recv(t.message, None);
    ch.conn.close();
    Ok(verified)
}
