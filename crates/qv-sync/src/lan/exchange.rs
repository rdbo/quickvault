// SPDX-License-Identifier: AGPL-3.0-or-later

//! The exchange that follows a new-device grant (0013 §4.7, §7, §10). The
//! joiner B is the initiator and starts empty; the approver A serves its
//! committed state.
//!
//! The turns follow §7.1 as clarified: B State, A State, A Manifest parts, B
//! Want* (until `last`), A Object* (in request order), A `Want([], last)`,
//! B Done, A Done. B requests every reference in sorted order, so its
//! staging is an archive in frame order (plan 0037 decision 3).

use std::collections::BTreeSet;
use std::path::Path;

use qv_crypto::{KeyGeneration, VaultId, VaultKey};
use qv_model::{ObjectId, RandomId};
use qv_protocol::lan::{
    Done, MAX_MANIFEST_LENGTH, MAX_MANIFEST_PART, MAX_WANT_IDS, ManifestPart, ObjectMsg, Outcome,
    PairGrant, State, Want,
};
use qv_protocol::registry::check_features;
use qv_store::{LanServeState, LanStaging, MAX_OBJECTS, StagedKeyslot, VerifiedLanStaging};
use zeroize::Zeroizing;

use super::approver::ApproverVault;
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

/// A's side, after the grant: serve the committed state to an empty joiner.
/// `Ok` once B's `Done` arrived and A answered.
pub(crate) fn serve(
    ch: &mut Channel<'_>,
    vault: &dyn ApproverVault,
    id: VaultId,
    generation: KeyGeneration,
    t: &LanTimeouts,
) -> Result<(), LanError> {
    // B's state: this vault, empty, no features (§7.2).
    let msg = ch.recv(t.idle, None)?;
    let s = State::decode(msg.expose_secret()).map_err(bad)?;
    if s.vault_id != id.0 || s.key_generation != generation.0 {
        return Err(LanError::VaultMismatch);
    }
    check_features(&s.features).map_err(|_| LanError::Unsupported)?;
    if s.manifest_hash != [0; 32] || s.manifest_length != 0 {
        return Err(LanError::Protocol);
    }
    let state: LanServeState = vault.serve_state()?;
    let envelope = state.envelope();
    let len = u64::try_from(envelope.len()).map_err(|_| LanError::Limit)?;
    ch.send(
        &State::encode(&id.0, generation.0, state.manifest_hash(), len).map_err(bad)?,
        t.idle,
    )?;
    // B has no manifest to send; A's parts.
    let mut offset = 0u64;
    for part in envelope.chunks(MAX_MANIFEST_PART) {
        ch.send(&ManifestPart::encode(offset, part).map_err(bad)?, t.idle)?;
        offset += u64::try_from(part.len()).map_err(|_| LanError::Limit)?;
    }
    // B's requests, then the objects in request order.
    let mut requested = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        let msg = ch.recv(t.idle, None)?;
        let want = Want::decode(msg.expose_secret()).map_err(bad)?;
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
            break;
        }
    }
    for id in requested {
        let envelope = vault.object(&state, id)?;
        ch.send(&ObjectMsg::encode(&envelope).map_err(bad)?, t.idle)?;
    }
    // A wants nothing from an empty joiner.
    ch.send(&Want::encode(&[], true).map_err(bad)?, t.idle)?;
    let msg = ch.recv(t.idle, None)?;
    let done = Done::decode(msg.expose_secret()).map_err(bad)?;
    if done.manifest_hash != *state.manifest_hash() {
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
    ch.send(
        &State::encode(&id.0, generation.0, &[0; 32], 0).map_err(bad)?,
        t.idle,
    )?;
    let msg = ch.recv(t.idle, None)?;
    let s = State::decode(msg.expose_secret()).map_err(bad)?;
    drop(msg);
    if s.vault_id != id.0 || s.key_generation != generation.0 {
        return Err(LanError::VaultMismatch);
    }
    check_features(&s.features).map_err(|_| LanError::Unsupported)?;
    if s.manifest_length > MAX_MANIFEST_LENGTH {
        return Err(LanError::Limit);
    }
    if s.manifest_length == 0 {
        return Err(LanError::Protocol);
    }
    let length = usize::try_from(s.manifest_length).map_err(|_| LanError::Limit)?;
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
    let wanted: Vec<[u8; 16]> = staging.wanted().iter().map(RandomId::to_bytes).collect();
    if wanted.is_empty() {
        ch.send(&Want::encode(&[], true).map_err(bad)?, t.idle)?;
    }
    let chunks = wanted.chunks(MAX_WANT_IDS).count();
    for (i, chunk) in wanted.chunks(MAX_WANT_IDS).enumerate() {
        ch.send(&Want::encode(chunk, i + 1 == chunks).map_err(bad)?, t.idle)?;
    }
    for _ in 0..wanted.len() {
        let msg = ch.recv(t.idle, None)?;
        let object = ObjectMsg::decode(msg.expose_secret()).map_err(bad)?;
        staging
            .add_object(object.envelope)
            .map_err(LanError::from_staging)?;
    }
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
    ch.send(
        &Done::encode(Outcome::Merged, &s.manifest_hash).map_err(bad)?,
        t.idle,
    )?;
    // A's Done is informational; B's remaining steps are local.
    let _ = ch.recv(t.message, None);
    ch.conn.close();
    Ok(verified)
}
