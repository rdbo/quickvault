// SPDX-License-Identifier: AGPL-3.0-or-later

//! The retired `lan_link` rows (0013 §9.1, 0004 §2.4; plan 0042). Nothing
//! about a LAN peer is stored any more. The table and the head's
//! `lan_links_digest` stay in the format so that files written before 0014
//! still open: every commit writes the empty set, and open still checks the
//! stored rows against the head.
//!
//! The row check runs before any value is read: at most [`MAX_LAN_LINKS`]
//! rows, 16-byte IDs, the header's generation, and bounded blobs. On open the
//! digest of the stored rows must equal head key 8, so a planted or modified
//! row is an integrity error. The anchor catches a moved head. Rows are
//! never decrypted.

use qv_crypto::{ObjectHashProfile, StoredDataProfile, object_hash};
use qv_encoding::encode_array;
use qv_model::RandomId;
use rusqlite::Connection;

use crate::StoreError;
use crate::header::Header;
use crate::schema::validation_err;
use crate::vault::accepted_profile;

/// Most `lan_link` rows a pre-0014 file may hold.
pub(crate) const MAX_LAN_LINKS: usize = 64;
/// Largest stored sealed envelope: the pre-0014 ciphertext bound (512
/// bytes, 0004 §2.4) plus the envelope fields.
pub(crate) const MAX_LAN_ENVELOPE: usize = 512 + 64;

/// One stored link row: its ID and exact sealed envelope.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StoredLink {
    pub(crate) link_id: [u8; 16],
    pub(crate) sealed: Vec<u8>,
}

/// `H(["qv/lan-links/v1", [[link_id, SHA-256(sealed)], …]])` over rows
/// sorted by link ID (0013 §9.1).
pub(crate) fn digest(rows: &[StoredLink]) -> Result<[u8; 32], StoreError> {
    let mut sorted: Vec<&StoredLink> = rows.iter().collect();
    sorted.sort_by_key(|a| a.link_id);
    let bytes = encode_array(|a| {
        a.text("qv/lan-links/v1");
        a.array(|a| {
            for r in &sorted {
                a.array(|a| {
                    a.bytes(&r.link_id);
                    a.bytes(&object_hash(ObjectHashProfile::V1, &r.sealed).0);
                    Ok(())
                })?;
            }
            Ok(())
        })
    })
    .map_err(|_| StoreError::Internal)?;
    Ok(object_hash(ObjectHashProfile::V1, &bytes).0)
}

/// The digest of no links (new, restored and rotated vaults).
pub(crate) fn empty_digest() -> Result<[u8; 32], StoreError> {
    digest(&[])
}

fn len_of(n: i64) -> Result<usize, StoreError> {
    usize::try_from(n).map_err(|_| StoreError::Integrity)
}

/// Checks the `lan_link` rows' count, types and lengths without reading a
/// value, then reads them sorted by ID.
pub(crate) fn read(conn: &Connection, header: &Header) -> Result<Vec<StoredLink>, StoreError> {
    let count: i64 = conn
        .query_row("SELECT count(*) FROM lan_link", [], |r| r.get(0))
        .map_err(|e| validation_err(&e))?;
    if len_of(count)? > MAX_LAN_LINKS {
        return Err(StoreError::LimitExceeded);
    }
    let mut stmt = conn
        .prepare(
            "SELECT typeof(link_id), octet_length(link_id), typeof(key_generation), \
             typeof(sealed), octet_length(sealed) FROM lan_link",
        )
        .map_err(|e| validation_err(&e))?;
    let shapes = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .map_err(|e| validation_err(&e))?;
    for shape in shapes {
        let (id_type, id_len, gen_type, sealed_type, sealed_len) =
            shape.map_err(|e| validation_err(&e))?;
        if id_type != "blob"
            || id_len != 16
            || gen_type != "integer"
            || sealed_type != "blob"
            || len_of(sealed_len)? > MAX_LAN_ENVELOPE
        {
            return Err(StoreError::Integrity);
        }
    }
    let mut stmt = conn
        .prepare("SELECT link_id, key_generation, sealed FROM lan_link ORDER BY link_id")
        .map_err(|e| validation_err(&e))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|e| validation_err(&e))?;
    let mut out = Vec::with_capacity(len_of(count)?);
    for row in rows {
        let (id, generation, sealed) = row.map_err(|e| validation_err(&e))?;
        if generation != i64::from(header.key_generation.0) {
            return Err(StoreError::Integrity);
        }
        out.push(StoredLink {
            link_id: id.try_into().map_err(|_| StoreError::Integrity)?,
            sealed,
        });
    }
    if out.len() != len_of(count)? {
        return Err(StoreError::Integrity);
    }
    Ok(out)
}

/// What this vault serves in a LAN exchange (0013 §7.2–7.5): its committed
/// manifest envelope and the references that envelope names.
pub struct LanServeState {
    vault_id: qv_crypto::VaultId,
    key_generation: qv_crypto::KeyGeneration,
    manifest_hash: [u8; 32],
    envelope: Vec<u8>,
    refs: std::collections::BTreeMap<qv_model::ObjectId, (StoredDataProfile, u64, [u8; 32])>,
}

impl core::fmt::Debug for LanServeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanServeState(..)")
    }
}

impl LanServeState {
    /// The vault ID.
    pub fn vault_id(&self) -> qv_crypto::VaultId {
        self.vault_id
    }
    /// The key generation.
    pub fn key_generation(&self) -> qv_crypto::KeyGeneration {
        self.key_generation
    }
    /// SHA-256 of [`Self::envelope`].
    pub fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }
    /// The manifest envelope, exactly as in an archive frame (0004 §6.1).
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    /// Whether the served manifest references `id`.
    pub fn contains(&self, id: qv_model::ObjectId) -> bool {
        self.refs.contains_key(&id)
    }
    /// How many objects the served manifest references.
    pub fn object_count(&self) -> usize {
        self.refs.len()
    }
}

impl crate::UnlockedVault {
    /// How many `lan_link` rows a file written before 0014 still holds.
    /// They are never read, and the next commit clears them (0013 §9.1).
    pub fn retired_lan_links(&self) -> usize {
        self.state.links.len()
    }

    /// The committed manifest envelope and its references, for serving.
    pub fn lan_serve_state(&self) -> Result<LanServeState, StoreError> {
        let header = self.file.header;
        let stored = crate::schema::read_manifest(&self.file.conn)?;
        if stored.hash != self.state.head.manifest_hash
            || stored.key_generation != header.key_generation
        {
            return Err(StoreError::Changed);
        }
        let profile = accepted_profile(&header, stored.data_profile)?;
        let envelope = crate::manifest::envelope_bytes(
            header.key_generation,
            profile,
            &stored.nonce,
            &stored.ciphertext,
        )?;
        if object_hash(ObjectHashProfile::V1, &envelope).0 != stored.hash {
            return Err(StoreError::Integrity);
        }
        let refs = self
            .state
            .manifest
            .references()
            .iter()
            .map(|r| (r.object_id(), (r.data_profile(), r.length(), *r.sha256())))
            .collect();
        Ok(LanServeState {
            vault_id: header.vault_id,
            key_generation: header.key_generation,
            manifest_hash: stored.hash,
            envelope: envelope.to_vec(),
            refs,
        })
    }

    /// The archive-format envelope of one object `state` references, with its
    /// ciphertext hash rechecked. A missing row (the state moved on) is
    /// [`StoreError::NotFound`]; an unreferenced ID is
    /// [`StoreError::InvalidEdit`].
    pub fn lan_object_envelope(
        &self,
        state: &LanServeState,
        id: qv_model::ObjectId,
    ) -> Result<Vec<u8>, StoreError> {
        let (profile, length, sha) = *state.refs.get(&id).ok_or(StoreError::InvalidEdit)?;
        self.local_envelope(id, profile, length, &sha)
    }

    /// The archive-format envelope of this vault's object row `id`, checked
    /// against the expected profile, length and SHA-256 (Integrity). A
    /// missing row is [`StoreError::NotFound`].
    pub(crate) fn local_envelope(
        &self,
        id: qv_model::ObjectId,
        profile: StoredDataProfile,
        length: u64,
        sha: &[u8; 32],
    ) -> Result<Vec<u8>, StoreError> {
        let generation = self.file.header.key_generation;
        self.file.budget.reset();
        let mut reader = crate::schema::ObjectReader::new(&self.file.conn)?;
        if reader.meta(generation, &id.to_bytes())?.is_none() {
            return Err(StoreError::NotFound);
        }
        let (stored_profile, nonce, ciphertext) =
            reader.read(generation, &id.to_bytes(), length)?;
        if stored_profile != profile.id()
            || object_hash(ObjectHashProfile::V1, &ciphertext).0 != *sha
        {
            return Err(StoreError::Integrity);
        }
        crate::object::ObjectEnvelope {
            object_id: id,
            key_generation: generation,
            data_profile: profile,
            nonce,
            ciphertext,
        }
        .encode()
    }
}
