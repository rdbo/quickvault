// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local LAN peer state (0013 §9, 0004 §2.4): `lan_link` rows bound to the
//! head by `lan_links_digest`, and unauthenticated `lan_hint` rows.
//!
//! The row check runs before any value is read: at most [`MAX_LAN_LINKS`]
//! rows, 16-byte IDs, the header's generation, and bounded blobs. On open the
//! digest of the stored rows must equal head key 8, so a removed row planted
//! back or a modified row is an integrity error. The anchor catches a moved
//! head. Rows are decrypted only when used. Hints are convenience data: an
//! invalid hint reads as absent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use qv_crypto::lan::{LINK_ROW_CIPHERTEXT_MAX, LinkKey, LinkRow, open_link_row, seal_link_row};
use qv_crypto::{ObjectHashProfile, StoredDataProfile, object_hash};
use qv_encoding::{Decoder, encode_array};
use qv_model::RandomId;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::StoreError;
use crate::header::Header;
use crate::schema::validation_err;
use crate::vault::{Keys, accepted_profile};

/// Most `lan_link` rows per vault (0013 §9.1).
pub const MAX_LAN_LINKS: usize = 64;
/// Most endpoints in one hint (0013 §9.2).
pub const MAX_LAN_HINT_ENDPOINTS: usize = 4;
/// Largest stored sealed envelope: the ciphertext bound plus the envelope
/// fields.
pub(crate) const MAX_LAN_ENVELOPE: usize = LINK_ROW_CIPHERTEXT_MAX + 64;

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

fn malformed<T>(_: T) -> StoreError {
    StoreError::Integrity
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

fn envelope(
    profile: StoredDataProfile,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    Ok(encode_array(|a| {
        a.uint(1);
        a.uint(u64::from(profile.id()));
        a.bytes(nonce);
        a.bytes(ciphertext);
        Ok(())
    })
    .map_err(|_| StoreError::Internal)?
    .to_vec())
}

/// `(profile, nonce, ciphertext)` of a bounded `[1, profile, nonce, ct]`.
fn parse_envelope<'a>(
    header: &Header,
    blob: &'a [u8],
) -> Result<(StoredDataProfile, [u8; 24], &'a [u8]), StoreError> {
    if blob.len() > MAX_LAN_ENVELOPE {
        return Err(StoreError::LimitExceeded);
    }
    let mut d = Decoder::new(blob).map_err(malformed)?;
    if d.array().map_err(malformed)? != 4 {
        return Err(StoreError::Integrity);
    }
    if d.uint().map_err(malformed)? != 1 {
        return Err(StoreError::Unsupported);
    }
    let profile = u16::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
    let profile = accepted_profile(header, profile)?;
    let nonce: [u8; 24] = d
        .bytes()
        .map_err(malformed)?
        .try_into()
        .map_err(malformed)?;
    let ciphertext = d.bytes().map_err(malformed)?;
    d.finish().map_err(malformed)?;
    Ok((profile, nonce, ciphertext))
}

/// Seals a link row (0013 §9.1). An invalid label is
/// [`StoreError::InvalidEdit`].
pub(crate) fn seal_row(
    keys: &Keys,
    header: &Header,
    link_id: &[u8; 16],
    key: &LinkKey,
    label: &str,
    created_at: u64,
) -> Result<Vec<u8>, StoreError> {
    if !qv_crypto::lan::valid_link_label(label) {
        return Err(StoreError::InvalidEdit);
    }
    let sealed = seal_link_row(
        &keys.local,
        header.data_profile,
        header.vault_id,
        header.key_generation,
        link_id,
        key,
        label,
        created_at,
    )?;
    envelope(header.data_profile, &sealed.nonce, &sealed.ciphertext)
}

/// Authenticates and decodes a stored link row; any failure is
/// [`StoreError::Integrity`].
pub(crate) fn open_row(
    keys: &Keys,
    header: &Header,
    row: &StoredLink,
) -> Result<LinkRow, StoreError> {
    let (profile, nonce, ciphertext) = parse_envelope(header, &row.sealed)?;
    open_link_row(
        &keys.local,
        profile,
        header.vault_id,
        header.key_generation,
        &row.link_id,
        &nonce,
        ciphertext,
    )
    .map_err(|_| StoreError::Integrity)
}

fn hint_aad(header: &Header, link_id: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    encode_array(|a| {
        a.text("qv/lan-hint/v1");
        a.bytes(&header.vault_id.0);
        a.uint(u64::from(header.key_generation.0));
        a.bytes(link_id);
        Ok(())
    })
    .map_err(|_| StoreError::Internal)
}

/// Seals a hint: up to [`MAX_LAN_HINT_ENDPOINTS`] endpoints and the last
/// successful session time (0 = never). Extra endpoints are dropped.
pub(crate) fn seal_hint(
    keys: &Keys,
    header: &Header,
    link_id: &[u8; 16],
    endpoints: &[SocketAddr],
    last_success_at: u64,
) -> Result<Vec<u8>, StoreError> {
    let plaintext = encode_array(|a| {
        a.array(|a| {
            for e in endpoints.iter().take(MAX_LAN_HINT_ENDPOINTS) {
                a.array(|a| {
                    match e.ip() {
                        IpAddr::V4(v4) => a.bytes(&v4.octets()),
                        IpAddr::V6(v6) => a.bytes(&v6.octets()),
                    }
                    a.uint(e.port().into());
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        a.uint(last_success_at);
        Ok(())
    })
    .map_err(|_| StoreError::Internal)?;
    let sealed = qv_crypto::seal(
        &keys.local,
        header.data_profile,
        &hint_aad(header, link_id)?,
        &plaintext,
        LINK_ROW_CIPHERTEXT_MAX,
    )?;
    envelope(header.data_profile, &sealed.nonce, &sealed.ciphertext)
}

/// Opens a hint. `None` for anything invalid: hints are never trusted.
pub(crate) fn open_hint(
    keys: &Keys,
    header: &Header,
    link_id: &[u8; 16],
    blob: &[u8],
) -> Option<Vec<SocketAddr>> {
    let (profile, nonce, ciphertext) = parse_envelope(header, blob).ok()?;
    let plaintext = qv_crypto::open(
        &keys.local,
        profile,
        &hint_aad(header, link_id).ok()?,
        &nonce,
        ciphertext,
        LINK_ROW_CIPHERTEXT_MAX,
    )
    .ok()?;
    let mut d = Decoder::new(plaintext.expose_secret()).ok()?;
    if d.array().ok()? != 2 {
        return None;
    }
    let n = usize::try_from(d.array().ok()?).ok()?;
    if n > MAX_LAN_HINT_ENDPOINTS {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if d.array().ok()? != 2 {
            return None;
        }
        let raw = d.bytes().ok()?;
        let ip = if let Ok(v4) = <[u8; 4]>::try_from(raw) {
            IpAddr::V4(Ipv4Addr::from(v4))
        } else {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?))
        };
        let port = u16::try_from(d.uint().ok()?).ok().filter(|p| *p != 0)?;
        out.push(SocketAddr::new(ip, port));
    }
    d.uint().ok()?;
    d.finish().ok()?;
    Some(out)
}

/// Reads one hint row, bounded; `None` if absent or invalid.
pub(crate) fn read_hint(conn: &Connection, link_id: &[u8; 16]) -> Option<Vec<u8>> {
    let (kind, len): (String, i64) = conn
        .query_row(
            "SELECT typeof(sealed), octet_length(sealed) FROM lan_hint WHERE link_id = ?1",
            [link_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()?;
    if kind != "blob" || usize::try_from(len).ok()? > MAX_LAN_ENVELOPE {
        return None;
    }
    conn.query_row(
        "SELECT sealed FROM lan_hint WHERE link_id = ?1",
        [link_id.as_slice()],
        |r| r.get(0),
    )
    .ok()
}

/// A decrypted link row without its key: what a frontend lists.
pub struct LanLinkRow {
    /// The link ID.
    pub link_id: [u8; 16],
    /// The user-chosen label (UTF-8).
    pub label: qv_crypto::SecretBytes,
    /// When the link was created (display only).
    pub created_at: qv_model::Timestamp,
}

impl core::fmt::Debug for LanLinkRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanLinkRow(<redacted>)")
    }
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
    /// The LAN links, decrypted (labels and times only). Any row failure is
    /// [`StoreError::Integrity`].
    pub fn lan_links(&self) -> Result<Vec<LanLinkRow>, StoreError> {
        let keys = Keys::derive(&self.vk, &self.file.header)?;
        self.state
            .links
            .iter()
            .map(|r| {
                let row = open_row(&keys, &self.file.header, r)?;
                Ok(LanLinkRow {
                    link_id: r.link_id,
                    label: row.label,
                    created_at: qv_model::Timestamp(
                        i64::try_from(row.created_at).map_err(|_| StoreError::Integrity)?,
                    ),
                })
            })
            .collect()
    }

    /// The link key of `link_id`, for the LAN session handshake (phase
    /// 2.10). [`StoreError::NotFound`] if there is no such link.
    pub fn lan_link_key(&self, link_id: &[u8; 16]) -> Result<LinkKey, StoreError> {
        let keys = Keys::derive(&self.vk, &self.file.header)?;
        let r = self
            .state
            .links
            .iter()
            .find(|r| r.link_id == *link_id)
            .ok_or(StoreError::NotFound)?;
        Ok(open_row(&keys, &self.file.header, r)?.key)
    }

    /// The link's endpoint hints, best-effort: absent or invalid → empty.
    pub fn lan_hint(&self, link_id: &[u8; 16]) -> Vec<SocketAddr> {
        let Ok(keys) = Keys::derive(&self.vk, &self.file.header) else {
            return Vec::new();
        };
        read_hint(&self.file.conn, link_id)
            .and_then(|blob| open_hint(&keys, &self.file.header, link_id, &blob))
            .unwrap_or_default()
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
        let generation = self.file.header.key_generation;
        let mut reader = crate::schema::ObjectReader::new(&self.file.conn)?;
        if reader.meta(generation, &id.to_bytes())?.is_none() {
            return Err(StoreError::NotFound);
        }
        let (stored_profile, nonce, ciphertext) =
            reader.read(generation, &id.to_bytes(), length)?;
        if stored_profile != profile.id()
            || object_hash(ObjectHashProfile::V1, &ciphertext).0 != sha
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
