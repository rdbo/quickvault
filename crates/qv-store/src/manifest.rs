// SPDX-License-Identifier: AGPL-3.0-or-later

//! The encrypted manifest (spec 0004 §3.4–3.6, §4.1–4.2; 0005 §5.1).
//!
//! The manifest names the whole committed state: every record's active
//! heads, its retained history and history floor, attachment chunk lists,
//! the three control records (0003 §2.3), and the sorted object reference
//! list. It excludes itself, its checkpoint and local-only tables.
//!
//! Plaintext (canonical CBOR map; all keys required; unknown keys fail
//! closed, because the manifest is a control structure). Development values,
//! frozen in phase 1.16:
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | format | uint, = [`MANIFEST_FORMAT`] |
//! | 1 | config_digest | bstr 32 |
//! | 2 | control | `[vault_meta_id, keyslot_id, root_group_id]` |
//! | 3 | records | `[[record_id, heads, history, floor], …]`, strictly ascending by record ID |
//! | 4 | references | `[[object_id, data_profile, ciphertext_length, sha256], …]`, strictly ascending by object ID |
//!
//! A version reference is `[version_id, clock, object_id]`, plus a fourth
//! element `[chunk_object_id, …]` for an `attachment_meta` version. `heads`
//! (1 to 256) and `history` are strictly ascending by version ID; `floor` is
//! a clock (empty: no floor).
//!
//! Validation, before anything is trusted: sort orders and uniqueness; every
//! budget (checked against the count before allocating); version clocks
//! non-empty and unique within the record; heads pairwise concurrent;
//! every history version strictly dominated by a head and not suppressed by
//! the floor; every role (version object or chunk) resolves to exactly one
//! reference and every reference to exactly one role; role-dependent object
//! lengths; the control records present and distinct.
//!
//! Encryption: stored-data under the `manifest` purpose key with AAD
//! `["qv/manifest/v1", vault_id, key_generation, data_profile]`. The envelope
//! is `[key_generation, data_profile, nonce, ciphertext]`, and
//! `manifest_hash` is SHA-256 of its canonical encoding, hashed in a stream
//! so the ciphertext is never copied. `reference_digest` is SHA-256 of the
//! canonical reference array. The configuration digest is SHA-256 of
//! `["qv/config/v1", format, vault_id, key_generation, min_data_profile,
//! min_derivation_profile]`.

use qv_crypto::{
    DerivationProfile, KeyGeneration, ObjectHashProfile, ObjectHasher, PurposeKey, RecordId,
    StoredDataProfile, VaultId, object_hash, purpose,
};
use qv_encoding::{Decoder, Encoder, encode_array};
use qv_model::{Causality, Clock, HistoryFloor, MAX_HEADS, ObjectId, RandomId, VersionId};
use zeroize::Zeroizing;

use crate::error::StoreError;
use crate::header::{FORMAT, Header};
use crate::limits::{
    MAX_CHUNKS, MAX_CLOCK_COMPONENTS, MAX_MANIFEST_CIPHERTEXT, MAX_OBJECTS, MAX_RECORD_CIPHERTEXT,
    MAX_RECORDS, MAX_TOTAL_CIPHERTEXT,
};
use crate::object::Scope;

/// The development manifest format.
pub const MANIFEST_FORMAT: u64 = 0x7FFF_0001;

const AAD_LABEL: &str = "qv/manifest/v1";
const CONFIG_LABEL: &str = "qv/config/v1";

/// The ciphertext length of every attachment chunk: 64 KiB padded with
/// framing (0004 §3.3).
pub(crate) fn chunk_ciphertext_len() -> Result<u64, StoreError> {
    let n = qv_crypto::sealed_len(64 * 1024).ok_or(StoreError::Internal)?;
    u64::try_from(n).map_err(|_| StoreError::Internal)
}

/// The smallest stored-data ciphertext (an empty plaintext).
fn min_ciphertext_len() -> Result<u64, StoreError> {
    let n = qv_crypto::sealed_len(0).ok_or(StoreError::Internal)?;
    u64::try_from(n).map_err(|_| StoreError::Internal)
}

/// One version's role: its ID, clock and object.
#[derive(Clone, PartialEq, Eq)]
pub struct VersionRef {
    version_id: VersionId,
    clock: Clock,
    object_id: ObjectId,
    chunks: Option<Vec<ObjectId>>,
}

impl VersionRef {
    pub(crate) fn new(version_id: VersionId, clock: Clock, object_id: ObjectId) -> Self {
        Self {
            version_id,
            clock,
            object_id,
            chunks: None,
        }
    }

    /// The same role with an attachment's chunk list.
    pub(crate) fn with_chunks(mut self, chunks: Vec<ObjectId>) -> Self {
        self.chunks = Some(chunks);
        self
    }

    /// The version ID.
    pub fn version_id(&self) -> VersionId {
        self.version_id
    }

    /// The version's clock.
    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    /// The object holding the encrypted version.
    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// The chunk objects of an `attachment_meta` version, in order.
    pub fn chunks(&self) -> Option<&[ObjectId]> {
        self.chunks.as_deref()
    }
}

/// One record's state in the manifest.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordEntry {
    record_id: RecordId,
    heads: Vec<VersionRef>,
    history: Vec<VersionRef>,
    floor: Clock,
}

impl RecordEntry {
    /// The record ID.
    pub fn record_id(&self) -> RecordId {
        self.record_id
    }

    /// The active heads, ascending by version ID (more than one is a
    /// conflict).
    pub fn heads(&self) -> &[VersionRef] {
        &self.heads
    }

    /// Retained history, ascending by version ID.
    pub fn history(&self) -> &[VersionRef] {
        &self.history
    }

    /// The history suppression floor.
    pub fn floor(&self) -> HistoryFloor {
        HistoryFloor::new(self.floor.clone())
    }

    /// The head or history version with this ID.
    pub fn version(&self, id: VersionId) -> Option<&VersionRef> {
        self.heads
            .iter()
            .chain(self.history.iter())
            .find(|v| v.version_id == id)
    }
}

/// An object reference: what the manifest commits to about one object.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ObjectRef {
    object_id: ObjectId,
    data_profile: StoredDataProfile,
    length: u64,
    sha256: [u8; 32],
}

impl ObjectRef {
    pub(crate) fn new(
        object_id: ObjectId,
        data_profile: StoredDataProfile,
        ciphertext: &[u8],
    ) -> Result<Self, StoreError> {
        Ok(Self {
            object_id,
            data_profile,
            length: u64::try_from(ciphertext.len()).map_err(|_| StoreError::LimitExceeded)?,
            sha256: object_hash(ObjectHashProfile::V1, ciphertext).0,
        })
    }

    /// The object ID.
    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// The object's stored-data profile.
    pub fn data_profile(&self) -> StoredDataProfile {
        self.data_profile
    }

    /// The ciphertext length in bytes.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// SHA-256 of the ciphertext.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// The decoded and validated manifest.
///
/// It holds IDs, clocks and object references, which are not secret
/// (`qv-model`); the plaintext it was decoded from is zeroized.
#[derive(Clone, PartialEq, Eq)]
pub struct Manifest {
    config_digest: [u8; 32],
    vault_meta_id: RecordId,
    keyslot_id: RecordId,
    root_group_id: RecordId,
    records: Vec<RecordEntry>,
    references: Vec<ObjectRef>,
}

// Redacted `Debug`: these types are not secret, but they map records to
// object IDs, the linkage 0004 §2.2 hides, and 0004 §5.1 treats metadata as
// confidential, so a stray `{:?}` must not print them (review of plan 0009).
macro_rules! redacted_debug {
    ($($t:ident),+) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(..)"))
            }
        }
    )+};
}
redacted_debug!(VersionRef, RecordEntry, ObjectRef, Manifest);

fn malformed<E>(_: E) -> StoreError {
    StoreError::Integrity
}

fn read_id<T: RandomId>(d: &mut Decoder<'_>) -> Result<T, StoreError> {
    let b: [u8; 16] = d
        .bytes()
        .map_err(malformed)?
        .try_into()
        .map_err(malformed)?;
    Ok(T::from_bytes(b)?)
}

fn read_record_id(d: &mut Decoder<'_>) -> Result<RecordId, StoreError> {
    let b: [u8; 16] = d
        .bytes()
        .map_err(malformed)?
        .try_into()
        .map_err(malformed)?;
    Ok(<RecordId as RandomId>::from_bytes(b)?)
}

/// Reads an array length and checks it against `max` before any allocation.
fn read_len(d: &mut Decoder<'_>, max: usize) -> Result<usize, StoreError> {
    let n = d.array().map_err(malformed)?;
    let n = usize::try_from(n).map_err(|_| StoreError::LimitExceeded)?;
    if n > max {
        return Err(StoreError::LimitExceeded);
    }
    Ok(n)
}

/// Running totals checked while decoding, so a hostile manifest is refused
/// before it is fully allocated.
#[derive(Default)]
struct Counts {
    versions: usize,
    clock_components: usize,
}

impl Counts {
    fn add_clock(&mut self, c: &Clock) -> Result<(), StoreError> {
        self.clock_components = self
            .clock_components
            .checked_add(c.pairs().len())
            .filter(|&n| n <= MAX_CLOCK_COMPONENTS)
            .ok_or(StoreError::LimitExceeded)?;
        Ok(())
    }

    fn add_version(&mut self) -> Result<(), StoreError> {
        self.versions = self
            .versions
            .checked_add(1)
            .filter(|&n| n <= MAX_OBJECTS)
            .ok_or(StoreError::LimitExceeded)?;
        Ok(())
    }
}

fn decode_version(d: &mut Decoder<'_>, counts: &mut Counts) -> Result<VersionRef, StoreError> {
    counts.add_version()?;
    let n = d.array().map_err(malformed)?;
    if n != 3 && n != 4 {
        return Err(StoreError::Integrity);
    }
    let version_id = read_id(d)?;
    let clock = Clock::decode(d)?;
    counts.add_clock(&clock)?;
    let object_id = read_id(d)?;
    let chunks = if n == 4 {
        let count = read_len(d, MAX_CHUNKS)?;
        let mut chunks = Vec::with_capacity(count);
        for _ in 0..count {
            chunks.push(read_id(d)?);
        }
        Some(chunks)
    } else {
        None
    };
    Ok(VersionRef {
        version_id,
        clock,
        object_id,
        chunks,
    })
}

fn encode_version(v: &VersionRef, e: &mut Encoder) -> Result<(), qv_encoding::EncodeError> {
    e.array(|a| {
        a.bytes(&v.version_id.to_bytes());
        v.clock.encode(a)?;
        a.bytes(&v.object_id.to_bytes());
        if let Some(chunks) = &v.chunks {
            a.array(|c| {
                for id in chunks {
                    c.bytes(&id.to_bytes());
                }
                Ok(())
            })?;
        }
        Ok(())
    })
}

fn encode_references(refs: &[ObjectRef], e: &mut Encoder) -> Result<(), qv_encoding::EncodeError> {
    e.array(|a| {
        for r in refs {
            a.array(|x| {
                x.bytes(&r.object_id.to_bytes());
                x.uint(u64::from(r.data_profile.id()));
                x.uint(r.length);
                x.bytes(&r.sha256);
                Ok(())
            })?;
        }
        Ok(())
    })
}

/// SHA-256 of `["qv/config/v1", format, vault_id, key_generation,
/// min_data_profile, min_derivation_profile]` (0004 §3.4).
pub(crate) fn config_digest(header: &Header) -> Result<[u8; 32], StoreError> {
    config_digest_for(
        header.vault_id,
        header.key_generation,
        header.min_data_profile,
        header.min_derivation_profile,
    )
}

/// See [`config_digest`]: the same digest from the four stored minima, so the
/// archive reader can recompute it from an archive header (0004 §6.2).
pub(crate) fn config_digest_for(
    vault_id: VaultId,
    key_generation: KeyGeneration,
    min_data_profile: StoredDataProfile,
    min_derivation_profile: DerivationProfile,
) -> Result<[u8; 32], StoreError> {
    let bytes = encode_array(|a| {
        a.text(CONFIG_LABEL);
        a.uint(FORMAT);
        a.bytes(&vault_id.0);
        a.uint(u64::from(key_generation.0));
        a.uint(u64::from(min_data_profile.id()));
        a.uint(u64::from(min_derivation_profile.id()));
        Ok(())
    })
    .map_err(|_| StoreError::Internal)?;
    Ok(object_hash(ObjectHashProfile::V1, &bytes).0)
}

impl Manifest {
    /// A new vault's manifest: the control IDs, no records yet.
    pub(crate) fn empty(
        header: &Header,
        vault_meta_id: RecordId,
        keyslot_id: RecordId,
        root_group_id: RecordId,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            config_digest: config_digest(header)?,
            vault_meta_id,
            keyslot_id,
            root_group_id,
            records: Vec::new(),
            references: Vec::new(),
        })
    }

    /// The vault metadata record (0003 §2.3).
    pub fn vault_meta_id(&self) -> RecordId {
        self.vault_meta_id
    }

    /// The password-keyslot record.
    pub fn keyslot_id(&self) -> RecordId {
        self.keyslot_id
    }

    /// The root group, fixed at creation.
    pub fn root_group_id(&self) -> RecordId {
        self.root_group_id
    }

    /// Every record, ascending by record ID.
    pub fn records(&self) -> &[RecordEntry] {
        &self.records
    }

    /// One record.
    pub fn record(&self, id: RecordId) -> Option<&RecordEntry> {
        self.records
            .binary_search_by(|r| r.record_id.cmp(&id))
            .ok()
            .and_then(|i| self.records.get(i))
    }

    /// Every object reference, ascending by object ID.
    pub fn references(&self) -> &[ObjectRef] {
        &self.references
    }

    /// The reference of one object.
    pub fn reference(&self, id: ObjectId) -> Option<&ObjectRef> {
        self.references
            .binary_search_by(|r| r.object_id.cmp(&id))
            .ok()
            .and_then(|i| self.references.get(i))
    }

    /// The configuration digest the manifest commits to.
    pub(crate) fn config_digest(&self) -> &[u8; 32] {
        &self.config_digest
    }

    /// SHA-256 of the canonical sorted reference list (0004 §3.5).
    pub fn reference_digest(&self) -> Result<[u8; 32], StoreError> {
        let mut e = Encoder::new();
        encode_references(&self.references, &mut e).map_err(|_| StoreError::Internal)?;
        let bytes = e.finish().map_err(|_| StoreError::Internal)?;
        Ok(object_hash(ObjectHashProfile::V1, &bytes).0)
    }

    /// The canonical plaintext.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let mut e = Encoder::new();
        e.map(|m| {
            m.entry(0, |e| {
                e.uint(MANIFEST_FORMAT);
                Ok(())
            })?;
            m.entry(1, |e| {
                e.bytes(&self.config_digest);
                Ok(())
            })?;
            m.entry(2, |e| {
                e.array(|a| {
                    a.bytes(&self.vault_meta_id.0);
                    a.bytes(&self.keyslot_id.0);
                    a.bytes(&self.root_group_id.0);
                    Ok(())
                })
            })?;
            m.entry(3, |e| {
                e.array(|a| {
                    for r in &self.records {
                        a.array(|x| {
                            x.bytes(&r.record_id.0);
                            x.array(|h| {
                                for v in &r.heads {
                                    encode_version(v, h)?;
                                }
                                Ok(())
                            })?;
                            x.array(|h| {
                                for v in &r.history {
                                    encode_version(v, h)?;
                                }
                                Ok(())
                            })?;
                            r.floor.encode(x)
                        })?;
                    }
                    Ok(())
                })
            })?;
            m.entry(4, |e| encode_references(&self.references, e))
        })
        .map_err(|_| StoreError::Internal)?;
        e.finish().map_err(|_| StoreError::Internal)
    }

    /// Decodes and validates a decrypted manifest plaintext (every rule in
    /// the module docs). Public for the `manifest_decode` fuzz target;
    /// vaults open manifests only after authenticating them.
    pub fn decode(input: &[u8]) -> Result<Self, StoreError> {
        let mut d = Decoder::new(input).map_err(malformed)?;
        let mut format = None;
        let mut config_digest = None;
        let mut control = None;
        let mut records = None;
        let mut references = None;
        let mut counts = Counts::default();
        for _ in 0..d.map().map_err(malformed)? {
            match d.int().map_err(malformed)? {
                0 => format = Some(d.uint().map_err(malformed)?),
                1 => {
                    let b: [u8; 32] = d
                        .bytes()
                        .map_err(malformed)?
                        .try_into()
                        .map_err(malformed)?;
                    config_digest = Some(b);
                }
                2 => {
                    if d.array().map_err(malformed)? != 3 {
                        return Err(StoreError::Integrity);
                    }
                    control = Some((
                        read_record_id(&mut d)?,
                        read_record_id(&mut d)?,
                        read_record_id(&mut d)?,
                    ));
                }
                3 => {
                    let n = read_len(&mut d, MAX_RECORDS)?;
                    let mut list = Vec::with_capacity(n);
                    for _ in 0..n {
                        if d.array().map_err(malformed)? != 4 {
                            return Err(StoreError::Integrity);
                        }
                        let record_id = read_record_id(&mut d)?;
                        let nh = read_len(&mut d, MAX_HEADS)?;
                        let mut heads = Vec::with_capacity(nh);
                        for _ in 0..nh {
                            heads.push(decode_version(&mut d, &mut counts)?);
                        }
                        let remaining = MAX_OBJECTS.saturating_sub(counts.versions);
                        let nhist = read_len(&mut d, remaining)?;
                        let mut history = Vec::with_capacity(nhist);
                        for _ in 0..nhist {
                            history.push(decode_version(&mut d, &mut counts)?);
                        }
                        let floor = Clock::decode(&mut d)?;
                        counts.add_clock(&floor)?;
                        list.push(RecordEntry {
                            record_id,
                            heads,
                            history,
                            floor,
                        });
                    }
                    records = Some(list);
                }
                4 => {
                    let n = read_len(&mut d, MAX_OBJECTS)?;
                    let mut list = Vec::with_capacity(n);
                    for _ in 0..n {
                        if d.array().map_err(malformed)? != 4 {
                            return Err(StoreError::Integrity);
                        }
                        let object_id = read_id(&mut d)?;
                        let profile =
                            u16::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
                        let data_profile = StoredDataProfile::from_id(profile)?;
                        let length = d.uint().map_err(malformed)?;
                        let sha256: [u8; 32] = d
                            .bytes()
                            .map_err(malformed)?
                            .try_into()
                            .map_err(malformed)?;
                        list.push(ObjectRef {
                            object_id,
                            data_profile,
                            length,
                            sha256,
                        });
                    }
                    references = Some(list);
                }
                _ => return Err(StoreError::Unsupported),
            }
        }
        d.finish().map_err(malformed)?;
        if format.ok_or(StoreError::Integrity)? != MANIFEST_FORMAT {
            return Err(StoreError::Unsupported);
        }
        let (vault_meta_id, keyslot_id, root_group_id) = control.ok_or(StoreError::Integrity)?;
        let m = Self {
            config_digest: config_digest.ok_or(StoreError::Integrity)?,
            vault_meta_id,
            keyslot_id,
            root_group_id,
            records: records.ok_or(StoreError::Integrity)?,
            references: references.ok_or(StoreError::Integrity)?,
        };
        m.validate()?;
        Ok(m)
    }

    /// Every structural rule and budget (see the module docs).
    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        if self.records.len() > MAX_RECORDS || self.references.len() > MAX_OBJECTS {
            return Err(StoreError::LimitExceeded);
        }
        if self
            .records
            .windows(2)
            .any(|w| w[0].record_id >= w[1].record_id)
            || self
                .references
                .windows(2)
                .any(|w| w[0].object_id >= w[1].object_id)
        {
            return Err(StoreError::Integrity);
        }
        let control = [self.vault_meta_id, self.keyslot_id, self.root_group_id];
        if control[0] == control[1] || control[0] == control[2] || control[1] == control[2] {
            return Err(StoreError::Integrity);
        }
        if control.iter().any(|&id| self.record(id).is_none()) {
            return Err(StoreError::Integrity);
        }

        let total = self
            .references
            .iter()
            .try_fold(0u64, |t, r| t.checked_add(r.length))
            .ok_or(StoreError::LimitExceeded)?;
        if total > MAX_TOTAL_CIPHERTEXT {
            return Err(StoreError::LimitExceeded);
        }

        let chunk_len = chunk_ciphertext_len()?;
        let min_len = min_ciphertext_len()?;
        let max_record = u64::try_from(MAX_RECORD_CIPHERTEXT).map_err(|_| StoreError::Internal)?;
        let mut used = vec![false; self.references.len()];
        let mut use_role = |id: ObjectId, chunk: bool| -> Result<(), StoreError> {
            let i = self
                .references
                .binary_search_by(|r| r.object_id.cmp(&id))
                .map_err(|_| StoreError::Integrity)?;
            let slot = used.get_mut(i).ok_or(StoreError::Internal)?;
            if *slot {
                return Err(StoreError::Integrity);
            }
            *slot = true;
            let len = self.references.get(i).ok_or(StoreError::Internal)?.length;
            let fits = if chunk {
                len == chunk_len
            } else {
                (min_len..=max_record).contains(&len)
            };
            if fits {
                Ok(())
            } else {
                Err(StoreError::Integrity)
            }
        };

        let mut components = 0usize;
        let mut versions = 0usize;
        for r in &self.records {
            if r.heads.is_empty() {
                return Err(StoreError::Integrity);
            }
            if r.heads.len() > MAX_HEADS {
                return Err(StoreError::LimitExceeded);
            }
            for list in [&r.heads, &r.history] {
                if list.windows(2).any(|w| w[0].version_id >= w[1].version_id) {
                    return Err(StoreError::Integrity);
                }
            }
            components = components
                .checked_add(r.floor.pairs().len())
                .ok_or(StoreError::LimitExceeded)?;
            let all: Vec<&VersionRef> = r.heads.iter().chain(r.history.iter()).collect();
            versions = versions
                .checked_add(all.len())
                .ok_or(StoreError::LimitExceeded)?;
            for v in &all {
                if v.clock.is_empty() {
                    return Err(StoreError::Integrity);
                }
                components = components
                    .checked_add(v.clock.pairs().len())
                    .ok_or(StoreError::LimitExceeded)?;
                use_role(v.object_id, false)?;
                if let Some(chunks) = &v.chunks {
                    if chunks.len() > MAX_CHUNKS {
                        return Err(StoreError::LimitExceeded);
                    }
                    for &c in chunks {
                        use_role(c, true)?;
                    }
                }
            }
            if components > MAX_CLOCK_COMPONENTS || versions > MAX_OBJECTS {
                return Err(StoreError::LimitExceeded);
            }
            // Version IDs unique across heads and history (both lists are
            // sorted, so a merged sort finds duplicates).
            let mut ids: Vec<VersionId> = all.iter().map(|v| v.version_id).collect();
            ids.sort_unstable();
            if ids.windows(2).any(|w| w[0] == w[1]) {
                return Err(StoreError::Integrity);
            }
            // Clocks unique within the record (0005 §1.4).
            let mut clocks: Vec<&Clock> = all.iter().map(|v| &v.clock).collect();
            clocks.sort_unstable_by(|a, b| a.pairs().cmp(b.pairs()));
            if clocks.windows(2).any(|w| w[0] == w[1]) {
                return Err(StoreError::Integrity);
            }
            // Heads pairwise concurrent: none dominates another.
            for (i, a) in r.heads.iter().enumerate() {
                for b in r.heads.iter().skip(i + 1) {
                    if a.clock.compare(&b.clock) != Causality::Concurrent {
                        return Err(StoreError::Integrity);
                    }
                }
            }
            let floor = HistoryFloor::new(r.floor.clone());
            for h in &r.history {
                if !r.heads.iter().any(|head| head.clock.dominates(&h.clock))
                    || floor.suppresses(&h.clock)
                {
                    return Err(StoreError::Integrity);
                }
            }
        }
        if used.iter().any(|u| !u) {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }

    fn record_index(&self, id: RecordId) -> Result<usize, usize> {
        self.records.binary_search_by(|r| r.record_id.cmp(&id))
    }

    pub(crate) fn insert_reference(&mut self, r: ObjectRef) -> Result<(), StoreError> {
        match self
            .references
            .binary_search_by(|x| x.object_id.cmp(&r.object_id))
        {
            Ok(_) => Err(StoreError::Internal),
            Err(i) => {
                self.references.insert(i, r);
                Ok(())
            }
        }
    }

    /// Adds a new record with one head. The caller has checked the edit;
    /// [`Self::validate`] runs before the manifest is sealed.
    pub(crate) fn add_record(
        &mut self,
        record_id: RecordId,
        head: VersionRef,
        object: ObjectRef,
    ) -> Result<(), StoreError> {
        let i = match self.record_index(record_id) {
            Ok(_) => return Err(StoreError::Internal),
            Err(i) => i,
        };
        self.insert_reference(object)?;
        self.records.insert(
            i,
            RecordEntry {
                record_id,
                heads: vec![head],
                history: Vec::new(),
                floor: Clock::new(),
            },
        );
        Ok(())
    }

    /// Replaces every head of `record_id` with `head`; the old heads move to
    /// history (0005 §2.1). The caller has checked that `head` dominates
    /// them.
    pub(crate) fn replace_heads(
        &mut self,
        record_id: RecordId,
        head: VersionRef,
        object: ObjectRef,
    ) -> Result<(), StoreError> {
        let i = self
            .record_index(record_id)
            .map_err(|_| StoreError::Internal)?;
        self.insert_reference(object)?;
        let r = self.records.get_mut(i).ok_or(StoreError::Internal)?;
        let old = core::mem::replace(&mut r.heads, vec![head]);
        r.history.extend(old);
        r.history.sort_by_key(|v| v.version_id);
        Ok(())
    }

    /// Replaces every head of `record_id` with the final tombstone `head`
    /// and drops all of its history (0007 §2.2). The floor becomes the join
    /// of the old floor and every dropped version's clock: it covers only
    /// versions that are removed, as 0007 §1.3–1.4 require, so an old copy
    /// cannot bring them back. The dropped versions' references (and chunk
    /// references) are removed; the commit prunes their rows. The caller has
    /// checked that `head` dominates the old heads.
    pub(crate) fn finalize(
        &mut self,
        record_id: RecordId,
        head: VersionRef,
        object: ObjectRef,
    ) -> Result<(), StoreError> {
        let i = self
            .record_index(record_id)
            .map_err(|_| StoreError::Internal)?;
        self.insert_reference(object)?;
        let r = self.records.get_mut(i).ok_or(StoreError::Internal)?;
        let old_heads = core::mem::replace(&mut r.heads, vec![head]);
        let old_history = core::mem::take(&mut r.history);
        let mut floor = r.floor.clone();
        let mut dropped = Vec::new();
        for v in old_heads.into_iter().chain(old_history) {
            floor = floor.join(&v.clock)?;
            dropped.push(v.object_id);
            dropped.extend(v.chunks.into_iter().flatten());
        }
        r.floor = floor;
        for id in dropped {
            let k = self
                .references
                .binary_search_by(|x| x.object_id.cmp(&id))
                .map_err(|_| StoreError::Internal)?;
            self.references.remove(k);
        }
        Ok(())
    }

    /// This manifest's control IDs and configuration digest with `other`'s
    /// records and references (tests build hostile manifests with it).
    #[cfg(test)]
    pub(crate) fn with_records_of(mut self, other: &Manifest) -> Self {
        self.records = other.records.clone();
        self.references = other.references.clone();
        self
    }

    /// Replaces the control IDs (tests only).
    #[cfg(test)]
    pub(crate) fn set_control(&mut self, meta: RecordId, keyslot: RecordId, root: RecordId) {
        self.vault_meta_id = meta;
        self.keyslot_id = keyslot;
        self.root_group_id = root;
    }

    /// Removes one history version and its reference (and its chunks'),
    /// for retention and purge (phase 1.12) and the prune tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn remove_history(
        &mut self,
        record_id: RecordId,
        version: VersionId,
    ) -> Result<(), StoreError> {
        let i = self
            .record_index(record_id)
            .map_err(|_| StoreError::Internal)?;
        let r = self.records.get_mut(i).ok_or(StoreError::Internal)?;
        let j = r
            .history
            .iter()
            .position(|v| v.version_id == version)
            .ok_or(StoreError::Internal)?;
        let v = r.history.remove(j);
        let objects = core::iter::once(v.object_id).chain(v.chunks.into_iter().flatten());
        for id in objects {
            let k = self
                .references
                .binary_search_by(|x| x.object_id.cmp(&id))
                .map_err(|_| StoreError::Internal)?;
            self.references.remove(k);
        }
        Ok(())
    }

    /// Drops retained history and advances the record floor to its heads.
    /// Active heads and their references remain present (0007 §1.4).
    pub(crate) fn purge_history(&mut self, record_id: RecordId) -> Result<(), StoreError> {
        let i = self
            .record_index(record_id)
            .map_err(|_| StoreError::NotFound)?;
        let r = self.records.get_mut(i).ok_or(StoreError::Internal)?;
        let mut floor = r.floor.clone();
        for head in &r.heads {
            floor = floor.join(head.clock())?;
        }
        r.floor = floor;
        let old = core::mem::take(&mut r.history);
        let mut dropped = std::collections::BTreeSet::new();
        for v in old {
            let ids = core::iter::once(v.object_id).chain(v.chunks.into_iter().flatten());
            dropped.extend(ids);
        }
        self.references.retain(|r| !dropped.contains(&r.object_id));
        Ok(())
    }

    /// Applies a monotonic floor and drops only explicitly eligible covered history.
    pub(crate) fn retain_history(
        &mut self,
        record_id: RecordId,
        floor: Clock,
        eligible: &std::collections::BTreeSet<VersionId>,
    ) -> Result<(), StoreError> {
        let i = self
            .record_index(record_id)
            .map_err(|_| StoreError::NotFound)?;
        let r = self.records.get_mut(i).ok_or(StoreError::Internal)?;
        r.floor = r.floor.join(&floor)?;
        let suppressed = HistoryFloor::new(r.floor.clone());
        let mut dropped = std::collections::BTreeSet::new();
        r.history.retain(|v| {
            if eligible.contains(&v.version_id) && suppressed.suppresses(&v.clock) {
                dropped.insert(v.object_id);
                dropped.extend(v.chunks.iter().flatten().copied());
                false
            } else {
                true
            }
        });
        self.references.retain(|r| !dropped.contains(&r.object_id));
        Ok(())
    }
}

/// `["qv/manifest/v1", vault_id, key_generation, data_profile]`.
fn manifest_aad(
    scope: Scope,
    profile: StoredDataProfile,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    encode_array(|a| {
        a.text(AAD_LABEL);
        a.bytes(&scope.vault_id.0);
        a.uint(u64::from(scope.key_generation.0));
        a.uint(u64::from(profile.id()));
        Ok(())
    })
    .map_err(|_| StoreError::Internal)
}

/// An encrypted manifest and its hash.
pub(crate) struct SealedManifest {
    pub(crate) key_generation: KeyGeneration,
    pub(crate) data_profile: StoredDataProfile,
    pub(crate) nonce: [u8; 24],
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) hash: [u8; 32],
}

/// The shortest CBOR head of a byte string of `len` bytes.
fn bstr_head(len: usize) -> Vec<u8> {
    let len = len as u64;
    if len < 24 {
        vec![0x40 | len as u8]
    } else if len <= 0xff {
        vec![0x58, len as u8]
    } else if len <= 0xffff {
        let mut v = vec![0x59];
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v
    } else if len <= 0xffff_ffff {
        let mut v = vec![0x5a];
        v.extend_from_slice(&(len as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![0x5b];
        v.extend_from_slice(&len.to_be_bytes());
        v
    }
}

/// SHA-256 of the canonical envelope `[key_generation, data_profile, nonce,
/// ciphertext]`, hashed in a stream: the prefix, then the ciphertext.
pub(crate) fn envelope_hash(
    generation: KeyGeneration,
    profile: StoredDataProfile,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<[u8; 32], StoreError> {
    let mut e = Encoder::new();
    e.uint(u64::from(generation.0));
    let gen_bytes = e.finish().map_err(|_| StoreError::Internal)?;
    let mut e = Encoder::new();
    e.uint(u64::from(profile.id()));
    let profile_bytes = e.finish().map_err(|_| StoreError::Internal)?;
    let mut h = ObjectHasher::new(ObjectHashProfile::V1);
    h.update(&[0x84]);
    h.update(&gen_bytes);
    h.update(&profile_bytes);
    h.update(&bstr_head(nonce.len()));
    h.update(nonce);
    h.update(&bstr_head(ciphertext.len()));
    h.update(ciphertext);
    Ok(h.finalize().0)
}

/// The canonical manifest envelope `[key_generation, data_profile, nonce,
/// ciphertext]` (0004 §3.5, §6.1). `manifest_hash` is the SHA-256 of exactly
/// these bytes, which is what an archive's manifest frame carries.
pub(crate) fn envelope_bytes(
    generation: KeyGeneration,
    profile: StoredDataProfile,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut e = Encoder::new();
    e.array(|a| {
        a.uint(u64::from(generation.0));
        a.uint(u64::from(profile.id()));
        a.bytes(nonce);
        a.bytes(ciphertext);
        Ok(())
    })
    .map_err(|_| StoreError::Internal)?;
    e.finish().map_err(|_| StoreError::Internal)
}

/// Encrypts a validated manifest.
pub(crate) fn seal_manifest(
    key: &PurposeKey<purpose::Manifest>,
    scope: Scope,
    profile: StoredDataProfile,
    manifest: &Manifest,
) -> Result<SealedManifest, StoreError> {
    manifest.validate()?;
    let plaintext = manifest.encode()?;
    let aad = manifest_aad(scope, profile)?;
    let sealed = qv_crypto::seal(key, profile, &aad, &plaintext, MAX_MANIFEST_CIPHERTEXT)?;
    let hash = envelope_hash(
        scope.key_generation,
        profile,
        &sealed.nonce,
        &sealed.ciphertext,
    )?;
    Ok(SealedManifest {
        key_generation: scope.key_generation,
        data_profile: profile,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        hash,
    })
}

/// Decrypts, decodes and validates a stored manifest. The caller has checked
/// its hash against the authenticated head.
pub(crate) fn open_manifest(
    key: &PurposeKey<purpose::Manifest>,
    scope: Scope,
    profile: StoredDataProfile,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Manifest, StoreError> {
    let aad = manifest_aad(scope, profile)?;
    let plaintext = qv_crypto::open(
        key,
        profile,
        &aad,
        nonce,
        ciphertext,
        MAX_MANIFEST_CIPHERTEXT,
    )?;
    Manifest::decode(plaintext.expose_secret())
}

#[cfg(test)]
pub(crate) mod tests {
    use qv_crypto::{DerivationProfile, VaultId, VaultKey};
    use qv_model::WriterId;

    use super::*;
    use crate::header::tests::v4;

    pub(crate) fn rid(n: u8) -> RecordId {
        RecordId(v4(n))
    }

    fn id16(n: u32) -> [u8; 16] {
        let mut b = v4(0);
        b[0..4].copy_from_slice(&n.to_be_bytes());
        b
    }

    fn oid(n: u32) -> ObjectId {
        ObjectId::from_bytes(id16(n)).unwrap()
    }

    fn vid(n: u32) -> VersionId {
        VersionId::from_bytes(id16(n)).unwrap()
    }

    fn writer(n: u32) -> WriterId {
        WriterId::from_bytes(id16(n)).unwrap()
    }

    fn clock(pairs: &[(u32, u64)]) -> Clock {
        let mut p: Vec<_> = pairs.iter().map(|&(w, c)| (writer(w), c)).collect();
        p.sort();
        Clock::from_pairs(p).unwrap()
    }

    fn header() -> Header {
        Header::new_vault(VaultId(v4(0x31)))
    }

    fn reference(id: ObjectId, len: u64) -> ObjectRef {
        ObjectRef {
            object_id: id,
            data_profile: StoredDataProfile::V1,
            length: len,
            sha256: [7; 32],
        }
    }

    /// Control records 1–3, each with one head; record 4 with a head and two
    /// history versions. Objects are numbered by the version they hold.
    pub(crate) fn sample() -> Manifest {
        let mut m = Manifest::empty(&header(), rid(1), rid(2), rid(3)).unwrap();
        for n in 1..=4u8 {
            let k = u32::from(n);
            m.add_record(
                rid(n),
                VersionRef::new(vid(k), clock(&[(1, u64::from(n))]), oid(k)),
                reference(oid(k), 100),
            )
            .unwrap();
        }
        m.replace_heads(
            rid(4),
            VersionRef::new(vid(40), clock(&[(1, 10)]), oid(40)),
            reference(oid(40), 100),
        )
        .unwrap();
        m.replace_heads(
            rid(4),
            VersionRef::new(vid(41), clock(&[(1, 11), (2, 1)]), oid(41)),
            reference(oid(41), 100),
        )
        .unwrap();
        m.validate().unwrap();
        m
    }

    fn reencode(m: &Manifest) -> Result<Manifest, StoreError> {
        Manifest::decode(&m.encode().unwrap())
    }

    #[test]
    fn manifest_round_trip() {
        let m = sample();
        let bytes = m.encode().unwrap();
        let back = Manifest::decode(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.encode().unwrap().as_slice(), bytes.as_slice());
        let r4 = back.record(rid(4)).unwrap();
        assert_eq!(r4.heads().len(), 1);
        assert_eq!(r4.heads()[0].version_id(), vid(41));
        assert_eq!(r4.history().len(), 2);
        assert!(r4.version(vid(4)).is_some());
        assert_eq!(back.references().len(), 6);
        assert!(back.reference(oid(40)).is_some());
        assert_eq!(back.config_digest(), &config_digest(&header()).unwrap());
        assert_ne!(back.reference_digest().unwrap(), [0; 32]);
    }

    #[test]
    fn manifest_envelope_bytes_hash_to_the_manifest_hash() {
        let nonce = [9u8; 24];
        let ciphertext = vec![7u8; 4096];
        let bytes =
            envelope_bytes(KeyGeneration(1), StoredDataProfile::V1, &nonce, &ciphertext).unwrap();
        assert_eq!(
            object_hash(ObjectHashProfile::V1, &bytes).0,
            envelope_hash(KeyGeneration(1), StoredDataProfile::V1, &nonce, &ciphertext).unwrap(),
            "the re-encoded envelope must hash to the stored manifest hash"
        );
        // An archive frame wraps it as a canonical four-element array.
        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.array().unwrap(), 4);
        assert_eq!(d.uint().unwrap(), 1);
        assert_eq!(d.uint().unwrap(), 1);
        assert_eq!(d.bytes().unwrap(), nonce.as_slice());
        assert_eq!(d.bytes().unwrap(), ciphertext.as_slice());
        d.finish().unwrap();
    }

    #[test]
    fn history_purge_keeps_conflicting_heads_tombstones_and_their_references() {
        let mut m = sample();
        let i = m.record_index(rid(4)).unwrap();
        let second = VersionRef::new(vid(42), clock(&[(1, 10), (2, 2)]), oid(42));
        m.records[i].heads.push(second);
        m.insert_reference(reference(oid(42), 100)).unwrap();
        m.validate().unwrap();
        let heads = m.records[i].heads.clone();
        m.purge_history(rid(4)).unwrap();
        m.validate().unwrap();
        assert_eq!(m.records[i].heads, heads);
        assert!(m.records[i].history.is_empty());
        assert!(
            heads
                .iter()
                .all(|h| m.records[i].floor().suppresses(h.clock()))
        );
        assert!(heads.iter().all(|h| m.reference(h.object_id()).is_some()));
        let floor = m.records[i].floor();
        m.purge_history(rid(4)).unwrap();
        assert_eq!(m.records[i].floor(), floor);
    }

    #[test]
    fn manifest_structure_rejections() {
        let check = |f: &dyn Fn(&mut Manifest)| {
            let mut m = sample();
            f(&mut m);
            (m.validate().err(), reencode(&m).err())
        };
        let integrity = (Some(StoreError::Integrity), Some(StoreError::Integrity));
        // Unsorted and duplicate records.
        assert_eq!(check(&|m| m.records.swap(0, 1)), integrity);
        assert_eq!(
            check(&|m| {
                let r = m.records[0].clone();
                m.records.insert(0, r);
            }),
            integrity
        );
        // Unsorted references; a duplicate reference.
        assert_eq!(check(&|m| m.references.swap(0, 1)), integrity);
        assert_eq!(
            check(&|m| {
                let r = m.references[0];
                m.references.insert(0, r);
            }),
            integrity
        );
        // A role with no reference; a reference with no role; two roles
        // sharing one object.
        assert_eq!(
            check(&|m| {
                m.references.retain(|r| r.object_id != oid(40));
            }),
            integrity
        );
        assert_eq!(
            check(&|m| {
                m.references.push(reference(oid(999), 100));
            }),
            integrity
        );
        assert_eq!(
            check(&|m| {
                m.records[3].history[0].object_id = oid(41);
                m.references.retain(|r| r.object_id != oid(4));
            }),
            integrity
        );
        // Unsorted history; a history version not dominated by the head;
        // one equal to the head clock; one under the floor.
        assert_eq!(check(&|m| m.records[3].history.swap(0, 1)), integrity);
        assert_eq!(
            check(&|m| m.records[3].history[0].clock = clock(&[(3, 1)])),
            integrity
        );
        assert_eq!(
            check(&|m| m.records[3].history[0].clock = clock(&[(1, 11), (2, 1)])),
            integrity
        );
        assert_eq!(check(&|m| m.records[3].floor = clock(&[(1, 4)])), integrity);
        // Two heads where one dominates the other.
        assert_eq!(
            check(&|m| {
                let h = m.records[3].history.pop().unwrap();
                m.records[3].heads.insert(0, h);
            }),
            integrity
        );
        // A version ID in both heads and history.
        assert_eq!(
            check(&|m| m.records[3].history[0].version_id = vid(41)),
            integrity
        );
        // No heads; an empty clock.
        assert_eq!(check(&|m| m.records[0].heads.clear()), integrity);
        assert_eq!(
            check(&|m| m.records[0].heads[0].clock = Clock::new()),
            integrity
        );
        // A control ID with no record, and two equal control IDs.
        assert_eq!(check(&|m| m.root_group_id = rid(9)), integrity);
        assert_eq!(check(&|m| m.keyslot_id = rid(1)), integrity);
        // Role-dependent object lengths: too short, too long, a chunk of
        // the wrong length.
        assert_eq!(check(&|m| m.references[0].length = 19), integrity);
        assert_eq!(
            check(&|m| m.references[0].length = MAX_RECORD_CIPHERTEXT as u64 + 1),
            integrity
        );
        assert_eq!(
            check(&|m| {
                m.records[0].heads[0].chunks = Some(vec![oid(500)]);
                m.references.push(reference(oid(500), 100));
                m.references.sort_by_key(|r| r.object_id);
            }),
            integrity
        );
        // The same with the right chunk length passes.
        let mut m = sample();
        m.records[0].heads[0].chunks = Some(vec![oid(500)]);
        m.references
            .push(reference(oid(500), chunk_ciphertext_len().unwrap()));
        m.references.sort_by_key(|r| r.object_id);
        assert_eq!(reencode(&m).unwrap(), m);
    }

    /// Map entries written by closures.
    type Entries<'a> = [(i64, &'a dyn Fn(&mut Encoder))];

    /// A manifest map with the given entries, for key-level tests.
    fn raw_manifest(entries: &Entries<'_>) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(|m| {
            for (k, f) in entries {
                m.entry(*k, |e| {
                    f(e);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .unwrap();
        e.finish().unwrap().to_vec()
    }

    #[test]
    fn manifest_key_rejections() {
        let good = sample().encode().unwrap().to_vec();
        // Rebuild the sample's entries from its decoded parts.
        let mut d = Decoder::new(&good).unwrap();
        let n = d.map().unwrap();
        let mut items: Vec<(i64, Vec<u8>)> = Vec::new();
        for _ in 0..n {
            let k = d.int().unwrap();
            items.push((k, d.raw_item().unwrap().to_vec()));
        }
        let build = |skip: Option<i64>, extra: Option<i64>, format: Option<u64>| {
            let mut e = Encoder::new();
            e.map(|m| {
                for (k, v) in &items {
                    if Some(*k) == skip {
                        continue;
                    }
                    if *k == 0
                        && let Some(f) = format
                    {
                        m.entry(0, |e| {
                            e.uint(f);
                            Ok(())
                        })?;
                        continue;
                    }
                    m.raw_entry(*k, &qv_encoding::RawValue::from_canonical(v).unwrap())?;
                }
                if let Some(x) = extra {
                    m.entry(x, |e| {
                        e.uint(0);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap();
            e.finish().unwrap().to_vec()
        };
        assert_eq!(
            Manifest::decode(&build(None, None, None)).unwrap(),
            sample()
        );
        for k in 0..=4 {
            assert_eq!(
                Manifest::decode(&build(Some(k), None, None)).err(),
                Some(StoreError::Integrity),
                "missing key {k}"
            );
        }
        assert_eq!(
            Manifest::decode(&build(None, Some(5), None)).err(),
            Some(StoreError::Unsupported)
        );
        assert_eq!(
            Manifest::decode(&build(None, Some(-1), None)).err(),
            Some(StoreError::Unsupported)
        );
        assert_eq!(
            Manifest::decode(&build(None, None, Some(1))).err(),
            Some(StoreError::Unsupported)
        );
        // An unknown reference profile.
        let refs = raw_manifest(&[(4, &|e: &mut Encoder| {
            e.array(|a| {
                a.array(|x| {
                    x.bytes(&oid(1).to_bytes());
                    x.uint(2);
                    x.uint(100);
                    x.bytes(&[0; 32]);
                    Ok(())
                })
            })
            .unwrap();
        })]);
        assert_eq!(Manifest::decode(&refs).err(), Some(StoreError::Unsupported));
        assert_eq!(Manifest::decode(&[0x80]).err(), Some(StoreError::Integrity));
        let mut trailing = good;
        trailing.push(0);
        assert_eq!(
            Manifest::decode(&trailing).err(),
            Some(StoreError::Integrity)
        );
    }

    #[test]
    fn manifest_budgets() {
        // A records array claiming more than the budget is refused from its
        // header; the decoder never reaches the (missing) elements, because
        // validation fails first or the count check does.
        let over = |key: i64, n: usize, item: &dyn Fn(&mut Encoder)| {
            raw_manifest(&[(key, &|e: &mut Encoder| {
                e.array(|a| {
                    for _ in 0..n {
                        item(a);
                    }
                    Ok(())
                })
                .unwrap();
            })])
        };
        let empty_rec = |a: &mut Encoder| {
            a.array(|x| {
                x.bytes(&v4(1));
                x.array(|_| Ok(()))?;
                x.array(|_| Ok(()))?;
                x.array(|_| Ok(()))
            })
            .unwrap();
        };
        assert_eq!(
            Manifest::decode(&over(3, MAX_RECORDS + 1, &empty_rec)).err(),
            Some(StoreError::LimitExceeded)
        );
        let ref_item = |a: &mut Encoder| {
            a.array(|x| {
                x.bytes(&v4(1));
                x.uint(1);
                x.uint(100);
                x.bytes(&[0; 32]);
                Ok(())
            })
            .unwrap();
        };
        assert_eq!(
            Manifest::decode(&over(4, MAX_OBJECTS + 1, &ref_item)).err(),
            Some(StoreError::LimitExceeded)
        );
        // 257 heads in one record.
        let heads = raw_manifest(&[(3, &|e: &mut Encoder| {
            e.array(|a| {
                a.array(|x| {
                    x.bytes(&v4(1));
                    x.array(|h| {
                        for i in 0..=MAX_HEADS as u32 {
                            h.array(|v| {
                                v.bytes(&id16(i));
                                clock(&[(i, 1)]).encode(v)?;
                                v.bytes(&id16(i));
                                Ok(())
                            })?;
                        }
                        Ok(())
                    })?;
                    x.array(|_| Ok(()))?;
                    x.array(|_| Ok(()))
                })
            })
            .unwrap();
        })]);
        assert_eq!(
            Manifest::decode(&heads).err(),
            Some(StoreError::LimitExceeded)
        );
        // 161 chunks.
        let mut m = sample();
        m.records[0].heads[0].chunks =
            Some((0..=MAX_CHUNKS as u32).map(|i| oid(1000 + i)).collect());
        assert_eq!(reencode(&m).err(), Some(StoreError::LimitExceeded));
        assert_eq!(m.validate().err(), Some(StoreError::LimitExceeded));
        // Total referenced ciphertext over 1 GiB.
        let mut m = sample();
        m.references[0].length = MAX_TOTAL_CIPHERTEXT;
        assert_eq!(m.validate().err(), Some(StoreError::LimitExceeded));
        // Clock components: a floor of 256 writers on many records.
        let mut m = sample();
        let wide = clock(&(0..256).map(|w| (w, 1)).collect::<Vec<_>>());
        let wide_head = clock(&(0..256).map(|w| (w, 2)).collect::<Vec<_>>());
        let records = MAX_CLOCK_COMPONENTS / 512 + 1;
        for i in 0..records as u32 {
            let id = RecordId(id16(0x7000_0000 + i));
            m.add_record(
                id,
                VersionRef::new(
                    vid(0x7000_0000 + i),
                    wide_head.clone(),
                    oid(0x7000_0000 + i),
                ),
                reference(oid(0x7000_0000 + i), 100),
            )
            .unwrap();
            let k = m.record_index(id).unwrap();
            m.records[k].floor = wide.clone();
        }
        assert_eq!(m.validate().err(), Some(StoreError::LimitExceeded));
        assert_eq!(reencode(&m).err(), Some(StoreError::LimitExceeded));
    }

    #[test]
    fn manifest_envelope_hash_matches_full_encoding() {
        for len in [0usize, 23, 24, 255, 256, 65_535, 65_536, 70_000] {
            let ciphertext = vec![0x5a; len];
            let nonce = [3u8; 24];
            let mut e = Encoder::new();
            e.array(|a| {
                a.uint(7);
                a.uint(1);
                a.bytes(&nonce);
                a.bytes(&ciphertext);
                Ok(())
            })
            .unwrap();
            let full = e.finish().unwrap();
            assert_eq!(
                envelope_hash(KeyGeneration(7), StoredDataProfile::V1, &nonce, &ciphertext)
                    .unwrap(),
                object_hash(ObjectHashProfile::V1, &full).0,
                "len {len}"
            );
        }
    }

    #[test]
    fn manifest_seal_binds_scope() {
        let vk = VaultKey::generate().unwrap();
        let h = header();
        let scope = Scope {
            vault_id: h.vault_id,
            key_generation: h.key_generation,
        };
        let key = |s: Scope| {
            vk.purpose_key::<purpose::Manifest>(s.vault_id, s.key_generation, DerivationProfile::V1)
                .unwrap()
        };
        let m = sample();
        let sealed = seal_manifest(&key(scope), scope, StoredDataProfile::V1, &m).unwrap();
        assert_eq!(
            sealed.hash,
            envelope_hash(
                sealed.key_generation,
                sealed.data_profile,
                &sealed.nonce,
                &sealed.ciphertext
            )
            .unwrap()
        );
        let back = open_manifest(
            &key(scope),
            scope,
            StoredDataProfile::V1,
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .unwrap();
        assert_eq!(back, m);
        // Same key, another vault ID or generation in the AAD.
        for other in [
            Scope {
                vault_id: VaultId(v4(0x32)),
                ..scope
            },
            Scope {
                key_generation: KeyGeneration(2),
                ..scope
            },
        ] {
            assert_eq!(
                open_manifest(
                    &key(scope),
                    other,
                    StoredDataProfile::V1,
                    &sealed.nonce,
                    &sealed.ciphertext
                )
                .err(),
                Some(StoreError::Integrity)
            );
        }
        // A profile byte other than the one sealed (built by hand: only V1).
        let mut aad = manifest_aad(scope, StoredDataProfile::V1).unwrap().to_vec();
        *aad.last_mut().unwrap() = 0x02;
        let wrong = qv_crypto::seal(
            &key(scope),
            StoredDataProfile::V1,
            &aad,
            &m.encode().unwrap(),
            MAX_MANIFEST_CIPHERTEXT,
        )
        .unwrap();
        assert_eq!(
            open_manifest(
                &key(scope),
                scope,
                StoredDataProfile::V1,
                &wrong.nonce,
                &wrong.ciphertext
            )
            .err(),
            Some(StoreError::Integrity)
        );
        // An invalid manifest is never sealed.
        let mut bad = m.clone();
        bad.records[0].heads.clear();
        assert_eq!(
            seal_manifest(&key(scope), scope, StoredDataProfile::V1, &bad).err(),
            Some(StoreError::Integrity)
        );
    }

    #[test]
    fn manifest_remove_history() {
        let mut m = sample();
        m.remove_history(rid(4), vid(4)).unwrap();
        m.validate().unwrap();
        assert!(m.reference(oid(4)).is_none());
        assert_eq!(m.record(rid(4)).unwrap().history().len(), 1);
    }

    /// The worst-case manifest at the maximum budgets (0004 §4.2, 0012 row
    /// "Budget inconsistency"): 50,000 records, 250,000 referenced version
    /// objects (a version object costs more manifest bytes than a chunk),
    /// exactly `MAX_CLOCK_COMPONENTS` clock components with 9-byte
    /// counters, and reference lengths chosen to maximize their encoding
    /// under the 1 GiB total.
    pub(crate) fn worst_case() -> Manifest {
        const VERSIONS_PER_RECORD: usize = 5;
        let records = MAX_RECORDS;
        assert_eq!(records * VERSIONS_PER_RECORD, MAX_OBJECTS);
        let big = 1u64 << 40;
        let writers: Vec<WriterId> = (0..17).map(|w| writer(0x2000_0000 + w)).collect();
        // History versions take one component each; heads take the rest.
        let history_components = records * (VERSIONS_PER_RECORD - 1);
        let head_components = MAX_CLOCK_COMPONENTS - history_components;
        let wide_heads = head_components - records * 16; // heads with 17 components
        let long_refs = 15_000; // references of 65,536 bytes (5-byte length)
        let mut m = Manifest {
            config_digest: [0xff; 32],
            vault_meta_id: RecordId(id16(0x1000_0000)),
            keyslot_id: RecordId(id16(0x1000_0001)),
            root_group_id: RecordId(id16(0x1000_0002)),
            records: Vec::with_capacity(records),
            references: Vec::with_capacity(MAX_OBJECTS),
        };
        let mut object = 0u32;
        for k in 0..records {
            let k32 = u32::try_from(k).unwrap();
            let n = if k < wide_heads { 17 } else { 16 };
            let mut head_pairs: Vec<(WriterId, u64)> =
                writers[..n].iter().map(|&w| (w, big)).collect();
            head_pairs[0].1 = big + 10;
            let mut versions: Vec<VersionRef> = Vec::new();
            for i in 0..VERSIONS_PER_RECORD {
                let clock = if i == 0 {
                    Clock::from_pairs(head_pairs.clone()).unwrap()
                } else {
                    Clock::from_pairs(vec![(writers[0], big + i as u64)]).unwrap()
                };
                let vid = VersionId::from_bytes(id16(0x3000_0000 + k32 * 8 + i as u32)).unwrap();
                versions.push(VersionRef::new(vid, clock, oid(object)));
                let length = if (object as usize) < long_refs {
                    65_536
                } else {
                    256
                };
                m.references.push(ObjectRef {
                    object_id: oid(object),
                    data_profile: StoredDataProfile::V1,
                    length,
                    sha256: [0xff; 32],
                });
                object += 1;
            }
            let head = versions.remove(0);
            m.records.push(RecordEntry {
                record_id: RecordId(id16(0x1000_0000 + k32)),
                heads: vec![head],
                history: versions,
                floor: Clock::new(),
            });
        }
        m
    }

    #[test]
    fn manifest_worst_case_fits_the_limit() {
        let m = worst_case();
        m.validate().unwrap();
        let total: u64 = m.references().iter().map(ObjectRef::length).sum();
        assert!(total <= MAX_TOTAL_CIPHERTEXT);
        let components: usize = m
            .records()
            .iter()
            .flat_map(|r| r.heads().iter().chain(r.history()))
            .map(|v| v.clock().pairs().len())
            .sum();
        assert_eq!(components, MAX_CLOCK_COMPONENTS);
        let bytes = m.encode().unwrap();
        let sealed = qv_crypto::sealed_len(bytes.len()).unwrap();
        eprintln!(
            "worst-case manifest: {} bytes plaintext, {} bytes sealed, limit {}",
            bytes.len(),
            sealed,
            MAX_MANIFEST_CIPHERTEXT
        );
        assert!(sealed <= MAX_MANIFEST_CIPHERTEXT);
        assert_eq!(Manifest::decode(&bytes).unwrap(), m);
        // One more component anywhere is over the budget.
        let mut over = m;
        let extra = writer(0x2fff_ffff);
        let r = over.records.last_mut().unwrap();
        let mut pairs = r.heads[0].clock.pairs().to_vec();
        pairs.push((extra, 1));
        pairs.sort();
        r.heads[0].clock = Clock::from_pairs(pairs).unwrap();
        assert_eq!(over.validate().err(), Some(StoreError::LimitExceeded));
    }

    #[test]
    fn manifest_fits_sqlite_length_limit() {
        assert!(MAX_MANIFEST_CIPHERTEXT <= crate::sqlite::MAX_LENGTH as usize);
    }
}
