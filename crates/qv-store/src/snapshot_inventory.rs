// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cross-generation snapshot inventory (0007 §3.2–3.3; plan 0022).
//!
//! Snapshot policy authenticates archives with the current vault key, so a
//! rotation would leave every snapshot of an earlier generation uncounted
//! and never pruned. Before a generation is installed, the rotation builds
//! this inventory from the snapshots it can still authenticate (with the old
//! VK) and the previous generation's inventory, and MACs it with the new
//! generation's local-state key. Snapshot policy (roadmap 1.15c) counts its
//! rows in the per-vault budgets and removes a row's file only after the
//! file's streamed SHA-256 and size match. Rows never become paths: names are
//! formatted from the 16-byte archive ID only.
//!
//! Development wire format (frozen in phase 1.16): canonical CBOR map
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | format | uint, 1 |
//! | 1 | vault_id | bstr 16 (UUIDv4) |
//! | 2 | generation | uint (u32, ≥ 2): the MAC key's generation |
//! | 3 | rows | array ≤ [`MAX_INVENTORY_ROWS`] of `[archive_id bstr16, generation uint, created_at int, size uint, sha256 bstr32]`, strictly ascending by archive ID |
//! | 4 | mac | bstr 32 |
//!
//! The MAC is MAC/1 under the generation's `local-state` purpose key over
//! canonical `["qv/snapshot-inventory/v1", body]`, where body is the encoded
//! map of keys 0–3. A row's generation is at least 1 and below the
//! inventory's. The file is `inventory-<32 hex vault id>-<8 hex
//! generation>.qvinv` in the snapshot directory, at most
//! [`MAX_INVENTORY_BYTES`].

use qv_crypto::{DerivationProfile, KeyGeneration, MacProfile, MacTag, VaultId, VaultKey, purpose};
use qv_encoding::{Decoder, Encoder, encode_array};
use qv_model::{RandomId, Timestamp};
use zeroize::Zeroizing;

use crate::StoreError;

/// Largest inventory file, checked before decoding or reading it.
pub const MAX_INVENTORY_BYTES: usize = 1024 * 1024;

/// Most rows an inventory carries; more aborts the rotation.
pub const MAX_INVENTORY_ROWS: usize = 4096;

const FORMAT: u64 = 1;
const LABEL: &str = "qv/snapshot-inventory/v1";

/// One snapshot of an earlier generation of this vault. Not secret: the
/// archive ID is what `snapshot ls` prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryRow {
    /// The archive's random ID (its file name).
    pub archive_id: [u8; 16],
    /// The generation whose key authenticated its header.
    pub generation: KeyGeneration,
    /// Its creation time, from that authenticated header.
    pub created_at: Timestamp,
    /// The file size when it was hashed.
    pub size: u64,
    /// The streamed SHA-256 of the whole file.
    pub sha256: [u8; 32],
}

impl InventoryRow {
    /// The 32 lowercase hex digits of the archive ID.
    pub fn archive_id_hex(&self) -> String {
        self.archive_id.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A verified inventory of one vault ID and generation. Rows are sorted by
/// archive ID and unique. `Debug` prints counts only.
pub struct SnapshotInventory {
    vault_id: VaultId,
    generation: KeyGeneration,
    rows: Vec<InventoryRow>,
    mac: MacTag,
}

/// A decoded inventory that is not authenticated yet; `verify` is its only use.
pub struct UnverifiedInventory(SnapshotInventory);

impl core::fmt::Debug for SnapshotInventory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SnapshotInventory({} rows)", self.rows.len())
    }
}

impl core::fmt::Debug for UnverifiedInventory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UnverifiedInventory(..)")
    }
}

fn bad<E>(_: E) -> StoreError {
    StoreError::Integrity
}

fn required<T>(v: Option<T>) -> Result<T, StoreError> {
    v.ok_or(StoreError::Integrity)
}

fn validate(
    vault_id: VaultId,
    generation: KeyGeneration,
    rows: &[InventoryRow],
) -> Result<(), StoreError> {
    VaultId::from_bytes(vault_id.0).map_err(bad)?;
    if generation.0 < 2 {
        return Err(StoreError::Integrity);
    }
    if rows.len() > MAX_INVENTORY_ROWS {
        return Err(StoreError::LimitExceeded);
    }
    if rows.windows(2).any(|w| w[0].archive_id >= w[1].archive_id)
        || rows
            .iter()
            .any(|r| r.generation.0 == 0 || r.generation >= generation)
    {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

fn key(
    vk: &VaultKey,
    vault_id: VaultId,
    generation: KeyGeneration,
) -> Result<qv_crypto::PurposeKey<purpose::LocalState>, StoreError> {
    Ok(vk.purpose_key::<purpose::LocalState>(vault_id, generation, DerivationProfile::V1)?)
}

impl SnapshotInventory {
    /// Validates the rows and MACs them for `generation` with its VK.
    pub(crate) fn sign(
        vault_id: VaultId,
        generation: KeyGeneration,
        mut rows: Vec<InventoryRow>,
        vk: &VaultKey,
    ) -> Result<Self, StoreError> {
        rows.sort_by_key(|r| r.archive_id);
        validate(vault_id, generation, &rows)?;
        let mut inventory = Self {
            vault_id,
            generation,
            rows,
            mac: MacTag::from_bytes([0; 32]),
        };
        let k = key(vk, vault_id, generation)?;
        inventory.mac = qv_crypto::mac(&k, MacProfile::V1, &inventory.transcript()?)?;
        Ok(inventory)
    }

    /// The vault this inventory belongs to.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The generation whose key MACs it (the vault's current generation).
    pub fn generation(&self) -> KeyGeneration {
        self.generation
    }

    /// The rows, ascending by archive ID.
    pub fn rows(&self) -> &[InventoryRow] {
        &self.rows
    }

    fn transcript(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let body = self.encode_map(false)?;
        encode_array(|a| {
            a.text(LABEL);
            a.bytes(&body);
            Ok(())
        })
        .map_err(|_| StoreError::Internal)
    }

    fn encode_map(&self, with_mac: bool) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        validate(self.vault_id, self.generation, &self.rows)?;
        let mut e = Encoder::new();
        e.map(|m| {
            m.entry(0, |e| {
                e.uint(FORMAT);
                Ok(())
            })?;
            m.entry(1, |e| {
                e.bytes(&self.vault_id.0);
                Ok(())
            })?;
            m.entry(2, |e| {
                e.uint(u64::from(self.generation.0));
                Ok(())
            })?;
            m.entry(3, |e| {
                e.array(|a| {
                    for r in &self.rows {
                        a.array(|x| {
                            x.bytes(&r.archive_id);
                            x.uint(u64::from(r.generation.0));
                            x.int(r.created_at.0);
                            x.uint(r.size);
                            x.bytes(&r.sha256);
                            Ok(())
                        })?;
                    }
                    Ok(())
                })
            })?;
            if with_mac {
                m.entry(4, |e| {
                    e.bytes(self.mac.as_bytes());
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|_| StoreError::Internal)?;
        e.finish().map_err(|_| StoreError::Internal)
    }

    /// Canonical file bytes, MAC included.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        Ok(self.encode_map(true)?.to_vec())
    }

    /// Checks the size cap, then the strict canonical structure, with every
    /// count bounded before allocation. The result is untrusted until
    /// [`UnverifiedInventory::verify`].
    pub fn decode(input: &[u8]) -> Result<UnverifiedInventory, StoreError> {
        if input.len() > MAX_INVENTORY_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        let mut d = Decoder::new(input).map_err(bad)?;
        let count = d.map().map_err(bad)?;
        if count > 5 {
            return Err(StoreError::Unsupported);
        }
        let (mut format, mut vault, mut generation, mut rows, mut mac) =
            (None, None, None, None, None);
        for _ in 0..count {
            match d.int().map_err(bad)? {
                0 => format = Some(d.uint().map_err(bad)?),
                1 => {
                    let b: [u8; 16] = d.bytes().map_err(bad)?.try_into().map_err(bad)?;
                    vault = Some(VaultId(b));
                }
                2 => {
                    let g = u32::try_from(d.uint().map_err(bad)?).map_err(bad)?;
                    generation = Some(KeyGeneration(g));
                }
                3 => {
                    let n = usize::try_from(d.array().map_err(bad)?).map_err(bad)?;
                    if n > MAX_INVENTORY_ROWS {
                        return Err(StoreError::LimitExceeded);
                    }
                    let mut out = Vec::with_capacity(n);
                    for _ in 0..n {
                        if d.array().map_err(bad)? != 5 {
                            return Err(StoreError::Integrity);
                        }
                        let archive_id = d.bytes().map_err(bad)?.try_into().map_err(bad)?;
                        let g = u32::try_from(d.uint().map_err(bad)?).map_err(bad)?;
                        let created_at = Timestamp(d.int().map_err(bad)?);
                        let size = d.uint().map_err(bad)?;
                        let sha256 = d.bytes().map_err(bad)?.try_into().map_err(bad)?;
                        out.push(InventoryRow {
                            archive_id,
                            generation: KeyGeneration(g),
                            created_at,
                            size,
                            sha256,
                        });
                    }
                    rows = Some(out);
                }
                4 => {
                    let b: [u8; 32] = d.bytes().map_err(bad)?.try_into().map_err(bad)?;
                    mac = Some(MacTag::from_bytes(b));
                }
                _ => return Err(StoreError::Unsupported),
            }
        }
        d.finish().map_err(bad)?;
        if required(format)? != FORMAT {
            return Err(StoreError::Unsupported);
        }
        let inventory = SnapshotInventory {
            vault_id: required(vault)?,
            generation: required(generation)?,
            rows: required(rows)?,
            mac: required(mac)?,
        };
        validate(inventory.vault_id, inventory.generation, &inventory.rows)?;
        Ok(UnverifiedInventory(inventory))
    }
}

impl UnverifiedInventory {
    /// Authenticates the inventory for exactly this vault ID and generation
    /// with that generation's VK (constant-time MAC check).
    pub fn verify(
        self,
        vault_id: VaultId,
        generation: KeyGeneration,
        vk: &VaultKey,
    ) -> Result<SnapshotInventory, StoreError> {
        let inventory = self.0;
        if inventory.vault_id != vault_id || inventory.generation != generation {
            return Err(StoreError::Integrity);
        }
        let k = key(vk, vault_id, generation)?;
        qv_crypto::verify_mac(&k, MacProfile::V1, &inventory.transcript()?, &inventory.mac)
            .map_err(bad)?;
        Ok(inventory)
    }
}

/// The inventory's file name in the snapshot directory.
pub(crate) fn file_name(vault_id: VaultId, generation: KeyGeneration) -> String {
    let mut name = String::from("inventory-");
    for b in vault_id.0 {
        name.push_str(&format!("{b:02x}"));
    }
    name.push_str(&format!("-{:08x}.qvinv", generation.0));
    name
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};

    use qv_crypto::ContentHasher;

    use super::*;
    use crate::archive::{ArchiveScope, SnapshotDir, SnapshotEntry};
    use crate::fs;
    use crate::{PreparedRotation, UnlockedVault};

    fn check_cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
        if cancelled() {
            Err(StoreError::Io)
        } else {
            Ok(())
        }
    }

    impl SnapshotDir {
        /// Builds the inventory that carries this vault's snapshots of
        /// generations up to the source's into the rotation's new generation
        /// (plan 0022 build rules). Reads and hashes files; writes nothing.
        ///
        /// A previous inventory that does not verify is
        /// [`StoreError::Integrity`] (the rotation aborts fail-closed). Its
        /// rows are carried only while their file still exists with the same
        /// size and SHA-256. Every snapshot whose header authenticates with
        /// the source VK becomes a row. More than [`MAX_INVENTORY_ROWS`] is
        /// [`StoreError::LimitExceeded`].
        pub fn prepare_inventory(
            &self,
            rotation: &PreparedRotation,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<SnapshotInventory, StoreError> {
            let source = rotation.source();
            let previous = self.inventory(source)?;
            self.build_inventory(
                source.header().vault_id,
                source.header().key_generation,
                source.vault_key(),
                previous.as_ref(),
                rotation.new_generation(),
                rotation.new_vault_key(),
                cancelled,
            )
        }

        /// The build rules of [`Self::prepare_inventory`] with explicit
        /// inputs: `previous` is already verified for `generation`.
        #[allow(clippy::too_many_arguments)] // One call site; named inputs keep the roles explicit.
        pub(crate) fn build_inventory(
            &self,
            vault_id: VaultId,
            generation: KeyGeneration,
            source_vk: &VaultKey,
            previous: Option<&SnapshotInventory>,
            next: KeyGeneration,
            new_vk: &VaultKey,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<SnapshotInventory, StoreError> {
            let entries = self.entries()?;
            let scope = ArchiveScope::new(vault_id, generation);
            let mut rows: BTreeMap<[u8; 16], InventoryRow> = BTreeMap::new();
            for entry in &entries {
                check_cancel(cancelled)?;
                let Ok(header) = self.read_header(entry, scope, source_vk) else {
                    continue;
                };
                let (size, sha256) = self.hash_entry(entry, cancelled)?;
                rows.insert(
                    header.archive_id(),
                    InventoryRow {
                        archive_id: header.archive_id(),
                        generation,
                        created_at: header.created_at(),
                        size,
                        sha256: *sha256.expose_secret(),
                    },
                );
                if rows.len() > MAX_INVENTORY_ROWS {
                    return Err(StoreError::LimitExceeded);
                }
            }
            for row in previous.into_iter().flat_map(SnapshotInventory::rows) {
                check_cancel(cancelled)?;
                if rows.contains_key(&row.archive_id) {
                    continue;
                }
                let Some(entry) = find(&entries, row) else {
                    continue;
                };
                if self.matches(entry, row, cancelled)? {
                    rows.insert(row.archive_id, row.clone());
                    if rows.len() > MAX_INVENTORY_ROWS {
                        return Err(StoreError::LimitExceeded);
                    }
                }
            }
            SnapshotInventory::sign(vault_id, next, rows.into_values().collect(), new_vk)
        }

        /// Publishes `inventory` under its generation's name: temp file,
        /// write, fsync, re-read and compare, `RENAME_NOREPLACE`, directory
        /// fsync. An existing name is [`StoreError::Exists`] and is never
        /// replaced. Returns the SHA-256 of the published bytes (the rotation
        /// journal's inventory digest).
        pub fn publish_inventory(
            &self,
            inventory: &SnapshotInventory,
        ) -> Result<[u8; 32], StoreError> {
            fs::check_private_dir(self.path())?;
            let bytes = inventory.encode()?;
            let target = self
                .path()
                .join(file_name(inventory.vault_id, inventory.generation));
            let (locked, temp) = fs::create_temp(&target)?;
            let written = (|| {
                let mut file = locked.into_file();
                file.write_all(&bytes).map_err(|_| StoreError::Io)?;
                rustix::fs::fsync(&file).map_err(crate::error::errno_err)?;
                drop(file);
                if read_bounded(&temp)? != bytes {
                    return Err(StoreError::Integrity);
                }
                fs::rename_noreplace(&temp, &target)
            })();
            if let Err(e) = written {
                fs::remove_best_effort(&temp);
                return Err(e);
            }
            fs::sync_dir(self.path())?;
            Ok(qv_crypto::object_hash(qv_crypto::ObjectHashProfile::V1, &bytes).0)
        }

        /// The vault's current-generation inventory: `None` if there is none;
        /// [`StoreError::Integrity`] if it does not verify with the vault key.
        /// Symlinks and files that are not owner-only regular files are
        /// refused; the size is checked before reading.
        pub fn inventory(
            &self,
            vault: &UnlockedVault,
        ) -> Result<Option<SnapshotInventory>, StoreError> {
            let h = vault.header();
            let path = self.path().join(file_name(h.vault_id, h.key_generation));
            match rustix::fs::lstat(&path) {
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(e) => return Err(crate::error::errno_err(e)),
                Ok(_) => {}
            }
            let bytes = read_bounded(&path)?;
            let inventory = SnapshotInventory::decode(&bytes)?.verify(
                h.vault_id,
                h.key_generation,
                vault.vault_key(),
            )?;
            Ok(Some(inventory))
        }

        /// Removes the snapshot file of a row of the vault's verified
        /// inventory, only if its streamed SHA-256 and size still match.
        /// [`StoreError::NotFound`] if the file or the row is absent;
        /// [`StoreError::Integrity`] (file kept) if the file differs.
        pub fn remove_inventoried(
            &self,
            vault: &UnlockedVault,
            row: &InventoryRow,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<(), StoreError> {
            let inventory = self.inventory(vault)?.ok_or(StoreError::NotFound)?;
            if !inventory.rows().contains(row) {
                return Err(StoreError::NotFound);
            }
            let entries = self.entries()?;
            let entry = find(&entries, row).ok_or(StoreError::NotFound)?;
            if !self.matches(entry, row, cancelled)? {
                return Err(StoreError::Integrity);
            }
            self.remove(entry)
        }

        /// Removes one generation's inventory file (1.15c: after completion
        /// the superseded one, on rollback the unused new one). Absent is Ok.
        // Called by the journal installer of roadmap 1.15c and by tests.
        #[allow(dead_code)]
        pub(crate) fn remove_inventory(
            &self,
            vault_id: VaultId,
            generation: KeyGeneration,
        ) -> Result<(), StoreError> {
            match std::fs::remove_file(self.path().join(file_name(vault_id, generation))) {
                Ok(()) => fs::sync_dir(self.path()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(StoreError::Io),
            }
        }

        /// The size and streamed SHA-256 of one snapshot file.
        fn hash_entry(
            &self,
            entry: &SnapshotEntry,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<(u64, qv_crypto::SecretArray<32>), StoreError> {
            let mut file = self.open_entry(entry)?;
            let mut hasher = ContentHasher::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut size = 0u64;
            loop {
                check_cancel(cancelled)?;
                let n = match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(StoreError::Io),
                };
                hasher.update(buf.get(..n).ok_or(StoreError::Internal)?);
                size = size
                    .checked_add(n as u64)
                    .ok_or(StoreError::LimitExceeded)?;
            }
            Ok((size, hasher.finalize()))
        }

        /// Whether `entry` still has the row's size and SHA-256.
        fn matches(
            &self,
            entry: &SnapshotEntry,
            row: &InventoryRow,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<bool, StoreError> {
            let (size, sha256) = self.hash_entry(entry, cancelled)?;
            Ok(size == row.size && sha256.ct_eq(&row.sha256))
        }
    }

    /// The snapshot file of a row's archive ID, of either kind.
    fn find<'e>(entries: &'e [SnapshotEntry], row: &InventoryRow) -> Option<&'e SnapshotEntry> {
        let id = row.archive_id_hex();
        entries.iter().find(|e| e.archive_id() == id)
    }

    /// Reads a private regular inventory file of at most
    /// [`MAX_INVENTORY_BYTES`], checking its size before reading.
    fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>, StoreError> {
        let file = fs::open_private_ro(path)?;
        let len = file.metadata().map_err(|_| StoreError::Io)?.len();
        if len > MAX_INVENTORY_BYTES as u64 {
            return Err(StoreError::LimitExceeded);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(len).map_err(|_| StoreError::Io)?);
        file.take(MAX_INVENTORY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StoreError::Io)?;
        if bytes.len() > MAX_INVENTORY_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "snapshot_inventory_tests.rs"]
mod tests;
