// SPDX-License-Identifier: AGPL-3.0-or-later

//! Creating, opening and unlocking a vault file (spec 0004 §1, §3.6, §5.1;
//! 0005 §5.4; 0002 §8).
//!
//! - [`VaultFile::open`]: file checks and lock, location warnings, SQLite
//!   sidecar checks, SQLite with the vault flags, identity re-check,
//!   hardening, then (in one read transaction) schema validation, row checks
//!   and header/slot decoding. No KDF runs and nothing is authenticated yet.
//! - [`VaultFile::unlock`]: one Argon2id run unwraps VK from the password
//!   slot (a KEK-commitment or AEAD failure is only
//!   [`StoreError::WrongPassword`]), the header MAC is verified, and then, in
//!   one read transaction, the 0004 §3.6 unlock verification: the head MAC,
//!   the manifest hash and AEAD, the configuration digest, every referenced
//!   object row and length, and the AEAD and identity of every head. Last,
//!   the head is compared with the external anchor (0005 §5.4). A missing
//!   or mismatched anchor fails closed; only
//!   [`VaultFile::unlock_for_recovery`] opens such a vault, with writes
//!   blocked until [`UnlockedVault::adopt_baseline`].
//! - [`VaultFile::create`]: builds the vault under a temporary name in the
//!   same directory with its three control records, first manifest and
//!   head 1, commits durably, writes the first anchor, moves the vault into
//!   place without replacing anything, syncs the directory, and reopens it
//!   through the open and unlock-verification path.
//!
//! Writes are in `write`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use qv_crypto::{
    KeyGeneration, MacTag, MasterPassword, ObjectHashProfile, PasswordKdfProfile, PasswordSlot,
    PasswordWrapProfile, PurposeKey, RecordId, SlotId, StoredDataProfile, VaultId, VaultKey, mac,
    object_hash, purpose, verify_mac,
};
use qv_model::{
    Extensions, Group, Keyslot, Payload, RandomId, RecordBody, RecordKind, RecordVersion, Settings,
    Text, Timestamp, VaultMeta, VersionId, WriterId,
};
use rusqlite::{Connection, TransactionBehavior};

use crate::anchor::AnchorDir;
use crate::crash::{CrashPoint, point};
use crate::error::{StoreError, errno_err, write_err};
use crate::fs::{self, LockedFile};
use crate::head::{Anchor, AnchorStatus, LocalHead, compare, head_mac, local_digest, verify_head};
use crate::header::{Header, INITIAL_GENERATION, SlotRow, mac_transcript};
use crate::location::{LocationWarnings, warnings_for};
use crate::manifest::{
    Manifest, ObjectRef, VersionRef, config_digest, envelope_hash, open_manifest, seal_manifest,
};
use crate::object::{RecordRole, Scope, SealedObject, open_record, seal_record};
use crate::schema::{self, ObjectReader, StoredHead, StoredReplica, validation_err};
use crate::slot::{LocalSlot, password_slot};
use crate::sqlite::{StepBudget, harden, open_connection};
use crate::validation::{check_control_kinds, check_head};

/// The vault file extension (0004 §1.1).
pub const VAULT_EXTENSION: &str = "qvault";

#[cfg(test)]
thread_local! {
    /// Test hook: `create` fails after its temporary file exists.
    pub(crate) static FAIL_CREATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// An open, locked and validated vault file whose header is not yet
/// authenticated. [`VaultFile::unlock`] turns it into an [`UnlockedVault`].
pub struct VaultFile {
    // Field order matters: the connection is dropped before the lock
    // descriptor, because closing any descriptor of the file drops SQLite's
    // POSIX locks on it (see `fs`).
    pub(crate) conn: Connection,
    lock: LockedFile,
    path: PathBuf,
    pub(crate) header: Header,
    pub(crate) header_body: Vec<u8>,
    pub(crate) header_mac: MacTag,
    pub(crate) slots: Vec<LocalSlot>,
    warnings: LocationWarnings,
    pub(crate) budget: StepBudget,
    pub(crate) role: FileRole,
}

/// What an open vault file is for. Only `rotation` creates a
/// [`FileRole::Candidate`]; it can be verified but never written or anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileRole {
    /// An ordinary vault path: reserved rotation names are refused.
    Ordinary,
    /// A rotation's private replacement under its reserved name.
    Candidate,
}

/// Whether this session may write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteGate {
    /// Writes are allowed.
    Open,
    /// The anchor check failed with this error; only `adopt_baseline`
    /// writes.
    Blocked(StoreError),
    /// A commit is durable but its anchor update failed; the next write
    /// retries the anchor first.
    AnchorPending,
}

/// The verified committed state of an unlocked vault.
pub(crate) struct State {
    pub(crate) manifest: Manifest,
    pub(crate) kinds: BTreeMap<RecordId, RecordKind>,
    /// The head row's exact bytes, for the re-read inside a write.
    pub(crate) stored_head: StoredHead,
    pub(crate) head: LocalHead,
    pub(crate) digest: [u8; 32],
    pub(crate) replica: StoredReplica,
    pub(crate) writer: WriterId,
}

/// A vault whose password slot, header MAC, head, manifest and heads have
/// been verified.
pub struct UnlockedVault {
    pub(crate) file: VaultFile,
    pub(crate) vk: VaultKey,
    pub(crate) state: State,
    pub(crate) anchors: AnchorDir,
    pub(crate) gate: WriteGate,
}

impl fmt::Debug for VaultFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No path: it can name the user's vault.
        f.write_str("VaultFile(..)")
    }
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnlockedVault(<redacted>)")
    }
}

/// The header MAC over the exact stored bytes.
pub(crate) fn header_tag(
    vk: &VaultKey,
    header: &Header,
    body: &[u8],
    slots: &[SlotRow<'_>],
) -> Result<(PurposeKey<purpose::HeaderMac>, zeroize::Zeroizing<Vec<u8>>), StoreError> {
    let key = vk.purpose_key::<purpose::HeaderMac>(
        header.vault_id,
        header.key_generation,
        header.derivation_profile,
    )?;
    Ok((key, mac_transcript(body, slots)?))
}

/// The purpose keys a session uses, derived on demand.
pub(crate) struct Keys {
    pub(crate) record: PurposeKey<purpose::Record>,
    pub(crate) manifest: PurposeKey<purpose::Manifest>,
    pub(crate) local: PurposeKey<purpose::LocalState>,
}

impl Keys {
    pub(crate) fn derive(vk: &VaultKey, header: &Header) -> Result<Self, StoreError> {
        let (v, g, d) = (
            header.vault_id,
            header.key_generation,
            header.derivation_profile,
        );
        Ok(Self {
            record: vk.purpose_key::<purpose::Record>(v, g, d)?,
            manifest: vk.purpose_key::<purpose::Manifest>(v, g, d)?,
            local: vk.purpose_key::<purpose::LocalState>(v, g, d)?,
        })
    }
}

pub(crate) fn scope(header: &Header) -> Scope {
    Scope {
        vault_id: header.vault_id,
        key_generation: header.key_generation,
    }
}

/// A stored data profile that this header accepts.
pub(crate) fn accepted_profile(header: &Header, id: u16) -> Result<StoredDataProfile, StoreError> {
    let p = StoredDataProfile::from_id(id)?;
    if p.accepts(header.min_data_profile) {
        Ok(p)
    } else {
        Err(StoreError::Unsupported)
    }
}

/// Reads and verifies the committed state (0004 §3.6, §5.1). Run inside
/// one read transaction, after the header MAC.
pub(crate) fn load_state(
    conn: &Connection,
    header: &Header,
    vk: &VaultKey,
) -> Result<State, StoreError> {
    let keys = Keys::derive(vk, header)?;
    let stored = schema::read_state(conn)?;

    // The head: MAC before parsing.
    let head_tag = MacTag::from_bytes(stored.head.mac);
    verify_head(
        &keys.local,
        header.mac_profile,
        &stored.head.body,
        &head_tag,
    )?;
    let head = LocalHead::decode(&stored.head.body)?;
    if head.vault_id != header.vault_id || head.key_generation != header.key_generation {
        return Err(StoreError::Integrity);
    }
    let digest = local_digest(&stored.head.body, &head_tag)?;

    // The manifest the head names.
    let m = &stored.manifest;
    if m.hash != head.manifest_hash || m.key_generation != header.key_generation {
        return Err(StoreError::Integrity);
    }
    let profile = accepted_profile(header, m.data_profile)?;
    if envelope_hash(m.key_generation, profile, &m.nonce, &m.ciphertext)? != m.hash {
        return Err(StoreError::Integrity);
    }
    let s = scope(header);
    let manifest = open_manifest(&keys.manifest, s, profile, &m.nonce, &m.ciphertext)?;
    if *manifest.config_digest() != config_digest(header)? {
        return Err(StoreError::Integrity);
    }

    // Every referenced object row exists with its profile and length.
    let mut reader = ObjectReader::new(conn)?;
    for r in manifest.references() {
        accepted_profile(header, r.data_profile().id())?;
        let meta = reader
            .meta(header.key_generation, &r.object_id().to_bytes())?
            .ok_or(StoreError::Integrity)?;
        if meta.data_profile != r.data_profile().id() || meta.length != r.length() {
            return Err(StoreError::Integrity);
        }
    }

    // Every head decrypts for its role; one kind per record; control rules.
    let mut kinds = BTreeMap::new();
    for rec in manifest.records() {
        let mut kind = None;
        for h in rec.heads() {
            let version = read_role(
                &mut reader,
                &keys,
                header,
                &manifest,
                rec.record_id(),
                h,
                false,
            )?;
            let k = version.kind();
            if kind.is_some_and(|known| known != k) {
                return Err(StoreError::Integrity);
            }
            kind = Some(k);
            check_head(&manifest, rec.record_id(), h, &version)?;
        }
        kinds.insert(rec.record_id(), kind.ok_or(StoreError::Integrity)?);
    }
    check_control_kinds(&manifest, &kinds)?;

    let writer = WriterId::from_bytes(stored.replica.writer_id)?;
    Ok(State {
        manifest,
        kinds,
        stored_head: stored.head,
        head,
        digest,
        replica: stored.replica,
        writer,
    })
}

/// Reads and decrypts one version for its manifest role. With
/// `check_hash`, the ciphertext's SHA-256 must match the reference before
/// AEAD (history reads, 0004 §3.6).
pub(crate) fn read_role(
    reader: &mut ObjectReader<'_>,
    keys: &Keys,
    header: &Header,
    manifest: &Manifest,
    record: RecordId,
    v: &VersionRef,
    check_hash: bool,
) -> Result<RecordVersion, StoreError> {
    let r = manifest
        .reference(v.object_id())
        .ok_or(StoreError::Integrity)?;
    let (profile, nonce, ciphertext) =
        reader.read(header.key_generation, &v.object_id().to_bytes(), r.length())?;
    if profile != r.data_profile().id()
        || (check_hash && object_hash(ObjectHashProfile::V1, &ciphertext).0 != *r.sha256())
    {
        return Err(StoreError::Integrity);
    }
    let role = RecordRole {
        record,
        version: v.version_id(),
        clock: v.clock(),
        object: v.object_id(),
    };
    open_record(
        &keys.record,
        scope(header),
        &role,
        r.data_profile(),
        &nonce,
        &ciphertext,
    )
}

impl VaultFile {
    /// Flushes a completed new file before publication.
    pub(crate) fn sync(&self) -> Result<(), StoreError> {
        self.lock.sync()
    }

    /// Opens a vault for unlocking: file checks, lock, hardening, schema
    /// validation and header/slot decoding. No KDF runs here.
    pub fn open(path: &Path) -> Result<VaultFile, StoreError> {
        crate::rotation_guard::check(path)?;
        let lock = fs::open_existing(path)?;
        Self::open_locked(path, lock)
    }

    pub(crate) fn open_locked(path: &Path, lock: LockedFile) -> Result<VaultFile, StoreError> {
        Self::open_locked_as(path, lock, FileRole::Ordinary)
    }

    /// [`Self::open_locked`] for a given role. Only the rotation's own
    /// replacement skips the reserved-name refusal; the marker, sidecar,
    /// identity and hardening checks always run.
    pub(crate) fn open_locked_as(
        path: &Path,
        lock: LockedFile,
        role: FileRole,
    ) -> Result<VaultFile, StoreError> {
        Self::guard(path, role)?;
        let warnings = warnings_for(path, &lock);
        // SQLite rolls back or replays these before any check below.
        fs::check_sidecars(path)?;
        lock.same_as_path(path)?;
        let conn = open_connection(path)?;
        lock.same_as_path(path)?;
        let budget = StepBudget::new();
        harden(&conn, &budget)?;
        let rows = {
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| validation_err(&e))?;
            schema::validate_schema(&tx)?;
            let rows = schema::read_rows(&tx)?;
            tx.commit().map_err(|e| validation_err(&e))?;
            rows
        };
        let header = Header::decode(&rows.header_body)?;
        let slots = rows
            .slots
            .into_iter()
            .map(LocalSlot::from_stored)
            .collect::<Result<Vec<_>, _>>()?;
        password_slot(&slots)?;
        Ok(VaultFile {
            conn,
            lock,
            path: path.to_owned(),
            header,
            header_body: rows.header_body,
            header_mac: MacTag::from_bytes(rows.header_mac),
            slots,
            warnings,
            budget,
            role,
        })
    }

    fn guard(path: &Path, role: FileRole) -> Result<(), StoreError> {
        match role {
            FileRole::Ordinary => crate::rotation_guard::check(path),
            FileRole::Candidate if crate::rotation_guard::is_reserved(path) => {
                crate::rotation_guard::check_marker(path)
            }
            FileRole::Candidate => Err(StoreError::Internal),
        }
    }

    /// Unlocks with the master password: one KDF run, the header MAC, the
    /// full unlock verification and the anchor check. A missing anchor is
    /// [`StoreError::NoAnchor`] and any other mismatch
    /// [`StoreError::Rollback`]. On failure the file is closed; reopen to
    /// retry.
    pub fn unlock(
        self,
        password: &MasterPassword,
        anchors: &AnchorDir,
    ) -> Result<UnlockedVault, StoreError> {
        let (vault, status) = self.unlock_for_recovery(password, anchors)?;
        match status {
            AnchorStatus::Missing => Err(StoreError::NoAnchor),
            AnchorStatus::Mismatch => Err(StoreError::Rollback),
            _ => Ok(vault),
        }
    }

    /// Like [`Self::unlock`], but a missing or mismatched anchor is reported
    /// as the [`AnchorStatus`] instead of an error. The vault can then be
    /// read, and [`UnlockedVault::write`] fails with that error until
    /// [`UnlockedVault::adopt_baseline`] makes the current state the new
    /// baseline (explicit recovery, 0005 §5.4).
    pub fn unlock_for_recovery(
        self,
        password: &MasterPassword,
        anchors: &AnchorDir,
    ) -> Result<(UnlockedVault, AnchorStatus), StoreError> {
        self.budget.reset();
        let slot = password_slot(&self.slots)?;
        let vk =
            slot.keyslot
                .slot
                .unlock(password, self.header.vault_id, self.header.key_generation)?;
        self.verify_header(&vk)?;
        self.finish_unlock(vk, anchors)
    }

    /// Opens an existing local vault using a bounded recovery phrase.
    /// A failed initial header key confirmation cannot distinguish a wrong
    /// phrase from header damage; failures after confirmation are Integrity.
    /// Missing/mismatched anchors still require explicit baseline adoption.
    pub fn unlock_with_phrase(
        self,
        phrase: &[u8],
        anchors: &AnchorDir,
    ) -> Result<(UnlockedVault, AnchorStatus), StoreError> {
        if phrase.len() > 1024 {
            return Err(StoreError::LimitExceeded);
        }
        let vk = VaultKey::from_recovery_phrase(phrase)?;
        match self.verify_header(&vk) {
            Err(StoreError::Integrity) => return Err(StoreError::WrongPhrase),
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        self.finish_unlock(vk, anchors)
    }

    /// The unlock verification and anchor check, once VK is known and the
    /// header MAC verified.
    /// The path this file was opened at.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A rotation replacement's verified state, without any anchor access:
    /// its head is one step past the shared anchor by construction, and only
    /// the installer may advance that anchor (plan 0022). The session can be
    /// read and verified; every write path refuses it.
    pub(crate) fn finish_candidate(
        self,
        vk: VaultKey,
        anchors: &AnchorDir,
    ) -> Result<UnlockedVault, StoreError> {
        if self.role != FileRole::Candidate {
            return Err(StoreError::Internal);
        }
        self.check_identity()?;
        self.budget.reset();
        let state = {
            let tx = self
                .conn
                .unchecked_transaction()
                .map_err(|e| validation_err(&e))?;
            let state = load_state(&tx, &self.header, &vk)?;
            tx.commit().map_err(|e| validation_err(&e))?;
            state
        };
        Ok(UnlockedVault {
            file: self,
            vk,
            state,
            anchors: anchors.clone(),
            gate: WriteGate::Blocked(StoreError::Integrity),
        })
    }

    fn finish_unlock(
        self,
        vk: VaultKey,
        anchors: &AnchorDir,
    ) -> Result<(UnlockedVault, AnchorStatus), StoreError> {
        self.check_identity()?;
        self.budget.reset();
        let state = {
            let tx = self
                .conn
                .unchecked_transaction()
                .map_err(|e| validation_err(&e))?;
            let state = load_state(&tx, &self.header, &vk)?;
            tx.commit().map_err(|e| validation_err(&e))?;
            state
        };
        let anchor = anchors.load(&state.replica.replica_id)?;
        let status = compare(&state.head, &state.digest, anchor.as_ref());
        let gate = match status {
            AnchorStatus::Verified => WriteGate::Open,
            AnchorStatus::Advanced => {
                // Crash after the DB commit: finish its anchor update.
                anchors.store(&state.replica.replica_id, &anchor_of(&state))?;
                WriteGate::Open
            }
            AnchorStatus::Missing => WriteGate::Blocked(StoreError::NoAnchor),
            _ => WriteGate::Blocked(StoreError::Rollback),
        };
        Ok((
            UnlockedVault {
                file: self,
                vk,
                state,
                anchors: anchors.clone(),
                gate,
            },
            status,
        ))
    }

    pub(crate) fn verify_header(&self, vk: &VaultKey) -> Result<(), StoreError> {
        let rows: Vec<SlotRow<'_>> = self.slots.iter().map(LocalSlot::row).collect();
        let (key, transcript) = header_tag(vk, &self.header, &self.header_body, &rows)?;
        verify_mac(&key, self.header.mac_profile, &transcript, &self.header_mac)
            .map_err(|_| StoreError::Integrity)
    }

    /// Location warnings for this vault's path (0004 §1.1).
    pub fn warnings(&self) -> LocationWarnings {
        self.warnings
    }

    /// [`StoreError::Replaced`] if the path no longer names the locked
    /// file (0004 §1.3).
    pub fn check_identity(&self) -> Result<(), StoreError> {
        Self::guard(&self.path, self.role)?;
        self.lock.same_as_path(&self.path)
    }

    /// The decoded header, **unverified**: its MAC is checked only by
    /// unlock (0011 `info`).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The vault format (the SQLite `user_version`), which `open` has
    /// already checked against the supported one.
    pub fn schema_version(&self) -> u32 {
        u32::try_from(crate::schema::SCHEMA_VERSION).unwrap_or(u32::MAX)
    }

    /// The password slot's KDF profile, **unverified** (the slot is covered
    /// by the header MAC, which only unlock checks).
    pub fn password_kdf(&self) -> Result<PasswordKdfProfile, StoreError> {
        Ok(password_slot(&self.slots)?.keyslot.slot.kdf_profile)
    }

    /// Creates a new vault named `name` at `path`, which must not exist, in
    /// an existing private directory, with a `.qvault` name, and records its
    /// first anchor in `anchors`. Runs the password KDF once and returns the
    /// vault unlocked.
    pub fn create(
        path: &Path,
        password: &MasterPassword,
        name: &str,
        anchors: &AnchorDir,
    ) -> Result<UnlockedVault, StoreError> {
        crate::rotation_guard::check(path)?;
        if path.extension().and_then(|e| e.to_str()) != Some(VAULT_EXTENSION) {
            return Err(StoreError::Unsupported);
        }
        let name = Text::new(name).map_err(|_| StoreError::InvalidEdit)?;
        match rustix::fs::lstat(path) {
            Ok(_) => return Err(StoreError::Exists),
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(errno_err(e)),
        }
        fs::check_parent(path)?;
        let (lock, temp) = fs::create_temp(path)?;
        let mut anchored = None;
        let built = build(&temp, password, &name).and_then(|(vk, replica, anchor)| {
            lock.sync()?;
            point(CrashPoint::CreateBuilt)?;
            crate::rotation_guard::check(path)?;
            anchors.store(&replica, &anchor)?;
            anchored = Some(replica);
            point(CrashPoint::CreateAnchored)?;
            crate::rotation_guard::check(path)?;
            fs::rename_noreplace(&temp, path)?;
            Ok(vk)
        });
        let vk = match built {
            Ok(vk) => vk,
            Err(e) => {
                fs::remove_best_effort(&fs::with_suffix(&temp, "-journal"));
                fs::remove_best_effort(&temp);
                if let Some(r) = anchored {
                    anchors.remove_best_effort(&r);
                }
                return Err(e);
            }
        };
        fs::sync_dir(fs::parent_of(path))?;
        let file = Self::open_locked(path, lock)?;
        // Self-test: the stored vault verifies under the new VK like any
        // other, and its anchor matches.
        file.verify_header(&vk)?;
        match file.finish_unlock(vk, anchors)? {
            (vault, AnchorStatus::Verified) => Ok(vault),
            _ => Err(StoreError::Internal),
        }
    }
}

/// The anchor for a state's head.
pub(crate) fn anchor_of(state: &State) -> Anchor {
    Anchor {
        vault_id: state.head.vault_id,
        key_generation: state.head.key_generation,
        local_seq: state.head.local_seq,
        local_digest: state.digest,
    }
}

/// Milliseconds since the Unix epoch (display only, 0005 §1.5).
pub(crate) fn now() -> Timestamp {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    Timestamp(i64::try_from(ms).unwrap_or(i64::MAX))
}

/// Inserts one object row.
pub(crate) fn insert_object(
    conn: &Connection,
    generation: KeyGeneration,
    o: &SealedObject,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO object (key_generation, object_id, data_profile, nonce, ciphertext) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            i64::from(generation.0),
            o.object_id.to_bytes().as_slice(),
            i64::from(o.data_profile.id()),
            o.nonce.as_slice(),
            o.ciphertext.as_slice()
        ],
    )
    .map_err(|e| write_err(conn, &e, len64(o.ciphertext.len())))?;
    Ok(())
}

pub(crate) fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// A new head body and its MAC for `head`.
pub(crate) fn sign_head(
    keys: &Keys,
    header: &Header,
    head: &LocalHead,
) -> Result<(StoredHead, [u8; 32]), StoreError> {
    let body = head.encode()?;
    let tag = head_mac(&keys.local, header.mac_profile, &body)?;
    let digest = local_digest(&body, &tag)?;
    Ok((
        StoredHead {
            body,
            mac: *tag.as_bytes(),
        },
        digest,
    ))
}

/// One control record version of a new vault.
fn control_version(
    writer: WriterId,
    counter: u64,
    payload: Payload,
) -> Result<RecordVersion, StoreError> {
    let clock = qv_model::Clock::from_pairs(vec![(writer, counter)])?;
    Ok(RecordVersion {
        version_id: VersionId::generate()?,
        clock,
        modified_at: now(),
        body: RecordBody::Live(payload),
        ext: Extensions::new(),
    })
}

/// Writes a complete new vault into the empty file at `temp`. Returns VK,
/// the replica ID and the first anchor.
fn build(
    temp: &Path,
    password: &MasterPassword,
    name: &Text,
) -> Result<(VaultKey, [u8; 16], Anchor), StoreError> {
    #[cfg(test)]
    if FAIL_CREATE.with(std::cell::Cell::get) {
        return Err(StoreError::Internal);
    }
    fs::check_sidecars(temp)?;
    let mut conn = open_connection(temp)?;
    harden(&conn, &StepBudget::new())?;
    conn.pragma_update(None, "page_size", 4096)
        .map_err(|e| validation_err(&e))?;

    let vault_id = VaultId::generate()?;
    let slot_id = SlotId::generate()?;
    let vk = VaultKey::generate()?;
    let slot = PasswordSlot::create(
        password,
        &vk,
        vault_id,
        INITIAL_GENERATION,
        slot_id,
        PasswordKdfProfile::V1,
        PasswordWrapProfile::V1,
    )?;
    let local = LocalSlot::password(slot)?;
    let header = Header::new_vault(vault_id);
    let body = header.encode()?;
    let (key, transcript) = header_tag(&vk, &header, &body, &[local.row()])?;
    let tag = mac(&key, header.mac_profile, &transcript)?;
    let keys = Keys::derive(&vk, &header)?;
    let s = scope(&header);

    // The replica and the three control records (0003 §2.3).
    let replica_id = qv_crypto::random_array::<16>().map_err(|_| StoreError::Rng)?;
    let writer = WriterId::generate()?;
    let meta_id = <RecordId as RandomId>::generate()?;
    let keyslot_id = <RecordId as RandomId>::generate()?;
    let root_id = <RecordId as RandomId>::generate()?;
    let root = control_version(
        writer,
        1,
        Payload::Group(Group {
            parent: None,
            name: Text::new(name.expose())?,
            notes: None,
            icon: None,
            order: Text::new("a")?,
            deleted_at: None,
            ext: Extensions::new(),
        }),
    )?;
    let meta = control_version(
        writer,
        2,
        Payload::VaultMeta(VaultMeta {
            name: Text::new(name.expose())?,
            description: None,
            root_group: root_id,
            settings: Settings::default(),
            ext: Extensions::new(),
        }),
    )?;
    // The keyslot record holds the same descriptor as the local slot.
    let keyslot = control_version(
        writer,
        3,
        Payload::PasswordKeyslot(Keyslot::decode(&local.body)?),
    )?;

    let mut manifest = Manifest::empty(&header, meta_id, keyslot_id, root_id)?;
    let mut objects = Vec::new();
    for (id, v) in [(root_id, &root), (meta_id, &meta), (keyslot_id, &keyslot)] {
        let o = seal_record(&keys.record, s, header.data_profile, id, v)?;
        manifest.add_record(
            id,
            VersionRef::new(v.version_id, v.clock.clone(), o.object_id),
            ObjectRef::new(o.object_id, o.data_profile, &o.ciphertext)?,
        )?;
        objects.push(o);
    }
    let sealed = seal_manifest(&keys.manifest, s, header.data_profile, &manifest)?;
    let head = LocalHead {
        vault_id,
        key_generation: header.key_generation,
        local_seq: 1,
        previous_digest: None,
        manifest_hash: sealed.hash,
        remote: None,
    };
    let (stored_head, digest) = sign_head(&keys, &header, &head)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| crate::error::sqlite_err(&e))?;
    let w = |e: rusqlite::Error| write_err(&tx, &e, 0);
    schema::install(&tx)?;
    tx.execute(
        "INSERT INTO header (id, body, mac) VALUES (1, ?1, ?2)",
        rusqlite::params![body.as_slice(), tag.as_bytes().as_slice()],
    )
    .map_err(w)?;
    tx.execute(
        "INSERT INTO keyslot (slot_id, type, body) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            local.slot_id.0.as_slice(),
            i64::try_from(local.kind).map_err(|_| StoreError::Internal)?,
            local.body.as_slice()
        ],
    )
    .map_err(w)?;
    tx.execute(
        "INSERT INTO replica (id, replica_id, writer_id, next_counter) VALUES (1, ?1, ?2, 4)",
        rusqlite::params![replica_id.as_slice(), writer.to_bytes().as_slice()],
    )
    .map_err(w)?;
    for o in &objects {
        insert_object(&tx, header.key_generation, o)?;
    }
    insert_manifest(&tx, &sealed)?;
    tx.execute(
        "INSERT INTO local_head (id, body, mac) VALUES (1, ?1, ?2)",
        rusqlite::params![stored_head.body.as_slice(), stored_head.mac.as_slice()],
    )
    .map_err(w)?;
    tx.commit().map_err(|e| crate::error::sqlite_err(&e))?;
    conn.close()
        .map_err(|(_, err)| crate::error::sqlite_err(&err))?;
    let anchor = Anchor {
        vault_id,
        key_generation: header.key_generation,
        local_seq: 1,
        local_digest: digest,
    };
    Ok((vk, replica_id, anchor))
}

/// Inserts one manifest row.
pub(crate) fn insert_manifest(
    conn: &Connection,
    m: &crate::manifest::SealedManifest,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO manifest (manifest_hash, key_generation, data_profile, nonce, ciphertext) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            m.hash.as_slice(),
            i64::from(m.key_generation.0),
            i64::from(m.data_profile.id()),
            m.nonce.as_slice(),
            m.ciphertext.as_slice()
        ],
    )
    .map_err(|e| write_err(conn, &e, len64(m.ciphertext.len())))?;
    Ok(())
}

impl UnlockedVault {
    /// The authenticated header.
    pub fn header(&self) -> &Header {
        &self.file.header
    }

    /// Opens one read transaction over the committed state and re-checks that
    /// the head and replica rows on disk are the ones this session verified
    /// ([`StoreError::Changed`] otherwise, 0004 §1.3). The archive writer runs
    /// its whole pass inside it (0004 §6) and never writes.
    pub(crate) fn begin_read(&self) -> Result<(), StoreError> {
        self.check_identity()?;
        self.file.budget.reset();
        if let Err(e) = self.file.conn.execute_batch("BEGIN") {
            return Err(crate::error::sqlite_err(&e));
        }
        let fresh = schema::read_head(&self.file.conn)
            .and_then(|h| Ok((h, schema::read_replica(&self.file.conn)?)));
        match fresh {
            Ok((head, replica))
                if head == self.state.stored_head && replica == self.state.replica =>
            {
                Ok(())
            }
            Ok(_) => {
                self.abort_read();
                Err(StoreError::Changed)
            }
            Err(e) => {
                self.abort_read();
                Err(e)
            }
        }
    }

    /// Ends a successful read pass.
    pub(crate) fn end_read(&self) -> Result<(), StoreError> {
        self.file
            .conn
            .execute_batch("COMMIT")
            .map_err(|e| crate::error::sqlite_err(&e))
    }

    /// Abandons a read pass; the error is ignored because a read transaction
    /// changes nothing.
    pub(crate) fn abort_read(&self) {
        let _ = self.file.conn.execute_batch("ROLLBACK");
    }

    /// Location warnings for this vault's path.
    pub fn warnings(&self) -> LocationWarnings {
        self.file.warnings
    }

    /// See [`VaultFile::check_identity`].
    pub fn check_identity(&self) -> Result<(), StoreError> {
        self.file.check_identity()
    }

    /// VK, for `qv-core` (1.8) and the write path only. Frontends never
    /// call this (`ARCHITECTURE.md` §3).
    pub fn vault_key(&self) -> &VaultKey {
        &self.vk
    }

    /// The verified manifest of the committed state.
    pub fn manifest(&self) -> &Manifest {
        &self.state.manifest
    }

    /// The kind of a record, known from its verified heads.
    pub fn record_kind(&self, id: RecordId) -> Option<RecordKind> {
        self.state.kinds.get(&id).copied()
    }

    /// This replica's writer ID (0005 §1.3).
    pub fn writer_id(&self) -> WriterId {
        self.state.writer
    }

    /// The committed head's sequence number (0005 §5.4).
    pub fn local_seq(&self) -> u64 {
        self.state.head.local_seq
    }

    /// Decrypts one head or history version. A history version's ciphertext
    /// is checked against its reference (length and SHA-256) before AEAD
    /// (0004 §3.6); a mismatch is [`StoreError::Integrity`].
    pub fn read_version(
        &self,
        record: RecordId,
        version: VersionId,
    ) -> Result<RecordVersion, StoreError> {
        let m = &self.state.manifest;
        let entry = m.record(record).ok_or(StoreError::NotFound)?;
        let v = entry.version(version).ok_or(StoreError::NotFound)?;
        let is_head = entry.heads().iter().any(|h| h.version_id() == version);
        let header = &self.file.header;
        self.file.budget.reset();
        let keys = Keys::derive(&self.vk, header)?;
        let mut reader = ObjectReader::new(&self.file.conn)?;
        read_role(&mut reader, &keys, header, m, record, v, !is_head)
    }
}

impl UnlockedVault {
    /// Redisplays the recovery phrase only after reauthenticating the current
    /// operational slot. The returned phrase uses protected memory.
    pub fn recovery_phrase(
        &self,
        password: &MasterPassword,
    ) -> Result<qv_crypto::RecoveryPhrase, StoreError> {
        self.check_identity()?;
        let vk = password_slot(&self.file.slots)?.keyslot.slot.unlock(
            password,
            self.file.header.vault_id,
            self.file.header.key_generation,
        )?;
        self.file.verify_header(&vk)?;
        Ok(qv_crypto::RecoveryPhrase::from_vault_key(&vk)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use qv_crypto::{DerivationProfile, MacProfile};
    use qv_model::{Clock, Entry};

    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};

    /// Argon2id at 256 MiB: at most one run at a time in this test binary.
    static KDF: Mutex<()> = Mutex::new(());

    pub(crate) fn kdf() -> MutexGuard<'static, ()> {
        KDF.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) const PASSWORD: &str = "correct horse battery staple";
    pub(crate) const NAME: &str = "Personal";

    pub(crate) fn pw(s: &str) -> MasterPassword {
        MasterPassword::from_utf8(s.as_bytes()).unwrap()
    }

    /// A private anchor directory inside `d`.
    pub(crate) fn anchors(d: &TestDir) -> AnchorDir {
        AnchorDir::open(&d.join("anchors")).unwrap()
    }

    /// A MAC under VK's header-MAC key: compares VKs without exposing them.
    fn fingerprint(u: &UnlockedVault) -> [u8; 32] {
        let h = u.header();
        let key = u
            .vault_key()
            .purpose_key::<purpose::HeaderMac>(h.vault_id, h.key_generation, h.derivation_profile)
            .unwrap();
        *mac(&key, MacProfile::V1, b"fingerprint")
            .unwrap()
            .as_bytes()
    }

    pub(crate) struct Fixture {
        pub(crate) bytes: Vec<u8>,
        /// The anchor file's name and bytes.
        pub(crate) anchor: (std::ffi::OsString, Vec<u8>),
        fingerprint: [u8; 32],
    }

    /// One vault created with [`PASSWORD`], shared by the tests.
    pub(crate) fn fixture() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            let _k = kdf();
            let d = TestDir::new();
            let a = TestDir::new();
            let p = d.join("fixture.qvault");
            let u = VaultFile::create(&p, &pw(PASSWORD), NAME, &anchors(&a)).unwrap();
            let fingerprint = fingerprint(&u);
            drop(u);
            let entry = std::fs::read_dir(a.join("anchors"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            Fixture {
                bytes: std::fs::read(&p).unwrap(),
                anchor: (entry.file_name(), std::fs::read(entry.path()).unwrap()),
                fingerprint,
            }
        })
    }

    /// A private copy of the fixture vault in `d`, with its anchor in `a`.
    pub(crate) fn copy_fixture(d: &TestDir, a: &TestDir, name: &str) -> (PathBuf, AnchorDir) {
        let p = d.join(name);
        write_file(&p, &fixture().bytes, 0o600);
        let dir = anchors(a);
        let (anchor_name, bytes) = &fixture().anchor;
        write_file(&a.join("anchors").join(anchor_name), bytes, 0o600);
        (p, dir)
    }

    pub(crate) fn unlock(
        p: &Path,
        a: &AnchorDir,
        password: &str,
    ) -> Result<UnlockedVault, StoreError> {
        let _k = kdf();
        VaultFile::open(p)?.unlock(&pw(password), a)
    }

    pub(crate) fn err<T>(r: Result<T, StoreError>) -> StoreError {
        match r {
            Ok(_) => panic!("unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    /// An entry version in the root group, as a local edit over `heads`.
    pub(crate) fn entry_version(
        root: RecordId,
        title: &str,
        writer: WriterId,
        counter: u64,
        heads: &[Clock],
    ) -> RecordVersion {
        RecordVersion {
            version_id: VersionId::generate().unwrap(),
            clock: Clock::for_edit(heads, writer, counter).unwrap(),
            modified_at: now(),
            body: RecordBody::Live(Payload::Entry(Entry {
                group: root,
                type_hint: Text::new("login").unwrap(),
                title: Text::new(title).unwrap(),
                fields: Vec::new(),
                notes: None,
                icon: None,
                expires_at: None,
                created_at: Timestamp(1),
                modified_at: Timestamp(1),
                deleted_at: None,
                ext: Extensions::new(),
            })),
            ext: Extensions::new(),
        }
    }

    /// Commits one edit of `record` (a new entry if it does not exist yet)
    /// and returns its version ID.
    pub(crate) fn edit(u: &mut UnlockedVault, record: RecordId, title: &str) -> VersionId {
        let root = u.manifest().root_group_id();
        let mut w = u.write().unwrap();
        let c = w.reserve_counter().unwrap();
        let heads = w.head_clocks(record);
        let v = entry_version(root, title, w.writer_id(), c, &heads);
        let id = v.version_id;
        w.put_local(record, v).unwrap();
        w.commit().unwrap();
        id
    }

    fn title(v: &RecordVersion) -> String {
        match &v.body {
            RecordBody::Live(Payload::Entry(e)) => e.title.expose().to_owned(),
            _ => panic!("not an entry"),
        }
    }

    #[test]
    fn vault_create_then_unlock() {
        let d = TestDir::new();
        let a = TestDir::new();
        let dir = anchors(&a);
        let p = d.join("v.qvault");
        let created = {
            let _k = kdf();
            VaultFile::create(&p, &pw(PASSWORD), NAME, &dir).unwrap()
        };
        let meta = std::fs::symlink_metadata(&p).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let h = *created.header();
        assert_eq!(h.key_generation, KeyGeneration(1));
        assert_eq!(h.data_profile, StoredDataProfile::V1);
        assert_eq!(h.derivation_profile, DerivationProfile::V1);
        assert_eq!(h.mac_profile, MacProfile::V1);
        assert!(!created.warnings().sync_folder);
        assert_eq!(created.local_seq(), 1);
        let fp = fingerprint(&created);
        // While open, the vault is locked.
        assert_eq!(err(VaultFile::open(&p)), StoreError::Locked);
        drop(created);
        let reopened = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(*reopened.header(), h);
        assert_eq!(fingerprint(&reopened), fp);
        // Three control records of the right kinds, each one head.
        let m = reopened.manifest();
        assert_eq!(m.records().len(), 3);
        assert_eq!(m.references().len(), 3);
        assert_eq!(
            reopened.record_kind(m.vault_meta_id()),
            Some(RecordKind::VaultMeta)
        );
        assert_eq!(
            reopened.record_kind(m.keyslot_id()),
            Some(RecordKind::PasswordKeyslot)
        );
        assert_eq!(
            reopened.record_kind(m.root_group_id()),
            Some(RecordKind::Group)
        );
        let meta_head = m.record(m.vault_meta_id()).unwrap().heads()[0].version_id();
        match reopened
            .read_version(m.vault_meta_id(), meta_head)
            .unwrap()
            .body
        {
            RecordBody::Live(Payload::VaultMeta(v)) => {
                assert_eq!(v.name.expose(), NAME);
                assert_eq!(v.root_group, m.root_group_id());
            }
            _ => panic!("not vault metadata"),
        }
        let root_head = m.record(m.root_group_id()).unwrap().heads()[0].version_id();
        assert!(
            reopened
                .read_version(m.root_group_id(), root_head)
                .unwrap()
                .check_root()
                .is_ok()
        );
        let slot_head = m.record(m.keyslot_id()).unwrap().heads()[0].version_id();
        match reopened
            .read_version(m.keyslot_id(), slot_head)
            .unwrap()
            .body
        {
            RecordBody::Live(Payload::PasswordKeyslot(k)) => {
                assert_eq!(
                    k.encode().unwrap().as_slice(),
                    reopened.file.slots[0].body.as_slice()
                );
            }
            _ => panic!("not a keyslot"),
        }
        assert_eq!(
            err(reopened.read_version(m.vault_meta_id(), VersionId::generate().unwrap())),
            StoreError::NotFound
        );
        // Only the vault remains in the directory: no temp or journal file.
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("v.qvault")]);
        // One anchor.
        assert_eq!(std::fs::read_dir(a.join("anchors")).unwrap().count(), 1);
    }

    #[test]
    fn vault_fixture_unlocks_with_its_password() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(fingerprint(&u), fixture().fingerprint);
    }

    #[test]
    fn vault_unverified_info_needs_no_password() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let header = {
            let f = VaultFile::open(&p).unwrap();
            assert_eq!(f.schema_version(), 0x7FFF_0002);
            assert_eq!(f.password_kdf(), Ok(PasswordKdfProfile::V1));
            *f.header()
        };
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(&header, u.header());
    }

    #[test]
    fn vault_wrong_password() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        assert_eq!(
            err(unlock(&p, &dir, "wrong horse")),
            StoreError::WrongPassword
        );
    }

    /// Changes the vault with plain SQL, unlocks it, expects `expected`,
    /// and checks the file was not changed by the refused unlock.
    fn refused_unlock(sql: &str, expected: StoreError) {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        Connection::open(&p).unwrap().execute_batch(sql).unwrap();
        let before = std::fs::read(&p).unwrap();
        assert_eq!(err(unlock(&p, &dir, PASSWORD)), expected, "{sql}");
        assert_eq!(std::fs::read(&p).unwrap(), before, "{sql}: file changed");
    }

    #[test]
    fn vault_header_mac_tamper_is_integrity() {
        // The right password: the slot opens, the MAC does not verify.
        refused_unlock(
            "UPDATE header SET mac = zeroblob(32)",
            StoreError::Integrity,
        );
    }

    #[test]
    fn vault_mac_covers_slots() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        {
            let c = Connection::open(&p).unwrap();
            let mut body: Vec<u8> = c
                .query_row("SELECT body FROM keyslot", [], |r| r.get(0))
                .unwrap();
            // A canonical unknown key 9 after keys 0–6: still decodes.
            assert_eq!(body[0], 0xa7);
            body[0] = 0xa8;
            body.extend_from_slice(&[0x09, 0x00]);
            assert!(qv_model::Keyslot::decode(&body).is_ok());
            c.execute("UPDATE keyslot SET body = ?1", [body]).unwrap();
        }
        assert_eq!(err(unlock(&p, &dir, PASSWORD)), StoreError::Integrity);
    }

    #[test]
    fn vault_slot_from_another_vault_is_wrong_password() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let other = d.join("other.qvault");
        {
            let _k = kdf();
            drop(VaultFile::create(&other, &pw(PASSWORD), NAME, &anchors(&a)).unwrap());
        }
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        {
            let c = Connection::open(&p).unwrap();
            c.execute("ATTACH DATABASE ?1 AS o", [other.to_str().unwrap()])
                .unwrap();
            c.execute_batch("DELETE FROM keyslot; INSERT INTO keyslot SELECT * FROM o.keyslot;")
                .unwrap();
        }
        // Same password, but the slot is bound to the other vault's ID.
        assert_eq!(err(unlock(&p, &dir, PASSWORD)), StoreError::WrongPassword);
    }

    #[test]
    fn vault_tampered_state_is_integrity() {
        let cases = [
            // A deleted object row.
            "DELETE FROM object WHERE rowid = (SELECT min(rowid) FROM object)",
            // An object row with another length.
            "UPDATE object SET ciphertext = CAST(ciphertext || x'00' AS BLOB) WHERE rowid = (SELECT min(rowid) FROM object)",
            // The same length, one bit flipped.
            "UPDATE object SET ciphertext = CAST((CASE WHEN substr(ciphertext, 1, 1) = x'00' THEN x'01' ELSE x'00' END) || substr(ciphertext, 2) AS BLOB) WHERE rowid = (SELECT min(rowid) FROM object)",
            // Another nonce.
            "UPDATE object SET nonce = zeroblob(24) WHERE rowid = (SELECT min(rowid) FROM object)",
            // Another profile.
            "UPDATE object SET data_profile = 2 WHERE rowid = (SELECT min(rowid) FROM object)",
            // A deleted manifest row (refused by the row checks at open).
            "DELETE FROM manifest",
            // A flipped manifest byte.
            "UPDATE manifest SET ciphertext = CAST((CASE WHEN substr(ciphertext, 1, 1) = x'00' THEN x'01' ELSE x'00' END) || substr(ciphertext, 2) AS BLOB)",
            // A head MAC flipped; a head body changed.
            "UPDATE local_head SET mac = zeroblob(32)",
            "UPDATE local_head SET body = x'a0'",
            // A writer ID that is not a UUIDv4.
            "UPDATE replica SET writer_id = zeroblob(16)",
        ];
        for sql in cases {
            refused_unlock(sql, StoreError::Integrity);
        }
        // An object swapped with another object of the same vault (the
        // two rows exchange their contents; the IDs stay).
        refused_unlock(
            "CREATE TEMP TABLE t AS SELECT * FROM object;
             UPDATE object SET nonce = (SELECT nonce FROM t WHERE t.object_id <> object.object_id ORDER BY t.object_id LIMIT 1),
                               ciphertext = (SELECT ciphertext FROM t WHERE t.object_id <> object.object_id ORDER BY t.object_id LIMIT 1);",
            StoreError::Integrity,
        );
    }

    /// Re-seals the committed manifest after `f` changes it and writes a
    /// correctly MAC'd head for it, as an author holding VK could.
    pub(crate) fn rewrite_manifest(u: &mut UnlockedVault, f: impl FnOnce(&mut Manifest)) {
        let header = u.file.header;
        let keys = Keys::derive(&u.vk, &header).unwrap();
        let mut m = u.state.manifest.clone();
        f(&mut m);
        // Sealed without validation, as a hostile author would.
        let plaintext = m.encode().unwrap();
        let aad = encode_manifest_aad(&header);
        let sealed = qv_crypto::seal(
            &keys.manifest,
            header.data_profile,
            &aad,
            &plaintext,
            crate::limits::MAX_MANIFEST_CIPHERTEXT,
        )
        .unwrap();
        let hash = envelope_hash(
            header.key_generation,
            header.data_profile,
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .unwrap();
        let mut head = u.state.head.clone();
        head.manifest_hash = hash;
        let (stored, _) = sign_head(&keys, &header, &head).unwrap();
        let c = &u.file.conn;
        c.execute("DELETE FROM manifest", []).unwrap();
        c.execute(
            "INSERT INTO manifest VALUES (?1, 1, 1, ?2, ?3)",
            rusqlite::params![hash.as_slice(), sealed.nonce.as_slice(), sealed.ciphertext],
        )
        .unwrap();
        c.execute(
            "UPDATE local_head SET body = ?1, mac = ?2",
            rusqlite::params![stored.body, stored.mac.as_slice()],
        )
        .unwrap();
    }

    fn encode_manifest_aad(h: &Header) -> Vec<u8> {
        qv_encoding::encode_array(|a| {
            a.text("qv/manifest/v1");
            a.bytes(&h.vault_id.0);
            a.uint(u64::from(h.key_generation.0));
            a.uint(u64::from(h.data_profile.id()));
            Ok(())
        })
        .unwrap()
        .to_vec()
    }

    #[test]
    fn vault_authored_manifest_faults_are_integrity() {
        type Change = Box<dyn FnOnce(&mut Manifest)>;
        let other_header = Header::new_vault(VaultId::generate().unwrap());
        let cases: Vec<(&str, Change)> = vec![
            (
                "configuration digest of another vault",
                Box::new(move |m| {
                    *m = Manifest::empty(
                        &other_header,
                        m.vault_meta_id(),
                        m.keyslot_id(),
                        m.root_group_id(),
                    )
                    .unwrap()
                    .with_records_of(m);
                }),
            ),
            (
                "control IDs swapped",
                Box::new(|m| {
                    let (meta, slot, root) = (m.vault_meta_id(), m.keyslot_id(), m.root_group_id());
                    m.set_control(slot, meta, root);
                }),
            ),
            (
                "root and metadata swapped",
                Box::new(|m| {
                    let (meta, slot, root) = (m.vault_meta_id(), m.keyslot_id(), m.root_group_id());
                    m.set_control(root, slot, meta);
                }),
            ),
        ];
        for (what, change) in cases {
            let (d, a) = (TestDir::new(), TestDir::new());
            let (p, dir) = copy_fixture(&d, &a, "v.qvault");
            {
                let mut u = unlock(&p, &dir, PASSWORD).unwrap();
                rewrite_manifest(&mut u, change);
            }
            assert_eq!(
                err(unlock(&p, &dir, PASSWORD)),
                StoreError::Integrity,
                "{what}"
            );
        }
        // The unchanged re-seal still opens (as a rollback: its head digest
        // no longer matches the anchor), which shows the cases above fail
        // for their change alone.
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        {
            let mut u = unlock(&p, &dir, PASSWORD).unwrap();
            rewrite_manifest(&mut u, |_| {});
        }
        assert_eq!(err(unlock(&p, &dir, PASSWORD)), StoreError::Rollback);
    }

    #[test]
    fn vault_anchor_missing_or_from_elsewhere() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        // Another copy of the same vault, one commit ahead.
        let (d2, a2) = (TestDir::new(), TestDir::new());
        let (q, dir2) = copy_fixture(&d2, &a2, "v.qvault");
        {
            let mut u = unlock(&q, &dir2, PASSWORD).unwrap();
            let r = <RecordId as RandomId>::generate().unwrap();
            edit(&mut u, r, "x");
        }
        let (anchor_name, _) = &fixture().anchor;
        let newer = std::fs::read(a2.join("anchors").join(anchor_name)).unwrap();
        // The old DB with the newer anchor: rollback.
        write_file(&a.join("anchors").join(anchor_name), &newer, 0o600);
        let before = std::fs::read(&p).unwrap();
        assert_eq!(err(unlock(&p, &dir, PASSWORD)), StoreError::Rollback);
        assert_eq!(std::fs::read(&p).unwrap(), before);
        // No anchor at all.
        std::fs::remove_file(a.join("anchors").join(anchor_name)).unwrap();
        assert_eq!(err(unlock(&p, &dir, PASSWORD)), StoreError::NoAnchor);
        assert_eq!(std::fs::read(&p).unwrap(), before);
        // Explicit recovery: readable, not writable until adopted.
        let (mut u, status) = {
            let _k = kdf();
            VaultFile::open(&p)
                .unwrap()
                .unlock_for_recovery(&pw(PASSWORD), &dir)
                .unwrap()
        };
        assert_eq!(status, AnchorStatus::Missing);
        assert_eq!(u.manifest().records().len(), 3);
        assert_eq!(err(u.write()), StoreError::NoAnchor);
        let old_writer = u.writer_id();
        u.adopt_baseline().unwrap();
        assert_ne!(u.writer_id(), old_writer);
        assert_eq!(u.local_seq(), 2);
        let r = <RecordId as RandomId>::generate().unwrap();
        edit(&mut u, r, "after recovery");
        drop(u);
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(u.local_seq(), 3);
        assert_eq!(u.manifest().records().len(), 4);
        let rec = u.manifest().record(r).unwrap();
        let head = &rec.heads()[0];
        assert_eq!(head.clock().pairs(), &[(u.writer_id(), 1)]);
        assert_eq!(
            title(&u.read_version(r, head.version_id()).unwrap()),
            "after recovery"
        );
    }

    #[test]
    fn vault_create_refusals() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let dir = anchors(&a);
        let existing = d.join("v.qvault");
        write_file(&existing, b"keep", 0o600);
        // These fail before any KDF.
        let p = pw(PASSWORD);
        let create = |path: &Path| VaultFile::create(path, &p, NAME, &dir);
        assert_eq!(err(create(&existing)), StoreError::Exists);
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
        let link = d.join("l.qvault");
        std::os::unix::fs::symlink(d.join("missing"), &link).unwrap();
        assert_eq!(err(create(&link)), StoreError::Exists);
        assert_eq!(err(create(&d.join("v.db"))), StoreError::Unsupported);
        assert_eq!(err(create(&d.join("v"))), StoreError::Unsupported);
        let open_dir = d.subdir("open", 0o777);
        assert_eq!(
            err(create(&open_dir.join("v.qvault"))),
            StoreError::UnsafeFile
        );
        assert_eq!(
            err(create(&d.join("missing/v.qvault"))),
            StoreError::NotFound
        );
        // A name the model refuses.
        let long = "n".repeat(qv_model::MAX_TEXT_BYTES + 1);
        assert_eq!(
            err(VaultFile::create(&d.join("n.qvault"), &p, &long, &dir)),
            StoreError::InvalidEdit
        );
        assert_eq!(std::fs::read_dir(a.join("anchors")).unwrap().count(), 0);
    }

    #[test]
    fn vault_failed_create_leaves_nothing() {
        let (d, a) = (TestDir::new(), TestDir::new());
        FAIL_CREATE.with(|f| f.set(true));
        let r = VaultFile::create(&d.join("v.qvault"), &pw(PASSWORD), NAME, &anchors(&a));
        FAIL_CREATE.with(|f| f.set(false));
        assert_eq!(err(r), StoreError::Internal);
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(a.join("anchors")).unwrap().count(), 0);
    }

    #[test]
    fn vault_open_lock_identity_and_debug() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, _) = copy_fixture(&d, &a, "v.qvault");
        let f = VaultFile::open(&p).unwrap();
        assert_eq!(err(VaultFile::open(&p)), StoreError::Locked);
        assert_eq!(f.check_identity(), Ok(()));
        assert!(!f.warnings().any());
        let shown = format!("{f:?}");
        assert_eq!(shown, "VaultFile(..)");
        assert!(!shown.contains("v.qvault"));
        let (q, _) = copy_fixture(&d, &a, "w.qvault");
        std::fs::rename(&q, &p).unwrap();
        assert_eq!(f.check_identity(), Err(StoreError::Replaced));
        drop(f);
        // The replacement is a valid vault and opens on its own.
        assert!(VaultFile::open(&p).is_ok());
    }

    #[test]
    fn vault_unlocked_debug_is_redacted() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(format!("{u:?}"), "UnlockedVault(<redacted>)");
        assert_eq!(u.check_identity(), Ok(()));
    }
}
