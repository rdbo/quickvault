// SPDX-License-Identifier: AGPL-3.0-or-later

//! The mutation transaction (spec 0004 §1.3, §5.2; 0005 §1.2–1.3, §5.4).
//!
//! Every write goes through [`UnlockedVault::write`] → [`Write::put_local`]
//! → [`Write::commit`], in this order:
//!
//! 1. Refuse if writes are blocked; finish a pending anchor update first;
//!    check the file identity; `BEGIN IMMEDIATE`; re-read the head and
//!    replica rows, which must equal what this session verified
//!    ([`StoreError::Changed`] otherwise).
//! 2. Each `put_local` checks the edit, encrypts the version under a new
//!    object ID and inserts the object row. A final tombstone (0007 §2.2)
//!    also drops the record's history and advances its history floor to
//!    cover every dropped version, in the same manifest.
//! 3. `commit` seals the new manifest (every budget checked first), inserts
//!    it and deletes the old one,
//! 4. writes the new head (sequence + 1, naming the old head's digest),
//! 5. stores the counter reservation and prunes the object rows whose
//!    references the new manifest dropped,
//! 6. commits durably (`synchronous=FULL`),
//! 7. replaces the external anchor, and only then
//! 8. updates the session and reports success.
//!
//! A crash before step 6 leaves the old state; after it, the next unlock
//! sees a head one step past the anchor and advances the anchor (0005
//! §5.4). If step 7 fails, `commit` returns the anchor's error although the
//! change is durable, and the next write retries the anchor before it
//! starts, so the database never gets two steps ahead of its anchor.
//!
//! Counters are reserved in the same SQLite transaction that uses them
//! (`replica.next_counter`, plan 0009 D-B), so no committed version can
//! carry a counter whose reservation is not committed too. Offline vaults
//! have no outbox (server sync, milestone 3).

use std::collections::{BTreeMap, BTreeSet};

use qv_crypto::RecordId;
use qv_model::{
    Clock, Deletion, ObjectId, Payload, RandomId, RecordBody, RecordKind, RecordVersion, WriterId,
};

use crate::crash::{CrashPoint, point};
use crate::error::{StoreError, sqlite_err, write_err};
use crate::head::LocalHead;
use crate::manifest::{Manifest, ObjectRef, VersionRef, seal_manifest};
use crate::object::seal_record;
use crate::schema;
use crate::vault::{
    Keys, UnlockedVault, WriteGate, anchor_of, insert_manifest, insert_object, len64, scope,
    sign_head,
};

/// Largest counter: SQLite stores `next_counter` as a signed 64-bit integer.
const MAX_COUNTER: u64 = i64::MAX as u64;

/// One open mutation. Dropping it without [`Write::commit`] rolls the
/// transaction back and leaves the vault unchanged.
pub struct Write<'v> {
    vault: &'v mut UnlockedVault,
    keys: Keys,
    manifest: Manifest,
    writer: WriterId,
    next_counter: u64,
    reserved: BTreeSet<u64>,
    used: BTreeSet<u64>,
    touched: BTreeSet<RecordId>,
    new_kinds: Vec<(RecordId, RecordKind)>,
    staged: BTreeMap<RecordId, crate::attachment::StagedAttachment>,
    growth: u64,
    puts: usize,
    poisoned: bool,
    finished: bool,
}

impl core::fmt::Debug for Write<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Write(..)")
    }
}

impl Drop for Write<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Nothing is reported from here; an open transaction is also
            // rolled back when the connection closes.
            let _ = self.vault.file.conn.execute_batch("ROLLBACK");
        }
    }
}

fn rollback(vault: &UnlockedVault) {
    let _ = vault.file.conn.execute_batch("ROLLBACK");
}

impl UnlockedVault {
    /// Starts a mutation (0004 §5.2). Fails with the anchor error
    /// ([`StoreError::Rollback`], [`StoreError::NoAnchor`]) while writes are
    /// blocked, with [`StoreError::Replaced`] if the path no longer names
    /// this file, and with [`StoreError::Changed`] if the head on disk is not
    /// the one this session verified.
    pub fn write(&mut self) -> Result<Write<'_>, StoreError> {
        if let WriteGate::Blocked(e) = self.gate {
            return Err(e);
        }
        self.finish_pending_anchor()?;
        self.begin(None)
    }

    /// Retries a failed anchor update before the next commit, so the
    /// database never gets two steps ahead of its anchor.
    fn finish_pending_anchor(&mut self) -> Result<(), StoreError> {
        if self.gate == WriteGate::AnchorPending {
            self.anchors
                .store(&self.state.replica.replica_id, &anchor_of(&self.state))?;
            self.gate = WriteGate::Open;
        }
        Ok(())
    }

    /// Explicit recovery (0005 §5.4): makes the current verified state the
    /// new baseline. A new writer ID replaces the old one (its counters may
    /// have been rolled back, 0005 §1.3), the head advances by one naming
    /// the current head, and the anchor is replaced. Writes are then
    /// allowed. Only for a vault opened with
    /// [`crate::VaultFile::unlock_for_recovery`] after the user chose to
    /// accept its state.
    pub fn adopt_baseline(&mut self) -> Result<(), StoreError> {
        self.finish_pending_anchor()?;
        let writer = WriterId::generate()?;
        let w = self.begin(Some(writer))?;
        w.commit()?;
        Ok(())
    }

    fn begin(&mut self, new_writer: Option<WriterId>) -> Result<Write<'_>, StoreError> {
        self.check_identity()?;
        self.file.budget.reset();
        let keys = Keys::derive(&self.vk, &self.file.header)?;
        self.file
            .conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| sqlite_err(&e))?;
        let fresh = schema::read_head(&self.file.conn)
            .and_then(|h| Ok((h, schema::read_replica(&self.file.conn)?)));
        match fresh {
            Ok((head, replica))
                if head == self.state.stored_head && replica == self.state.replica => {}
            Ok(_) => {
                rollback(self);
                return Err(StoreError::Changed);
            }
            Err(e) => {
                rollback(self);
                return Err(e);
            }
        }
        if let Err(e) = point(CrashPoint::Begun) {
            rollback(self);
            return Err(e);
        }
        let (writer, next_counter) = match new_writer {
            Some(w) => (w, 1),
            None => (self.state.writer, self.state.replica.next_counter),
        };
        let manifest = self.state.manifest.clone();
        Ok(Write {
            vault: self,
            keys,
            manifest,
            writer,
            next_counter,
            reserved: BTreeSet::new(),
            used: BTreeSet::new(),
            touched: BTreeSet::new(),
            new_kinds: Vec::new(),
            staged: BTreeMap::new(),
            growth: 0,
            puts: 0,
            poisoned: false,
            finished: false,
        })
    }
}

impl Write<'_> {
    /// Streams bounded plaintext into encrypted objects in this transaction.
    /// Any failure poisons the write; commit requires matching metadata consumption.
    pub fn stage_attachment(
        &mut self,
        record: RecordId,
        source: &mut impl std::io::Read,
        cancelled: &impl Fn() -> bool,
    ) -> Result<crate::StagedAttachment, StoreError> {
        if self
            .manifest
            .records()
            .len()
            .saturating_add(self.staged.len())
            >= crate::MAX_RECORDS
        {
            self.poisoned = true;
            return Err(StoreError::LimitExceeded);
        }
        if self.poisoned
            || self.manifest.record(record).is_some()
            || self.staged.contains_key(&record)
        {
            self.poisoned = true;
            return Err(StoreError::InvalidEdit);
        }
        let result = self.stage_content(record, source, cancelled);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn stage_content(
        &mut self,
        record: RecordId,
        source: &mut impl std::io::Read,
        cancelled: &impl Fn() -> bool,
    ) -> Result<crate::StagedAttachment, StoreError> {
        use qv_crypto::{ContentHasher, SecretArray, SecretBytes, purpose};
        let header = self.vault.file.header;
        let root = self.vault.vk.purpose_key::<purpose::Attachment>(
            header.vault_id,
            header.key_generation,
            header.derivation_profile,
        )?;
        let key = root.attachment_key(header.vault_id, qv_crypto::AttachmentId(record.0))?;
        let mut buf = SecretBytes::zeroed(qv_crypto::CHUNK_BYTES);
        let mut hash = ContentHasher::new();
        let mut size = 0u64;
        let mut chunks = Vec::new();
        loop {
            let mut filled = 0;
            while filled < buf.len() {
                if cancelled() {
                    return Err(StoreError::Io);
                }
                let allowed = (qv_model::MAX_ATTACHMENT_BYTES - size - filled as u64 + 1)
                    .min((buf.len() - filled) as u64) as usize;
                let n = match source.read(&mut buf.expose_secret_mut()[filled..filled + allowed]) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(StoreError::Io),
                };
                if n == 0 {
                    break;
                }
                filled += n;
                if size + filled as u64 > qv_model::MAX_ATTACHMENT_BYTES {
                    return Err(StoreError::LimitExceeded);
                }
            }
            if filled == 0 {
                break;
            }
            if chunks.len() >= crate::MAX_CHUNKS
                || self.manifest.references().len() >= crate::MAX_OBJECTS
            {
                return Err(StoreError::LimitExceeded);
            }
            size += filled as u64;
            hash.update(&buf.expose_secret()[..filled]);
            let id = ObjectId::generate()?;
            let aad = crate::attachment::aad(
                scope(&header),
                record,
                id,
                chunks.len(),
                header.data_profile,
            )?;
            let sealed = qv_crypto::seal_chunk(
                &key,
                header.data_profile,
                &aad,
                &buf.expose_secret()[..filled],
            )?;
            buf.expose_secret_mut().fill(0);
            let reference = ObjectRef::new(id, header.data_profile, &sealed.ciphertext)?;
            let total = self
                .manifest
                .references()
                .iter()
                .try_fold(reference.length(), |n, r| {
                    n.checked_add(r.length()).ok_or(StoreError::LimitExceeded)
                })?;
            if total > crate::MAX_TOTAL_CIPHERTEXT {
                return Err(StoreError::LimitExceeded);
            }
            let object = crate::object::SealedObject {
                object_id: id,
                data_profile: header.data_profile,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
            };
            insert_object(&self.vault.file.conn, header.key_generation, &object)?;
            self.growth = self.growth.saturating_add(len64(object.ciphertext.len()));
            self.manifest.insert_reference(reference)?;
            chunks.push(id);
            point(CrashPoint::ObjectsWritten)?;
            if filled < buf.len() {
                break;
            }
        }
        let hash = hash.finalize();
        let mut copy = SecretArray::zeroed();
        copy.expose_secret_mut()
            .copy_from_slice(hash.expose_secret());
        self.staged.insert(
            record,
            crate::StagedAttachment {
                chunks: chunks.clone(),
                size,
                hash: copy,
            },
        );
        Ok(crate::StagedAttachment { chunks, size, hash })
    }

    /// This replica's writer ID, for the new clock.
    pub fn writer_id(&self) -> WriterId {
        self.writer
    }

    /// Reserves the next counter of this replica's writer (0005 §1.3). The
    /// reservation is stored by [`Self::commit`] in the same transaction as
    /// the versions that use it. [`StoreError::LimitExceeded`] once the
    /// counters are exhausted (a new writer ID is needed).
    pub fn reserve_counter(&mut self) -> Result<u64, StoreError> {
        let c = self.next_counter;
        if c >= MAX_COUNTER {
            return Err(StoreError::LimitExceeded);
        }
        self.next_counter = c + 1;
        self.reserved.insert(c);
        Ok(c)
    }

    /// The clocks of the current heads of `record` (none for a new record),
    /// to join into the edit's clock with `Clock::for_edit`.
    pub fn head_clocks(&self, record: RecordId) -> Vec<Clock> {
        self.manifest
            .record(record)
            .map(|r| r.heads().iter().map(|h| h.clock().clone()).collect())
            .unwrap_or_default()
    }

    /// Stages one local edit of `record` (0005 §1.2). The clock's component
    /// for this writer must be a counter reserved by this `Write`, the clock
    /// must strictly dominate every current head, the kind must not change,
    /// control records (vault metadata, password keyslot, root group) keep
    /// their rules, and each record takes at most one edit per `Write`.
    /// Anything else is [`StoreError::InvalidEdit`] with nothing written.
    ///
    /// A final tombstone of an existing record drops all of its history and
    /// advances its floor (0007 §2.2); a new record cannot start as one.
    pub fn put_local(
        &mut self,
        record: RecordId,
        version: RecordVersion,
    ) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Internal);
        }
        if let Some(staged) = self.staged.get(&record) {
            let matches = matches!(&version.body, RecordBody::Live(Payload::AttachmentMeta(a))
                if a.size == staged.size && a.chunk_object_ids == staged.chunks && &a.content_hash == staged.hash.expose_secret());
            if !matches {
                self.poisoned = true;
                return Err(StoreError::InvalidEdit);
            }
        }
        self.check_edit(record, &version)?;
        let counter = version.clock.get(self.writer);
        let header = self.vault.file.header;
        let object = seal_record(
            &self.keys.record,
            scope(&header),
            header.data_profile,
            record,
            &version,
        )?;
        let reference = ObjectRef::new(object.object_id, object.data_profile, &object.ciphertext)?;
        let mut role = VersionRef::new(version.version_id, version.clock.clone(), object.object_id);
        if let RecordBody::Live(Payload::AttachmentMeta(a)) = &version.body {
            role = role.with_chunks(a.chunk_object_ids.clone());
        }
        if let Err(e) = insert_object(&self.vault.file.conn, header.key_generation, &object) {
            self.poisoned = true;
            return Err(e);
        }
        let staged = if self.manifest.record(record).is_some() {
            if version.deletion() == Deletion::Final {
                self.manifest.finalize(record, role, reference)
            } else {
                self.manifest.replace_heads(record, role, reference)
            }
        } else {
            self.new_kinds.push((record, version.kind()));
            self.manifest.add_record(record, role, reference)
        };
        if let Err(e) = staged {
            self.poisoned = true;
            return Err(e);
        }
        self.staged.remove(&record);
        self.used.insert(counter);
        self.touched.insert(record);
        self.growth = self.growth.saturating_add(len64(object.ciphertext.len()));
        self.puts += 1;
        if self.puts == 1
            && let Err(e) = point(CrashPoint::ObjectsWritten)
        {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    /// The `put_local` rules, checked before anything is written.
    fn check_edit(&self, record: RecordId, v: &RecordVersion) -> Result<(), StoreError> {
        let invalid = Err(StoreError::InvalidEdit);
        if self.touched.contains(&record) {
            return invalid;
        }
        let counter = v.clock.get(self.writer);
        if !self.reserved.contains(&counter) || self.used.contains(&counter) {
            return invalid;
        }
        let kind = v.kind();
        let m = &self.manifest;
        match m.record(record) {
            None => {
                // Control records exist only from `create`; a record cannot
                // start as a final tombstone.
                if matches!(kind, RecordKind::VaultMeta | RecordKind::PasswordKeyslot)
                    || v.deletion() == Deletion::Final
                {
                    return invalid;
                }
            }
            Some(entry) => {
                if self.vault.state.kinds.get(&record) != Some(&kind) {
                    return invalid;
                }
                let heads = entry.heads();
                if !heads.iter().all(|h| v.clock.dominates(h.clock())) {
                    return invalid;
                }
                // Second line for counter reuse (plan 0009 D-B): the counter
                // exceeds the writer's joined component.
                if Clock::for_edit(heads.iter().map(VersionRef::clock), self.writer, counter)
                    .is_err()
                {
                    return invalid;
                }
                if entry.version(v.version_id).is_some() {
                    return invalid;
                }
            }
        }
        // Vault metadata and the keyslot record are undeletable (0003 §2.3);
        // the model refuses to encode their tombstones, but that is an edit
        // rule, not an integrity failure.
        if v.deletion() == Deletion::Final
            && matches!(kind, RecordKind::VaultMeta | RecordKind::PasswordKeyslot)
        {
            return invalid;
        }
        if record == m.root_group_id() && v.check_root().is_err() {
            return invalid;
        }
        if let RecordBody::Live(Payload::VaultMeta(meta)) = &v.body
            && meta.root_group != m.root_group_id()
        {
            return invalid;
        }
        // Chunks are written from phase 1.11; until then an attachment can
        // name only chunks that already exist.
        if let RecordBody::Live(Payload::AttachmentMeta(a)) = &v.body
            && !a
                .chunk_object_ids
                .iter()
                .all(|c: &ObjectId| m.reference(*c).is_some())
        {
            return invalid;
        }
        Ok(())
    }

    /// Removes one history version (retention and purge, phase 1.12; the
    /// prune tests).
    #[cfg(test)]
    pub(crate) fn drop_history(
        &mut self,
        record: RecordId,
        version: qv_model::VersionId,
    ) -> Result<(), StoreError> {
        self.manifest.remove_history(record, version)
    }

    /// Commits the mutation (steps 3–8 of the module docs).
    pub fn commit(mut self) -> Result<(), StoreError> {
        if self.poisoned || !self.staged.is_empty() {
            return Err(StoreError::Internal);
        }
        let header = self.vault.file.header;
        let sealed = seal_manifest(
            &self.keys.manifest,
            scope(&header),
            header.data_profile,
            &self.manifest,
        )?;
        let old = &self.vault.state;
        let head = LocalHead {
            vault_id: old.head.vault_id,
            key_generation: old.head.key_generation,
            local_seq: old
                .head
                .local_seq
                .checked_add(1)
                .ok_or(StoreError::LimitExceeded)?,
            previous_digest: Some(old.digest),
            manifest_hash: sealed.hash,
            remote: old.head.remote,
        };
        let (stored_head, digest) = sign_head(&self.keys, &header, &head)?;
        let old_hash = old.head.manifest_hash;
        let growth = self.growth.saturating_add(len64(sealed.ciphertext.len()));

        let conn = &self.vault.file.conn;
        let w = |e: rusqlite::Error| write_err(conn, &e, growth);
        insert_manifest(conn, &sealed)?;
        conn.execute(
            "DELETE FROM manifest WHERE manifest_hash = ?1",
            [old_hash.as_slice()],
        )
        .map_err(w)?;
        point(CrashPoint::ManifestWritten)?;
        conn.execute(
            "UPDATE local_head SET body = ?1, mac = ?2 WHERE id = 1",
            rusqlite::params![stored_head.body.as_slice(), stored_head.mac.as_slice()],
        )
        .map_err(w)?;
        point(CrashPoint::HeadWritten)?;
        let next = i64::try_from(self.next_counter).map_err(|_| StoreError::LimitExceeded)?;
        conn.execute(
            "UPDATE replica SET writer_id = ?1, next_counter = ?2 WHERE id = 1",
            rusqlite::params![self.writer.to_bytes().as_slice(), next],
        )
        .map_err(w)?;
        let kept: BTreeSet<ObjectId> = self
            .manifest
            .references()
            .iter()
            .map(ObjectRef::object_id)
            .collect();
        let generation = i64::from(header.key_generation.0);
        for r in self.vault.state.manifest.references() {
            if !kept.contains(&r.object_id()) {
                conn.execute(
                    "DELETE FROM object WHERE key_generation = ?1 AND object_id = ?2",
                    rusqlite::params![generation, r.object_id().to_bytes().as_slice()],
                )
                .map_err(w)?;
            }
        }
        point(CrashPoint::Pruned)?;
        conn.execute_batch("COMMIT").map_err(w)?;
        // Durable from here: the session follows the database.
        self.finished = true;
        let replica = schema::StoredReplica {
            replica_id: self.vault.state.replica.replica_id,
            writer_id: self.writer.to_bytes(),
            next_counter: self.next_counter,
        };
        let state = &mut self.vault.state;
        core::mem::swap(&mut state.manifest, &mut self.manifest);
        state.kinds.extend(self.new_kinds.drain(..));
        state.stored_head = stored_head;
        state.head = head;
        state.digest = digest;
        state.replica = replica;
        state.writer = self.writer;
        self.vault.gate = WriteGate::AnchorPending;
        point(CrashPoint::Committed)?;
        self.vault.anchors.store(
            &self.vault.state.replica.replica_id,
            &anchor_of(&self.vault.state),
        )?;
        self.vault.gate = WriteGate::Open;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use qv_model::{Extensions, Group, Text, Timestamp};
    use rusqlite::Connection;

    use super::*;
    use crate::fs::test_dir::TestDir;
    use crate::vault::VaultFile;
    use crate::vault::tests::{PASSWORD, copy_fixture, edit, entry_version, err, unlock};

    fn new_record() -> RecordId {
        <RecordId as RandomId>::generate().unwrap()
    }

    fn object_count(u: &UnlockedVault) -> i64 {
        u.file
            .conn
            .query_row("SELECT count(*) FROM object", [], |r| r.get(0))
            .unwrap()
    }

    fn soft_delete(mut v: RecordVersion) -> RecordVersion {
        if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
            e.deleted_at = Some(Timestamp(5));
        }
        v
    }

    #[test]
    fn write_edits_build_history() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let r = new_record();
        let mut versions = Vec::new();
        {
            let mut u = unlock(&p, &dir, PASSWORD).unwrap();
            versions.push(edit(&mut u, r, "one"));
            versions.push(edit(&mut u, r, "two"));
            versions.push(edit(&mut u, r, "three"));
            // Soft delete as a fourth causal edit.
            let root = u.manifest().root_group_id();
            let mut w = u.write().unwrap();
            let c = w.reserve_counter().unwrap();
            let heads = w.head_clocks(r);
            let v = soft_delete(entry_version(root, "three", w.writer_id(), c, &heads));
            versions.push(v.version_id);
            w.put_local(r, v).unwrap();
            w.commit().unwrap();
            assert_eq!(u.local_seq(), 5);
        }
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(u.local_seq(), 5);
        let rec = u.manifest().record(r).unwrap();
        assert_eq!(rec.heads().len(), 1);
        assert_eq!(rec.heads()[0].version_id(), versions[3]);
        assert_eq!(rec.history().len(), 3);
        let head = u.read_version(r, versions[3]).unwrap();
        assert_eq!(head.deletion(), qv_model::Deletion::SoftDeleted);
        for (v, t) in versions.iter().take(3).zip(["one", "two", "three"]) {
            match u.read_version(r, *v).unwrap().body {
                RecordBody::Live(Payload::Entry(e)) => assert_eq!(e.title.expose(), t),
                _ => panic!("not an entry"),
            }
        }
        // Counters 4..=7 after the fixture's 1..=3, one per version.
        let writer = u.writer_id();
        assert_eq!(rec.heads()[0].clock().get(writer), 7);
        assert_eq!(u.state.replica.next_counter, 8);
        assert_eq!(u.record_kind(r), Some(RecordKind::Entry));
        // Old manifests are gone; three control objects plus four versions.
        assert_eq!(object_count(&u), 7);
    }

    #[test]
    fn write_history_is_verified_on_read() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let r = new_record();
        let (first, second);
        {
            let mut u = unlock(&p, &dir, PASSWORD).unwrap();
            first = edit(&mut u, r, "one");
            second = edit(&mut u, r, "two");
            let oid = u
                .manifest()
                .record(r)
                .unwrap()
                .version(first)
                .unwrap()
                .object_id();
            // Flip one ciphertext byte of the history object behind the
            // session's back (same length).
            let c = Connection::open(&p).unwrap();
            let mut ct: Vec<u8> = c
                .query_row(
                    "SELECT ciphertext FROM object WHERE object_id = ?1",
                    [oid.to_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            ct[10] ^= 1;
            c.execute(
                "UPDATE object SET ciphertext = ?1 WHERE object_id = ?2",
                rusqlite::params![ct, oid.to_bytes().as_slice()],
            )
            .unwrap();
        }
        // Unlock checks history rows and lengths only, so it succeeds; the
        // read checks the hash.
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert!(u.read_version(r, second).is_ok());
        assert_eq!(err(u.read_version(r, first)), StoreError::Integrity);
    }

    #[test]
    fn write_put_local_rules() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        let r = new_record();
        let root = u.manifest().root_group_id();
        // The base head joins another writer's component (as after a merge),
        // so a clock built from this writer alone does not dominate it.
        let foreign = Clock::from_pairs(vec![(WriterId::generate().unwrap(), 9)]).unwrap();
        {
            let mut w = u.write().unwrap();
            let c = w.reserve_counter().unwrap();
            w.put_local(r, entry_version(root, "base", w.writer_id(), c, &[foreign]))
                .unwrap();
            w.commit().unwrap();
        }
        let meta = u.manifest().vault_meta_id();
        let seq = u.local_seq();
        let objects = object_count(&u);
        let base_head = u.manifest().record(r).unwrap().heads()[0].clone();

        let check =
            |u: &mut UnlockedVault, f: &dyn Fn(&mut Write<'_>) -> RecordVersion, rec: RecordId| {
                let mut w = u.write().unwrap();
                let v = f(&mut w);
                let e = w.put_local(rec, v).err();
                drop(w);
                e
            };
        let invalid = Some(StoreError::InvalidEdit);
        // An unreserved counter.
        assert_eq!(
            check(
                &mut u,
                &|w| entry_version(root, "x", w.writer_id(), 1000, &w.head_clocks(r)),
                r
            ),
            invalid
        );
        // A clock that does not dominate the head (built without it).
        assert_eq!(
            check(
                &mut u,
                &|w| {
                    let c = w.reserve_counter().unwrap();
                    entry_version(root, "x", w.writer_id(), c, &[])
                },
                r
            ),
            invalid
        );
        // Another writer's clock: no counter reserved for this writer.
        assert_eq!(
            check(
                &mut u,
                &|w| {
                    let _ = w.reserve_counter().unwrap();
                    let other = WriterId::generate().unwrap();
                    entry_version(root, "x", other, 1, &[])
                },
                r
            ),
            invalid
        );
        // A second vault-metadata record.
        assert_eq!(
            check(
                &mut u,
                &|w| {
                    let c = w.reserve_counter().unwrap();
                    let mut v = entry_version(root, "x", w.writer_id(), c, &[]);
                    v.body = RecordBody::Live(Payload::VaultMeta(qv_model::VaultMeta {
                        name: Text::new("m").unwrap(),
                        description: None,
                        root_group: root,
                        settings: qv_model::Settings::default(),
                        ext: Extensions::new(),
                    }));
                    v
                },
                new_record()
            ),
            invalid
        );
        // Vault metadata naming another root.
        assert_eq!(
            check(
                &mut u,
                &|w| {
                    let c = w.reserve_counter().unwrap();
                    let heads = w.head_clocks(meta);
                    let mut v = entry_version(root, "x", w.writer_id(), c, &heads);
                    v.body = RecordBody::Live(Payload::VaultMeta(qv_model::VaultMeta {
                        name: Text::new("m").unwrap(),
                        description: None,
                        root_group: new_record(),
                        settings: qv_model::Settings::default(),
                        ext: Extensions::new(),
                    }));
                    v
                },
                meta
            ),
            invalid
        );
        // The root soft-deleted.
        assert_eq!(
            check(
                &mut u,
                &|w| {
                    let c = w.reserve_counter().unwrap();
                    let heads = w.head_clocks(root);
                    let mut v = entry_version(root, "x", w.writer_id(), c, &heads);
                    v.body = RecordBody::Live(Payload::Group(Group {
                        parent: None,
                        name: Text::new("root").unwrap(),
                        notes: None,
                        icon: None,
                        order: Text::new("a").unwrap(),
                        deleted_at: Some(Timestamp(9)),
                        ext: Extensions::new(),
                    }));
                    v
                },
                root
            ),
            invalid
        );
        // A kind change: the entry record as a group.
        assert_eq!(
            check(
                &mut u,
                &|w| {
                    let c = w.reserve_counter().unwrap();
                    let heads = w.head_clocks(r);
                    let mut v = entry_version(root, "x", w.writer_id(), c, &heads);
                    v.body = RecordBody::Live(Payload::Group(Group {
                        parent: Some(root),
                        name: Text::new("g").unwrap(),
                        notes: None,
                        icon: None,
                        order: Text::new("a").unwrap(),
                        deleted_at: None,
                        ext: Extensions::new(),
                    }));
                    v
                },
                r
            ),
            invalid
        );
        // A duplicate version ID (the head's own ID with a new clock).
        assert_eq!(
            check(
                &mut u,
                &|w| {
                    let c = w.reserve_counter().unwrap();
                    let mut v = entry_version(root, "x", w.writer_id(), c, &w.head_clocks(r));
                    v.version_id = base_head.version_id();
                    v
                },
                r
            ),
            invalid
        );
        // A reused counter and a second edit of one record in one write.
        {
            let mut w = u.write().unwrap();
            let c = w.reserve_counter().unwrap();
            let heads = w.head_clocks(r);
            w.put_local(r, entry_version(root, "ok", w.writer_id(), c, &heads))
                .unwrap();
            let other = new_record();
            assert_eq!(
                w.put_local(other, entry_version(root, "reuse", w.writer_id(), c, &[])),
                Err(StoreError::InvalidEdit)
            );
            let c2 = w.reserve_counter().unwrap();
            let heads = w.head_clocks(r);
            assert_eq!(
                w.put_local(r, entry_version(root, "again", w.writer_id(), c2, &heads)),
                Err(StoreError::InvalidEdit)
            );
            // Dropped without commit.
        }
        // Nothing was written by any of these.
        assert_eq!(u.local_seq(), seq);
        assert_eq!(object_count(&u), objects);
        drop(u);
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(u.local_seq(), seq);
        assert_eq!(u.manifest().record(r).unwrap().heads()[0], base_head);
    }

    #[test]
    fn write_changed_head_is_refused() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        Connection::open(&p)
            .unwrap()
            .execute("UPDATE local_head SET mac = zeroblob(32)", [])
            .unwrap();
        assert_eq!(err(u.write()), StoreError::Changed);
        // A changed counter reservation is refused the same way.
        let (d2, a2) = (TestDir::new(), TestDir::new());
        let (q, dir2) = copy_fixture(&d2, &a2, "v.qvault");
        let mut u2 = unlock(&q, &dir2, PASSWORD).unwrap();
        Connection::open(&q)
            .unwrap()
            .execute("UPDATE replica SET next_counter = 1", [])
            .unwrap();
        assert_eq!(err(u2.write()), StoreError::Changed);
        drop(u);
    }

    #[test]
    fn write_failed_anchor_blocks_until_retried() {
        if rustix::process::geteuid().is_root() {
            // Root ignores the directory permission this test relies on.
            return;
        }
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let anchor_dir = a.join("anchors");
        let mode = |m: u32| {
            std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let r = new_record();
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        let root = u.manifest().root_group_id();
        mode(0o500);
        let mut w = u.write().unwrap();
        let c = w.reserve_counter().unwrap();
        w.put_local(r, entry_version(root, "durable", w.writer_id(), c, &[]))
            .unwrap();
        assert_eq!(w.commit(), Err(StoreError::Io));
        // The change is durable; the session follows the database.
        assert_eq!(u.local_seq(), 2);
        assert!(u.manifest().record(r).is_some());
        // The next write retries the anchor first and refuses to start.
        assert_eq!(err(u.write()), StoreError::Io);
        mode(0o700);
        drop(u);
        // Reopening sees one commit past the anchor and advances it.
        let (u, status) = {
            let _k = crate::vault::tests::kdf();
            VaultFile::open(&p)
                .unwrap()
                .unlock_for_recovery(&crate::vault::tests::pw(PASSWORD), &dir)
                .unwrap()
        };
        assert_eq!(status, crate::head::AnchorStatus::Advanced);
        assert_eq!(u.local_seq(), 2);
        drop(u);
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        assert!(u.manifest().record(r).is_some());
        // Another failure, then a retry in the same session succeeds.
        mode(0o500);
        edit_expect_err(&mut u, r);
        mode(0o700);
        edit(&mut u, r, "after retry");
        assert_eq!(u.local_seq(), 4);
        drop(u);
        assert_eq!(unlock(&p, &dir, PASSWORD).unwrap().local_seq(), 4);
    }

    #[test]
    fn write_adopt_baseline_retries_pending_anchor() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        // `adopt_baseline` is a commit too: with an anchor update pending it
        // must retry the anchor first, or the DB gets two steps ahead.
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let anchor_dir = a.join("anchors");
        let mode = |m: u32| {
            std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        mode(0o500);
        edit_expect_err(&mut u, new_record());
        assert_eq!(u.adopt_baseline(), Err(StoreError::Io));
        assert_eq!(u.local_seq(), 2);
        mode(0o700);
        drop(u);
        assert_eq!(unlock(&p, &dir, PASSWORD).unwrap().local_seq(), 2);
    }

    fn edit_expect_err(u: &mut UnlockedVault, r: RecordId) {
        let root = u.manifest().root_group_id();
        let mut w = u.write().unwrap();
        let c = w.reserve_counter().unwrap();
        let heads = w.head_clocks(r);
        w.put_local(r, entry_version(root, "x", w.writer_id(), c, &heads))
            .unwrap();
        assert_eq!(w.commit(), Err(StoreError::Io));
    }

    #[test]
    fn write_prunes_dropped_references() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let r = new_record();
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        let first = edit(&mut u, r, "one");
        let second = edit(&mut u, r, "two");
        edit(&mut u, r, "three");
        assert_eq!(object_count(&u), 6);
        let dropped = u
            .manifest()
            .record(r)
            .unwrap()
            .version(first)
            .unwrap()
            .object_id();
        let kept = u
            .manifest()
            .record(r)
            .unwrap()
            .version(second)
            .unwrap()
            .object_id();
        let mut w = u.write().unwrap();
        w.drop_history(r, first).unwrap();
        w.commit().unwrap();
        assert_eq!(object_count(&u), 5);
        let exists = |id: ObjectId| -> bool {
            u.file
                .conn
                .query_row(
                    "SELECT count(*) FROM object WHERE object_id = ?1",
                    [id.to_bytes().as_slice()],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                == 1
        };
        assert!(!exists(dropped));
        assert!(exists(kept));
        drop(u);
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(u.manifest().record(r).unwrap().history().len(), 1);
        assert_eq!(err(u.read_version(r, first)), StoreError::NotFound);
    }

    #[test]
    fn write_final_tombstone_drops_history() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let r = new_record();
        let (versions, clocks, tomb_id);
        {
            let mut u = unlock(&p, &dir, PASSWORD).unwrap();
            versions = ["one", "two", "three", "four"].map(|t| edit(&mut u, r, t));
            let rec = u.manifest().record(r).unwrap();
            clocks = versions.map(|v| rec.version(v).unwrap().clock().clone());
            assert_eq!(rec.history().len(), 3);
            assert_eq!(object_count(&u), 7);
            let mut w = u.write().unwrap();
            let c = w.reserve_counter().unwrap();
            let heads = w.head_clocks(r);
            let tomb = RecordVersion {
                version_id: qv_model::VersionId::generate().unwrap(),
                clock: Clock::for_edit(&heads, w.writer_id(), c).unwrap(),
                modified_at: Timestamp(9),
                body: RecordBody::Tombstone(RecordKind::Entry),
                ext: Extensions::new(),
            };
            tomb_id = tomb.version_id;
            w.put_local(r, tomb).unwrap();
            w.commit().unwrap();
            // Four versions dropped, one tombstone added.
            assert_eq!(object_count(&u), 4);
        }
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        let rec = u.manifest().record(r).unwrap();
        assert_eq!(rec.heads().len(), 1);
        assert_eq!(rec.heads()[0].version_id(), tomb_id);
        assert!(rec.history().is_empty());
        let floor = rec.floor();
        for c in &clocks {
            assert!(floor.suppresses(c));
        }
        assert!(!floor.suppresses(rec.heads()[0].clock()));
        for v in versions {
            assert_eq!(err(u.read_version(r, v)), StoreError::NotFound);
        }
        assert_eq!(
            u.read_version(r, tomb_id).unwrap().deletion(),
            Deletion::Final
        );
    }

    #[test]
    fn write_final_tombstone_rules() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        let m = u.manifest().clone();
        let tomb = |w: &mut Write<'_>, record: RecordId, kind: RecordKind| {
            let c = w.reserve_counter().unwrap();
            let heads = w.head_clocks(record);
            RecordVersion {
                version_id: qv_model::VersionId::generate().unwrap(),
                clock: Clock::for_edit(&heads, w.writer_id(), c).unwrap(),
                modified_at: Timestamp(9),
                body: RecordBody::Tombstone(kind),
                ext: Extensions::new(),
            }
        };
        let cases = [
            (new_record(), RecordKind::Entry),
            (m.vault_meta_id(), RecordKind::VaultMeta),
            (m.keyslot_id(), RecordKind::PasswordKeyslot),
            (m.root_group_id(), RecordKind::Group),
        ];
        for (record, kind) in cases {
            let mut w = u.write().unwrap();
            let v = tomb(&mut w, record, kind);
            assert_eq!(w.put_local(record, v), Err(StoreError::InvalidEdit));
            drop(w);
            assert_eq!(u.local_seq(), 1);
            assert_eq!(object_count(&u), 3);
        }

        // An attachment with no chunks can be tombstoned.
        let entry = new_record();
        edit(&mut u, entry, "owner");
        let att = new_record();
        let mut w = u.write().unwrap();
        let c = w.reserve_counter().unwrap();
        let v = RecordVersion {
            version_id: qv_model::VersionId::generate().unwrap(),
            clock: Clock::for_edit(&[], w.writer_id(), c).unwrap(),
            modified_at: Timestamp(9),
            body: RecordBody::Live(Payload::AttachmentMeta(qv_model::AttachmentMeta {
                entry,
                name: Text::new("empty.txt").unwrap(),
                mime: Text::new("text/plain").unwrap(),
                size: 0,
                chunk_object_ids: Vec::new(),
                content_hash: [0; 32],
                ext: Extensions::new(),
            })),
            ext: Extensions::new(),
        };
        w.put_local(att, v).unwrap();
        w.commit().unwrap();
        let mut w = u.write().unwrap();
        let v = tomb(&mut w, att, RecordKind::AttachmentMeta);
        w.put_local(att, v).unwrap();
        w.commit().unwrap();
        drop(u);
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        let rec = u.manifest().record(att).unwrap();
        assert!(rec.history().is_empty());
        assert_eq!(u.record_kind(att), Some(RecordKind::AttachmentMeta));
    }

    #[test]
    fn write_manifest_debug_is_redacted() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        let m = u.manifest();
        let rec = &m.records()[0];
        assert_eq!(format!("{m:?}"), "Manifest(..)");
        assert_eq!(format!("{rec:?}"), "RecordEntry(..)");
        assert_eq!(format!("{:?}", rec.heads()[0]), "VersionRef(..)");
        assert_eq!(format!("{:?}", m.references()[0]), "ObjectRef(..)");
    }

    #[test]
    fn write_dropped_write_and_empty_commit() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        {
            let root = u.manifest().root_group_id();
            let mut w = u.write().unwrap();
            let c = w.reserve_counter().unwrap();
            w.put_local(
                new_record(),
                entry_version(root, "x", w.writer_id(), c, &[]),
            )
            .unwrap();
            assert_eq!(format!("{w:?}"), "Write(..)");
        }
        assert_eq!(u.local_seq(), 1);
        assert_eq!(object_count(&u), 3);
        // A commit with no edits still advances the head (used by
        // adopt_baseline).
        u.write().unwrap().commit().unwrap();
        assert_eq!(u.local_seq(), 2);
        drop(u);
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        assert_eq!(u.local_seq(), 2);
        assert_eq!(u.manifest().records().len(), 3);
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            // Each case runs Argon2id twice; a few sequences suffice to
            // exercise the edit rules against the reopened state.
            #![proptest_config(ProptestConfig::with_cases(6))]

            /// Random local edits over a few records keep the manifest
            /// valid, every record one head that dominates its history, and
            /// reopening yields the same manifest bytes.
            #[test]
            fn write_random_edits_round_trip(ops in proptest::collection::vec((0usize..4, 1usize..3), 1..8)) {
                let (d, a) = (TestDir::new(), TestDir::new());
                let (p, dir) = copy_fixture(&d, &a, "v.qvault");
                let records: Vec<RecordId> = (0..4).map(|_| new_record()).collect();
                let mut u = unlock(&p, &dir, PASSWORD).unwrap();
                let root = u.manifest().root_group_id();
                for (first, count) in &ops {
                    // `count` records per commit, starting at `first`.
                    let mut w = u.write().unwrap();
                    for k in 0..*count {
                        let r = records[(first + k) % records.len()];
                        let c = w.reserve_counter().unwrap();
                        let heads = w.head_clocks(r);
                        w.put_local(r, entry_version(root, "p", w.writer_id(), c, &heads)).unwrap();
                    }
                    w.commit().unwrap();
                }
                prop_assert_eq!(u.local_seq(), 1 + ops.len() as u64);
                let m = u.manifest().clone();
                m.validate().unwrap();
                for rec in m.records() {
                    prop_assert_eq!(rec.heads().len(), 1);
                    let head = rec.heads()[0].clock();
                    prop_assert!(rec.history().iter().all(|h| head.dominates(h.clock())));
                }
                let edits: usize = ops.iter().map(|(_, c)| c).sum();
                prop_assert_eq!(m.references().len(), 3 + edits);
                drop(u);
                let u = unlock(&p, &dir, PASSWORD).unwrap();
                prop_assert_eq!(u.manifest().encode().unwrap(), m.encode().unwrap());
            }
        }
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;
    use crate::{
        fs::test_dir::TestDir,
        vault::tests::{PASSWORD, copy_fixture, err, unlock},
    };
    use qv_model::{Extensions, Text, Timestamp, VersionId};
    fn version(w: &mut Write<'_>, r: RecordId, a: qv_model::AttachmentMeta) -> RecordVersion {
        let c = w.reserve_counter().unwrap();
        RecordVersion {
            version_id: VersionId::generate().unwrap(),
            clock: Clock::for_edit(&w.head_clocks(r), w.writer_id(), c).unwrap(),
            modified_at: Timestamp(1_700_000_000_000),
            body: RecordBody::Live(Payload::AttachmentMeta(a)),
            ext: Extensions::new(),
        }
    }
    fn count(u: &UnlockedVault) -> i64 {
        u.file
            .conn
            .query_row("SELECT count(*) FROM object", [], |r| r.get(0))
            .unwrap()
    }
    #[test]
    fn attachment_staging_errors_and_unconsumed_metadata_rollback() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        let initial = count(&u);
        let seq = u.local_seq();
        for mode in 0..4 {
            let r = RecordId::generate().unwrap();
            let entry = u.manifest().root_group_id();
            let mut w = u.write().unwrap();
            let staged = w
                .stage_attachment(r, &mut &vec![7; 65_537][..], &|| false)
                .unwrap();
            match mode {
                0 => {
                    assert_eq!(err(w.commit()), StoreError::Internal);
                }
                1 => {
                    let mut meta =
                        staged.into_meta(entry, Text::new("x").unwrap(), Text::new("x").unwrap());
                    meta.content_hash[0] ^= 1;
                    let v = version(&mut w, r, meta);
                    assert_eq!(err(w.put_local(r, v)), StoreError::InvalidEdit);
                    assert!(w.commit().is_err());
                }
                2 => {
                    struct Broken;
                    impl std::io::Read for Broken {
                        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                            Err(std::io::ErrorKind::Other.into())
                        }
                    }
                    assert!(
                        w.stage_attachment(RecordId::generate().unwrap(), &mut Broken, &|| false)
                            .is_err()
                    );
                    assert!(w.commit().is_err());
                }
                _ => {
                    assert!(
                        w.stage_attachment(RecordId::generate().unwrap(), &mut &b"x"[..], &|| true)
                            .is_err()
                    );
                    assert!(w.commit().is_err());
                }
            }
            assert_eq!(count(&u), initial);
            assert_eq!(u.local_seq(), seq);
        }
    }
    #[test]
    fn attachment_authenticated_wrong_hash_reorder_and_context_fail() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        for mode in 0..4 {
            let mut r = RecordId::generate().unwrap();
            let entry = u.manifest().root_group_id();
            let mut w = u.write().unwrap();
            let staged = w
                .stage_attachment(r, &mut &vec![9; 65_537][..], &|| false)
                .unwrap();
            let mut meta =
                staged.into_meta(entry, Text::new("x").unwrap(), Text::new("x").unwrap());
            if mode == 0 {
                meta.content_hash[0] ^= 1;
                w.staged.get_mut(&r).unwrap().hash.expose_secret_mut()[0] ^= 1;
            }
            if mode == 1 {
                meta.chunk_object_ids.reverse();
                w.staged.get_mut(&r).unwrap().chunks.reverse();
            }
            if mode == 2 {
                // A trusted fixture rebinding ciphertext to a different attachment ID.
                let other = RecordId::generate().unwrap();
                let tracked = w.staged.remove(&r).unwrap();
                w.staged.insert(other, tracked);
                r = other;
            }
            if mode == 3 {
                meta.size += 1;
                w.staged.get_mut(&r).unwrap().size += 1;
            }
            let v = version(&mut w, r, meta);
            let id = v.version_id;
            w.put_local(r, v).unwrap();
            w.commit().unwrap();
            assert_eq!(
                err(u.verify_attachment(r, id, &|| false)),
                StoreError::Integrity
            );
        }
    }
    #[test]
    fn attachment_ciphertext_mutations_and_reopen() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (p, dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        let r = RecordId::generate().unwrap();
        let entry = u.manifest().root_group_id();
        let mut w = u.write().unwrap();
        let staged = w
            .stage_attachment(r, &mut &vec![3; 65_537][..], &|| false)
            .unwrap();
        let meta = staged.into_meta(entry, Text::new("x").unwrap(), Text::new("x").unwrap());
        let chunks = meta.chunk_object_ids.clone();
        let v = version(&mut w, r, meta);
        let id = v.version_id;
        w.put_local(r, v).unwrap();
        w.commit().unwrap();
        u.verify_attachment(r, id, &|| false).unwrap();
        let sql = "SELECT ciphertext FROM object WHERE object_id=?1";
        let original: Vec<u8> = u
            .file
            .conn
            .query_row(sql, [chunks[0].to_bytes().as_slice()], |r| r.get(0))
            .unwrap();
        for mode in 0..3 {
            let mut bad = original.clone();
            match mode {
                0 => bad[30] ^= 1,
                1 => {
                    bad.pop();
                }
                _ => bad.push(0),
            };
            u.file
                .conn
                .execute(
                    "UPDATE object SET ciphertext=?1 WHERE object_id=?2",
                    rusqlite::params![bad, chunks[0].to_bytes().as_slice()],
                )
                .unwrap();
            assert_eq!(
                err(u.verify_attachment(r, id, &|| false)),
                StoreError::Integrity
            );
        }
        u.file
            .conn
            .execute(
                "UPDATE object SET ciphertext=?1 WHERE object_id=?2",
                rusqlite::params![original, chunks[0].to_bytes().as_slice()],
            )
            .unwrap();
        drop(u);
        let u = unlock(&p, &dir, PASSWORD).unwrap();
        u.verify_attachment(r, id, &|| false).unwrap();
        u.file
            .conn
            .execute(
                "DELETE FROM object WHERE object_id=?1",
                [chunks[0].to_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            err(u.verify_attachment(r, id, &|| false)),
            StoreError::Integrity
        );
    }
}

#[cfg(test)]
mod attachment_crash_tests {
    use super::*;
    use crate::{
        crash::test::{arm, disarm},
        fs::test_dir::TestDir,
        vault::tests::{PASSWORD, copy_fixture, unlock},
    };
    #[test]
    fn attachment_crash_at_staging_commit_and_anchor_boundaries() {
        use CrashPoint::*;
        for point in [
            Begun,
            ObjectsWritten,
            ManifestWritten,
            HeadWritten,
            Pruned,
            Committed,
            AnchorTempWritten,
            AnchorReplaced,
        ] {
            let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
            let (p, dir) = copy_fixture(&d, &a, "v.qvault");
            let r = RecordId::generate().unwrap();
            {
                let mut u = unlock(&p, &dir, PASSWORD).unwrap();
                let entry = u.manifest().root_group_id();
                arm(point, &p, &a.join("anchors"), s.path());
                let result = (|| -> Result<(), StoreError> {
                    let mut w = u.write()?;
                    let staged = w.stage_attachment(r, &mut &vec![5; 65_537][..], &|| false)?;
                    let meta = staged.into_meta(
                        entry,
                        qv_model::Text::new("x")?,
                        qv_model::Text::new("x")?,
                    );
                    let counter = w.reserve_counter()?;
                    w.put_local(
                        r,
                        RecordVersion {
                            version_id: qv_model::VersionId::generate()?,
                            clock: Clock::for_edit(&[], w.writer_id(), counter)?,
                            modified_at: qv_model::Timestamp(123),
                            body: RecordBody::Live(Payload::AttachmentMeta(meta)),
                            ext: qv_model::Extensions::new(),
                        },
                    )?;
                    w.commit()
                })();
                assert_eq!(result, Err(StoreError::Internal));
                assert!(!disarm(), "{point:?}");
            }
            let anchors = crate::AnchorDir::open(&s.join("anchors")).unwrap();
            let u = unlock(&s.join("v.qvault"), &anchors, PASSWORD).unwrap();
            let durable = matches!(point, Committed | AnchorTempWritten | AnchorReplaced);
            assert_eq!(u.manifest().record(r).is_some(), durable, "{point:?}");
            if durable {
                let v = u.manifest().record(r).unwrap().heads()[0].version_id();
                u.verify_attachment(r, v, &|| false).unwrap();
            }
        }
    }
}
