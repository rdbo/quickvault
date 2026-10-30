// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use qv_crypto::{
    MacTag, PasswordKdfProfile, PasswordSlot, PasswordWrapProfile, SecretBytes, SlotId,
};
use qv_encoding::{Decoder, Encoder};
use qv_model::{
    Entry, Extensions, Group, Keyslot, RandomId, Settings, Text, Timestamp, VaultMeta, WriterId,
};

fn id(n: u32) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    bytes
}
fn rid(n: u32) -> RecordId {
    RecordId(id(n))
}
fn vid(n: u32) -> VersionId {
    VersionId::from_bytes(id(n)).unwrap()
}
fn clock(pairs: &[(u32, u64)]) -> Clock {
    Clock::from_pairs(
        pairs
            .iter()
            .map(|&(n, c)| (WriterId::from_bytes(id(n)).unwrap(), c))
            .collect(),
    )
    .unwrap()
}
fn version(n: u32, pairs: &[(u32, u64)], body: RecordBody) -> RecordVersion {
    RecordVersion {
        version_id: vid(n),
        clock: clock(pairs),
        modified_at: Timestamp(n as i64),
        body,
        ext: Extensions::new(),
    }
}
fn entry(n: u32, pairs: &[(u32, u64)], title: &str) -> RecordVersion {
    version(
        n,
        pairs,
        RecordBody::Live(Payload::Entry(Entry {
            group: rid(3),
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
    )
}
struct Record {
    id: RecordId,
    heads: Vec<RecordVersion>,
    history: Vec<RecordVersion>,
    floor: Clock,
}
fn record(heads: Vec<RecordVersion>) -> Record {
    Record {
        id: rid(4),
        heads,
        history: vec![],
        floor: Clock::new(),
    }
}
struct State {
    manifest: Manifest,
    versions: BTreeMap<(RecordId, VersionId), SecretBytes>,
}
fn controls() -> Vec<Record> {
    let bodies = [
        Payload::VaultMeta(VaultMeta {
            name: Text::new("test").unwrap(),
            description: None,
            root_group: rid(3),
            settings: Settings::default(),
            ext: Extensions::new(),
        }),
        Payload::PasswordKeyslot(Keyslot {
            slot: PasswordSlot {
                slot_id: SlotId(id(40)),
                kdf_profile: PasswordKdfProfile::V1,
                kdf_salt: [0; 32],
                wrap_profile: PasswordWrapProfile::V1,
                kek_commit: MacTag::from_bytes([0; 32]),
                nonce: [0; 24],
                wrapped_vk: [0; 48],
            },
            ext: Extensions::new(),
        }),
        Payload::Group(Group {
            parent: None,
            name: Text::new("root").unwrap(),
            notes: None,
            icon: None,
            order: Text::new("a").unwrap(),
            deleted_at: None,
            ext: Extensions::new(),
        }),
    ];
    bodies
        .into_iter()
        .enumerate()
        .map(|(i, body)| Record {
            id: rid(i as u32 + 1),
            heads: vec![version(
                i as u32 + 11,
                &[(1, i as u64 + 1)],
                RecordBody::Live(body),
            )],
            history: vec![],
            floor: Clock::new(),
        })
        .collect()
}

// Independent metadata fixture using the development manifest registry. These
// tests supply authenticated-role stand-ins; the real archive test below uses
// encryption and the production reader as well.
fn build(extra: Vec<Record>, salt: u8) -> State {
    let mut records = controls();
    records.extend(extra);
    records.sort_by_key(|r| r.id);
    let mut versions = BTreeMap::new();
    let mut refs = BTreeMap::new();
    let mut e = Encoder::new();
    e.map(|m| {
        m.entry(0, |e| {
            e.uint(qv_store::MANIFEST_FORMAT);
            Ok(())
        })?;
        m.entry(1, |e| {
            e.bytes(&[7; 32]);
            Ok(())
        })?;
        m.entry(2, |e| {
            e.array(|a| {
                for n in 1..=3 {
                    a.bytes(&id(n));
                }
                Ok(())
            })
        })?;
        m.entry(3, |e| {
            e.array(|a| {
                for r in &records {
                    a.array(|row| {
                        row.bytes(&r.id.0);
                        for list in [&r.heads, &r.history] {
                            row.array(|vs| {
                                let mut sorted: Vec<_> = list.iter().collect();
                                sorted.sort_by_key(|v| v.version_id);
                                for v in sorted {
                                    let mut object = v.version_id.to_bytes();
                                    object[0] = salt;
                                    refs.insert(object, (32, [salt; 32]));
                                    let mut encoded = v.encode().unwrap();
                                    versions.insert(
                                        (r.id, v.version_id),
                                        SecretBytes::take_from(&mut encoded),
                                    );
                                    vs.array(|x| {
                                        x.bytes(&v.version_id.to_bytes());
                                        v.clock.encode(x)?;
                                        x.bytes(&object);
                                        if let RecordBody::Live(Payload::AttachmentMeta(meta)) =
                                            &v.body
                                        {
                                            x.array(|chunks| {
                                                for chunk in &meta.chunk_object_ids {
                                                    chunks.bytes(&chunk.to_bytes());
                                                    refs.insert(
                                                        chunk.to_bytes(),
                                                        (
                                                            qv_crypto::sealed_len(
                                                                qv_model::CHUNK_SIZE as usize,
                                                            )
                                                            .unwrap()
                                                                as u64,
                                                            [salt; 32],
                                                        ),
                                                    );
                                                }
                                                Ok(())
                                            })?;
                                        }
                                        Ok(())
                                    })?;
                                }
                                Ok(())
                            })?;
                        }
                        r.floor.encode(row)?;
                        Ok(())
                    })?;
                }
                Ok(())
            })
        })?;
        m.entry(4, |e| {
            e.array(|a| {
                for (object, (length, hash)) in &refs {
                    a.array(|x| {
                        x.bytes(object);
                        x.uint(1);
                        x.uint(*length);
                        x.bytes(hash);
                        Ok(())
                    })?;
                }
                Ok(())
            })
        })?;
        Ok(())
    })
    .unwrap();
    let encoded = e.finish().unwrap();
    State {
        manifest: Manifest::decode(&encoded).unwrap(),
        versions,
    }
}
fn read(state: &State, record: RecordId, version: VersionId) -> Result<RecordVersion, StoreError> {
    Ok(RecordVersion::decode(
        state
            .versions
            .get(&(record, version))
            .ok_or(StoreError::NotFound)?
            .expose_secret(),
    )?)
}
fn combine(a: &State, b: &State) -> Candidate {
    merge(
        &a.manifest,
        &b.manifest,
        &mut |s, r, v| read(if s == Source::Local { a } else { b }, r, v),
        &|| false,
    )
    .unwrap()
}
fn state_of(candidate: Candidate, a: &State, b: &State) -> State {
    let mut versions = BTreeMap::new();
    for r in candidate.manifest().records() {
        for v in r.heads().iter().chain(r.history()) {
            let source = if candidate.source(v.object_id()) == Some(Source::Local) {
                a
            } else {
                b
            };
            let mut encoded = read(source, r.record_id(), v.version_id())
                .unwrap()
                .encode()
                .unwrap();
            versions.insert(
                (r.record_id(), v.version_id()),
                SecretBytes::take_from(&mut encoded),
            );
        }
    }
    State {
        manifest: candidate.manifest,
        versions,
    }
}
fn logical(state: &State) -> Vec<(RecordId, Vec<VersionId>, Vec<VersionId>, Clock)> {
    state
        .manifest
        .records()
        .iter()
        .map(|r| {
            (
                r.record_id(),
                r.heads().iter().map(VersionRef::version_id).collect(),
                r.history().iter().map(VersionRef::version_id).collect(),
                r.floor().clock().clone(),
            )
        })
        .collect()
}

// 0012 §1: Order-dependent merges
#[test]
fn permutations_regroupings_duplicates_and_reencrypted_identity_converge() {
    let states = [
        build(vec![record(vec![entry(100, &[(10, 1)], "old date")])], 0),
        build(vec![record(vec![entry(101, &[(20, 1)], "concurrent")])], 1),
        build(
            vec![record(vec![entry(102, &[(10, 2), (20, 1)], "covers both")])],
            2,
        ),
    ];
    let mut expected = None;
    for [a, b, c] in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let ab = state_of(combine(&states[a], &states[b]), &states[a], &states[b]);
        let left = state_of(combine(&ab, &states[c]), &ab, &states[c]);
        let bc = state_of(combine(&states[b], &states[c]), &states[b], &states[c]);
        let right = state_of(combine(&states[a], &bc), &states[a], &bc);
        assert_eq!(logical(&left), logical(&right));
        let duplicated = combine(&left, &left);
        assert_eq!(duplicated.manifest(), &left.manifest);
        if let Some(ref e) = expected {
            assert_eq!(&logical(&left), e);
        } else {
            expected = Some(logical(&left));
        }
    }
    // Same version/content under distinct object IDs: keep local envelopes.
    let same = build(vec![record(vec![entry(100, &[(10, 1)], "old date")])], 3);
    assert_eq!(combine(&states[0], &same).manifest(), &states[0].manifest);
}

// 0012 §1: Deleted-entry resurrection
#[test]
fn old_archive_cannot_revive_tombstone_or_suppressed_history() {
    let old = build(vec![record(vec![entry(100, &[(10, 1)], "years old")])], 0);
    let mut deleted = record(vec![version(
        102,
        &[(10, 3)],
        RecordBody::Tombstone(RecordKind::Entry),
    )]);
    deleted.floor = clock(&[(10, 2)]);
    let deleted = build(vec![deleted], 0);
    let merged = combine(&deleted, &old);
    let r = merged.manifest().record(rid(4)).unwrap();
    assert_eq!(r.heads()[0].version_id(), vid(102));
    assert!(r.history().is_empty());
    assert_eq!(r.floor().clock(), &clock(&[(10, 2)]));
    let concurrent = build(
        vec![record(vec![entry(103, &[(20, 1)], "unseen concurrent")])],
        1,
    );
    let mut all = state_of(merged, &deleted, &old);
    let conflicted = combine(&all, &concurrent);
    assert_eq!(
        conflicted.manifest().record(rid(4)).unwrap().heads().len(),
        2
    );
    assert_eq!(
        conflicted
            .manifest()
            .record(rid(4))
            .unwrap()
            .floor()
            .clock(),
        &clock(&[(10, 2)])
    );
    all = state_of(conflicted, &all, &concurrent);
    assert_eq!(combine(&all, &old).manifest(), &all.manifest);
}

#[test]
fn floors_join_and_never_hide_active_heads() {
    let mut a = record(vec![entry(100, &[(10, 2)], "active")]);
    a.history.push(entry(99, &[(10, 1)], "history"));
    let a = build(vec![a], 0);
    let mut b = record(vec![entry(101, &[(20, 1)], "concurrent")]);
    b.floor = clock(&[(10, 3)]);
    let b = build(vec![b], 1);
    let merged = combine(&a, &b);
    let r = merged.manifest().record(rid(4)).unwrap();
    assert_eq!(r.heads().len(), 2);
    assert!(r.history().is_empty());
    assert_eq!(r.floor().clock(), &clock(&[(10, 3)]));
    assert_eq!(
        combine(&b, &a).manifest().record(rid(4)).unwrap().heads(),
        r.heads()
    );
}

#[test]
fn identity_binding_and_limits_reject_without_changing_inputs() {
    let a = build(vec![record(vec![entry(100, &[(10, 1)], "one")])], 0);
    let before = a.manifest.encode().unwrap();
    for b in [
        build(vec![record(vec![entry(100, &[(10, 1)], "substituted")])], 1),
        build(
            vec![record(vec![entry(
                101,
                &[(10, 1)],
                "equal clock different id",
            )])],
            1,
        ),
        build(
            vec![record(vec![version(
                101,
                &[(20, 1)],
                RecordBody::Tombstone(RecordKind::Group),
            )])],
            1,
        ),
    ] {
        assert_eq!(
            merge(
                &a.manifest,
                &b.manifest,
                &mut |s, r, v| read(if s == Source::Local { &a } else { &b }, r, v),
                &|| false
            )
            .unwrap_err(),
            StoreError::Integrity
        );
    }
    let b = build(vec![record(vec![entry(100, &[(10, 1)], "one")])], 0);
    assert_eq!(
        merge(
            &a.manifest,
            &b.manifest,
            &mut |_, _, _| Ok(entry(999, &[(10, 1)], "wrong binding")),
            &|| false
        )
        .unwrap_err(),
        StoreError::Integrity
    );
    assert_eq!(
        merge(
            &a.manifest,
            &b.manifest,
            &mut |_, _, _| unreachable!(),
            &|| true
        )
        .unwrap_err(),
        StoreError::Io
    );
    // Each input fits 256 heads; the 257-head union must abort, never prune.
    let x = build(
        vec![record(
            (0..128)
                .map(|n| entry(1000 + n, &[(1000 + n, 1)], "x"))
                .collect(),
        )],
        0,
    );
    let y = build(
        vec![record(
            (128..257)
                .map(|n| entry(1000 + n, &[(1000 + n, 1)], "y"))
                .collect(),
        )],
        1,
    );
    assert_eq!(
        merge(
            &x.manifest,
            &y.manifest,
            &mut |s, r, v| read(if s == Source::Local { &x } else { &y }, r, v),
            &|| false
        )
        .unwrap_err(),
        StoreError::LimitExceeded
    );
    assert_eq!(a.manifest.encode().unwrap().as_slice(), before.as_slice());
}

#[test]
fn unknown_extensions_participate_in_complete_identity() {
    let a = build(vec![record(vec![entry(100, &[(10, 1)], "one")])], 0);
    let encoded = entry(100, &[(10, 1)], "one").encode().unwrap();
    let mut d = Decoder::new(&encoded).unwrap();
    let n = d.map().unwrap();
    let mut e = Encoder::new();
    e.map(|m| {
        for _ in 0..n {
            let key = d.int().unwrap();
            let raw = d.raw_value().unwrap();
            m.raw_entry(key, &raw)?;
        }
        m.entry(100, |e| {
            e.bool(true);
            Ok(())
        })?;
        Ok(())
    })
    .unwrap();
    let extended = RecordVersion::decode(&e.finish().unwrap()).unwrap();
    let b = build(vec![record(vec![extended])], 1);
    assert_eq!(
        merge(
            &a.manifest,
            &b.manifest,
            &mut |s, r, v| read(if s == Source::Local { &a } else { &b }, r, v),
            &|| false
        )
        .unwrap_err(),
        StoreError::Integrity
    );
    let only = build(vec![], 0);
    let candidate = combine(&only, &b);
    let version = candidate.manifest().record(rid(4)).unwrap().heads()[0].version_id();
    assert_eq!(version, vid(100));
    assert_eq!(
        candidate.source(
            ObjectId::from_bytes({
                let mut b = id(100);
                b[0] = 1;
                b
            })
            .unwrap()
        ),
        Some(Source::Incoming)
    );
}

#[test]
fn object_collisions_scope_and_cross_record_identity_reuse_are_errors() {
    let a = build(vec![record(vec![entry(100, &[(10, 1)], "one")])], 0);
    // Same object ID with a changed commitment must reject even if the
    // corresponding version would later be suppressed by a floor.
    let refs = a.manifest.references();
    let mut e = Encoder::new();
    let encoded = a.manifest.encode().unwrap();
    let mut d = Decoder::new(&encoded).unwrap();
    let n = d.map().unwrap();
    e.map(|m| {
        for _ in 0..n {
            let key = d.int().unwrap();
            if key == 4 {
                d.skip().unwrap();
                m.entry(4, |e| {
                    e.array(|a| {
                        for r in refs {
                            a.array(|x| {
                                x.bytes(&r.object_id().to_bytes());
                                x.uint(r.data_profile().id() as u64);
                                x.uint(r.length());
                                x.bytes(&[55; 32]);
                                Ok(())
                            })?;
                        }
                        Ok(())
                    })
                })?;
            } else {
                let raw = d.raw_value().unwrap();
                m.raw_entry(key, &raw)?;
            }
        }
        Ok(())
    })
    .unwrap();
    let collision = Manifest::decode(&e.finish().unwrap()).unwrap();
    assert_eq!(
        merge(
            &a.manifest,
            &collision,
            &mut |_, _, _| unreachable!(),
            &|| false
        )
        .unwrap_err(),
        StoreError::Integrity
    );
    let mut other = record(vec![entry(100, &[(10, 1)], "other record")]);
    other.id = rid(5);
    let b = build(vec![other], 1);
    assert_eq!(
        merge(
            &a.manifest,
            &b.manifest,
            &mut |_, _, _| unreachable!(),
            &|| false
        )
        .unwrap_err(),
        StoreError::Integrity
    );
    let mut bytes = a.manifest.encode().unwrap();
    let position = bytes.windows(32).position(|b| b == [7; 32]).unwrap();
    bytes[position] = 8;
    let foreign = Manifest::decode(&bytes).unwrap();
    assert_eq!(
        merge(
            &a.manifest,
            &foreign,
            &mut |_, _, _| unreachable!(),
            &|| false
        )
        .unwrap_err(),
        StoreError::Integrity
    );
}

#[test]
fn cancellation_during_role_scans_discards_the_candidate() {
    let a = build(vec![record(vec![entry(100, &[(10, 1)], "one")])], 0);
    let cancel = std::cell::Cell::new(false);
    let mut reads = 0;
    let result = merge(
        &a.manifest,
        &a.manifest,
        &mut |_, r, v| {
            reads += 1;
            cancel.set(true);
            read(&a, r, v)
        },
        &|| cancel.get(),
    );
    assert_eq!(result.unwrap_err(), StoreError::Io);
    assert_eq!(reads, 1);
}

#[test]
fn covered_dominated_permanent_tombstone_is_never_silently_forgotten() {
    let a = build(
        vec![record(vec![version(
            100,
            &[(10, 1)],
            RecordBody::Tombstone(RecordKind::Entry),
        )])],
        0,
    );
    let mut r = record(vec![entry(101, &[(10, 2)], "later")]);
    r.floor = clock(&[(10, 1)]);
    let b = build(vec![r], 1);
    assert_eq!(
        merge(
            &a.manifest,
            &b.manifest,
            &mut |s, r, v| read(if s == Source::Local { &a } else { &b }, r, v),
            &|| false
        )
        .unwrap_err(),
        StoreError::Integrity
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn authenticated_archive_and_real_store_build_a_nonmutating_candidate() {
    use qv_crypto::MasterPassword;
    use qv_store::{AnchorDir, ArchiveScope, VaultFile, VerifiedIncoming};
    use std::os::unix::fs::DirBuilderExt;
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Dir(std::env::temp_dir().join(format!(
        "qv-sync-{}",
        u64::from_be_bytes(qv_crypto::random_array().unwrap())
    )));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir.0)
        .unwrap();
    let private = dir.0.join("private");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .unwrap();
    let anchors = AnchorDir::open(&dir.0.join("anchors")).unwrap();
    let password = MasterPassword::from_utf8(b"test fixture password").unwrap();
    let mut u = VaultFile::create(&dir.0.join("v.qvault"), &password, "fixture", &anchors).unwrap();
    let root = u.manifest().root_group_id();
    let record = <RecordId as RandomId>::generate().unwrap();
    let put = |u: &mut qv_store::UnlockedVault, title: &str| {
        let mut w = u.write().unwrap();
        let counter = w.reserve_counter().unwrap();
        let mut v = entry(100, &[(10, 1)], title);
        v.version_id = VersionId::generate().unwrap();
        v.clock = Clock::for_edit(&w.head_clocks(record), w.writer_id(), counter).unwrap();
        if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
            e.group = root;
        }
        w.put_local(record, v).unwrap();
        w.commit().unwrap();
    };
    put(&mut u, "old");
    let source = dir.0.join("old.qvsnap");
    u.write_archive(
        std::fs::File::create(&source).unwrap(),
        Timestamp(1),
        &|| false,
    )
    .unwrap();
    put(&mut u, "current");
    let mut w = u.write().unwrap();
    w.purge_history(record).unwrap();
    w.commit().unwrap();
    let seq = u.local_seq();
    let before = u.manifest().encode().unwrap();
    let scope = ArchiveScope::new(u.header().vault_id, u.header().key_generation);
    let mut incoming =
        VerifiedIncoming::open(&source, &private, scope, u.vault_key(), &|| false).unwrap();
    let im = incoming.manifest().clone();
    let candidate = merge(
        u.manifest(),
        &im,
        &mut |s, r, v| match s {
            Source::Local => u.read_version(r, v),
            Source::Incoming => incoming.read_version(u.vault_key(), r, v),
        },
        &|| false,
    )
    .unwrap();
    assert_eq!(
        candidate.manifest().encode().unwrap().as_slice(),
        before.as_slice()
    );
    assert!(
        candidate
            .manifest()
            .record(record)
            .unwrap()
            .history()
            .is_empty()
    );
    for r in candidate.manifest().references() {
        assert_eq!(candidate.source(r.object_id()), Some(Source::Local));
    }
    assert_eq!(u.local_seq(), seq);
    assert_eq!(std::fs::read_dir(private).unwrap().count(), 0);
}

#[test]
fn attachments_keep_complete_chunk_references_and_reject_role_substitution() {
    let a = build(vec![record(vec![entry(100, &[(10, 1)], "owner")])], 0);
    let mut attachment = record(vec![version(
        200,
        &[(20, 1)],
        RecordBody::Live(Payload::AttachmentMeta(qv_model::AttachmentMeta {
            entry: rid(4),
            name: Text::new("untrusted.bin").unwrap(),
            mime: Text::new("application/octet-stream").unwrap(),
            size: 9,
            chunk_object_ids: vec![ObjectId::from_bytes(id(5000)).unwrap()],
            content_hash: [4; 32],
            ext: Extensions::new(),
        })),
    )]);
    attachment.id = rid(5);
    let b = build(
        vec![record(vec![entry(100, &[(10, 1)], "owner")]), attachment],
        1,
    );
    let candidate = combine(&a, &b);
    let chunk = ObjectId::from_bytes(id(5000)).unwrap();
    assert!(candidate.manifest().reference(chunk).is_some());
    assert_eq!(candidate.source(chunk), Some(Source::Incoming));
    assert_eq!(
        candidate.manifest().record(rid(5)).unwrap().heads()[0].chunks(),
        Some([chunk].as_slice())
    );
    assert_eq!(
        merge(
            &a.manifest,
            &b.manifest,
            &mut |s, r, v| {
                let mut decoded = read(if s == Source::Local { &a } else { &b }, r, v)?;
                if let RecordBody::Live(Payload::AttachmentMeta(meta)) = &mut decoded.body {
                    meta.chunk_object_ids[0] = ObjectId::from_bytes(id(5001)).unwrap();
                }
                Ok(decoded)
            },
            &|| false
        )
        .unwrap_err(),
        StoreError::Integrity
    );
}
