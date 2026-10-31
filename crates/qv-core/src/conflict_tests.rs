// SPDX-License-Identifier: AGPL-3.0-or-later

// Test-only fixture helpers fail loudly; no user secrets are used.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use crate::testutil::{Env, PASSWORD, TestDir, err, kdf, pw};
use crate::{FieldKind, FieldValue, ItemHandle, SnapshotKind};
use qv_store::{AnchorDir, ArchiveScope, VaultFile};

fn branch(env: &Env, s: &Session, name: &str) -> Session {
    let path = env.dir.path().join(format!("{name}.qvault"));
    s.read(|ctx| {
        let mut bytes = Vec::new();
        let now = ctx.now();
        ctx.open.vault.write_archive(&mut bytes, now, &|| false)?;
        let h = ctx.open.vault.header();
        VaultFile::create_from_archive(
            &path,
            &mut std::io::Cursor::new(bytes),
            ArchiveScope::new(h.vault_id, h.key_generation),
            ctx.open.vault.vault_key(),
            &AnchorDir::open(&env.anchors)?,
            &|| false,
        )?;
        Ok(())
    })
    .unwrap();
    let _k = kdf();
    env.core().unlock(&path, &pw(PASSWORD), None).unwrap()
}
fn export(s: &Session, dir: &TestDir) -> std::path::PathBuf {
    let r = s.export_archive(dir.path(), false, None).unwrap();
    dir.path().join(format!("{}.qvsnap", r.archive_id))
}
fn head(s: &Session, id: RecordId) -> VersionId {
    s.read(|ctx| Ok(ctx.open.index.get(id).unwrap().heads[0]))
        .unwrap()
}
fn edit(s: &Session, id: RecordId, f: impl FnOnce(&mut RecordVersion)) {
    s.mutate(|ctx| {
        let info = ctx.open.index.get(id).unwrap();
        let mut v = ctx.open.vault.read_version(id, info.single_head()?)?;
        f(&mut v);
        crate::edit::commit(
            ctx,
            vec![Change {
                record: id,
                kind: v.kind(),
                body: v.body,
                ext: v.ext,
            }],
        )
    })
    .unwrap();
}
fn handle(s: &Session, id: RecordId, version: VersionId) -> ConflictVersionHandle {
    let record = s.conflict_matches(&crate::setup::hex(&id.0)).unwrap()[0];
    s.conflict_versions(record)
        .unwrap()
        .into_iter()
        .find(|v| v.version == version)
        .unwrap()
}
fn one(s: &Session, id: RecordId) -> ConflictVersionHandle {
    handle(s, id, head(s, id))
}
fn add(s: &Session) -> crate::EntryHandle {
    let mut d = s.new_entry(s.root().unwrap(), "login", "original").unwrap();
    d.add_field(
        "password",
        FieldKind::Secret,
        FieldValue::text("protected-password-canary").unwrap(),
    )
    .unwrap();
    d.add_field(
        "OTP",
        FieldKind::Totp,
        FieldValue::text("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8")
            .unwrap(),
    )
    .unwrap();
    s.save_entry(d).unwrap()
}
fn raw_unknown(v: &RecordVersion) -> RecordVersion {
    use qv_encoding::{Decoder, Kind};
    fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        if n < 24 {
            out.push(major << 5 | n as u8);
        } else {
            assert!(n <= 255);
            out.extend([major << 5 | 24, n as u8]);
        }
    }
    fn copy(d: &mut Decoder<'_>, out: &mut Vec<u8>) {
        match d.peek_kind().unwrap() {
            Kind::Map => {
                let n = d.map().unwrap();
                head(out, 5, n + 1);
                for _ in 0..n {
                    let key = d.int().unwrap();
                    assert!((0..24).contains(&key));
                    out.push(key as u8);
                    copy(d, out);
                }
                out.extend([0x18, 100, 0x61, b'x']);
            }
            Kind::Array => {
                let n = d.array().unwrap();
                head(out, 4, n);
                for _ in 0..n {
                    copy(d, out);
                }
            }
            _ => out.extend_from_slice(d.raw_item().unwrap()),
        }
    }
    let encoded = v.encode().unwrap();
    let mut out = zeroize::Zeroizing::new(Vec::new());
    copy(&mut Decoder::new(&encoded).unwrap(), &mut out);
    RecordVersion::decode(&out).unwrap()
}

// 0012 §1: Order-dependent merges
// 0012 §1: Mixed credentials
#[test]
fn conflict_all_kinds_resolve_complete_versions_and_keep_unseen_edits() {
    let env = Env::new();
    let s = env.unlock_with(Some(env.snapshot_policy()));
    let entry = add(&s);
    let id = entry.record;
    edit(&s, id, |v| {
        *v = raw_unknown(v);
    });
    let data = vec![47; 70000];
    let attachment = s
        .add_attachment(
            entry,
            "payload.bin",
            "application/octet-stream",
            &mut data.as_slice(),
            None,
        )
        .unwrap();
    let aid = s
        .read(|ctx| {
            Ok(*ctx
                .open
                .index
                .records
                .iter()
                .find(|(_, r)| r.kind == RecordKind::AttachmentMeta)
                .unwrap()
                .0)
        })
        .unwrap();
    let remote = branch(&env, &s, "remote");
    let unseen = branch(&env, &s, "unseen");
    let (group, meta, slot) = s
        .read(|ctx| {
            Ok((
                ctx.open.vault.manifest().root_group_id(),
                ctx.open.vault.manifest().vault_meta_id(),
                ctx.open.vault.manifest().keyslot_id(),
            ))
        })
        .unwrap();
    for (session, label) in [(&s, "local"), (&remote, "remote")] {
        edit(session, id, |v| {
            if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
                e.title = Text::new(label).unwrap();
            }
        });
        edit(session, group, |v| {
            if let RecordBody::Live(Payload::Group(g)) = &mut v.body {
                g.name = Text::new(label).unwrap();
            }
        });
        edit(session, meta, |v| {
            if let RecordBody::Live(Payload::VaultMeta(m)) = &mut v.body {
                m.name = Text::new(label).unwrap();
                m.settings.history_depth = Some(7);
            }
        });
        session
            .resolve_version(&one(session, aid), None, None)
            .unwrap();
        let _k = kdf();
        session
            .change_password(
                &pw(if label == "local" {
                    "local changed password"
                } else {
                    "remote changed password"
                }),
                None,
            )
            .unwrap();
    }
    let remote_heads: Vec<_> = [id, group, meta, aid, slot]
        .into_iter()
        .map(|id| (id, head(&remote, id)))
        .collect();
    let dir = TestDir::new();
    let incoming = export(&remote, &dir);
    assert_eq!(
        s.merge_archive(&incoming, false, None).unwrap().conflicts,
        5
    );
    assert_eq!(s.conflict_records().unwrap().len(), 5);
    let h = handle(&s, id, remote_heads[0].1);
    let view = s.conflict_version(&h).unwrap();
    assert!(view.unknown_extensions);
    let ConflictDetails::Entry { detail, .. } = view.details else {
        panic!()
    };
    assert!(
        detail
            .fields
            .iter()
            .all(|f| !f.protected || f.value.is_none())
    );
    assert!(s.edit_entry(entry).is_err());
    for (id, version) in &remote_heads {
        let h = handle(&s, *id, *version);
        let before = s.overview().unwrap().local_seq;
        if *id == slot {
            let _k = kdf();
            assert_eq!(
                err(s.resolve_version(&h, Some(&pw("wrong selected password")), None)),
                CoreError::Store(qv_store::StoreError::WrongPassword)
            );
            assert_eq!(s.overview().unwrap().local_seq, before);
            s.resolve_version(&h, Some(&pw("remote changed password")), None)
                .unwrap();
        } else {
            s.resolve_version(&h, None, None).unwrap();
        }
        assert_eq!(s.overview().unwrap().local_seq, before + 1);
        assert_eq!(err(s.conflict_version(&h)), CoreError::StaleHandle);
    }
    assert!(s.conflict_records().unwrap().is_empty());
    let detail = s.entry(entry).unwrap();
    assert_eq!(detail.title.expose(), "remote");
    let secret = detail
        .fields
        .iter()
        .find(|f| f.name.expose() == "password")
        .unwrap();
    assert_eq!(
        s.reveal(secret.handle).unwrap().expose_secret(),
        b"protected-password-canary"
    );
    let otp = detail
        .fields
        .iter()
        .find(|f| f.name.expose() == "OTP")
        .unwrap();
    assert!(s.totp(otp.handle).is_ok());
    s.read(|ctx| {
        let v = ctx
            .open
            .vault
            .read_version(id, ctx.open.index.get(id).unwrap().heads[0])?;
        assert_eq!(v.ext.len(), 1);
        let old = ctx.open.vault.read_version(id, remote_heads[0].1)?;
        assert!(v.ext.content_eq(&old.ext));
        let RecordBody::Live(Payload::Entry(e)) = v.body else {
            panic!()
        };
        let RecordBody::Live(Payload::Entry(old)) = old.body else {
            panic!()
        };
        assert_eq!(e.ext.len(), 1);
        assert!(e.ext.content_eq(&old.ext));
        assert_eq!(e.fields.len(), old.fields.len());
        for (a, b) in e.fields.iter().zip(&old.fields) {
            assert_eq!(a.ext.len(), 1);
            assert!(a.ext.content_eq(&b.ext));
            assert_eq!(a.value.expose_secret(), b.value.expose_secret());
        }
        Ok(())
    })
    .unwrap();
    let attached = s.attachments(entry).unwrap();
    assert_eq!(attached.len(), 1);
    let mut copied = Vec::new();
    s.save_attachment(attached[0].handle, &mut copied, None)
        .unwrap();
    assert_eq!(copied, data);
    assert!(s.verify(None).unwrap().ok());
    let _ = attachment;
    s.lock();
    let reopened = {
        let _k = kdf();
        env.core_with(Some(env.snapshot_policy()))
            .unlock(&env.path, &pw("remote changed password"), None)
            .unwrap()
    };
    edit(&unseen, id, |v| {
        if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
            e.title = Text::new("unseen").unwrap();
        }
    });
    let unseen_file = export(&unseen, &dir);
    assert_eq!(
        reopened
            .merge_archive(&unseen_file, false, None)
            .unwrap()
            .conflicts,
        1
    );
    assert_eq!(err(reopened.conflict_version(&h)), CoreError::StaleHandle);
}

// 0012 §1: Deleted-entry resurrection
#[test]
fn conflict_final_entry_refuses_other_conflicts_and_finalizes_unseen_owned_attachments() {
    for attachment_conflict in [false, true] {
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let entry = add(&s);
        let id = entry.record;
        if attachment_conflict {
            s.add_attachment(entry, "existing", "x/test", &mut &[1, 2, 3][..], None)
                .unwrap();
        }
        let remote = branch(&env, &s, "remote");
        s.delete(ItemHandle::Entry(entry), false).unwrap();
        s.purge(&[ItemHandle::Entry(entry)]).unwrap();
        edit(&remote, id, |v| {
            if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
                e.title = Text::new("concurrent edit").unwrap();
            }
        });
        let remote_entry = remote.read(|ctx| Ok(ctx.entry_handle(id))).unwrap();
        if attachment_conflict {
            let aid = remote
                .read(|ctx| {
                    Ok(*ctx
                        .open
                        .index
                        .records
                        .iter()
                        .find(|(_, r)| r.kind == RecordKind::AttachmentMeta)
                        .unwrap()
                        .0)
                })
                .unwrap();
            remote
                .resolve_version(&one(&remote, aid), None, None)
                .unwrap();
        } else {
            remote
                .add_attachment(
                    remote_entry,
                    "new unseen",
                    "x/test",
                    &mut &[3, 2, 1][..],
                    None,
                )
                .unwrap();
        }
        let dir = TestDir::new();
        s.merge_archive(&export(&remote, &dir), false, None)
            .unwrap();
        let record = s.conflict_matches(&entry.id_hex()).unwrap()[0];
        let final_head = s
            .conflict_versions(record)
            .unwrap()
            .into_iter()
            .find(|h| s.conflict_version(h).unwrap().state == Deletion::Final)
            .unwrap();
        if attachment_conflict {
            assert_eq!(
                err(s.resolve_version(&final_head, None, None)),
                CoreError::Conflict
            );
            let a = s
                .conflict_records()
                .unwrap()
                .into_iter()
                .find(|r| r.kind == RecordKind::AttachmentMeta)
                .unwrap();
            let h = s
                .conflict_versions(a.handle)
                .unwrap()
                .into_iter()
                .find(|h| s.conflict_version(h).unwrap().state == Deletion::Final)
                .unwrap();
            s.resolve_version(&h, None, None).unwrap();
        }
        assert_eq!(
            s.resolve_version(&final_head, None, None)
                .unwrap()
                .conflicts,
            0
        );
        s.read(|ctx| {
            for r in ctx
                .open
                .index
                .records
                .values()
                .filter(|r| matches!(r.kind, RecordKind::Entry | RecordKind::AttachmentMeta))
            {
                assert!(r.status.finally_deleted);
            }
            Ok(())
        })
        .unwrap();
        assert!(s.verify(None).unwrap().ok());
    }
}

// 0012 §1: Mixed credentials
#[test]
fn conflict_slotless_snapshot_restores_working_slot_without_resolving_heads() {
    let env = Env::new();
    let s = env.unlock_with(Some(env.snapshot_policy()));
    let remote = branch(&env, &s, "remote");
    {
        let _k = kdf();
        s.change_password(&pw("local working password"), None)
            .unwrap();
        remote
            .change_password(&pw("remote slot password"), None)
            .unwrap();
    }
    let dir = TestDir::new();
    assert_eq!(
        s.merge_archive(&export(&remote, &dir), false, None)
            .unwrap()
            .conflicts,
        1
    );
    let copy = s.begin_destructive(false, None).unwrap();
    let snapshot = copy.summary().archive_id.clone();
    s.finish_destructive(copy).unwrap();
    let restored = env.dir.path().join("conflicted-restore.qvault");
    s.restore_snapshot(&snapshot, &restored, None).unwrap();
    let _k = kdf();
    let restored = env
        .core()
        .unlock(&restored, &pw("local working password"), None)
        .unwrap();
    assert_eq!(restored.overview().unwrap().conflicts, 1);
    assert!(restored.verify(None).unwrap().ok());
    assert!(
        s.snapshots()
            .unwrap()
            .snapshots
            .iter()
            .all(|r| r.kind == SnapshotKind::Ordinary)
    );
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn conflict_handles_reject_changes_and_lock_races_on_both_sides_of_commit() {
    use std::sync::{Arc, mpsc};
    for after in [false, true] {
        let env = Env::new();
        let s = Arc::new(env.unlock());
        let entry = add(&s);
        let id = entry.record;
        let stale = one(&s, id);
        edit(&s, id, |v| {
            if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
                e.title = Text::new("changed").unwrap();
            }
        });
        assert_eq!(
            err(s.resolve_version(&stale, None, None)),
            CoreError::StaleHandle
        );
        let h = one(&s, id);
        let before = s.overview().unwrap().local_seq;
        let (arrive_tx, arrive_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        let worker = {
            let s = s.clone();
            std::thread::spawn(move || {
                use crate::session::hooks::{self, Point};
                hooks::arm(
                    if after {
                        Point::AfterCommit
                    } else {
                        Point::BeforeCommit
                    },
                    arrive_tx,
                    go_rx,
                );
                s.resolve_version(&h, None, None)
            })
        };
        arrive_rx.recv().unwrap();
        let locker = {
            let s = s.clone();
            std::thread::spawn(move || s.lock())
        };
        while !s.is_locked() {
            std::thread::yield_now();
        }
        go_tx.send(()).unwrap();
        let result = worker.join().unwrap();
        if after {
            assert_eq!(result.unwrap().conflicts, 0);
        } else {
            assert_eq!(err(result), CoreError::Cancelled);
        }
        locker.join().unwrap();
        assert_eq!(
            env.unlock().overview().unwrap().local_seq,
            before + u64::from(after)
        );
    }
}

// 0012 §1: Old-date concurrent edits
#[test]
fn conflict_additional_head_invalidates_inspected_choice_even_when_selected_stays_active() {
    let env = Env::new();
    let s = env.unlock_with(Some(env.snapshot_policy()));
    let entry = add(&s);
    let id = entry.record;
    let r1 = branch(&env, &s, "remote1");
    let r2 = branch(&env, &s, "remote2");
    for (s, title) in [(&s, "local"), (&r1, "one"), (&r2, "two")] {
        edit(s, id, |v| {
            if let RecordBody::Live(Payload::Entry(e)) = &mut v.body {
                e.title = Text::new(title).unwrap();
            }
        });
    }
    let d = TestDir::new();
    s.merge_archive(&export(&r1, &d), false, None).unwrap();
    let h = handle(&s, id, head(&r1, id));
    s.merge_archive(&export(&r2, &d), false, None).unwrap();
    let seq = s.overview().unwrap().local_seq;
    assert_eq!(
        err(s.resolve_version(&h, None, None)),
        CoreError::StaleHandle
    );
    assert_eq!(s.overview().unwrap().local_seq, seq);
    let token = CancelToken::new();
    token.cancel();
    let h = handle(&s, id, head(&r1, id));
    assert_eq!(
        err(s.resolve_version(&h, None, Some(&token))),
        CoreError::Cancelled
    );
    assert_eq!(s.resolve_version(&h, None, None).unwrap().conflicts, 0);
}
