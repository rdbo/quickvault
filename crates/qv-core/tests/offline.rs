// SPDX-License-Identifier: AGPL-3.0-or-later

//! A full offline lifecycle through the public API only (0005 §0.1, 0012
//! *Implicit server prerequisite*, core level): there is no server, account
//! or network setting anywhere in `CoreConfig`.

#![cfg(any(target_os = "linux", target_os = "android"))]
// The helpers below are test code, but clippy's `allow-*-in-tests` settings
// only cover `#[test]` functions.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

mod common;

use common::describe;
use qv_core::{
    AnchorDir, Core, CoreConfig, FieldKind, FieldValue, ItemHandle, MasterPassword, Text,
};

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let mut name = String::from("qv-core-offline-");
        for b in std::process::id().to_be_bytes() {
            name.push_str(&format!("{b:02x}"));
        }
        let p = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&p);
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn core(anchors: &Path) -> Core {
    let snapshots = qv_core::SnapshotPolicy::new(
        qv_core::SnapshotDir::open(&anchors.with_file_name("snapshots")).unwrap(),
    );
    Core::new(CoreConfig::new(AnchorDir::open(anchors).unwrap()).with_snapshots(snapshots))
}

fn pw() -> MasterPassword {
    MasterPassword::from_utf8(b"an offline test password").unwrap()
}

// 0012 §1: Implicit server prerequisite
#[test]
fn offline_lifecycle() {
    let d = Dir::new();
    let path = d.0.join("personal.qvault");
    let anchors = d.0.join("anchors");
    let before = {
        let created = core(&anchors).create(&path, &pw(), "Personal").unwrap();
        assert_eq!(
            created.recovery_phrase.expose_secret().split(' ').count(),
            24
        );
        let s = created.session;
        let root = s.root().unwrap();

        let work = s.save_group(s.new_group(root, "Work").unwrap()).unwrap();
        let home = s.save_group(s.new_group(root, "Home").unwrap()).unwrap();
        let old = s.save_group(s.new_group(work, "Old").unwrap()).unwrap();

        let mut e = s.new_entry(work, "login", "Mail").unwrap();
        e.add_field(
            "Username",
            FieldKind::Text,
            FieldValue::text("me@example.org").unwrap(),
        )
        .unwrap();
        e.add_field(
            "Password",
            FieldKind::Secret,
            FieldValue::text("s3cret").unwrap(),
        )
        .unwrap();
        e.entry_mut().notes = Some(Text::new("recovery codes in the safe").unwrap());
        let mail = s.save_entry(e).unwrap();

        let mut e = s.new_entry(home, "note", "Wifi").unwrap();
        e.add_field(
            "Key",
            FieldKind::Secret,
            FieldValue::text("hunter22").unwrap(),
        )
        .unwrap();
        let wifi = s.save_entry(e).unwrap();

        let mut e = s.new_entry(old, "login", "Legacy").unwrap();
        e.add_field(
            "Password",
            FieldKind::Secret,
            FieldValue::text("1234").unwrap(),
        )
        .unwrap();
        s.save_entry(e).unwrap();
        let tmp = s
            .save_entry(s.new_entry(home, "login", "Temporary").unwrap())
            .unwrap();

        // Edit, move, delete, restore, purge.
        let mut e = s.edit_entry(mail).unwrap();
        e.entry_mut().title = Text::new("Mail (work)").unwrap();
        s.save_entry(e).unwrap();
        s.move_item(ItemHandle::Entry(wifi), work).unwrap();
        s.move_item(ItemHandle::Group(old), home).unwrap();
        s.delete(ItemHandle::Group(old), true).unwrap();
        s.restore(ItemHandle::Group(old)).unwrap();
        s.delete(ItemHandle::Entry(tmp), false).unwrap();
        let copy = s.begin_destructive(false, None).unwrap();
        s.purge(&[ItemHandle::Entry(tmp)], false).unwrap();
        s.finish_destructive(copy).unwrap();
        s.delete(ItemHandle::Group(old), true).unwrap();

        let mut st = s.edit_settings().unwrap();
        st.meta_mut().name = Text::new("Personal vault").unwrap();
        s.save_settings(st).unwrap();

        let hits = common::collect(|cursor| {
            s.search_page(
                "example.org",
                cursor,
                qv_core::PageLimit::default(),
                &qv_core::CancelToken::new(),
            )
        });
        assert_eq!(hits.len(), 1);
        assert!(
            common::collect(|cursor| s.search_page(
                "s3cret",
                cursor,
                qv_core::PageLimit::default(),
                &qv_core::CancelToken::new()
            ))
            .is_empty()
        );

        let state = describe(&s);
        s.lock();
        assert!(s.overview().is_err());
        state
    };
    assert_eq!(
        before,
        [
            "Personal vault entries=2 groups=2 trash=2 conflicts=0",
            // Groups by name (0004 §7.3, plan 0069).
            "group Home",
            "group Work",
            "  entry Mail (work) [login] Username=me@example.org Password=<s3cret> notes=recovery codes in the safe",
            "  entry Wifi [note] Key=<hunter22>",
            "trash Legacy",
            "trash Old",
        ]
    );
    // A new process: another Core, the same anchors.
    let s = core(&anchors).unlock(&path, &pw(), None).unwrap();
    assert_eq!(describe(&s), before);
}
