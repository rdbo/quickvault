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

use qv_core::{
    AnchorDir, Core, CoreConfig, FieldKind, FieldValue, GroupHandle, ItemHandle, MasterPassword,
    Session, Text,
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
    Core::new(CoreConfig::new(AnchorDir::open(anchors).unwrap()))
}

fn pw() -> MasterPassword {
    MasterPassword::from_utf8(b"an offline test password").unwrap()
}

/// Everything the views show, revealed values included, as text.
fn describe(s: &Session) -> Vec<String> {
    fn walk(s: &Session, g: GroupHandle, depth: usize, out: &mut Vec<String>) {
        let l = s.list(g).unwrap();
        for e in &l.entries {
            let d = s.entry(e.handle).unwrap();
            let mut line = format!(
                "{}entry {} [{}]",
                "  ".repeat(depth),
                d.title.expose(),
                d.type_hint.expose()
            );
            for f in &d.fields {
                let v = match &f.value {
                    Some(v) => String::from_utf8(v.expose_secret().to_vec()).unwrap(),
                    None => format!(
                        "<{}>",
                        String::from_utf8(s.reveal(f.handle).unwrap().expose_secret().to_vec())
                            .unwrap()
                    ),
                };
                line.push_str(&format!(" {}={}", f.name.expose(), v));
            }
            if let Some(n) = &d.notes {
                line.push_str(&format!(" notes={}", n.expose()));
            }
            out.push(line);
        }
        for c in &l.groups {
            out.push(format!("{}group {}", "  ".repeat(depth), c.name.expose()));
            walk(s, c.handle, depth + 1, out);
        }
    }
    let o = s.overview().unwrap();
    let mut out = vec![format!(
        "{} entries={} groups={} trash={} conflicts={}",
        o.name.expose(),
        o.entries,
        o.groups,
        o.in_trash,
        o.conflicts
    )];
    walk(s, s.root().unwrap(), 0, &mut out);
    let mut trash: Vec<String> = s
        .trash()
        .unwrap()
        .iter()
        .map(|t| format!("trash {}", t.name.expose()))
        .collect();
    trash.sort();
    out.extend(trash);
    out.extend(
        s.recovered()
            .unwrap()
            .iter()
            .map(|e| format!("recovered {}", e.title.expose())),
    );
    out
}

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
        s.purge(&[ItemHandle::Entry(tmp)]).unwrap();
        s.delete(ItemHandle::Group(old), true).unwrap();

        let mut st = s.edit_settings().unwrap();
        st.meta_mut().name = Text::new("Personal vault").unwrap();
        s.save_settings(st).unwrap();

        let hits = s.search("example.org").unwrap();
        assert_eq!(hits.len(), 1);
        assert!(s.search("s3cret").unwrap().is_empty());

        let state = describe(&s);
        s.lock();
        assert!(s.overview().is_err());
        state
    };
    assert_eq!(
        before,
        [
            "Personal vault entries=2 groups=2 trash=2 conflicts=0",
            "group Work",
            "  entry Mail (work) [login] Username=me@example.org Password=<s3cret> notes=recovery codes in the safe",
            "  entry Wifi [note] Key=<hunter22>",
            "group Home",
            "trash Legacy",
            "trash Old",
        ]
    );
    // A new process: another Core, the same anchors.
    let s = core(&anchors).unlock(&path, &pw(), None).unwrap();
    assert_eq!(describe(&s), before);
}
