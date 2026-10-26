// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault ls` and `qvault search` end to end (vaults built with `qv-core`
//! in the test, the binary run through pipes with `--password-stdin`).

#![cfg(any(target_os = "linux", target_os = "android"))]
// The helpers are test code, but clippy's `allow-*-in-tests` settings only
// cover `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::{Home, Output, PASSWORD, arg, piped};
use qv_core::{EntryHandle, FieldKind, FieldValue, GroupHandle, ItemHandle, Session, Text};

const HOSTILE: &str = "\u{1b}]52;c;aGk=\u{7}evil\u{202e}txt\u{1b}[2J\u{9b}31m";
const HOSTILE_ESCAPED: &str = "\\x1b]52;c;aGk=\\x07evil\\u{202e}txt\\x1b[2J\\u{9b}31m";

fn group(s: &Session, parent: GroupHandle, name: &str) -> GroupHandle {
    let d = s.new_group(parent, name).unwrap();
    s.save_group(d).unwrap()
}

fn entry(
    s: &Session,
    g: GroupHandle,
    title: &str,
    fields: &[(&str, FieldKind, &str)],
) -> EntryHandle {
    let mut d = s.new_entry(g, "login", title).unwrap();
    for (name, kind, value) in fields {
        d.add_field(name, *kind, FieldValue::text(value).unwrap())
            .unwrap();
    }
    d.entry_mut().notes = Some(Text::new("xyzzy notes").unwrap());
    s.save_entry(d).unwrap()
}

struct Fixture {
    home: Home,
    recovered: EntryHandle,
    same: [GroupHandle; 2],
}

fn fixture() -> Fixture {
    let home = Home::new();
    let s = home.create();
    let root = s.root().unwrap();
    let work = group(&s, root, "Work");
    let _home_g = group(&s, root, "Home");
    let mail = group(&s, work, "Mail");
    entry(
        &s,
        work,
        "GitHub",
        &[
            ("Username", FieldKind::Text, "alice"),
            ("Password", FieldKind::Secret, "secret-value"),
            ("URL", FieldKind::Url, "https://github.com"),
        ],
    );
    entry(
        &s,
        mail,
        "Gmail",
        &[("Address", FieldKind::Email, "bob@example.org")],
    );
    entry(&s, root, "Loose", &[]);
    entry(&s, root, HOSTILE, &[("Username", FieldKind::Text, HOSTILE)]);
    let a = group(&s, root, "Same");
    let b = group(&s, root, "Same");
    // A recovered entry: its group is deleted, the entry restored alone.
    let temp = group(&s, root, "Temp");
    let recovered = entry(&s, temp, "Orphan", &[]);
    s.delete(ItemHandle::Group(temp), true).unwrap();
    s.restore(ItemHandle::Entry(recovered)).unwrap();
    drop(s);
    Fixture {
        home,
        recovered,
        same: [a, b],
    }
}

fn run(f: &Fixture, args: &[&str]) -> Output {
    let vault = arg(&f.home.vault());
    let mut all = vec!["--password-stdin", "-v", &vault];
    all.extend_from_slice(args);
    piped(f.home.qvault(all), format!("{PASSWORD}\n").as_bytes())
}

fn no_raw_controls(s: &str) {
    assert!(
        !s.chars()
            .any(|c| (c.is_control() && c != '\n') || c == '\u{202e}'),
        "{s:?}"
    );
}

#[test]
fn browse_ls() {
    let f = fixture();
    let out = run(&f, &["ls"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    no_raw_controls(&out.stdout);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(&lines[..4], ["Work/", "Home/", "Same/", "Same/"]);
    // Root entries by title (case-insensitive); the hostile one escaped.
    assert!(lines.contains(&"Loose"));
    assert!(lines.contains(&format!("{HOSTILE_ESCAPED}  {HOSTILE_ESCAPED}").as_str()));
    let rec = lines
        .iter()
        .position(|l| l.starts_with("Recovered items"))
        .unwrap();
    assert!(lines[rec + 1].starts_with(&format!("@{}  Orphan", &f.recovered.id_hex()[..12])));

    let out = run(&f, &["ls", "Work"]);
    assert_eq!(
        out.stdout,
        "Work/Mail/\nWork/GitHub  alice  https://github.com\n"
    );
    let out = run(&f, &["ls", "-r", "Work/"]);
    assert_eq!(
        out.stdout,
        "Work/Mail/\nWork/Mail/Gmail  bob@example.org\nWork/GitHub  alice  https://github.com\n"
    );
    assert_eq!(run(&f, &["ls", "Nope"]).code, 4);

    // Two groups named "Same": exit 5, both IDs listed.
    let out = run(&f, &["ls", "Same"]);
    assert_eq!(out.code, 5);
    for g in f.same {
        assert!(out.stderr.contains(&g.id_hex()), "{}", out.stderr);
    }
    let out = run(&f, &["ls", &format!("@{}", &f.same[1].id_hex()[..8])]);
    assert_eq!(out.code, 0, "{}", out.stderr);

    let out = run(&f, &["ls", "--json"]);
    assert_eq!(out.code, 0);
    no_raw_controls(&out.stdout);
    assert!(out.stdout.starts_with("{\"groups\":[{\"id\":\""));
    assert!(
        out.stdout
            .contains("\"title\":\"\\u001b]52;c;aGk=\\u0007evil\\u202etxt")
    );
    assert!(out.stdout.contains("\"recovered\":[{\"id\":\""));
    assert!(out.stdout.contains("\"path\":null,\"title\":\"Orphan\""));
    // Protected values and notes are never listed.
    assert!(!out.stdout.contains("secret-value"));
    assert!(!out.stdout.contains("xyzzy"));
}

#[test]
fn browse_search() {
    let f = fixture();
    let hits = |q: &str| run(&f, &["search", q]);
    assert_eq!(
        hits("git").stdout,
        "Work/GitHub  alice  https://github.com\n"
    );
    assert_eq!(
        hits("ALICE").stdout,
        "Work/GitHub  alice  https://github.com\n"
    );
    assert_eq!(
        hits("github.com").stdout,
        "Work/GitHub  alice  https://github.com\n"
    );
    assert_eq!(
        hits("mail").stdout,
        "Work/Mail/\nWork/Mail/Gmail  bob@example.org\n"
    );
    // Never protected values or notes.
    assert_eq!(hits("secret-value").stdout, "");
    assert_eq!(hits("xyzzy").stdout, "");
    let out = hits("evil");
    no_raw_controls(&out.stdout);
    assert!(out.stdout.contains(HOSTILE_ESCAPED));
    let out = run(&f, &["search", "--json", "gmail"]);
    assert!(
        out.stdout
            .starts_with("{\"hits\":[{\"kind\":\"entry\",\"entry\":{\"id\":")
    );
    // Bounds.
    assert_eq!(hits("").code, 2);
    assert_eq!(hits(&"x".repeat(1025)).code, 9);
    assert_eq!(hits(&"x".repeat(1024)).code, 0);
}
