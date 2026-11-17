// SPDX-License-Identifier: AGPL-3.0-or-later

//! The 1.0 golden vault and archive (spec 0015 §6, plan 0064): every later
//! build must open the committed files, show the same contents and leave
//! them byte for byte unchanged. They were made once by
//! `examples/golden_vault.rs`; never regenerate them.

#![cfg(any(target_os = "linux", target_os = "android", windows))]
#![allow(clippy::unwrap_used)]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

mod common;

use common::describe;
use qv_core::{AnchorDir, AnchorStatus, Core, CoreConfig, MasterPassword, SnapshotDir};

const PASSWORD: &[u8] = b"quickvault 1.0 golden vault, published test password";

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qv-store/tests/golden")
}

struct Dir(PathBuf);

impl Dir {
    /// A private copy of the golden vault and its anchor directory.
    fn new() -> Self {
        let mut name = String::from("qv-core-golden-");
        for b in std::process::id().to_be_bytes() {
            name.push_str(&format!("{b:02x}"));
        }
        let p = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&p);
        let private = |d: &Path| qv_core::create_private_dirs(d).unwrap();
        private(&p);
        private(&p.join("anchors"));
        let copy = |from: PathBuf, to: PathBuf| {
            std::fs::copy(from, &to).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600)).unwrap();
            #[cfg(windows)]
            qv_win::fs::chmod_like(&to, 0o600).unwrap();
        };
        copy(golden().join("1.0.qvault"), p.join("1.0.qvault"));
        for a in std::fs::read_dir(golden().join("anchors")).unwrap() {
            let a = a.unwrap();
            copy(a.path(), p.join("anchors").join(a.file_name()));
        }
        Self(p)
    }

    fn core(&self) -> Core {
        let snapshots =
            qv_core::SnapshotPolicy::new(SnapshotDir::open(&self.0.join("snapshots")).unwrap());
        Core::new(
            CoreConfig::new(AnchorDir::open(&self.0.join("anchors")).unwrap())
                .with_snapshots(snapshots),
        )
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sha256(p: &Path) -> [u8; 32] {
    qv_crypto::object_hash(qv_crypto::ObjectHashProfile::V1, &std::fs::read(p).unwrap()).0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// The committed files are the ones made for 1.0: their hashes are in the
/// golden README (review of plan 0064, finding 2).
#[test]
fn golden_files_are_the_1_0_files() {
    for (file, sha) in [
        (
            "1.0.qvault",
            "55969343745c5ec471aade44fce82773379f1e03739cdb7e2169482d60a2dc32",
        ),
        (
            "1.0.qvsnap",
            "2abb3ca769b334e1bac19b4fcfe57bdfc18aa02f75a60b199cb2399307cffe0d",
        ),
        (
            "anchors/dd99ac246edb5022eb6a57ab2690be42.anchor",
            "f76f4a5d314d11913c7230766cbc609c7715a8d98daa0f8be7bc3cd0a57fb57f",
        ),
    ] {
        assert_eq!(hex(&sha256(&golden().join(file))), sha, "{file}");
    }
    assert_eq!(
        std::fs::read_dir(golden().join("anchors")).unwrap().count(),
        1
    );
}

fn password() -> MasterPassword {
    MasterPassword::from_utf8(PASSWORD).unwrap()
}

// Groups are listed by name (0004 §7.3, plan 0069); the stored bytes and
// order keys are unchanged.
const CONTENTS: &[&str] = &[
    "Golden vault entries=4 groups=2 trash=2 conflicts=0",
    "group Home",
    "  entry Card [card] Cardholder=A. Holder Number=<4111111111111111> Expires=2030-01 CVV=<123>",
    "  entry Note [note] Text=line 1\nline 2",
    "group Work",
    "  entry Mail (work) [login] Username=me@example.invalid Password=<s3cret> \
     Website=https://mail.example.invalid Email=me@example.invalid \
     One-time code=<otpauth://totp/Mail?secret=JBSWY3DPEHPK3PXP> \
     notes=recovery codes in the safe",
    "  entry Wifi [wifi] Password=<hunter22>",
    "trash Legacy",
    "trash Old",
];

/// The attachment content `golden_vault` stored: 70,000 fixed bytes.
fn attachment() -> Vec<u8> {
    (0..70_000u32).map(|i| (i % 251) as u8).collect()
}

#[test]
fn golden_vault_and_archive_open_unchanged() {
    let d = Dir::new();
    let vault = d.0.join("1.0.qvault");
    let before = sha256(&vault);
    {
        let s = d.core().unlock(&vault, &password(), None).unwrap();
        let state = describe(&s);
        assert_eq!(state, CONTENTS, "contents:\n{}", state.join("\n"));
        let report = s.verify(None).unwrap();
        assert_eq!(report.anchor, AnchorStatus::Verified);
        let c = &report.counts;
        assert_eq!(
            (
                c.objects,
                c.records,
                c.active_heads,
                c.retained_versions,
                c.tombstones,
                c.suppressed_records,
                c.total_bytes
            ),
            (26, 13, 13, 11, 1, 1, 139_836)
        );

        let mail = common::collect(|cursor| {
            s.search_page(
                "Mail (work)",
                cursor,
                qv_core::PageLimit::default(),
                &qv_core::CancelToken::new(),
            )
        });
        let [qv_core::SearchHit::Entry(mail)] = mail.as_slice() else {
            panic!("one Mail entry expected");
        };
        // Field kinds and flags as stored (the contents above print values
        // only).
        let detail = s.entry(mail.handle).unwrap();
        let kinds: Vec<_> = detail
            .fields
            .iter()
            .map(|f| (f.name.expose().to_owned(), f.kind, f.protected))
            .collect();
        use qv_core::FieldKind::{Email, Secret, Text, Totp, Url};
        let expect = |n: &str, k, p| (n.to_owned(), k, p);
        assert_eq!(
            kinds,
            [
                expect("Username", Text, false),
                expect("Password", Secret, true),
                expect("Website", Url, false),
                expect("Email", Email, false),
                expect("One-time code", Totp, true),
            ]
        );
        // Two earlier titles, kept as history.
        assert_eq!(s.history(mail.handle).unwrap().len(), 2);
        let files = s.attachments(mail.handle).unwrap();
        let [file] = files.as_slice() else {
            panic!("one attachment expected");
        };
        assert_eq!(
            (file.name.expose(), file.mime.expose(), file.size),
            ("readme.txt", "text/plain", 70_000)
        );
        let expected = attachment();
        let mut content = Vec::new();
        while content.len() < expected.len() {
            let length = (expected.len() - content.len()).min(65_536);
            let part = s
                .attachment_range(file.handle, content.len() as u64, length, None)
                .unwrap();
            assert!(!part.expose_secret().is_empty());
            content.extend_from_slice(part.expose_secret());
        }
        assert_eq!(content, expected);
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 1);
        s.lock();
    }
    assert_eq!(sha256(&vault), before, "opening rewrote the golden vault");

    // The archive authenticates and merges into the vault it came from,
    // changing nothing visible.
    let s = d.core().unlock(&vault, &password(), None).unwrap();
    let merged = s.merge_archive(&golden().join("1.0.qvsnap"), None).unwrap();
    assert!(merged.completion_error.is_none());
    assert_eq!(merged.conflicts, 0);
    assert_eq!(describe(&s), CONTENTS);
}
