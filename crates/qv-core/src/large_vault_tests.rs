// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stock-budget integration fixture; no patched limit or prebuilt plaintext index.
use crate::testutil::{Env, PASSWORD, TestDir, kdf, pw};
use crate::{CancelToken, FieldKind, FieldValue, PageLimit, SearchHit, Session, Text};
use std::time::Instant;
use zeroize::Zeroizing;

const ROWS: usize = 90;
const VALUE_BYTES: usize = 256 * 1024;
const SEARCH_BYTES: usize = ROWS * 3 * VALUE_BYTES;

fn resources(session: &Session, stage: &str) {
    session.read(|ctx| {
        let manifest=ctx.open.vault.manifest();
        eprintln!("large-vault {stage} counters: records={} heads={} objects={} referenced_ciphertext={} cache_text={} cache_query_text={}",
            manifest.records().len(),manifest.records().iter().map(|record|record.heads().len()).sum::<usize>(),
            manifest.references().len(),manifest.references().iter().map(|object|object.length()).sum::<u64>(),
            ctx.open.index.cache.bytes(),ctx.open.index.cache.total_bytes());
        Ok(())
    }).unwrap();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let metric = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        };
        eprintln!(
            "large-vault {stage} process memory KiB: rss={:?} hwm={:?}",
            metric("VmRSS:"),
            metric("VmHWM:")
        );
    }
}

fn check(session: &Session) {
    let cancel = CancelToken::new();
    let mut cursor = None;
    let mut count = 0;
    let mut page_count = 0;
    loop {
        let page = session
            .search_page("bulk", cursor, PageLimit::default(), &cancel)
            .unwrap();
        assert!(page.items.len() <= crate::MAX_PAGE_ROWS);
        for hit in page.items {
            let SearchHit::Entry(entry) = hit else {
                panic!("unexpected group")
            };
            assert!(entry.title.expose().starts_with("bulk"));
            assert_eq!(entry.fields.len(), 3);
            assert!(
                entry
                    .fields
                    .iter()
                    .all(|f| f.value.expose().len() == VALUE_BYTES)
            );
            count += 1;
        }
        page_count += 1;
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(count, ROWS);
    session
        .read(|ctx| {
            assert!(ctx.open.index.cache.total_bytes() <= crate::index::MAX_VIEW_BYTES);
            Ok(())
        })
        .unwrap();
    resources(session, "complete-search");
    eprintln!(
        "large-vault traversal: rows={count} pages={page_count} searchable_bytes={SEARCH_BYTES}"
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn enroll_large(source: &Session, phrase: Option<&qv_crypto::RecoveryPhrase>) {
    struct Offer;
    impl crate::ApproverUi for Offer {
        fn confirm(&mut self, _: &str, _: &str) -> bool {
            true
        }
        fn master_password(&mut self, _: bool) -> Option<qv_crypto::MasterPassword> {
            Some(pw(PASSWORD))
        }
    }
    struct Join(Option<crate::SecretBytes>);
    impl crate::JoinerUi for Join {
        fn show_code(&mut self, _: &crate::Sas) -> bool {
            true
        }
        fn confirm_vault(&mut self, _: &[u8], _: &crate::Sas) -> bool {
            true
        }
        fn master_password(&mut self) -> Option<qv_crypto::MasterPassword> {
            Some(pw(PASSWORD))
        }
        fn credentials(&mut self) -> Option<crate::EnrollmentCredential> {
            Some(match self.0.take() {
                Some(words) => crate::EnrollmentCredential::RecoveryPhrase(words),
                None => crate::EnrollmentCredential::Password(pw(PASSWORD)),
            })
        }
        fn confirm_recovered_vault(&mut self, _: &[u8]) -> bool {
            true
        }
    }
    let receiver = Env::empty(TestDir::new());
    let core = receiver.core();
    let dest = receiver.dir.path().join("lan-large.qvault");
    let window = source
        .open_sync_window(crate::SyncWindowOptions {
            scope: crate::ListenScope::LoopbackForTests,
            ..crate::SyncWindowOptions::default()
        })
        .unwrap();
    let code = window.code(&[]).unwrap();
    let manual = std::str::from_utf8(code.manual.expose_secret()).unwrap();
    let words = phrase.map(|phrase| {
        crate::SecretBytes::try_init(phrase.expose_secret().len(), |out| {
            out.copy_from_slice(phrase.expose_secret().as_bytes());
            Ok::<(), ()>(())
        })
        .unwrap()
    });
    let mut ui = Join(words);
    let start = Instant::now();
    let (served, joined) = std::thread::scope(|scope| {
        let h = scope.spawn(|| window.run(source, &mut Offer, None));
        let joined = core
            .join_new_device(
                crate::JoinCode::from_manual(manual).unwrap(),
                &dest,
                crate::SyncOptions {
                    extra_endpoints: vec![format!("127.0.0.1:{}", code.port).parse().unwrap()],
                    allow_loopback: true,
                    ..crate::SyncOptions::default()
                },
                &mut ui,
                None,
            )
            .unwrap();
        (h.join().unwrap().unwrap(), joined)
    });
    assert!(matches!(
        served,
        crate::Served::Joined {
            peer_confirmed: true,
            failure: None,
            ..
        }
    ));
    assert!(!joined.is_read_only().unwrap());
    assert_eq!(joined.overview().unwrap().entries, ROWS);
    check(&joined);
    joined.lock();
    assert_eq!(
        core.unlock(&dest, &pw(PASSWORD), None)
            .unwrap()
            .overview()
            .unwrap()
            .entries,
        ROWS
    );
    eprintln!(
        "large-vault LAN {} enrollment and reopen: {:?}",
        if phrase.is_some() { "key" } else { "password" },
        start.elapsed()
    );
}

#[cfg(target_os = "linux")]
fn quick_large(env: &Env) {
    let core = env
        .core()
        .with_linux_platform(crate::quick_unlock::synthetic_services(), true);
    let session = core.unlock(&env.path, &pw(PASSWORD), None).unwrap();
    session
        .enroll_quick(&pw(PASSWORD), qv_platform::QuickPolicy::Class3, None)
        .unwrap();
    session.lock();
    let start = Instant::now();
    let session = core.unlock_quick(&env.path, None).unwrap();
    assert_eq!(session.overview().unwrap().entries, ROWS);
    check(&session);
    session.lock();
    eprintln!(
        "large-vault synthetic quick open and complete search: {:?}",
        start.elapsed()
    );
}

// 0012 §1: Budget inconsistency
#[test]
fn large_vault_stock_budget_opens_edits_searches_restores_merges_and_rotates() {
    const {
        assert!(SEARCH_BYTES > crate::index::MAX_VIEW_BYTES);
    }
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    let start = Instant::now();
    let value = Zeroizing::new("x".repeat(VALUE_BYTES));
    let mut first = None;
    for i in 0..ROWS {
        let mut d = session
            .new_entry(root, "login", &format!("bulk {i:03}"))
            .unwrap();
        for name in ["Username", "Website text", "Other text"] {
            d.add_field(name, FieldKind::Text, FieldValue::text(&value).unwrap())
                .unwrap();
        }
        let h = session.save_entry(d).unwrap();
        first.get_or_insert(h);
    }
    eprintln!("large-vault author: {:?}", start.elapsed());
    assert_eq!(session.overview().unwrap().entries, ROWS);
    let mut d = session.edit_entry(first.unwrap()).unwrap();
    d.entry_mut().title = Text::new("bulk edited").unwrap();
    session.save_entry(d).unwrap();
    session.lock();
    let start = Instant::now();
    let session = env.unlock_with(Some(env.snapshot_policy()));
    eprintln!("large-vault password open: {:?}", start.elapsed());
    let start = Instant::now();
    check(&session);
    eprintln!("large-vault complete paged search: {:?}", start.elapsed());

    // Streamed archive export, mandatory recovery snapshot, and ordinary import.
    let dir = TestDir::new();
    let report = session.export_archive(dir.path(), false, None).unwrap();
    assert_eq!(report.completion_error, None);
    let archive = dir.path().join(format!("{}.qvsnap", report.archive_id));
    assert!(
        session
            .merge_archive(&archive, false, None)
            .unwrap()
            .accepted
    );
    assert_eq!(session.overview().unwrap().entries, ROWS);
    let snapshot = session.snapshots().unwrap().snapshots.remove(0);
    let restored = env.dir.path().join("restored.qvault");
    session
        .restore_snapshot(&snapshot.archive_id, &restored, None)
        .unwrap();
    let core = env.core();
    let restored_session = {
        let _k = kdf();
        core.unlock(&restored, &pw(PASSWORD), None).unwrap()
    };
    assert_eq!(restored_session.overview().unwrap().entries, ROWS);
    restored_session.lock();
    let phrase = {
        let _k = kdf();
        session.recovery_phrase(&pw(PASSWORD)).unwrap()
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        enroll_large(&session, None);
        enroll_large(&session, Some(&phrase));
    }
    session.lock();
    let (session, _) = core
        .unlock_with_phrase(&env.path, phrase.expose_secret().as_bytes(), None)
        .unwrap();
    assert_eq!(session.overview().unwrap().entries, ROWS);
    session.lock();

    #[cfg(target_os = "linux")]
    quick_large(&env);
    let session = env.unlock_with(Some(env.snapshot_policy()));
    let mut rotation = {
        let _k = kdf();
        session
            .begin_rotation(&pw("large vault replacement password"), false, None)
            .unwrap()
    };
    for i in [3, 11, 20] {
        let word = Zeroizing::new(rotation.phrase().expose_word(i).unwrap().to_owned());
        assert!(rotation.confirm_word(i, word.as_bytes()).unwrap());
    }
    rotation.install(None).unwrap();
    let session = {
        let _k = kdf();
        core.unlock(&env.path, &pw("large vault replacement password"), None)
            .unwrap()
    };
    assert_eq!(session.overview().unwrap().entries, ROWS);
    assert!(session.verify(None).unwrap().ok());
    check(&session);
    // The raw-document path must preserve the same cache-independent dataset
    // after rotation, not only generation-one or small archive fixtures.
    session.lock();
    let started = Instant::now();
    let mut input = std::fs::File::open(&env.path).unwrap();
    let pending = core.stage_vault_import(&mut input, None).unwrap();
    drop(input);
    let verified = {
        let _k = kdf();
        core.authenticate_vault_import(&pending, &pw("large vault replacement password"), None)
            .unwrap()
    };
    let imported = core
        .publish_vault_import(
            verified,
            &env.dir.path().join("imported-large.qvault"),
            None,
        )
        .unwrap();
    assert_eq!(imported.overview().unwrap().entries, ROWS);
    assert_eq!(imported.overview().unwrap().local_seq, 1);
    check(&imported);
    assert!(imported.verify(None).unwrap().ok());
    imported.lock();
    eprintln!(
        "large-vault explicit document import: {:?}",
        started.elapsed()
    );
}
