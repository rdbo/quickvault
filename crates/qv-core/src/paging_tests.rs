// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete-result, hostile-cursor and bounded-memory paging regressions.
use super::*;
use crate::testutil::{Env, add_entry, add_group, err};

fn hit_id(hit: &SearchHit) -> String {
    match hit {
        SearchHit::Group(g) => g.handle.id_hex(),
        SearchHit::Entry(e) => e.handle.id_hex(),
    }
}
fn limit(rows: usize) -> PageLimit {
    PageLimit::new(rows, MAX_PAGE_TEXT_BYTES).unwrap()
}
fn tiny_cache(session: &Session) {
    session
        .read(|ctx| {
            ctx.open.index = crate::index::Index::build(&ctx.open.vault, &|| false, 1)?;
            Ok(())
        })
        .unwrap();
}

// 0012 §1: Budget inconsistency
#[test]
fn paging_complete_order_matches_eager_reference_with_an_uncacheable_row() {
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    for name in ["zeta", "ALPHA", "İstanbul"] {
        add_group(&session, root, name);
    }
    for i in 0..45 {
        add_entry(&session, root, &format!("item {}", i % 8));
    }
    tiny_cache(&session);
    let expected = session.list(root).unwrap();
    let expected: Vec<_> = expected
        .groups
        .iter()
        .map(|g| g.handle.id_hex())
        .chain(expected.entries.iter().map(|e| e.handle.id_hex()))
        .collect();
    let mut cursor = None;
    let mut actual = Vec::new();
    loop {
        let page = session
            .list_page(root, cursor, limit(7), &CancelToken::new())
            .unwrap();
        assert!(page.items.len() <= 7);
        actual.extend(page.items.iter().map(hit_id));
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(actual, expected);
    let expected: Vec<_> = session.search("i").unwrap().iter().map(hit_id).collect();
    let mut cursor = None;
    let mut actual = Vec::new();
    loop {
        let page = session
            .search_page("i", cursor, limit(3), &CancelToken::new())
            .unwrap();
        actual.extend(page.items.iter().map(hit_id));
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(actual, expected);
    session
        .read(|ctx| {
            assert!(ctx.open.index.bytes() <= 1);
            assert!(ctx.open.index.cache.total_bytes() <= crate::index::MAX_VIEW_BYTES);
            Ok(())
        })
        .unwrap();
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn paging_rejects_query_scope_revision_and_session_substitution() {
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    for title in ["first", "second", "third"] {
        add_entry(&session, root, title);
    }
    let cancel = CancelToken::new();
    let page = session.search_page("i", None, limit(1), &cancel).unwrap();
    let cursor = page.next.unwrap();
    assert_eq!(format!("{cursor:?}"), "ViewCursor(<redacted>)");
    assert_eq!(
        err(session.search_page("e", Some(cursor), limit(1), &cancel)),
        CoreError::StaleHandle
    );
    let cursor = session
        .all_items_page(None, limit(1), &cancel)
        .unwrap()
        .next
        .unwrap();
    assert_eq!(
        err(session.list_page(root, Some(cursor), limit(1), &cancel)),
        CoreError::StaleHandle
    );
    let cursor = session
        .all_items_page(None, limit(1), &cancel)
        .unwrap()
        .next
        .unwrap();
    add_entry(&session, root, "new edit");
    assert_eq!(
        err(session.all_items_page(Some(cursor), limit(1), &cancel)),
        CoreError::StaleHandle
    );
    let cursor = session
        .all_items_page(None, limit(1), &cancel)
        .unwrap()
        .next
        .unwrap();
    drop(session);
    let other = env.unlock();
    assert_eq!(
        err(other.all_items_page(Some(cursor), limit(1), &cancel)),
        CoreError::StaleHandle
    );
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn paging_cancellation_and_search_exclusions_preserve_secret_boundary() {
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    add_entry(&session, root, "İstanbul");
    let cancel = CancelToken::new();
    for query in ["hunter2", "xyzzy", "memo text"] {
        assert!(
            session
                .search_page(query, None, limit(1), &cancel)
                .unwrap()
                .items
                .is_empty()
        );
    }
    assert_eq!(
        session
            .search_page("i\u{307}", None, limit(1), &cancel)
            .unwrap()
            .items
            .len(),
        1
    );
    cancel.cancel();
    assert_eq!(
        err(session.all_items_page(None, limit(1), &cancel)),
        CoreError::Cancelled
    );
    session.lock();
    assert_eq!(
        err(session.all_items_page(None, limit(1), &CancelToken::new())),
        CoreError::SessionLocked
    );
}

// 0012 §1: Budget inconsistency
#[test]
fn paging_text_bound_never_truncates_a_valid_row_or_loses_continuation() {
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    let title = "x".repeat(240 * 1024);
    let field = "v".repeat(240 * 1024);
    for i in 0..4 {
        let mut draft = session
            .new_entry(root, "login", &format!("{i}{title}"))
            .unwrap();
        for name in ["a", "b"] {
            draft
                .add_field(
                    name,
                    qv_model::FieldKind::Text,
                    qv_model::FieldValue::text(&field).unwrap(),
                )
                .unwrap();
        }
        session.save_entry(draft).unwrap();
    }
    tiny_cache(&session);
    let mut cursor = None;
    let mut count = 0;
    loop {
        let page = session
            .all_items_page(cursor, PageLimit::default(), &CancelToken::new())
            .unwrap();
        let mut bytes = 0;
        for row in &page.items {
            assert_eq!(row.title.expose().len(), title.len() + 1);
            assert_eq!(row.fields.len(), 2);
            for value in &row.fields {
                assert_eq!(value.value.expose(), field);
            }
            bytes += row.title.allocated_bytes()
                + row.type_hint.allocated_bytes()
                + row.type_key.capacity()
                + row
                    .fields
                    .iter()
                    .map(|f| f.name.allocated_bytes() + f.value.allocated_bytes())
                    .sum::<usize>();
        }
        assert!(bytes <= MAX_PAGE_TEXT_BYTES);
        assert!(page.items.len() <= 2);
        count += page.items.len();
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(count, 4);
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn paging_releases_session_between_batches_and_rejects_a_concurrent_edit() {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    let env = Env::new();
    let session = Arc::new(env.unlock());
    let root = session.root().unwrap();
    for i in 0..30 {
        add_entry(&session, root, &format!("entry {i}"));
    }
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let worker = {
        let session = Arc::clone(&session);
        std::thread::spawn(move || {
            crate::session::hooks::arm(crate::session::hooks::Point::PageBatch, arrived_tx, go_rx);
            session.all_items_page(None, limit(5), &CancelToken::new())
        })
    };
    arrived_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let editor = {
        let session = Arc::clone(&session);
        std::thread::spawn(move || {
            add_group(&session, root, "concurrent edit");
            done_tx.send(()).unwrap();
        })
    };
    let free = done_rx.recv_timeout(Duration::from_secs(10)).is_ok();
    go_tx.send(()).unwrap();
    editor.join().unwrap();
    assert!(free, "page held the session mutex between batches");
    assert_eq!(err(worker.join().unwrap()), CoreError::StaleHandle);
}

// 0012 §1: Budget inconsistency
#[test]
fn paging_type_counts_are_complete_and_group_counts_use_structural_descendants() {
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    let parent = add_group(&session, root, "parent");
    let child = add_group(&session, parent, "child");
    let types: Vec<_> = ["wifi", "login", "note", "card"]
        .into_iter()
        .map(str::to_owned)
        .chain((0..11).map(|i| format!("custom{i:02}")))
        .chain([String::new()])
        .collect();
    for kind in &types {
        for group in [root, child] {
            let draft = session.new_entry(group, kind, "same title").unwrap();
            session.save_entry(draft).unwrap();
        }
    }
    tiny_cache(&session);
    let mut kinds = Vec::new();
    let mut cursor = None;
    loop {
        let page = session
            .kinds_page(cursor, limit(3), &CancelToken::new())
            .unwrap();
        assert!(page.items.len() <= 3);
        for kind in page.items {
            kinds.push((kind.kind.to_string(), kind.count));
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    // Unknown and empty hints share the Other bucket (0003 §5.1).
    let expected: Vec<_> = [
        ("login", 2),
        ("note", 2),
        ("card", 2),
        ("wifi", 2),
        ("other", 24),
    ]
    .into_iter()
    .map(|(k, n)| (k.to_owned(), n))
    .collect();
    assert_eq!(kinds, expected);
    for (kind, count) in &expected {
        let page = session
            .items_page(
                ItemFilter {
                    kind: Some(kind),
                    ..ItemFilter::default()
                },
                None,
                PageLimit::default(),
                &CancelToken::new(),
            )
            .unwrap();
        assert_eq!(page.items.len(), *count, "{kind}");
        assert!(
            page.items
                .iter()
                .all(|e| type_bucket(&e.type_hint.expose().to_lowercase()) == kind)
        );
    }
    let groups = session
        .groups_page(Some(root), "", None, limit(3), &CancelToken::new())
        .unwrap();
    assert_eq!(groups.items.len(), 1);
    assert_eq!(groups.items[0].entries, types.len());
    let children = session
        .groups_page(Some(parent), "", None, limit(3), &CancelToken::new())
        .unwrap();
    assert_eq!(children.items[0].entries, types.len());
    let entries = session
        .items_page(
            ItemFilter {
                group: Some(parent),
                ..ItemFilter::default()
            },
            None,
            PageLimit::default(),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(entries.items.len(), types.len());
    assert_eq!(session.overview().unwrap().entries, 2 * types.len());
}

// 0012 §1: Budget inconsistency
#[test]
fn paging_backward_cursor_returns_adjacent_rows_without_a_history_cache() {
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    for i in 0..25 {
        add_entry(&session, root, &format!("row {i:02}"));
    }
    tiny_cache(&session);
    let cancel = CancelToken::new();
    let first = session.all_items_page(None, limit(7), &cancel).unwrap();
    assert!(first.previous.is_none());
    let expected: Vec<_> = first.items.iter().map(|v| v.handle.id_hex()).collect();
    let second = session
        .all_items_page(first.next.clone(), limit(7), &cancel)
        .unwrap();
    let third = session
        .all_items_page(second.next.clone(), limit(7), &cancel)
        .unwrap();
    let back_to_second = session
        .all_items_page(third.previous, limit(7), &cancel)
        .unwrap();
    assert_eq!(
        back_to_second
            .items
            .iter()
            .map(|v| v.handle.id_hex())
            .collect::<Vec<_>>(),
        second
            .items
            .iter()
            .map(|v| v.handle.id_hex())
            .collect::<Vec<_>>()
    );
    let back_to_first = session
        .all_items_page(back_to_second.previous, limit(7), &cancel)
        .unwrap();
    assert_eq!(
        back_to_first
            .items
            .iter()
            .map(|v| v.handle.id_hex())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(back_to_first.previous.is_none());
    assert!(back_to_first.next.is_some());
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn paging_autofill_preserves_exact_identity_order_and_rejects_requester_substitution() {
    use crate::platform::autofill::{AppIdentity, PackageName, Requester, SignerSet};
    let env = Env::new();
    let session = env.unlock();
    let root = session.root().unwrap();
    let app = AppIdentity {
        package: PackageName::parse("com.example.bank").unwrap(),
        signers: SignerSet::new(&[[7; 32]]).unwrap(),
    };
    for title in ["z", "A", "a", "A", "İstanbul"] {
        let e = add_entry(&session, root, title);
        session.link_app(e, &app).unwrap();
    }
    // A look-alike title carries no matching URL identity.
    add_entry(&session, root, "com.example.bank");
    let requester = Requester::App(app.clone());
    let expected = session.autofill_candidates(&requester).unwrap();
    tiny_cache(&session);
    let cancel = CancelToken::new();
    let mut cursor = None;
    let mut actual = Vec::new();
    loop {
        let page = session
            .autofill_candidates_page(&requester, cursor, limit(2), &cancel)
            .unwrap();
        assert!(page.items.len() <= 2);
        actual.extend(page.items.into_iter().map(|c| (c.key(), c.title)));
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(actual.len(), 5);
    for ((key, title), reference) in actual.iter().zip(&expected) {
        assert_eq!(*key, reference.key());
        assert_eq!(title.expose(), reference.title.expose());
    }
    let cursor = session
        .autofill_candidates_page(&requester, None, limit(1), &cancel)
        .unwrap()
        .next
        .unwrap();
    let other = Requester::App(AppIdentity {
        signers: SignerSet::new(&[[8; 32]]).unwrap(),
        ..app
    });
    assert_eq!(
        err(session.autofill_candidates_page(&other, Some(cursor), limit(1), &cancel)),
        CoreError::StaleHandle
    );
    assert!(
        session
            .autofill_candidates_page(&other, None, limit(1), &cancel)
            .unwrap()
            .items
            .is_empty()
    );
    cancel.cancel();
    assert_eq!(
        err(session.autofill_candidates_page(&requester, None, limit(1), &cancel)),
        CoreError::Cancelled
    );
}

// 0012 §1: Ambiguous trust boundary
#[test]
fn paging_paths_stream_names_and_fail_if_the_snapshot_changes() {
    let env = Env::new();
    let s = env.unlock();
    let root = s.root().unwrap();
    let a = add_group(&s, root, "A/B");
    let b = add_group(&s, a, "C\\D");
    let e = add_entry(&s, b, "Entry");
    let revision = s.view_revision().unwrap();
    let mut path = s
        .item_path(crate::ItemHandle::Entry(e), revision)
        .unwrap()
        .unwrap();
    assert_eq!(s.path_next(&mut path).unwrap().unwrap().expose(), "A/B");
    assert_eq!(s.path_next(&mut path).unwrap().unwrap().expose(), "C\\D");
    assert_eq!(s.path_next(&mut path).unwrap().unwrap().expose(), "Entry");
    assert!(s.path_next(&mut path).unwrap().is_none());
    let mut root_path = s
        .item_path(crate::ItemHandle::Group(root), revision)
        .unwrap()
        .unwrap();
    assert!(s.path_next(&mut root_path).unwrap().is_none());
    add_entry(&s, root, "later");
    assert_eq!(err(s.path_next(&mut path)), CoreError::StaleHandle);
    assert_eq!(
        err(s.item_path(crate::ItemHandle::Entry(e), revision)),
        CoreError::StaleHandle
    );
    let foreign = Env::new().unlock();
    assert_eq!(err(foreign.path_next(&mut path)), CoreError::StaleHandle);
}
