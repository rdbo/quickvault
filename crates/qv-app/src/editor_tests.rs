// SPDX-License-Identifier: AGPL-3.0-or-later

//! Headless item-editor tests (plan 0040 E1–E11) through the real controller
//! and core. All values are synthetic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crate::controller::AppError;
use crate::editor::{ItemType, same_slot};
use crate::views::{self, EntryFormView, Role};
use crate::workspace::{RevealKey, Screen, WsAction, WsField};
use crate::workspace_tests::{Env, KDF};
use qv_core::FieldKind;

const CARD: &str = "4242 4242 4242 4242";

fn lock() -> std::sync::MutexGuard<'static, ()> {
    KDF.lock().unwrap_or_else(|p| p.into_inner())
}
fn form(env: &Env) -> EntryFormView {
    env.c.entry_form(env.epoch()).expect("open entry form")
}
fn row(f: &EntryFormView, name: &str) -> u16 {
    f.rows
        .iter()
        .find(|r| same_slot(&r.name, name))
        .unwrap_or_else(|| panic!("row {name}"))
        .index
}
fn names(f: &EntryFormView) -> Vec<String> {
    f.rows.iter().map(|r| r.name.to_string()).collect()
}
fn start(env: &Env, typed: &str) {
    let root = env.read(|s| s.root());
    env.act(WsAction::NewEntry(root));
    assert!(form(env).start);
    env.put(WsField::Start, typed);
}
fn saved(env: &Env) -> qv_core::EntryHandle {
    env.act(WsAction::SaveEntry);
    assert_eq!(env.error(), None);
    match env.screen() {
        Screen::Entry(e) => e,
        other => panic!("saved entry screen, got {other:?}"),
    }
}
fn reveal(env: &Env, e: qv_core::EntryHandle, name: &str) -> Vec<u8> {
    let view = env.read(|s| views::entry(s, e));
    let f = view
        .fields
        .iter()
        .find(|f| same_slot(&f.name, name))
        .unwrap();
    env.read(|s| s.reveal(f.handle).map(|v| v.expose_secret().to_vec()))
}
/// Every text the form view would render, to check a card number never
/// reaches it.
fn rendered(f: &EntryFormView) -> String {
    let mut out = format!(
        "{}|{}|{}",
        f.title.as_str(),
        f.type_hint.as_str(),
        f.notes.as_str()
    );
    if let Some(g) = &f.guess {
        out += &format!("|{}|{}", g.line.as_str(), g.sub.as_str());
    }
    if let Some((t, from)) = &f.auto_title {
        out += &format!("|{}|{from}", t.as_str());
    }
    if let Some(c) = &f.card {
        out += &format!("|{:?}|{}|{}", c.info, c.name.as_str(), c.expiry.as_str());
    }
    for r in &f.rows {
        out += &format!(
            "|{}|{}",
            r.name.as_str(),
            r.value.as_deref().map_or("", |v| v.as_str())
        );
    }
    out
}

#[test]
fn a_pasted_card_number_becomes_a_protected_field_and_never_a_shown_value() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, CARD);
    let f = form(&env);
    let g = f.guess.as_ref().unwrap();
    assert_eq!(
        (g.kind, g.line.as_str()),
        (ItemType::Card, "Visa ending 4242")
    );
    assert!(!rendered(&f).contains("4242 4242") && !rendered(&f).contains("42424242"));
    env.act(WsAction::StartAs(None));
    let f = form(&env);
    assert!(!f.start && f.guess.is_none());
    assert_eq!(f.kind, Some(ItemType::Card));
    assert_eq!(
        names(&f),
        ["Name on card", "Card number", "Expires", "Security code"]
    );
    let number = &f.rows[usize::from(row(&f, "Card number"))];
    assert!(number.protected && number.replaced && number.filled && number.value.is_none());
    assert_eq!(number.role, Role::CardNumber);
    assert_eq!(f.rows[usize::from(row(&f, "Expires"))].role, Role::Expiry);
    let card = f.card.clone().unwrap();
    assert_eq!(card.info.last4.as_deref(), Some("4242"));
    assert_eq!(card.info.valid, Some(true));
    assert_eq!(
        f.auto_title.as_ref().map(|t| (t.0.as_str(), t.1)),
        Some(("Visa ••4242", "the card number"))
    );
    assert!(!rendered(&f).contains("42424242"));
    let e = saved(&env);
    let view = env.read(|s| views::entry(s, e));
    assert_eq!(view.title.as_str(), "Visa ••4242");
    assert_eq!(reveal(&env, e, "Card number"), b"4242424242424242");
    let face = env.read(|s| Ok(views::card_face(s, &view))).unwrap();
    assert_eq!(face.info.last4.as_deref(), Some("4242"));

    // Choosing another type drops the number instead of titling the item with it.
    start(&env, CARD);
    env.act(WsAction::StartAs(Some(ItemType::Login)));
    let f = form(&env);
    assert_eq!(f.title.as_str(), "");
    assert!(!rendered(&f).contains("4242"));
    assert!(f.rows.iter().all(|r| !r.replaced));
}

#[test]
fn sites_and_networks_fill_their_fields_and_title_the_item() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "https://www.github.com/login");
    env.act(WsAction::StartAs(None));
    let f = form(&env);
    assert_eq!(f.kind, Some(ItemType::Login));
    let site = &f.rows[usize::from(row(&f, "Website"))];
    assert_eq!(
        site.value.as_deref().map(String::as_str),
        Some("github.com")
    );
    let pw = row(&f, "Password");
    assert_eq!(f.rows[usize::from(pw)].role, Role::Password);
    env.put(WsField::Replacement(pw), "hunter2-synthetic");
    let e = saved(&env);
    assert_eq!(env.read(|s| views::entry(s, e)).title.as_str(), "GitHub");

    start(&env, "Home Wi-Fi");
    env.act(WsAction::StartAs(None));
    let f = form(&env);
    assert_eq!(f.kind, Some(ItemType::Wifi));
    assert_eq!(
        f.wifi
            .as_ref()
            .map(|w| (w.name.as_str(), w.security.as_str())),
        Some(("Home Wi-Fi", "WPA2"))
    );
    assert_eq!(
        f.rows[usize::from(row(&f, "Security"))].role,
        Role::Security
    );
    env.put(WsField::Replacement(row(&f, "Password")), "join;me");
    env.put(WsField::FieldValue(row(&f, "Security")), "WPA3");
    let e = saved(&env);
    assert_eq!(
        env.read(|s| views::entry(s, e)).title.as_str(),
        "Home Wi-Fi"
    );
    // The join code is a timed reveal of the payload.
    env.act(WsAction::Reveal(RevealKey::WifiJoin(e)));
    assert_eq!(env.error(), None);
    let payload = env
        .c
        .revealed(env.epoch(), &RevealKey::WifiJoin(e))
        .unwrap();
    assert_eq!(
        payload.expose_secret(),
        br"WIFI:T:WPA;S:Home Wi-Fi;P:join\;me;;"
    );
    assert!(crate::qr::encode(payload.expose_secret()).is_ok());
    env.act(WsAction::Hide);
    assert!(
        env.c
            .revealed(env.epoch(), &RevealKey::WifiJoin(e))
            .is_none()
    );

    // A name with no source for a title still needs one.
    start(&env, "");
    env.act(WsAction::StartAs(Some(ItemType::Other)));
    assert!(form(&env).rows.is_empty() && form(&env).auto_title.is_none());
    env.act(WsAction::SaveEntry);
    assert_eq!(env.error(), Some(AppError::NameRequired));
}

#[test]
fn changing_the_type_keeps_filled_fields_with_their_replacements() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "Bank");
    env.act(WsAction::StartAs(Some(ItemType::Login)));
    let f = form(&env);
    assert_eq!(f.title.as_str(), "Bank");
    env.put(WsField::FieldValue(row(&f, "Username")), "alice");
    env.put(WsField::Replacement(row(&f, "Password")), "kept-secret");
    env.act(WsAction::SetType(ItemType::Card));
    assert!(env.notice().is_some());
    let f = form(&env);
    assert_eq!(f.type_hint.as_str(), "card");
    // Template first, then the filled fields; the empty Website is dropped.
    assert_eq!(
        names(&f),
        [
            "Name on card",
            "Card number",
            "Expires",
            "Security code",
            "Username",
            "Password"
        ]
    );
    let pw = &f.rows[usize::from(row(&f, "Password"))];
    assert!(pw.replaced && pw.protected);
    assert!(!f.rows[usize::from(row(&f, "Card number"))].replaced);
    // Back to a login: the template reuses them by name.
    env.act(WsAction::SetType(ItemType::Login));
    let f = form(&env);
    assert_eq!(names(&f), ["Username", "Password", "Website"]);
    assert!(f.rows[1].replaced);
    let e = saved(&env);
    assert_eq!(reveal(&env, e, "Password"), b"kept-secret");
    assert_eq!(reveal(&env, e, "Username"), b"alice");
}

#[test]
fn moving_removing_and_undo_keep_replacements_on_their_fields() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "Shop");
    env.act(WsAction::StartAs(Some(ItemType::Login)));
    env.put(WsField::Replacement(1), "moved-secret");
    env.act(WsAction::MoveField(1, true));
    let f = form(&env);
    assert_eq!(names(&f), ["Password", "Username", "Website"]);
    assert!(f.rows[0].replaced && !f.rows[1].replaced);
    env.act(WsAction::MoveField(0, true));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.act(WsAction::MoveField(2, false));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.act(WsAction::RemoveField(0));
    let f = form(&env);
    assert_eq!(names(&f), ["Username", "Website"]);
    assert_eq!(f.removed.as_deref().map(String::as_str), Some("Password"));
    assert!(f.rows.iter().all(|r| !r.replaced));
    env.act(WsAction::UndoRemoveField);
    let f = form(&env);
    assert_eq!(names(&f), ["Password", "Username", "Website"]);
    assert!(f.rows[0].replaced && f.removed.is_none());
    env.act(WsAction::UndoRemoveField);
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    let e = saved(&env);
    assert_eq!(reveal(&env, e, "Password"), b"moved-secret");
}

#[test]
fn added_fields_take_the_kind_their_name_suggests() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "Server");
    env.act(WsAction::StartAs(Some(ItemType::Other)));
    env.put(WsField::NewFieldName, "PIN");
    assert_eq!(form(&env).new_kind, (FieldKind::Secret, true));
    env.act(WsAction::AddField(None));
    env.act(WsAction::AddNamedField("Recovery codes"));
    env.put(WsField::NewFieldName, "Two-factor code");
    env.act(WsAction::AddField(Some(FieldKind::Text)));
    env.act(WsAction::AddField(None));
    let f = form(&env);
    let kinds: Vec<(String, FieldKind, bool)> = f
        .rows
        .iter()
        .map(|r| (r.name.to_string(), r.kind, r.protected))
        .collect();
    assert_eq!(
        kinds,
        [
            ("PIN".into(), FieldKind::Secret, true),
            ("Recovery codes".into(), FieldKind::Multiline, true),
            ("Two-factor code".into(), FieldKind::Text, false),
            ("Text".into(), FieldKind::Text, false),
        ]
    );
    assert_eq!(f.rows[0].role, Role::Hidden);
}

#[test]
fn a_generated_value_moves_into_the_field_without_reaching_the_form() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "Forum");
    env.act(WsAction::StartAs(Some(ItemType::Login)));
    let pw = row(&form(&env), "Password");
    // Not a protected field: refused.
    env.act(WsAction::Generate);
    env.act(WsAction::UseGenerated(row(&form(&env), "Username")));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    env.act(WsAction::Dismiss);
    env.act(WsAction::Generate);
    let shown = env
        .c
        .generated(env.epoch())
        .unwrap()
        .0
        .expose_secret()
        .to_vec();
    env.act(WsAction::UseGenerated(pw));
    assert_eq!(env.error(), None);
    assert!(env.c.generated(env.epoch()).is_none());
    let f = form(&env);
    let r = &f.rows[usize::from(pw)];
    assert!(r.generated && r.replaced && r.value.is_none());
    let rendered = rendered(&f);
    assert!(!rendered.contains(std::str::from_utf8(&shown).unwrap()));
    // The 30 s reveal shows it on request; typing keeps a reveal current.
    env.act(WsAction::Reveal(RevealKey::Replacement(pw)));
    assert_eq!(
        env.c
            .revealed(env.epoch(), &RevealKey::Replacement(pw))
            .unwrap()
            .expose_secret(),
        shown.as_slice()
    );
    env.put(WsField::Replacement(pw), "typed-over");
    assert_eq!(form(&env).showing, Some(pw));
    assert_eq!(
        env.c
            .revealed(env.epoch(), &RevealKey::Replacement(pw))
            .unwrap()
            .expose_secret(),
        b"typed-over"
    );
    env.put(WsField::Replacement(pw), "");
    assert!(
        env.c
            .revealed(env.epoch(), &RevealKey::Replacement(pw))
            .is_none()
    );
    env.act(WsAction::Generate);
    let again = env
        .c
        .generated(env.epoch())
        .unwrap()
        .0
        .expose_secret()
        .to_vec();
    env.act(WsAction::UseGenerated(pw));
    let e = saved(&env);
    assert_eq!(reveal(&env, e, "Password"), again);

    // Editing shows only that a value is saved.
    env.act(WsAction::EditEntry(e));
    let f = form(&env);
    let r = &f.rows[usize::from(row(&f, "Password"))];
    assert!(r.stored && !r.replaced && r.value.is_none());
    assert!(!f.rows[usize::from(row(&f, "Username"))].stored);
}

#[test]
fn colours_and_groups_are_saved_with_the_item() {
    let _k = lock();
    let env = Env::unlocked();
    let root = env.read(|s| s.root());
    env.act(WsAction::NewGroup(root));
    env.put(WsField::GroupName, "Work");
    env.act(WsAction::SetHue(Some(5)));
    assert_eq!(env.c.group_form(env.epoch()).unwrap().colour, Some(5));
    env.act(WsAction::SaveGroup);
    let work = env.read(views::top_groups);
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].colour, Some(5));
    let work = work[0].handle;

    start(&env, "Payroll");
    env.act(WsAction::StartAs(Some(ItemType::Login)));
    assert_eq!(form(&env).group, root);
    env.act(WsAction::SetGroup(work));
    env.act(WsAction::SetHue(Some(3)));
    env.act(WsAction::SetHue(Some(12)));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
    assert_eq!(form(&env).colour, Some(3));
    let e = saved(&env);
    let listed = env.read(|s| views::browse(s, Some(work)));
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].colour, Some(3));
    assert_eq!(env.read(|s| views::entry(s, e)).colour, Some(3));
    env.act(WsAction::EditEntry(e));
    env.act(WsAction::SetHue(None));
    assert_eq!(form(&env).colour, None);
    saved(&env);
    assert_eq!(env.read(|s| views::entry(s, e)).colour, None);
}
