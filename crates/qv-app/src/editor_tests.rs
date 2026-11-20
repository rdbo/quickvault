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

#[test]
fn display_escaping_does_not_change_editor_values_or_saved_content() {
    let _k = lock();
    let env = Env::unlocked();
    let title = "Mail\u{202e}exe\u{200b}";
    let value = "فارسی\u{200c}\u{200d}\u{2066}hidden";
    let entry = env.read(|s| {
        let mut draft = s.new_entry(s.root()?, "login", title)?;
        draft.add_field(
            "User\u{202e}name",
            FieldKind::Text,
            qv_core::FieldValue::text(value).unwrap(),
        )?;
        s.save_entry(draft)
    });
    let displayed = env.read(|s| views::entry(s, entry));
    assert!(displayed.title.contains("\\u{202e}"));
    assert!(displayed.fields[0].name.contains("\\u{202e}"));
    assert!(
        displayed.fields[0]
            .value
            .as_ref()
            .unwrap()
            .contains("\\u{2066}")
    );
    env.act(WsAction::EditEntry(entry));
    let view = form(&env);
    assert_eq!(view.title.as_str(), title);
    assert_eq!(view.rows[0].name.as_str(), "User\u{202e}name");
    assert_eq!(view.rows[0].value.as_ref().unwrap().as_str(), value);
    env.act(WsAction::SaveEntry);
    assert_eq!(env.error(), None);
    let actual = env.read(|s| s.edit_entry(entry));
    assert_eq!(actual.entry().title.expose(), title);
    assert_eq!(
        actual.entry().fields[0].value.expose_secret(),
        value.as_bytes()
    );
}

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
fn a_save_refused_for_a_missing_title_keeps_the_typed_password() {
    let _k = lock();
    let env = Env::unlocked();
    // A login with no title and no website to take one from.
    start(&env, "");
    env.act(WsAction::StartAs(Some(ItemType::Login)));
    let f = form(&env);
    assert!(f.title.is_empty() && f.auto_title.is_none());
    let pw = row(&f, "Password");
    env.put(WsField::Replacement(pw), "typed-before-the-title");
    // Not ready: the Save buttons do not clear the webview's inputs.
    assert!(!form(&env).ready);
    env.act(WsAction::SaveEntry);
    assert_eq!(env.error(), Some(AppError::NameRequired));
    assert_eq!(env.screen(), Screen::EditEntry);
    let f = form(&env);
    assert!(!f.ready && f.rows.iter().any(|r| r.index == pw && r.replaced));
    // Once titled the save is ready (and clears); the password is kept.
    env.put(WsField::Title, "Bank");
    assert!(form(&env).ready);
    let e = saved(&env);
    assert_eq!(reveal(&env, e, "Password"), b"typed-before-the-title");
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
    // The form's group chip shows the group's own color, not the item's
    // or an automatic one (plan 0072).
    let (name, colour) = env.read(|s| views::group_chip(s, work));
    assert_eq!((name.as_str(), colour), ("Work", Some(5)));
    let (name, colour) = env.read(|s| views::group_chip(s, root));
    assert_eq!((name.as_str(), colour), ("No group", None));
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

#[test]
fn forms_keep_the_list_they_were_opened_from() {
    let _k = lock();
    let env = Env::unlocked();
    let root = env.read(|s| s.root());
    let group = |name: &str| {
        env.act(WsAction::NewGroup(root));
        env.put(WsField::GroupName, name);
        env.act(WsAction::SaveGroup);
        match env.screen() {
            Screen::Browse(Some(g)) => g,
            other => panic!("group screen, got {other:?}"),
        }
    };
    let (one, two) = (group("One"), group("Two"));
    let list = |env: &Env| env.c.list_context(env.epoch()).unwrap();
    // Visit Two, then One, then open a new item in One: the list beside the
    // form and Cancel stay on One (the owner saw Two highlighted).
    env.c.navigate(env.epoch(), Screen::Browse(Some(two)));
    env.c.navigate(env.epoch(), Screen::Browse(Some(one)));
    env.act(WsAction::NewEntry(one));
    assert_eq!(env.screen(), Screen::EditEntry);
    assert_eq!(list(&env), Screen::Browse(Some(one)));
    env.c.back(env.epoch());
    assert_eq!(env.screen(), Screen::Browse(Some(one)));

    env.act(WsAction::NewEntry(one));
    env.act(WsAction::StartAs(Some(ItemType::Note)));
    env.put(WsField::Title, "In one");
    let e = saved(&env);
    assert_eq!(list(&env), Screen::Browse(Some(one)));
    assert_eq!(env.read(|s| views::browse(s, Some(one))).entries.len(), 1);
    // Editing from the entry: Cancel returns to it, Save lands on it once.
    env.act(WsAction::EditEntry(e));
    assert_eq!(list(&env), Screen::Browse(Some(one)));
    env.c.back(env.epoch());
    assert_eq!(env.screen(), Screen::Entry(e));
    env.act(WsAction::EditEntry(e));
    saved(&env);
    env.c.back(env.epoch());
    assert_eq!(env.screen(), Screen::Browse(Some(one)));
    // Renaming a group lands on it without stacking it twice.
    env.act(WsAction::RenameGroup(one));
    assert_eq!(list(&env), Screen::Browse(Some(one)));
    env.act(WsAction::SaveGroup);
    assert_eq!(env.screen(), Screen::Browse(Some(one)));
    env.c.back(env.epoch());
    assert_ne!(env.screen(), Screen::Browse(Some(one)));
}

#[test]
fn moving_the_pointer_postpones_the_inactivity_lock() {
    use crate::controller::{FormEpoch, Phase};
    use std::time::{Duration, Instant};
    let _k = lock();
    let env = Env::unlocked();
    let idle = |env: &Env| {
        env.c.state().active = Instant::now() - crate::workspace::IDLE - Duration::from_secs(1)
    };
    // (Read the epoch first: a snapshot applies the idle lock.)
    let epoch = env.epoch();
    // Activity reported after the limit without actions keeps it unlocked.
    idle(&env);
    env.c.activity(epoch);
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    // A stale epoch's activity does not count.
    idle(&env);
    env.c.activity(FormEpoch(epoch.0.wrapping_sub(1)));
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
}

#[test]
fn an_open_file_picker_lengthens_the_inactivity_lock() {
    use crate::controller::Phase;
    use crate::workspace::PICKER_IDLE;
    use std::time::{Duration, Instant};
    let _k = lock();
    let env = Env::unlocked();
    let idle = |env: &Env, d: Duration| env.c.state().active = Instant::now() - d;
    // A picker open for almost its limit keeps the vault unlocked.
    let open = env.c.picker_open();
    idle(&env, PICKER_IDLE - Duration::from_secs(1));
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    // Closing it counts as activity; the usual limit applies again.
    drop(open);
    assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    idle(&env, crate::workspace::IDLE + Duration::from_secs(1));
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
    // Still bounded: the longer limit expires too.
    drop(env);
    let env = Env::unlocked();
    let open = env.c.picker_open();
    idle(&env, PICKER_IDLE);
    assert_eq!(env.c.snapshot().phase, Phase::Locked);
    // A picker closing after the lock changes nothing for the next unlock.
    drop(open);
    assert_eq!(env.c.state().pickers, 0);
}

/// RFC 6238's SHA-1 key "12345678901234567890", as sites print it.
const SETUP_KEY: &str = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
const STORED: &[u8] = b"otpauth://totp/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// `uri`'s code around now (a period can turn between two reads).
fn codes_now(uri: &[u8]) -> [String; 2] {
    let t = qv_core::Totp::parse(uri).unwrap();
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let at = |ms| {
        t.code_at(qv_core::Timestamp(ms))
            .unwrap()
            .expose_secret()
            .to_owned()
    };
    [at(ms), at(ms - 2000)]
}

#[test]
fn a_login_sets_up_its_two_factor_code_from_a_setup_key() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "github.com");
    env.act(WsAction::StartAs(None));
    // A login without a code offers one; nothing is added until it is set up.
    let f = form(&env);
    assert!(f.totp_slot);
    assert!(f.rows.iter().all(|r| r.kind != FieldKind::Totp));
    env.act(WsAction::TotpOpen(None));
    let sheet = form(&env).totp_sheet.unwrap();
    assert!(!sheet.replacing);
    assert!(sheet.state == views::SheetState::Empty);
    // A wrong key is refused in the sheet, which stays open.
    env.put(WsField::TotpInput, "not a key!");
    env.act(WsAction::TotpCheck);
    assert!(matches!(
        form(&env).totp_sheet.unwrap().state,
        views::SheetState::Invalid(_)
    ));
    env.act(WsAction::TotpAdd);
    assert!(form(&env).totp_sheet.is_some());
    assert!(form(&env).totp_slot);
    // The key as the site prints it: checked on a pause, with today's code.
    env.put(WsField::TotpInput, SETUP_KEY);
    env.act(WsAction::TotpCheck);
    match form(&env).totp_sheet.unwrap().state {
        views::SheetState::Valid(false, Some(code)) => {
            assert!(codes_now(STORED).iter().any(|c| *c == *code.code));
            assert_eq!(code.period, 30);
            assert!((1..=30).contains(&code.left));
        }
        _ => panic!("a valid setup key"),
    }
    // Settings for a key change the stored URI.
    env.act(WsAction::TotpOptions(qv_core::KeyOptions {
        digits: 8,
        ..qv_core::KeyOptions::default()
    }));
    match form(&env).totp_sheet.unwrap().state {
        views::SheetState::Valid(false, Some(code)) => assert_eq!(code.code.len(), 8),
        _ => panic!("still valid"),
    }
    env.act(WsAction::TotpOptions(qv_core::KeyOptions::default()));
    env.act(WsAction::TotpAdd);
    let f = form(&env);
    assert!(f.totp_sheet.is_none());
    assert!(!f.totp_slot);
    let i = row(&f, "Two-factor code");
    let r = f.rows.iter().find(|r| r.index == i).unwrap();
    assert_eq!(
        (r.kind, r.protected, r.replaced),
        (FieldKind::Totp, true, true)
    );
    assert!(
        codes_now(STORED)
            .iter()
            .any(|c| *c == *r.code.as_ref().unwrap().code)
    );
    // Neither the key nor the URI is in anything the form renders.
    let shown = rendered(&f);
    assert!(!shown.to_lowercase().contains("gezd"), "{shown}");
    let e = saved(&env);
    assert_eq!(reveal(&env, e, "Two-factor code"), STORED);
    let now = env.read(|s| {
        let view = views::entry(s, e)?;
        let field = view
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        s.totp(field.handle)
    });
    assert!(codes_now(STORED).contains(&now.code.expose_secret().to_owned()));
    assert_eq!(now.period, 30);
    // Replacing it targets the same field.
    env.act(WsAction::EditEntry(e));
    let i = row(&form(&env), "Two-factor code");
    env.act(WsAction::TotpOpen(Some(i)));
    assert!(form(&env).totp_sheet.unwrap().replacing);
    env.put(
        WsField::TotpInput,
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=7",
    );
    env.act(WsAction::TotpAdd);
    let f = form(&env);
    assert_eq!(
        f.rows.iter().filter(|r| r.kind == FieldKind::Totp).count(),
        1
    );
    assert_eq!(
        f.rows
            .iter()
            .find(|r| r.index == i)
            .unwrap()
            .code
            .as_ref()
            .unwrap()
            .code
            .len(),
        7
    );
    // Opening it for a field that is not a code is refused.
    let user = row(&f, "Username");
    env.act(WsAction::TotpOpen(Some(user)));
    assert_eq!(env.error(), Some(AppError::InvalidInput));
}

#[test]
fn a_pasted_two_factor_link_starts_a_login_with_its_code() {
    let _k = lock();
    let env = Env::unlocked();
    let link = "otpauth://totp/Example%20Co:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
    start(&env, link);
    let g = form(&env).guess.unwrap();
    assert_eq!(g.kind, ItemType::Login);
    assert_eq!(g.line.as_str(), "Login for Example");
    assert_eq!(g.sub.as_str(), "Two-factor code for alice@example.com");
    env.act(WsAction::StartAs(None));
    let f = form(&env);
    assert_eq!(f.title.as_str(), "Example");
    let user = row(&f, "Username");
    let r = f.rows.iter().find(|r| r.index == user).unwrap();
    assert_eq!(r.value.as_ref().unwrap().as_str(), "alice@example.com");
    assert!(!f.totp_slot);
    let i = row(&f, "Two-factor code");
    let r = f.rows.iter().find(|r| r.index == i).unwrap();
    assert!(r.filled && r.code.is_some());
    assert!(!rendered(&f).contains("GEZD"));
    let e = saved(&env);
    assert_eq!(reveal(&env, e, "Two-factor code"), link.as_bytes());
    // A link that does not parse is not taken for a code.
    start(&env, "otpauth://totp/x?secret=1");
    assert_ne!(
        form(&env).guess.map(|g| g.line.to_string()),
        Some("Login with a two-factor code".to_owned())
    );
}

#[test]
fn adding_a_two_factor_field_opens_its_setup_and_a_lock_drops_it() {
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "Server");
    env.act(WsAction::StartAs(Some(ItemType::Other)));
    // The common name and the kind both open the sheet, not an empty field.
    env.act(WsAction::AddNamedField("Two-factor code"));
    assert!(form(&env).totp_sheet.is_some());
    assert!(form(&env).rows.is_empty());
    env.act(WsAction::TotpClose);
    assert!(form(&env).totp_sheet.is_none());
    env.put(WsField::NewFieldName, "Authenticator");
    env.act(WsAction::AddField(Some(FieldKind::Totp)));
    assert!(form(&env).rows.is_empty());
    env.put(WsField::TotpInput, SETUP_KEY);
    env.act(WsAction::TotpAdd);
    let f = form(&env);
    assert_eq!(names(&f), ["Authenticator"]);
    // Only logins get the empty slot.
    assert!(!f.totp_slot);
    // An open sheet and its input end with the lock.
    let i = row(&f, "Authenticator");
    env.act(WsAction::TotpOpen(Some(i)));
    env.put(WsField::TotpInput, SETUP_KEY);
    env.c.lock();
    env.unlock(crate::workspace_tests::PASSWORD);
    assert!(env.c.entry_form(env.epoch()).is_none());
}

#[test]
fn a_scanned_two_factor_link_is_added_and_other_codes_are_not_kept() {
    use crate::qr::{QrTarget, TEST_PAIR};
    let _k = lock();
    let env = Env::unlocked();
    start(&env, "github.com");
    env.act(WsAction::StartAs(None));
    // No sheet, no scan target.
    let link = b"otpauth://totp/GitHub:me?secret=GEZDGNBVGY3TQOJQ";
    assert!(env.c.accept_qr(env.epoch(), QrTarget::Totp, link).is_err());
    env.act(WsAction::TotpOpen(None));
    // A sync code is refused in the sheet and not kept as its input.
    assert_eq!(
        env.c.accept_qr(env.epoch(), QrTarget::Totp, TEST_PAIR),
        Ok(false)
    );
    let sheet = form(&env).totp_sheet.unwrap();
    assert!(!sheet.scanned);
    assert!(matches!(sheet.state, views::SheetState::Invalid(_)));
    // So is a bare setup key: a site's QR code is always a link.
    let key = b"GEZDGNBVGY3TQOJQ";
    assert_eq!(env.c.accept_qr(env.epoch(), QrTarget::Totp, key), Ok(false));
    // A link fills the sheet and, being the user's scan, is added at once.
    assert_eq!(env.c.accept_qr(env.epoch(), QrTarget::Totp, link), Ok(true));
    let sheet = form(&env).totp_sheet.unwrap();
    assert!(sheet.scanned);
    assert!(matches!(
        sheet.state,
        views::SheetState::Valid(true, Some(_))
    ));
    env.c.start_scanned(env.epoch(), QrTarget::Totp);
    env.wait();
    let f = form(&env);
    assert!(f.totp_sheet.is_none());
    let i = row(&f, "Two-factor code");
    assert!(f.rows.iter().find(|r| r.index == i).unwrap().code.is_some());
    let e = saved(&env);
    assert_eq!(reveal(&env, e, "Two-factor code"), link);
}
