// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conversions between the controller's types and the bridge's (handles to
//! references and back) and the display helpers the screens use.
use super::refs::{Refs, Target};
use crate::editor::ItemType;
use crate::workspace::{CopyKey, GenFlag, GenMode, Pane, RevealKey, Screen};
use qv_core::{FieldKind, ItemHandle};
use qv_ui_api as api;
use qv_ui_api::{Glyph, Icon, Z};
use zeroize::Zeroizing;

/// The tile classes of the twelve colours.
const HUES: [&str; 12] = [
    "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11",
];
/// The tile class of a colour token's number.
pub(crate) fn hue_class(n: u8) -> &'static str {
    HUES[usize::from(n) % HUES.len()]
}
/// An automatic colour from a record ID (hex).
pub(crate) fn id_hue(id_hex: &str) -> &'static str {
    let byte = id_hex
        .get(..4)
        .and_then(|h| u16::from_str_radix(h, 16).ok())
        .unwrap_or(0);
    HUES[usize::from(byte) % 12]
}
/// The chosen colour, else the automatic one.
pub(crate) fn item_hue(colour: Option<u8>, id_hex: &str) -> &'static str {
    colour.map_or_else(|| id_hue(id_hex), hue_class)
}
/// A type's start-tile colour.
pub(crate) fn type_hue(kind: ItemType) -> &'static str {
    match kind {
        ItemType::Login => "h6",
        ItemType::Card => "h7",
        ItemType::Wifi => "h5",
        ItemType::Note => "h2",
        ItemType::Other => "h11",
    }
}
/// A vault's colour from its name (names are not secret).
pub(crate) fn vault_hue(name: &str) -> &'static str {
    let n = name
        .bytes()
        .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(b)));
    hue_class((n % 12) as u8)
}
/// A title's monogram.
pub(crate) fn initial(title: &str) -> String {
    title
        .chars()
        .find(|c| !c.is_whitespace())
        .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect())
}
/// A type hint's icon.
pub(crate) fn kind_icon(kind: &str) -> Icon {
    match kind {
        "login" | "password" | "account" => Icon::Key,
        "note" | "notes" | "secure note" => Icon::Note,
        "card" | "credit card" | "payment" => Icon::Card,
        "wifi" | "wi-fi" | "network" => Icon::Wifi,
        _ => Icon::File,
    }
}
/// An entry tile: its bucket's icon, or the title's monogram for Other.
pub(crate) fn entry_glyph(kind: &str, title: &str) -> Glyph {
    if qv_core::type_bucket(kind) == "other" {
        Glyph::Letter(initial(title))
    } else {
        Glyph::Icon(kind_icon(kind))
    }
}
/// A sidebar label for a type hint.
pub(crate) fn kind_label(kind: &str) -> String {
    match qv_core::type_bucket(&kind.to_lowercase()) {
        "login" => "Logins",
        "note" => "Notes",
        "card" => "Cards",
        "wifi" => "Wi-Fi",
        _ => "Other",
    }
    .to_owned()
}
/// A bucket's singular name, for a row without a visible field.
pub(crate) fn type_name(bucket: &str) -> &'static str {
    match bucket {
        "login" => "Login",
        "card" => "Card",
        "wifi" => "Wi-Fi",
        "note" => "Note",
        _ => "Other",
    }
}

enum Family {
    Image,
    Audio,
    Video,
    Text,
    Other,
}
fn file_family(name: &str, mime: &str) -> Family {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let m = mime.to_ascii_lowercase();
    if m.starts_with("image/") || matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") {
        Family::Image
    } else if m.starts_with("audio/")
        || matches!(ext.as_str(), "mp3" | "ogg" | "wav" | "flac" | "m4a")
    {
        Family::Audio
    } else if m.starts_with("video/") || matches!(ext.as_str(), "mp4" | "webm") {
        Family::Video
    } else if m.starts_with("text/")
        || matches!(ext.as_str(), "txt" | "md" | "csv" | "json" | "log")
    {
        Family::Text
    } else {
        Family::Other
    }
}
/// A file's shelf tone (decoration only).
pub(crate) fn file_tone(name: &str, mime: &str) -> &'static str {
    match file_family(name, mime) {
        Family::Image => "img",
        Family::Audio => "aud",
        Family::Video => "vid",
        Family::Text => "txt",
        Family::Other => "oth",
    }
}
/// A file's icon.
pub(crate) fn file_icon(name: &str, mime: &str) -> Icon {
    match file_family(name, mime) {
        Family::Text => Icon::Note,
        _ => Icon::File,
    }
}

pub(crate) fn pane(p: Pane) -> api::Pane {
    match p {
        Pane::Overview => api::Pane::Overview,
        Pane::General => api::Pane::General,
        Pane::Password => api::Pane::Password,
        Pane::Phrase => api::Pane::Phrase,
        Pane::Rotation => api::Pane::Rotation,
        Pane::Verify => api::Pane::Verify,
        Pane::Storage => api::Pane::Storage,
        Pane::About => api::Pane::About,
    }
}
pub(crate) fn pane_back(p: api::Pane) -> Pane {
    match p {
        api::Pane::Overview => Pane::Overview,
        api::Pane::General => Pane::General,
        api::Pane::Password => Pane::Password,
        api::Pane::Phrase => Pane::Phrase,
        api::Pane::Rotation => Pane::Rotation,
        api::Pane::Verify => Pane::Verify,
        api::Pane::Storage => Pane::Storage,
        api::Pane::About => Pane::About,
    }
}

pub(crate) fn item(refs: &mut Refs, i: ItemHandle) -> api::ItemRef {
    match i {
        ItemHandle::Entry(e) => api::ItemRef::Entry(refs.issue(Target::Entry(e))),
        ItemHandle::Group(g) => api::ItemRef::Group(refs.issue(Target::Group(g))),
    }
}
pub(crate) fn item_back(refs: &Refs, i: api::ItemRef) -> Option<ItemHandle> {
    Some(match i {
        api::ItemRef::Entry(r) => ItemHandle::Entry(refs.entry(r)?),
        api::ItemRef::Group(r) => ItemHandle::Group(refs.group(r)?),
    })
}

/// A screen as the page names it. Form screens are never navigation
/// targets, so they have no counterpart.
pub(crate) fn screen(refs: &mut Refs, s: &Screen) -> Option<api::Screen> {
    Some(match s {
        Screen::Browse(g) => api::Screen::Browse(g.map(|g| refs.issue(Target::Group(g)))),
        Screen::Recovered => api::Screen::Recovered,
        Screen::Search => api::Screen::Search,
        Screen::Entry(e) => api::Screen::Entry(refs.issue(Target::Entry(*e))),
        Screen::EditEntry | Screen::EditGroup => return None,
        Screen::Move(i, at) => {
            api::Screen::Move(item(refs, *i), at.map(|g| refs.issue(Target::Group(g))))
        }
        Screen::Trash => api::Screen::Trash,
        Screen::History(e) => api::Screen::History(refs.issue(Target::Entry(*e))),
        Screen::HistoryVersion(e, v) => {
            api::Screen::HistoryVersion(refs.issue(Target::Entry(*e)), v.clone())
        }
        Screen::Conflicts => api::Screen::Conflicts,
        Screen::ConflictRecord(r) => api::Screen::ConflictRecord(r.clone()),
        Screen::Attachments(e) => api::Screen::Attachments(refs.issue(Target::Entry(*e))),
        Screen::Generator => api::Screen::Generator,
        Screen::Snapshots => api::Screen::Snapshots,
        Screen::Archives => api::Screen::Archives,
        Screen::Devices => api::Screen::Devices,
        Screen::Settings(p) => api::Screen::Settings(pane(*p)),
        Screen::Autofill => api::Screen::Autofill,
        Screen::More => api::Screen::More,
        Screen::Kind(k) => api::Screen::Kind(k.to_string()),
    })
}

/// The bounded text of a page-supplied ID (record or version, 32 hex).
fn hex_id(s: &str) -> Option<String> {
    (s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_owned())
}

/// A page-named screen, references resolved; `None` if one is stale.
pub(crate) fn screen_back(refs: &Refs, s: &api::Screen) -> Option<Screen> {
    Some(match s {
        api::Screen::Browse(g) => Screen::Browse(match g {
            Some(r) => Some(refs.group(*r)?),
            None => None,
        }),
        api::Screen::Recovered => Screen::Recovered,
        api::Screen::Search => Screen::Search,
        api::Screen::Entry(r) => Screen::Entry(refs.entry(*r)?),
        api::Screen::Move(i, at) => Screen::Move(
            item_back(refs, *i)?,
            match at {
                Some(r) => Some(refs.group(*r)?),
                None => None,
            },
        ),
        api::Screen::Trash => Screen::Trash,
        api::Screen::History(r) => Screen::History(refs.entry(*r)?),
        api::Screen::HistoryVersion(r, v) => Screen::HistoryVersion(refs.entry(*r)?, hex_id(v)?),
        api::Screen::Conflicts => Screen::Conflicts,
        api::Screen::ConflictRecord(r) => Screen::ConflictRecord(hex_id(r)?),
        api::Screen::Attachments(r) => Screen::Attachments(refs.entry(*r)?),
        api::Screen::Generator => Screen::Generator,
        api::Screen::Snapshots => Screen::Snapshots,
        api::Screen::Archives => Screen::Archives,
        api::Screen::Devices => Screen::Devices,
        api::Screen::Settings(p) => Screen::Settings(pane_back(*p)),
        api::Screen::Autofill => Screen::Autofill,
        api::Screen::More => Screen::More,
        api::Screen::Kind(k) => {
            if k.len() > 64 {
                return None;
            }
            Screen::Kind(Zeroizing::new(k.clone()))
        }
    })
}

pub(crate) fn reveal(refs: &mut Refs, k: &RevealKey) -> api::RevealKey {
    match k {
        RevealKey::Field(f) => api::RevealKey::Field(refs.issue(Target::Field(*f))),
        RevealKey::History(v, id) => {
            api::RevealKey::History(v.clone(), refs.issue(Target::FieldId(*id)))
        }
        RevealKey::Conflict(r, v, id) => {
            api::RevealKey::Conflict(r.clone(), v.clone(), refs.issue(Target::FieldId(*id)))
        }
        RevealKey::Replacement(i) => api::RevealKey::Replacement(*i),
        RevealKey::Generated => api::RevealKey::Generated,
        RevealKey::Totp(f) => api::RevealKey::Totp(refs.issue(Target::Field(*f))),
        RevealKey::WifiJoin(e) => api::RevealKey::WifiJoin(refs.issue(Target::Entry(*e))),
    }
}
pub(crate) fn reveal_back(refs: &Refs, k: &api::RevealKey) -> Option<RevealKey> {
    Some(match k {
        api::RevealKey::Field(r) => RevealKey::Field(refs.field(*r)?),
        api::RevealKey::History(v, r) => RevealKey::History(hex_id(v)?, refs.field_id(*r)?),
        api::RevealKey::Conflict(rec, v, r) => {
            RevealKey::Conflict(hex_id(rec)?, hex_id(v)?, refs.field_id(*r)?)
        }
        api::RevealKey::Replacement(i) => RevealKey::Replacement(*i),
        api::RevealKey::Generated => RevealKey::Generated,
        api::RevealKey::Totp(r) => RevealKey::Totp(refs.field(*r)?),
        api::RevealKey::WifiJoin(r) => RevealKey::WifiJoin(refs.entry(*r)?),
    })
}
pub(crate) fn copy(refs: &mut Refs, k: &CopyKey) -> api::CopyKey {
    match k {
        CopyKey::Field(e, f) => {
            api::CopyKey::Field(refs.issue(Target::Entry(*e)), refs.issue(Target::Field(*f)))
        }
        CopyKey::Totp(e, f) => {
            api::CopyKey::Totp(refs.issue(Target::Entry(*e)), refs.issue(Target::Field(*f)))
        }
        CopyKey::Generated => api::CopyKey::Generated,
        CopyKey::Notes(e) => api::CopyKey::Notes(refs.issue(Target::Entry(*e))),
    }
}
pub(crate) fn copy_back(refs: &Refs, k: &api::CopyKey) -> Option<CopyKey> {
    Some(match k {
        api::CopyKey::Field(e, f) => CopyKey::Field(refs.entry(*e)?, refs.field(*f)?),
        api::CopyKey::Totp(e, f) => CopyKey::Totp(refs.entry(*e)?, refs.field(*f)?),
        api::CopyKey::Generated => CopyKey::Generated,
        api::CopyKey::Notes(e) => CopyKey::Notes(refs.entry(*e)?),
    })
}

pub(crate) fn item_type(t: ItemType) -> api::ItemType {
    match t {
        ItemType::Login => api::ItemType::Login,
        ItemType::Card => api::ItemType::Card,
        ItemType::Wifi => api::ItemType::Wifi,
        ItemType::Note => api::ItemType::Note,
        ItemType::Other => api::ItemType::Other,
    }
}
pub(crate) fn item_type_back(t: api::ItemType) -> ItemType {
    match t {
        api::ItemType::Login => ItemType::Login,
        api::ItemType::Card => ItemType::Card,
        api::ItemType::Wifi => ItemType::Wifi,
        api::ItemType::Note => ItemType::Note,
        api::ItemType::Other => ItemType::Other,
    }
}
pub(crate) fn type_choice(t: ItemType) -> api::TypeChoice {
    api::TypeChoice {
        kind: item_type(t),
        name: t.name().to_owned(),
        hint: t.hint().to_owned(),
        icon: kind_icon(t.hint()),
        hue: type_hue(t).to_owned(),
    }
}

pub(crate) fn field_kind(k: FieldKind) -> api::FieldKind {
    match k {
        FieldKind::Text => api::FieldKind::Text,
        FieldKind::Secret => api::FieldKind::Secret,
        FieldKind::Url => api::FieldKind::Url,
        FieldKind::Email => api::FieldKind::Email,
        FieldKind::Totp => api::FieldKind::Totp,
        FieldKind::Multiline => api::FieldKind::Multiline,
        FieldKind::Date => api::FieldKind::Date,
        _ => api::FieldKind::Other,
    }
}
/// A page-chosen kind; `Other` is not addable.
pub(crate) fn field_kind_back(k: api::FieldKind) -> Option<FieldKind> {
    Some(match k {
        api::FieldKind::Text => FieldKind::Text,
        api::FieldKind::Secret => FieldKind::Secret,
        api::FieldKind::Url => FieldKind::Url,
        api::FieldKind::Email => FieldKind::Email,
        api::FieldKind::Totp => FieldKind::Totp,
        api::FieldKind::Multiline => FieldKind::Multiline,
        api::FieldKind::Date => FieldKind::Date,
        api::FieldKind::Other => return None,
    })
}

pub(crate) fn gen_mode(m: GenMode) -> api::GenMode {
    match m {
        GenMode::Characters => api::GenMode::Characters,
        GenMode::Words => api::GenMode::Words,
        GenMode::Pin => api::GenMode::Pin,
    }
}
pub(crate) fn gen_mode_back(m: api::GenMode) -> GenMode {
    match m {
        api::GenMode::Characters => GenMode::Characters,
        api::GenMode::Words => GenMode::Words,
        api::GenMode::Pin => GenMode::Pin,
    }
}
pub(crate) fn gen_flag_back(f: api::GenFlag) -> GenFlag {
    match f {
        api::GenFlag::Lower => GenFlag::Lower,
        api::GenFlag::Upper => GenFlag::Upper,
        api::GenFlag::Digits => GenFlag::Digits,
        api::GenFlag::Symbols => GenFlag::Symbols,
        api::GenFlag::Ambiguous => GenFlag::Ambiguous,
        api::GenFlag::Each => GenFlag::Each,
        api::GenFlag::Capitalize => GenFlag::Capitalize,
        api::GenFlag::AppendDigit => GenFlag::AppendDigit,
    }
}

pub(crate) fn mode(m: crate::controller::Mode) -> api::Mode {
    use crate::controller::Mode;
    match m {
        Mode::Unlock => api::Mode::Unlock,
        Mode::Import => api::Mode::Import,
        Mode::Create => api::Mode::Create,
        Mode::Recover => api::Mode::Recover,
        Mode::Join => api::Mode::Join,
    }
}
pub(crate) fn mode_back(m: api::Mode) -> crate::controller::Mode {
    use crate::controller::Mode;
    match m {
        api::Mode::Unlock => Mode::Unlock,
        api::Mode::Import => Mode::Import,
        api::Mode::Create => Mode::Create,
        api::Mode::Recover => Mode::Recover,
        api::Mode::Join => Mode::Join,
    }
}
pub(crate) fn phase(p: crate::controller::Phase) -> api::Phase {
    use crate::controller::Phase;
    match p {
        Phase::Locked => api::Phase::Locked,
        Phase::WeakPassword => api::Phase::WeakPassword,
        Phase::Opening => api::Phase::Opening,
        Phase::Phrase => api::Phase::Phrase,
        Phase::Recovery => api::Phase::Recovery,
        Phase::Unlocked => api::Phase::Unlocked,
        Phase::Rotation => api::Phase::Rotation,
    }
}
pub(crate) fn action_back(a: api::Action) -> crate::controller::Action {
    use crate::controller::Action;
    match a {
        api::Action::SuggestPassword => Action::SuggestPassword,
        api::Action::Create => Action::Create,
        api::Action::ConfirmWeak => Action::ConfirmWeak,
        api::Action::Unlock => Action::Unlock,
        api::Action::ImportVault => Action::ImportVault,
        api::Action::QuickUnlock => Action::QuickUnlock,
        api::Action::Recover => Action::Recover,
        api::Action::RecoverPassword => Action::RecoverPassword,
        api::Action::ConfirmPhrase => Action::ConfirmPhrase,
        api::Action::SkipPhrase => Action::SkipPhrase,
        api::Action::AdoptBaseline => Action::AdoptBaseline,
        api::Action::ConfirmRotation => Action::ConfirmRotation,
        api::Action::InstallRotation => Action::InstallRotation,
        api::Action::CancelRotation => Action::CancelRotation,
        api::Action::ResumeComplete => Action::ResumeComplete,
        api::Action::ResumeRollback => Action::ResumeRollback,
        api::Action::JoinDevice => Action::JoinDevice,
    }
}
pub(crate) fn quick_policy(p: qv_core::platform::QuickPolicy) -> api::QuickPolicy {
    match p {
        qv_core::platform::QuickPolicy::Class3 => api::QuickPolicy::Class3,
        qv_core::platform::QuickPolicy::DeviceCredential => api::QuickPolicy::DeviceCredential,
    }
}
pub(crate) fn quick_policy_back(p: api::QuickPolicy) -> qv_core::platform::QuickPolicy {
    match p {
        api::QuickPolicy::Class3 => qv_core::platform::QuickPolicy::Class3,
        api::QuickPolicy::DeviceCredential => qv_core::platform::QuickPolicy::DeviceCredential,
    }
}

/// A listed vault for the page.
pub(crate) fn vault_choice(
    refs: &mut Refs,
    v: &crate::vaults::Listed,
    current: bool,
    quick: bool,
) -> api::VaultChoice {
    api::VaultChoice {
        id: refs.issue(Target::Vault(v.path.clone())),
        name: Z::from(crate::views::z(&v.name)),
        file: Z::from(crate::views::z(&v.file)),
        place: Z::from(crate::views::z(&v.place)),
        exists: v.exists,
        in_folder: v.in_folder,
        current,
        quick,
        hue: vault_hue(&v.name).to_owned(),
        initial: initial(&v.name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_follow_the_record_id_or_the_choice() {
        let id = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        assert_eq!(id_hue(id), "h6");
        assert_eq!(item_hue(Some(3), id), "h3");
        assert_eq!(id_hue(""), "h0");
        assert_eq!(initial("  bank"), "B");
        assert_eq!(initial(""), "?");
    }

    #[test]
    fn page_ids_are_bounded_hex() {
        let refs = Refs::default();
        assert!(screen_back(&refs, &api::Screen::ConflictRecord("abc123".into())).is_some());
        assert!(screen_back(&refs, &api::Screen::ConflictRecord("../etc".into())).is_none());
        assert!(screen_back(&refs, &api::Screen::Entry(api::Ref([1; 16]))).is_none());
        assert!(screen_back(&refs, &api::Screen::Kind("x".repeat(65))).is_none());
    }
}
