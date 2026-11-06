// SPDX-License-Identifier: AGPL-3.0-or-later

//! Item-editor rules (plan 0040 E1–E10): item types and their templates, the
//! on-device start guess, field-kind inference, card and Wi‑Fi helpers, the
//! colour token (0003 §5.5) and the form's field list edits.
//!
//! Protected inputs are read in place. Only the derived values that 0009 §1.8
//! allows leave them: a card number's brand, last four digits and validity.
//! Nothing here looks anything up online.
use crate::controller::AppError;
use crate::workspace::{EntryForm, protect};
use qv_core::{Field, FieldKind, FieldValue, SecretBytes};
use zeroize::Zeroizing;

/// The number of tile colours (`h0`–`h11`).
pub const HUES: u8 = 12;
const HUE_PREFIX: &str = "hue:";

/// What an item is. The stored type hints are the existing strings
/// (0003 §5); "Something else" is `custom`, the name for unknown hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemType {
    /// A website or app sign-in.
    Login,
    /// A payment card.
    Card,
    /// A Wi‑Fi network.
    Wifi,
    /// A secure note.
    Note,
    /// Anything else.
    Other,
}
/// One template field.
pub struct Template {
    /// Field name.
    pub name: &'static str,
    /// Field kind (protection follows its default, 0003 §5.3).
    pub kind: FieldKind,
    /// Initial value.
    pub value: &'static str,
}
const fn t(name: &'static str, kind: FieldKind, value: &'static str) -> Template {
    Template { name, kind, value }
}
const LOGIN: [Template; 3] = [
    t("Username", FieldKind::Text, ""),
    t("Password", FieldKind::Secret, ""),
    t("Website", FieldKind::Url, ""),
];
const CARD: [Template; 4] = [
    t("Name on card", FieldKind::Text, ""),
    t(CARD_NUMBER, FieldKind::Secret, ""),
    t(EXPIRES, FieldKind::Text, ""),
    t("Security code", FieldKind::Secret, ""),
];
const WIFI: [Template; 3] = [
    t(NETWORK, FieldKind::Text, ""),
    t("Password", FieldKind::Secret, ""),
    t(SECURITY, FieldKind::Text, "WPA2"),
];
/// The card-number field name.
pub const CARD_NUMBER: &str = "Card number";
/// The card-expiry field name.
pub const EXPIRES: &str = "Expires";
/// The Wi‑Fi network-name field name.
pub const NETWORK: &str = "Network name";
/// The Wi‑Fi security field name.
pub const SECURITY: &str = "Security";
/// Wi‑Fi security choices: stored value and label.
pub const SECURITY_CHOICES: [(&str, &str); 4] = [
    ("WPA3", "WPA3"),
    ("WPA2", "WPA2"),
    ("WEP", "WEP"),
    ("None", "Open network"),
];

impl ItemType {
    /// Every type, in menu order.
    pub const ALL: [Self; 5] = [Self::Login, Self::Card, Self::Wifi, Self::Note, Self::Other];
    /// The stored type hint.
    pub fn hint(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Card => "card",
            Self::Wifi => "wifi",
            Self::Note => "note",
            Self::Other => "custom",
        }
    }
    /// The displayed name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::Card => "Card",
            Self::Wifi => "Wi‑Fi",
            Self::Note => "Note",
            Self::Other => "Something else",
        }
    }
    /// The type of a stored hint, if it is one of these.
    pub fn from_hint(hint: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|t| hint.eq_ignore_ascii_case(t.hint()))
    }
    /// The title placeholder.
    pub fn placeholder(self) -> &'static str {
        match self {
            Self::Login => "Name it, like GitHub",
            Self::Card => "Name it, like Everyday Visa",
            Self::Wifi => "Name it, like Home Wi‑Fi",
            Self::Note => "Untitled note",
            Self::Other => "Name it",
        }
    }
    /// The fields a new item of this type starts with.
    pub fn template(self) -> &'static [Template] {
        match self {
            Self::Login => &LOGIN,
            Self::Card => &CARD,
            Self::Wifi => &WIFI,
            Self::Note | Self::Other => &[],
        }
    }
    /// A few field names people often add to this type.
    pub fn common(self) -> &'static [&'static str] {
        match self {
            Self::Login => &["Two-factor code", "Email", "Recovery codes", "PIN"],
            Self::Card => &["PIN", "Bank phone", "Billing address"],
            Self::Wifi => &["Router admin password", "Guest network"],
            Self::Note => &["Reference", "Date"],
            Self::Other => &["Username", "Password", "Account number", "PIN"],
        }
    }
}

/// The colour a stored `icon` names (`hue:<0–11>`), or `None` for the
/// automatic colour (absent, a built-in icon name or anything unknown).
pub fn colour(icon: Option<&str>) -> Option<u8> {
    let n = icon?.strip_prefix(HUE_PREFIX)?;
    if n.is_empty() || n.len() > 2 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse::<u8>().ok().filter(|n| *n < HUES)
}
/// The `icon` text after the user picks a colour (`None` is "Automatic").
/// Automatic removes only a colour token; other icon values are kept.
pub fn pick_colour(icon: Option<&str>, pick: Option<u8>) -> Result<Option<String>, AppError> {
    match pick {
        Some(n) if n < HUES => Ok(Some(format!("{HUE_PREFIX}{n}"))),
        Some(_) => Err(AppError::InvalidInput),
        None if colour(icon).is_some() => Ok(None),
        None => Ok(icon.map(str::to_owned)),
    }
}

/// The ASCII digits of a card number written with optional spaces or
/// dashes, or `None` if it contains anything else.
fn card_digits(value: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len().min(32)));
    for &b in value {
        match b {
            b'0'..=b'9' => out.push(b),
            b' ' | b'-' => {}
            _ => return None,
        }
    }
    Some(out)
}
fn brand(digits: &[u8]) -> Option<&'static str> {
    let two = |a: u8, b: u8| digits.len() >= 2 && (a..=b).contains(&digits[1]);
    match digits.first()? {
        b'4' => Some("Visa"),
        b'5' if two(b'1', b'5') => Some("Mastercard"),
        b'2' if two(b'2', b'7') => Some("Mastercard"),
        b'3' if digits.get(1).is_some_and(|d| *d == b'4' || *d == b'7') => Some("Amex"),
        b'6' if digits.starts_with(b"6011") || digits.starts_with(b"65") => Some("Discover"),
        _ => None,
    }
}
fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut d = u32::from(d - b'0');
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum.is_multiple_of(10)
}
/// What may be shown about a card number (0009 §1.8): never the number.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CardInfo {
    /// The network, from the leading digits.
    pub brand: Option<&'static str>,
    /// The last four digits, once there are at least four.
    pub last4: Option<String>,
    /// The Luhn check, once the number is as long as a full number of its
    /// brand (15 for Amex, else 16), so typing is not called invalid.
    pub valid: Option<bool>,
}
impl CardInfo {
    /// Derive the shown facts from a card number, read in place.
    pub fn of(value: &[u8]) -> Self {
        let Some(d) = card_digits(value) else {
            return Self::default();
        };
        let last4 = (d.len() >= 4).then(|| String::from_utf8_lossy(&d[d.len() - 4..]).into_owned());
        let brand = brand(&d);
        let full = if brand == Some("Amex") { 15 } else { 16 };
        Self {
            brand,
            last4,
            valid: (d.len() >= full).then(|| luhn(&d)),
        }
    }
    /// The automatic title, like "Visa ••4242".
    pub fn title(&self) -> Option<String> {
        let last4 = self.last4.as_ref()?;
        Some(format!("{} ••{last4}", self.brand.unwrap_or("Card")))
    }
}

/// The host name of a typed website or URL, lowercased without `www.`.
pub fn domain(input: &str) -> Option<String> {
    let s = input.trim().to_ascii_lowercase();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(&s);
    let s = s.strip_prefix("www.").unwrap_or(s);
    let end = s.find(['/', ':', '?', '#']).unwrap_or(s.len());
    let host = &s[..end];
    let labels: Vec<&str> = host.split('.').collect();
    let ok = labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()));
    ok.then(|| host.to_owned())
}
/// A readable name for a site: `github.com` is "GitHub", `bbc.co.uk` "Bbc".
pub fn site_name(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    let n = parts.len();
    let core = if n > 2 && parts[n - 2].len() <= 3 {
        parts[n - 3]
    } else {
        parts[n.saturating_sub(2)]
    };
    const KNOWN: [(&str, &str); 5] = [
        ("github", "GitHub"),
        ("gitlab", "GitLab"),
        ("paypal", "PayPal"),
        ("youtube", "YouTube"),
        ("linkedin", "LinkedIn"),
    ];
    if let Some((_, name)) = KNOWN.iter().find(|(k, _)| *k == core) {
        return (*name).to_owned();
    }
    let mut c = core.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// What the start box holds, once recognised.
pub enum Start {
    /// A card number (digits only).
    Card(Zeroizing<Vec<u8>>),
    /// A website's host name.
    Site(String),
    /// Anything else: a name.
    Name(Zeroizing<String>),
}
/// The start step's guess (plan 0040 E1).
pub struct Guess {
    /// The suggested type.
    pub kind: ItemType,
    /// The headline, like "Login for GitHub".
    pub line: Zeroizing<String>,
    /// The second line.
    pub sub: Zeroizing<String>,
    /// What was recognised.
    pub start: Start,
}
const WIFI_WORDS: [&str; 6] = ["wi-fi", "wifi", "wlan", "ssid", "router", "network"];
/// Recognise what the start box holds, on the device.
pub fn guess(input: &[u8]) -> Option<Guess> {
    let text = std::str::from_utf8(input).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(d) = card_digits(text.as_bytes()).filter(|d| (12..=19).contains(&d.len())) {
        let info = CardInfo::of(&d);
        let last4 = info.last4.clone().unwrap_or_default();
        // A pasted number is complete: check it whatever its length.
        let sub = if luhn(&d) {
            "The number checks out"
        } else {
            "This number does not check out; you can still save it"
        };
        return Some(Guess {
            kind: ItemType::Card,
            line: Zeroizing::new(format!("{} ending {last4}", info.brand.unwrap_or("Card"))),
            sub: Zeroizing::new(sub.to_owned()),
            start: Start::Card(d),
        });
    }
    if let Some(d) = domain(text) {
        let name = site_name(&d);
        return Some(Guess {
            kind: ItemType::Login,
            line: Zeroizing::new(format!("Login for {name}")),
            sub: Zeroizing::new(d.clone()),
            start: Start::Site(d),
        });
    }
    let lower = Zeroizing::new(text.to_lowercase());
    let (kind, line, sub) = if WIFI_WORDS.iter().any(|w| lower.contains(w)) {
        (
            ItemType::Wifi,
            format!("Wi‑Fi network “{text}”"),
            "Network name and password",
        )
    } else {
        (
            ItemType::Login,
            format!("Login named “{text}”"),
            "Username, password and website",
        )
    };
    Some(Guess {
        kind,
        line: Zeroizing::new(line),
        sub: Zeroizing::new(sub.to_owned()),
        start: Start::Name(Zeroizing::new(text.to_owned())),
    })
}

/// The kind (and protection) a new field's name suggests (plan 0040 E7).
pub fn kind_for(name: &str) -> (FieldKind, bool) {
    let n = name.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| n.contains(w));
    let word = |w: &str| n.split(|c: char| !c.is_alphanumeric()).any(|x| x == w);
    if has(&[
        "otp",
        "2fa",
        "totp",
        "two-factor",
        "two factor",
        "twofactor",
        "authenticator",
    ]) {
        return (FieldKind::Totp, true);
    }
    if has(&[
        "pass", "cvv", "cvc", "secret", "token", "api key", "api-key", "apikey",
    ]) || has(&[
        "private",
        "seed",
        "recovery",
        "backup code",
        "security code",
    ]) || word("pin")
    {
        return if has(&["codes", "recovery"]) {
            (FieldKind::Multiline, true)
        } else {
            (FieldKind::Secret, true)
        };
    }
    if n.contains("mail") {
        return (FieldKind::Email, false);
    }
    if has(&["url", "site", "web", "link", "domain"]) {
        return (FieldKind::Url, false);
    }
    if has(&["address", "codes", "memo"]) || word("note") || word("notes") {
        return (FieldKind::Multiline, false);
    }
    (FieldKind::Text, false)
}
/// A kind's name in the editor.
pub fn kind_label(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "Text",
        FieldKind::Secret => "Hidden",
        FieldKind::Url => "Website",
        FieldKind::Email => "Email",
        FieldKind::Multiline => "Multi-line",
        FieldKind::Totp => "One-time code",
        FieldKind::Date => "Date",
        _ => "Other",
    }
}
/// The kinds offered when adding a field.
pub const ADD_KINDS: [FieldKind; 6] = [
    FieldKind::Text,
    FieldKind::Secret,
    FieldKind::Url,
    FieldKind::Email,
    FieldKind::Multiline,
    FieldKind::Totp,
];

/// The current UTC year and month (1–12) from the device clock.
pub fn this_month() -> (i64, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    // Civil-from-days (H. Hinnant), as `views::date` does.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, u32::try_from(m).unwrap_or(1))
}
/// A card expiry's month and year text: `MM/YY`, `MM / YYYY`, or four
/// digits typed without the slash (`MMYY`).
fn expiry_parts(value: &str) -> Option<(&str, &str)> {
    let v = value.trim();
    match v.split_once('/') {
        Some((m, y)) => Some((m.trim(), y.trim())),
        None if v.len() == 4 && v.bytes().all(|b| b.is_ascii_digit()) => Some((&v[..2], &v[2..])),
        None => None,
    }
}
/// A card expiry as `MM/YY` for the card face, else as typed.
pub fn expiry_shown(value: &str) -> String {
    match expiry_parts(value) {
        Some((m, y)) if m.len() == 2 && (y.len() == 2 || y.len() == 4) => {
            format!("{m}/{}", &y[y.len() - 2..])
        }
        _ => value.trim().to_owned(),
    }
}
/// How long a card's `MM/YY` (or `MM/YYYY`) expiry has left, and whether
/// that is comfortable (three months or more). `None` until it parses.
pub fn expiry(value: &str, now: (i64, u32)) -> Option<(String, bool)> {
    let (m, y) = expiry_parts(value)?;
    if m.is_empty() || m.len() > 2 || !m.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !(y.len() == 2 || y.len() == 4) || !y.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let month: u32 = m.parse().ok()?;
    let mut year: i64 = y.parse().ok()?;
    if y.len() == 2 {
        year += 2000;
    }
    if !(1..=12).contains(&month) {
        return Some(("Month 01–12".into(), false));
    }
    let left = (year - now.0) * 12 + i64::from(month) - i64::from(now.1);
    Some(match left {
        l if l < 0 => ("Expired".into(), false),
        0 => ("Expires this month".into(), false),
        l if l >= 12 => (format!("{} yr left", l / 12), true),
        l => (format!("{l} mo left"), l >= 3),
    })
}

/// The `WIFI:` join payload (the de-facto ZXing format) for a QR code.
/// It carries the password, so it is shown only through a reveal (E8).
pub fn wifi_payload(
    ssid: &[u8],
    password: Option<&[u8]>,
    security: &str,
) -> Result<SecretBytes, AppError> {
    if ssid.is_empty() {
        return Err(AppError::InvalidInput);
    }
    let kind = if security.eq_ignore_ascii_case("wep") {
        "WEP"
    } else if security.eq_ignore_ascii_case("none") || security.is_empty() {
        "nopass"
    } else {
        "WPA"
    };
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    let push = |out: &mut Vec<u8>, v: &[u8]| {
        for &b in v {
            if matches!(b, b'\\' | b';' | b',' | b':' | b'"') {
                out.push(b'\\');
            }
            out.push(b);
        }
    };
    out.extend_from_slice(b"WIFI:T:");
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(b";S:");
    push(&mut out, ssid);
    out.push(b';');
    if kind != "nopass" {
        out.extend_from_slice(b"P:");
        push(&mut out, password.unwrap_or_default());
        out.push(b';');
    }
    out.push(b';');
    if out.len() > crate::qr::MAX_PAYLOAD {
        return Err(AppError::TooLargeForApp);
    }
    protect(&out)
}

/// Whether two field names are the same template slot.
pub(crate) fn same_slot(a: &str, b: &str) -> bool {
    fn alias(s: &str) -> &str {
        if s.eq_ignore_ascii_case("url") {
            "website"
        } else {
            s
        }
    }
    alias(a.trim()).eq_ignore_ascii_case(alias(b.trim()))
}
/// Whether a form field holds anything worth keeping.
fn filled(form: &EntryForm, i: usize, f: &Field) -> bool {
    !f.value.expose_secret().is_empty()
        || u16::try_from(i).is_ok_and(|i| form.replacements.contains_key(&i))
}
/// Rebuild the form's index-keyed state after the fields were reordered:
/// `map[old] = Some(new)`, or `None` if the field is gone.
fn remap(form: &mut EntryForm, map: &[Option<u16>]) {
    let at = |k: u16| map.get(usize::from(k)).copied().flatten();
    form.replacements = std::mem::take(&mut form.replacements)
        .into_iter()
        .filter_map(|(k, v)| at(k).map(|n| (n, v)))
        .collect();
    form.generated = form.generated.iter().filter_map(|k| at(*k)).collect();
    form.filled = form.filled.iter().filter_map(|k| at(*k)).collect();
    form.too_large = form.too_large.iter().filter_map(|k| at(*k)).collect();
}
/// Change the item's type (E2): template fields reuse filled fields of the
/// same name, other filled fields are kept after them, and empty fields the
/// template does not have are dropped. Returns whether any non-template
/// field was kept.
pub(crate) fn set_type(form: &mut EntryForm, kind: ItemType) -> Result<bool, AppError> {
    let hint = qv_core::Text::new(kind.hint()).map_err(|_| AppError::InvalidInput)?;
    let old = std::mem::take(&mut form.draft.entry_mut().fields);
    let keep: Vec<bool> = old
        .iter()
        .enumerate()
        .map(|(i, f)| filled(form, i, f))
        .collect();
    let mut slots: Vec<Option<Field>> = old.into_iter().map(Some).collect();
    let mut map = vec![None; slots.len()];
    let mut next = 0u16;
    for tpl in kind.template() {
        let found = slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|f| same_slot(f.name.expose(), tpl.name))
        });
        if let Some(j) = found
            && let Some(f) = slots[j].take()
        {
            form.draft.entry_mut().fields.push(f);
            map[j] = Some(next);
        } else {
            let value = FieldValue::text(tpl.value).map_err(|_| AppError::InvalidInput)?;
            form.draft.add_field(tpl.name, tpl.kind, value)?;
        }
        next += 1;
    }
    let mut kept = false;
    for (j, slot) in slots.iter_mut().enumerate() {
        if keep[j]
            && let Some(f) = slot.take()
        {
            form.draft.entry_mut().fields.push(f);
            map[j] = Some(next);
            next += 1;
            kept = true;
        }
    }
    remap(form, &map);
    form.draft.entry_mut().type_hint = hint;
    Ok(kept)
}
/// Swap a field with its neighbour (`up` toward the top).
pub(crate) fn move_field(form: &mut EntryForm, i: u16, up: bool) -> Result<(), AppError> {
    let len = form.draft.entry().fields.len();
    let a = usize::from(i);
    let b = if up {
        a.checked_sub(1)
    } else {
        a.checked_add(1)
    }
    .filter(|b| *b < len);
    let Some(b) = b.filter(|_| a < len) else {
        return Err(AppError::InvalidInput);
    };
    form.draft.entry_mut().fields.swap(a, b);
    let map: Vec<Option<u16>> = (0..len)
        .map(|k| {
            u16::try_from(if k == a {
                b
            } else if k == b {
                a
            } else {
                k
            })
            .ok()
        })
        .collect();
    remap(form, &map);
    Ok(())
}
/// A removed field, kept for Undo until the next removal or the form ends.
pub(crate) struct Removed {
    pub(crate) index: u16,
    pub(crate) field: Field,
    pub(crate) replacement: Option<SecretBytes>,
    pub(crate) generated: bool,
    pub(crate) filled: bool,
    pub(crate) too_large: bool,
}
/// Remove a field, keeping it for Undo.
pub(crate) fn remove_field(form: &mut EntryForm, i: u16) -> Result<(), AppError> {
    let len = form.draft.entry().fields.len();
    let index = usize::from(i);
    if index >= len {
        return Err(AppError::InvalidInput);
    }
    let field = form.draft.entry_mut().fields.remove(index);
    let replacement = form.replacements.remove(&i);
    let removed = Removed {
        index: i,
        field,
        replacement,
        generated: form.generated.contains(&i),
        filled: form.filled.contains(&i),
        too_large: form.too_large.contains(&i),
    };
    let map: Vec<Option<u16>> = (0..len)
        .map(|k| match k.cmp(&index) {
            std::cmp::Ordering::Less => u16::try_from(k).ok(),
            std::cmp::Ordering::Equal => None,
            std::cmp::Ordering::Greater => u16::try_from(k - 1).ok(),
        })
        .collect();
    remap(form, &map);
    form.removed = Some(removed);
    Ok(())
}
/// Put the last removed field back where it was.
pub(crate) fn undo_remove(form: &mut EntryForm) -> Result<(), AppError> {
    let r = form.removed.take().ok_or(AppError::InvalidInput)?;
    let len = form.draft.entry().fields.len();
    let index = usize::from(r.index).min(len);
    let at = u16::try_from(index).map_err(|_| AppError::InvalidInput)?;
    let map: Vec<Option<u16>> = (0..len)
        .map(|k| u16::try_from(if k >= index { k + 1 } else { k }).ok())
        .collect();
    remap(form, &map);
    form.draft.entry_mut().fields.insert(index, r.field);
    if let Some(v) = r.replacement {
        form.replacements.insert(at, v);
    }
    if r.generated {
        form.generated.push(at);
    }
    if r.filled {
        form.filled.push(at);
    }
    if r.too_large {
        form.too_large.push(at);
    }
    Ok(())
}
/// The title an untitled item gets on save, and where it comes from
/// (plan 0040 E3): a login's website, a Wi‑Fi network's name, or a card's
/// brand and last four digits.
pub(crate) fn auto_title(form: &EntryForm) -> Option<(String, &'static str)> {
    let e = form.draft.entry();
    let plain = |i: usize| {
        let f = &e.fields[i];
        (!f.protected)
            .then(|| std::str::from_utf8(f.value.expose_secret()).ok())
            .flatten()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    match ItemType::from_hint(e.type_hint.expose())? {
        ItemType::Login => {
            let i = e.fields.iter().position(|f| f.kind == FieldKind::Url)?;
            Some((site_name(&domain(plain(i)?)?), "the website"))
        }
        ItemType::Wifi => Some((
            plain(find(&e.fields, NETWORK)?)?.to_owned(),
            "the network name",
        )),
        ItemType::Card => {
            let i = find(&e.fields, CARD_NUMBER)?;
            let replaced = u16::try_from(i)
                .ok()
                .and_then(|k| form.replacements.get(&k));
            let value = match replaced {
                Some(v) => v.expose_secret(),
                None => e.fields[i].value.expose_secret(),
            };
            Some((CardInfo::of(value).title()?, "the card number"))
        }
        ItemType::Note | ItemType::Other => None,
    }
}
/// Find a field by name (case-insensitive).
pub fn find(fields: &[Field], name: &str) -> Option<usize> {
    fields.iter().position(|f| same_slot(f.name.expose(), name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colour_tokens_parse_strictly_and_automatic_keeps_other_icons() {
        assert_eq!(colour(Some("hue:0")), Some(0));
        assert_eq!(colour(Some("hue:11")), Some(11));
        for bad in [
            "hue:12", "hue:", "hue:+1", "hue:-1", "hue: 3", "hue:003", "Hue:3", "key", "",
        ] {
            assert_eq!(colour(Some(bad)), None, "{bad}");
        }
        assert_eq!(colour(None), None);
        assert_eq!(
            pick_colour(None, Some(4)).unwrap().as_deref(),
            Some("hue:4")
        );
        assert_eq!(
            pick_colour(Some("key"), Some(4)).unwrap().as_deref(),
            Some("hue:4")
        );
        assert!(pick_colour(None, Some(12)).is_err());
        assert_eq!(pick_colour(Some("hue:4"), None).unwrap(), None);
        assert_eq!(
            pick_colour(Some("key"), None).unwrap().as_deref(),
            Some("key")
        );
        assert_eq!(
            pick_colour(Some("hue:99"), None).unwrap().as_deref(),
            Some("hue:99")
        );
    }

    #[test]
    fn guesses_cards_sites_wifi_and_names_without_echoing_card_numbers() {
        let g = guess(b"  4242 4242 4242 4242 ").unwrap();
        assert_eq!(g.kind, ItemType::Card);
        assert_eq!(g.line.as_str(), "Visa ending 4242");
        assert_eq!(g.sub.as_str(), "The number checks out");
        assert!(!g.line.contains("4242 4242") && !g.sub.contains("4242"));
        assert!(matches!(&g.start, Start::Card(d) if d.as_slice() == b"4242424242424242"));
        let bad = guess(b"4242-4242-4242-4241").unwrap();
        assert_eq!(bad.kind, ItemType::Card);
        assert!(bad.sub.starts_with("This number does not check out"));
        assert_eq!(
            guess(b"5555555555554444").unwrap().line.as_str(),
            "Mastercard ending 4444"
        );
        assert_eq!(
            guess(b"378282246310005").unwrap().line.as_str(),
            "Amex ending 0005"
        );
        // Too short for a card: a name.
        assert_eq!(guess(b"12345").unwrap().kind, ItemType::Login);

        let g = guess(b"https://www.GitHub.com/login").unwrap();
        assert_eq!(g.kind, ItemType::Login);
        assert_eq!(g.line.as_str(), "Login for GitHub");
        assert!(matches!(&g.start, Start::Site(d) if d == "github.com"));
        assert_eq!(guess(b"bbc.co.uk").unwrap().line.as_str(), "Login for Bbc");
        assert_eq!(
            guess(b"mail.google.com").unwrap().line.as_str(),
            "Login for Google"
        );

        let g = guess(b"Home Wi-Fi").unwrap();
        assert_eq!(g.kind, ItemType::Wifi);
        assert!(matches!(&g.start, Start::Name(n) if n.as_str() == "Home Wi-Fi"));
        let g = guess(b"Library card").unwrap();
        assert_eq!(g.kind, ItemType::Login);
        assert_eq!(g.line.as_str(), "Login named “Library card”");
        assert!(guess(b"   ").is_none());
        assert!(guess(&[0xff, 0xfe]).is_none());
        assert!(domain("1.5").is_none() && domain("a..b").is_none() && domain("x").is_none());
    }

    #[test]
    fn card_info_shows_brand_last_four_and_validity_only() {
        let c = CardInfo::of(b"4242 4242 4242 4242");
        assert_eq!(c.brand, Some("Visa"));
        assert_eq!(c.last4.as_deref(), Some("4242"));
        assert_eq!(c.valid, Some(true));
        assert_eq!(c.title().as_deref(), Some("Visa ••4242"));
        let short = CardInfo::of(b"601");
        assert_eq!(short.last4, None);
        assert_eq!(short.valid, None);
        assert_eq!(short.title(), None);
        assert_eq!(
            CardInfo::of(b"9999 1234").title().as_deref(),
            Some("Card ••1234")
        );
        assert_eq!(CardInfo::of(b"not a number"), CardInfo::default());
        // Part-typed numbers are neither valid nor invalid yet.
        assert_eq!(CardInfo::of(b"4242 4242 4242 4").valid, None);
        assert_eq!(CardInfo::of(b"3782 822463 1000").valid, None);
        assert_eq!(CardInfo::of(b"3782 822463 10005").valid, Some(true));
        assert_eq!(CardInfo::of(b"4242 4242 4242 4241").valid, Some(false));
    }

    #[test]
    fn field_kinds_follow_the_name() {
        let k = |n: &str| kind_for(n);
        assert_eq!(k("Two-factor code"), (FieldKind::Totp, true));
        assert_eq!(k("2FA"), (FieldKind::Totp, true));
        assert_eq!(k("PIN"), (FieldKind::Secret, true));
        assert_eq!(k("Router admin password"), (FieldKind::Secret, true));
        assert_eq!(k("API key"), (FieldKind::Secret, true));
        assert_eq!(k("Recovery codes"), (FieldKind::Multiline, true));
        assert_eq!(k("Email"), (FieldKind::Email, false));
        assert_eq!(k("Website"), (FieldKind::Url, false));
        assert_eq!(k("Billing address"), (FieldKind::Multiline, false));
        assert_eq!(k("Pinecone"), (FieldKind::Text, false));
        assert_eq!(k("Account number"), (FieldKind::Text, false));
    }

    #[test]
    fn expiry_counts_months_from_the_given_month() {
        let now = (2026, 11);
        assert_eq!(expiry("12/28", now), Some(("2 yr left".into(), true)));
        assert_eq!(expiry("01 / 27", now), Some(("2 mo left".into(), false)));
        assert_eq!(expiry("02/2027", now), Some(("3 mo left".into(), true)));
        assert_eq!(
            expiry("11/26", now),
            Some(("Expires this month".into(), false))
        );
        assert_eq!(expiry("10/26", now), Some(("Expired".into(), false)));
        assert_eq!(expiry("13/30", now), Some(("Month 01–12".into(), false)));
        assert_eq!(expiry("1/2", now), None);
        assert_eq!(expiry("ab/cd", now), None);
        assert_eq!(expiry("1228", now), Some(("2 yr left".into(), true)));
        assert_eq!(expiry("122", now), None);
        assert_eq!(expiry_shown("1228"), "12/28");
        assert_eq!(expiry_shown("12 / 2028"), "12/28");
        assert_eq!(expiry_shown("soon"), "soon");
        let (y, m) = this_month();
        assert!(y >= 2024 && (1..=12).contains(&m));
    }

    #[test]
    fn wifi_payload_escapes_and_is_bounded() {
        let p = wifi_payload(br#"My;Net"#, Some(br#"a\b,c:d"e"#), "WPA2").unwrap();
        assert_eq!(
            p.expose_secret(),
            br#"WIFI:T:WPA;S:My\;Net;P:a\\b\,c\:d\"e;;"#
        );
        let open = wifi_payload(b"Cafe", Some(b"ignored"), "None").unwrap();
        assert_eq!(open.expose_secret(), b"WIFI:T:nopass;S:Cafe;;");
        let wep = wifi_payload(b"Old", Some(b"k"), "wep").unwrap();
        assert_eq!(wep.expose_secret(), b"WIFI:T:WEP;S:Old;P:k;;");
        assert!(matches!(
            wifi_payload(b"", Some(b"x"), "WPA2"),
            Err(AppError::InvalidInput)
        ));
        let long = vec![b';'; crate::qr::MAX_PAYLOAD / 2];
        assert!(matches!(
            wifi_payload(&long, None, "WPA3"),
            Err(AppError::TooLargeForApp)
        ));
    }

    #[test]
    fn item_types_round_trip_their_hints() {
        for t in ItemType::ALL {
            assert_eq!(ItemType::from_hint(t.hint()), Some(t));
        }
        assert_eq!(ItemType::from_hint("LOGIN"), Some(ItemType::Login));
        assert_eq!(ItemType::from_hint("ssh-key"), None);
        assert!(same_slot("url", "Website") && same_slot(" username ", "Username"));
    }
}
