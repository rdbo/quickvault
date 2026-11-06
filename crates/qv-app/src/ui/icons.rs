// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault's own 16-unit stroke icons (plan 0040). Paths are constants
//! drawn for this app and rendered as SVG elements, never as markup text.
use dioxus::prelude::*;

/// The icon set. Window-control and theme icons appear only in the desktop
/// title bar, so Android builds do not construct them.
#[cfg_attr(target_os = "android", allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Icon {
    Lock,
    Search,
    Plus,
    ChevronDown,
    Up,
    Right,
    Back,
    All,
    Key,
    Note,
    Card,
    Wifi,
    Generator,
    Devices,
    Trash,
    Conflicts,
    Settings,
    Copy,
    User,
    Eye,
    EyeOff,
    Edit,
    More,
    History,
    Attach,
    Move,
    Globe,
    Sun,
    Moon,
    Minimize,
    Maximize,
    Close,
    Shield,
    Check,
    Finger,
    File,
    Folder,
    Refresh,
    Qr,
    Warn,
    Archive,
    Clock,
    Restore,
    Palette,
}
impl Icon {
    fn path(self) -> &'static str {
        match self {
            Self::Lock => {
                "M5 7h6a1.5 1.5 0 0 1 1.5 1.5v3.5a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5V8.5A1.5 1.5 0 0 1 5 7zM5.5 7V5a2.5 2.5 0 0 1 5 0v2"
            }
            Self::Search => "M11.5 7a4.5 4.5 0 1 1-9 0a4.5 4.5 0 1 1 9 0zM10.5 10.5L14 14",
            Self::Plus => "M8 3v10M3 8h10",
            Self::ChevronDown => "M4 6l4 4 4-4",
            Self::Up => "M4 10l4-4 4 4",
            Self::Right => "M6 4l4 4-4 4",
            Self::Back => "M13 8H3M7 4L3 8l4 4",
            Self::All => "M2.5 4.5h11M2.5 8h11M2.5 11.5h11",
            Self::Key => {
                "M10.5 2.5a3 3 0 1 1-2.6 4.5L3 11.9V13.5h1.6l.4-.4V12h1.1l.6-.6V10.3h1.1l1.1-1.1A3 3 0 0 1 10.5 2.5zM11 5h.01"
            }
            Self::Note => "M4 2.5h6l2.5 2.5v8.5H4zM10 2.5V5h2.5M6 8h4M6 10.5h4",
            Self::Card => "M2 4.5h12v7H2zM2 7h12M4.5 9.5h2",
            Self::Wifi => "M2 6.5a9 9 0 0 1 12 0M4 8.7a6 6 0 0 1 8 0M6 10.9a3 3 0 0 1 4 0M8 13h.01",
            Self::Generator => {
                "M8 2.5v3M8 10.5v3M2.5 8h3M10.5 8h3M4.2 4.2l2 2M9.8 9.8l2 2M11.8 4.2l-2 2M6.2 9.8l-2 2"
            }
            Self::Devices => {
                "M3 3.5h5a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1zM11 6h2a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1zM4 11.5h4"
            }
            Self::Trash => "M3 4.5h10M6 4.5V3h4v1.5M4.5 4.5l.7 8.5h5.6l.7-8.5",
            Self::Conflicts => "M3 5h8l-2-2M13 11H5l2 2",
            Self::Settings => {
                "M10 8a2 2 0 1 1-4 0a2 2 0 1 1 4 0zM8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M12.2 3.8l-1.4 1.4M5.2 10.8l-1.4 1.4"
            }
            Self::Copy => {
                "M7 5.5h5a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 12V7A1.5 1.5 0 0 1 7 5.5zM10.5 5.5V3.5a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"
            }
            Self::User => {
                "M10.5 5.5a2.5 2.5 0 1 1-5 0a2.5 2.5 0 1 1 5 0zM3 13.5c.8-2.4 2.7-3.5 5-3.5s4.2 1.1 5 3.5"
            }
            Self::Eye => {
                "M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8zM10 8a2 2 0 1 1-4 0a2 2 0 1 1 4 0z"
            }
            Self::EyeOff => {
                "M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8zM2.5 2.5l11 11"
            }
            Self::Edit => "M3 13l1-3.5 6.5-6.5 2.5 2.5L6.5 12z",
            Self::More => "M4 8h.01M8 8h.01M12 8h.01",
            Self::History => "M2.5 8a5.5 5.5 0 1 0 1.6-3.9M2.5 2.5v2.5h2.5M8 5.5V8l1.8 1.2",
            Self::Attach => {
                "M10.5 5L6 9.5a1.5 1.5 0 0 0 2 2l5-5a3 3 0 0 0-4-4L4 7.5a4.5 4.5 0 0 0 6.5 6.5"
            }
            Self::Move => {
                "M2.5 4.5a1 1 0 0 1 1-1h3l1.5 1.5h4.5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1zM6 9h4M8.5 7.5L10 9l-1.5 1.5"
            }
            Self::Globe => {
                "M13.5 8a5.5 5.5 0 1 1-11 0a5.5 5.5 0 1 1 11 0zM2.5 8h11M8 2.5c1.6 1.6 2.3 3.5 2.3 5.5S9.6 11.9 8 13.5C6.4 11.9 5.7 10 5.7 8S6.4 4.1 8 2.5"
            }
            Self::Sun => {
                "M10.5 8a2.5 2.5 0 1 1-5 0a2.5 2.5 0 1 1 5 0zM8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M12.6 3.4l-1 1M4.4 11.6l-1 1"
            }
            Self::Moon => "M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5z",
            Self::Minimize => "M4 8.5h8",
            Self::Maximize => "M4.5 4.5h7v7h-7z",
            Self::Close => "M4.5 4.5l7 7M11.5 4.5l-7 7",
            Self::Shield => "M8 2l5 2v4c0 3-2.2 5.2-5 6-2.8-.8-5-3-5-6V4z",
            Self::Check => "M3.5 8.5l3 3 6-7",
            Self::Finger => {
                "M5 13c-1-1.5-1.5-3-1.5-5a4.5 4.5 0 0 1 9 0c0 1-.1 2-.3 3M8 8c0 2-.5 4-1.5 5.5M10.5 9.5c-.2 1.5-.6 2.8-1.2 4M6 8a2 2 0 0 1 4 0"
            }
            Self::File => "M4 2.5h5.5L12 5v8.5H4zM9.5 2.5V5H12",
            Self::Folder => {
                "M2.5 4.5a1 1 0 0 1 1-1h3l1.5 1.5h4.5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1z"
            }
            Self::Refresh => "M13 3v3h-3M3 13v-3h3M12.4 6A5 5 0 0 0 3.5 5.2M3.6 10a5 5 0 0 0 8.9.8",
            Self::Qr => {
                "M2.5 2.5h4v4h-4zM9.5 2.5h4v4h-4zM2.5 9.5h4v4h-4zM9.5 9.5h1.5M12.5 9.5h1v1M9.5 12h1.5v1.5M12.5 12.5h1v1"
            }
            Self::Warn => "M8 2.5l6 10.5H2zM8 6.5v3M8 11h.01",
            Self::Archive => {
                "M3.5 3h9a1 1 0 0 1 1 1v1a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zM3.5 6v6.5h9V6M6.5 9h3"
            }
            Self::Clock => "M13.5 8a5.5 5.5 0 1 1-11 0a5.5 5.5 0 1 1 11 0zM8 5v3l2 1.5",
            Self::Restore => "M3 8a5 5 0 1 0 1.5-3.5M3 2.5V5h2.5",
            Self::Palette => "M3.5 3.5h9v9h-9zM3.5 6.5h9",
        }
    }
}

/// A decorative icon; the surrounding control carries the accessible name.
#[component]
pub(crate) fn Svg(icon: Icon, #[props(default)] large: bool) -> Element {
    rsx! {
        svg { class: if large { "ico lg" } else { "ico" }, view_box: "0 0 16 16", "aria-hidden": "true", "focusable": "false",
            path { d: icon.path() }
        }
    }
}

/// The icon for an entry type hint.
pub(crate) fn kind_icon(kind: &str) -> Icon {
    match kind {
        "login" | "password" | "account" => Icon::Key,
        "note" | "notes" | "secure note" => Icon::Note,
        "card" | "credit card" | "payment" => Icon::Card,
        "wifi" | "wi-fi" | "network" => Icon::Wifi,
        _ => Icon::File,
    }
}

/// A stable colour for a vault item, from its random record ID (hex), so
/// renaming keeps it and synced devices agree.
const HUES: [&str; 12] = [
    "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11",
];
/// The tile class of a colour token's number (0–11).
pub(crate) fn hue_class(n: u8) -> &'static str {
    HUES[usize::from(n) % HUES.len()]
}
/// An item's tile colour: the one the user chose (0003 §5.5), else the
/// automatic colour from its record ID.
pub(crate) fn item_hue(colour: Option<u8>, id_hex: &str) -> &'static str {
    colour.map_or_else(|| id_hue(id_hex), hue_class)
}
/// The colour of an item type's start tile.
pub(crate) fn type_hue(kind: crate::editor::ItemType) -> &'static str {
    use crate::editor::ItemType;
    match kind {
        ItemType::Login => "h6",
        ItemType::Card => "h7",
        ItemType::Wifi => "h5",
        ItemType::Note => "h2",
        ItemType::Other => "h11",
    }
}
pub(crate) fn id_hue(id_hex: &str) -> &'static str {
    let byte = id_hex
        .get(..4)
        .and_then(|h| u16::from_str_radix(h, 16).ok())
        .unwrap_or(0);
    HUES[usize::from(byte) % 12]
}

/// A title's monogram letter, as text.
pub(crate) fn initial(title: &str) -> String {
    title
        .chars()
        .find(|c| !c.is_whitespace())
        .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect())
}

#[cfg(test)]
mod tests {
    use super::{id_hue, item_hue};

    #[test]
    fn id_hue_depends_only_on_the_record_id() {
        let id = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        assert_eq!(id_hue(id), id_hue(id));
        // 0xa1b2 % 12 == 6
        assert_eq!(id_hue(id), "h6");
        assert_eq!(id_hue("000c0000000000000000000000000000"), "h0");
        // Malformed or short IDs fall back instead of panicking.
        assert_eq!(id_hue(""), "h0");
        assert_eq!(id_hue("zz"), "h0");
    }

    #[test]
    fn a_chosen_colour_wins_over_the_automatic_one() {
        let id = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        assert_eq!(item_hue(None, id), "h6");
        assert_eq!(item_hue(Some(3), id), "h3");
        assert_eq!(item_hue(Some(11), ""), "h11");
    }
}
