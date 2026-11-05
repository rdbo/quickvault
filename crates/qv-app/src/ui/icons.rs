// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault's own 16-unit stroke icons (plan 0040). Paths are constants
//! drawn for this app and rendered as SVG elements, never as markup text.
use dioxus::prelude::*;

/// The icon set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Icon {
    Lock,
    Search,
    Plus,
    Folder,
    Vault,
    Generator,
    Trash,
    Conflicts,
    Snapshots,
    History,
    Archives,
    Devices,
    Settings,
    Edit,
    Attach,
    Copy,
    Eye,
    EyeOff,
    Back,
    Chevron,
    More,
    Check,
    Move,
}
impl Icon {
    fn path(self) -> &'static str {
        match self {
            Self::Lock => {
                "M5 7h6a1.5 1.5 0 0 1 1.5 1.5v3.5a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5V8.5A1.5 1.5 0 0 1 5 7zM5.5 7V5a2.5 2.5 0 0 1 5 0v2"
            }
            Self::Search => "M11.5 7a4.5 4.5 0 1 1-9 0a4.5 4.5 0 1 1 9 0zM10.5 10.5L14 14",
            Self::Plus => "M8 3v10M3 8h10",
            Self::Folder => {
                "M2.5 4.5a1 1 0 0 1 1-1h3l1.5 1.5h4.5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1z"
            }
            Self::Vault => "M2.5 4.5h11M2.5 8h11M2.5 11.5h11",
            Self::Generator => {
                "M8 2.5v3M8 10.5v3M2.5 8h3M10.5 8h3M4.2 4.2l2 2M9.8 9.8l2 2M11.8 4.2l-2 2M6.2 9.8l-2 2"
            }
            Self::Trash => "M3 4.5h10M6 4.5V3h4v1.5M4.5 4.5l.7 8.5h5.6l.7-8.5",
            Self::Conflicts => "M3 5h8l-2-2M13 11H5l2 2",
            Self::Snapshots => "M13.5 8a5.5 5.5 0 1 1-11 0a5.5 5.5 0 1 1 11 0zM8 5v3l2 1.5",
            Self::History => "M2.5 8a5.5 5.5 0 1 0 1.6-3.9M2.5 2.5v2.5h2.5M8 5.5V8l1.8 1.2",
            Self::Archives => {
                "M3.5 3h9a1 1 0 0 1 1 1v1a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zM3.5 6v6.5h9V6M6.5 9h3"
            }
            Self::Devices => {
                "M3 3.5h5a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1zM11 6h2a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1zM4 11.5h4"
            }
            Self::Settings => {
                "M10 8a2 2 0 1 1-4 0a2 2 0 1 1 4 0zM8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M12.2 3.8l-1.4 1.4M5.2 10.8l-1.4 1.4"
            }
            Self::Edit => "M3 13l1-3.5 6.5-6.5 2.5 2.5L6.5 12z",
            Self::Attach => {
                "M10.5 5L6 9.5a1.5 1.5 0 0 0 2 2l5-5a3 3 0 0 0-4-4L4 7.5a4.5 4.5 0 0 0 6.5 6.5"
            }
            Self::Copy => {
                "M7 5.5h5a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 12V7A1.5 1.5 0 0 1 7 5.5zM10.5 5.5V3.5a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"
            }
            Self::Eye => {
                "M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8zM10 8a2 2 0 1 1-4 0a2 2 0 1 1 4 0z"
            }
            Self::EyeOff => {
                "M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8zM2.5 2.5l11 11"
            }
            Self::Back => "M13 8H3M7 4L3 8l4 4",
            Self::Chevron => "M6 4l4 4-4 4",
            Self::More => "M3 3h4v4H3zM9 3h4v4H9zM3 9h4v4H3zM9 9h4v4H9z",
            Self::Check => "M3.5 8.5l3 3 6-7",
            Self::Move => {
                "M2.5 4.5a1 1 0 0 1 1-1h3l1.5 1.5h4.5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1zM6 9h4M8.5 7.5L10 9l-1.5 1.5"
            }
        }
    }
}

/// A decorative icon; the surrounding control carries the accessible name.
#[component]
pub(crate) fn Svg(icon: Icon) -> Element {
    rsx! {
        svg { class: "ico", view_box: "0 0 16 16", "aria-hidden": "true", "focusable": "false",
            path { d: icon.path() }
        }
    }
}
