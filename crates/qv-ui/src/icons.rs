// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault's own 16-unit stroke icons and logo (plan 0040), drawn as SVG
//! elements, never as markup text.
use leptos::prelude::*;
pub(crate) use qv_ui_api::Icon;

pub(crate) fn path(icon: Icon) -> &'static str {
    match icon {
        Icon::Lock => {
            "M5 7h6a1.5 1.5 0 0 1 1.5 1.5v3.5a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5V8.5A1.5 1.5 0 0 1 5 7zM5.5 7V5a2.5 2.5 0 0 1 5 0v2"
        }
        Icon::Search => "M11.5 7a4.5 4.5 0 1 1-9 0a4.5 4.5 0 1 1 9 0zM10.5 10.5L14 14",
        Icon::Plus => "M8 3v10M3 8h10",
        Icon::ChevronDown => "M4 6l4 4 4-4",
        Icon::Up => "M4 10l4-4 4 4",
        Icon::Right => "M6 4l4 4-4 4",
        Icon::Back => "M13 8H3M7 4L3 8l4 4",
        Icon::All => "M2.5 4.5h11M2.5 8h11M2.5 11.5h11",
        Icon::Key => {
            "M13.5 5.5a3 3 0 1 1-6 0a3 3 0 1 1 6 0zM8.4 7.6L2.5 13.5M4 12l1.6 1.6M5.6 10.4l1.2 1.2M11.2 4.8h.01"
        }
        Icon::Note => "M4 2.5h6l2.5 2.5v8.5H4zM10 2.5V5h2.5M6 8h4M6 10.5h4",
        Icon::Card => "M2 4.5h12v7H2zM2 7h12M4.5 9.5h2",
        Icon::Wifi => "M2 6.5a9 9 0 0 1 12 0M4 8.7a6 6 0 0 1 8 0M6 10.9a3 3 0 0 1 4 0M8 13h.01",
        Icon::Generator => {
            "M8 2.5v3M8 10.5v3M2.5 8h3M10.5 8h3M4.2 4.2l2 2M9.8 9.8l2 2M11.8 4.2l-2 2M6.2 9.8l-2 2"
        }
        Icon::Devices => {
            "M3 3.5h5a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1zM11 6h2a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1zM4 11.5h4"
        }
        Icon::Trash => "M3 4.5h10M6 4.5V3h4v1.5M4.5 4.5l.7 8.5h5.6l.7-8.5",
        Icon::Conflicts => "M3 5h8l-2-2M13 11H5l2 2",
        Icon::Settings => {
            "M10 8a2 2 0 1 1-4 0a2 2 0 1 1 4 0zM8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M12.2 3.8l-1.4 1.4M5.2 10.8l-1.4 1.4"
        }
        Icon::Copy => {
            "M7 5.5h5a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 12V7A1.5 1.5 0 0 1 7 5.5zM10.5 5.5V3.5a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"
        }
        Icon::User => {
            "M10.5 5.5a2.5 2.5 0 1 1-5 0a2.5 2.5 0 1 1 5 0zM3 13.5c.8-2.4 2.7-3.5 5-3.5s4.2 1.1 5 3.5"
        }
        Icon::Eye => {
            "M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8zM10 8a2 2 0 1 1-4 0a2 2 0 1 1 4 0z"
        }
        Icon::EyeOff => {
            "M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8zM2.5 2.5l11 11"
        }
        Icon::Edit => "M3 13l1-3.5 6.5-6.5 2.5 2.5L6.5 12z",
        Icon::More => "M4 8h.01M8 8h.01M12 8h.01",
        Icon::History => "M2.5 8a5.5 5.5 0 1 0 1.6-3.9M2.5 2.5v2.5h2.5M8 5.5V8l1.8 1.2",
        Icon::Attach => {
            "M10.5 5L6 9.5a1.5 1.5 0 0 0 2 2l5-5a3 3 0 0 0-4-4L4 7.5a4.5 4.5 0 0 0 6.5 6.5"
        }
        Icon::Move => {
            "M2.5 4.5a1 1 0 0 1 1-1h3l1.5 1.5h4.5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1zM6 9h4M8.5 7.5L10 9l-1.5 1.5"
        }
        Icon::Globe => {
            "M13.5 8a5.5 5.5 0 1 1-11 0a5.5 5.5 0 1 1 11 0zM2.5 8h11M8 2.5c1.6 1.6 2.3 3.5 2.3 5.5S9.6 11.9 8 13.5C6.4 11.9 5.7 10 5.7 8S6.4 4.1 8 2.5"
        }
        Icon::Sun => {
            "M10.5 8a2.5 2.5 0 1 1-5 0a2.5 2.5 0 1 1 5 0zM8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M12.6 3.4l-1 1M4.4 11.6l-1 1"
        }
        Icon::Moon => "M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5z",
        Icon::Minimize => "M4 8.5h8",
        Icon::Maximize => "M4.5 4.5h7v7h-7z",
        Icon::Close => "M4.5 4.5l7 7M11.5 4.5l-7 7",
        Icon::Shield => "M8 2l5 2v4c0 3-2.2 5.2-5 6-2.8-.8-5-3-5-6V4z",
        Icon::Check => "M3.5 8.5l3 3 6-7",
        Icon::Finger => {
            "M5 13c-1-1.5-1.5-3-1.5-5a4.5 4.5 0 0 1 9 0c0 1-.1 2-.3 3M8 8c0 2-.5 4-1.5 5.5M10.5 9.5c-.2 1.5-.6 2.8-1.2 4M6 8a2 2 0 0 1 4 0"
        }
        Icon::File => "M4 2.5h5.5L12 5v8.5H4zM9.5 2.5V5H12",
        Icon::Folder => {
            "M2.5 4.5a1 1 0 0 1 1-1h3l1.5 1.5h4.5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1z"
        }
        Icon::Refresh => "M13 3v3h-3M3 13v-3h3M12.4 6A5 5 0 0 0 3.5 5.2M3.6 10a5 5 0 0 0 8.9.8",
        Icon::Qr => {
            "M2.5 2.5h4v4h-4zM9.5 2.5h4v4h-4zM2.5 9.5h4v4h-4zM9.5 9.5h1.5M12.5 9.5h1v1M9.5 12h1.5v1.5M12.5 12.5h1v1"
        }
        Icon::Warn => "M8 2.5l6 10.5H2zM8 6.5v3M8 11h.01",
        Icon::Archive => {
            "M3.5 3h9a1 1 0 0 1 1 1v1a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zM3.5 6v6.5h9V6M6.5 9h3"
        }
        Icon::Clock => "M13.5 8a5.5 5.5 0 1 1-11 0a5.5 5.5 0 1 1 11 0zM8 5v3l2 1.5",
        Icon::Restore => "M3 8a5 5 0 1 0 1.5-3.5M3 2.5V5h2.5",
        Icon::Palette => "M3.5 3.5h9v9h-9zM3.5 6.5h9",
        Icon::Play => "M5 3.2v9.6L12.5 8z",
        Icon::Pause => "M5.5 3.5v9M10.5 3.5v9",
        Icon::Volume => {
            "M2.5 6h2.5l3.5-3v10L5 10H2.5zM11 5.5a3.5 3.5 0 0 1 0 5M12.8 3.7a6 6 0 0 1 0 8.6"
        }
        Icon::Muted => "M2.5 6h2.5l3.5-3v10L5 10H2.5zM11 6l3.5 4M14.5 6L11 10",
        Icon::Expand => "M2.5 6V2.5H6M10 2.5h3.5V6M13.5 10v3.5H10M6 13.5H2.5V10",
        Icon::Shrink => "M6 2.5V6H2.5M13.5 6H10V2.5M10 13.5V10h3.5M2.5 10H6v3.5",
    }
}

/// The official mark (`docs/logo/logo.svg`, plan 0054): a vault door with
/// two hinges whose combination dial is cut out and turned so the ring and a
/// short rounded tail crossing it form a Q, on a charcoal tile. Its colours
/// are fixed in both themes.
struct LogoArt {
    /// The two hinges.
    hinges: &'static str,
    /// The door with the dial cut out, filled even-odd: the door, the outer
    /// and inner edges of the ring-and-tail cut, and the hub.
    door: &'static str,
}
const LOGO: LogoArt = LogoArt {
    hinges: "M100 156H112A14 14 0 0 1 126 170V202A14 14 0 0 1 112 216H100A14 14 0 0 1 86 202V170A14 14 0 0 1 100 156ZM100 296H112A14 14 0 0 1 126 310V342A14 14 0 0 1 112 356H100A14 14 0 0 1 86 342V310A14 14 0 0 1 100 296Z",
    door: "M182 104H350A72 72 0 0 1 422 176V336A72 72 0 0 1 350 408H182A72 72 0 0 1 110 336V176A72 72 0 0 1 182 104ZM348.76 310.33L357.04 317.79A15 15 0 0 1 336.97 340.08L328.68 332.63A99 99 0 1 1 348.76 310.33ZM326.09 289.92L324.34 288.35A15 15 0 0 0 304.27 310.64L306.01 312.21A69 69 0 1 1 326.09 289.92ZM240 256a26 26 0 1 0 52 0a26 26 0 1 0 -52 0Z",
};
/// `docs/logo/logo-small.svg`: 32 px and below, with a heavier ring, tail and hub.
const LOGO_SMALL: LogoArt = LogoArt {
    hinges: "M100 156H112A14 14 0 0 1 126 170V202A14 14 0 0 1 112 216H100A14 14 0 0 1 86 202V170A14 14 0 0 1 100 156ZM100 296H112A14 14 0 0 1 126 310V342A14 14 0 0 1 112 356H100A14 14 0 0 1 86 342V310A14 14 0 0 1 100 296Z",
    door: "M182 104H350A72 72 0 0 1 422 176V336A72 72 0 0 1 350 408H182A72 72 0 0 1 110 336V176A72 72 0 0 1 182 104ZM355.23 309.43L361.13 314.74A20 20 0 0 1 334.36 344.47L328.46 339.15A104 104 0 1 1 355.23 309.43ZM324.56 281.82L323.97 281.28A20 20 0 0 0 297.21 311.01L297.8 311.54A64 64 0 1 1 324.56 281.82ZM236 256a30 30 0 1 0 60 0a30 30 0 1 0 -60 0Z",
};

/// The QuickVault logo. Decorative: the name is always shown next to it.
/// `small` selects the cut drawn for 32 px and below.
#[component]
pub(crate) fn Logo(class: &'static str, #[prop(optional)] small: bool) -> impl IntoView {
    let art = if small { &LOGO_SMALL } else { &LOGO };
    view! {
        <svg class=format!("logo {class}") viewBox="0 0 512 512" aria-hidden="true" focusable="false">
            <rect width="512" height="512" rx="112" fill="#0E1113"></rect>
            <path fill="#43D4A4" d=art.hinges></path>
            <path fill="#43D4A4" fill-rule="evenodd" d=art.door></path>
        </svg>
    }
}

/// A decorative icon; the surrounding control carries the accessible name.
#[component]
pub(crate) fn Svg(icon: Icon, #[prop(optional)] large: bool) -> impl IntoView {
    view! {
        <svg class=if large { "ico lg" } else { "ico" } viewBox="0 0 16 16" aria-hidden="true" focusable="false">
            <path d=path(icon)></path>
        </svg>
    }
}

/// The icons as a view, for children of a reactive match.
pub(crate) fn svg(icon: Icon) -> impl IntoView {
    view! { <Svg icon/> }
}

/// A glyph: an icon or a monogram.
pub(crate) fn glyph(g: &qv_ui_api::Glyph) -> AnyView {
    match g {
        qv_ui_api::Glyph::Icon(i) => view! { <Svg icon=*i large=true/> }.into_any(),
        qv_ui_api::Glyph::Letter(l) => l.clone().into_any(),
    }
}
