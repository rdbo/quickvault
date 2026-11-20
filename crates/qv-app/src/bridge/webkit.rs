// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebKitGTK settings and handlers that Tauri does not expose (Linux), as
//! the hardened Dioxus webview had them (0008 §4; plans 0057, 0069, 0071):
//! no permission, file-chooser or authentication prompts, no web storage,
//! page cache, hyperlink auditing or developer extras, no element full
//! screen (WEBKIT.md W6), and a context menu only in editable fields, with
//! editing actions only.
use webkit2gtk::{
    AuthenticationRequestExt, ContextMenuAction, ContextMenuExt, ContextMenuItemExt,
    FileChooserRequestExt, HitTestResultExt, PermissionRequestExt, SettingsExt, WebViewExt,
};

/// Applies the settings and handlers to the app's webview.
pub(super) fn harden(view: &webkit2gtk::WebView) {
    view.connect_context_menu(|_, menu, _, hit| editing_menu(menu, hit));
    view.connect_permission_request(|_, request| {
        request.deny();
        true
    });
    view.connect_run_file_chooser(|_, request| {
        request.cancel();
        true
    });
    view.connect_authenticate(|_, request| {
        request.cancel();
        true
    });
    if let Some(settings) = view.settings() {
        settings.set_enable_html5_database(false);
        settings.set_enable_html5_local_storage(false);
        settings.set_enable_page_cache(false);
        settings.set_enable_hyperlink_auditing(false);
        settings.set_enable_developer_extras(false);
        // Native video full screen draws black here; the app offers window
        // full screen instead (WEBKIT.md W6).
        settings.set_enable_fullscreen(false);
    }
}

/// Context menu items kept in editable fields (plan 0069): select-all,
/// delete and paste, which pasting needs. Copy and cut stay cancelled by the
/// page, so copies go through the app's clearing clipboard. Everything else
/// (reload, inspect, links, spelling, input methods) is removed.
fn editing_menu_action(action: ContextMenuAction) -> bool {
    matches!(
        action,
        ContextMenuAction::Paste | ContextMenuAction::Delete | ContextMenuAction::SelectAll
    )
}

/// Applies [`editing_menu_action`]: the menu is suppressed (`true`) unless
/// the target is editable and an allowed item remains.
fn editing_menu(menu: &webkit2gtk::ContextMenu, hit: &webkit2gtk::HitTestResult) -> bool {
    if !hit.context_is_editable() {
        return true;
    }
    for item in menu.items() {
        if item.is_separator() || !editing_menu_action(item.stock_action()) {
            menu.remove(&item);
        }
    }
    menu.items().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    // 0012 §1: Webview exposure
    #[test]
    fn editing_menu_keeps_only_paste_delete_and_select_all() {
        use ContextMenuAction as A;
        for allowed in [A::Paste, A::Delete, A::SelectAll] {
            assert!(editing_menu_action(allowed));
        }
        for refused in [
            A::Copy,
            A::Cut,
            A::Reload,
            A::InspectElement,
            A::OpenLink,
            A::CopyLinkToClipboard,
            A::OpenImageInNewWindow,
            A::SpellingGuess,
            A::InputMethods,
            A::Unicode,
            A::NoAction,
            A::Custom,
        ] {
            assert!(!editing_menu_action(refused), "{refused:?}");
        }
    }
}
