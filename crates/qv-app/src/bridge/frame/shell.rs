// SPDX-License-Identifier: AGPL-3.0-or-later

//! The unlocked shell: sidebar, content, tabs, toasts, confirmations.
use super::{Ctx, convert, items, pages};
use crate::controller::View;
use crate::page_read::{Lane, Rows, Spec};
use crate::workspace::{ConfirmKind, Pane, Screen, WsField};
use qv_ui_api as api;
use qv_ui_api::{Icon, Z};
use zeroize::Zeroizing;

pub(super) fn shell(ctx: &mut Ctx<'_>, view: &View) -> api::Shell {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let screen = c.screen(epoch).unwrap_or(Screen::Browse(None));
    let overview = ctx
        .hooks
        .last("shell.overview", c.read(epoch, crate::views::overview))
        .and_then(Result::ok);
    let root = ctx
        .hooks
        .last("shell.root", c.read(epoch, |s| s.root()))
        .and_then(Result::ok);
    let (_, group_read) = ctx.hooks.page(
        c,
        epoch,
        "shell.groups",
        Lane::Groups,
        0,
        Spec::Groups {
            parent: root,
            query: Zeroizing::new(String::new()),
        },
    );
    let (_, kind_read) = ctx
        .hooks
        .page(c, epoch, "shell.kinds", Lane::Overlay, 0, Spec::Kinds);
    let group_page = group_read.as_ref().and_then(|r| r.page.clone());
    let groups: Vec<crate::views::GroupRow> = match group_page.as_deref().map(|p| &p.rows) {
        Some(Rows::Groups(groups)) => groups.clone(),
        _ => Vec::new(),
    };
    if let Some(Rows::Kinds(kinds)) = kind_read
        .as_ref()
        .and_then(|r| r.page.as_deref())
        .map(|p| &p.rows)
    {
        let mut counts = [0; 5];
        for row in kinds {
            if let Some(i) = qv_core::TYPE_BUCKETS
                .iter()
                .position(|b| *b == row.kind.as_str())
            {
                counts[i] = row.count;
            }
        }
        ctx.hooks.counts = Some(counts);
    }
    let counts = ctx.hooks.counts;
    let recovered = overview.as_ref().map_or(0, |o| o.recovered);
    let total = overview.as_ref().map_or(0, |o| o.entries);
    let context = c.list_context(epoch).unwrap_or(Screen::Browse(None));
    let vault_screen = screen.is_list() || screen.is_vault_detail();
    let (notice, error, report) = c.status(epoch).unwrap_or((None, None, None));
    let undo = c.peek(epoch, |ws| ws.undo.clone()).flatten();
    let pending = c.pending(epoch);
    let busy = view.busy;
    let new_in = match &context {
        Screen::Browse(Some(g)) => Some(*g),
        _ => root,
    };
    let section_on = |s: &Screen| match (s, &screen) {
        (Screen::Settings(_), Screen::Settings(_) | Screen::More) => true,
        (Screen::Conflicts, Screen::ConflictRecord(_)) => true,
        (a, b) => a == b,
    };
    let tab_on = |t: &Screen| match t {
        Screen::Browse(_) => vault_screen,
        Screen::Settings(_) => matches!(
            screen,
            Screen::Settings(_)
                | Screen::More
                | Screen::Trash
                | Screen::Conflicts
                | Screen::ConflictRecord(_)
                | Screen::Snapshots
                | Screen::Archives
                | Screen::Autofill
        ),
        other => *other == screen,
    };
    let trash = overview.as_ref().map_or(0, |o| o.trash);
    let conflicts = overview.as_ref().map_or(0, |o| o.conflicts);
    let types = crate::editor::ItemType::ALL
        .iter()
        .map(|t| {
            let k = qv_core::type_bucket(t.hint());
            let target = Screen::Kind(Zeroizing::new(k.to_owned()));
            api::TypeNav {
                kind: k.to_owned(),
                label: convert::kind_label(k),
                on: vault_screen && context == target,
                count: counts
                    .zip(qv_core::TYPE_BUCKETS.iter().position(|b| *b == k))
                    .map(|(c, i)| c[i]),
                icon: convert::kind_icon(k),
            }
        })
        .collect();
    let group_navs = groups
        .iter()
        .map(|g| api::GroupNav {
            id: ctx.refs.issue(super::super::refs::Target::Group(g.handle)),
            name: Z::from(g.name.clone()),
            hue: convert::item_hue(g.colour, &g.handle.id_hex()).to_owned(),
            entries: g.entries,
            on: vault_screen && context == Screen::Browse(Some(g.handle)),
        })
        .collect();
    let tools = [
        (
            Screen::Generator,
            "Generator",
            Icon::Generator,
            "nav-generator",
            0usize,
        ),
        (Screen::Devices, "Sync", Icon::Refresh, "nav-devices", 0),
        (Screen::Trash, "Trash", Icon::Trash, "nav-trash", trash),
        (
            Screen::Conflicts,
            "Conflicts",
            Icon::Conflicts,
            "nav-conflicts",
            conflicts,
        ),
    ]
    .into_iter()
    .filter(|(_, label, _, _, count)| {
        *label != "Conflicts" || *count > 0 || screen == Screen::Conflicts
    })
    .filter_map(|(target, label, icon, id, count)| {
        Some(api::ToolNav {
            on: section_on(&target),
            target: convert::screen(ctx.refs, &target)?,
            label: label.to_owned(),
            icon,
            id: id.to_owned(),
            count,
        })
    })
    .collect();
    let sidebar = api::Sidebar {
        total,
        all_on: vault_screen && context == Screen::Browse(None),
        types,
        kind_error: kind_read
            .as_ref()
            .and_then(|r| r.error)
            .map(|e| e.message().to_owned()),
        root: root.map(|r| ctx.refs.issue(super::super::refs::Target::Group(r))),
        groups: group_navs,
        group_page: Ctx::page_nav("shell.groups", group_read.as_ref()),
        recovered,
        recovered_on: vault_screen && context == Screen::Recovered,
        tools,
        settings_on: section_on(&Screen::Settings(Pane::Overview)),
    };
    let content = if vault_screen {
        api::Content::Vault {
            list: Box::new(items::list_pane(
                ctx, view, &context, &screen, conflicts, &groups,
            )),
            detail: Box::new(items::detail(ctx, view, &screen, report.clone())),
        }
    } else {
        api::Content::Page(Box::new(pages::page(ctx, view, &screen, report.clone())))
    };
    let lan = pages::lan(ctx);
    let viewer = items::viewer(ctx);
    let palette = palette(ctx, root);
    if !vault_screen {
        ctx.ui.copy_menu = None;
        ctx.ui.row_menu = None;
        ctx.ui.group_menu = false;
        ctx.ui.bar_pop = None;
    }
    let confirm = pending.filter(|_| !busy).map(|kind| {
        confirm(
            kind,
            view.live.weak_seconds,
            c.peek(epoch, |ws| ws.pending_keep()).unwrap_or(false),
        )
    });
    let toasts = api::Toasts {
        clipboard: view.live.clipboard,
        error: error.map(|e| e.message().to_owned()),
        notice: notice.map(str::to_owned),
        undo: undo
            .filter(|_| notice.is_some())
            .map(|u| super::super::dispatch::undo(ctx.refs, &u)),
    };
    let lan_shown = c.lan_view(epoch).is_some();
    api::Shell {
        revision: view.revision,
        busy,
        busy_shown: view.busy_shown,
        scanning: view.scanning,
        scanning_totp: view.scanning && c.entry_form(epoch).is_some_and(|f| f.totp_sheet.is_some()),
        live: api::Live {
            reveal_left: view.live.reveal_left,
            clipboard: view.live.clipboard,
            weak_seconds: view.live.weak_seconds,
        },
        fixture_banner: super::locked::is_fixture(c) && cfg!(target_os = "android"),
        anchor_warning: overview.as_ref().is_some_and(|o| o.anchor_warning),
        vault_screen,
        inert: pending.is_some(),
        sidebar,
        content,
        fab: vault_screen && screen.is_list() && !busy,
        tabs: [
            tab_on(&Screen::Browse(None)),
            tab_on(&Screen::Generator),
            tab_on(&Screen::Devices),
            tab_on(&Screen::Settings(Pane::Overview)),
        ],
        busy_toast: view.busy_shown && !lan_shown && !view.scanning,
        lan,
        cards: cards(ctx),
        viewer,
        confirm,
        toasts,
        palette,
        new_in: new_in.map(|g| ctx.refs.issue(super::super::refs::Target::Group(g))),
        root: root.map(|g| ctx.refs.issue(super::super::refs::Target::Group(g))),
        light: c.theme() == crate::prefs::Theme::Light,
    }
}

/// The phone vault sheet's data.
fn cards(ctx: &mut Ctx<'_>) -> api::VaultCards {
    let c = ctx.c;
    let vaults = c.vaults();
    let current = c.open_vault().map(|v| v.path);
    let editing = c.screen(ctx.epoch).is_some_and(|s| s.is_form());
    let quick: Vec<bool> = vaults
        .iter()
        .map(|v| current.as_ref() != Some(&v.path) && v.exists && c.quick_ready_for(&v.path))
        .collect();
    let open_quick = c.quick_open();
    api::VaultCards {
        vaults: vaults
            .iter()
            .zip(quick)
            .map(|(v, q)| {
                let on = current.as_ref() == Some(&v.path);
                convert::vault_choice(ctx.refs, v, on, q)
            })
            .collect(),
        open_quick,
        editing,
    }
}

/// The command bar's reads, while it is open.
fn palette(ctx: &mut Ctx<'_>, root: Option<qv_core::GroupHandle>) -> Option<api::Palette> {
    let _ = root;
    if !ctx.ui.palette {
        return None;
    }
    let c = ctx.c;
    let epoch = ctx.epoch;
    let query = c
        .peek(epoch, |ws| {
            String::from_utf8_lossy(ws.input(WsField::Command)).into_owned()
        })
        .map(Zeroizing::new)
        .unwrap_or_default();
    let (_, read) = ctx.hooks.page(
        c,
        epoch,
        "palette",
        Lane::Overlay,
        2,
        Spec::Search(query.clone()),
    );
    let page = read.as_ref().and_then(|r| r.page.clone());
    let (groups, hits) = match page.as_deref().map(|p| &p.rows) {
        Some(Rows::Search { groups, entries }) => (groups.clone(), entries.clone()),
        _ => (Vec::new(), Vec::new()),
    };
    Some(api::Palette {
        query: Z::from(query),
        hits: hits
            .iter()
            .map(|e| api::Hit {
                id: ctx.refs.issue(super::super::refs::Target::Entry(e.handle)),
                hue: convert::item_hue(e.colour, &e.handle.id_hex()).to_owned(),
                glyph: convert::entry_glyph(e.kind, &e.title),
                title: Z::from(e.title.clone()),
                sub: Z::from(e.subtitle.clone()),
            })
            .collect(),
        groups: groups
            .iter()
            .map(|g| {
                (
                    ctx.refs.issue(super::super::refs::Target::Group(g.handle)),
                    Z::from(g.name.clone()),
                )
            })
            .collect(),
        page: Ctx::page_nav("palette", read.as_ref()),
    })
}

/// A confirmation's texts.
fn confirm(kind: ConfirmKind, seconds: u64, keep: bool) -> api::Confirm {
    let holding = match kind {
        ConfirmKind::EmptyTrash(n)
        | ConfirmKind::PurgeExpired(_, n)
        | ConfirmKind::PurgeHistory(n)
        | ConfirmKind::RemoveAttachment(n) => n,
        _ => 0,
    };
    let snapshots = match (holding, keep) {
        (0, _) => String::new(),
        (1, false) => " 1 snapshot holds this data and is deleted too.".to_owned(),
        (n, false) => format!(" {n} snapshots hold this data and are deleted too."),
        (1, true) => " 1 snapshot holds this data and is kept, so it stays recoverable until the snapshot expires.".to_owned(),
        (n, true) => format!(" {n} snapshots hold this data and are kept, so it stays recoverable until they expire."),
    };
    let message = match kind {
        ConfirmKind::DeleteRecursive => "Move this group and everything in it to the trash?".to_owned(),
        ConfirmKind::EmptyTrash(_) => format!("Permanently delete every non-conflicted item in the trash?{snapshots} Independent copies may remain."),
        ConfirmKind::PurgeExpired(false, _) => format!("Permanently delete the trash items past their retention period?{snapshots}"),
        ConfirmKind::PurgeExpired(true, _) => format!("Vault dates are ahead of this device's clock, so expiry may be wrong. Check the clock first. Permanently delete the expired items anyway?{snapshots}"),
        ConfirmKind::PurgeHistory(_) => format!("Purge this entry's local history? Active versions remain.{snapshots} Unseen concurrent history and independent copies may remain; there is no secure erasure."),
        ConfirmKind::RemoveAttachment(_) => format!("Permanently remove this attachment?{snapshots} Independent copies may remain; there is no secure erasure."),
        ConfirmKind::SaveAttachment => "Write this attachment's plaintext to the chosen file? It is not encrypted there, and a failure may leave incomplete plaintext.".to_owned(),
        ConfirmKind::SelfContained => "Include the password slot? Anyone holding this file can try offline master-password guessing, and a later password change does not revoke it.".to_owned(),
        ConfirmKind::Resolve(false) => "Create a new complete version from this choice, covering every version shown? Edits not seen here may still conflict.".to_owned(),
        ConfirmKind::Resolve(true) => "This choice permanently deletes the record's payload and history. Independent copies may remain. Create this resolution?".to_owned(),
        ConfirmKind::RestoreConflicts => "Restore this version and resolve the entry's current conflict with it?".to_owned(),
        ConfirmKind::OverBudget(n) => format!("The mandatory recovery snapshot needs {n} bytes and exceeds the snapshot budget. Allow it to exceed the budget? Nothing changes otherwise."),
        ConfirmKind::DeleteSnapshots(1, None) => "Delete this snapshot? You can no longer restore the vault as it was then. Deletion is not secure erasure.".to_owned(),
        ConfirmKind::DeleteSnapshots(n, bytes) => format!("Delete all {n} snapshots?{} You can no longer restore earlier states of the vault. Deletion is not secure erasure.", bytes.map_or_else(String::new, |b| format!(" They use {} of the vault file.", crate::views::human_size(b)))),
        ConfirmKind::OldSnapshots(n) => format!("{n} local snapshots were taken before this password change and still open with the old password. Delete them? Copies elsewhere remain; deletion is not cryptographic erasure."),
        ConfirmKind::LinkApp => "Link this app to the entry? QuickVault verified the app's package and signing certificate, but cannot tell whether the app belongs to the service. Link only an app you trust.".to_owned(),
        ConfirmKind::ReducedQuick => "Lower protection: your screen lock PIN, pattern or password would open this vault, so anyone who knows it could too. Use it instead of your fingerprint? Fingerprint unlock never falls back to it by itself.".to_owned(),
        ConfirmKind::LargeAttachment(n) => format!("This file is {}. Adding it takes a while and makes the vault that much larger, and previews of large files may be slow. Add it?", crate::views::human_size(n)),
        ConfirmKind::WeakPassword => "This password is weak and could be guessed by an attacker who obtains your vault file. Use it anyway?".to_owned(),
    };
    api::Confirm {
        message,
        weak: kind == ConfirmKind::WeakPassword,
        holding,
        keep,
        seconds,
    }
}

/// A finished task's report.
pub(super) fn report(report: &crate::workspace::Report) -> api::ReportCard {
    use crate::workspace::Report;
    let (ok, lines): (bool, Vec<String>) = match report {
        Report::Merge {
            accepted,
            conflicts,
            incomplete,
        } => (
            !incomplete,
            vec![
                if *accepted {
                    "Archive merged: a new local acceptance was committed.".into()
                } else {
                    "This archive was already accepted.".into()
                },
                format!("Conflicts now: {conflicts}"),
                if *incomplete {
                    "Completion reporting failed after the durable acceptance; check the vault before retrying.".into()
                } else {
                    String::new()
                },
            ],
        ),
        Report::Export {
            id,
            self_contained,
            incomplete,
        } => (
            !incomplete,
            vec![
                format!("Archive published: {id}"),
                if *self_contained {
                    "It includes the password slot.".into()
                } else {
                    "It opens only with this vault's key (another device or the recovery phrase)."
                        .into()
                },
                if *incomplete {
                    "Crash durability is unconfirmed because publication completion failed.".into()
                } else {
                    String::new()
                },
            ],
        ),
        Report::Resolved {
            conflicts,
            incomplete,
        } => (
            !incomplete,
            vec![
                format!("Resolution committed. Conflicts now: {conflicts}"),
                if *incomplete {
                    "Completion reporting failed after durable publication.".into()
                } else {
                    String::new()
                },
            ],
        ),
        Report::Verify {
            ok,
            anchor,
            objects,
            bytes,
            records,
            notes,
        } => {
            let mut v = vec![
                if *ok {
                    "Integrity check passed.".to_owned()
                } else {
                    "Integrity check FAILED. Keep the original file and recover from a verified backup.".to_owned()
                },
                format!("External anchor: {anchor}"),
                format!("{objects} objects ({bytes} bytes) re-hashed; {records} records checked"),
            ];
            v.extend(notes.iter().map(|n| format!("Note: {n}")));
            (*ok, v)
        }
        Report::Purged { purged, kept } => (
            true,
            vec![
                format!("{purged} item(s) permanently deleted."),
                if *kept > 0 {
                    format!("{kept} conflicted item(s) kept in the trash.")
                } else {
                    String::new()
                },
            ],
        ),
    };
    api::ReportCard {
        ok,
        lines: lines.into_iter().filter(|l| !l.is_empty()).collect(),
    }
}
