// SPDX-License-Identifier: AGPL-3.0-or-later

//! Section pages and the LAN panel.
use super::super::refs::Target;
use super::{Ctx, convert, items};
use crate::controller::View;
use crate::page_read::{Lane, Rows, Spec};
use crate::views;
use crate::workspace::{Pane, Report, RevealKey, Screen, WsField};
use qv_ui_api as api;
use qv_ui_api::{Icon, Z};
use zeroize::Zeroizing;

pub(super) fn page(
    ctx: &mut Ctx<'_>,
    view: &View,
    screen: &Screen,
    report: Option<Report>,
) -> api::Page {
    let key = match screen {
        Screen::Settings(p) => format!("{}-Settings-{p:?}", ctx.epoch.0),
        s => format!("{}-{s:?}", ctx.epoch.0),
    };
    let body = match screen {
        Screen::Generator => generator(ctx),
        Screen::Devices => devices(ctx, view),
        Screen::Trash => trash(ctx),
        Screen::Conflicts => conflicts(ctx),
        Screen::ConflictRecord(r) => compare(ctx, r),
        Screen::Snapshots => snapshots(ctx),
        Screen::Archives => api::PageBody::Archives(api::Archives {
            picker: items::picker(),
        }),
        Screen::Settings(p) => settings(ctx, view, *p),
        Screen::More => settings(ctx, view, Pane::Overview),
        Screen::Autofill => autofill(ctx),
        _ => api::PageBody::Empty,
    };
    api::Page {
        key,
        report: report.as_ref().map(super::shell::report),
        body,
    }
}

fn unreadable(error: Option<crate::controller::AppError>) -> api::PageBody {
    api::PageBody::Unreadable(
        error
            .map_or("Loading…", crate::controller::AppError::message)
            .to_owned(),
    )
}

fn generated(c: &crate::controller::Controller, epoch: crate::controller::FormEpoch) -> Option<Z> {
    c.generated(epoch)
        .map(|(v, _)| Z::from(views::z(&String::from_utf8_lossy(v.expose_secret()))))
        .filter(|z| !z.is_empty())
}

fn generator(ctx: &mut Ctx<'_>) -> api::PageBody {
    let Some(form) = ctx.c.generator_form(ctx.epoch) else {
        return unreadable(None);
    };
    api::PageBody::Generator(api::Generator {
        value: generated(ctx.c, ctx.epoch),
        mode: convert::gen_mode(form.mode),
        length: form.length,
        words: form.words,
        pin: form.pin,
        flags: form.flags,
        separator: form.separator.clone(),
        exclude: Z::from(form.exclude.clone()),
        bits: form.bits,
    })
}

fn devices(ctx: &mut Ctx<'_>, view: &View) -> api::PageBody {
    let c = ctx.c;
    let vault = c
        .open_vault()
        .map(|v| convert::vault_choice(ctx.refs, &v, true, false));
    api::PageBody::Devices(api::Devices {
        scanned: c.lan_scanned(ctx.epoch),
        scan: cfg!(target_os = "android") && crate::qr::camera_available(),
        vault,
        busy: view.busy,
    })
}

fn trash(ctx: &mut Ctx<'_>) -> api::PageBody {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let (_, read) = ctx
        .hooks
        .page(c, epoch, "trash", Lane::Main, 2, Spec::Trash);
    let page = read.as_ref().and_then(|r| r.page.clone());
    let rows = match page.as_deref().map(|p| &p.rows) {
        Some(Rows::Trash(rows)) => rows.clone(),
        _ => Vec::new(),
    };
    let expiry = match c.read(epoch, qv_core::Session::expiry_summary) {
        Some(Ok(v)) => v,
        other => return unreadable(other.and_then(Result::err)),
    };
    api::PageBody::Trash(api::Trash {
        clock_anomaly: expiry.clock_anomaly,
        items: rows
            .iter()
            .map(|t| api::TrashRow {
                item: convert::item(ctx.refs, t.item),
                name: Z::from(t.name.clone()),
                hue: convert::id_hue(&t.item.id_hex()).to_owned(),
                initial: convert::initial(&t.name),
                deleted: t
                    .deleted
                    .clone()
                    .unwrap_or_else(|| "Deleted by a concurrent version".into()),
                conflict: t.conflict,
            })
            .collect(),
        loaded: page.is_some(),
        expired: expiry.expired,
        page: Ctx::page_nav("trash", read.as_ref()),
    })
}

fn conflicts(ctx: &mut Ctx<'_>) -> api::PageBody {
    let c = ctx.c;
    let (_, read) = ctx
        .hooks
        .page(c, ctx.epoch, "conflicts", Lane::Main, 2, Spec::Conflicts);
    let page = read.as_ref().and_then(|r| r.page.clone());
    let rows = match page.as_deref().map(|p| &p.rows) {
        Some(Rows::Conflicts(rows)) => rows.clone(),
        _ => Vec::new(),
    };
    api::PageBody::Conflicts(api::Conflicts {
        rows: rows
            .iter()
            .map(|r| api::ConflictRow {
                record: r.record.clone(),
                name: r.name.clone().map_or_else(|| Z::new(r.kind), Z::from),
                kind: r.kind.to_owned(),
                versions: r.versions,
            })
            .collect(),
        loaded: page.is_some(),
        page: Ctx::page_nav("conflicts", read.as_ref()),
    })
}

fn compare(ctx: &mut Ctx<'_>, record: &str) -> api::PageBody {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let v = match c.read(epoch, |s| views::conflict_compare(s, record)) {
        Some(Ok(v)) => v,
        other => return unreadable(other.and_then(Result::err)),
    };
    let identical = v.identical();
    let n = v.heads.len();
    let cols = match n {
        0..=2 => "cols-2",
        3 => "cols-3",
        _ => "cols-4",
    };
    let lead = if identical {
        format!(
            "“{}” has {n} versions with the same content. Keep either one.",
            v.name.as_str()
        )
    } else {
        format!(
            "“{}” was changed on more than one device. Only the differences are shown side by side; keep the version you want.",
            v.name.as_str()
        )
    };
    let cell = |refs: &mut super::super::refs::Refs, i: usize, cell: &views::Cell| match cell {
        views::Cell::Text(t) if t.is_empty() => api::Cell::Empty,
        views::Cell::Text(t) => api::Cell::Text(Z::from(t.clone())),
        views::Cell::Missing => api::Cell::Missing,
        views::Cell::Masked(field) => {
            let version = v
                .heads
                .get(i)
                .map(|h| h.version.clone())
                .unwrap_or_default();
            let key = RevealKey::Conflict(record.to_owned(), version, *field);
            let shown = c
                .revealed(epoch, &key)
                .map(|s| Z::from(views::z(&String::from_utf8_lossy(s.expose_secret()))));
            api::Cell::Masked(convert::reveal(refs, &key), shown)
        }
    };
    let diff = v
        .rows
        .iter()
        .filter(|r| !r.same)
        .map(|r| {
            (
                Z::from(r.label.clone()),
                r.cells
                    .iter()
                    .enumerate()
                    .map(|(i, x)| cell(ctx.refs, i, x))
                    .collect(),
            )
        })
        .collect();
    let same = v
        .rows
        .iter()
        .filter(|r| r.same)
        .map(|r| {
            let first = match r.cells.first() {
                Some(views::Cell::Text(t)) if t.is_empty() => api::Cell::Empty,
                Some(views::Cell::Text(t)) => api::Cell::Text(Z::from(t.clone())),
                Some(views::Cell::Masked(_)) => api::Cell::SameProtected,
                _ => api::Cell::Missing,
            };
            (Z::from(r.label.clone()), first)
        })
        .collect();
    api::PageBody::Compare(Box::new(api::Compare {
        record: record.to_owned(),
        lead,
        identical,
        needs_password: v.needs_password,
        kind: v.kind.to_owned(),
        cols: cols.to_owned(),
        heads: v
            .heads
            .iter()
            .map(|h| api::Head {
                label: h.label.to_string(),
                version: h.version.clone(),
                state: h.state.to_owned(),
                modified: h.modified.clone(),
            })
            .collect(),
        diff,
        same,
    }))
}

fn snapshots(ctx: &mut Ctx<'_>) -> api::PageBody {
    let ((rows, unreadable_count), kept) = match ctx.c.read(ctx.epoch, |s| {
        Ok((views::snapshots(s)?, s.storage()?.snapshot_bytes))
    }) {
        Some(Ok(v)) => v,
        other => return unreadable(other.and_then(Result::err)),
    };
    let typed = cfg!(target_os = "android") || crate::documents::picker_missing();
    api::PageBody::Snapshots(api::Snapshots {
        rows: rows
            .iter()
            .map(|r| api::Snapshot {
                id: r.id.clone(),
                created: r.created.clone(),
                kind: r.kind.to_owned(),
                size: views::human_size(r.size),
            })
            .collect(),
        unreadable: unreadable_count,
        kept: views::human_size(kept),
        typed: typed.then(|| {
            if cfg!(target_os = "android") {
                "Name for the restored vault".to_owned()
            } else {
                "New vault file for the restore (full path)".to_owned()
            }
        }),
        portal: cfg!(any(target_os = "linux", windows)) && !crate::documents::picker_missing(),
    })
}

/// The checks behind a protection level that are not in place.
fn protection_gaps(
    os: &qv_core::platform::ProtectionStatus,
    process_reduced: bool,
) -> Vec<&'static str> {
    use qv_core::platform::Evidence::Verified;
    [
        (os.storage == Verified, "disk encryption"),
        (os.swap == Verified, "swap"),
        (os.hibernation == Verified, "hibernation"),
        (os.lifecycle, "screen-lock detection"),
        (os.clipboard, "clipboard clearing"),
        (!process_reduced, "memory protection"),
    ]
    .into_iter()
    .filter(|(ok, _)| !ok)
    .map(|(_, name)| name)
    .collect()
}

fn guidance(ctx: &Ctx<'_>) -> api::Guidance {
    api::Guidance {
        fair: ctx.c.peek(ctx.epoch, |ws| ws.fair_warning).unwrap_or(false),
        // Cleared inputs show no stale rating.
        meter: ctx
            .c
            .peek(ctx.epoch, |ws| {
                ws.rating
                    .meter
                    .filter(|_| !ws.input(crate::workspace::WsField::NewPassword).is_empty())
            })
            .flatten()
            .map(convert::meter),
        suggestion: generated(ctx.c, ctx.epoch),
    }
}

fn settings(ctx: &mut Ctx<'_>, view: &View, pane: Pane) -> api::PageBody {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let body = match pane {
        Pane::Overview => {
            let os = c.protection();
            let reduced = qv_core::harden().is_reduced();
            let level = crate::prefs::level(&os, reduced);
            let missing = protection_gaps(&os, reduced);
            let detail = if missing.is_empty() {
                "Encrypted storage, swap and hibernation, with screen-lock detection and clipboard clearing".to_owned()
            } else {
                format!("Not confirmed: {}", missing.join(", "))
            };
            api::SettingsBody::Overview(Box::new(api::Overview {
                theme: c.theme().name().to_owned(),
                idle_only: view.reduced_lifecycle,
                detail,
                level: level.label().to_owned(),
                tone: level.tone().to_owned(),
                quick: match c.quick_policy() {
                    Some(qv_core::platform::QuickPolicy::Class3) => "Fingerprint unlock is on",
                    Some(qv_core::platform::QuickPolicy::DeviceCredential) => {
                        "Screen-lock unlock is on"
                    }
                    None => "Fingerprint unlock; autofill on supported phones",
                }
                .to_owned(),
                file: c
                    .open_vault()
                    .map(|v| (Z::from(views::z(&v.file)), Z::from(views::z(&v.place)))),
                folder: Z::from(views::z(&crate::vaults::shown_place(&c.default_folder()))),
                folder_change: cfg!(any(target_os = "linux", windows))
                    && !crate::documents::picker_missing(),
            }))
        }
        Pane::General => api::SettingsBody::General(c.settings_form(epoch).map(|f| api::General {
            name: Z::from(f.name.clone()),
            description: Z::from(f.description.clone()),
            history_depth: f.history_depth.clone(),
            trash_days: f.trash_days.clone(),
        })),
        Pane::Password => api::SettingsBody::Password(api::PasswordPane {
            quick_available: c.protection().quick_unlock,
            policy: c.quick_policy().map(convert::quick_policy),
            autofill: c.autofill_available(),
            guidance: guidance(ctx),
        }),
        Pane::Phrase => api::SettingsBody::Phrase(api::PhrasePane {
            shown: c.phrase_screen(epoch).map(|screen| {
                let words = c
                    .phrase_words(epoch)
                    .map(|v| {
                        String::from_utf8_lossy(v.expose_secret())
                            .split_whitespace()
                            .map(Z::new)
                            .collect()
                    })
                    .unwrap_or_default();
                (words, screen.confirmed, screen.positions)
            }),
        }),
        Pane::Rotation => api::SettingsBody::Rotation(guidance(ctx)),
        Pane::Verify => api::SettingsBody::Verify,
        Pane::Storage => api::SettingsBody::Storage(match c.read(epoch, |s| s.storage()) {
            Some(Ok(i)) => Ok(api::Storage {
                file: views::human_size(i.file_bytes),
                free: if i.free_bytes == 0 {
                    "None".to_owned()
                } else {
                    format!(
                        "{} can be returned to this device",
                        views::human_size(i.free_bytes)
                    )
                },
                snapshots: format!(
                    "{} kept only by snapshots",
                    views::human_size(i.snapshot_bytes)
                ),
                disk: i
                    .disk_free
                    .map_or_else(|| "Unknown".to_owned(), views::human_size),
                empty: i.free_bytes == 0,
            }),
            other => Err(other
                .and_then(Result::err)
                .map_or("Loading…", crate::controller::AppError::message)
                .to_owned()),
        }),
        Pane::About => {
            let about = c.about(epoch);
            let overview = c.read(epoch, views::overview).and_then(Result::ok);
            api::SettingsBody::About(api::About {
                overview: overview.map(|o| [o.entries, o.groups, o.trash, o.conflicts]),
                header: about.map(|a| {
                    (
                        a.vault_id.clone(),
                        a.key_generation,
                        a.format,
                        format!(
                            "Argon2id, {} MiB, {} iterations, {} lanes",
                            a.kdf.0, a.kdf.1, a.kdf.2
                        ),
                    )
                }),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            })
        }
    };
    api::PageBody::Settings(Box::new(api::Settings {
        pane: convert::pane(pane),
        nested: pane != Pane::Overview,
        body,
    }))
}

fn autofill(ctx: &mut Ctx<'_>) -> api::PageBody {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let Some(view) = c.autofill_view() else {
        return api::PageBody::Autofill(Box::new(api::Autofill {
            label: None,
            candidates: Vec::new(),
            loaded: true,
            page: None,
            app: None,
            query: Z::default(),
            results: Vec::new(),
            link_page: None,
        }));
    };
    let (_, read) = ctx.hooks.page(
        c,
        epoch,
        "autofill",
        Lane::Main,
        2,
        Spec::Autofill(view.requester.clone()),
    );
    let page = read.as_ref().and_then(|r| r.page.clone());
    let candidates = match page.as_deref().map(|p| &p.rows) {
        Some(Rows::Autofill(rows)) => rows
            .iter()
            .map(|cand| {
                let title = views::z(cand.title.expose());
                api::Candidate {
                    key: ctx.refs.issue(Target::Candidate(cand.key())),
                    hue: convert::id_hue(&cand.entry().id_hex()).to_owned(),
                    initial: convert::initial(&title),
                    title: Z::from(title),
                    username: Z::from(views::z(cand.username.as_ref().map_or("", |u| u.expose()))),
                    conflicted: cand.conflicted,
                }
            })
            .collect(),
        _ => Vec::new(),
    };
    let query = c
        .peek(epoch, |ws| {
            String::from_utf8_lossy(ws.input(WsField::Query)).into_owned()
        })
        .map(Zeroizing::new)
        .unwrap_or_default();
    let (_, link_read) = ctx.hooks.page(
        c,
        epoch,
        "autofill.link",
        Lane::Overlay,
        2,
        Spec::Search(if view.app.is_some() {
            query.clone()
        } else {
            Zeroizing::new(String::new())
        }),
    );
    let results = match link_read
        .as_ref()
        .and_then(|r| r.page.as_deref())
        .map(|p| &p.rows)
    {
        Some(Rows::Search { entries, .. }) => entries
            .iter()
            .map(|e| {
                (
                    ctx.refs.issue(Target::Entry(e.handle)),
                    Z::from(e.title.clone()),
                )
            })
            .collect(),
        _ => Vec::new(),
    };
    api::PageBody::Autofill(Box::new(api::Autofill {
        label: Some(Z::from(views::z(&view.label))),
        candidates,
        loaded: page.is_some(),
        page: Ctx::page_nav("autofill", read.as_ref()),
        app: view.app.clone(),
        query: Z::from(query),
        results,
        link_page: Ctx::page_nav("autofill.link", link_read.as_ref()),
    }))
}

/// The LAN operation.
pub(super) fn lan(ctx: &mut Ctx<'_>) -> Option<api::Lan> {
    use crate::lan::{LanKind, Question};
    let c = ctx.c;
    let v = c.lan_view(ctx.epoch)?;
    let vault = c.open_vault().map(|o| {
        (
            Z::from(views::z(&o.name)),
            convert::vault_hue(&o.name).to_owned(),
        )
    });
    let title = match v.kind {
        LanKind::Window if v.code.is_some() => "Scan or type this code on the other device",
        LanKind::Window if v.admitted => "Connected to another device",
        LanKind::Window => "Connecting with another device",
        LanKind::Sync => "Syncing with another device",
        LanKind::Join => "Joining from another device",
    };
    let done = v
        .done
        .as_ref()
        .map(|d| receipt(ctx, v.kind, d, v.closes_in));
    Some(api::Lan {
        done,
        title: title.to_owned(),
        names_vault: matches!(v.kind, LanKind::Window | LanKind::Sync),
        vault,
        qr: v.qr.as_ref().map(items::qr),
        code: v
            .code
            .as_ref()
            .map(|c| Z::from(String::from_utf8_lossy(c.expose_secret()).into_owned())),
        endpoints: v.endpoints.clone(),
        seconds: v.seconds,
        admitted: v.admitted,
        sas: v.sas.clone(),
        info: v.info.clone(),
        question: v.question.clone().map(|q| match q {
            Question::Approve { sas, vault } => api::Question::Approve { sas, vault },
            Question::JoinVault { vault, sas } => api::Question::JoinVault { vault, sas },
            Question::ChooseCredential => api::Question::ChooseCredential,
            Question::RecoveryPhrase => api::Question::RecoveryPhrase,
            Question::JoinRecoveredVault { vault } => api::Question::JoinRecoveredVault { vault },
            Question::Password { offering, retry } => api::Question::Password { offering, retry },
        }),
        question_id: v.question_id,
    })
}

fn receipt(
    ctx: &mut Ctx<'_>,
    kind: crate::lan::LanKind,
    done: &crate::lan::LanDone,
    closes_in: Option<u64>,
) -> api::Receipt {
    use crate::lan::LanKind;
    let round = done.round.as_ref();
    let conflicts = round.map_or(0, |r| r.conflicts);
    let confirmed = round.is_none_or(|r| r.peer_confirmed);
    let tone = if done.error.is_some() {
        "bad"
    } else if conflicts > 0 || !confirmed {
        "warn"
    } else {
        "ok"
    };
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    let title = match (round, done.error) {
        (None, Some(_)) if kind == LanKind::Join => "Joining didn't finish".to_owned(),
        (None, Some(_)) => "Sync didn't finish".to_owned(),
        (None, None) => done
            .lines
            .first()
            .cloned()
            .unwrap_or_else(|| "Done".to_owned()),
        (Some(_), Some(_)) => "Synced, with a problem".to_owned(),
        (Some(r), None) if r.conflicts > 0 => format!(
            "{} your choice",
            plural(r.conflicts, "item needs", "items need")
        ),
        (Some(r), None) if r.received && r.changes.total() > 0 => format!(
            "Received {}",
            plural(r.changes.total(), "change", "changes")
        ),
        (Some(r), None) if r.received => "Received changes".to_owned(),
        (Some(_), None) => "Up to date".to_owned(),
    };
    let sub = match (round, done.error) {
        (_, Some(e)) => e.message().to_owned(),
        (Some(r), None) if !r.peer_confirmed => {
            "The other device didn't confirm receipt. Sync again later to be sure.".to_owned()
        }
        (Some(r), None) if r.conflicts > 0 => {
            "Both devices changed the same items. Pick what to keep.".to_owned()
        }
        (Some(_), None) => "Both devices now hold the same vault.".to_owned(),
        (None, None) => done.lines.get(1).cloned().unwrap_or_default(),
    };
    let icon = match tone {
        "bad" => Icon::Warn,
        "warn" if conflicts > 0 => Icon::Conflicts,
        "warn" => Icon::Warn,
        _ => Icon::Check,
    };
    let changes = round.map(|r| r.changes.clone()).unwrap_or_default();
    let listed = changes
        .added
        .iter()
        .map(|c| ("new", c))
        .chain(changes.updated.iter().map(|c| ("changed", c)))
        .chain(changes.trashed.iter().map(|c| ("trash", c)))
        .map(|(mark, ch)| {
            (
                mark.to_owned(),
                ch.entry.map(|h| ctx.refs.issue(Target::Entry(h))),
                Z::from(ch.title.clone()),
            )
        })
        .collect();
    let ring = closes_in.map(|left| {
        let total = crate::lan::RECEIPT_SECONDS as f64;
        format!(
            "{:.1}",
            56.5 * (1.0 - (left as f64 / total).clamp(0.0, 1.0))
        )
    });
    api::Receipt {
        tone: tone.to_owned(),
        title,
        sub,
        icon,
        counts: changes.counts,
        total: changes.total(),
        listed,
        conflicts,
        ring,
    }
}
