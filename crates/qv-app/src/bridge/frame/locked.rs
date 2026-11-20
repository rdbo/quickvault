// SPDX-License-Identifier: AGPL-3.0-or-later

//! The locked screens: welcome, unlock,
//! create, phrase, recover, import, join, recovery baseline, rotation and
//! resume. The page keeps the wizard step, the phrase's shown state and the
//! menus, as the component's signals did.
use super::{Ctx, convert};
use crate::controller::{Mode, Phase, View};
use qv_core::platform::Evidence;
use qv_ui_api as api;
use qv_ui_api::Z;

fn is_preview(c: &crate::controller::Controller) -> bool {
    #[cfg(feature = "fixture")]
    {
        c.is_preview()
    }
    #[cfg(not(feature = "fixture"))]
    {
        let _ = c;
        false
    }
}
pub(super) fn is_fixture(c: &crate::controller::Controller) -> bool {
    #[cfg(feature = "fixture")]
    {
        c.is_fixture()
    }
    #[cfg(not(feature = "fixture"))]
    {
        let _ = c;
        false
    }
}

fn evidence_row(label: &str, e: Evidence) -> api::StatusRow {
    let (class, text) = match e {
        Evidence::Verified => ("r ok", "Protected"),
        Evidence::KnownGap => ("r warn", "Not protected"),
        Evidence::Unknown => ("r warn", "Unknown"),
    };
    api::StatusRow {
        label: label.to_owned(),
        class: class.to_owned(),
        text: text.to_owned(),
    }
}
fn status_row(label: &str, ok: bool) -> api::StatusRow {
    api::StatusRow {
        label: label.to_owned(),
        class: if ok { "r ok" } else { "r warn" }.to_owned(),
        text: if ok { "Available" } else { "Unavailable" }.to_owned(),
    }
}

/// Device protection as the locked screen's sheet shows it.
pub(super) fn protection(c: &crate::controller::Controller) -> api::Protection {
    let os = c.protection();
    let process_reduced = qv_core::harden().is_reduced();
    let level = crate::prefs::level(&os, process_reduced);
    api::Protection {
        label: level.label().to_owned(),
        tone: level.tone().to_owned(),
        reduced: os.is_reduced() || process_reduced,
        rows: vec![
            evidence_row("Disk encryption", os.storage),
            evidence_row("Swap", os.swap),
            evidence_row("Hibernation", os.hibernation),
            status_row("Screen-lock and sleep detection", os.lifecycle),
            status_row("Clipboard clearing", os.clipboard),
            status_row("Process and memory protection", !process_reduced),
        ],
        quick_unlock: os.quick_unlock,
    }
}

fn words(bytes: Option<qv_core::SecretBytes>) -> Vec<Z> {
    bytes
        .as_ref()
        .and_then(|v| std::str::from_utf8(v.expose_secret()).ok())
        .unwrap_or("")
        .split_whitespace()
        .map(Z::new)
        .collect()
}

pub(super) fn locked(ctx: &mut Ctx<'_>, view: &View) -> api::Locked {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let fixture = is_fixture(c);
    let picked = c.picked_vault(epoch);
    let app_vault = c.app_vault_exists();
    let selected = c.selected_vault();
    let vaults: Vec<api::VaultChoice> = c
        .vaults()
        .iter()
        .map(|v| {
            let on = selected.as_ref().is_some_and(|s| s.path == v.path) && picked.is_none();
            convert::vault_choice(ctx.refs, v, on, false)
        })
        .collect();
    let selected = selected
        .as_ref()
        .map(|v| convert::vault_choice(ctx.refs, v, true, false));
    // The phrase shows only in the phase that displays it.
    let words = if matches!(view.phase, Phase::Phrase | Phase::Rotation) {
        words(c.phrase(epoch))
    } else {
        Vec::new()
    };
    let suggestion = if view.suggestion_visible {
        c.suggestion(epoch)
            .as_ref()
            .and_then(|v| std::str::from_utf8(v.expose_secret()).ok().map(Z::new))
    } else {
        None
    };
    let quick = view.mode == Mode::Unlock && c.quick_ready();
    let quick_label =
        if c.quick_policy_selected() == Some(qv_core::platform::QuickPolicy::DeviceCredential) {
            "Unlock with screen lock"
        } else {
            "Unlock with fingerprint"
        };
    let lan = super::pages::lan(ctx);
    api::Locked {
        mode: convert::mode(view.mode),
        phase: convert::phase(view.phase),
        busy: view.busy,
        preview: is_preview(c),
        fixture,
        error: view.error.map(|e| e.message().to_owned()),
        notice: view.notice().map(str::to_owned),
        picked: picked.map(|p| Z::from(crate::views::z(&p))),
        first_run: !app_vault && c.picked_vault(epoch).is_none(),
        vaults,
        selected,
        folder_place: Z::from(crate::views::z(&crate::vaults::shown_place(
            &c.default_folder(),
        ))),
        words,
        suggestion,
        can_pick: cfg!(any(target_os = "linux", target_os = "android", windows)),
        fallback: crate::documents::picker_missing() || fixture,
        typed_path: fixture,
        quick,
        quick_label: quick_label.to_owned(),
        protection: protection(c),
        ack_needed: view.ack_needed,
        gate: c.protection_ack_needed(),
        resume: view.resume.map(|r| (r.new, r.old)),
        rotation_confirmed: view.rotation_confirmed,
        positions: view.positions,
        weak_seconds: view.weak_seconds,
        fair_warning: view.fair_warning,
        meter: view.meter.map(convert::meter),
        suggestion_visible: view.suggestion_visible,
        mismatch: c.repeat_mismatch(epoch),
        import_name: Z::from(c.import_name(epoch)),
        import_ready: view.import_ready,
        import_ack: view.import_ack,
        code_scanned: view.code_scanned(),
        join_review: view.join_review(),
        autoprompt: view.autoprompt,
        autofill_banner: c.autofill_banner(),
        lan,
        scanning: view.scanning,
        camera: crate::qr::camera_available(),
    }
}
