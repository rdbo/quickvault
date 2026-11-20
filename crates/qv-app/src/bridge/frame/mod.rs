// SPDX-License-Identifier: AGPL-3.0-or-later

//! Building frames: one function per screen part, making the controller
//! reads and display decisions, with handles turned into references. (The
//! Dioxus UI these mirror is `src/ui/` before plan 0071, in git history.)
mod editor;
mod items;
mod locked;
mod pages;
mod shell;

use super::convert;
use super::hooks::Hooks;
use super::refs::Refs;
use crate::controller::{AppError, Controller, FormEpoch, Phase};
use qv_ui_api as api;
use qv_ui_api::{BarPop, EditorPop, Z};

/// Popovers whose content the backend reads (their open state lives here,
/// as their page reads do).
#[derive(Default)]
pub(crate) struct UiState {
    pub(crate) palette: bool,
    pub(crate) copy_menu: Option<String>,
    pub(crate) row_menu: Option<String>,
    pub(crate) group_menu: bool,
    pub(crate) bar_pop: Option<BarPop>,
    pub(crate) editor_pop: Option<EditorPop>,
    /// The form the editor popover belongs to.
    pub(crate) editor_form: Option<String>,
}

/// What one frame build reads and writes.
pub(crate) struct Ctx<'a> {
    pub(crate) c: &'a Controller,
    pub(crate) epoch: FormEpoch,
    pub(crate) refs: &'a mut Refs,
    pub(crate) hooks: &'a mut Hooks,
    pub(crate) ui: &'a mut UiState,
}

impl Ctx<'_> {
    /// A page slot's navigation.
    pub(crate) fn page_nav(
        slot: &str,
        read: Option<&crate::page_read::Read>,
    ) -> Option<api::PageNav> {
        let read = read?;
        let window = read.window;
        Some(api::PageNav {
            slot: slot.to_owned(),
            serial: read.serial,
            previous: match window {
                Some((origin, _)) => !origin,
                None => read.page.as_ref().is_some_and(|p| p.previous.is_some()),
            },
            next: read.page.as_ref().is_some_and(|p| p.next.is_some()),
            loading: read.loading,
            error: read.error.map(|e| e.message().to_owned()),
            window: window.is_some(),
            more: window.is_some_and(|(_, room)| room),
        })
    }
}

pub(crate) fn platform() -> api::Platform {
    if cfg!(target_os = "android") {
        api::Platform::Android
    } else if cfg!(windows) {
        api::Platform::Windows
    } else {
        api::Platform::Linux
    }
}

/// The failure screen's texts.
fn failed(error: AppError) -> api::Body {
    let title = match error {
        AppError::LockMonitoring => "Lock monitoring unavailable",
        AppError::PrivateStorage => "Private storage unavailable",
        AppError::AlreadyRunning => "QuickVault is already running",
        _ => "Protection unavailable",
    };
    api::Body::Failed {
        title: title.to_owned(),
        message: error.message().to_owned(),
    }
}

/// The whole frame.
pub(crate) fn build(
    active: Option<&Result<Controller, AppError>>,
    refs: &mut Refs,
    hooks: &mut Hooks,
    ui: &mut UiState,
    seq: u64,
) -> api::Frame {
    refs.next_frame();
    let Some(Ok(c)) = active else {
        let error = active
            .and_then(|r| r.as_ref().err())
            .copied()
            .unwrap_or(AppError::Unavailable);
        return api::Frame {
            seq,
            epoch: 0,
            mode: "dark".to_owned(),
            platform: platform(),
            title: api::TitleBar {
                unlocked: false,
                idle_left: 0,
                busy: false,
                vault: None,
                idle_only: false,
                light: false,
                ready: false,
                vaults: Vec::new(),
                editing: false,
            },
            body: failed(error),
            fixture: None,
        };
    };
    let view = c.snapshot();
    let epoch = view.epoch;
    let unlocked = view.phase == Phase::Unlocked;
    let mut ctx = Ctx {
        c,
        epoch,
        refs,
        hooks,
        ui,
    };
    // The title bar's vault name, kept while an operation owns the vault.
    let name = ctx
        .hooks
        .last(
            "root.name",
            if unlocked {
                c.read(epoch, |s| {
                    crate::views::overview(s).map(|o| Some(o.name.to_string()))
                })
            } else {
                Some(Ok(None))
            },
        )
        .and_then(Result::ok)
        .flatten();
    let title = title_bar(&mut ctx, &view, unlocked, name);
    let body = if unlocked {
        api::Body::Unlocked(Box::new(shell::shell(&mut ctx, &view)))
    } else {
        api::Body::Locked(Box::new(locked::locked(&mut ctx, &view)))
    };
    let fixture = fixture(c);
    ctx.hooks.finish(c);
    api::Frame {
        seq,
        epoch: epoch.0,
        mode: view.theme.name().to_owned(),
        platform: platform(),
        title,
        body,
        fixture,
    }
}

#[cfg(feature = "fixture")]
fn fixture(c: &Controller) -> Option<api::Fixture> {
    c.is_fixture().then(|| api::Fixture {
        root: c.0.base.to_string_lossy().into_owned(),
        peer_opened: {
            #[cfg(target_os = "linux")]
            {
                crate::lan::fixture::complete()
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        },
    })
}
#[cfg(not(feature = "fixture"))]
fn fixture(_: &Controller) -> Option<api::Fixture> {
    None
}

/// The desktop title bar.
fn title_bar(
    ctx: &mut Ctx<'_>,
    view: &crate::controller::View,
    unlocked: bool,
    name: Option<String>,
) -> api::TitleBar {
    let c = ctx.c;
    let current = c.open_vault().map(|v| v.path);
    let vaults = if unlocked {
        c.vaults()
            .iter()
            .map(|v| {
                let on = current.as_ref() == Some(&v.path);
                convert::vault_choice(ctx.refs, v, on, false)
            })
            .collect()
    } else {
        Vec::new()
    };
    api::TitleBar {
        unlocked,
        idle_left: view.idle_left,
        busy: if unlocked { view.busy_shown } else { view.busy },
        vault: name.map(|n| Z::from(crate::views::z(&n))),
        idle_only: view.reduced_lifecycle,
        light: c.theme() == crate::prefs::Theme::Light,
        ready: true,
        vaults,
        editing: c.screen(ctx.epoch).is_some_and(|s| s.is_form()),
    }
}
