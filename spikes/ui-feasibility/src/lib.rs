// SPDX-License-Identifier: AGPL-3.0-or-later

//! Disposable Dioxus feasibility spike (plan 0013), not a production vault app.
#[cfg(feature = "ui")]
mod app;
// Controller-only tests intentionally omit the renderer; its UI entry points
// remain unused in that configuration. Default builds still check all UI code.
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
mod controller;
#[cfg(feature = "ui")]
mod platform;

/// Runs the shared fixture UI. There is no user-vault discovery or network sync.
#[cfg(feature = "ui")]
pub fn run() -> ! {
    use dioxus_desktop::tao::event::{Event, WindowEvent};
    qv_core::harden();
    let config = dioxus_desktop::Config::new()
        .with_window(dioxus_desktop::WindowBuilder::new().with_title("QuickVault feasibility"))
        .with_disable_context_menu(true)
        .with_disable_drag_drop_handler(true)
        .with_custom_event_handler(|event, _| {
            let must_lock = matches!(
                event,
                Event::Suspended
                    | Event::LoopDestroyed
                    | Event::WindowEvent {
                        event: WindowEvent::CloseRequested,
                        ..
                    }
            );
            if must_lock && let Some(c) = app::ACTIVE.get() {
                c.lock();
            }
        });
    dioxus_desktop::launch::launch_virtual_dom(dioxus::prelude::VirtualDom::new(app::app), config)
}
