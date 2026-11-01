// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native startup and lifecycle. No vault operations bypass core.
#[cfg(any(target_os = "linux", feature = "validation"))]
use crate::controller::Controller;
#[cfg(target_os = "linux")]
use crate::controller::{AppError, private_dir};
#[cfg(target_os = "linux")]
use std::sync::Arc;

/// Launch the shared Android/Linux UI with required platform services.
pub fn run() -> ! {
    qv_core::harden();
    #[cfg(target_os = "linux")]
    let guard = {
        let setup = (|| {
            let base = state_root().map_err(|_| AppError::PrivateStorage)?;
            private_dir(&base).map_err(|_| AppError::PrivateStorage)?;
            let guard = qv_core::platform::InstanceLock::acquire(&base).map_err(|error| {
                if error == qv_core::platform::PlatformError::Busy {
                    AppError::AlreadyRunning
                } else {
                    AppError::PrivateStorage
                }
            })?;
            let controller =
                Controller::new(base, Arc::new(qv_core::platform::LinuxPlatform::default()));
            let _ = crate::ui::ACTIVE.set(controller);
            Ok::<_, AppError>(guard)
        })();
        if setup.is_err() {
            let _ = crate::ui::ACTIVE.set(Err(AppError::Unavailable));
        }
        setup.ok()
    };
    #[cfg(target_os = "android")]
    crate::android::initialize();
    #[cfg(target_os = "linux")]
    let _instance = guard;
    launch("QuickVault", include_bytes!("../assets/app.js"))
}

/// Synthetic shared-screen preview; no persistent vault action is permitted.
#[cfg(feature = "validation")]
pub fn run_preview() -> ! {
    let _ = crate::ui::ACTIVE.set(Controller::preview());
    launch(
        "QuickVault · read-only preview",
        include_bytes!("../assets/app.js"),
    )
}
/// Actual shared screens and core operations, using only synthetic fixture data.
#[cfg(feature = "validation")]
pub fn run_flow_fixture() -> ! {
    let _ = crate::ui::ACTIVE.set(Controller::validation_fixture());
    const SCRIPT: &str = concat!(
        include_str!("../assets/app.js"),
        "\n",
        include_str!("bin/flow.js")
    );
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(60));
        eprintln!("full UI fixture timeout");
        std::process::exit(2)
    });
    launch("QuickVault synthetic flow", SCRIPT.as_bytes())
}
fn launch(title: &'static str, script: &'static [u8]) -> ! {
    let mut policy = dioxus_desktop::hardened::HardenedWebview::default();
    policy.assets.insert(
        "/app.css",
        ("text/css", include_bytes!("../assets/app.css")),
    );
    policy.assets.insert("/app.js", ("text/javascript", script));
    let config = dioxus_desktop::Config::new()
        .with_window(
            dioxus_desktop::WindowBuilder::new()
                .with_title(title)
                .with_inner_size(dioxus_desktop::LogicalSize::new(1180.0, 900.0)),
        )
        .with_hardened_webview(policy)
        .with_custom_event_handler(|event, _| {
            use dioxus_desktop::tao::event::{Event, WindowEvent};
            if matches!(
                event,
                Event::Suspended
                    | Event::LoopDestroyed
                    | Event::WindowEvent {
                        event: WindowEvent::CloseRequested,
                        ..
                    }
            ) && let Some(Ok(c)) = crate::ui::ACTIVE.get()
            {
                c.lock();
            }
        });
    dioxus_desktop::launch::launch_virtual_dom(
        dioxus::prelude::VirtualDom::new(crate::ui::app),
        config,
    )
}
#[cfg(target_os = "linux")]
fn state_root() -> Result<std::path::PathBuf, AppError> {
    let path = if let Some(root) = std::env::var_os("XDG_STATE_HOME") {
        std::path::PathBuf::from(root).join("quickvault")
    } else {
        std::path::PathBuf::from(std::env::var_os("HOME").ok_or(AppError::Unavailable)?)
            .join(".local/state/quickvault")
    };
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::Unavailable);
    }
    Ok(path)
}
