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
    let guard = match linux_setup(state_root().map_err(|_| AppError::PrivateStorage)) {
        Ok((guard, controller)) => {
            let _ = crate::ui::ACTIVE.set(controller);
            Some(guard)
        }
        Err(error) => {
            // Keep the fixed category so the refusal screen names the cause.
            let _ = crate::ui::ACTIVE.set(Err(error));
            None
        }
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
        std::thread::sleep(std::time::Duration::from_secs(150));
        eprintln!("full UI fixture timeout");
        std::process::exit(2)
    });
    launch("QuickVault synthetic flow", SCRIPT.as_bytes())
}
/// The initial window size. Validation builds accept `QV_UI_SIZE=WxH` so
/// screenshots can cover the narrow and mid layouts (plan 0040).
fn window_size() -> (f64, f64) {
    #[cfg(feature = "validation")]
    if let Some((w, h)) = std::env::var("QV_UI_SIZE")
        .ok()
        .and_then(|v| v.split_once('x').map(|(w, h)| (w.parse(), h.parse())))
        .and_then(|(w, h)| Some((w.ok()?, h.ok()?)))
        .filter(|&(w, h): &(f64, f64)| {
            (360.0..=4096.0).contains(&w) && (480.0..=4096.0).contains(&h)
        })
    {
        return (w, h);
    }
    (1200.0, 800.0)
}
fn launch(title: &'static str, script: &'static [u8]) -> ! {
    let mut policy = dioxus_desktop::hardened::HardenedWebview::default();
    policy.assets.insert(
        "/app.css",
        ("text/css", include_bytes!("../assets/app.css")),
    );
    policy.assets.insert("/app.js", ("text/javascript", script));
    let (width, height) = window_size();
    let config = dioxus_desktop::Config::new()
        .with_window(
            dioxus_desktop::WindowBuilder::new()
                .with_title(title)
                .with_inner_size(dioxus_desktop::LogicalSize::new(width, height))
                .with_min_inner_size(dioxus_desktop::LogicalSize::new(360.0, 480.0)),
        )
        .with_hardened_webview(policy)
        .with_custom_event_handler(|event, _| {
            use dioxus_desktop::tao::event::{Event, WindowEvent};
            // On Android, tao's Suspended is the activity pause. The native
            // lifecycle poller reports every pause (generation counter) as a
            // background transition that a foreground clipboard hold may defer;
            // locking here as well would defeat that deferral.
            let suspended = cfg!(not(target_os = "android")) && matches!(event, Event::Suspended);
            if (suspended
                || matches!(
                    event,
                    Event::LoopDestroyed
                        | Event::WindowEvent {
                            event: WindowEvent::CloseRequested,
                            ..
                        }
                ))
                && let Some(Ok(c)) = crate::ui::ACTIVE.get()
            {
                c.lock();
            }
        });
    dioxus_desktop::launch::launch_virtual_dom(
        dioxus::prelude::VirtualDom::new(crate::ui::app),
        config,
    )
}
/// Private state, single-instance ownership and the controller, in that order.
#[cfg(target_os = "linux")]
fn linux_setup(
    base: Result<std::path::PathBuf, AppError>,
) -> Result<
    (
        qv_core::platform::InstanceLock,
        Result<Controller, AppError>,
    ),
    AppError,
> {
    let base = base?;
    private_dir(&base).map_err(|_| AppError::PrivateStorage)?;
    let guard = qv_core::platform::InstanceLock::acquire(&base).map_err(|error| {
        if error == qv_core::platform::PlatformError::Busy {
            AppError::AlreadyRunning
        } else {
            AppError::PrivateStorage
        }
    })?;
    let controller = Controller::new(base, Arc::new(qv_core::platform::LinuxPlatform::default()));
    Ok((guard, controller))
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
#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn linux_startup_reports_the_specific_storage_or_instance_refusal() {
        let dir = std::env::temp_dir().join(format!("qv-app-startup-{}", std::process::id()));
        private_dir(&dir).unwrap();
        let (guard, controller) = linux_setup(Ok(dir.clone())).unwrap();
        assert!(controller.is_ok());
        assert!(matches!(
            linux_setup(Ok(dir.clone())),
            Err(AppError::AlreadyRunning)
        ));
        drop(guard);
        let file = dir.join("not-a-directory");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(
            linux_setup(Ok(file)),
            Err(AppError::PrivateStorage)
        ));
        assert!(matches!(
            linux_setup(Err(AppError::PrivateStorage)),
            Err(AppError::PrivateStorage)
        ));
        drop(controller);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
