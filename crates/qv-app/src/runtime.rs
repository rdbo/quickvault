// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native startup and lifecycle. No vault operations bypass core.
#[cfg(any(target_os = "linux", windows, feature = "validation"))]
use crate::controller::Controller;
#[cfg(any(target_os = "linux", windows))]
use crate::controller::{AppError, private_dir};
#[cfg(any(target_os = "linux", windows))]
use std::sync::Arc;

/// Launch the shared Android/Linux/Windows UI with required platform services.
pub fn run() -> ! {
    // The file-picker helper (plan 0044): answer and exit before hardening,
    // the instance lock or any vault access.
    #[cfg(target_os = "linux")]
    if let Some(code) = crate::picker::helper() {
        std::process::exit(code);
    }
    qv_core::harden();
    #[cfg(any(target_os = "linux", windows))]
    let guard = match desktop_setup(state_root().map_err(|_| AppError::PrivateStorage)) {
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
    #[cfg(any(target_os = "linux", windows))]
    let _instance = guard;
    #[cfg(feature = "validation")]
    if crate::validation_media::enabled() {
        launch("QuickVault synthetic media", MEDIA_SCRIPT.as_bytes());
    }
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
    let fixture = Controller::validation_fixture();
    if crate::validation_media::enabled()
        && let Err(error) = fixture
    {
        eprintln!("synthetic media setup failed: {}", error.message());
        std::process::exit(1);
    }
    let _ = crate::ui::ACTIVE.set(fixture);
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
    if crate::validation_media::enabled() {
        launch("QuickVault synthetic media", MEDIA_SCRIPT.as_bytes());
    }
    launch("QuickVault synthetic flow", SCRIPT.as_bytes())
}
#[cfg(feature = "validation")]
const MEDIA_SCRIPT: &str = concat!(
    include_str!("../assets/app.js"),
    "\n",
    include_str!("bin/media.js")
);
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
    // Revocable bounded media ranges on the existing listener (0003 §6.4, plan0050).
    policy.preview = Some(std::sync::Arc::new(crate::preview::serve));
    let (width, height) = window_size();
    let config = dioxus_desktop::Config::new()
        .with_window(
            dioxus_desktop::WindowBuilder::new()
                .with_title(title)
                // The logo for the taskbar and window switcher, rendered from
                // `LOGO.svg`; a decoding failure leaves the framework default.
                .with_window_icon(
                    dioxus_desktop::icon_from_memory(include_bytes!("../assets/icon-256.png")).ok(),
                )
                // The app draws its own title bar (0009 §1.8); no effect on Android.
                .with_decorations(false)
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
#[cfg(any(target_os = "linux", windows))]
fn desktop_setup(
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
    #[cfg(target_os = "linux")]
    let services = Arc::new(qv_core::platform::LinuxPlatform::default());
    // Windows requires the WTS lock/sleep watcher (0009 §5.1).
    #[cfg(windows)]
    let services = Arc::new(qv_core::platform::WindowsPlatform::default());
    let controller = Controller::new(base, services);
    Ok((guard, controller))
}
/// `%LOCALAPPDATA%\QuickVault\state`: device-local, never roaming.
#[cfg(windows)]
fn state_root() -> Result<std::path::PathBuf, AppError> {
    let path =
        std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or(AppError::Unavailable)?)
            .join("QuickVault")
            .join("state");
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::Unavailable);
    }
    Ok(path)
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
        let (guard, controller) = desktop_setup(Ok(dir.clone())).unwrap();
        assert!(controller.is_ok());
        assert!(matches!(
            desktop_setup(Ok(dir.clone())),
            Err(AppError::AlreadyRunning)
        ));
        drop(guard);
        let file = dir.join("not-a-directory");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(
            desktop_setup(Ok(file)),
            Err(AppError::PrivateStorage)
        ));
        assert!(matches!(
            desktop_setup(Err(AppError::PrivateStorage)),
            Err(AppError::PrivateStorage)
        ));
        drop(controller);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
