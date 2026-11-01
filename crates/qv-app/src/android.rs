// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal Wry dispatch glue; OS observations go to qv-platform through core.
use crate::controller::{AppError, Controller, private_dir};
use qv_core::platform::{AndroidPlatform, AndroidState};
use std::sync::Arc;

pub(crate) fn initialize() {
    dioxus_desktop::wry::prelude::dispatch(move |env, activity, _| {
        let setup = (|| {
            let vm = env.get_java_vm().map_err(|_| ())?;
            let activity = env.new_global_ref(activity).map_err(|_| ())?;
            Ok::<_, ()>((vm, activity))
        })();
        let Ok((vm, activity)) = setup else {
            let _ = crate::ui::ACTIVE.set(Err(AppError::Unavailable));
            return;
        };
        std::thread::spawn(move || {
            let os = Arc::new(AndroidPlatform::default());
            let Ok(mut env) = vm.attach_current_thread() else {
                let _ = crate::ui::ACTIVE.set(Err(AppError::Unavailable));
                return;
            };
            let root = (|| {
                let path = env
                    .call_method(
                        activity.as_obj(),
                        "qvPrivateRoot",
                        "()Ljava/lang/String;",
                        &[],
                    )
                    .map_err(|_| ())?
                    .l()
                    .map_err(|_| ())?;
                let path = env
                    .get_string(&path.into())
                    .map_err(|_| ())?
                    .to_string_lossy()
                    .into_owned();
                let path = std::fs::canonicalize(path)
                    .map_err(|_| ())?
                    .join("quickvault");
                private_dir(&path).map_err(|_| ())?;
                Ok::<_, ()>(path)
            })();
            let Ok(root) = root else {
                let _ = crate::ui::ACTIVE.set(Err(AppError::Unavailable));
                return;
            };
            let mut ready = false;
            let mut generation = None;
            loop {
                let flags = env
                    .call_method(activity.as_obj(), "qvStatus", "()I", &[])
                    .and_then(|v| v.i());
                let Ok(flags) = flags else {
                    os.update(AndroidState::default());
                    break;
                };
                if flags & 16 != 0 {
                    os.update(AndroidState::default());
                    break;
                }
                let observed = AndroidState {
                    monitoring: true,
                    foreground: flags & 1 != 0,
                    screen_unlocked: flags & 2 != 0,
                    secure_window: flags & 4 != 0 && flags & 8 != 0,
                };
                let next_generation = env
                    .call_method(activity.as_obj(), "qvGeneration", "()J", &[])
                    .and_then(|v| v.j());
                let Ok(next_generation) = next_generation else {
                    os.update(AndroidState::default());
                    break;
                };
                if generation.is_some_and(|old| old != next_generation) {
                    // Preserve even a pause/resume or screen-off transition that
                    // happened entirely between two native status polls.
                    os.update(AndroidState {
                        foreground: false,
                        screen_unlocked: false,
                        ..observed
                    });
                }
                generation = Some(next_generation);
                os.update(observed);
                if !ready && observed.secure_window {
                    let _ = crate::ui::ACTIVE.set(Controller::new(root.clone(), os.clone()));
                    ready = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    });
}
