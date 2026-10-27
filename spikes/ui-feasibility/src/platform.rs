// SPDX-License-Identifier: AGPL-3.0-or-later

//! Small OS hooks; secret entry remains ordinary shared Dioxus input.
use std::path::PathBuf;

pub(crate) fn initialize(done: impl FnOnce(Result<PathBuf, ()>) + Send + 'static) {
    #[cfg(not(target_os = "android"))]
    done(Ok(std::env::var_os("QV_SPIKE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("quickvault-ui-feasibility-{}", std::process::id()))
        })));
    #[cfg(target_os = "android")]
    dioxus_desktop::wry::prelude::dispatch(move |env, activity, _| {
        let result = (|| {
            let window = env
                .call_method(activity, "getWindow", "()Landroid/view/Window;", &[])
                .map_err(|_| ())?
                .l()
                .map_err(|_| ())?;
            // FLAG_SECURE: this changes only the spike's own window.
            env.call_method(&window, "addFlags", "(I)V", &[0x2000.into()])
                .map_err(|_| ())?;
            let dir = env
                .call_method(activity, "getNoBackupFilesDir", "()Ljava/io/File;", &[])
                .map_err(|_| ())?
                .l()
                .map_err(|_| ())?;
            let path = env
                .call_method(dir, "getAbsolutePath", "()Ljava/lang/String;", &[])
                .map_err(|_| ())?
                .l()
                .map_err(|_| ())?;
            let path = env
                .get_string(&path.into())
                .map_err(|_| ())?
                .to_string_lossy()
                .into_owned();
            // Android can return an app directory through a symlinked alias.
            // SQLite NOFOLLOW rejects symlinks in any path component, not just
            // the final file. Resolve this OS-owned existing root first; keep
            // all store no-follow, ownership and private-parent checks intact.
            let root = std::fs::canonicalize(PathBuf::from(path)).map_err(|_| ())?;
            Ok::<_, ()>(root.join("qv-feasibility"))
        })();
        done(result.map_err(|_| ()));
    });
}

pub(crate) fn watch_background(controller: crate::controller::Controller) {
    #[cfg(not(target_os = "android"))]
    let _ = controller;
    #[cfg(target_os = "android")]
    dioxus_desktop::wry::prelude::dispatch(move |env, activity, _| {
        let (Ok(vm), Ok(activity)) = (env.get_java_vm(), env.new_global_ref(activity)) else {
            controller.lock();
            return;
        };
        std::thread::spawn(move || {
            let Ok(mut env) = vm.attach_current_thread() else {
                controller.lock();
                return;
            };
            let mut was_background = false;
            loop {
                let background = env
                    .call_method(activity.as_obj(), "qvIsBackground", "()Z", &[])
                    .and_then(|v| v.z())
                    .unwrap_or(true);
                if background && !was_background {
                    controller.lock();
                }
                was_background = background;
                let destroyed = env
                    .call_method(activity.as_obj(), "qvIsDestroyed", "()Z", &[])
                    .and_then(|v| v.z())
                    .unwrap_or(true);
                if destroyed {
                    controller.lock();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
    });
}

pub(crate) fn probe(done: impl FnOnce(String) + Send + 'static) {
    #[cfg(not(target_os = "android"))]
    done(
        "Linux OS adapters are deferred to qv-platform; no clipboard content was read or written."
            .into(),
    );
    #[cfg(target_os = "android")]
    dioxus_desktop::wry::prelude::dispatch(move |env, activity, _| {
        let summary = (|| {
            let text = env
                .call_method(activity, "qvProbeSummary", "()Ljava/lang/String;", &[])
                .map_err(|_| ())?
                .l()
                .map_err(|_| ())?;
            Ok::<_, ()>(
                env.get_string(&text.into())
                    .map_err(|_| ())?
                    .to_string_lossy()
                    .into_owned(),
            )
        })()
        .unwrap_or_else(|()| {
            "Platform availability probe failed; optional features remain disabled.".into()
        });
        done(summary);
    });
}
