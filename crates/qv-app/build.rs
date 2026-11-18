// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tauri's build step for the app (plan 0071): only the `qv` command is
//! exposed to the window (capabilities/main.json). The page is built by
//! `crates/qv-ui/build.sh` into `dist/ui`; without it a placeholder page
//! keeps library builds and checks working.
fn main() {
    #[cfg(feature = "desktop")]
    {
        let ui = std::path::Path::new("dist/ui");
        if !ui.join("index.html").exists() {
            let _ = std::fs::create_dir_all(ui);
            let _ = std::fs::write(
                ui.join("index.html"),
                "<!doctype html><title>QuickVault</title><p>The page is not built: run crates/qv-ui/build.sh.</p>",
            );
        }
        // A release package must carry the real page, never the placeholder.
        if std::env::var("PROFILE").as_deref() == Ok("release")
            && !ui.join("pkg/qv_ui_bg.wasm").exists()
        {
            println!("cargo:warning=release build without the page: run crates/qv-ui/build.sh");
            std::process::exit(1);
        }
        println!("cargo:rerun-if-changed=dist/ui");
        println!("cargo:rerun-if-changed=tauri.conf.json");
        println!("cargo:rerun-if-changed=capabilities");
        if let Err(e) = tauri_build::try_build(
            tauri_build::Attributes::new()
                .app_manifest(tauri_build::AppManifest::new().commands(&["qv"])),
        ) {
            println!("cargo:warning={e}");
            std::process::exit(1);
        }
    }
}
