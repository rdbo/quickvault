// SPDX-License-Identifier: AGPL-3.0-or-later

//! Only the `qv` command is exposed to the window (capabilities/main.json).
fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["qv"])),
    )
    .unwrap_or_else(|e| {
        println!("cargo:warning={e}");
        std::process::exit(1);
    });
}
