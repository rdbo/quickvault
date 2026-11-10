// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit synthetic-only native media qualification. Absent from production.
use crate::controller::{AppError, Controller, Phase, private_dir};
use crate::workspace::{Screen, Workspace};
use qv_core::{AnchorDir, Core, CoreConfig, MasterPassword, SnapshotDir, SnapshotPolicy};
use std::io::Read;
use std::sync::Arc;

pub(crate) fn enabled() -> bool {
    #[cfg(target_os = "android")]
    {
        option_env!("QV_APP_MEDIA_VALIDATION") == Some("1")
    }
    #[cfg(not(target_os = "android"))]
    {
        std::env::var_os("QV_TEST_MEDIA_FLOW").is_some_and(|value| value == "1")
    }
}
struct Wave {
    header: [u8; 44],
    at: u64,
}
impl Wave {
    const DATA: u32 = 8 * 1024 * 1024;
    fn new() -> Self {
        let mut header = [0; 44];
        header[..4].copy_from_slice(b"RIFF");
        header[4..8].copy_from_slice(&(Self::DATA + 36).to_le_bytes());
        header[8..16].copy_from_slice(b"WAVEfmt ");
        header[16..20].copy_from_slice(&16u32.to_le_bytes());
        header[20..22].copy_from_slice(&1u16.to_le_bytes());
        header[22..24].copy_from_slice(&1u16.to_le_bytes());
        header[24..28].copy_from_slice(&8000u32.to_le_bytes());
        header[28..32].copy_from_slice(&16000u32.to_le_bytes());
        header[32..34].copy_from_slice(&2u16.to_le_bytes());
        header[34..36].copy_from_slice(&16u16.to_le_bytes());
        header[36..40].copy_from_slice(b"data");
        header[40..].copy_from_slice(&Self::DATA.to_le_bytes());
        Self { header, at: 0 }
    }
}
impl Read for Wave {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out
            .len()
            .min((u64::from(Self::DATA) + 44 - self.at) as usize);
        out[..n].fill(0); // Public synthetic silence, generated without a full-file allocation.
        if self.at < 44 {
            let start = self.at as usize;
            let header = n.min(44 - start);
            out[..header].copy_from_slice(&self.header[start..start + header]);
        }
        self.at += n as u64;
        Ok(n)
    }
}
pub(crate) fn install(controller: &Controller) -> Result<(), AppError> {
    if !enabled() || !controller.is_fixture() {
        return Err(AppError::InvalidInput);
    }
    let base = controller.0.base.join("media-fixture");
    // A new named fixture only, never an existing/personal vault.
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&base).map_err(|_| AppError::Unavailable)?;
    private_dir(&base)?;
    let vaults = base.join("vaults");
    private_dir(&vaults)?;
    let anchors = AnchorDir::open(&base.join("anchors")).map_err(qv_core::CoreError::from)?;
    let snapshots = SnapshotPolicy::new(
        SnapshotDir::open(&base.join("snapshots")).map_err(qv_core::CoreError::from)?,
    );
    let core = Core::new(CoreConfig::new(anchors).with_snapshots(snapshots))
        .with_platform(controller.0.services.clone(), true); // Synthetic fixture acknowledgement only.
    let password = MasterPassword::from_utf8(b"synthetic-media-fixture-only-0050")
        .map_err(|_| AppError::Unavailable)?;
    let path = vaults.join("synthetic-media.qvault");
    let created = core.create(&path, &password, "Synthetic media")?;
    let session = Arc::new(created.session);
    drop(created.recovery_phrase);
    let entry =
        session.save_entry(session.new_entry(session.root()?, "note", "Synthetic media")?)?;
    session.add_attachment(entry, "a-audio.wav", "wrong/type", &mut Wave::new(), None)?;
    for (name, bytes) in [
        (
            "b-video.mp4",
            include_bytes!("../tests/fixtures/preview.mp4").as_slice(),
        ),
        (
            "c-image.png",
            include_bytes!("../tests/fixtures/preview.png").as_slice(),
        ),
        (
            "d-large.png",
            include_bytes!("../tests/fixtures/large-preview.png").as_slice(),
        ),
    ] {
        session.add_attachment(entry, name, "wrong/type", &mut &bytes[..], None)?;
    }
    let mut state = controller.state();
    state.session = Some(session);
    state.phase = Phase::Unlocked;
    state.vault_path = Some(path);
    state.epoch = state.epoch.wrapping_add(1);
    let mut workspace = Workspace::new(false);
    workspace.screen = Screen::Entry(entry);
    state.workspace = Some(workspace);
    state.revision = state.revision.wrapping_add(1);
    println!("synthetic media fixture ready; pid={}", std::process::id());
    Ok(())
}
pub(crate) fn finish(controller: &Controller, passed: bool) {
    if !enabled() || !controller.is_fixture() {
        std::process::exit(2);
    }
    controller.lock();
    let cleaned = std::fs::remove_dir_all(controller.0.base.join("media-fixture")).is_ok();
    #[cfg(target_os = "linux")]
    let cleaned = cleaned && std::fs::remove_dir_all(&controller.0.base).is_ok();
    let passed = passed && cleaned;
    #[cfg(target_os = "android")]
    {
        // Fixed status only, inside this explicitly isolated synthetic build.
        // Keep the activity alive so instrumentation can read the outcome.
        let _ = std::fs::write(
            controller.0.base.join("media-result"),
            if passed { b"PASS" } else { b"FAIL" },
        );
        return;
    }
    #[cfg(not(target_os = "android"))]
    if passed {
        println!("synthetic media playback, seek and revocation passed");
        std::process::exit(0);
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("synthetic media validation failed");
        std::process::exit(1);
    }
}
