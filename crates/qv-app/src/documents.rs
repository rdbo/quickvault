// SPDX-License-Identifier: AGPL-3.0-or-later

//! User-selected files. Linux and Windows use bounded absolute paths through
//! the shared no-follow helpers (0011 §4 path rules; Windows dialogs, plan
//! 0052). Android uses Storage Access
//! Framework documents (`android.rs`): attachments stream in bounded chunks
//! without plaintext temporary files; ciphertext archives are staged in the
//! private no-backup directory and removed afterwards.
use crate::controller::{AppError, Controller};
use crate::workspace::Workspace;
#[cfg(not(target_os = "android"))]
use crate::workspace::WsField;
use qv_core::CancelToken;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[cfg(all(feature = "desktop", windows))]
pub(crate) use qv_core::platform::WindowsPick as Pick;
/// The system picker's choice kind: the desktop portal on Linux, the
/// native dialogs on Windows (plan 0052).
#[cfg(all(feature = "desktop", target_os = "linux"))]
pub(crate) use qv_core::platform::portal::Pick;

/// Attachment bound shared with the CLI and model (10 MiB).
pub const MAX_ATTACHMENT: u64 = 10 * 1024 * 1024;

#[cfg(any(target_os = "linux", windows))]
fn file_error(e: qv_core::platform::PlatformError) -> AppError {
    match e {
        qv_core::platform::PlatformError::StorageCapacity => {
            qv_core::CoreError::Store(qv_core::StoreError::StorageCapacity).into()
        }
        qv_core::platform::PlatformError::LimitExceeded => qv_core::CoreError::LimitExceeded.into(),
        qv_core::platform::PlatformError::Cancelled => qv_core::CoreError::Cancelled.into(),
        _ => AppError::InvalidInput,
    }
}

/// What a document picker is choosing for (Android); used by the UI.
#[cfg(feature = "desktop")]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PickKind {
    /// Attachment input or plaintext output.
    Any,
    /// Archive input or export destination.
    Archive,
    /// A vault to authenticate and import as an independent private copy.
    Vault,
}
/// Which screen's path input a system picker fills.
#[cfg(feature = "desktop")]
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))] // Linux portal picker only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathFor {
    /// The unlocked workspace's file field.
    Workspace,
    /// The locked screen's vault file.
    Locked,
    /// A vault file to list and select where it is (0009 §1.8).
    Import,
    /// The folder new vaults go to.
    Folder,
}
#[cfg(all(feature = "desktop", any(target_os = "linux", windows)))]
static NO_PICKER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Validation fixtures never open a real desktop dialog: they use the typed
/// fallback, which the synthetic flows exercise.
#[cfg(all(feature = "validation", target_os = "linux"))]
pub(crate) fn force_no_picker() {
    NO_PICKER.store(true, std::sync::atomic::Ordering::SeqCst);
}
/// No system picker answered here; screens then offer a typed path instead.
#[cfg(feature = "desktop")]
pub fn picker_missing() -> bool {
    #[cfg(any(target_os = "linux", windows))]
    {
        NO_PICKER.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}

/// Open a vault through the platform picker. Android returns a document
/// capability for verified private import; Linux retains the original path.
#[cfg(feature = "desktop")]
pub(crate) fn pick_vault(c: &Controller, epoch: crate::controller::FormEpoch) {
    #[cfg(any(target_os = "linux", windows))]
    pick_path(
        c,
        epoch,
        PathFor::Import,
        crate::documents::Pick::Open,
        "Open a QuickVault vault",
        None,
    );
    #[cfg(target_os = "android")]
    crate::android::request_pick(c, epoch, PickKind::Vault, false);
    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    let _ = (c, epoch);
}

/// Switching obeys the same unsaved-input/lock rules as the existing list.
#[cfg(feature = "desktop")]
pub(crate) fn switch_to_file(c: &Controller, epoch: crate::controller::FormEpoch) {
    if c.switch_vault(
        epoch,
        crate::controller::SwitchTo::Mode(crate::controller::Mode::Unlock),
    ) {
        pick_vault(c, c.snapshot().epoch);
    }
}
/// Linux: show the desktop's file picker on a worker thread and put the choice
/// into the current screen's protected path input (0009 §1.8). Cancelling
/// changes nothing; a stale screen ignores the result.
#[cfg(all(feature = "desktop", any(target_os = "linux", windows)))]
pub(crate) fn pick_path(
    c: &Controller,
    epoch: crate::controller::FormEpoch,
    to: PathFor,
    kind: crate::documents::Pick,
    title: &'static str,
    then: Option<crate::workspace::WsAction>,
) {
    let c = c.clone();
    let _ = std::thread::Builder::new()
        .name("qv-picker".into())
        .spawn(move || {
            #[cfg(target_os = "linux")]
            let chosen = crate::picker::pick(title, &kind);
            #[cfg(windows)]
            let chosen = qv_core::platform::pick(title, &kind);
            match chosen {
                Ok(Some(path)) => match path.into_os_string().into_string() {
                    Ok(mut text) => {
                        match to {
                            PathFor::Workspace => c.ws_input(epoch, WsField::Path, &mut text),
                            PathFor::Locked => {
                                c.input(epoch, crate::controller::InputField::Path, &mut text)
                            }
                            PathFor::Import => c.import_vault(epoch, std::path::Path::new(&text)),
                            PathFor::Folder => {
                                if let Err(e) = c.set_default_folder(std::path::Path::new(&text)) {
                                    c.report(epoch, e);
                                }
                            }
                        }
                        zeroize::Zeroize::zeroize(&mut text);
                        if let Some(action) = then {
                            c.act(epoch, action);
                        }
                    }
                    Err(_) => c.report(epoch, AppError::InvalidInput),
                },
                Ok(None) => {}
                Err(_) => {
                    NO_PICKER.store(true, std::sync::atomic::Ordering::SeqCst);
                    c.report(epoch, AppError::NoFilePicker);
                }
            }
            c.touch();
        });
}
/// A chosen input document.
pub(crate) enum Source {
    /// An absolute local path (Linux).
    #[cfg_attr(target_os = "android", allow(dead_code))]
    Path(PathBuf),
    /// A picked Android document, by request id.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    Document(u64),
}
/// A chosen output destination.
pub(crate) enum Target {
    /// An absolute local path (Linux).
    #[cfg_attr(target_os = "android", allow(dead_code))]
    Path(PathBuf),
    /// A created Android document, by request id.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    Document(u64),
}
/// An archive path for core; a staged private copy is removed on drop.
pub(crate) struct Staged {
    path: PathBuf,
    remove: bool,
}
impl Staged {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for Staged {
    fn drop(&mut self) {
        if self.remove {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
#[cfg(not(target_os = "android"))]
fn absolute(ws: &Workspace) -> Result<PathBuf, AppError> {
    let path = PathBuf::from(ws.text(WsField::Path)?);
    if !path.is_absolute() {
        return Err(AppError::InvalidInput);
    }
    Ok(path)
}
#[cfg(target_os = "android")]
fn picked(ws: &Workspace, create: bool) -> Result<u64, AppError> {
    let _ = ws;
    crate::android::picked_for(create)
        .and_then(|id| u64::try_from(id).ok())
        .ok_or(AppError::InvalidInput)
}
/// Directory for a new archive: private staging on Android.
#[cfg(target_os = "android")]
pub(crate) fn export_dir(ws: &Workspace) -> Result<PathBuf, AppError> {
    picked(ws, true)?;
    crate::android::staging_dir()
}
/// Directory for a new archive: the chosen local directory.
#[cfg(not(target_os = "android"))]
pub(crate) fn export_dir(ws: &Workspace) -> Result<PathBuf, AppError> {
    absolute(ws)
}
/// After export on Android, copy the published archive to the picked document.
#[cfg(target_os = "android")]
pub(crate) fn finish_export(_: &Controller, dir: &Path, id: &str) -> Result<(), AppError> {
    crate::android::copy_out_archive(dir, id)
}
/// Local exports are already at their destination.
#[cfg(not(target_os = "android"))]
pub(crate) fn finish_export(_: &Controller, _: &Path, _: &str) -> Result<(), AppError> {
    Ok(())
}
#[cfg(target_os = "android")]
pub(crate) fn import_source(ws: &Workspace) -> Result<Source, AppError> {
    Ok(Source::Document(picked(ws, false)?))
}
#[cfg(not(target_os = "android"))]
pub(crate) fn import_source(ws: &Workspace) -> Result<Source, AppError> {
    Ok(Source::Path(absolute(ws)?))
}
/// A path core can authenticate: the local file itself, or a bounded private
/// staged copy of a picked document (ciphertext only).
pub(crate) fn stage_import(
    c: &Controller,
    source: Source,
    token: &CancelToken,
) -> Result<Staged, AppError> {
    let _ = (c, token);
    match source {
        Source::Path(path) => Ok(Staged {
            path,
            remove: false,
        }),
        Source::Document(id) => stage_document(id, token),
    }
}
#[cfg(target_os = "android")]
fn stage_document(id: u64, token: &CancelToken) -> Result<Staged, AppError> {
    let path = crate::android::stage_document(id, token)?;
    Ok(Staged { path, remove: true })
}
#[cfg(not(target_os = "android"))]
fn stage_document(_: u64, _: &CancelToken) -> Result<Staged, AppError> {
    Err(AppError::Unavailable)
}
pub(crate) fn attachment_source(ws: &Workspace) -> Result<Source, AppError> {
    import_source(ws)
}
#[cfg(target_os = "android")]
pub(crate) fn attachment_target(ws: &Workspace) -> Result<Target, AppError> {
    Ok(Target::Document(picked(ws, true)?))
}
#[cfg(not(target_os = "android"))]
pub(crate) fn attachment_target(ws: &Workspace) -> Result<Target, AppError> {
    Ok(Target::Path(absolute(ws)?))
}
/// Open attachment input with its default name (the UTF-8 basename).
pub(crate) fn open_attachment(
    c: &Controller,
    source: Source,
    token: &CancelToken,
) -> Result<(Box<dyn Read + Send>, Zeroizing<String>), AppError> {
    let _ = c;
    match source {
        Source::Path(path) => {
            #[cfg(any(target_os = "linux", windows))]
            {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(AppError::InvalidInput)?;
                let name = Zeroizing::new(name.to_owned());
                let cancel = cancellation(token);
                let input = qv_core::platform::files::Input::open(&path, MAX_ATTACHMENT, cancel)
                    .map_err(|e| {
                        if e == qv_core::platform::PlatformError::LimitExceeded {
                            AppError::Core(qv_core::CoreError::LimitExceeded)
                        } else {
                            AppError::InvalidInput
                        }
                    })?;
                Ok((Box::new(input), name))
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                let _ = (path, token);
                Err(AppError::Unavailable)
            }
        }
        Source::Document(id) => read_document(id, token),
    }
}
/// Explicit plaintext output; partial content may remain on failure.
pub(crate) struct Output {
    inner: Box<dyn Write + Send>,
    finish: Box<dyn FnOnce() -> Result<(), AppError> + Send>,
}
impl Output {
    pub(crate) fn finish(self) -> Result<(), AppError> {
        let Self { mut inner, finish } = self;
        inner.flush().map_err(|_| AppError::Unavailable)?;
        drop(inner);
        finish()
    }
}
impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
pub(crate) fn create_output(
    c: &Controller,
    target: Target,
    token: &CancelToken,
) -> Result<Output, AppError> {
    let _ = c;
    match target {
        Target::Path(path) => {
            #[cfg(any(target_os = "linux", windows))]
            {
                let out = qv_core::platform::files::Output::create(&path, cancellation(token))
                    .map_err(file_error)?;
                let out = std::sync::Arc::new(std::sync::Mutex::new(out));
                let writer = Shared(out.clone());
                Ok(Output {
                    inner: Box::new(writer),
                    finish: Box::new(move || {
                        out.lock()
                            .map_err(|_| AppError::Unavailable)?
                            .finish()
                            .map_err(file_error)
                    }),
                })
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                let _ = (path, token);
                Err(AppError::Unavailable)
            }
        }
        Target::Document(id) => write_document(id, token),
    }
}
#[cfg(target_os = "android")]
fn read_document(
    id: u64,
    token: &CancelToken,
) -> Result<(Box<dyn Read + Send>, Zeroizing<String>), AppError> {
    crate::android::read_document(id, MAX_ATTACHMENT, token)
}
#[cfg(not(target_os = "android"))]
fn read_document(
    _: u64,
    _: &CancelToken,
) -> Result<(Box<dyn Read + Send>, Zeroizing<String>), AppError> {
    Err(AppError::Unavailable)
}
#[cfg(target_os = "android")]
fn write_document(id: u64, token: &CancelToken) -> Result<Output, AppError> {
    crate::android::write_document(id, token)
}
#[cfg(not(target_os = "android"))]
fn write_document(_: u64, _: &CancelToken) -> Result<Output, AppError> {
    Err(AppError::Unavailable)
}
#[cfg(any(target_os = "linux", windows))]
struct Shared(std::sync::Arc<std::sync::Mutex<qv_core::platform::files::Output>>);
#[cfg(any(target_os = "linux", windows))]
impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?
            .write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?
            .flush()
    }
}
#[cfg(any(target_os = "linux", windows))]
fn cancellation(token: &CancelToken) -> qv_core::platform::Cancellation {
    let token = token.clone();
    std::sync::Arc::new(move || token.is_cancelled())
}
impl Output {
    #[cfg(target_os = "android")]
    pub(crate) fn new(
        inner: Box<dyn Write + Send>,
        finish: Box<dyn FnOnce() -> Result<(), AppError> + Send>,
    ) -> Self {
        Self { inner, finish }
    }
}
