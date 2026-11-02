// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal Wry dispatch glue; OS observations go to qv-platform through core.
//! Clipboard text and attachment chunks cross JNI as documented best-effort
//! JVM intermediates (0008 §4.4); Uris stay in Kotlin. No unsafe code.
use crate::controller::{AppError, Controller, FormEpoch, private_dir};
use crate::documents::{Output, PickKind};
use dioxus_desktop::wry::prelude::jni::{
    self, JNIEnv, JavaVM,
    objects::{GlobalRef, JObject, JValue},
};
use qv_core::CancelToken;
use qv_core::platform::{
    AndroidClipboardBackend, AndroidPlatform, AndroidState, BackgroundDeferral, ClipToken,
    PlatformError,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

static BRIDGE: OnceLock<(JavaVM, GlobalRef)> = OnceLock::new();
static ROOT: OnceLock<PathBuf> = OnceLock::new();
/// The current document pick: request id and whether it creates a document.
static PICK: Mutex<Option<(i64, bool)>> = Mutex::new(None);
static OS: OnceLock<Arc<AndroidPlatform>> = OnceLock::new();
/// The system picker always backgrounds the activity. A pick started in the
/// foreground defers only background expiry (decision 1's rule) until the
/// lifecycle poller sees the activity back with the pick finished, or the pick
/// forgotten by a lock. Screen lock, lost protection and the inactivity lock
/// still apply. Only the poller drops it: dropping can run lock callbacks.
static PICK_DEFERRAL: Mutex<Option<BackgroundDeferral>> = Mutex::new(None);
const CHUNK: i32 = 64 * 1024;

/// Call the activity on this thread; a pending Java exception is cleared and
/// reported as a data-free failure.
fn call<T>(f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>) -> Result<T, AppError> {
    let (vm, activity) = BRIDGE.get().ok_or(AppError::Unavailable)?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| AppError::Unavailable)?;
    let result = f(&mut env, activity.as_obj());
    if result.is_err() {
        let _ = env.exception_clear();
    }
    result.map_err(|_| AppError::Unavailable)
}
struct NativeClipboard;
impl AndroidClipboardBackend for NativeClipboard {
    fn set(&self, text: &str) -> Result<ClipToken, PlatformError> {
        call(|env, a| {
            let s = env.new_string(text)?;
            env.call_method(a, "qvCopy", "(Ljava/lang/String;)J", &[JValue::Object(&s)])?
                .j()
        })
        .map(ClipToken)
        .map_err(|_| PlatformError::Io)
    }
    fn owned(&self, token: ClipToken) -> Option<bool> {
        match call(|env, a| {
            env.call_method(a, "qvClipOwned", "(J)I", &[JValue::Long(token.0)])?
                .i()
        }) {
            Ok(1) => Some(true),
            Ok(0) => Some(false),
            _ => None,
        }
    }
    fn clear(&self) -> Result<(), PlatformError> {
        call(|env, a| env.call_method(a, "qvClipClear", "()V", &[]).map(|_| ()))
            .map_err(|_| PlatformError::Io)
    }
}
/// Ask the user to choose a document; the result is polled by later actions.
pub(crate) fn request_pick(c: &Controller, epoch: FormEpoch, kind: PickKind, create: bool) {
    if c.screen(epoch).is_none() {
        return;
    }
    let archive = kind == PickKind::Archive;
    let deferral = OS.get().and_then(|os| os.defer_background());
    if let Ok(id) = call(|env, a| {
        env.call_method(
            a,
            "qvPick",
            "(ZZ)J",
            &[JValue::Bool(create.into()), JValue::Bool(archive.into())],
        )?
        .j()
    }) && let Ok(mut pick) = PICK.lock()
    {
        *pick = Some((id, create));
        drop(pick);
        // Clear a stale "Chosen" hint at once.
        c.touch();
        let previous = PICK_DEFERRAL
            .lock()
            .ok()
            .and_then(|mut held| std::mem::replace(&mut *held, deferral));
        drop(previous);
    }
}
/// Poller only. Once a pick has an outcome, advance the revision so the
/// screen shows it. End its deferral once the activity is back and the pick
/// has an outcome, or once the pick was forgotten.
fn poll_pick(foreground: bool, seen: &mut Option<i64>) {
    let pick = PICK.lock().ok().and_then(|p| *p);
    let held = PICK_DEFERRAL.lock().is_ok_and(|held| held.is_some());
    let finished = match pick {
        None => true,
        Some((id, _)) if held || *seen != Some(id) => call(|env, a| {
            env.call_method(a, "qvPickState", "(J)I", &[JValue::Long(id)])?
                .i()
        })
        .is_ok_and(|state| state != 0),
        Some(_) => true,
    };
    if let (Some((id, _)), true) = (pick, finished)
        && *seen != Some(id)
    {
        *seen = Some(id);
        if let Some(Ok(c)) = crate::ui::ACTIVE.get() {
            c.touch();
        }
    }
    if held && finished && (foreground || pick.is_none()) {
        let deferral = PICK_DEFERRAL.lock().ok().and_then(|mut held| held.take());
        drop(deferral);
    }
}
/// Forget any document choice (lock).
pub(crate) fn forget_pick() {
    if let Ok(mut pick) = PICK.lock() {
        *pick = None;
    }
    let _ = call(|env, a| env.call_method(a, "qvForgetPick", "()V", &[]).map(|_| ()));
}
fn ready(id: i64) -> bool {
    call(|env, a| {
        env.call_method(a, "qvPickState", "(J)I", &[JValue::Long(id)])?
            .i()
    })
    .is_ok_and(|s| s == 1)
}
/// The chosen document for an input (`create == false`) or an output.
pub(crate) fn picked_for(create: bool) -> Option<i64> {
    let (id, kind) = (*PICK.lock().ok()?)?;
    (kind == create && ready(id)).then_some(id)
}
/// The chosen document's display name, shown as untrusted escaped text.
pub(crate) fn picked_name() -> Option<String> {
    let (id, _) = (*PICK.lock().ok()?)?;
    if !ready(id) {
        return None;
    }
    call(|env, a| {
        let name = env
            .call_method(a, "qvPickedName", "()Ljava/lang/String;", &[])?
            .l()?;
        if name.is_null() {
            // Some providers (and file Uris) report no display name.
            return Ok(Some("unnamed document".to_owned()));
        }
        Ok(Some(
            env.get_string(&name.into())?.to_string_lossy().into_owned(),
        ))
    })
    .ok()
    .flatten()
}
/// Bounded chunked reader over the picked document.
struct DocReader {
    left: u64,
    token: CancelToken,
}
impl Read for DocReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.token.is_cancelled() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        let want = i32::try_from(out.len().min(CHUNK as usize)).unwrap_or(CHUNK);
        let mut bytes = call(|env, a| {
            let array = env
                .call_method(a, "qvRead", "(I)[B", &[JValue::Int(want)])?
                .l()?;
            if array.is_null() {
                return Ok(None);
            }
            Ok(Some(env.convert_byte_array(
                jni::objects::JByteArray::from(array),
            )?))
        })
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Other))?;
        let n = bytes.len().min(out.len());
        if u64::try_from(n).map_or(true, |n| n > self.left) {
            bytes.zeroize();
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        out[..n].copy_from_slice(&bytes[..n]);
        bytes.zeroize();
        self.left -= n as u64;
        Ok(n)
    }
}
impl Drop for DocReader {
    fn drop(&mut self) {
        let _ = call(|env, a| {
            env.call_method(a, "qvCloseDoc", "(Z)Z", &[JValue::Bool(0)])
                .map(|_| ())
        });
    }
}
/// Open the picked input document with its default name.
pub(crate) fn read_document(
    id: u64,
    max: u64,
    token: &CancelToken,
) -> Result<(Box<dyn Read + Send>, Zeroizing<String>), AppError> {
    let id = i64::try_from(id).map_err(|_| AppError::InvalidInput)?;
    let name = picked_name().unwrap_or_else(|| "attachment".into());
    let opened = call(|env, a| {
        env.call_method(a, "qvOpenRead", "(J)Z", &[JValue::Long(id)])?
            .z()
    })?;
    if !opened {
        return Err(AppError::InvalidInput);
    }
    let reader = DocReader {
        left: max,
        token: token.clone(),
    };
    Ok((Box::new(reader), Zeroizing::new(name)))
}
struct DocWriter {
    token: CancelToken,
}
impl Write for DocWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.token.is_cancelled() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        let n = bytes.len().min(CHUNK as usize);
        let ok = call(|env, a| {
            let array = env.byte_array_from_slice(&bytes[..n])?;
            env.call_method(a, "qvWrite", "([B)Z", &[JValue::Object(&array)])?
                .z()
        })
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?;
        if !ok {
            return Err(std::io::ErrorKind::Other.into());
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Create plaintext output into the picked document; finishing syncs it.
pub(crate) fn write_document(id: u64, token: &CancelToken) -> Result<Output, AppError> {
    let id = i64::try_from(id).map_err(|_| AppError::InvalidInput)?;
    let opened = call(|env, a| {
        env.call_method(a, "qvOpenWrite", "(J)Z", &[JValue::Long(id)])?
            .z()
    })?;
    if !opened {
        return Err(AppError::InvalidInput);
    }
    Ok(Output::new(
        Box::new(DocWriter {
            token: token.clone(),
        }),
        Box::new(|| {
            let ok = call(|env, a| {
                env.call_method(a, "qvCloseDoc", "(Z)Z", &[JValue::Bool(1)])?
                    .z()
            })?;
            // A written destination is not reused: a later save would
            // silently overwrite it.
            forget_pick();
            ok.then_some(()).ok_or(AppError::Unavailable)
        }),
    ))
}
/// Private staging directory for ciphertext archives.
pub(crate) fn staging_dir() -> Result<PathBuf, AppError> {
    let dir = ROOT.get().ok_or(AppError::Unavailable)?.join("staging");
    private_dir(&dir)?;
    Ok(dir)
}
/// Copy a picked archive into private staging, at most the archive bound.
pub(crate) fn stage_document(id: u64, token: &CancelToken) -> Result<PathBuf, AppError> {
    let (mut reader, _) = read_document(id, qv_core::MAX_ARCHIVE_TOTAL_LENGTH, token)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = staging_dir()?.join(format!("import-{nanos}.qvsnap"));
    let result = (|| -> Result<(), AppError> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| AppError::Unavailable)?;
        std::io::copy(&mut reader, &mut file).map_err(|_| AppError::InvalidInput)?;
        file.sync_all().map_err(|_| AppError::Unavailable)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&path);
    }
    result.map(|()| path)
}
/// Copy a published staged archive to the picked destination, then remove it.
pub(crate) fn copy_out_archive(dir: &Path, id: &str) -> Result<(), AppError> {
    let source = dir.join(format!("{id}.qvsnap"));
    let result = (|| -> Result<(), AppError> {
        let doc = picked_for(true).ok_or(AppError::InvalidInput)?;
        let doc = u64::try_from(doc).map_err(|_| AppError::InvalidInput)?;
        let mut output = write_document(doc, &CancelToken::new())?;
        let mut file = std::fs::File::open(&source).map_err(|_| AppError::Unavailable)?;
        std::io::copy(&mut file, &mut output).map_err(|_| AppError::Unavailable)?;
        output.finish()
    })();
    let _ = std::fs::remove_file(&source);
    result
}

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
        let poll_activity = activity.clone();
        let Ok(poll_vm) = env.get_java_vm() else {
            let _ = crate::ui::ACTIVE.set(Err(AppError::Unavailable));
            return;
        };
        let _ = BRIDGE.set((vm, activity));
        std::thread::spawn(move || {
            let os = Arc::new(AndroidPlatform::default().with_clipboard(Arc::new(NativeClipboard)));
            let _ = OS.set(os.clone());
            let Ok(mut env) = poll_vm.attach_current_thread() else {
                let _ = crate::ui::ACTIVE.set(Err(AppError::Unavailable));
                return;
            };
            let activity = poll_activity;
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
            // Ciphertext staging left by an interrupted import/export is removed.
            let _ = std::fs::remove_dir_all(root.join("staging"));
            let _ = ROOT.set(root.clone());
            let mut ready = false;
            let mut generation = None;
            let mut seen_pick = None;
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
                let next = env
                    .call_method(activity.as_obj(), "qvGeneration", "()J", &[])
                    .and_then(|v| v.j())
                    .and_then(|pause| {
                        env.call_method(activity.as_obj(), "qvScreenGeneration", "()J", &[])
                            .and_then(|v| v.j())
                            .map(|screen| (pause, screen))
                    });
                let Ok(next) = next else {
                    os.update(AndroidState::default());
                    break;
                };
                // Preserve a pause/resume or screen-off transition that happened
                // entirely between two polls. A screen-off locks at once; a
                // pause is a background transition (deferred only by a clipboard
                // hold started in the foreground).
                if let Some((pause, screen)) = generation {
                    if screen != next.1 {
                        os.update(AndroidState {
                            foreground: false,
                            screen_unlocked: false,
                            ..observed
                        });
                    } else if pause != next.0 {
                        os.update(AndroidState {
                            foreground: false,
                            ..observed
                        });
                    }
                }
                generation = Some(next);
                os.update(observed);
                poll_pick(observed.foreground, &mut seen_pick);
                if !ready && observed.secure_window {
                    let _ = crate::ui::ACTIVE.set(Controller::new(root.clone(), os.clone()));
                    ready = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    });
}
