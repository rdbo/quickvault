// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal Wry dispatch glue; OS observations go to qv-platform through core.
//! Clipboard text and attachment chunks cross JNI as documented best-effort
//! JVM intermediates (0008 §4.4); Uris stay in Kotlin. No unsafe code.
use crate::autofill::AutofillSink;
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
    if c.screen(epoch).is_none() || c.snapshot().busy {
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
    }) && id > 0
        && let Ok(mut pick) = PICK.lock()
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
            #[cfg(feature = "validation")]
            let quick: Arc<dyn qv_core::platform::AndroidKeystoreBackend> =
                Arc::new(FixtureKeystore);
            #[cfg(not(feature = "validation"))]
            let quick: Arc<dyn qv_core::platform::AndroidKeystoreBackend> =
                Arc::new(NativeKeystore);
            let os = Arc::new(
                AndroidPlatform::default()
                    .with_clipboard(Arc::new(NativeClipboard))
                    .with_keystore(Arc::new(qv_core::platform::AndroidKeystore::new(quick))),
            );
            let _ = OS.set(os.clone());
            crate::autofill::set_sink(Box::new(NativeAutofill));
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
                #[cfg(feature = "validation")]
                let path = path.join("validation-current");
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
                    stopped(&mut env, &activity);
                    break;
                };
                if flags & 16 != 0 {
                    os.update(AndroidState::default());
                    stopped(&mut env, &activity);
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
                    stopped(&mut env, &activity);
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
                    #[cfg(not(feature = "validation"))]
                    let controller = Controller::new(root.clone(), os.clone());
                    #[cfg(feature = "validation")]
                    let controller = Controller::new(root.clone(), os.clone()).inspect(|c| {
                        c.0.fixture.store(true, std::sync::atomic::Ordering::SeqCst);
                    });
                    let _ = crate::ui::ACTIVE.set(controller);
                    ready = true;
                }
                // A cold-start handoff claims its request before this runtime
                // exists; fetch it only once the controller can take it.
                if ready {
                    poll_autofill();
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    });
}

/// Bounded native keystore channel. No vault or plaintext enters UI events.
struct NativeKeystore;
impl qv_core::platform::AndroidKeystoreBackend for NativeKeystore {
    fn validated(&self) -> bool {
        call(|env, a| env.call_method(a, "qvQuickAvailable", "()Z", &[])?.z()).unwrap_or(false)
    }
    fn seal(
        &self,
        binding: qv_core::platform::QuickBinding,
        policy: qv_core::platform::QuickPolicy,
        secret: &qv_core::SecretBytes,
        cancel: qv_core::platform::Cancellation,
    ) -> Result<qv_core::SecretBytes, PlatformError> {
        quick_operation(true, binding, policy, secret, cancel)
    }
    fn open(
        &self,
        binding: qv_core::platform::QuickBinding,
        policy: qv_core::platform::QuickPolicy,
        envelope: &qv_core::SecretBytes,
        cancel: qv_core::platform::Cancellation,
    ) -> Result<qv_core::SecretBytes, PlatformError> {
        quick_operation(false, binding, policy, envelope, cancel)
    }
    fn delete(&self, envelope: &qv_core::SecretBytes) -> Result<(), PlatformError> {
        if envelope.len() > 1536 {
            return Err(PlatformError::InvalidInput);
        }
        let ok = call(|env, a| {
            let array = env.byte_array_from_slice(envelope.expose_secret())?;
            env.call_method(a, "qvQuickDelete", "([B)Z", &[JValue::Object(&array)])?
                .z()
        })
        .map_err(|_| PlatformError::Io)?;
        if ok { Ok(()) } else { Err(PlatformError::Io) }
    }
}
fn quick_operation(
    encrypt: bool,
    binding: qv_core::platform::QuickBinding,
    policy: qv_core::platform::QuickPolicy,
    payload: &qv_core::SecretBytes,
    cancel: qv_core::platform::Cancellation,
) -> Result<qv_core::SecretBytes, PlatformError> {
    let limit = if encrypt { 1024 } else { 1536 };
    if payload.is_empty() || payload.len() > limit {
        return Err(PlatformError::InvalidInput);
    }
    if cancel() {
        return Err(PlatformError::Cancelled);
    }
    let _foreground = OS
        .get()
        .and_then(|os| os.defer_background())
        .ok_or(PlatformError::Unavailable)?;
    let id = call(|env, a| {
        let context = env.byte_array_from_slice(&binding.encode())?;
        let bytes = env.byte_array_from_slice(payload.expose_secret())?;
        env.call_method(
            a,
            "qvQuickStart",
            "(Z[BI[B)J",
            &[
                JValue::Bool(encrypt.into()),
                JValue::Object(&context),
                JValue::Int(policy as i32),
                JValue::Object(&bytes),
            ],
        )?
        .j()
    })
    .map_err(|_| PlatformError::Io)?;
    if id <= 0 {
        return Err(PlatformError::Unavailable);
    }
    let began = std::time::Instant::now();
    let result = (|| {
        loop {
            if cancel() || began.elapsed() >= std::time::Duration::from_secs(60) {
                return Err(PlatformError::Cancelled);
            }
            let status = call(|env, a| {
                env.call_method(a, "qvQuickState", "(J)I", &[JValue::Long(id)])?
                    .i()
            })
            .map_err(|_| PlatformError::Io)?;
            // Success and cancellation can both arrive before credential UI
            // dismissal is observed. Retain the guard through that observation.
            let _resumed = if status != 0 {
                let resumed = OS.get().and_then(|os| os.defer_background());
                if resumed.is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                resumed
            } else {
                None
            };
            if status == 1 {
                let maximum = if encrypt { 1536 } else { 1024 };
                let bytes = call(|env, a| {
                    let array: jni::objects::JByteArray = env
                        .call_method(a, "qvQuickResult", "(J)[B", &[JValue::Long(id)])?
                        .l()?
                        .into();
                    let length = env.get_array_length(&array)?;
                    if length <= 0 || length > maximum {
                        return Err(jni::errors::Error::NullPtr("quick result bounds"));
                    }
                    env.convert_byte_array(array)
                })
                .map_err(|_| PlatformError::Io)?;
                let bytes = Zeroizing::new(bytes);
                return qv_core::SecretBytes::try_init(bytes.len(), |out| {
                    out.copy_from_slice(&bytes);
                    Ok(())
                });
            }
            if status != 0 {
                let transient = call(|env, a| {
                    env.call_method(a, "qvQuickFailureKind", "(J)I", &[JValue::Long(id)])?
                        .i()
                })
                .unwrap_or(2);
                return Err(if transient == 1 {
                    PlatformError::Cancelled
                } else {
                    PlatformError::Unavailable
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })();
    let _ = call(|env, a| {
        env.call_method(
            a,
            "qvQuickFinish",
            "(JZ)V",
            &[JValue::Long(id), JValue::Bool(result.is_ok().into())],
        )
        .map(|_| ())
    });
    result
}

/// Availability-only test adapter. Built solely into the explicitly marked,
/// path-restricted synthetic fixture; hardware operations remain the real ones.
#[cfg(feature = "validation")]
struct FixtureKeystore;
#[cfg(feature = "validation")]
impl qv_core::platform::AndroidKeystoreBackend for FixtureKeystore {
    fn validated(&self) -> bool {
        true
    }
    fn seal(
        &self,
        b: qv_core::platform::QuickBinding,
        p: qv_core::platform::QuickPolicy,
        s: &qv_core::SecretBytes,
        c: qv_core::platform::Cancellation,
    ) -> Result<qv_core::SecretBytes, PlatformError> {
        qv_core::platform::AndroidKeystoreBackend::seal(&NativeKeystore, b, p, s, c)
    }
    fn open(
        &self,
        b: qv_core::platform::QuickBinding,
        p: qv_core::platform::QuickPolicy,
        s: &qv_core::SecretBytes,
        c: qv_core::platform::Cancellation,
    ) -> Result<qv_core::SecretBytes, PlatformError> {
        qv_core::platform::AndroidKeystoreBackend::open(&NativeKeystore, b, p, s, c)
    }
    fn delete(&self, s: &qv_core::SecretBytes) -> Result<(), PlatformError> {
        qv_core::platform::AndroidKeystoreBackend::delete(&NativeKeystore, s)
    }
}

/// Bounded strings from the native registry (already length-limited there).
fn autofill_string(id: i64, method: &str, max: usize) -> Result<Option<String>, ()> {
    call(|env, a| {
        let value = env
            .call_method(a, method, "(J)Ljava/lang/String;", &[JValue::Long(id)])?
            .l()?;
        if value.is_null() {
            return Ok(None);
        }
        let value: jni::objects::JString = value.into();
        let text = env.get_string(&value)?.to_string_lossy().into_owned();
        Ok(Some(text))
    })
    .map_err(|_| ())
    .and_then(|v| match v {
        Some(t) if t.len() > max => Err(()),
        v => Ok(v),
    })
}
/// Fetch and validate a newly claimed request; anything invalid is cancelled.
fn poll_autofill() {
    use qv_core::platform::autofill::{FillRequest, MAX_HOST, MAX_PACKAGE, MAX_SIGNERS, Roles};
    let Ok(id) = call(|env, a| env.call_method(a, "qvAutofillPending", "()J", &[])?.j()) else {
        return;
    };
    if id <= 0 {
        return;
    }
    let request = (|| {
        let package = autofill_string(id, "qvAutofillPackage", MAX_PACKAGE)?.ok_or(())?;
        let scheme = autofill_string(id, "qvAutofillScheme", 8)?;
        let host = autofill_string(id, "qvAutofillHost", MAX_HOST)?;
        let signers = call(|env, a| {
            let array: jni::objects::JByteArray = env
                .call_method(a, "qvAutofillSigners", "(J)[B", &[JValue::Long(id)])?
                .l()?
                .into();
            let length = env.get_array_length(&array)?;
            if length <= 0 || length as usize > MAX_SIGNERS * 32 {
                return Err(jni::errors::Error::NullPtr("autofill signer bounds"));
            }
            env.convert_byte_array(array)
        })
        .map_err(|_| ())?;
        let roles = call(|env, a| {
            env.call_method(a, "qvAutofillRoles", "(J)I", &[JValue::Long(id)])?
                .i()
        })
        .map_err(|_| ())?;
        let roles = Roles {
            username: roles & 1 != 0,
            password: roles & 2 != 0,
        };
        FillRequest::new(
            &package,
            &signers,
            scheme.as_deref(),
            host.as_deref(),
            roles,
        )
        .map_err(|_| ())
    })();
    let controller = crate::ui::ACTIVE.get().and_then(|c| c.as_ref().ok());
    match (request, controller) {
        (Ok(request), Some(c)) => {
            let requester = requester(&request);
            c.autofill_offer(id, requester, request.roles);
        }
        _ => NativeAutofill.cancel(id),
    }
}
/// Browser trust is the compiled allowlist. Only the marked validation build
/// additionally trusts its own instrumentation package, signed by this app's
/// own key, so device tests can exercise the exact-origin path.
fn requester(
    request: &qv_core::platform::autofill::FillRequest,
) -> qv_core::platform::autofill::Requester {
    #[cfg(feature = "validation")]
    if let Some(origin) = &request.web
        && request.app.package.as_str() == "org.quickvault.app.test"
        && call(|env, a| {
            let array: jni::objects::JByteArray =
                env.call_method(a, "qvOwnSigners", "()[B", &[])?.l()?.into();
            let length = env.get_array_length(&array)?;
            if length <= 0 || length > 256 {
                return Err(jni::errors::Error::NullPtr("own signer bounds"));
            }
            env.convert_byte_array(array)
        })
        .ok()
        .and_then(|own| qv_core::platform::autofill::SignerSet::from_flat(&own))
        .is_some_and(|own| own == request.app.signers)
    {
        return qv_core::platform::autofill::Requester::Web {
            browser: request.app.clone(),
            origin: origin.clone(),
        };
    }
    request.requester(qv_core::platform::autofill::TRUSTED_BROWSERS)
}
/// Native side of the handoff registry.
struct NativeAutofill;
impl crate::autofill::AutofillSink for NativeAutofill {
    fn complete(
        &self,
        native: i64,
        username: Option<&qv_core::SecretBytes>,
        password: Option<&qv_core::SecretBytes>,
    ) -> bool {
        use qv_core::platform::autofill::MAX_FILL_VALUE;
        if [username, password]
            .iter()
            .flatten()
            .any(|v| v.len() > MAX_FILL_VALUE)
        {
            return false;
        }
        // The JVM arrays are zeroed by the registry after copying (0008 §4.4).
        call(|env, a| {
            let null = JObject::null();
            let user = match username {
                Some(v) => JObject::from(env.byte_array_from_slice(v.expose_secret())?),
                None => null,
            };
            let null = JObject::null();
            let pass = match password {
                Some(v) => JObject::from(env.byte_array_from_slice(v.expose_secret())?),
                None => null,
            };
            env.call_method(
                a,
                "qvAutofillComplete",
                "(J[B[B)Z",
                &[
                    JValue::Long(native),
                    JValue::Object(&user),
                    JValue::Object(&pass),
                ],
            )?
            .z()
        })
        .unwrap_or(false)
    }
    fn cancel(&self, native: i64) {
        let _ = call(|env, a| {
            env.call_method(a, "qvAutofillCancel", "(J)V", &[JValue::Long(native)])
                .map(|_| ())
        });
    }
}
/// Whether this device's autofill gate is open.
pub(crate) fn autofill_available() -> bool {
    call(|env, a| env.call_method(a, "qvAutofillAvailable", "()Z", &[])?.z()).unwrap_or(false)
}
/// Open the system autofill-service chooser (backgrounds, and so locks, the app).
pub(crate) fn open_autofill_settings() {
    let _ = call(|env, a| {
        env.call_method(a, "qvOpenAutofillSettings", "()V", &[])
            .map(|_| ())
    });
}

/// After the destroy lock: give worker and clipboard-hold threads (which wake
/// at least every 250 ms) time to observe cancellation, then let the activity
/// end this process. One Rust runtime per process (plan 0035).
fn stopped(env: &mut JNIEnv<'_>, activity: &GlobalRef) {
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = env.call_method(activity.as_obj(), "qvRuntimeStopped", "()V", &[]);
    let _ = env.exception_clear();
}

/// Native camera capability, including the independent physical-device gate.
pub(crate) fn qr_available() -> bool {
    call(|env, a| env.call_method(a, "qvQrAvailable", "()Z", &[])?.z()).unwrap_or(false)
}
static QR_SCAN: Mutex<Option<i64>> = Mutex::new(None);
/// Lock may close capture while its worker is decoding a frame.
pub(crate) fn forget_scan() {
    if let Some(id) = QR_SCAN.lock().ok().and_then(|mut slot| slot.take()) {
        let _ = call(|env, a| {
            env.call_method(a, "qvQrFinish", "(J)V", &[JValue::Long(id)])
                .map(|_| ())
        });
    }
}
struct CameraScan(i64);
impl Drop for CameraScan {
    fn drop(&mut self) {
        if let Ok(mut slot) = QR_SCAN.lock()
            && *slot == Some(self.0)
        {
            *slot = None;
        }
        let _ = call(|env, a| {
            env.call_method(a, "qvQrFinish", "(J)V", &[JValue::Long(self.0)])
                .map(|_| ())
        });
    }
}
/// A bounded camera action. Images never enter the renderer or a file.
pub(crate) fn capture_qr(cancel: &CancelToken) -> Result<qv_core::SecretBytes, AppError> {
    use std::time::{Duration, Instant};
    if cancel.is_cancelled() {
        return Err(qv_core::CoreError::Cancelled.into());
    }
    // The camera permission prompt backgrounds the app like the document
    // picker; defer only background expiry while this scan runs, taken before
    // the scan starts so the prompt cannot pause the app first. The scan ends
    // on any other pause, and a deferred lock fires when this guard drops
    // while still in the background (screen lock never waits).
    let _deferral = OS.get().and_then(|os| os.defer_background());
    let id = call(|env, a| env.call_method(a, "qvQrStart", "()J", &[])?.j())?;
    if id <= 0 {
        return Err(AppError::Unavailable);
    }
    let _guard = CameraScan(id);
    *QR_SCAN.lock().map_err(|_| AppError::Unavailable)? = Some(id);
    let end = Instant::now() + Duration::from_secs(30);
    let mut attempts = 0;
    while Instant::now() < end && attempts < 60 {
        if cancel.is_cancelled() {
            return Err(qv_core::CoreError::Cancelled.into());
        }
        let state = call(|env, a| {
            env.call_method(a, "qvQrState", "(J)I", &[JValue::Long(id)])?
                .i()
        })?;
        if state != 0 {
            return Err(if state == 1 {
                qv_core::CoreError::Cancelled.into()
            } else {
                AppError::Unavailable
            });
        }
        let frame = call(|env, a| {
            let object = env
                .call_method(a, "qvQrFrame", "(J)[B", &[JValue::Long(id)])?
                .l()?;
            if object.is_null() {
                return Ok(None);
            }
            let array = jni::objects::JByteArray::from(object);
            let len = env.get_array_length(&array)?;
            if len < 8 || len as usize > crate::qr::MAX_PIXELS + 8 {
                return Ok(Some(Err(AppError::InvalidInput)));
            }
            let raw = Zeroizing::new(env.convert_byte_array(&array)?);
            // Clear the returned JVM array in bounded chunks before dropping
            // its local JNI reference. Provider/VM intermediates remain best effort.
            let zeros = [0i8; 4096];
            let mut offset = 0;
            while offset < len {
                let n = (len - offset).min(4096);
                env.set_byte_array_region(&array, offset, &zeros[..n as usize])?;
                offset += n;
            }
            Ok(Some(crate::workspace::protect(&raw)))
        })?;
        if let Some(frame) = frame {
            attempts += 1;
            // An unreadable or ambiguous frame is skipped (0014 §6.6).
            if let Some(payload) = crate::qr::scan_frame(frame?.expose_secret()) {
                if Instant::now() >= end || cancel.is_cancelled() {
                    return Err(qv_core::CoreError::Cancelled.into());
                }
                let live = call(|env, a| {
                    env.call_method(a, "qvQrState", "(J)I", &[JValue::Long(id)])?
                        .i()
                })?;
                if live != 0 {
                    return Err(qv_core::CoreError::Cancelled.into());
                }
                return Ok(payload);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(qv_core::CoreError::Cancelled.into())
}
