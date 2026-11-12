// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session-local named mutexes for short cooperative directory locks
//! (plan 0052): Windows cannot lock a directory handle. A mutex left by a
//! process that died is acquired as abandoned, like a released `flock`.
#![allow(unsafe_code)] // Win32 FFI boundary; every block has a SAFETY note.

use std::io;
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, INFINITE, ReleaseMutex, WaitForSingleObject,
};

/// A held named mutex. Ownership is per thread, so the guard is `!Send`:
/// it must be released on the thread that acquired it.
pub struct NamedLock {
    handle: OwnedHandle,
    _thread: PhantomData<*const ()>,
}

/// Waits for and holds the mutex `Local\<name>` (this logon session only).
/// `name` must not contain a backslash.
pub fn named_lock(name: &str) -> io::Result<NamedLock> {
    if name.is_empty() || name.len() > 200 || name.contains('\\') || name.contains('\0') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let full: Vec<u16> = format!("Local\\{name}").encode_utf16().chain([0]).collect();
    // SAFETY: NUL-terminated name; default security; no initial ownership.
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, full.as_ptr()) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateMutexW returned a new handle that we now own.
    let handle = unsafe { OwnedHandle::from_raw_handle(h) };
    // SAFETY: valid mutex handle.
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), INFINITE) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(NamedLock {
            handle,
            _thread: PhantomData,
        }),
        _ => Err(io::Error::last_os_error()),
    }
}

impl Drop for NamedLock {
    fn drop(&mut self) {
        // SAFETY: this thread owns the mutex (the guard is !Send).
        unsafe { ReleaseMutex(self.handle.as_raw_handle()) };
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn named_lock_excludes_other_threads() {
        let name = format!("qv-test-{}", std::process::id());
        let held = named_lock(&name).unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let e = entered.clone();
        let n = name.clone();
        let t = std::thread::spawn(move || {
            let _g = named_lock(&n).unwrap();
            e.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!entered.load(Ordering::SeqCst));
        drop(held);
        t.join().unwrap();
        assert!(entered.load(Ordering::SeqCst));
        assert!(named_lock("a\\b").is_err());
        assert!(named_lock("").is_err());
    }
}
