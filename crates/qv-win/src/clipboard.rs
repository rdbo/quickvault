// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foreground clipboard ownership for protected text (spec 0008 §3, 0009
//! §5.1; plan 0052).
//!
//! A message-only window owns the clipboard; its thread must keep pumping
//! messages ([`Owner::pump`]) while it holds the clipboard, because other
//! applications send it `WM_DESTROYCLIPBOARD` synchronously when they
//! replace the content. The text is offered as `CF_UNICODETEXT` together
//! with the formats that ask clipboard history, cloud clipboard and
//! clipboard monitors to skip it. Ownership is the sequence number recorded
//! after publication: a later change means another owner replaced it.
//! Clearing zeroes the global memory before emptying, and only while the
//! sequence number and owner are still ours. Copies made by readers, and
//! formats the system synthesizes on request, are outside our control.
#![allow(unsafe_code)] // Win32 FFI boundary; every block has a SAFETY note.

use std::io;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GlobalFree, HWND};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardOwner,
    GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, HWND_MESSAGE, MSG,
    MsgWaitForMultipleObjects, PM_REMOVE, PeekMessageW, QS_ALLINPUT, RegisterClassExW,
    UnregisterClassW, WNDCLASSEXW,
};

const CF_UNICODETEXT: u32 = 13;
/// Formats that keep the text out of clipboard history, the cloud
/// clipboard and monitoring tools (documented by Microsoft for password
/// managers).
const EXCLUSIONS: [(&str, u32); 3] = [
    ("ExcludeClipboardContentFromMonitorProcessing", 0),
    ("CanIncludeInClipboardHistory", 0),
    ("CanUploadToCloudClipboard", 0),
];

/// The current clipboard sequence number.
pub fn sequence() -> u32 {
    // SAFETY: no arguments.
    unsafe { GetClipboardSequenceNumber() }
}

/// A message-only owner window on the current thread (hence `!Send`).
pub struct Owner {
    hwnd: HWND,
    class: Vec<u16>,
    _thread: PhantomData<*const ()>,
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    // SAFETY: forwarding the unmodified arguments of this window procedure.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Copies `len` bytes of `data` into a new movable global block.
fn global_copy(data: *const u8, len: usize) -> io::Result<*mut core::ffi::c_void> {
    // SAFETY: plain allocation; null on failure.
    let h = unsafe { GlobalAlloc(GMEM_MOVEABLE, len) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is a live movable block; lock it to get its address.
    let p = unsafe { GlobalLock(h) };
    if p.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: freeing the block we just allocated.
        unsafe { GlobalFree(h) };
        return Err(e);
    }
    // SAFETY: `p` is valid for `len` bytes (GlobalAlloc's size); the source
    // is valid for `len` bytes by the caller; the regions are distinct.
    unsafe { std::ptr::copy_nonoverlapping(data, p.cast::<u8>(), len) };
    // SAFETY: balancing the lock above.
    unsafe { GlobalUnlock(h) };
    Ok(h)
}

/// Zeroes and frees a global block that was never handed to the clipboard.
fn global_discard(h: *mut core::ffi::c_void) {
    zero_global(h);
    // SAFETY: we still own `h`.
    unsafe { GlobalFree(h) };
}

/// Overwrites a global block with zeros (best effort).
fn zero_global(h: *mut core::ffi::c_void) {
    // SAFETY: `h` is a global block; GlobalSize only reads its header.
    let size = unsafe { GlobalSize(h) };
    // SAFETY: lock to get the address of the live block.
    let p = unsafe { GlobalLock(h) };
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is valid for `size` bytes while locked.
    unsafe { std::ptr::write_bytes(p.cast::<u8>(), 0, size) };
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
    // SAFETY: balancing the lock above.
    unsafe { GlobalUnlock(h) };
}

impl Owner {
    /// Creates the owner window on this thread.
    pub fn new() -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let class: Vec<u16> = format!(
            "QuickVaultClipboard-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .encode_utf16()
        .chain([0])
        .collect();
        // SAFETY: a null name returns this module's handle.
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        // SAFETY: `wc` and its class name outlive the registration (the
        // class is unregistered in Drop, before `class` drops).
        if unsafe { RegisterClassExW(&raw const wc) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a message-only window of the class above.
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            )
        };
        if hwnd.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: the class has no windows.
            unsafe { UnregisterClassW(class.as_ptr(), instance) };
            return Err(e);
        }
        Ok(Self {
            hwnd,
            class,
            _thread: PhantomData,
        })
    }

    /// Dispatches this thread's messages for up to `wait`.
    pub fn pump(&self, wait: Duration) {
        let end = Instant::now() + wait;
        loop {
            let mut msg = MSG {
                hwnd: std::ptr::null_mut(),
                message: 0,
                wParam: 0,
                lParam: 0,
                time: 0,
                pt: Default::default(),
            };
            // SAFETY: `msg` is writable; any window of this thread.
            while unsafe { PeekMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0
            {
                // SAFETY: dispatching a message PeekMessageW just filled in.
                unsafe { DispatchMessageW(&raw const msg) };
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let ms = u32::try_from(left.as_millis()).unwrap_or(u32::MAX).max(1);
            // SAFETY: no handles; waits for input to this thread or the timeout.
            unsafe { MsgWaitForMultipleObjects(0, std::ptr::null(), 0, ms, QS_ALLINPUT) };
        }
    }

    fn open(&self) -> io::Result<()> {
        // Another application may hold the clipboard briefly.
        for _ in 0..40 {
            // SAFETY: our live window.
            if unsafe { OpenClipboard(self.hwnd) } != 0 {
                return Ok(());
            }
            self.pump(Duration::from_millis(25));
        }
        Err(io::Error::other("clipboard busy"))
    }

    /// Publishes NUL-free UTF-16LE `text` (bytes, so callers can keep it
    /// in protected byte buffers) with the exclusion formats and returns the
    /// resulting sequence number.
    pub fn set_text(&self, text: &[u8]) -> io::Result<u32> {
        if !text.len().is_multiple_of(2) || text.chunks(2).any(|u| u == [0, 0]) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.open()?;
        let result = (|| {
            // SAFETY: the clipboard is open by our window, which becomes owner.
            if unsafe { EmptyClipboard() } == 0 {
                return Err(io::Error::last_os_error());
            }
            // Copy the text plus a terminating NUL unit into the block.
            let bytes = text.len() + 2;
            // SAFETY: plain allocation; null on failure.
            let h = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: lock the live block for its address.
            let p = unsafe { GlobalLock(h) }.cast::<u8>();
            if p.is_null() {
                let e = io::Error::last_os_error();
                // SAFETY: freeing the block we allocated.
                unsafe { GlobalFree(h) };
                return Err(e);
            }
            // SAFETY: `p` is valid for len + 2 bytes; `text` for len bytes.
            unsafe { std::ptr::copy_nonoverlapping(text.as_ptr(), p, text.len()) };
            // SAFETY: the two NUL bytes lie within the block.
            let end = unsafe { p.add(text.len()) };
            // SAFETY: `end` points to the block's last two writable bytes.
            unsafe { std::ptr::write_bytes(end, 0, 2) };
            // SAFETY: balancing the lock.
            unsafe { GlobalUnlock(h) };
            // SAFETY: the clipboard is open and owned; on success the system
            // owns `h`.
            if unsafe { SetClipboardData(CF_UNICODETEXT, h) }.is_null() {
                let e = io::Error::last_os_error();
                global_discard(h);
                return Err(e);
            }
            for (name, value) in EXCLUSIONS {
                let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
                // SAFETY: NUL-terminated name.
                let format = unsafe { RegisterClipboardFormatW(name.as_ptr()) };
                if format == 0 {
                    return Err(io::Error::last_os_error());
                }
                let data = value.to_le_bytes();
                let h = global_copy(data.as_ptr(), data.len())?;
                // SAFETY: as above; the system owns `h` on success.
                if unsafe { SetClipboardData(format, h) }.is_null() {
                    let e = io::Error::last_os_error();
                    global_discard(h);
                    return Err(e);
                }
            }
            Ok(())
        })();
        // SAFETY: closing the clipboard we opened.
        unsafe { CloseClipboard() };
        if result.is_err() {
            // Never leave a partial publication behind.
            let _ = self.clear_if(sequence());
        }
        result.map(|()| sequence())
    }

    /// Clears the clipboard, zeroing our text first, if `seq` is still the
    /// current sequence number and our window still owns it. Returns
    /// whether it was still ours.
    pub fn clear_if(&self, seq: u32) -> io::Result<bool> {
        if sequence() != seq {
            return Ok(false);
        }
        self.open()?;
        // SAFETY: the clipboard is open; these only read its state.
        let ours = sequence() == seq && unsafe { GetClipboardOwner() } == self.hwnd;
        if ours {
            // SAFETY: the clipboard is open; the handle stays valid until
            // EmptyClipboard frees it.
            let h = unsafe { GetClipboardData(CF_UNICODETEXT) };
            if !h.is_null() {
                zero_global(h);
            }
            // SAFETY: open and owned by our window.
            unsafe { EmptyClipboard() };
        }
        // SAFETY: closing the clipboard we opened.
        unsafe { CloseClipboard() };
        Ok(ours)
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        // SAFETY: a null name returns this module's handle.
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        // SAFETY: our window, on its own thread (the type is !Send).
        unsafe { DestroyWindow(self.hwnd) };
        // SAFETY: the class has no windows left.
        unsafe { UnregisterClassW(self.class.as_ptr(), instance) };
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn clipboard_publish_detect_replacement_and_clear_only_own() {
        let owner = Owner::new().unwrap();
        let text: Vec<u8> = "secret".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let seq = owner.set_text(&text).unwrap();
        assert_eq!(sequence(), seq);
        assert!(owner.set_text(&[0x61, 0, 0, 0]).is_err(), "embedded NUL");
        assert!(owner.set_text(&[0x61]).is_err(), "odd length");
        // A successor's content is never cleared.
        let other = Owner::new().unwrap();
        let theirs = other.set_text(&[0x61, 0]).unwrap();
        assert_ne!(theirs, seq);
        assert!(!owner.clear_if(seq).unwrap());
        assert!(other.clear_if(theirs).unwrap());
        owner.pump(Duration::from_millis(10));
    }
}
