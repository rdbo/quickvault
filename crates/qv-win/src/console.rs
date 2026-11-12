// SPDX-License-Identifier: AGPL-3.0-or-later

//! No-echo console input for CLI prompts (spec 0009 §3, §5.1; 0011 §3;
//! plan 0052).
//!
//! The console's echo and line input are turned off, so the console keeps
//! no line buffer or history of what is typed, and the caller edits the
//! line itself from single UTF-16 key units. Pending input is discarded
//! when the mode is set, so type-ahead cannot answer a prompt. Only
//! standard input is used, and only when it is a console.
#![allow(unsafe_code)] // Win32 FFI boundary; every block has a SAFETY note.

use std::io;
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, FlushConsoleInputBuffer,
    GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT, ReadConsoleInputW, STD_ERROR_HANDLE,
    STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode, WriteConsoleW,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const VK_MENU: u16 = 0x12;

fn std_handle(which: STD_HANDLE) -> io::Result<HANDLE> {
    // SAFETY: returns one of the process's standard handles (not owned).
    let h = unsafe { GetStdHandle(which) };
    if h.is_null() || h as isize == -1 {
        return Err(io::ErrorKind::NotFound.into());
    }
    Ok(h)
}

fn stdin() -> io::Result<HANDLE> {
    std_handle(STD_INPUT_HANDLE)
}

/// Standard output or standard error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Std {
    /// Standard output.
    Out,
    /// Standard error.
    Err,
}

/// Whether the stream is a console.
pub fn is_console(which: Std) -> bool {
    let h = std_handle(match which {
        Std::Out => STD_OUTPUT_HANDLE,
        Std::Err => STD_ERROR_HANDLE,
    });
    h.and_then(mode).is_ok()
}

/// Turns on virtual-terminal processing for console output (best effort),
/// so the alternate-screen and line-control sequences work in conhost.
pub fn enable_vt() {
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        if let Ok(h) = std_handle(which)
            && let Ok(m) = mode(h)
        {
            // SAFETY: a console output handle and a valid mode.
            unsafe { SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING) };
        }
    }
}

/// Writes `bytes` (UTF-8) straight to the standard handle, never through
/// `std`'s buffered `Stdout`. A console gets UTF-16 through `WriteConsoleW`
/// (invalid UTF-8 shows as U+FFFD), and the temporary UTF-16 copy is
/// overwritten afterwards (best effort); a pipe or file gets the bytes.
pub fn write_std(which: Std, bytes: &[u8]) -> io::Result<()> {
    let h = std_handle(match which {
        Std::Out => STD_OUTPUT_HANDLE,
        Std::Err => STD_ERROR_HANDLE,
    })?;
    if mode(h).is_ok() {
        let mut units: Vec<u16> = String::from_utf8_lossy(bytes).encode_utf16().collect();
        let result = (|| {
            let mut rest = &units[..];
            while !rest.is_empty() {
                let n = rest.len().min(8192);
                let mut written = 0u32;
                // SAFETY: `rest` holds at least `n` readable units.
                let ok = unsafe {
                    WriteConsoleW(
                        h,
                        rest.as_ptr().cast(),
                        n as u32,
                        &raw mut written,
                        std::ptr::null(),
                    )
                };
                if ok == 0 || written == 0 {
                    return Err(io::Error::last_os_error());
                }
                rest = &rest[(written as usize).min(n)..];
            }
            Ok(())
        })();
        units.fill(0);
        std::hint::black_box(&units);
        return result;
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = u32::try_from(rest.len().min(1 << 20)).unwrap_or(1 << 20);
        let mut written = 0u32;
        // SAFETY: `rest` holds at least `n` readable bytes; synchronous write.
        let ok = unsafe { WriteFile(h, rest.as_ptr(), n, &raw mut written, std::ptr::null_mut()) };
        if ok == 0 || written == 0 {
            return Err(io::Error::last_os_error());
        }
        rest = &rest[(written as usize).min(rest.len())..];
    }
    Ok(())
}

fn mode(h: HANDLE) -> io::Result<u32> {
    let mut m = 0;
    // SAFETY: `m` is writable; fails unless `h` is a console input handle.
    if unsafe { GetConsoleMode(h, &raw mut m) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(m)
}

/// Whether standard input is a console.
pub fn stdin_is_console() -> bool {
    stdin().and_then(mode).is_ok()
}

/// Restores the saved console mode when dropped (discarding pending input
/// first if asked).
pub struct RawMode {
    saved: u32,
    flush: bool,
}

/// Discards pending console input.
pub fn flush_input() {
    if let Ok(h) = stdin() {
        // SAFETY: a console input handle (or harmless failure).
        unsafe { FlushConsoleInputBuffer(h) };
    }
}

/// Turns echo and line input off (and Ctrl-C processing too unless
/// `keep_signals`), discarding pending input.
pub fn raw_mode(keep_signals: bool, flush_on_drop: bool) -> io::Result<RawMode> {
    let h = stdin()?;
    let saved = mode(h)?;
    let mut new = saved & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    if !keep_signals {
        new &= !ENABLE_PROCESSED_INPUT;
    }
    // SAFETY: a console input handle and a valid mode.
    if unsafe { SetConsoleMode(h, new) } == 0 {
        return Err(io::Error::last_os_error());
    }
    flush_input();
    Ok(RawMode {
        saved,
        flush: flush_on_drop,
    })
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Ok(h) = stdin() {
            if self.flush {
                // SAFETY: a console input handle.
                unsafe { FlushConsoleInputBuffer(h) };
            }
            // SAFETY: restoring the mode read earlier.
            unsafe { SetConsoleMode(h, self.saved) };
        }
    }
}

/// Waits up to `timeout` for one typed character unit. `Ok(None)` after the
/// timeout or for input that is not a character (key releases, mouse,
/// focus, resize). The input record is cleared after reading (best effort).
pub fn read_unit(timeout: Duration) -> io::Result<Option<u16>> {
    let h = stdin()?;
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: waiting on a console input handle.
    match unsafe { WaitForSingleObject(h, ms) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => return Ok(None),
        _ => return Err(io::Error::last_os_error()),
    }
    let mut record = INPUT_RECORD::default();
    let mut read = 0u32;
    // SAFETY: room for exactly one record; `read` is writable.
    if unsafe { ReadConsoleInputW(h, &raw mut record, 1, &raw mut read) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut unit = None;
    if read == 1 && u32::from(record.EventType) == KEY_EVENT {
        // SAFETY: KEY_EVENT selects the KeyEvent union member.
        let key = unsafe { record.Event.KeyEvent };
        // SAFETY: UnicodeChar is the member filled by the W function.
        let c = unsafe { key.uChar.UnicodeChar };
        // Alt+numpad entry delivers its character on the Alt release.
        if c != 0 && (key.bKeyDown != 0 || key.wVirtualKeyCode == VK_MENU) {
            unit = Some(c);
        }
    }
    record = INPUT_RECORD::default();
    std::hint::black_box(&record);
    Ok(unit)
}
