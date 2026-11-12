// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session lock, disconnect, logoff, suspend and end-of-session
//! notifications (spec 0009 §5.1; 0008 §1.4; plan 0052).
//!
//! A hidden top-level window on its own thread is registered with
//! `WTSRegisterSessionNotification(NOTIFY_FOR_THIS_SESSION)` and receives
//! `WM_POWERBROADCAST` (message-only windows do not get power broadcasts).
//! The callback runs on that thread and must return promptly. If the message
//! loop ends for any reason other than [`SessionWatcher`]'s drop, the
//! callback receives [`SessionEvent::Lost`].
#![allow(unsafe_code)] // Win32 FFI boundary; every block has a SAFETY note.

use std::cell::RefCell;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSFreeMemory,
    WTSINFOEXW, WTSQuerySessionInformationW, WTSRegisterSessionNotification, WTSSessionInfoEx,
    WTSUnRegisterSessionNotification,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, MSG,
    PostThreadMessageW, RegisterClassExW, UnregisterClassW, WM_ENDSESSION, WM_POWERBROADCAST,
    WM_QUIT, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
};

/// Why the session should lock (no data beyond the kind).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// The workstation was locked.
    Locked,
    /// The session was disconnected from its console or remote client.
    Disconnected,
    /// The user is logging off.
    Logoff,
    /// The system is suspending or hibernating.
    Suspend,
    /// The Windows session is ending (shutdown or logoff).
    EndSession,
    /// Monitoring stopped unexpectedly.
    Lost,
}

/// Callback for [`SessionWatcher::start`].
pub type Callback = Arc<dyn Fn(SessionEvent) + Send + Sync>;

// WM_WTSSESSION_CHANGE codes and power events (WinUser.h; windows-sys
// spreads them over features not otherwise needed).
const WTS_CONSOLE_DISCONNECT: usize = 0x2;
const WTS_REMOTE_DISCONNECT: usize = 0x4;
const WTS_SESSION_LOGOFF: usize = 0x6;
const WTS_SESSION_LOCK: usize = 0x7;
const PBT_APMSUSPEND: usize = 0x4;
const WTS_SESSIONSTATE_LOCK: i32 = 0;

thread_local! {
    static CALLBACK: RefCell<Option<Callback>> = const { RefCell::new(None) };
}

fn deliver(event: SessionEvent) {
    // Clone out of the cell so the callback never runs while it is borrowed.
    if let Some(cb) = CALLBACK.with(|c| c.borrow().clone()) {
        cb(event);
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match (msg, wparam) {
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK) => deliver(SessionEvent::Locked),
        (WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT) => {
            deliver(SessionEvent::Disconnected);
        }
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOGOFF) => deliver(SessionEvent::Logoff),
        (WM_POWERBROADCAST, PBT_APMSUSPEND) => {
            deliver(SessionEvent::Suspend);
            return 1;
        }
        (WM_ENDSESSION, w) if w != 0 => deliver(SessionEvent::EndSession),
        _ => {}
    }
    // SAFETY: forwarding the unmodified arguments of this window procedure.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// A running watcher; dropping it stops the thread without a `Lost` event.
pub struct SessionWatcher {
    thread: Option<JoinHandle<()>>,
    thread_id: u32,
    stopping: Arc<AtomicBool>,
}

impl SessionWatcher {
    /// Starts the watcher thread and returns once its window is registered
    /// for session notifications, or the reason it could not be.
    pub fn start(callback: Callback) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let thread = std::thread::Builder::new()
            .name("qv-session".into())
            .spawn(move || run(callback, tx, stop))?;
        match rx.recv() {
            Ok(Ok(thread_id)) => Ok(Self {
                thread: Some(thread),
                thread_id,
                stopping,
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other("session watcher thread ended"))
            }
        }
    }
}

impl Drop for SessionWatcher {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // SAFETY: posting a message with no pointers to a thread id.
        unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn run(callback: Callback, ready: mpsc::Sender<io::Result<u32>>, stopping: Arc<AtomicBool>) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    CALLBACK.with(|c| *c.borrow_mut() = Some(callback));
    let class = wide(&format!(
        "QuickVaultSession-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    // SAFETY: a null name returns this module's handle; nothing is freed.
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
    // SAFETY: `wc` and the class name it points to outlive the class (it
    // is unregistered below, before `class` drops).
    if unsafe { RegisterClassExW(&raw const wc) } == 0 {
        let _ = ready.send(Err(io::Error::last_os_error()));
        return;
    }
    // SAFETY: a hidden top-level window (no WS_VISIBLE) of the class above.
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
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    let registered = !hwnd.is_null()
        // SAFETY: `hwnd` is our live window.
        && unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } != 0;
    if !registered {
        let e = io::Error::last_os_error();
        if !hwnd.is_null() {
            // SAFETY: destroying our own window on its thread.
            unsafe { DestroyWindow(hwnd) };
        }
        // SAFETY: the class has no windows left.
        unsafe { UnregisterClassW(class.as_ptr(), instance) };
        let _ = ready.send(Err(e));
        return;
    }
    // SAFETY: no arguments; the id of this thread.
    let _ = ready.send(Ok(unsafe { GetCurrentThreadId() }));
    let mut msg = MSG {
        hwnd: std::ptr::null_mut(),
        message: 0,
        wParam: 0,
        lParam: 0,
        time: 0,
        pt: Default::default(),
    };
    loop {
        // SAFETY: `msg` is writable; any window of this thread.
        let got = unsafe { GetMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0) };
        if got <= 0 {
            break;
        }
        // SAFETY: dispatching a message GetMessageW just filled in.
        unsafe { DispatchMessageW(&raw const msg) };
    }
    // SAFETY: our registered window, destroyed on its own thread, then its
    // class.
    unsafe { WTSUnRegisterSessionNotification(hwnd) };
    // SAFETY: as above.
    unsafe { DestroyWindow(hwnd) };
    // SAFETY: as above.
    unsafe { UnregisterClassW(class.as_ptr(), instance) };
    if !stopping.load(Ordering::SeqCst) {
        deliver(SessionEvent::Lost);
    }
    CALLBACK.with(|c| *c.borrow_mut() = None);
}

/// Whether this session is locked right now (`WTSSessionInfoEx`). `Ok(None)`
/// when Windows does not report the state.
pub fn session_locked() -> io::Result<Option<bool>> {
    let mut buf: *mut u16 = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: out-pointers are writable; the buffer is freed below.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &raw mut buf,
            &raw mut len,
        )
    };
    if ok == 0 || buf.is_null() {
        return Err(io::Error::last_os_error());
    }
    let state = if (len as usize) >= size_of::<WTSINFOEXW>() {
        // SAFETY: the buffer holds at least one WTSINFOEXW (allocated by
        // WTS, suitably aligned); level 1 is the only defined level.
        let info = unsafe { &*buf.cast::<WTSINFOEXW>() };
        if info.Level == 1 {
            // SAFETY: Level 1 selects the WTSInfoExLevel1 union member.
            let flags = unsafe { info.Data.WTSInfoExLevel1.SessionFlags };
            match flags {
                WTS_SESSIONSTATE_LOCK => Some(true),
                1 => Some(false),
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    };
    // SAFETY: freeing the buffer WTS allocated; no reference into it remains.
    unsafe { WTSFreeMemory(buf.cast()) };
    Ok(state)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn watcher_starts_and_stops_without_a_lost_event() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = events.clone();
        match SessionWatcher::start(Arc::new(move |e| seen.lock().unwrap().push(e))) {
            Ok(w) => drop(w),
            // Wine without a session manager may refuse registration.
            Err(e) if std::env::var_os("QV_WINE").is_some() => {
                eprintln!("skipped under Wine: {e}");
                return;
            }
            Err(e) => panic!("watcher: {e}"),
        }
        assert!(events.lock().unwrap().is_empty());
        // The state query answers on a desktop session.
        let _ = session_locked();
    }
}
