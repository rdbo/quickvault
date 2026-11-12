// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native open, save and folder dialogs for explicit user file choices
//! (plan 0052; the Linux app uses the desktop portal). The flat comdlg32 and
//! shell32 calls need no COM vtables. Each dialog runs on its own thread
//! with an apartment-threaded COM initialization, so callers on any thread
//! may use it. Chosen files are not added to the recent-documents list. The
//! returned path is untrusted: callers open it through their no-follow file
//! checks.
#![allow(unsafe_code)] // Win32 FFI boundary; every block has a SAFETY note.

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    CommDlgExtendedError, GetOpenFileNameW, GetSaveFileNameW, OFN_DONTADDTORECENT, OFN_EXPLORER,
    OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_NODEREFERENCELINKS,
    OFN_NOREADONLYRETURN, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Shell::{
    BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS, BROWSEINFOW, SHBrowseForFolderW, SHGetPathFromIDListW,
};

/// The longest path a dialog may return, in UTF-16 units.
const MAX_PATH_UNITS: usize = 32_768;

/// What to choose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choose {
    /// An existing file to read.
    Open,
    /// A new file to write, suggesting this name.
    Save(String),
    /// An existing folder.
    Folder,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().filter(|&u| u != 0).chain([0]).collect()
}

fn path_of(buf: &[u16]) -> Option<PathBuf> {
    let len = buf.iter().position(|&u| u == 0)?;
    (len > 0).then(|| PathBuf::from(OsString::from_wide(&buf[..len])))
}

/// Shows the dialog and waits for the user. `Ok(None)` if cancelled.
pub fn choose(title: &str, kind: &Choose) -> io::Result<Option<PathBuf>> {
    let (title, kind) = (title.to_owned(), kind.clone());
    std::thread::Builder::new()
        .name("qv-dialog".into())
        .spawn(move || {
            // SAFETY: initializes COM for this new thread only; balanced
            // below when it succeeded.
            let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
            let result = run(&title, &kind);
            if hr >= 0 {
                // SAFETY: balancing a successful CoInitializeEx on this thread.
                unsafe { CoUninitialize() };
            }
            result
        })?
        .join()
        .map_err(|_| io::Error::other("dialog thread failed"))?
}

fn run(title: &str, kind: &Choose) -> io::Result<Option<PathBuf>> {
    let title = wide(title);
    let mut buf = vec![0u16; MAX_PATH_UNITS];
    match kind {
        Choose::Folder => {
            let info = BROWSEINFOW {
                hwndOwner: std::ptr::null_mut(),
                pidlRoot: std::ptr::null_mut(),
                pszDisplayName: buf.as_mut_ptr(),
                lpszTitle: title.as_ptr(),
                ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
                lpfn: None,
                lParam: 0,
                iImage: 0,
            };
            // SAFETY: `info` and the buffers it names (display name: at
            // least MAX_PATH units) live for the call.
            let pidl = unsafe { SHBrowseForFolderW(&raw const info) };
            if pidl.is_null() {
                return Ok(None);
            }
            buf.fill(0);
            // SAFETY: a PIDL from the dialog; `buf` holds MAX_PATH units.
            let ok = unsafe { SHGetPathFromIDListW(pidl, buf.as_mut_ptr()) };
            // SAFETY: freeing the PIDL the shell allocated.
            unsafe { CoTaskMemFree(pidl.cast()) };
            if ok == 0 {
                return Err(io::Error::other("not a file system folder"));
            }
            Ok(path_of(&buf))
        }
        Choose::Open | Choose::Save(_) => {
            let save = matches!(kind, Choose::Save(_));
            if let Choose::Save(name) = kind {
                let w: Vec<u16> = name.encode_utf16().filter(|&u| u != 0).collect();
                let n = w.len().min(MAX_PATH_UNITS - 1);
                buf[..n].copy_from_slice(&w[..n]);
            }
            let mut ofn = OPENFILENAMEW {
                lStructSize: size_of::<OPENFILENAMEW>() as u32,
                hwndOwner: std::ptr::null_mut(),
                hInstance: std::ptr::null_mut(),
                lpstrFilter: std::ptr::null(),
                lpstrCustomFilter: std::ptr::null_mut(),
                nMaxCustFilter: 0,
                nFilterIndex: 0,
                lpstrFile: buf.as_mut_ptr(),
                nMaxFile: MAX_PATH_UNITS as u32,
                lpstrFileTitle: std::ptr::null_mut(),
                nMaxFileTitle: 0,
                lpstrInitialDir: std::ptr::null(),
                lpstrTitle: title.as_ptr(),
                Flags: OFN_EXPLORER
                    | OFN_PATHMUSTEXIST
                    | OFN_NOCHANGEDIR
                    | OFN_DONTADDTORECENT
                    | OFN_HIDEREADONLY
                    | OFN_NODEREFERENCELINKS
                    | if save {
                        OFN_NOREADONLYRETURN
                    } else {
                        OFN_FILEMUSTEXIST
                    },
                nFileOffset: 0,
                nFileExtension: 0,
                lpstrDefExt: std::ptr::null(),
                lCustData: 0,
                lpfnHook: None,
                lpTemplateName: std::ptr::null(),
                pvReserved: std::ptr::null_mut(),
                dwReserved: 0,
                FlagsEx: 0,
            };
            let ok = if save {
                // SAFETY: `ofn` and the buffers it points to live for the call.
                unsafe { GetSaveFileNameW(&raw mut ofn) }
            } else {
                // SAFETY: as above.
                unsafe { GetOpenFileNameW(&raw mut ofn) }
            };
            if ok == 0 {
                // SAFETY: no arguments; 0 means the user cancelled.
                return match unsafe { CommDlgExtendedError() } {
                    0 => Ok(None),
                    code => Err(io::Error::other(format!("dialog error {code}"))),
                };
            }
            Ok(path_of(&buf))
        }
    }
}
