// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux file picking through a short-lived helper process (0009 §1.8,
//! plan 0044 revision).
//!
//! The app makes itself non-dumpable before it reads any secret (0008 §1.1).
//! xdg-desktop-portal identifies a caller through `/proc/<pid>/root`, which
//! a non-dumpable process does not expose, so it refuses the app's requests
//! ("Unable to open /proc/<pid>/root"). The app therefore re-executes its
//! own binary (`/proc/self/exe`) in a helper mode. After `execve` the helper
//! is dumpable again, holds no vault data and opens no vault; it asks the
//! portal and prints the answer.
//!
//! The request (kind, title and a suggested name, which may be vault data)
//! goes over stdin, never argv; the answer comes back over stdout, bounded.
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use qv_core::platform::PlatformError;
use qv_core::platform::portal::{MAX_PICKED, Pick};

/// The helper mode's only argument.
const ARG: &str = "--qv-portal-picker";
/// The largest request accepted on stdin.
const REQUEST_MAX: usize = 8 * 1024;

/// Request: a kind byte (`O` open, `F` folder, `S` save), the title, a NUL,
/// and the suggested file name (save only).
pub(crate) fn encode_request(title: &str, kind: &Pick) -> Vec<u8> {
    let (k, name) = match kind {
        Pick::Open => (b'O', ""),
        Pick::Folder => (b'F', ""),
        Pick::Save(name) => (b'S', name.as_str()),
    };
    let mut out = Vec::with_capacity(2 + title.len() + name.len());
    out.push(k);
    out.extend_from_slice(title.as_bytes());
    out.push(0);
    out.extend_from_slice(name.as_bytes());
    out
}
/// The helper's side of [`encode_request`]; anything malformed is `None`.
pub(crate) fn decode_request(b: &[u8]) -> Option<(String, Pick)> {
    if b.len() > REQUEST_MAX {
        return None;
    }
    let (&k, rest) = b.split_first()?;
    let nul = rest.iter().position(|c| *c == 0)?;
    let title = std::str::from_utf8(&rest[..nul]).ok()?.to_owned();
    let name = std::str::from_utf8(&rest[nul + 1..]).ok()?;
    if name.contains('\0') {
        return None;
    }
    let kind = match (k, name.is_empty()) {
        (b'O', true) => Pick::Open,
        (b'F', true) => Pick::Folder,
        (b'S', false) => Pick::Save(name.to_owned()),
        _ => return None,
    };
    Some((title, kind))
}
/// Response: `P` and the path's bytes, `C` cancelled, `U` unavailable.
pub(crate) fn encode_response(r: &Result<Option<PathBuf>, PlatformError>) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    match r {
        Ok(Some(p)) => {
            let mut out = vec![b'P'];
            out.extend_from_slice(p.as_os_str().as_bytes());
            out
        }
        Ok(None) => vec![b'C'],
        Err(_) => vec![b'U'],
    }
}
/// The app's side of [`encode_response`]: a local absolute path, or why not.
pub(crate) fn decode_response(b: &[u8]) -> Result<Option<PathBuf>, PlatformError> {
    use std::os::unix::ffi::OsStringExt;
    match b.split_first() {
        Some((b'C', [])) => Ok(None),
        Some((b'P', path))
            if !path.is_empty()
                && path.len() <= MAX_PICKED
                && path.first() == Some(&b'/')
                && !path.contains(&0) =>
        {
            Ok(Some(PathBuf::from(std::ffi::OsString::from_vec(
                path.to_vec(),
            ))))
        }
        _ => Err(PlatformError::Unavailable),
    }
}

/// In the helper process: answers one request and returns the exit code.
/// `None` when this process is the app. Called first thing, before
/// hardening, the instance lock or any vault access.
pub fn helper() -> Option<i32> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? != ARG || args.next().is_some() {
        return None;
    }
    let mut request = Vec::new();
    let read = std::io::stdin()
        .take(REQUEST_MAX as u64 + 1)
        .read_to_end(&mut request);
    let answer = match (read, decode_request(&request)) {
        (Ok(_), Some((title, kind))) => qv_core::platform::portal::pick(&title, &kind),
        _ => Err(PlatformError::Unavailable),
    };
    let mut out = std::io::stdout();
    Some(i32::from(
        out.write_all(&encode_response(&answer))
            .and_then(|()| out.flush())
            .is_err(),
    ))
}

/// In the app: asks the portal through the helper and waits for the user.
pub(crate) fn pick(title: &str, kind: &Pick) -> Result<Option<PathBuf>, PlatformError> {
    let mut child = Command::new("/proc/self/exe")
        .arg(ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| PlatformError::Unavailable)?;
    let sent = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(&encode_request(title, kind)));
    let mut answer = Vec::new();
    let got = child
        .stdout
        .take()
        .map(|out| out.take(MAX_PICKED as u64 + 2).read_to_end(&mut answer));
    let status = child.wait();
    match (sent, got, status) {
        (Some(Ok(())), Some(Ok(_)), Ok(s)) if s.success() => decode_response(&answer),
        _ => Err(PlatformError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn picker_requests_round_trip_and_refuse_malformed_input() {
        for kind in [
            Pick::Open,
            Pick::Folder,
            Pick::Save("My Vault.qvault".into()),
        ] {
            let b = encode_request("Open a vault", &kind);
            let (title, back) = decode_request(&b).unwrap();
            assert_eq!(title, "Open a vault");
            assert_eq!(format!("{back:?}"), format!("{kind:?}"));
        }
        for bad in [
            &b""[..],
            b"O",
            b"Xtitle\0",
            b"Otitle\0name",
            b"Ftitle\0name",
            b"Stitle\0",
            b"Stitle\0a\0b",
            b"O\xff\0",
        ] {
            assert!(decode_request(bad).is_none(), "{bad:?}");
        }
        let mut long = encode_request("t", &Pick::Open);
        long.resize(REQUEST_MAX + 1, b'a');
        assert!(decode_request(&long).is_none());
    }

    #[test]
    fn picker_responses_carry_only_absolute_local_paths() {
        let p = PathBuf::from("/home/a/My Vault\n.qvault");
        assert_eq!(
            decode_response(&encode_response(&Ok(Some(p.clone())))),
            Ok(Some(p))
        );
        assert_eq!(decode_response(&encode_response(&Ok(None))), Ok(None));
        assert_eq!(
            decode_response(&encode_response(&Err(PlatformError::Unavailable))),
            Err(PlatformError::Unavailable)
        );
        for bad in [&b""[..], b"P", b"Prelative", b"P/a\0b", b"Cx", b"Z/x"] {
            assert_eq!(
                decode_response(bad),
                Err(PlatformError::Unavailable),
                "{bad:?}"
            );
        }
        let mut long = vec![b'P', b'/'];
        long.resize(MAX_PICKED + 2, b'a');
        assert_eq!(decode_response(&long), Err(PlatformError::Unavailable));
    }
}
