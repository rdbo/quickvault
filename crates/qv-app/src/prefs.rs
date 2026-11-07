// SPDX-License-Identifier: AGPL-3.0-or-later

//! The app's non-secret preferences file (0009 §1.8, plan 0040 R2): the theme
//! and the protection status the user last acknowledged. Bounded, parsed
//! strictly, never read through a link, written to a 0600 temporary file and
//! renamed into place. Every failure falls back to the defaults.
use qv_core::platform::{Evidence, ProtectionStatus};
use std::io::{Read, Write};
use std::path::Path;

/// Largest preferences file read or written.
pub const MAX_PREFS: usize = 256;
const FILE: &str = "preferences";
const TEMP: &str = "preferences.tmp";
/// Longest acknowledged-status fingerprint accepted.
const MAX_FINGERPRINT: usize = 32;

/// The app colour theme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Theme {
    /// Dark (the default).
    #[default]
    Dark,
    /// Light.
    Light,
    /// Follow the operating system.
    System,
}
impl Theme {
    /// The stored and CSS name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::System => "system",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

/// Parsed preferences. Holds no vault data, name or path.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Prefs {
    /// The colour theme.
    pub theme: Theme,
    /// The reduced-protection status the user acknowledged, if any.
    pub protection: Option<String>,
}
impl Prefs {
    /// Parse bounded bytes; unknown keys and malformed lines are ignored.
    pub fn parse(bytes: &[u8]) -> Self {
        let mut prefs = Self::default();
        if bytes.len() > MAX_PREFS {
            return prefs;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return prefs;
        };
        for line in text.lines() {
            match line.split_once('=') {
                Some(("theme", v)) => {
                    if let Some(t) = Theme::parse(v) {
                        prefs.theme = t;
                    }
                }
                Some(("protection", v)) if valid_fingerprint(v) => {
                    prefs.protection = Some(v.to_owned());
                }
                _ => {}
            }
        }
        prefs
    }
    /// The file contents.
    pub fn encode(&self) -> String {
        let mut out = format!("theme={}\n", self.theme.name());
        if let Some(p) = self.protection.as_deref().filter(|p| valid_fingerprint(p)) {
            out.push_str("protection=");
            out.push_str(p);
            out.push('\n');
        }
        out
    }
    /// Load from the private app directory; any problem gives the defaults.
    pub fn load(base: &Path) -> Self {
        read_private(&base.join(FILE), MAX_PREFS).map_or_else(Self::default, |b| Self::parse(&b))
    }
    /// Save atomically: a fresh 0600 temporary file renamed into place.
    pub fn save(&self, base: &Path) -> std::io::Result<()> {
        let text = self.encode();
        if text.len() > MAX_PREFS {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        write_private(base, FILE, TEMP, text.as_bytes())
    }
}
/// Read a small private file: a regular file (never through a link) of at
/// most `max` bytes, else `None`.
pub(crate) fn read_private(path: &Path, max: usize) -> Option<Vec<u8>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() && m.len() <= max as u64 => {}
        _ => return None,
    }
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(max.min(4096));
    file.take(max as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= max).then_some(bytes)
}
/// Write a small private file atomically: a fresh 0600 temporary file in
/// `base`, synced and renamed into place. A non-file temporary path refuses.
pub(crate) fn write_private(
    base: &Path,
    file: &str,
    temp: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    let temp = base.join(temp);
    match std::fs::symlink_metadata(&temp) {
        Ok(m) if m.file_type().is_file() => std::fs::remove_file(&temp)?,
        Ok(_) => return Err(std::io::ErrorKind::AlreadyExists.into()),
        Err(_) => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = options.open(&temp)?;
    out.write_all(bytes)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(&temp, base.join(file))
}
fn valid_fingerprint(v: &str) -> bool {
    !v.is_empty() && v.len() <= MAX_FINGERPRINT && v.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A short code for a reduced protection status, or `None` when protection
/// is complete and no acknowledgement is needed (0008 §1.3, 0009 §1.8).
pub fn fingerprint(status: &ProtectionStatus, process_reduced: bool) -> Option<String> {
    if !status.is_reduced() && !process_reduced {
        return None;
    }
    let e = |v: Evidence| match v {
        Evidence::Verified => 'v',
        Evidence::KnownGap => 'g',
        Evidence::Unknown => 'u',
    };
    let b = |v: bool| if v { '1' } else { '0' };
    Some(format!(
        "s{}w{}h{}l{}c{}p{}",
        e(status.storage),
        e(status.swap),
        e(status.hibernation),
        b(status.lifecycle),
        b(status.clipboard),
        b(process_reduced)
    ))
}
/// Whether the acknowledged fingerprint covers the current one. Where
/// lifecycle monitoring is mandatory (every platform but Linux) the app does
/// not run without it, so its bit is not compared: a status read before the
/// first native report must not ask again (plan 0044 note 9).
pub fn acknowledged(current: Option<&str>, saved: Option<&str>, lifecycle_required: bool) -> bool {
    let norm = |v: &str| {
        if lifecycle_required {
            v.replace("l0", "l1")
        } else {
            v.to_owned()
        }
    };
    match (current, saved) {
        (None, _) => true,
        (Some(c), Some(s)) => norm(c) == norm(s),
        (Some(_), None) => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn status(storage: Evidence, lifecycle: bool) -> ProtectionStatus {
        ProtectionStatus {
            storage,
            swap: Evidence::Verified,
            hibernation: Evidence::Verified,
            lifecycle,
            clipboard: true,
            quick_unlock: false,
        }
    }
    #[test]
    fn prefs_parse_is_strict_bounded_and_round_trips() {
        assert_eq!(Prefs::parse(b""), Prefs::default());
        assert_eq!(Prefs::default().theme, Theme::Dark);
        let p = Prefs::parse(b"theme=light\nprotection=svwvhvl0c1p0\nother=x\n");
        assert_eq!(p.theme, Theme::Light);
        assert_eq!(p.protection.as_deref(), Some("svwvhvl0c1p0"));
        assert_eq!(Prefs::parse(p.encode().as_bytes()), p);
        // Malformed values are ignored, not partially applied.
        let bad = Prefs::parse(b"theme=neon\nprotection=a b\nprotection=../x\n");
        assert_eq!(bad, Prefs::default());
        assert_eq!(Prefs::parse(&[b'a'; MAX_PREFS + 1]), Prefs::default());
        assert_eq!(Prefs::parse(b"theme=\xff"), Prefs::default());
        let long = format!("protection={}", "a".repeat(MAX_FINGERPRINT + 1));
        assert_eq!(Prefs::parse(long.as_bytes()).protection, None);
    }
    #[test]
    fn prefs_files_are_private_atomic_and_never_followed() {
        let dir = std::env::temp_dir().join(format!("qv-prefs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(Prefs::load(&dir), Prefs::default());
        let p = Prefs {
            theme: Theme::System,
            protection: Some("suwuhul1c1p0".into()),
        };
        p.save(&dir).unwrap();
        assert_eq!(Prefs::load(&dir), p);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            // A link in place of the file is not followed.
            std::fs::remove_file(dir.join(FILE)).unwrap();
            std::fs::write(dir.join("target"), b"theme=light\n").unwrap();
            std::os::unix::fs::symlink(dir.join("target"), dir.join(FILE)).unwrap();
            assert_eq!(Prefs::load(&dir), Prefs::default());
            // A link in place of the temporary file is refused, not written through.
            std::fs::remove_file(dir.join(FILE)).unwrap();
            std::os::unix::fs::symlink(dir.join("target"), dir.join(TEMP)).unwrap();
            assert!(p.save(&dir).is_err());
            assert_eq!(std::fs::read(dir.join("target")).unwrap(), b"theme=light\n");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn protection_fingerprint_only_for_reduced_status() {
        let full = status(Evidence::Verified, true);
        assert_eq!(fingerprint(&full, false), None);
        assert!(fingerprint(&full, true).is_some());
        let a = fingerprint(&status(Evidence::Unknown, true), false).unwrap();
        let b = fingerprint(&status(Evidence::Unknown, false), false).unwrap();
        assert_ne!(a, b);
        assert!(valid_fingerprint(&a));
    }
    #[test]
    fn acknowledgement_ignores_lifecycle_only_where_it_is_required() {
        let on = fingerprint(&status(Evidence::Unknown, true), false).unwrap();
        let off = fingerprint(&status(Evidence::Unknown, false), false).unwrap();
        let other = fingerprint(&status(Evidence::KnownGap, true), false).unwrap();
        assert!(acknowledged(None, None, false));
        assert!(!acknowledged(Some(&on), None, true));
        assert!(acknowledged(Some(&on), Some(&on), false));
        // Linux: a lost lifecycle is a changed status.
        assert!(!acknowledged(Some(&off), Some(&on), false));
        // Android: a transient reading before the first report is not.
        assert!(acknowledged(Some(&off), Some(&on), true));
        assert!(acknowledged(Some(&on), Some(&off), true));
        assert!(!acknowledged(Some(&other), Some(&on), true));
        // The owner's saved value on the phone.
        assert!(acknowledged(
            Some("suwuhul0c1p0"),
            Some("suwuhul1c1p0"),
            true
        ));
    }
}
