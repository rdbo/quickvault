// SPDX-License-Identifier: AGPL-3.0-or-later

//! The vault list (0009 §1.8, plan 0041): the default folder, remembered
//! vault paths with a copy of each vault's name, and the vaults found in the
//! default folder. A vault's name is the one stored (encrypted and synced)
//! inside it; the copy here lets the lock screen show it. Files are never
//! renamed; a vault not yet opened here shows its file name.
//!
//! The list file is private app state, separate from the preferences file:
//! bounded, parsed strictly, never read through a link, and written
//! atomically with mode 0600. Listing never opens a vault; core re-checks
//! every path when it is opened (0011 §4).
use crate::controller::AppError;
use crate::prefs::{read_private, write_private};
use std::path::{Path, PathBuf};

/// Largest vault-list file read or written.
pub const MAX_LIST: usize = 640 * 1024;
/// Most remembered vaults, and most vaults scanned in a folder.
pub const MAX_VAULTS: usize = 64;
/// Longest accepted path, in bytes.
pub const MAX_PATH: usize = 4096;
/// Longest new vault name, in characters.
pub const MAX_NAME: usize = 64;
/// Longest remembered vault name, in bytes (longer names are cut).
pub const MAX_SHOWN: usize = 256;
const FILE: &str = "vault-list";
const TEMP: &str = "vault-list.tmp";
const EXTENSION: &str = "qvault";

/// The remembered vaults and the chosen default folder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultList {
    /// The chosen default folder (Linux), if not the built-in one.
    pub folder: Option<PathBuf>,
    /// Remembered vault files, most recently used first.
    pub recent: Vec<PathBuf>,
    /// The name each remembered vault had when last opened here.
    pub names: std::collections::BTreeMap<PathBuf, String>,
}
/// A name as remembered: one line, no control characters, bounded.
fn shown_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().any(char::is_control) {
        return None;
    }
    let mut end = name.len().min(MAX_SHOWN);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    Some(name[..end].to_owned())
}
fn valid_path(p: &str) -> Option<PathBuf> {
    let ok = !p.is_empty()
        && p.len() <= MAX_PATH
        && p.starts_with('/')
        && !p.contains(['\0', '\n', '\r', '\t']);
    ok.then(|| PathBuf::from(p))
}
fn is_vault(p: &Path) -> bool {
    p.extension().is_some_and(|e| e == EXTENSION)
}
impl VaultList {
    /// Parse bounded bytes; malformed lines are ignored, not partly applied.
    pub fn parse(bytes: &[u8]) -> Self {
        let mut list = Self::default();
        if bytes.len() > MAX_LIST {
            return list;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return list;
        };
        for line in text.lines() {
            match line.split_once(' ') {
                Some(("folder", p)) if list.folder.is_none() => list.folder = valid_path(p),
                Some(("vault", p)) => {
                    if let Some(p) = valid_path(p).filter(|p| is_vault(p))
                        && list.recent.len() < MAX_VAULTS
                        && !list.recent.contains(&p)
                    {
                        list.recent.push(p);
                    }
                }
                Some(("name", rest)) => {
                    if let Some((p, n)) = rest.split_once('\t')
                        && let (Some(p), Some(n)) = (valid_path(p), shown_name(n))
                    {
                        list.names.insert(p, n);
                    }
                }
                _ => {}
            }
        }
        // Names only for remembered vaults.
        let recent = list.recent.clone();
        list.names.retain(|p, _| recent.contains(p));
        list
    }
    /// The file contents.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        let mut line = |key: &str, p: &Path| {
            if let Some(p) = p.to_str().filter(|p| valid_path(p).is_some()) {
                out.push_str(key);
                out.push(' ');
                out.push_str(p);
                out.push('\n');
            }
        };
        if let Some(f) = &self.folder {
            line("folder", f);
        }
        for p in self.recent.iter().take(MAX_VAULTS) {
            line("vault", p);
        }
        for p in self.recent.iter().take(MAX_VAULTS) {
            if let (Some(n), Some(ps)) = (self.names.get(p).and_then(|n| shown_name(n)), p.to_str())
                && valid_path(ps).is_some()
            {
                out.push_str("name ");
                out.push_str(ps);
                out.push('\t');
                out.push_str(&n);
                out.push('\n');
            }
        }
        out
    }
    /// Load from the private app directory; any problem gives an empty list.
    pub fn load(base: &Path) -> Self {
        read_private(&base.join(FILE), MAX_LIST).map_or_else(Self::default, |b| Self::parse(&b))
    }
    /// Save atomically to the private app directory.
    pub fn save(&self, base: &Path) -> std::io::Result<()> {
        let text = self.encode();
        if text.len() > MAX_LIST {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        write_private(base, FILE, TEMP, text.as_bytes())
    }
    /// Put a vault first (it was just created, opened or picked).
    pub fn remember(&mut self, path: &Path) {
        if valid_path(&path.to_string_lossy()).is_none() || !is_vault(path) {
            return;
        }
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_path_buf());
        self.recent.truncate(MAX_VAULTS);
        let recent = self.recent.clone();
        self.names.retain(|p, _| recent.contains(p));
    }
    /// Remember a vault's name; returns whether it changed. Only for a
    /// remembered vault.
    pub fn set_name(&mut self, path: &Path, name: &str) -> bool {
        let Some(name) = shown_name(name).filter(|_| self.recent.iter().any(|p| p == path)) else {
            return false;
        };
        self.names.insert(path.to_path_buf(), name.clone()) != Some(name)
    }
    /// Drop a remembered vault (the file is untouched).
    pub fn forget(&mut self, path: &Path) {
        self.recent.retain(|p| p != path);
        self.names.remove(path);
    }
}

/// The folder new vaults go to: the chosen one, else the platform default.
/// Android, validation and test builds always use the private `vaults/`
/// directory, so fixtures and tests never touch a real vault folder.
pub fn default_folder(base: &Path, chosen: Option<&Path>) -> PathBuf {
    let private = base.join("vaults");
    if cfg!(any(target_os = "android", feature = "validation", test)) {
        return private;
    }
    if let Some(c) = chosen {
        return c.to_path_buf();
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|h| h.join(".local/share"))
        });
    data.map_or(private, |d| d.join("quickvault").join("vaults"))
}
/// The file name for a vault name (V4): trimmed, 1–64 characters, without
/// `/`, `\` or control characters, not starting with a dot.
pub fn file_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    let count = name.chars().count();
    let ok = (1..=MAX_NAME).contains(&count)
        && !name.starts_with('.')
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control());
    if ok {
        Ok(format!("{name}.{EXTENSION}"))
    } else {
        Err(AppError::VaultName)
    }
}
/// A folder for display, with the home directory shortened to `~`.
pub fn shown_place(dir: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        && let Ok(rest) = dir.strip_prefix(&home)
    {
        return if rest.as_os_str().is_empty() {
            "~".into()
        } else {
            format!("~/{}", rest.display())
        };
    }
    dir.display().to_string()
}

/// One vault on the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// Its file.
    pub path: PathBuf,
    /// Its name: the one stored inside, as last seen here, else the file
    /// name without `.qvault`.
    pub name: String,
    /// Its file name.
    pub file: String,
    /// Its folder, for display.
    pub place: String,
    /// The file is there (a regular file, not a link).
    pub exists: bool,
    /// It is found by scanning a folder, so removing it would not stick.
    pub in_folder: bool,
}
fn regular(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
}
/// The regular `.qvault` files directly in `dir` (at most 64, no links).
fn scan(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten().take(MAX_VAULTS * 4) {
        let p = entry.path();
        if is_vault(&p) && entry.file_type().is_ok_and(|t| t.is_file()) {
            out.push(p);
            if out.len() == MAX_VAULTS {
                break;
            }
        }
    }
    out
}
fn listed_one(path: PathBuf, folders: &[PathBuf], list: &VaultList) -> Listed {
    let stem = path
        .file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = list.names.get(&path).cloned().unwrap_or(stem);
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    Listed {
        file,
        exists: regular(&path),
        in_folder: folders.contains(&parent),
        place: shown_place(&parent),
        name,
        path,
    }
}
/// Every vault to offer (V5): remembered ones first, most recent first,
/// then the others found in `folder` (the default) and the private folder,
/// by name.
pub fn listed(base: &Path, folder: &Path, list: &VaultList) -> Vec<Listed> {
    let mut folders = vec![folder.to_path_buf()];
    if base.join("vaults") != folder {
        folders.push(base.join("vaults"));
    }
    let mut out: Vec<Listed> = list
        .recent
        .iter()
        .map(|p| listed_one(p.clone(), &folders, list))
        .collect();
    let mut found: Vec<Listed> = folders
        .iter()
        .flat_map(|f| scan(f))
        .filter(|p| !list.recent.contains(p))
        .map(|p| listed_one(p, &folders, list))
        .collect();
    found.sort_by_key(|l| l.name.to_lowercase());
    for l in found {
        if !out.iter().any(|o| o.path == l.path) {
            out.push(l);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qv-vaults-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn vault_list_parse_is_strict_bounded_and_round_trips() {
        let l = VaultList::parse(
            b"folder /home/a/V\nvault /home/a/V/Work.qvault\nvault relative.qvault\nvault /x/notes.txt\nvault /home/a/V/Work.qvault\nother /y\nfolder /second\n",
        );
        assert_eq!(l.folder.as_deref(), Some(Path::new("/home/a/V")));
        assert_eq!(l.recent, [PathBuf::from("/home/a/V/Work.qvault")]);
        assert_eq!(VaultList::parse(l.encode().as_bytes()), l);
        // Names: only for remembered vaults, one line, bounded.
        let named = VaultList::parse(
            "vault /v/A.qvault\nname /v/A.qvault\tFamily Vault\nname /v/B.qvault\tStray\nname /v/A.qvault\tbad\u{7}\n".as_bytes(),
        );
        assert_eq!(
            named
                .names
                .get(Path::new("/v/A.qvault"))
                .map(String::as_str),
            Some("Family Vault")
        );
        assert_eq!(named.names.len(), 1);
        assert_eq!(VaultList::parse(named.encode().as_bytes()), named);
        assert_eq!(
            VaultList::parse(&vec![b'a'; MAX_LIST + 1]),
            VaultList::default()
        );
        assert_eq!(
            VaultList::parse(b"vault /a\xff.qvault"),
            VaultList::default()
        );
        let long = format!("vault /{}.qvault", "a".repeat(MAX_PATH));
        assert!(VaultList::parse(long.as_bytes()).recent.is_empty());
        let many: String = (0..MAX_VAULTS + 5)
            .map(|i| format!("vault /v/{i}.qvault\n"))
            .collect();
        assert_eq!(VaultList::parse(many.as_bytes()).recent.len(), MAX_VAULTS);
    }

    #[test]
    fn remembering_moves_to_the_front_and_is_capped() {
        let mut l = VaultList::default();
        for i in 0..MAX_VAULTS + 3 {
            l.remember(Path::new(&format!("/v/{i}.qvault")));
        }
        assert_eq!(l.recent.len(), MAX_VAULTS);
        l.remember(Path::new("/v/40.qvault"));
        assert_eq!(l.recent[0], PathBuf::from("/v/40.qvault"));
        assert_eq!(
            l.recent.iter().filter(|p| p.ends_with("40.qvault")).count(),
            1
        );
        assert!(l.set_name(Path::new("/v/40.qvault"), "Forty"));
        assert!(!l.set_name(Path::new("/v/40.qvault"), "Forty"));
        assert!(!l.set_name(Path::new("/v/unknown.qvault"), "X"));
        assert!(!l.set_name(Path::new("/v/40.qvault"), "two\nlines"));
        let long = "é".repeat(MAX_SHOWN);
        assert!(l.set_name(Path::new("/v/40.qvault"), &long));
        assert!(l.names[Path::new("/v/40.qvault")].len() <= MAX_SHOWN);
        l.forget(Path::new("/v/40.qvault"));
        assert!(!l.recent.contains(&PathBuf::from("/v/40.qvault")));
        assert!(l.names.is_empty());
        // Not vault files, or not absolute: ignored.
        l.remember(Path::new("/v/notes.txt"));
        l.remember(Path::new("rel.qvault"));
        assert!(l.recent.iter().all(|p| p.is_absolute() && is_vault(p)));
    }

    #[test]
    fn vault_list_files_are_private_atomic_and_never_followed() {
        let d = dir("file");
        assert_eq!(VaultList::load(&d), VaultList::default());
        let mut l = VaultList::default();
        l.remember(Path::new("/home/a/Personal.qvault"));
        l.save(&d).unwrap();
        assert_eq!(VaultList::load(&d), l);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join(FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let other = d.join("elsewhere");
            std::fs::write(&other, l.encode()).unwrap();
            std::fs::remove_file(d.join(FILE)).unwrap();
            std::os::unix::fs::symlink(&other, d.join(FILE)).unwrap();
            assert_eq!(VaultList::load(&d), VaultList::default());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn vault_names_become_safe_file_names() {
        assert_eq!(file_name("  Personal ").unwrap(), "Personal.qvault");
        assert_eq!(file_name("Família 2").unwrap(), "Família 2.qvault");
        assert_eq!(
            file_name(&"é".repeat(MAX_NAME)).unwrap().chars().count(),
            MAX_NAME + 7
        );
        for bad in [
            "",
            "   ",
            ".hidden",
            "..",
            "a/b",
            "a\\b",
            "tab\there",
            &"x".repeat(MAX_NAME + 1),
        ] {
            assert!(
                matches!(file_name(bad), Err(AppError::VaultName)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn listing_scans_folders_skips_links_and_keeps_remembered_order() {
        let base = dir("list");
        let private = base.join("vaults");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(private.join("main.qvault"), b"x").unwrap();
        std::fs::write(private.join("Banking.qvault"), b"x").unwrap();
        std::fs::write(private.join("notes.txt"), b"x").unwrap();
        std::fs::create_dir_all(private.join("dir.qvault")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(private.join("main.qvault"), private.join("link.qvault"))
            .unwrap();
        let outside = base.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("Work.qvault"), b"x").unwrap();
        let mut l = VaultList::default();
        l.remember(&private.join("main.qvault"));
        l.remember(&outside.join("Work.qvault"));
        l.remember(&outside.join("Gone.qvault"));
        // A vault opened here shows its stored name; its file is unchanged.
        l.set_name(&private.join("main.qvault"), "Test");
        let shown = listed(&base, &private, &l);
        let names: Vec<&str> = shown.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["Gone", "Work", "Test", "Banking"]);
        assert_eq!(shown[2].file, "main.qvault");
        assert!(!shown[0].exists && !shown[0].in_folder);
        assert!(shown[1].exists && !shown[1].in_folder);
        assert!(shown[2].in_folder && shown[3].in_folder);
        // Tests (like Android and validation builds) use the private folder.
        assert_eq!(default_folder(&base, None), private);
        assert_eq!(default_folder(&base, Some(&outside)), private);
        let _ = std::fs::remove_dir_all(&base);
    }
}
