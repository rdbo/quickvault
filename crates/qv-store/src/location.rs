// SPDX-License-Identifier: AGPL-3.0-or-later

//! Location warnings (spec 0004 §1.1, 0011 *Security Considerations*).
//!
//! File-sync tools, network filesystems and removable media may copy or
//! roll back the live file, so a vault there gets a warning. Warnings are
//! advisory data: `open` and `create` still succeed and the frontend shows
//! them. Detection is heuristic, uses no network access, and looks at:
//!
//! - path components naming a known sync folder (`Dropbox`, `OneDrive`,
//!   `Google Drive`, …), `Sync` only directly under the home directory
//!   (Resilio), and ancestor directories holding a sync marker (`.stfolder`
//!   for Syncthing, `.dropbox`, `.sync`, `.owncloudsync.log`);
//! - the filesystem type (`fstatfs`): NFS, SMB/CIFS, FUSE (sshfs, rclone and
//!   many sync clients), AFS, Ceph and 9P count as network filesystems;
//!   VFAT and exFAT as removable;
//! - paths under `/media/` or `/run/media/` as removable;
//! - on Windows, the drive type: remote drives are network filesystems,
//!   removable and optical drives removable.

use std::path::{Component, Path};

/// Where a vault path may be unsafe for a live database.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocationWarnings {
    /// Inside a known file-sync folder.
    pub sync_folder: bool,
    /// On a network filesystem.
    pub network_fs: bool,
    /// On removable media.
    pub removable: bool,
    /// The external rollback record may be copied or rolled back with the vault.
    pub anchor_independence: bool,
}

impl LocationWarnings {
    /// Whether any warning applies.
    pub fn any(&self) -> bool {
        self.sync_folder || self.network_fs || self.removable || self.anchor_independence
    }
}

/// Folder names used by file-sync clients (compared case-insensitively).
const SYNC_NAMES: &[&str] = &[
    "Dropbox",
    "OneDrive",
    "Google Drive",
    "GoogleDrive",
    "My Drive",
    "iCloud Drive",
    "iCloudDrive",
    "Mobile Documents",
    "Nextcloud",
    "ownCloud",
    "pCloudDrive",
    "MEGA",
    "Seafile",
];

/// Files or directories that mark a synced folder tree.
const SYNC_MARKERS: &[&str] = &[".stfolder", ".dropbox", ".sync", ".owncloudsync.log"];

/// How many ancestor levels are examined for markers.
const MAX_ANCESTORS: usize = 64;

/// Network filesystem magic numbers (`statfs(2)` `f_type`).
const NETWORK_FS: &[u64] = &[
    0x6969,      // NFS
    0x517B,      // SMB
    0xFF53_4D42, // CIFS
    0xFE53_4D42, // SMB2
    0x6573_5546, // FUSE
    0x5346_414F, // AFS
    0x00C3_6400, // Ceph
    0x0102_1997, // 9P
];

/// Removable-media filesystem magic numbers.
const REMOVABLE_FS: &[u64] = &[
    0x4d44,      // VFAT
    0x2011_BAB0, // exFAT
];

fn component_name(c: Component<'_>) -> Option<&str> {
    match c {
        Component::Normal(s) => s.to_str(),
        _ => None,
    }
}

fn is_sync_name(name: &str) -> bool {
    SYNC_NAMES.iter().any(|n| name.eq_ignore_ascii_case(n))
        || name
            .get(..11)
            .is_some_and(|p| p.eq_ignore_ascii_case("OneDrive - "))
}

/// Warnings that follow from the directory path alone. `dir` should be the
/// canonical parent directory of the vault; `home` the user's home.
pub(crate) fn path_warnings(dir: &Path, home: Option<&Path>) -> LocationWarnings {
    let sync_named = dir
        .components()
        .filter_map(component_name)
        .any(is_sync_name);
    let resilio = home
        .and_then(|h| dir.strip_prefix(h).ok())
        .and_then(|rest| rest.components().next())
        .and_then(component_name)
        .is_some_and(|first| first.eq_ignore_ascii_case("Sync"));
    let removable = dir.starts_with("/media") || dir.starts_with("/run/media");
    LocationWarnings {
        sync_folder: sync_named || resilio,
        network_fs: false,
        removable,
        anchor_independence: false,
    }
}

/// Whether `dir` or one of its ancestors holds a sync marker.
pub(crate) fn has_sync_marker(dir: &Path) -> bool {
    dir.ancestors().take(MAX_ANCESTORS).any(|a| {
        SYNC_MARKERS
            .iter()
            .any(|m| std::fs::symlink_metadata(a.join(m)).is_ok())
    })
}

/// Warnings from a filesystem type (`f_type`, as 32-bit magic).
#[cfg_attr(windows, allow(dead_code))] // Unix `fstatfs` only; tested everywhere.
pub(crate) fn fs_type_warnings(f_type: u64) -> LocationWarnings {
    let magic = f_type & 0xFFFF_FFFF;
    LocationWarnings {
        sync_folder: false,
        network_fs: NETWORK_FS.contains(&magic),
        removable: REMOVABLE_FS.contains(&magic),
        anchor_independence: false,
    }
}

fn union(a: LocationWarnings, b: LocationWarnings) -> LocationWarnings {
    LocationWarnings {
        sync_folder: a.sync_folder || b.sync_folder,
        network_fs: a.network_fs || b.network_fs,
        removable: a.removable || b.removable,
        anchor_independence: a.anchor_independence || b.anchor_independence,
    }
}

/// All warnings for the vault at `path`, open as `file`.
#[cfg(any(target_os = "linux", target_os = "android", windows))]
pub(crate) fn warnings_for(path: &Path, file: &crate::fs::LockedFile) -> LocationWarnings {
    let dir = std::fs::canonicalize(crate::fs::parent_of(path)).ok();
    let home = home_dir();
    let by_path = dir.as_deref().map_or_else(LocationWarnings::default, |d| {
        let mut w = path_warnings(d, home.as_deref());
        w.sync_folder |= has_sync_marker(d);
        w
    });
    #[cfg(not(windows))]
    // `f_type` is a signed C long; the magic is its low 32 bits. Its Rust
    // type differs by target (already `u64` on Android), hence the allow.
    #[allow(clippy::unnecessary_cast)]
    let by_fs = rustix::fs::fstatfs(file.fd()).map_or_else(
        |_| LocationWarnings::default(),
        |s| fs_type_warnings(s.f_type as u64),
    );
    #[cfg(windows)]
    let by_fs = {
        let _ = file;
        dir.as_deref().and_then(volume_warnings).unwrap_or_default()
    };
    union(by_path, by_fs)
}

/// The home directory used by the sync-folder heuristics (`HOME`;
/// `USERPROFILE` on Windows).
#[cfg(any(target_os = "linux", target_os = "android", windows))]
pub(crate) fn home_dir() -> Option<std::path::PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).map(std::path::PathBuf::from)
}

/// Filesystem warnings for the volume holding `path`, `None` if unknown.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn volume_warnings(path: &Path) -> Option<LocationWarnings> {
    let file = std::fs::File::open(path).ok()?;
    // statfs magic has different signedness across Linux/Android ABIs.
    #[allow(clippy::unnecessary_cast)]
    rustix::fs::fstatfs(&file)
        .ok()
        .map(|s| fs_type_warnings(s.f_type as u64))
}

/// Filesystem warnings for the volume holding `path` (drive type), `None`
/// if unknown.
#[cfg(windows)]
pub(crate) fn volume_warnings(path: &Path) -> Option<LocationWarnings> {
    use qv_win::fs::Drive;
    match qv_win::fs::drive_type(path) {
        Drive::Local => Some(LocationWarnings::default()),
        Drive::Remote => Some(LocationWarnings {
            network_fs: true,
            ..LocationWarnings::default()
        }),
        Drive::Removable => Some(LocationWarnings {
            removable: true,
            ..LocationWarnings::default()
        }),
        Drive::Unknown => None,
    }
}

/// `<local>\QuickVault`, the Windows device-local application directory
/// (0009 §5.1) from `%LOCALAPPDATA%`. [`crate::StoreError::NotFound`]
/// unless it is absolute.
#[cfg(windows)]
pub(crate) fn windows_app_dir(
    local: Option<std::ffi::OsString>,
) -> Result<std::path::PathBuf, crate::StoreError> {
    local
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| p.join("QuickVault"))
        .ok_or(crate::StoreError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sync(dir: &str) -> bool {
        path_warnings(Path::new(dir), Some(Path::new("/home/u"))).sync_folder
    }

    #[test]
    fn location_sync_names() {
        for name in SYNC_NAMES {
            assert!(sync(&format!("/home/u/{name}/vaults")), "{name}");
            assert!(sync(&format!("/home/u/{}", name.to_lowercase())), "{name}");
            assert!(
                sync(&format!("/home/u/{}/x", name.to_uppercase())),
                "{name}"
            );
        }
        assert!(sync("/home/u/OneDrive - Contoso/x"));
        assert!(sync("/home/u/onedrive - contoso"));
        assert!(sync("/home/u/Library/Mobile Documents/com~apple~CloudDocs"));
        assert!(!sync("/home/u/Documents"));
        assert!(!sync("/home/u/DropboxBackup"));
        assert!(!sync("/home/u/OneDriveX"));
    }

    #[test]
    fn location_resilio_only_under_home() {
        assert!(sync("/home/u/Sync"));
        assert!(sync("/home/u/sync/vaults"));
        assert!(!sync("/srv/Sync"));
        assert!(!sync("/home/u/projects/Sync"));
        assert!(!path_warnings(Path::new("/home/u/Sync"), None).sync_folder);
    }

    #[test]
    fn location_removable_paths() {
        let w = |d: &str| path_warnings(Path::new(d), None);
        assert!(w("/media/usb").removable);
        assert!(w("/run/media/u/stick/vaults").removable);
        assert!(!w("/mediafiles").removable);
        assert!(!w("/home/u").any());
    }

    #[test]
    fn location_markers() {
        let d = crate::fs::test_dir::TestDir::new();
        let deep = d.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        assert!(!has_sync_marker(&deep));
        std::fs::create_dir(d.join("a/.stfolder")).unwrap();
        assert!(has_sync_marker(&deep));
        assert!(!has_sync_marker(d.path()));
    }

    #[test]
    fn location_fs_types() {
        assert!(fs_type_warnings(0x6969).network_fs);
        assert!(fs_type_warnings(0x6573_5546).network_fs);
        // A sign-extended negative C long keeps the same low 32 bits.
        assert!(fs_type_warnings(0xFFFF_FFFF_FF53_4D42).network_fs);
        assert!(fs_type_warnings(0x4d44).removable);
        assert!(!fs_type_warnings(0xEF53).any()); // ext4
        assert!(!fs_type_warnings(0x0102_1994).any()); // tmpfs
    }

    #[test]
    fn location_warnings_for_temp_dir() {
        let d = crate::fs::test_dir::TestDir::new();
        let p = d.join("v.qvault");
        crate::fs::test_dir::write_file(&p, b"x", 0o600);
        let f = crate::fs::open_existing(&p).unwrap();
        // The test temp dir is local and not a sync folder.
        assert!(!warnings_for(&p, &f).sync_folder);
        assert!(!LocationWarnings::default().any());
    }
}
