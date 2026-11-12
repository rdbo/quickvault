// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault selection (spec 0011 §1.2) and the core's set-up.
//!
//! First match wins: `--vault`/`-v`, then `QVAULT_PATH`, then
//! `default_vault` in the config file. The environment is read once in
//! `main` and passed in, so tests never change the process environment.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use qv_core::{AnchorDir, Core, CoreConfig, SnapshotPolicy};

use crate::config::{self, Config};
use crate::exit::CliError;

/// The environment variables qv reads. `QVAULT_PATH` names a path,
/// which is not a secret; no secret is ever read from the environment
/// (0011 §3.1).
#[derive(Clone, Debug, Default)]
pub(crate) struct Environment {
    pub(crate) qvault_path: Option<OsString>,
    pub(crate) home: Option<OsString>,
    pub(crate) xdg_config_home: Option<OsString>,
    /// `%APPDATA%` (Windows only).
    pub(crate) appdata: Option<OsString>,
}

impl Environment {
    pub(crate) fn from_process() -> Self {
        Self {
            qvault_path: std::env::var_os("QVAULT_PATH"),
            home: std::env::var_os("HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            appdata: if cfg!(windows) {
                std::env::var_os("APPDATA")
            } else {
                None
            },
        }
    }

    /// The config file path, if a home or config directory is known
    /// (Windows: `%APPDATA%\QuickVault\config.toml`, 0009 §5.1).
    pub(crate) fn config_path(&self) -> Option<PathBuf> {
        let absolute =
            |v: &Option<OsString>| v.as_ref().map(PathBuf::from).filter(|p| p.is_absolute());
        if cfg!(windows) {
            return absolute(&self.appdata).map(|d| d.join("QuickVault").join("config.toml"));
        }
        absolute(&self.xdg_config_home)
            .or_else(|| absolute(&self.home).map(|h| h.join(".config")))
            .map(|d| d.join("quickvault").join("config.toml"))
    }

    /// The parsed config file (empty if there is none).
    pub(crate) fn config(&self) -> Result<Config, CliError> {
        match self.config_path() {
            Some(p) => config::load(&p),
            None => Ok(Config::default()),
        }
    }
}

/// The selected vault, or `None` if nothing selects one.
pub(crate) fn selected_vault(
    explicit: Option<&Path>,
    env: &Environment,
) -> Result<Option<PathBuf>, CliError> {
    if let Some(p) = explicit {
        return Ok(Some(p.to_owned()));
    }
    if let Some(p) = env.qvault_path.as_ref().filter(|p| !p.is_empty()) {
        return Ok(Some(PathBuf::from(p)));
    }
    Ok(env.config()?.default_vault)
}

/// The selected vault, or exit 2.
pub(crate) fn require_vault(
    explicit: Option<&Path>,
    env: &Environment,
) -> Result<PathBuf, CliError> {
    selected_vault(explicit, env)?.ok_or_else(|| {
        CliError::usage(
            "no vault selected: use --vault <path>, set QVAULT_PATH, or set default_vault in \
             the config file",
        )
    })
}

/// A core with the default anchor and snapshot directories (0005 §5.4,
/// 0007 §3.1). An unusable snapshot directory must not break a read, so it
/// disables snapshots and the session reports that as a warning (0011 §4).
pub(crate) fn core() -> Result<Core, CliError> {
    let dir = AnchorDir::default_dir()?;
    let anchors = AnchorDir::open(&dir)?;
    let mut config = CoreConfig::new(anchors);
    if let Ok(policy) = SnapshotPolicy::default_dir() {
        config = config.with_snapshots(policy);
    }
    Ok(Core::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(qvault: Option<&str>, config_dir: Option<&Path>) -> Environment {
        Environment {
            qvault_path: qvault.map(OsString::from),
            home: None,
            xdg_config_home: config_dir.map(|p| p.as_os_str().to_owned()),
            // Windows file names ignore case: `QuickVault` is `quickvault`.
            appdata: config_dir.map(|p| p.as_os_str().to_owned()),
        }
    }

    #[test]
    fn select_order() {
        let dir = std::env::temp_dir().join(format!("qv-cli-select-{}", std::process::id()));
        let cfg = dir.join("quickvault");
        std::fs::create_dir_all(&cfg).unwrap();
        // An absolute path needs a drive on Windows.
        let r = if cfg!(windows) { "C:" } else { "" };
        let configured = PathBuf::from(format!("{r}/c/v.qvault"));
        std::fs::write(
            cfg.join("config.toml"),
            format!("default_vault = \"{r}/c/v.qvault\"\n"),
        )
        .unwrap();
        let explicit = PathBuf::from("/x/v.qvault");

        let e = env(Some("/e/v.qvault"), Some(&dir));
        assert_eq!(
            require_vault(Some(&explicit), &e).unwrap(),
            PathBuf::from("/x/v.qvault")
        );
        assert_eq!(
            require_vault(None, &e).unwrap(),
            PathBuf::from("/e/v.qvault")
        );
        let e = env(Some(""), Some(&dir));
        assert_eq!(require_vault(None, &e).unwrap(), configured.clone());
        let e = env(None, Some(&dir));
        assert_eq!(require_vault(None, &e).unwrap(), configured);

        let none = env(None, None);
        assert_eq!(selected_vault(None, &none).unwrap(), None);
        assert_eq!(require_vault(None, &none).unwrap_err().code, 2);

        // A broken config is a usage error even when it would select nothing.
        std::fs::write(cfg.join("config.toml"), "nope = 1\n").unwrap();
        assert_eq!(
            require_vault(None, &env(None, Some(&dir)))
                .unwrap_err()
                .code,
            2
        );
        // ... but `--vault` never reads it.
        assert!(require_vault(Some(&explicit), &env(None, Some(&dir))).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn select_config_path_windows() {
        let e = Environment {
            appdata: Some(r"C:\Users\a\AppData\Roaming".into()),
            ..Environment::default()
        };
        assert_eq!(
            e.config_path(),
            Some(PathBuf::from(
                r"C:\Users\a\AppData\Roaming\QuickVault\config.toml"
            ))
        );
        let relative = Environment {
            appdata: Some("relative".into()),
            home: Some(r"C:\Users\a".into()),
            ..Environment::default()
        };
        assert_eq!(relative.config_path(), None);
    }

    #[cfg(unix)]
    #[test]
    fn select_config_path() {
        let e = Environment {
            qvault_path: None,
            home: Some("/home/a".into()),
            xdg_config_home: Some("relative".into()),
            appdata: None,
        };
        assert_eq!(
            e.config_path(),
            Some(PathBuf::from("/home/a/.config/quickvault/config.toml"))
        );
        let e = Environment {
            xdg_config_home: Some("/cfg".into()),
            ..e
        };
        assert_eq!(
            e.config_path(),
            Some(PathBuf::from("/cfg/quickvault/config.toml"))
        );
        assert_eq!(Environment::default().config_path(), None);
    }
}
