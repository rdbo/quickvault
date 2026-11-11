// SPDX-License-Identifier: AGPL-3.0-or-later

//! Controller-owned selected-document import. Provider I/O stays off the UI.
use super::*;
#[cfg(any(test, all(feature = "desktop", target_os = "android")))]
use std::io::Read;

impl Controller {
    /// Begin one bounded ciphertext read. Its result belongs to this exact form
    /// epoch; background/lock drops it without changing the selected vault.
    #[cfg(any(test, all(feature = "desktop", target_os = "android")))]
    pub(crate) fn stage_vault_input(
        &self,
        epoch: FormEpoch,
        source: impl FnOnce(&CancelToken) -> Result<(Box<dyn Read + Send>, String), AppError>
        + Send
        + 'static,
    ) -> Result<(), AppError> {
        let mut s = self.state();
        if s.epoch != epoch.0 || s.phase != Phase::Locked {
            return Err(AppError::InvalidInput);
        }
        if self.0.working.load(Ordering::SeqCst) {
            return Err(AppError::Busy);
        }
        s.clear_inputs();
        s.pending_import = None;
        s.import_ack = false;
        s.import_name.clear();
        s.cancel.cancel();
        s.cancel = CancelToken::new();
        let token = s.cancel.clone();
        s.epoch = s.epoch.wrapping_add(1);
        let next = s.epoch;
        s.phase = Phase::Opening;
        s.status = "Reading selected vault…";
        s.active = Instant::now();
        s.error = None;
        self.0.working.store(true, Ordering::SeqCst);
        let worker = Worker(self.0.clone());
        let controller = self.clone();
        drop(s);
        std::thread::Builder::new()
            .name("qv-vault-import".into())
            .spawn(move || {
                let _worker = worker;
                let result = (|| {
                    let (mut input, name) = source(&token)?;
                    let core = controller.core()?;
                    let pending = core.stage_vault_import(&mut input, Some(&token))?;
                    drop(input);
                    let proposed = name.strip_suffix(".qvault").unwrap_or(&name).trim();
                    let name = if crate::vaults::file_name(proposed).is_ok() {
                        proposed.to_owned()
                    } else {
                        "Imported vault".to_owned()
                    };
                    Ok::<_, AppError>((pending, name))
                })();
                let mut s = controller.state();
                if s.epoch != next || token.is_cancelled() {
                    return;
                }
                s.phase = Phase::Locked;
                match result {
                    Ok((pending, name)) => {
                        s.pending_import = Some(Arc::new(pending));
                        s.import_name = name;
                        s.mode = Mode::Import;
                        s.status = "Selected vault ready for authentication";
                        s.active = Instant::now();
                    }
                    Err(error) => {
                        s.status = "Locked";
                        s.error = Some(error);
                    }
                }
                s.revision = s.revision.wrapping_add(1);
            })
            .map_err(|_| {
                let mut s = self.state();
                if s.epoch == next {
                    s.phase = Phase::Locked;
                    s.error = Some(AppError::Unavailable);
                }
                AppError::Unavailable
            })?;
        Ok(())
    }

    /// The local filename is explicitly non-secret, as in the existing vault
    /// list. No provider URI or candidate payload is returned to the renderer.
    #[cfg(any(test, feature = "desktop"))]
    pub(crate) fn import_name(&self, epoch: FormEpoch) -> String {
        let s = self.state();
        if s.epoch == epoch.0 && s.mode == Mode::Import {
            s.import_name.clone()
        } else {
            String::new()
        }
    }

    #[cfg(any(test, feature = "desktop"))]
    pub(crate) fn acknowledge_vault_import(&self, epoch: FormEpoch, accepted: bool) {
        let mut s = self.state();
        if s.epoch == epoch.0 && s.phase == Phase::Locked && s.pending_import.is_some() {
            s.import_ack = accepted;
            s.active = Instant::now();
            s.revision = s.revision.wrapping_add(1);
        }
    }

    pub(super) fn publish_import(
        &self,
        values: &[SecretBytes; INPUTS],
        token: &CancelToken,
    ) -> Result<Opened, AppError> {
        let source = {
            let s = self.state();
            if !s.import_ack || token.is_cancelled() {
                return Err(CoreError::Cancelled.into());
            }
            s.pending_import.clone().ok_or(AppError::InvalidInput)?
        };
        let name = std::str::from_utf8(values[InputField::Name.index()].expose_secret())
            .map_err(|_| AppError::VaultName)?;
        let folder = self.default_folder();
        private_dir(&folder)?;
        let path = folder.join(crate::vaults::file_name(name)?);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err(AppError::VaultExists),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AppError::Unavailable),
        }
        let core = self.core()?;
        let password =
            MasterPassword::from_utf8(values[InputField::Password.index()].expose_secret())
                .map_err(|_| AppError::InvalidInput)?;
        let verified = core.authenticate_vault_import(&source, &password, Some(token))?;
        drop(password);
        let result = core.publish_vault_import(verified, &path, Some(token));
        if matches!(
            result,
            Err(CoreError::Store(qv_core::StoreError::PublicationIncomplete))
        ) {
            self.note_import_publication(&path);
        }
        let session = result.map_err(|e| match e {
            CoreError::Store(qv_core::StoreError::Exists) => AppError::VaultExists,
            other => other.into(),
        })?;
        Ok(Opened::Session(session, path, false, None, None))
    }

    pub(super) fn note_import_publication(&self, path: &std::path::Path) {
        self.remember_vault(path);
        let mut s = self.state();
        if s.phase == Phase::Locked {
            s.error = Some(CoreError::Store(qv_core::StoreError::PublicationIncomplete).into());
            s.revision = s.revision.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::workspace_tests::{Env, KDF, PASSWORD};
    use std::io::Cursor;

    fn stage(env: &Env, bytes: Vec<u8>, name: &str) {
        let name = name.to_owned();
        env.c
            .stage_vault_input(env.epoch(), move |_| {
                Ok((Box::new(Cursor::new(bytes)), name))
            })
            .unwrap();
        env.wait();
        assert_eq!(env.c.snapshot().mode, Mode::Import);
        assert!(env.c.snapshot().import_ready);
    }

    // 0012 §1: Whole-file rollback
    #[test]
    fn vault_import_controller_requires_consent_retries_password_and_never_overwrites_source() {
        let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
        let env = Env::unlocked();
        let source = env.c.open_vault().unwrap().path;
        env.c.lock();
        let original = std::fs::read(&source).unwrap();
        let filename = source.file_name().unwrap().to_str().unwrap();
        stage(&env, original.clone(), filename);
        assert_eq!(
            env.c.submit(env.epoch(), Action::ImportVault, true),
            Err(AppError::Consent)
        );
        env.c.acknowledge_vault_import(env.epoch(), true);
        env.fill(InputField::Password, PASSWORD);
        env.c
            .submit(env.epoch(), Action::ImportVault, true)
            .unwrap();
        env.wait();
        assert_eq!(env.c.snapshot().error, Some(AppError::VaultExists));
        env.fill(InputField::Name, "Imported vault");
        env.fill(InputField::Password, "incorrect password");
        env.c
            .submit(env.epoch(), Action::ImportVault, true)
            .unwrap();
        env.wait();
        assert_eq!(
            env.c.snapshot().error,
            Some(AppError::Core(CoreError::Store(
                qv_core::StoreError::WrongPassword
            )))
        );
        assert_eq!(env.c.import_name(env.epoch()), "Imported vault");
        env.fill(InputField::Password, PASSWORD);
        env.c
            .submit(env.epoch(), Action::ImportVault, true)
            .unwrap();
        env.wait();
        assert_eq!(env.c.snapshot().error, None);
        assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
        assert_eq!(std::fs::read(&source).unwrap(), original);
        let imported = env.c.open_vault().unwrap().path;
        assert_ne!(source, imported);
        assert_eq!(
            imported,
            env.c.default_folder().join("Imported vault.qvault")
        );
        assert!(env.read(|s| s.verify(None)).ok());
        env.c.lock();
        env.fill(InputField::Password, PASSWORD);
        env.c.submit(env.epoch(), Action::Unlock, true).unwrap();
        env.wait();
        assert_eq!(env.c.snapshot().phase, Phase::Unlocked);
    }

    // 0012 §1: Webview exposure
    #[test]
    fn vault_import_controller_rejects_stale_picker_consent_and_late_results() {
        let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
        let env = Env::unlocked();
        let source = env.c.open_vault().unwrap().path;
        env.c.lock();
        let bytes = std::fs::read(&source).unwrap();
        let old = env.epoch();
        env.c.select_mode(old, Mode::Create);
        assert_eq!(
            env.c
                .stage_vault_input(old, |_| panic!("stale picker opened a document")),
            Err(AppError::InvalidInput)
        );
        env.c.select_mode(env.epoch(), Mode::Unlock);
        let (entered, received) = std::sync::mpsc::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        env.c
            .stage_vault_input(env.epoch(), move |_| {
                entered.send(()).unwrap();
                resumed.recv().unwrap();
                Ok((Box::new(Cursor::new(bytes)), "late.qvault".to_owned()))
            })
            .unwrap();
        received.recv_timeout(Duration::from_secs(10)).unwrap();
        env.c.lock();
        resume.send(()).unwrap();
        env.wait();
        let view = env.c.snapshot();
        assert_eq!(view.phase, Phase::Locked);
        assert!(!view.import_ready);
        assert!(!view.import_ack);
        assert!(!env.c.default_folder().join("late.qvault").exists());
    }

    // 0012 §1: Anchor crash windows
    #[test]
    fn vault_import_controller_retains_late_publication_without_reopening_session() {
        let _k = KDF.lock().unwrap_or_else(|p| p.into_inner());
        let env = Env::new();
        let core = env.c.core().unwrap();
        let path = env.c.default_folder().join("late-import.qvault");
        let created = core
            .create(
                &path,
                &MasterPassword::from_utf8(PASSWORD.as_bytes()).unwrap(),
                "Late import",
            )
            .unwrap();
        let epoch = env.epoch();
        let token = env.c.state().cancel.clone();
        env.c.lock();
        env.c.complete(
            epoch.0,
            &token,
            Ok(Opened::Session(
                created.session,
                path.clone(),
                false,
                None,
                None,
            )),
            true,
        );
        assert_eq!(env.c.snapshot().phase, Phase::Locked);
        assert!(env.c.state().session.is_none());
        assert!(env.c.vaults().iter().any(|v| v.path == path));
        assert_eq!(
            env.c.snapshot().error,
            Some(AppError::Core(CoreError::Store(
                qv_core::StoreError::PublicationIncomplete
            )))
        );
    }
}
