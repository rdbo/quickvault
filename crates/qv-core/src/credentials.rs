// SPDX-License-Identifier: AGPL-3.0-or-later

//! Password replacement and reauthenticated recovery-phrase redisplay.
use qv_crypto::{MasterPassword, PasswordKdfProfile, PasswordWrapProfile, RecoveryPhrase};
use qv_model::{Payload, RecordBody, RecordKind};

use crate::edit::{Change, commit_with};
use crate::views::{decrypt, record};
use crate::{CancelToken, CoreError, Session};

impl Session {
    /// Replaces the complete password slot and its encrypted causal record
    /// atomically. The vault key, generation and application objects stay the
    /// same. A copied old slot still enables access to this generation.
    /// Passing the same password exercises the current KDF-only rewrap path.
    pub fn change_password(
        &self,
        password: &MasterPassword,
        cancel: Option<&CancelToken>,
    ) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            ctx.check_cancel()?;
            if cancel.is_some_and(CancelToken::is_cancelled) {
                return Err(CoreError::Cancelled);
            }
            let id = ctx.open.vault.manifest().keyslot_id();
            let base = record(&ctx.open.index, id, RecordKind::PasswordKeyslot)?.single_head()?;
            let version = decrypt(ctx, id, base)?;
            commit_with(
                ctx,
                |write| {
                    let slot = write.stage_password(
                        password,
                        PasswordKdfProfile::V1,
                        PasswordWrapProfile::V1,
                    )?;
                    Ok(vec![Change {
                        record: id,
                        kind: RecordKind::PasswordKeyslot,
                        body: RecordBody::Live(Payload::PasswordKeyslot(slot)),
                        ext: version.ext,
                    }])
                },
                &|| cancel.is_some_and(CancelToken::is_cancelled),
            )
        })
    }

    /// Reauthenticates the current master password before returning a protected
    /// phrase. A concurrent lock discards the result, as for other secret reads.
    pub fn recovery_phrase(&self, password: &MasterPassword) -> Result<RecoveryPhrase, CoreError> {
        self.read(|ctx| {
            ctx.check_cancel()?;
            Ok(ctx.open.vault.recovery_phrase(password)?)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Env, PASSWORD, err, kdf, pw};
    const NEW: &str = "a new master password for credential transaction tests";

    #[test]
    fn credentials_password_change_and_phrase_recovery_round_trip() {
        let env = Env::new();
        let core = env.core();
        let s = env.unlock();
        let phrase = {
            let _k = kdf();
            s.recovery_phrase(&pw(PASSWORD)).unwrap()
        };
        let root = s.root().unwrap();
        s.save_entry(s.new_entry(root, "login", "preserved entry").unwrap())
            .unwrap();
        {
            let _k = kdf();
            s.change_password(&pw(NEW), None).unwrap();
        }
        assert_eq!(s.search("preserved entry").unwrap().len(), 1);
        assert!(s.verify(None).unwrap().ok());
        {
            let _k = kdf();
            assert_eq!(
                err(s.recovery_phrase(&pw(PASSWORD))),
                CoreError::Store(qv_store::StoreError::WrongPassword)
            );
            assert_eq!(
                s.recovery_phrase(&pw(NEW)).unwrap().expose_secret(),
                phrase.expose_secret()
            );
        }
        s.lock();
        {
            let _k = kdf();
            assert_eq!(
                err(core.unlock(&env.path, &pw(PASSWORD), None)),
                CoreError::Store(qv_store::StoreError::WrongPassword)
            );
        }
        let (s, status) = core
            .unlock_with_phrase(&env.path, phrase.expose_secret().as_bytes(), None)
            .unwrap();
        assert_eq!(status, qv_store::AnchorStatus::Verified);
        {
            let _k = kdf();
            s.change_password(&pw(PASSWORD), None).unwrap();
        }
        s.lock();
        assert_eq!(env.unlock().search("preserved entry").unwrap().len(), 1);
    }

    #[test]
    fn credentials_missing_anchor_requires_explicit_recovery_baseline() {
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let phrase = {
            let _k = kdf();
            s.recovery_phrase(&pw(PASSWORD)).unwrap()
        };
        s.lock();
        for e in std::fs::read_dir(&env.anchors).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
        let core = env.core_with(Some(env.snapshot_policy()));
        let (s, status) = core
            .unlock_with_phrase(&env.path, phrase.expose_secret().as_bytes(), None)
            .unwrap();
        assert_eq!(status, qv_store::AnchorStatus::Missing);
        assert!(s.is_read_only().unwrap());
        let before = std::fs::read(&env.path).unwrap();
        assert_eq!(
            err(s.change_password(&pw(NEW), None)),
            CoreError::Store(qv_store::StoreError::NoAnchor)
        );
        assert_eq!(std::fs::read(&env.path).unwrap(), before);
        let snapshot = s.begin_destructive(false, None).unwrap();
        s.adopt_baseline().unwrap();
        {
            let _k = kdf();
            s.change_password(&pw(NEW), None).unwrap();
        }
        s.finish_destructive(snapshot).unwrap();
        s.lock();
        let _k = kdf();
        assert!(core.unlock(&env.path, &pw(NEW), None).is_ok());
    }

    #[test]
    fn credentials_cancelled_and_locked_calls_change_nothing() {
        let env = Env::new();
        let s = env.unlock();
        let before = std::fs::read(&env.path).unwrap();
        let cancel = CancelToken::new();
        cancel.cancel();
        assert_eq!(
            s.change_password(&pw(NEW), Some(&cancel)),
            Err(CoreError::Cancelled)
        );
        assert_eq!(std::fs::read(&env.path).unwrap(), before);
        s.lock();
        assert_eq!(
            s.change_password(&pw(NEW), None),
            Err(CoreError::SessionLocked)
        );
        assert_eq!(
            err(s.recovery_phrase(&pw(PASSWORD))),
            CoreError::SessionLocked
        );
    }
}
