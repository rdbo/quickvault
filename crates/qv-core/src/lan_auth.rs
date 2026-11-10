// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private, one-use offering-side authorization (0013 §15.3). KDF/component
//! work runs outside the session mutex; the final check and seal share it.
use super::*;
use qv_crypto::lan::v2::{AuthMode, FinalEpoch, KeyAuthentication, RecordSealer};
use qv_crypto::lan_auth::PasswordAuthServer;
use qv_model::{Payload, RecordBody, RecordId, VersionId};
use qv_sync::lan::{CredentialApprover, SealedGrant};
use zeroize::Zeroizing;

struct Snapshot {
    vault: VaultId,
    generation: KeyGeneration,
    descriptor: Zeroizing<Vec<u8>>,
    record: RecordId,
    version: VersionId,
    object: ObjectId,
    hash: [u8; 32],
}
impl Snapshot {
    fn read(vault: &qv_store::UnlockedVault) -> Result<Self, LanError> {
        let manifest = vault.manifest();
        let record = manifest.keyslot_id();
        let entry = manifest.record(record).ok_or(LanError::Keyslot)?;
        let [head] = entry.heads() else {
            return Err(LanError::Keyslot);
        };
        let version = vault
            .read_version(record, head.version_id())
            .map_err(LanError::Store)?;
        let RecordBody::Live(Payload::PasswordKeyslot(slot)) = version.body else {
            return Err(LanError::Keyslot);
        };
        let descriptor = slot
            .encode_public_descriptor()
            .map_err(|_| LanError::Integrity)?;
        let working = vault
            .lan_working_password_descriptor()
            .map_err(LanError::Store)?;
        if descriptor.as_slice() != working.as_slice() || descriptor.len() != 171 {
            return Err(LanError::Keyslot);
        }
        let object = head.object_id();
        let reference = manifest.reference(object).ok_or(LanError::Integrity)?;
        Ok(Self {
            vault: vault.header().vault_id,
            generation: vault.header().key_generation,
            descriptor,
            record,
            version: head.version_id(),
            object,
            hash: *reference.sha256(),
        })
    }
    fn matches(&self, vault: &qv_store::UnlockedVault) -> Result<bool, LanError> {
        let now = Self::read(vault)?;
        Ok(self.vault == now.vault
            && self.generation == now.generation
            && self.record == now.record
            && self.version == now.version
            && self.object == now.object
            && self.hash == now.hash
            && self.descriptor.as_slice() == now.descriptor.as_slice())
    }
}

/// No public constructor, Clone, serialization or fields. Bound to one core
/// session, one outer transcript and the exact locally authenticated slot/head.
pub(super) struct Authorization {
    snapshot: Snapshot,
    session: SessionTag,
    t0: [u8; 32],
    expires: Option<Instant>,
}
impl CredentialApprover for SessionApprover<'_> {
    type Authorization = Authorization;
    fn authenticate_password(
        &self,
        password: MasterPassword,
        t0: &[u8; 32],
        ke1: &[u8],
    ) -> Result<(PasswordAuthServer, SecretBytes, Authorization), LanError> {
        if ke1.len() != qv_crypto::lan_auth::KE1_LEN {
            return Err(LanError::Integrity);
        }
        let snapshot = self
            .session
            .read(|ctx| {
                self.check_policy(ctx)?;
                Snapshot::read(&ctx.open.vault).map_err(CoreError::Lan)
            })
            .map_err(lan)?;
        // Only the typed password's unwrapped key leaves KDF work, never a
        // copy of the active session key. Compare under the rechecked mutex.
        let descriptor =
            qv_model::Keyslot::decode(&snapshot.descriptor).map_err(|_| LanError::Integrity)?;
        let unwrapped = descriptor
            .slot
            .unlock(&password, snapshot.vault, snapshot.generation)
            .map_err(|error| match error {
                qv_crypto::CryptoError::WrongPassword => LanError::Store(StoreError::WrongPassword),
                _ => LanError::Integrity,
            })?;
        let authorization = Authorization {
            snapshot,
            session: self.session.tag(),
            t0: *t0,
            expires: self.exchange.expires,
        };
        self.session
            .read(|ctx| {
                self.check_policy(ctx)?;
                self.check_snapshot(ctx, &authorization)?;
                if !unwrapped.ct_eq(ctx.open.vault.vault_key()) {
                    return Err(CoreError::Lan(LanError::Integrity));
                }
                Ok(())
            })
            .map_err(lan)?;
        drop(unwrapped);
        let (server, ke2) =
            PasswordAuthServer::start(&password, t0, ke1).map_err(|_| LanError::Integrity)?;
        drop(password);
        self.check_authorization(&authorization)?;
        Ok((server, ke2, authorization))
    }
    fn check_authorization(&self, authorization: &Authorization) -> Result<(), LanError> {
        self.session
            .read(|ctx| {
                self.check_policy(ctx)?;
                self.check_snapshot(ctx, authorization)
            })
            .map_err(lan)
    }
    fn key_auth(&self, mode: AuthMode, t0: [u8; 32]) -> Result<KeyAuthentication, LanError> {
        self.session
            .read(|ctx| {
                self.check_policy(ctx)?;
                KeyAuthentication::new(ctx.open.vault.vault_key(), mode, t0)
                    .map_err(crate::error::crypto)
            })
            .map_err(lan)
    }
    fn authorized_grant(
        &self,
        authorization: Authorization,
        sealer: &mut RecordSealer<FinalEpoch>,
    ) -> Result<SealedGrant, LanError> {
        // `mutate` deliberately preserves the outcome after a completed seal;
        // `read` would replace that outcome with Cancelled on a concurrent lock.
        self.session
            .mutate(|ctx| {
                self.check_policy(ctx)?;
                self.check_snapshot(ctx, &authorization)?;
                if sealer.binding() != (AuthMode::PasswordEnrollment, authorization.t0)
                    || sealer.next_sequence() != 0
                {
                    return Err(CoreError::Lan(LanError::Integrity));
                }
                let s = &authorization.snapshot;
                let plaintext = sync::credential_grant_plaintext(
                    ctx.open.vault.vault_key(),
                    s.vault,
                    s.generation,
                    &s.descriptor,
                    s.record,
                    s.version,
                    s.object,
                    &s.hash,
                )
                .map_err(CoreError::Lan)?;
                let record = sealer
                    .seal(plaintext.expose_secret())
                    .map_err(crate::error::crypto)?;
                drop(plaintext);
                #[cfg(test)]
                tests::after_seal();
                // The linearization point is the successful seal above. A later
                // cancellation cannot turn it into a claim of no key disclosure.
                if let Err(error) = self.check_policy(ctx) {
                    drop(record);
                    return Ok(SealedGrant::Discarded(lan(error)));
                }
                Ok(SealedGrant::Ready(record))
            })
            .map_err(lan)
    }
}
impl SessionApprover<'_> {
    fn check_policy(&self, ctx: &crate::session::Ctx<'_>) -> Result<(), CoreError> {
        ctx.check_cancel()?;
        if self.exchange.cancel.is_some_and(CancelToken::is_cancelled) {
            return Err(CoreError::Cancelled);
        }
        if self
            .exchange
            .expires
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(CoreError::Lan(LanError::Timeout));
        }
        if ctx.open.read_only {
            return Err(CoreError::Store(StoreError::NoAnchor));
        }
        Ok(())
    }
    fn check_snapshot(
        &self,
        ctx: &crate::session::Ctx<'_>,
        authorization: &Authorization,
    ) -> Result<(), CoreError> {
        if authorization.session != ctx.tag()
            || authorization.expires != self.exchange.expires
            || !authorization
                .snapshot
                .matches(&ctx.open.vault)
                .map_err(CoreError::Lan)?
        {
            return Err(CoreError::Lan(LanError::StateChanged));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::testutil::{Env, PASSWORD, pw};
    use qv_crypto::lan::PairingSecret;
    use qv_crypto::lan::v2::{PairingKeys, RecordOpener, Role};
    use qv_crypto::lan_auth::PasswordAuthClient;
    use std::cell::RefCell;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};

    thread_local! {static AFTER_SEAL: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);}
    pub(super) fn after_seal() {
        AFTER_SEAL.with(|slot| {
            if let Some(hook) = slot.borrow_mut().take() {
                hook();
            }
        });
    }
    fn approver<'s>(session: &'s Session, cancel: Option<&'s CancelToken>) -> SessionApprover<'s> {
        SessionApprover {
            session,
            exchange: SessionExchange::new(
                session,
                cancel,
                Some(Instant::now() + Duration::from_secs(600)),
            )
            .unwrap(),
        }
    }
    fn authenticated(
        a: &SessionApprover<'_>,
    ) -> (
        Authorization,
        RecordSealer<FinalEpoch>,
        RecordOpener<FinalEpoch>,
    ) {
        let t0 = [47; 32];
        let password = pw(PASSWORD);
        let (client, ke1) = PasswordAuthClient::start(&password, &t0).unwrap();
        let (server, ke2, authorization) = a
            .authenticate_password(pw(PASSWORD), &t0, ke1.expose_secret())
            .unwrap();
        let (ke3, b_auth) = client.finish(&password, ke2.expose_secret()).unwrap();
        drop(password);
        let a_auth = server.finish(ke3.expose_secret()).unwrap();
        let (dk, ek) = qv_crypto::XWingDecapsKey::generate().unwrap();
        let (ss, ct) = ek.encapsulate().unwrap();
        let other = dk.decapsulate(&ct).unwrap();
        let ta = [48; 32];
        let (a_schedule, a_initial) =
            PairingKeys::new(PairingSecret::from_bytes(&[49; 16]).unwrap())
                .unwrap()
                .begin(ss, AuthMode::PasswordEnrollment, t0)
                .unwrap();
        let (b_schedule, b_initial) =
            PairingKeys::new(PairingSecret::from_bytes(&[49; 16]).unwrap())
                .unwrap()
                .begin(other, AuthMode::PasswordEnrollment, t0)
                .unwrap();
        drop((a_initial, b_initial));
        let (a_keys, a_finished) = a_schedule.complete(a_auth, ta).unwrap();
        let (b_keys, b_finished) = b_schedule.complete(b_auth, ta).unwrap();
        drop((a_finished, b_finished));
        let (sealer, opener) = a_keys.split(Role::Offerer);
        let (other_sealer, other_opener) = b_keys.split(Role::Joiner);
        drop((opener, other_sealer));
        (authorization, sealer, other_opener)
    }

    // 0012 §1: LAN partial acceptance
    #[test]
    fn lan_grant_password_change_before_sealing_invalidates_exact_authorization() {
        let env = Env::new();
        let session = env.unlock();
        let a = approver(&session, None);
        let (authorization, mut sealer, _) = authenticated(&a);
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                session
                    .change_password(&pw("changed before grant authorization"), None)
                    .unwrap();
                barrier.wait();
            });
            barrier.wait();
            assert_eq!(
                a.authorized_grant(authorization, &mut sealer).err(),
                Some(LanError::StateChanged)
            );
        });
        assert_eq!(sealer.next_sequence(), 0);
    }

    // 0012 §1: LAN partial acceptance
    #[test]
    fn lan_grant_sealing_before_password_change_reports_disclosure_and_keeps_original_frame() {
        let env = Env::new();
        let session = env.unlock();
        let a = approver(&session, None);
        let (authorization, mut sealer, mut receiver) = authenticated(&a);
        let barrier = Arc::new(Barrier::new(2));
        let attempting = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            let b = barrier.clone();
            let pending = attempting.clone();
            scope.spawn(|| {
                barrier.wait();
                attempting.store(true, Ordering::SeqCst);
                session
                    .change_password(&pw("changed after the grant was sealed"), None)
                    .unwrap();
            });
            AFTER_SEAL.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    b.wait();
                    while !pending.load(Ordering::SeqCst) {
                        std::thread::yield_now();
                    }
                }))
            });
            let sealed = a.authorized_grant(authorization, &mut sealer).unwrap();
            let SealedGrant::Ready(record) = sealed else {
                panic!("must report a completed seal")
            };
            assert!(receiver.open(&record).is_ok());
        });
        assert_eq!(sealer.next_sequence(), 1);
        assert!(
            session
                .recovery_phrase(&pw("changed after the grant was sealed"))
                .is_ok()
        );
    }

    // 0012 §1: LAN partial acceptance
    #[test]
    fn lan_grant_cancel_or_lock_after_sealing_discards_output_but_preserves_disclosure_outcome() {
        for locking in [false, true] {
            let env = Env::new();
            let session = env.unlock();
            let token = CancelToken::new();
            let a = approver(&session, Some(&token));
            let (authorization, mut sealer, _) = authenticated(&a);
            let cancel = token.clone();
            let flag = session.locking.clone();
            AFTER_SEAL.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    if locking {
                        flag.store(true, Ordering::SeqCst);
                    } else {
                        cancel.cancel();
                    }
                }))
            });
            let sealed = a.authorized_grant(authorization, &mut sealer).unwrap();
            assert!(matches!(
                sealed,
                SealedGrant::Discarded(LanError::Cancelled)
            ));
            assert_eq!(sealer.next_sequence(), 1);
            session.lock();
        }
    }

    // 0012 §1: LAN discovery mistaken for trust
    #[test]
    fn lan_grant_local_wrong_password_or_preexisting_cancel_produces_no_server_response() {
        let env = Env::new();
        let session = env.unlock();
        let token = CancelToken::new();
        let a = approver(&session, Some(&token));
        let (client, ke1) = PasswordAuthClient::start(&pw(PASSWORD), &[47; 32]).unwrap();
        drop(client);
        assert_eq!(
            a.authenticate_password(pw("wrong local password"), &[47; 32], ke1.expose_secret())
                .err(),
            Some(LanError::Store(StoreError::WrongPassword))
        );
        token.cancel();
        assert_eq!(
            a.authenticate_password(pw(PASSWORD), &[47; 32], ke1.expose_secret())
                .err(),
            Some(LanError::Cancelled)
        );
    }
}
