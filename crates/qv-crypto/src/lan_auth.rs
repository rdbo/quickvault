// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-shot ephemeral password authentication (0013 §15.3).
//! Local setup and registration never cross this module or reach persistence.
//! This component does not authorize a grant: core must separately recheck the
//! verified local password/slot snapshot and session policy before sealing it.
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup,
};
use zeroize::Zeroizing;

use crate::lan_auth_engine::{CheckedRng, Stretch, Suite};
use crate::{CryptoError, MasterPassword, SecretArray, SecretBytes};

/// Exact fixed-suite KE1 length.
pub const KE1_LEN: usize = 96;
/// Exact fixed-suite KE2 length.
pub const KE2_LEN: usize = 320;
/// Exact fixed-suite KE3 length.
pub const KE3_LEN: usize = 64;
const CREDENTIAL: &[u8] = b"qv/lan-credential/v2";

fn identifiers() -> Identifiers<'static> {
    Identifiers {
        client: Some(b"qv/lan-joiner/v2"),
        server: Some(b"qv/lan-offerer/v2"),
    }
}
fn context(t0: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    qv_encoding::encode_array(|a| {
        a.text("qv/lan-pake-context/v2");
        a.array(|j| {
            j.uint(2);
            j.uint(1);
            j.uint(0);
            j.uint(0);
            Ok(())
        })?;
        a.bytes(t0);
        Ok(())
    })
    .map_err(|_| CryptoError::Internal)
}

fn protect<L: ArrayLength<u8>>(bytes: GenericArray<u8, L>) -> SecretBytes {
    let mut bytes = Zeroizing::new(bytes);
    SecretBytes::take_from(bytes.as_mut_slice())
}
#[cfg(test)]
std::thread_local! {
    // Fault injection belongs to this operation's test thread; unrelated
    // concurrent authentication attempts must never consume its draw counter.
    static FAIL_DRAW: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DRAW_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn fill_auth_random(out: &mut [u8]) -> Result<(), crate::RngError> {
    #[cfg(test)]
    {
        let draw = DRAW_COUNT.get() + 1;
        DRAW_COUNT.set(draw);
        if draw == FAIL_DRAW.get() {
            out.fill(0x55); // Simulate a partial OS fill before failure.
            return Err(crate::rng::test_error());
        }
    }
    crate::fill_random(out)
}
fn engine_operation<T>(
    operation: impl FnOnce(
        &mut CheckedRng<fn(&mut [u8]) -> Result<(), crate::RngError>>,
    ) -> Result<T, CryptoError>,
) -> Result<T, CryptoError> {
    let mut rng = CheckedRng::new(fill_auth_random as fn(&mut [u8]) -> Result<(), crate::RngError>);
    let result = operation(&mut rng);
    // T at each call site owns only protected, zeroizing application state.
    // This guard is also mandatory when the infallible component returned Ok.
    if rng.failed() {
        drop(result);
        Err(CryptoError::Rng)
    } else {
        result
    }
}
fn healthy<F: FnMut(&mut [u8]) -> Result<(), crate::RngError>>(
    rng: &CheckedRng<F>,
) -> Result<(), CryptoError> {
    if rng.failed() {
        Err(CryptoError::Rng)
    } else {
        Ok(())
    }
}

/// Credential-authentication output. Only the final schedule inside this crate
/// can read it; there is no raw-key or serialization API for frontends.
pub struct AuthSecret {
    pub(crate) key: SecretArray<64>,
    pub(crate) mode: crate::lan::v2::AuthMode,
    pub(crate) t0: [u8; 32],
}
impl core::fmt::Debug for AuthSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthSecret(<redacted>)")
    }
}

/// One client attempt; finishing consumes its protected inter-flight state.
pub struct PasswordAuthClient {
    state: SecretBytes,
    t0: [u8; 32],
}
impl core::fmt::Debug for PasswordAuthClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PasswordAuthClient(<redacted>)")
    }
}
impl PasswordAuthClient {
    /// Start a fresh attempt with an NFC-normalized password and exact outer transcript.
    pub fn start(
        password: &MasterPassword,
        t0: &[u8; 32],
    ) -> Result<(Self, SecretBytes), CryptoError> {
        engine_operation(|rng| {
            let started = ClientLogin::<Suite>::start(rng, password.expose_secret().as_bytes())
                .map_err(|_| CryptoError::Internal)?;
            healthy(rng)?;
            let message = protect(started.message.serialize());
            if message.expose_secret().len() != KE1_LEN {
                return Err(CryptoError::Internal);
            }
            Ok((
                Self {
                    state: protect(started.state.serialize()),
                    t0: *t0,
                },
                message,
            ))
        })
    }

    /// Authenticate the server response and produce KE3 plus the engine session
    /// secret. A wrong credential/context/response yields no finalization output.
    pub fn finish(
        self,
        password: &MasterPassword,
        ke2: &[u8],
    ) -> Result<(SecretBytes, AuthSecret), CryptoError> {
        if ke2.len() != KE2_LEN {
            return Err(CryptoError::Integrity);
        }
        let response =
            CredentialResponse::<Suite>::deserialize(ke2).map_err(|_| CryptoError::Integrity)?;
        let state = ClientLogin::<Suite>::deserialize(self.state.expose_secret())
            .map_err(|_| CryptoError::Internal)?;
        let context = context(&self.t0)?;
        engine_operation(|rng| {
            let finished = state
                .finish(
                    rng,
                    password.expose_secret().as_bytes(),
                    response,
                    ClientLoginFinishParameters::new(Some(&context), identifiers(), Some(&Stretch)),
                )
                .map_err(|_| CryptoError::Integrity)?;
            // The component returns plain arrays: guard every handed-back key
            // immediately, even if the RNG was poisoned or a later check fails.
            let session = Zeroizing::new(finished.session_key);
            let _export = Zeroizing::new(finished.export_key);
            healthy(rng)?;
            let message = protect(finished.message.serialize());
            if message.expose_secret().len() != KE3_LEN {
                return Err(CryptoError::Internal);
            }
            let secret = SecretArray::try_init(|out| {
                out.copy_from_slice(&session);
                Ok::<_, CryptoError>(())
            })?;
            Ok((
                message,
                AuthSecret {
                    key: secret,
                    mode: crate::lan::v2::AuthMode::PasswordEnrollment,
                    t0: self.t0,
                },
            ))
        })
    }
}

/// One offering-device attempt, made only from its locally verified password.
/// Registration and setup are already gone when this value is returned.
pub struct PasswordAuthServer {
    state: SecretBytes,
    t0: [u8; 32],
}
impl core::fmt::Debug for PasswordAuthServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PasswordAuthServer(<redacted>)")
    }
}
impl PasswordAuthServer {
    /// Fresh local registration followed by KE2. Never accepts peer registration.
    /// Call outside the session mutex: the explicit KDF uses256 MiB scratch.
    pub fn start(
        password: &MasterPassword,
        t0: &[u8; 32],
        ke1: &[u8],
    ) -> Result<(Self, SecretBytes), CryptoError> {
        if ke1.len() != KE1_LEN {
            return Err(CryptoError::Integrity);
        }
        let request =
            CredentialRequest::<Suite>::deserialize(ke1).map_err(|_| CryptoError::Integrity)?;
        let context = context(t0)?;
        engine_operation(|rng| {
            let setup = ServerSetup::<Suite>::new(rng);
            healthy(rng)?;
            let registration =
                ClientRegistration::<Suite>::start(rng, password.expose_secret().as_bytes())
                    .map_err(|_| CryptoError::Internal)?;
            healthy(rng)?;
            let response =
                ServerRegistration::<Suite>::start(&setup, registration.message, CREDENTIAL)
                    .map_err(|_| CryptoError::Internal)?;
            let finished = registration
                .state
                .finish(
                    rng,
                    password.expose_secret().as_bytes(),
                    response.message,
                    ClientRegistrationFinishParameters::new(identifiers(), Some(&Stretch)),
                )
                .map_err(|_| CryptoError::Internal)?;
            let _export = Zeroizing::new(finished.export_key);
            healthy(rng)?;
            let file = ServerRegistration::<Suite>::finish(finished.message);
            let started = ServerLogin::<Suite>::start(
                rng,
                &setup,
                Some(file),
                request,
                CREDENTIAL,
                ServerLoginParameters {
                    context: Some(&context),
                    identifiers: identifiers(),
                },
            )
            .map_err(|_| CryptoError::Integrity)?;
            healthy(rng)?;
            let message = protect(started.message.serialize());
            if message.expose_secret().len() != KE2_LEN {
                return Err(CryptoError::Internal);
            }
            Ok((
                Self {
                    state: protect(started.state.serialize()),
                    t0: *t0,
                },
                message,
            ))
        })
    }

    /// Verify the one KE3; no output survives a wrong/cross-session proof.
    pub fn finish(self, ke3: &[u8]) -> Result<AuthSecret, CryptoError> {
        if ke3.len() != KE3_LEN {
            return Err(CryptoError::Integrity);
        }
        let message = CredentialFinalization::<Suite>::deserialize(ke3)
            .map_err(|_| CryptoError::Integrity)?;
        let state = ServerLogin::<Suite>::deserialize(self.state.expose_secret())
            .map_err(|_| CryptoError::Internal)?;
        let context = context(&self.t0)?;
        let finished = state
            .finish(
                message,
                ServerLoginParameters {
                    context: Some(&context),
                    identifiers: identifiers(),
                },
            )
            .map_err(|_| CryptoError::Integrity)?;
        let session = Zeroizing::new(finished.session_key);
        let secret = SecretArray::try_init(|out| {
            out.copy_from_slice(&session);
            Ok::<_, CryptoError>(())
        })?;
        Ok(AuthSecret {
            key: secret,
            mode: crate::lan::v2::AuthMode::PasswordEnrollment,
            t0: self.t0,
        })
    }
}

#[cfg(test)]
mod tests {
    // Synthetic fixtures; component/setup errors fail these tests loudly.
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn password() -> MasterPassword {
        MasterPassword::from_utf8(b"synthetic authentication password").unwrap()
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn password_auth_discards_every_poisoned_client_and_server_operation() {
        let _guard = crate::memory::secrets_test_guard();
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                FAIL_DRAW.set(0);
                DRAW_COUNT.set(0);
            }
        }
        let _reset = Reset;
        let password = password();
        let t0 = [13; 32];
        DRAW_COUNT.set(0);
        let (_, ke1) = PasswordAuthClient::start(&password, &t0).unwrap();
        let client_draws = DRAW_COUNT.get();
        DRAW_COUNT.set(0);
        drop(PasswordAuthServer::start(&password, &t0, ke1.expose_secret()).unwrap());
        let server_draws = DRAW_COUNT.get();
        assert!(client_draws > 0 && server_draws > 0);
        for failed_draw in 1..=client_draws {
            DRAW_COUNT.set(0);
            FAIL_DRAW.set(failed_draw);
            assert_eq!(
                (
                    PasswordAuthClient::start(&password, &t0).err(),
                    DRAW_COUNT.get()
                ),
                (Some(CryptoError::Rng), failed_draw)
            );
            assert_eq!(DRAW_COUNT.get(), failed_draw);
        }
        for failed_draw in 1..=server_draws {
            DRAW_COUNT.set(0);
            FAIL_DRAW.set(failed_draw);
            assert_eq!(
                (
                    PasswordAuthServer::start(&password, &t0, ke1.expose_secret()).err(),
                    DRAW_COUNT.get()
                ),
                (Some(CryptoError::Rng), failed_draw)
            );
            assert_eq!(DRAW_COUNT.get(), failed_draw);
        }
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn password_auth_one_shot_round_trip_and_fresh_local_registrations() {
        let _guard = crate::memory::secrets_test_guard();
        let password = password();
        let t0 = [7; 32];
        let (client, ke1) = PasswordAuthClient::start(&password, &t0).unwrap();
        let (server, ke2) = PasswordAuthServer::start(&password, &t0, ke1.expose_secret()).unwrap();
        let (other, other_ke2) =
            PasswordAuthServer::start(&password, &t0, ke1.expose_secret()).unwrap();
        assert_eq!(ke1.expose_secret().len(), KE1_LEN);
        assert_eq!(ke2.expose_secret().len(), KE2_LEN);
        assert_ne!(ke2.expose_secret(), other_ke2.expose_secret());
        let (ke3, client_secret) = client.finish(&password, ke2.expose_secret()).unwrap();
        assert_eq!(ke3.expose_secret().len(), KE3_LEN);
        assert!(other.finish(ke3.expose_secret()).is_err());
        let server_secret = server.finish(ke3.expose_secret()).unwrap();
        assert!(client_secret.key.ct_eq(server_secret.key.expose_secret()));
        assert_eq!(format!("{client_secret:?}"), "AuthSecret(<redacted>)");
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn password_auth_rejects_wrong_password_context_lengths_and_modified_responses() {
        let _guard = crate::memory::secrets_test_guard();
        let password = password();
        let wrong = MasterPassword::from_utf8(b"wrong synthetic password").unwrap();
        for scenario in 0..3 {
            let client_password = if scenario == 0 { &wrong } else { &password };
            let (client, ke1) = PasswordAuthClient::start(client_password, &[1; 32]).unwrap();
            let server_t0 = if scenario == 1 { [2; 32] } else { [1; 32] };
            let (_, mut ke2) =
                PasswordAuthServer::start(&password, &server_t0, ke1.expose_secret()).unwrap();
            if scenario == 2 {
                ke2.expose_secret_mut()[319] ^= 1;
            }
            assert!(client.finish(client_password, ke2.expose_secret()).is_err());
        }
        for length in [0, 95, 97, 4097] {
            assert!(PasswordAuthServer::start(&password, &[1; 32], &vec![0; length]).is_err());
        }
        let (client, _) = PasswordAuthClient::start(&password, &[1; 32]).unwrap();
        assert!(client.finish(&password, &[0; KE2_LEN - 1]).is_err());
    }
}
