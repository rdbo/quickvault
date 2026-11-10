// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-suite engine adapters reviewed at 0047 step2; private to qv-crypto.
//! The public one-shot wrapper centralizes RNG-error rejection and key cleanup.
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct Suite;
impl opaque_ke::CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_opaque::Sha512>;
    type Ksf = Stretch;
}

#[derive(Default)]
pub(crate) struct Stretch;
impl opaque_ke::ksf::Ksf for Stretch {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        #[cfg(any(test, feature = "test-kdf-limit"))]
        let _kdf = crate::password::kdf_test_guard();
        use argon2_opaque::{Algorithm, Argon2, Block, Params, Version};
        use opaque_ke::errors::InternalError;
        let input = Zeroizing::new(input);
        if input.len() != 64 {
            return Err(InternalError::KsfError);
        }
        let params = Params::new(262_144, 3, 4, Some(64)).map_err(|_| InternalError::KsfError)?;
        // Dependency-owned block representation cannot use SecretBytes without
        // an unsafe cast. Like the existing password KDF, this 256 MiB scratch
        // is wiped but not memory-locked; the guard also covers error/unwind.
        let mut scratch = Zeroizing::new(vec![Block::new(); params.block_count()]);
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let output = crate::SecretArray::<64>::try_init(|out| {
            argon
                .hash_password_into_with_memory(&input, &[0; 16], out, &mut scratch)
                .map_err(|_| InternalError::KsfError)
        })?;
        // The trait transfers this output into the engine's private scratch.
        // The application-owned input, output and blocks wipe on this return.
        Ok(GenericArray::clone_from_slice(output.expose_secret()))
    }
}

/// Bridges an infallible dependency API to fallible OS randomness. After an
/// error, ff bytes are termination poison, never accepted randomness: every
/// caller must discard its entire result if `failed` is set. For this fixed
/// suite, ff reduces to a nonzero scalar, so zero-retry loops terminate. No
/// generator is seeded and no output/key may escape a poisoned operation.
pub(crate) struct CheckedRng<F> {
    source: F,
    failed: bool,
}
impl<F: FnMut(&mut [u8]) -> Result<(), crate::RngError>> CheckedRng<F> {
    pub(crate) fn new(source: F) -> Self {
        Self {
            source,
            failed: false,
        }
    }
    pub(crate) fn failed(&self) -> bool {
        self.failed
    }
}
impl<F: FnMut(&mut [u8]) -> Result<(), crate::RngError>> RngCore for CheckedRng<F> {
    fn next_u32(&mut self) -> u32 {
        let mut b = Zeroizing::new([0; 4]);
        self.fill_bytes(&mut *b);
        u32::from_le_bytes(*b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = Zeroizing::new([0; 8]);
        self.fill_bytes(&mut *b);
        u64::from_le_bytes(*b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !self.failed && (self.source)(dest).is_ok() {
            return;
        }
        self.failed = true;
        dest.zeroize();
        dest.fill(0xff);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), opaque_ke::rand::Error> {
        self.fill_bytes(dest);
        if self.failed {
            Err(opaque_ke::rand::Error::from(core::num::NonZeroU32::MIN))
        } else {
            Ok(())
        }
    }
}
impl<F: FnMut(&mut [u8]) -> Result<(), crate::RngError>> CryptoRng for CheckedRng<F> {}

#[cfg(test)]
mod tests {
    // Synthetic engine fixtures; unexpected component failures fail the test.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, Identifiers, ServerLogin, ServerLoginParameters,
        ServerRegistration, ServerSetup,
    };

    const CREDENTIAL: &[u8] = b"qv/lan-credential/v2";
    fn identities() -> Identifiers<'static> {
        Identifiers {
            client: Some(b"qv/lan-joiner/v2"),
            server: Some(b"qv/lan-offerer/v2"),
        }
    }

    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn engine_rng_failure_poison_terminates_selected_scalar_paths_and_is_latched() {
        use opaque_ke::key_exchange::group::Group;
        let mut calls = 0;
        let mut rng = CheckedRng::new(|out: &mut [u8]| {
            calls += 1;
            out.fill(0); // Partial failed source, not an accepted zero seed.
            Err(crate::rng::test_error())
        });
        let sk = opaque_ke::Ristretto255::random_sk(&mut rng);
        let mut encoded = opaque_ke::Ristretto255::serialize_sk(&sk);
        assert!(encoded.iter().any(|&v| v != 0));
        encoded.zeroize();
        // The other selected scalar path derives from a 32-byte seed.
        let seed = GenericArray::clone_from_slice(&[0xff; 32]);
        assert!(opaque_ke::Ristretto255::derive_scalar(seed).is_ok());
        let result = ClientLogin::<Suite>::start(&mut rng, b"synthetic password");
        assert!(result.is_ok()); // The engine cannot report this OS failure itself.
        assert!(rng.failed()); // The wrapper must reject and drop that whole result.
        drop(result);
        let setup = ServerSetup::<Suite>::new(&mut rng);
        assert!(rng.failed());
        drop(setup);
        assert_eq!(calls, 1); // No subsequent OS calls or weaker RNG fallback.
    }

    // 0012 §1: Unpinned crypto
    #[test]
    fn engine_stretch_profile_round_trip_context_binding_and_failure_injection() {
        // Memory-accounting tests take the exclusive guard. Actual KDF calls
        // also share password::kdf_test_guard across both Argon2 families.
        let _guard = crate::memory::secrets_test_guard();
        let mut rng = CheckedRng::new(crate::fill_random);
        let password = b"synthetic engine password";
        let setup = ServerSetup::<Suite>::new(&mut rng);
        assert!(!rng.failed());
        let registration = ClientRegistration::<Suite>::start(&mut rng, password).unwrap();
        assert!(!rng.failed());
        let response =
            ServerRegistration::<Suite>::start(&setup, registration.message, CREDENTIAL).unwrap();
        let mut finished = registration
            .state
            .finish(
                &mut rng,
                password,
                response.message,
                ClientRegistrationFinishParameters::new(identities(), Some(&Stretch)),
            )
            .unwrap();
        assert!(!rng.failed());
        finished.export_key.zeroize();
        let file = ServerRegistration::<Suite>::finish(finished.message);
        let context = b"synthetic canonical context checked by the wrapper";
        let parameters = || ServerLoginParameters {
            context: Some(context),
            identifiers: identities(),
        };
        let login = ClientLogin::<Suite>::start(&mut rng, password).unwrap();
        assert!(!rng.failed());
        let response = ServerLogin::<Suite>::start(
            &mut rng,
            &setup,
            Some(file.clone()),
            login.message.clone(),
            CREDENTIAL,
            parameters(),
        )
        .unwrap();
        assert!(!rng.failed());
        let mut finished = login
            .state
            .finish(
                &mut rng,
                password,
                response.message,
                ClientLoginFinishParameters::new(Some(context), identities(), Some(&Stretch)),
            )
            .unwrap();
        assert!(!rng.failed());
        let mut server = response
            .state
            .finish(finished.message, parameters())
            .unwrap();
        assert_eq!(finished.session_key.len(), 64);
        assert_eq!(finished.session_key, server.session_key);
        finished.session_key.zeroize();
        finished.export_key.zeroize();
        server.session_key.zeroize();

        // Inject a partial OS failure at every draw made by KE2 construction.
        let mut draws = 0;
        let mut count_rng = CheckedRng::new(|out: &mut [u8]| {
            draws += 1;
            crate::fill_random(out)
        });
        let sample = ServerLogin::<Suite>::start(
            &mut count_rng,
            &setup,
            Some(file.clone()),
            login.message.clone(),
            CREDENTIAL,
            parameters(),
        )
        .unwrap();
        assert!(!count_rng.failed());
        drop(sample);
        for fail_at in 1..=draws {
            let mut draw = 0;
            let mut failed = CheckedRng::new(|out: &mut [u8]| {
                draw += 1;
                if draw == fail_at {
                    out.fill(0);
                    Err(crate::rng::test_error())
                } else {
                    crate::fill_random(out)
                }
            });
            let result = ServerLogin::<Suite>::start(
                &mut failed,
                &setup,
                Some(file.clone()),
                login.message.clone(),
                CREDENTIAL,
                parameters(),
            );
            assert!(failed.failed());
            drop(result); // No message or engine state escapes the poisoned operation.
        }
        let request = ClientLogin::<Suite>::start(&mut rng, password).unwrap();
        let response = ServerLogin::<Suite>::start(
            &mut rng,
            &setup,
            Some(file),
            request.message,
            CREDENTIAL,
            parameters(),
        )
        .unwrap();
        let result = request.state.finish(
            &mut rng,
            password,
            response.message,
            ClientLoginFinishParameters::new(
                Some(b"substituted context"),
                identities(),
                Some(&Stretch),
            ),
        );
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod component_vectors {
    // Fixed published component fixtures; no product credentials or RNG.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use opaque_ke::{
        CipherSuite, ClientLogin, ClientLoginFinishParameters, CredentialFinalization,
        CredentialResponse, Identifiers, ServerLogin, ServerLoginParameters,
    };

    // 0012 §1: Unpinned crypto
    #[test]
    fn pinned_engine_authentication_matches_published_ristretto_component_vector() {
        let _guard = crate::memory::secrets_test_guard();
        // Test-only suite for the producer's fixture; production Suite always
        // uses the reviewed explicit Argon2 Stretch, never this Identity KSF.
        struct Component;
        impl CipherSuite for Component {
            type OprfCs = opaque_ke::Ristretto255;
            type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_opaque::Sha512>;
            type Ksf = opaque_ke::ksf::Identity;
        }
        let records = crate::kat::parse(include_str!(
            "../tests/vectors/opaque-ke-4.0.1-ristretto-component.txt"
        ));
        let r = &records[0];
        let identities = || Identifiers {
            client: Some(r.get("id_u")),
            server: Some(r.get("id_s")),
        };
        let mut rng = CheckedRng::new(|_: &mut [u8]| Err(crate::rng::test_error()));
        let state = ClientLogin::<Component>::deserialize(r.get("client_login_state")).unwrap();
        let response =
            CredentialResponse::<Component>::deserialize(r.get("credential_response")).unwrap();
        let result = state
            .finish(
                &mut rng,
                r.get("password"),
                response,
                ClientLoginFinishParameters::new(
                    Some(r.get("context")),
                    identities(),
                    Some(&opaque_ke::ksf::Identity),
                ),
            )
            .unwrap();
        let session = Zeroizing::new(result.session_key);
        let export = Zeroizing::new(result.export_key);
        assert!(!rng.failed()); // Fixed TripleDh KE3 needs no fresh entropy.
        let finalization = Zeroizing::new(result.message.serialize());
        assert_eq!(finalization.as_slice(), r.get("credential_finalization"));
        assert_eq!(session.as_slice(), r.get("session_key"));
        assert_eq!(export.as_slice(), r.get("export_key"));
        let state = ServerLogin::<Component>::deserialize(r.get("server_login_state")).unwrap();
        let message = CredentialFinalization::<Component>::deserialize(&finalization).unwrap();
        let result = state
            .finish(
                message,
                ServerLoginParameters {
                    context: Some(r.get("context")),
                    identifiers: identities(),
                },
            )
            .unwrap();
        let server = Zeroizing::new(result.session_key);
        assert_eq!(server.as_slice(), r.get("session_key"));
    }
}
