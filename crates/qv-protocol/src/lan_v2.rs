// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact bounded credential-authentication messages (0013 §15).
//! Secret fields borrow protected record plaintext. No key state or primitive
//! lives here; the driver authenticates records and enforces state order.
use super::{CT_LEN, EK_LEN, exact, generation};
use crate::{
    ProtocolError,
    frame::HANDSHAKE_FRAME_MAX,
    message::{Label, MessageReader, write_message},
    registry::{ErrorCode, LanProfile},
};
use qv_encoding::{EncodeError, Encoder, RawValue};
use zeroize::Zeroizing;

/// Credential, Finished and grant plaintexts have the same small bound.
pub const CREDENTIAL_MAX: usize = 4096;
/// Fixed known public slot projection length under the supported profiles.
pub const DESCRIPTOR_LEN: usize = 171;
/// The only accepted method/intent combinations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    /// Method0, intent0.
    PasswordEnrollment,
    /// Method1, intent0.
    KeyEnrollment,
    /// Method1, intent1.
    KeySync,
}
impl AuthMode {
    /// The wire authentication method.
    pub const fn method(self) -> u64 {
        match self {
            Self::PasswordEnrollment => 0,
            Self::KeyEnrollment | Self::KeySync => 1,
        }
    }
    /// The wire operation intent.
    pub const fn intent(self) -> u64 {
        match self {
            Self::PasswordEnrollment | Self::KeyEnrollment => 0,
            Self::KeySync => 1,
        }
    }
    /// Reject unknown combinations, including password/sync.
    pub fn from_codes(method: u64, intent: u64) -> Result<Self, ProtocolError> {
        match (method, intent) {
            (0, 0) => Ok(Self::PasswordEnrollment),
            (1, 0) => Ok(Self::KeyEnrollment),
            (1, 1) => Ok(Self::KeySync),
            _ => Err(ProtocolError::Unsupported),
        }
    }
    /// Exact J=[2,pake,method,intent] for contexts/schedules/transcripts.
    pub fn encode(self, a: &mut Encoder) -> Result<(), EncodeError> {
        a.array(|j| {
            j.uint(2);
            j.uint(u64::from(self == Self::PasswordEnrollment));
            j.uint(self.method());
            j.uint(self.intent());
            Ok(())
        })
    }
}
fn bad<E>(_: E) -> ProtocolError {
    ProtocolError::Malformed
}
fn bounded(bytes: &[u8], label: Label) -> Result<MessageReader<'_>, ProtocolError> {
    if bytes.len() > CREDENTIAL_MAX {
        return Err(ProtocolError::FrameTooLarge);
    }
    MessageReader::open(bytes, label)
}
fn v2(profile: u64) -> Result<(), ProtocolError> {
    if profile == LanProfile::V2.id() {
        Ok(())
    } else {
        Err(ProtocolError::Unsupported)
    }
}
fn array(
    f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    qv_encoding::encode_array(f).map_err(bad)
}

/// Eight-element hello, checked before any KEM or password work.
pub struct PairHello<'a> {
    /// Fixed profile2.
    pub profile: u64,
    /// Window ID.
    pub pairing_id: [u8; 16],
    /// Requested credential method and operation.
    pub mode: AuthMode,
    /// B's nonce commitment.
    pub commit: [u8; 32],
    /// Exact X-Wing public bytes, validated later by crypto.
    pub ek: &'a [u8; EK_LEN],
    /// Code MAC.
    pub mac: [u8; 32],
}
impl<'a> PairHello<'a> {
    fn fields(&self, a: &mut Encoder) {
        a.uint(2);
        a.bytes(&self.pairing_id);
        a.uint(self.mode.method());
        a.uint(self.mode.intent());
        a.bytes(&self.commit);
        a.bytes(self.ek);
    }
    /// Canonical seven-element MAC body.
    pub fn body(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        v2(self.profile)?;
        array(|a| {
            a.text(Label::PairHelloV2.as_str());
            self.fields(a);
            Ok(())
        })
    }
    /// Complete authenticated hello.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        v2(self.profile)?;
        write_message(Label::PairHelloV2, HANDSHAKE_FRAME_MAX, |a| {
            self.fields(a);
            a.bytes(&self.mac);
            Ok(())
        })
    }
    /// Exact profile/shape/bounds only; MAC and KEM validation are the driver's job.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = bounded(bytes, Label::PairHelloV2)?;
        let profile = r.uint()?;
        v2(profile)?;
        let pairing_id = r.bytes_exact()?;
        let mode = AuthMode::from_codes(r.uint()?, r.uint()?)?;
        let m = Self {
            profile,
            pairing_id,
            mode,
            commit: r.bytes_exact()?,
            ek: exact(&mut r)?,
            mac: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}
/// Seven-element accept, echoing the fixed profile/method/intent.
pub struct PairAccept<'a> {
    /// Fixed profile2.
    pub profile: u64,
    /// Echoed operation.
    pub mode: AuthMode,
    /// Fresh A nonce.
    pub nonce: [u8; 32],
    /// Exact KEM ciphertext.
    pub ct: &'a [u8; CT_LEN],
    /// Code MAC over the complete accept body and hello hash.
    pub mac: [u8; 32],
}
impl<'a> PairAccept<'a> {
    fn fields(&self, a: &mut Encoder) {
        a.uint(2);
        a.uint(self.mode.method());
        a.uint(self.mode.intent());
        a.bytes(&self.nonce);
        a.bytes(self.ct);
    }
    /// Canonical six-element body, inserted as an array into the MAC input.
    pub fn body(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        v2(self.profile)?;
        array(|a| {
            a.text(Label::PairAcceptV2.as_str());
            self.fields(a);
            Ok(())
        })
    }
    /// Exact accept MAC input, including H(hello) and the full nested body.
    pub fn mac_input(&self, hello_hash: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let body = RawValue::from_canonical(&self.body()?).map_err(bad)?;
        array(|a| {
            a.text("qv/lan-pair-accept-mac/v2");
            a.bytes(hello_hash);
            a.raw(&body)?;
            Ok(())
        })
    }
    /// Complete authenticated accept.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        v2(self.profile)?;
        write_message(Label::PairAcceptV2, HANDSHAKE_FRAME_MAX, |a| {
            self.fields(a);
            a.bytes(&self.mac);
            Ok(())
        })
    }
    /// Exact shape and echoed-mode fields; caller compares against its attempt.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = bounded(bytes, Label::PairAcceptV2)?;
        let profile = r.uint()?;
        v2(profile)?;
        let mode = AuthMode::from_codes(r.uint()?, r.uint()?)?;
        let m = Self {
            profile,
            mode,
            nonce: r.bytes_exact()?,
            ct: exact(&mut r)?,
            mac: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}
/// T0 input: complete canonical hello/accept are hashed by the caller first.
pub fn outer_transcript(
    mode: AuthMode,
    hello: &[u8; 32],
    accept: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    array(|a| {
        a.text("qv/lan-pair-th/v2");
        mode.encode(a)?;
        a.bytes(hello);
        a.bytes(accept);
        Ok(())
    })
}
/// TA input, binding complete R/S/F or PB/PA arrays, never variable concatenation.
pub fn auth_transcript(
    mode: AuthMode,
    t0: &[u8; 32],
    first: &[u8],
    second: &[u8],
    finalization: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if [
        first.len(),
        second.len(),
        finalization.map_or(0, <[u8]>::len),
    ]
    .iter()
    .any(|&n| n > CREDENTIAL_MAX)
    {
        return Err(ProtocolError::FrameTooLarge);
    }
    if (mode == AuthMode::PasswordEnrollment) != finalization.is_some() {
        return Err(ProtocolError::Malformed);
    }
    // Validate message labels/shapes as well as canonical array syntax.
    match mode {
        AuthMode::PasswordEnrollment => {
            PakeStart::decode(first)?;
            PakeResponse::decode(second)?;
            PakeFinish::decode(finalization.ok_or(ProtocolError::Malformed)?)?;
        }
        AuthMode::KeyEnrollment | AuthMode::KeySync => {
            KeyProve::decode(first)?;
            KeyProved::decode(second)?;
        }
    }
    let first = RawValue::from_canonical(first).map_err(bad)?;
    let second = RawValue::from_canonical(second).map_err(bad)?;
    let last = finalization
        .map(RawValue::from_canonical)
        .transpose()
        .map_err(bad)?;
    array(|a| {
        a.text("qv/lan-auth-th/v2");
        mode.encode(a)?;
        a.bytes(t0);
        a.raw(&first)?;
        a.raw(&second)?;
        if let Some(last) = last {
            a.raw(&last)?;
        }
        Ok(())
    })
}
/// R: nonce reveal and exact KE1. No engine bytes are allocated by decoding.
pub struct PakeStart<'a> {
    /// The committed nonce.
    pub nonce: [u8; 32],
    /// Fixed Ristretto suite KE1.
    pub ke1: &'a [u8; 96],
}
impl<'a> PakeStart<'a> {
    /// Canonical R.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::PakeStart, CREDENTIAL_MAX, |a| {
            a.bytes(&self.nonce);
            a.bytes(self.ke1);
            Ok(())
        })
    }
    /// Exact R, before the engine is called.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = bounded(bytes, Label::PakeStart)?;
        let m = Self {
            nonce: r.bytes_exact()?,
            ke1: exact(&mut r)?,
        };
        r.finish()?;
        Ok(m)
    }
}
macro_rules! blob {
    ($name:ident, $label:ident, $field:ident, $len:literal, $doc:literal) => {
        #[doc=$doc]
        pub struct $name<'a> {
            #[doc = "Exact bounded credential bytes."]
            pub $field: &'a [u8; $len],
        }
        impl<'a> $name<'a> {
            /// Canonical credential record plaintext.
            pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
                write_message(Label::$label, CREDENTIAL_MAX, |a| {
                    a.bytes(self.$field);
                    Ok(())
                })
            }
            /// Exact shape/length; no engine parsing or allocation.
            pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
                let mut r = bounded(bytes, Label::$label)?;
                let m = Self {
                    $field: exact(&mut r)?,
                };
                r.finish()?;
                Ok(m)
            }
        }
    };
}
blob!(PakeResponse, PakeResponse, ke2, 320, "S: exact KE2.");
blob!(
    PakeFinish,
    PakeFinish,
    ke3,
    64,
    "F: exact KE3, last epoch0 record."
);
blob!(
    Finished,
    Finished,
    mac,
    32,
    "FinishedB: separate first B epoch1 record."
);
blob!(
    KeyProve,
    KeyProve,
    mac,
    32,
    "PB: B proves independent VK possession first."
);
/// PA: authenticated identity, after A verified PB.
pub struct KeyProved {
    /// UUID bytes, semantically checked at core/model boundary.
    pub vault_id: [u8; 16],
    /// Nonzero generation.
    pub generation: u32,
    /// Role- and identity-bound proof.
    pub mac: [u8; 32],
}
impl KeyProved {
    /// Canonical PA.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if self.generation == 0 {
            return Err(ProtocolError::Malformed);
        }
        write_message(Label::KeyProved, CREDENTIAL_MAX, |a| {
            a.bytes(&self.vault_id);
            a.uint(self.generation.into());
            a.bytes(&self.mac);
            Ok(())
        })
    }
    /// Exact shape/length and generation bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = bounded(bytes, Label::KeyProved)?;
        let m = Self {
            vault_id: r.bytes_exact()?,
            generation: generation(&mut r)?,
            mac: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}
/// Password-only grant, borrowing from protected record plaintext. No Debug.
pub struct PairGrant<'a> {
    /// Vault UUID.
    pub vault_id: [u8; 16],
    /// Nonzero generation.
    pub generation: u32,
    /// Received key, never an application String/Vec.
    pub key: &'a [u8; 32],
    /// Allowlisted slot projection.
    pub descriptor: &'a [u8; DESCRIPTOR_LEN],
    /// Password control record.
    pub control_record: [u8; 16],
    /// Exact approved head version.
    pub head_version: [u8; 16],
    /// Exact approved head object.
    pub head_object: [u8; 16],
    /// Head object's authenticated ciphertext digest.
    pub head_hash: [u8; 32],
}
impl<'a> PairGrant<'a> {
    /// Canonical grant using a closure, so core can keep VK under its mutex.
    #[allow(clippy::too_many_arguments)] // Exact normative grant fields; no hidden/default identity or head.
    pub fn encode_with_key(
        vault: &[u8; 16],
        generation: u32,
        descriptor: &[u8; DESCRIPTOR_LEN],
        control_record: &[u8; 16],
        head_version: &[u8; 16],
        head_object: &[u8; 16],
        head_hash: &[u8; 32],
        write_key: impl FnOnce(&mut Encoder),
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if generation == 0 {
            return Err(ProtocolError::Malformed);
        }
        let encoded = write_message(Label::PairGrantV2, CREDENTIAL_MAX, |a| {
            a.bytes(vault);
            a.uint(generation.into());
            write_key(a);
            a.bytes(descriptor);
            a.bytes(control_record);
            a.bytes(head_version);
            a.bytes(head_object);
            a.bytes(head_hash);
            Ok(())
        })?;
        // Also enforce the closure's key field type/width, not only total arity.
        PairGrant::decode(&encoded)?;
        Ok(encoded)
    }
    /// Exact shape/bounds; core validates slot profiles, UUIDs and head binding.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = bounded(bytes, Label::PairGrantV2)?;
        let m = Self {
            vault_id: r.bytes_exact()?,
            generation: generation(&mut r)?,
            key: exact(&mut r)?,
            descriptor: exact(&mut r)?,
            control_record: r.bytes_exact()?,
            head_version: r.bytes_exact()?,
            head_object: r.bytes_exact()?,
            head_hash: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}
/// Profile2 errors retain the existing namespace; credential failures close silently.
pub struct ErrorMsg {
    /// Fixed existing code.
    pub code: ErrorCode,
}
impl ErrorMsg {
    /// Canonical encrypted error, when the state permits sending one.
    pub fn encode(code: ErrorCode) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::ErrorV2, CREDENTIAL_MAX, |a| {
            a.uint(code.code());
            Ok(())
        })
    }
    /// Recognizes an error without applying the credential-size bound to a
    /// normal (potentially larger) bulk record. Canonical input remains bounded
    /// by the caller's record layer. Unknown labels and malformed errors fail.
    pub fn peek(bytes: &[u8]) -> Result<Option<Self>, ProtocolError> {
        match MessageReader::open(bytes, Label::ErrorV2) {
            Ok(_) => Self::decode(bytes).map(Some),
            Err(ProtocolError::UnexpectedLabel) => Ok(None),
            Err(e) => Err(e),
        }
    }
    /// Exact shape; unknown codes map to Protocol.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = bounded(bytes, Label::ErrorV2)?;
        let m = Self {
            code: ErrorCode::from_wire(r.uint()?),
        };
        r.finish()?;
        Ok(m)
    }
}

#[cfg(test)]
#[path = "lan_v2_tests.rs"]
mod tests;
