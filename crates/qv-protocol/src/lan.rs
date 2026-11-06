// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed LAN messages (0013 §4, §7, §11) over [`MessageReader`] and
//! [`write_message`].
//!
//! Decoders check exact shapes and sizes only. Every semantic check is the
//! caller's: profile, `pairing_id`, MACs, X-Wing key validity, vault and
//! generation, and the order of the exchange. Fields that may be secret
//! (a revealed nonce, the VK of a grant) are borrowed from, or copied into,
//! wiped buffers. Messages that carry secrets are encoded into `Zeroizing`
//! buffers.

use qv_encoding::Encoder;
use zeroize::Zeroizing;

use crate::ProtocolError;
use crate::frame::HANDSHAKE_FRAME_MAX;
use crate::message::{Label, MessageReader, write_message};
use crate::registry::{ErrorCode, LanProfile};

/// Largest record plaintext: one message of 1 MiB plus 1 KiB (0013 §6.2).
pub const MESSAGE_MAX: usize = 1_048_576 + 1_024;
/// Most IDs in one `Want` (0013 §7.4).
pub const MAX_WANT_IDS: usize = 4096;
/// Most `Want` messages in one turn: ⌈250,000 / 4,096⌉ (0013 §7.4).
pub const MAX_WANT_MESSAGES: usize = 62;
/// Largest manifest part (0013 §7.3).
pub const MAX_MANIFEST_PART: usize = 1 << 20;
/// Largest manifest a state may announce (0013 §7.2).
pub const MAX_MANIFEST_LENGTH: u64 = 64 << 20;
/// Most entries in a `features` list. v1 sends none, and any entry is
/// unsupported; the bound only limits what a decoder allocates.
pub const MAX_FEATURES: usize = 16;
/// Largest object envelope in one `Object` message: a 1 MiB record
/// ciphertext plus its envelope fields.
pub const MAX_OBJECT_ENVELOPE: usize = 1_048_576 + 512;
/// X-Wing encapsulation key length (0002 §6.1).
pub const EK_LEN: usize = 1216;
/// X-Wing ciphertext length (0002 §6.1).
pub const CT_LEN: usize = 1120;

fn bad<E>(_: E) -> ProtocolError {
    ProtocolError::Malformed
}

/// The joining mode of a pairing hello (0013 §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinMode {
    /// `0`: the joiner has no copy of this vault and generation.
    NewDevice,
    /// `1`: the joiner holds the same vault and generation, unlocked, and
    /// asks for one sync session (0013 §4.8).
    Sync,
}

impl JoinMode {
    /// The wire value.
    pub const fn code(self) -> u64 {
        match self {
            Self::NewDevice => 0,
            Self::Sync => 1,
        }
    }

    fn from_code(code: u64) -> Result<Self, ProtocolError> {
        match code {
            0 => Ok(Self::NewDevice),
            1 => Ok(Self::Sync),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// The outcome of a `Done` (0013 §7.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `0`: nothing changed.
    Unchanged,
    /// `1`: merged (for a new device: received, §10).
    Merged,
    /// `2`: merged with conflicts.
    MergedWithConflicts,
}

impl Outcome {
    /// The wire value.
    pub const fn code(self) -> u64 {
        match self {
            Self::Unchanged => 0,
            Self::Merged => 1,
            Self::MergedWithConflicts => 2,
        }
    }

    fn from_code(code: u64) -> Result<Self, ProtocolError> {
        match code {
            0 => Ok(Self::Unchanged),
            1 => Ok(Self::Merged),
            2 => Ok(Self::MergedWithConflicts),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// A key generation on the wire: `1..=u32::MAX`.
fn generation(r: &mut MessageReader<'_>) -> Result<u32, ProtocolError> {
    u32::try_from(r.uint()?)
        .ok()
        .filter(|g| *g >= 1)
        .ok_or(ProtocolError::Malformed)
}

fn exact<'a, const N: usize>(r: &mut MessageReader<'a>) -> Result<&'a [u8; N], ProtocolError> {
    r.bytes_max(N)?.try_into().map_err(bad)
}

/// `PairHello` (0013 §4.3): `body ++ [mac]`.
#[derive(Debug)]
pub struct PairHello<'a> {
    /// The raw `lan_profile`, checked by the caller after the shape.
    pub profile: u64,
    /// The window's pairing ID.
    pub pairing_id: [u8; 16],
    /// The requested mode.
    pub mode: JoinMode,
    /// `commit_B`.
    pub commit: [u8; 32],
    /// B's X-Wing encapsulation key (not yet validated).
    pub ek: &'a [u8; EK_LEN],
    /// `MAC/1(K_hello, canonical(body))`.
    pub mac: [u8; 32],
}

impl<'a> PairHello<'a> {
    fn fields(
        a: &mut Encoder,
        profile: LanProfile,
        pairing_id: &[u8; 16],
        mode: JoinMode,
        commit: &[u8; 32],
        ek: &[u8; EK_LEN],
    ) {
        a.uint(profile.id());
        a.bytes(pairing_id);
        a.uint(mode.code());
        a.bytes(commit);
        a.bytes(ek);
    }

    /// The canonical body that the MAC covers: the first six elements.
    pub fn body(
        profile: LanProfile,
        pairing_id: &[u8; 16],
        mode: JoinMode,
        commit: &[u8; 32],
        ek: &[u8; EK_LEN],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        qv_encoding::encode_array(|a| {
            a.text(Label::PairHello.as_str());
            Self::fields(a, profile, pairing_id, mode, commit, ek);
            Ok(())
        })
        .map_err(bad)
    }

    /// The complete hello.
    pub fn encode(
        profile: LanProfile,
        pairing_id: &[u8; 16],
        mode: JoinMode,
        commit: &[u8; 32],
        ek: &[u8; EK_LEN],
        mac: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::PairHello, HANDSHAKE_FRAME_MAX, |a| {
            Self::fields(a, profile, pairing_id, mode, commit, ek);
            a.bytes(mac);
            Ok(())
        })
    }

    /// Decodes the exact shape; use [`crate::message::body_without_last`]
    /// for the MAC'd bytes.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::PairHello)?;
        let m = Self {
            profile: r.uint()?,
            pairing_id: r.bytes_exact()?,
            mode: JoinMode::from_code(r.uint()?)?,
            commit: r.bytes_exact()?,
            ek: exact(&mut r)?,
            mac: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `PairAccept` (0013 §4.4).
#[derive(Debug)]
pub struct PairAccept<'a> {
    /// `nonce_A`.
    pub nonce_a: [u8; 32],
    /// The X-Wing ciphertext.
    pub ct: &'a [u8; CT_LEN],
    /// `MAC/1(K_accept, canonical([label, H(hello), nonce_A, ct]))`.
    pub mac: [u8; 32],
}

impl<'a> PairAccept<'a> {
    /// The canonical array that the accept MAC covers.
    pub fn transcript(
        hello_hash: &[u8; 32],
        nonce_a: &[u8; 32],
        ct: &[u8; CT_LEN],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        qv_encoding::encode_array(|a| {
            a.text(Label::PairAccept.as_str());
            a.bytes(hello_hash);
            a.bytes(nonce_a);
            a.bytes(ct);
            Ok(())
        })
        .map_err(bad)
    }

    /// The complete accept.
    pub fn encode(
        nonce_a: &[u8; 32],
        ct: &[u8; CT_LEN],
        mac: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::PairAccept, HANDSHAKE_FRAME_MAX, |a| {
            a.bytes(nonce_a);
            a.bytes(ct);
            a.bytes(mac);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::PairAccept)?;
        let m = Self {
            nonce_a: r.bytes_exact()?,
            ct: exact(&mut r)?,
            mac: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// The canonical `["qv/lan-pair-th/v1", H(hello), H(accept)]`; `th` is its
/// hash (0013 §4.4).
pub fn pair_th_input(
    hello_hash: &[u8; 32],
    accept_hash: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    qv_encoding::encode_array(|a| {
        a.text("qv/lan-pair-th/v1");
        a.bytes(hello_hash);
        a.bytes(accept_hash);
        Ok(())
    })
    .map_err(bad)
}

/// `PairReveal` (0013 §4.5).
pub struct PairReveal {
    /// The revealed `nonce_B`.
    pub nonce_b: Zeroizing<[u8; 32]>,
}

impl PairReveal {
    /// Encodes the reveal of `nonce_b`.
    pub fn encode(nonce_b: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::PairReveal, MESSAGE_MAX, |a| {
            a.bytes(nonce_b);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::PairReveal)?;
        let nonce_b = Zeroizing::new(*exact::<32>(&mut r)?);
        r.finish()?;
        Ok(Self { nonce_b })
    }
}

/// `PairGrant` (0013 §4.7). `vk` borrows from the decrypted record.
pub struct PairGrant<'a> {
    /// The vault ID.
    pub vault_id: [u8; 16],
    /// The key generation.
    pub key_generation: u32,
    /// VK, 32 bytes.
    pub vk: &'a [u8],
}

impl<'a> PairGrant<'a> {
    /// Encodes a grant; `write_vk` writes VK as one 32-byte byte string.
    pub fn encode(
        vault_id: &[u8; 16],
        key_generation: u32,
        write_vk: impl FnOnce(&mut Encoder),
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::PairGrant, MESSAGE_MAX, |a| {
            a.bytes(vault_id);
            a.uint(key_generation.into());
            write_vk(a);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::PairGrant)?;
        let vault_id = r.bytes_exact()?;
        let key_generation = generation(&mut r)?;
        let vk = r.bytes_max(32)?;
        if vk.len() != 32 {
            return Err(ProtocolError::Malformed);
        }
        let m = Self {
            vault_id,
            key_generation,
            vk,
        };
        r.finish()?;
        Ok(m)
    }
}

impl core::fmt::Debug for PairGrant<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairGrant(<redacted>)")
    }
}

/// `PairProve` (0013 §4.8).
#[derive(Debug)]
pub struct PairProve {
    /// The vault ID.
    pub vault_id: [u8; 16],
    /// The key generation.
    pub key_generation: u32,
    /// `proof_B`.
    pub proof: [u8; 32],
}

impl PairProve {
    /// Encodes the joiner's proof.
    pub fn encode(
        vault_id: &[u8; 16],
        key_generation: u32,
        proof: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::PairProve, MESSAGE_MAX, |a| {
            a.bytes(vault_id);
            a.uint(key_generation.into());
            a.bytes(proof);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::PairProve)?;
        let m = Self {
            vault_id: r.bytes_exact()?,
            key_generation: generation(&mut r)?,
            proof: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `PairProved` (0013 §4.8).
#[derive(Debug)]
pub struct PairProved {
    /// `proof_A`.
    pub proof: [u8; 32],
}

impl PairProved {
    /// Encodes the offering device's proof.
    pub fn encode(proof: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::PairProved, MESSAGE_MAX, |a| {
            a.bytes(proof);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::PairProved)?;
        let m = Self {
            proof: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `State` (0013 §7.2).
#[derive(Debug)]
pub struct State {
    /// The vault ID.
    pub vault_id: [u8; 16],
    /// The key generation.
    pub key_generation: u32,
    /// SHA-256 of the sender's manifest envelope (all zero for a new device).
    pub manifest_hash: [u8; 32],
    /// The envelope's length in bytes.
    pub manifest_length: u64,
    /// Required features; v1 sends none.
    pub features: Vec<u64>,
}

impl State {
    /// Encodes a state with an empty feature list (v1).
    pub fn encode(
        vault_id: &[u8; 16],
        key_generation: u32,
        manifest_hash: &[u8; 32],
        manifest_length: u64,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::State, MESSAGE_MAX, |a| {
            a.bytes(vault_id);
            a.uint(key_generation.into());
            a.bytes(manifest_hash);
            a.uint(manifest_length);
            a.array(|_| Ok(()))
        })
    }

    /// Decodes the exact shape; a feature list above [`MAX_FEATURES`] is
    /// malformed before anything is allocated.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::State)?;
        let m = Self {
            vault_id: r.bytes_exact()?,
            key_generation: generation(&mut r)?,
            manifest_hash: r.bytes_exact()?,
            manifest_length: r.uint()?,
            features: r.uint_array_max(MAX_FEATURES)?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `Manifest` (0013 §7.3).
#[derive(Debug)]
pub struct ManifestPart<'a> {
    /// The part's offset in the envelope.
    pub offset: u64,
    /// At most [`MAX_MANIFEST_PART`] bytes.
    pub bytes: &'a [u8],
}

impl<'a> ManifestPart<'a> {
    /// Encodes one part.
    pub fn encode(offset: u64, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if bytes.len() > MAX_MANIFEST_PART {
            return Err(ProtocolError::Malformed);
        }
        write_message(Label::Manifest, MESSAGE_MAX, |a| {
            a.uint(offset);
            a.bytes(bytes);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::Manifest)?;
        let m = Self {
            offset: r.uint()?,
            bytes: r.bytes_max(MAX_MANIFEST_PART)?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `Want` (0013 §7.4).
#[derive(Debug)]
pub struct Want {
    /// At most [`MAX_WANT_IDS`] object IDs.
    pub ids: Vec<[u8; 16]>,
    /// Whether this ends the sender's requests.
    pub last: bool,
}

impl Want {
    /// Encodes one request message.
    pub fn encode(ids: &[[u8; 16]], last: bool) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if ids.len() > MAX_WANT_IDS {
            return Err(ProtocolError::Malformed);
        }
        write_message(Label::Want, MESSAGE_MAX, |a| {
            a.array(|a| {
                for id in ids {
                    a.bytes(id);
                }
                Ok(())
            })?;
            a.bool(last);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::Want)?;
        let m = Self {
            ids: r.bytes_array_exact(MAX_WANT_IDS)?,
            last: r.bool()?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `Object` (0013 §7.5).
#[derive(Debug)]
pub struct ObjectMsg<'a> {
    /// One object envelope, at most [`MAX_OBJECT_ENVELOPE`] bytes.
    pub envelope: &'a [u8],
}

impl<'a> ObjectMsg<'a> {
    /// Encodes one object.
    pub fn encode(envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if envelope.len() > MAX_OBJECT_ENVELOPE {
            return Err(ProtocolError::Malformed);
        }
        write_message(Label::Object, MESSAGE_MAX, |a| {
            a.bytes(envelope);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::Object)?;
        let m = Self {
            envelope: r.bytes_max(MAX_OBJECT_ENVELOPE)?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `Done` (0013 §7.7).
#[derive(Debug)]
pub struct Done {
    /// The sender's outcome.
    pub outcome: Outcome,
    /// The sender's new local manifest hash.
    pub manifest_hash: [u8; 32],
}

impl Done {
    /// Encodes a done.
    pub fn encode(
        outcome: Outcome,
        manifest_hash: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::Done, MESSAGE_MAX, |a| {
            a.uint(outcome.code());
            a.bytes(manifest_hash);
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::Done)?;
        let m = Self {
            outcome: Outcome::from_code(r.uint()?)?,
            manifest_hash: r.bytes_exact()?,
        };
        r.finish()?;
        Ok(m)
    }
}

/// `["qv/lan-error/v1", code]` (0013 §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorMsg {
    /// The code; unknown codes read as [`ErrorCode::Protocol`].
    pub code: ErrorCode,
}

impl ErrorMsg {
    /// Encodes an error record's plaintext.
    pub fn encode(code: ErrorCode) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        write_message(Label::Error, MESSAGE_MAX, |a| {
            a.uint(code.code());
            Ok(())
        })
    }

    /// Decodes the exact shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = MessageReader::open(bytes, Label::Error)?;
        let m = Self {
            code: ErrorCode::from_wire(r.uint()?),
        };
        r.finish()?;
        Ok(m)
    }

    /// `Some` if `bytes` is a well-formed error record, `None` if it carries
    /// another known label. Unknown labels and malformed errors are errors.
    pub fn peek(bytes: &[u8]) -> Result<Option<Self>, ProtocolError> {
        match Self::decode(bytes) {
            Ok(m) => Ok(Some(m)),
            Err(ProtocolError::UnexpectedLabel) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::message::body_without_last;
    use proptest::prelude::*;

    const EK: [u8; EK_LEN] = [3; EK_LEN];
    const CT: [u8; CT_LEN] = [4; CT_LEN];

    fn msg(label: &str, f: impl FnOnce(&mut Encoder)) -> Vec<u8> {
        qv_encoding::encode_array(|a| {
            a.text(label);
            f(a);
            Ok(())
        })
        .unwrap()
        .to_vec()
    }

    #[test]
    fn lan_pairing_messages_round_trip() {
        let body =
            PairHello::body(LanProfile::V1, &[1; 16], JoinMode::Sync, &[2; 32], &EK).unwrap();
        let hello = PairHello::encode(
            LanProfile::V1,
            &[1; 16],
            JoinMode::Sync,
            &[2; 32],
            &EK,
            &[5; 32],
        )
        .unwrap();
        assert!(hello.len() <= HANDSHAKE_FRAME_MAX);
        assert_eq!(body_without_last(&hello).unwrap(), body);
        let h = PairHello::decode(&hello).unwrap();
        assert_eq!(
            (h.profile, h.pairing_id, h.mode, h.commit, h.mac),
            (1, [1; 16], JoinMode::Sync, [2; 32], [5; 32])
        );
        assert_eq!(h.ek, &EK);

        let accept = PairAccept::encode(&[6; 32], &CT, &[7; 32]).unwrap();
        assert!(accept.len() <= HANDSHAKE_FRAME_MAX);
        let a = PairAccept::decode(&accept).unwrap();
        assert_eq!((a.nonce_a, a.ct, a.mac), ([6; 32], &CT, [7; 32]));
        let t = PairAccept::transcript(&[8; 32], &[6; 32], &CT).unwrap();
        let mut r = MessageReader::open(&t, Label::PairAccept).unwrap();
        assert_eq!(r.bytes_exact::<32>().unwrap(), [8; 32]);

        let reveal = PairReveal::encode(&[9; 32]).unwrap();
        assert_eq!(*PairReveal::decode(&reveal).unwrap().nonce_b, [9; 32]);

        let grant = PairGrant::encode(&[1; 16], 7, |e| e.bytes(&[0xaa; 32])).unwrap();
        let g = PairGrant::decode(&grant).unwrap();
        assert_eq!(
            (g.vault_id, g.key_generation, g.vk),
            ([1; 16], 7, &[0xaa; 32][..])
        );
        assert_eq!(format!("{g:?}"), "PairGrant(<redacted>)");

        let prove = PairProve::encode(&[1; 16], 7, &[3; 32]).unwrap();
        let p = PairProve::decode(&prove).unwrap();
        assert_eq!(
            (p.vault_id, p.key_generation, p.proof),
            ([1; 16], 7, [3; 32])
        );
        let proved = PairProved::encode(&[4; 32]).unwrap();
        assert_eq!(PairProved::decode(&proved).unwrap().proof, [4; 32]);
        assert_eq!(
            pair_th_input(&[1; 32], &[2; 32]).unwrap().len(),
            1 + 18 + 2 * 34
        );
    }

    #[test]
    fn lan_exchange_messages_round_trip() {
        let s = State::decode(&State::encode(&[1; 16], 2, &[3; 32], 99).unwrap()).unwrap();
        assert_eq!(
            (
                s.vault_id,
                s.key_generation,
                s.manifest_hash,
                s.manifest_length,
                s.features
            ),
            ([1; 16], 2, [3; 32], 99, vec![])
        );
        let part = ManifestPart::encode(5, &[1, 2, 3]).unwrap();
        let p = ManifestPart::decode(&part).unwrap();
        assert_eq!((p.offset, p.bytes), (5, &[1, 2, 3][..]));
        let big = vec![0; MAX_MANIFEST_PART];
        assert!(ManifestPart::encode(0, &big).unwrap().len() <= MESSAGE_MAX);
        assert_eq!(
            ManifestPart::encode(0, &[big, vec![0]].concat()).err(),
            Some(ProtocolError::Malformed)
        );
        let ids = vec![[7; 16]; MAX_WANT_IDS];
        let want = Want::encode(&ids, true).unwrap();
        assert!(want.len() <= MESSAGE_MAX);
        let w = Want::decode(&want).unwrap();
        assert_eq!((w.ids.len(), w.last), (MAX_WANT_IDS, true));
        assert!(
            Want::decode(&Want::encode(&[], false).unwrap())
                .unwrap()
                .ids
                .is_empty()
        );
        assert_eq!(
            Want::encode(&vec![[7; 16]; MAX_WANT_IDS + 1], true).err(),
            Some(ProtocolError::Malformed)
        );
        let env = vec![1; MAX_OBJECT_ENVELOPE];
        let o = ObjectMsg::encode(&env).unwrap();
        assert!(o.len() <= MESSAGE_MAX);
        assert_eq!(ObjectMsg::decode(&o).unwrap().envelope, &env[..]);
        let d =
            Done::decode(&Done::encode(Outcome::MergedWithConflicts, &[4; 32]).unwrap()).unwrap();
        assert_eq!(
            (d.outcome, d.manifest_hash),
            (Outcome::MergedWithConflicts, [4; 32])
        );
        let e = ErrorMsg::encode(ErrorCode::Keyslot).unwrap();
        assert_eq!(ErrorMsg::decode(&e).unwrap().code, ErrorCode::Keyslot);
        assert_eq!(
            ErrorMsg::peek(&e).unwrap(),
            Some(ErrorMsg {
                code: ErrorCode::Keyslot
            })
        );
        assert_eq!(ErrorMsg::peek(&want).unwrap(), None);
        let unknown = msg("qv/lan-error/v1", |a| a.uint(77));
        assert_eq!(
            ErrorMsg::peek(&unknown).unwrap().unwrap().code,
            ErrorCode::Protocol
        );
        assert_eq!(
            ErrorMsg::peek(&msg("qv/lan-nope/v1", |_| {})).err(),
            Some(ProtocolError::UnknownLabel)
        );
    }

    #[test]
    fn lan_removed_and_old_shapes_are_refused() {
        // 0014: the session handshake, PairDone and the address QR are gone.
        for label in [
            "qv/lan-hello/v1",
            "qv/lan-accept/v1",
            "qv/lan-confirm/v1",
            "qv/lan-pair-done/v1",
        ] {
            let m = msg(label, |a| a.bytes(&[8; 32]));
            assert_eq!(
                ErrorMsg::peek(&m).err(),
                Some(ProtocolError::UnknownLabel),
                "{label}"
            );
            assert!(PairProved::decode(&m).is_err(), "{label}");
        }
        // The pre-0014 grant (with link_id) and proved (with link_id).
        let old_grant = msg("qv/lan-pair-grant/v1", |a| {
            a.bytes(&[1; 16]);
            a.uint(1);
            a.bytes(&[0; 32]);
            a.bytes(&[2; 16]);
        });
        assert_eq!(
            PairGrant::decode(&old_grant).err(),
            Some(ProtocolError::Malformed)
        );
        let old_proved = msg("qv/lan-pair-proved/v1", |a| {
            a.bytes(&[2; 16]);
            a.bytes(&[4; 32]);
        });
        assert_eq!(
            PairProved::decode(&old_proved).err(),
            Some(ProtocolError::Malformed)
        );
        let short_proof = msg("qv/lan-pair-proved/v1", |a| a.bytes(&[4; 31]));
        assert_eq!(
            PairProved::decode(&short_proof).err(),
            Some(ProtocolError::Malformed)
        );
    }

    #[test]
    fn lan_messages_refuse_bad_shapes_and_ranges() {
        let malformed = |r: Result<(), ProtocolError>| assert_eq!(r, Err(ProtocolError::Malformed));
        let hello = |mode: u64| {
            msg("qv/lan-pair-hello/v1", |a| {
                a.uint(1);
                a.bytes(&[1; 16]);
                a.uint(mode);
                a.bytes(&[2; 32]);
                a.bytes(&EK);
                a.bytes(&[5; 32]);
            })
        };
        assert!(PairHello::decode(&hello(0)).is_ok());
        malformed(PairHello::decode(&hello(2)).map(drop));
        let short_ek = msg("qv/lan-pair-hello/v1", |a| {
            a.uint(1);
            a.bytes(&[1; 16]);
            a.uint(0);
            a.bytes(&[2; 32]);
            a.bytes(&EK[..1184]);
            a.bytes(&[5; 32]);
        });
        malformed(PairHello::decode(&short_ek).map(drop));
        let accept_ct = msg("qv/lan-pair-accept/v1", |a| {
            a.bytes(&[6; 32]);
            a.bytes(&CT[..1088]);
            a.bytes(&[7; 32]);
        });
        malformed(PairAccept::decode(&accept_ct).map(drop));
        for g in [0u64, u64::from(u32::MAX) + 1] {
            let m = msg("qv/lan-pair-prove/v1", |a| {
                a.bytes(&[1; 16]);
                a.uint(g);
                a.bytes(&[3; 32]);
            });
            malformed(PairProve::decode(&m).map(drop));
        }
        let grant31 = msg("qv/lan-pair-grant/v1", |a| {
            a.bytes(&[1; 16]);
            a.uint(1);
            a.bytes(&[0; 31]);
        });
        malformed(PairGrant::decode(&grant31).map(drop));
        let done3 = msg("qv/lan-done/v1", |a| {
            a.uint(3);
            a.bytes(&[0; 32]);
        });
        malformed(Done::decode(&done3).map(drop));
        let features = msg("qv/lan-state/v1", |a| {
            a.bytes(&[1; 16]);
            a.uint(1);
            a.bytes(&[0; 32]);
            a.uint(0);
            a.array(|a| {
                for i in 0..=MAX_FEATURES as u64 {
                    a.uint(i);
                }
                Ok(())
            })
            .unwrap();
        });
        malformed(State::decode(&features).map(drop));
        let many = msg("qv/lan-want/v1", |a| {
            a.array(|a| {
                for _ in 0..=MAX_WANT_IDS {
                    a.bytes(&[0; 16]);
                }
                Ok(())
            })
            .unwrap();
            a.bool(true);
        });
        malformed(Want::decode(&many).map(drop));
        let part = msg("qv/lan-manifest/v1", |a| {
            a.uint(0);
            a.bytes(&vec![0; MAX_MANIFEST_PART + 1]);
        });
        malformed(ManifestPart::decode(&part).map(drop));
        // Another label in place of the expected one.
        assert_eq!(
            Want::decode(&PairProved::encode(&[4; 32]).unwrap()).err(),
            Some(ProtocolError::UnexpectedLabel)
        );
        // Extra element.
        let extra = msg("qv/lan-pair-proved/v1", |a| {
            a.bytes(&[4; 32]);
            a.uint(0);
        });
        malformed(PairProved::decode(&extra).map(drop));
    }

    proptest! {
        #[test]
        fn lan_decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = PairHello::decode(&bytes);
            let _ = PairAccept::decode(&bytes);
            let _ = PairReveal::decode(&bytes);
            let _ = PairGrant::decode(&bytes);
            let _ = PairProve::decode(&bytes);
            let _ = PairProved::decode(&bytes);
            let _ = State::decode(&bytes);
            let _ = ManifestPart::decode(&bytes);
            let _ = Want::decode(&bytes);
            let _ = ObjectMsg::decode(&bytes);
            let _ = Done::decode(&bytes);
            let _ = ErrorMsg::peek(&bytes);
        }
    }
}
