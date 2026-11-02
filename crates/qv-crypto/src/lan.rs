// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN sync record layer (spec 0013 §6, profile `lan / 1`).
//!
//! Each direction of a pairing or session connection has its own
//! [`RecordKey`] and a 64-bit sequence number that starts at 0 and is never
//! sent. A record is
//!
//! ```text
//! XChaCha20-Poly1305(key, nonce = 16 zero bytes ‖ u64be(seq),
//!                    aad = canonical(["qv/lan-record/v1", seq]),
//!                    plaintext = one canonical message)
//! ```
//!
//! sent as ciphertext ‖ tag. The receiver opens with the sequence number it
//! expects next, so a failed tag, gap, reordering or replay fails, and any
//! failure poisons that direction: the session must abort (0013 §2). A
//! direction stops at 2³² records. Keys are unique per session and direction,
//! so counter nonces never repeat.
//!
//! The record keys come from the 0013 §4.4/§5.2 key schedule, which phase 2.9
//! adds to this module; until then keys are only built inside this crate.

use crate::error::CryptoError;
use crate::keys::cbor_array;
use crate::memory::{SecretArray, SecretBytes};
use crate::primitives::{NONCE_LEN, TAG_LEN, xchacha_open_in_place, xchacha_seal_in_place};

/// Largest record plaintext: one message of 1 MiB plus 1 KiB (0013 §6.2).
pub const RECORD_PLAINTEXT_MAX: usize = 1_048_576 + 1_024;
/// Bytes a record adds to its plaintext (the Poly1305 tag).
pub const RECORD_OVERHEAD: usize = TAG_LEN;
/// Records per direction; reaching it aborts the session (0013 §6.1).
pub const RECORDS_PER_DIRECTION: u64 = 1 << 32;

/// One direction's record key (`k_a2b`, `k_b2a`, `k_i2r` or `k_r2i`).
pub struct RecordKey(SecretArray<32>);

impl RecordKey {
    /// Wraps a key derived by this crate's LAN key schedule.
    #[cfg_attr(not(test), allow(dead_code))] // first non-test caller: 2.9 key schedule
    pub(crate) fn from_secret(key: SecretArray<32>) -> Self {
        Self(key)
    }
}

impl core::fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordKey(<redacted>)")
    }
}

fn nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[16..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn aad(seq: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text("qv/lan-record/v1");
        a.uint(seq);
    })
}

/// The sending half of one direction.
pub struct RecordSealer {
    key: RecordKey,
    seq: u64,
    failed: bool,
}

impl RecordSealer {
    /// Starts a direction at sequence number 0.
    pub fn new(key: RecordKey) -> Self {
        Self {
            key,
            seq: 0,
            failed: false,
        }
    }

    /// Seals the next record. An oversized plaintext or an exhausted
    /// direction fails with [`CryptoError::LimitExceeded`] and poisons the
    /// sealer; nothing is produced.
    ///
    /// The plaintext is copied into the output buffer and encrypted in place
    /// there, so the unlocked output briefly holds it; the buffer is sized
    /// once and never reallocates.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.failed
            || plaintext.len() > RECORD_PLAINTEXT_MAX
            || self.seq >= RECORDS_PER_DIRECTION
        {
            self.failed = true;
            return Err(CryptoError::LimitExceeded);
        }
        let aad = aad(self.seq)?;
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        match xchacha_seal_in_place(self.key.0.expose_secret(), &nonce(self.seq), &aad, &mut out) {
            Ok(tag) => {
                out.extend_from_slice(&tag);
                self.seq += 1;
                Ok(out)
            }
            Err(e) => {
                zeroize::Zeroize::zeroize(&mut out);
                self.failed = true;
                Err(e)
            }
        }
    }

    #[cfg(test)]
    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }
}

/// The receiving half of one direction.
pub struct RecordOpener {
    key: RecordKey,
    seq: u64,
    failed: bool,
}

impl RecordOpener {
    /// Starts a direction at sequence number 0.
    pub fn new(key: RecordKey) -> Self {
        Self {
            key,
            seq: 0,
            failed: false,
        }
    }

    /// Opens the next expected record into locked memory.
    ///
    /// The length is checked before anything is allocated
    /// ([`CryptoError::LimitExceeded`]); a failed tag is
    /// [`CryptoError::Integrity`]. Any failure poisons the opener, and every
    /// later call returns [`CryptoError::Integrity`].
    pub fn open(&mut self, record: &[u8]) -> Result<SecretBytes, CryptoError> {
        if self.failed {
            return Err(CryptoError::Integrity);
        }
        let result = self.open_next(record);
        match result {
            Ok(_) => self.seq += 1,
            Err(_) => self.failed = true,
        }
        result
    }

    fn open_next(&self, record: &[u8]) -> Result<SecretBytes, CryptoError> {
        if record.len() < TAG_LEN
            || record.len() > RECORD_PLAINTEXT_MAX + TAG_LEN
            || self.seq >= RECORDS_PER_DIRECTION
        {
            return Err(CryptoError::LimitExceeded);
        }
        let (body, tag) = record.split_at(record.len() - TAG_LEN);
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::Internal)?;
        let aad = aad(self.seq)?;
        SecretBytes::try_init(body.len(), |out| {
            out.copy_from_slice(body);
            xchacha_open_in_place(self.key.0.expose_secret(), &nonce(self.seq), &aad, out, tag)
        })
    }

    #[cfg(test)]
    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }
}

impl core::fmt::Debug for RecordSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordSealer(<redacted>)")
    }
}
impl core::fmt::Debug for RecordOpener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordOpener(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn key(b: u8) -> RecordKey {
        RecordKey::from_secret(
            SecretArray::try_init(|k| {
                k.fill(b);
                Ok::<(), CryptoError>(())
            })
            .unwrap(),
        )
    }
    fn pair(b: u8) -> (RecordSealer, RecordOpener) {
        (RecordSealer::new(key(b)), RecordOpener::new(key(b)))
    }

    #[test]
    fn lan_records_round_trip_within_bounds() {
        let (mut s, mut o) = pair(1);
        for len in [0, 1, RECORD_PLAINTEXT_MAX] {
            let msg = vec![0x5a; len];
            let rec = s.seal(&msg).unwrap();
            assert_eq!(rec.len(), len + RECORD_OVERHEAD);
            assert_eq!(o.open(&rec).unwrap().expose_secret(), &msg[..]);
        }
        assert_eq!(
            s.seal(&vec![0; RECORD_PLAINTEXT_MAX + 1]),
            Err(CryptoError::LimitExceeded)
        );
        // A refused seal poisons the direction.
        assert_eq!(s.seal(b"x"), Err(CryptoError::LimitExceeded));
        // Oversized and short records are refused before decrypting.
        let (_, mut o) = pair(1);
        assert!(matches!(
            o.open(&vec![0; RECORD_PLAINTEXT_MAX + RECORD_OVERHEAD + 1]),
            Err(CryptoError::LimitExceeded)
        ));
        let (_, mut o) = pair(1);
        assert!(matches!(o.open(&[0; 15]), Err(CryptoError::LimitExceeded)));
    }

    #[test]
    fn lan_record_nonce_and_aad_follow_the_spec() {
        let (mut s, _) = pair(2);
        for seq in 0u64..2 {
            let msg = format!("message {seq}");
            let rec = s.seal(msg.as_bytes()).unwrap();
            // Built independently from the 0013 §6.1 text.
            let mut nonce = [0u8; 24];
            nonce[16..].copy_from_slice(&seq.to_be_bytes());
            let mut aad = vec![0x82, 0x70];
            aad.extend_from_slice(b"qv/lan-record/v1");
            aad.push(u8::try_from(seq).unwrap());
            let (body, tag) = rec.split_at(rec.len() - 16);
            let mut buf = body.to_vec();
            xchacha_open_in_place(&[2; 32], &nonce, &aad, &mut buf, tag.try_into().unwrap())
                .unwrap();
            assert_eq!(buf, msg.as_bytes());
        }
    }

    #[test]
    fn lan_records_refuse_replay_reorder_gap_and_tamper_then_poison() {
        let (mut s, _) = pair(3);
        let r0 = s.seal(b"zero").unwrap();
        let r1 = s.seal(b"one").unwrap();
        let r2 = s.seal(b"two").unwrap();
        // Replay.
        let (_, mut o) = pair(3);
        o.open(&r0).unwrap();
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        assert_eq!(o.open(&r1).unwrap_err(), CryptoError::Integrity);
        // Reorder and gap.
        for first in [&r1, &r2] {
            let (_, mut o) = pair(3);
            assert_eq!(o.open(first).unwrap_err(), CryptoError::Integrity);
            assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        }
        // Tamper and truncation.
        let mut bad = r0.clone();
        bad[0] ^= 1;
        let (_, mut o) = pair(3);
        assert_eq!(o.open(&bad).unwrap_err(), CryptoError::Integrity);
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        let (_, mut o) = pair(3);
        assert!(o.open(&r0[..r0.len() - 1]).is_err());
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
        // The other direction's key does not open it.
        let (_, mut o) = pair(4);
        assert_eq!(o.open(&r0).unwrap_err(), CryptoError::Integrity);
    }

    #[test]
    fn lan_direction_stops_at_two_to_the_thirty_two() {
        let (mut s, mut o) = pair(5);
        s.set_seq(RECORDS_PER_DIRECTION - 1);
        o.set_seq(RECORDS_PER_DIRECTION - 1);
        let last = s.seal(b"last").unwrap();
        assert_eq!(o.open(&last).unwrap().expose_secret(), b"last");
        assert_eq!(s.seal(b"more"), Err(CryptoError::LimitExceeded));
        assert_eq!(o.open(&last).unwrap_err(), CryptoError::LimitExceeded);
        assert_eq!(
            format!("{s:?} {o:?}"),
            "RecordSealer(<redacted>) RecordOpener(<redacted>)"
        );
    }
}
