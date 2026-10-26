// SPDX-License-Identifier: AGPL-3.0-or-later

//! The recovery phrase (spec 0002 §4): VK as 24 BIP-39 English words.
//!
//! This is BIP-39 **entropy encoding** only: the 256 bits of VK plus the
//! 8-bit checksum `SHA-256(VK)[0]` split into twenty-four 11-bit word
//! indices. The BIP-39 PBKDF2 seed function is not used, and there is no extra
//! mnemonic passphrase (0002 §4.1). Decoding gives VK back directly.
//!
//! Input is normalized as follows: words are separated by any ASCII
//! whitespace, ASCII letters are lowercased, and each word must be 1–8 ASCII
//! letters. Exactly 24 words are required, given in full: 4-letter
//! abbreviations are not accepted. Every failure, including a bad checksum, is
//! [`CryptoError::WrongPhrase`].
//!
//! Timing (0008 §2): each word is looked up by scanning all 2,048 entries
//! with constant-time comparisons and selections (`ctutils`), with no early
//! exit, and the checksum is compared in constant time. The decoder branches
//! once, on "all words found and checksum valid". Two things are not constant
//! time: rejecting a word count other than 24 or a malformed word (that
//! depends on the shape of the typed input, not on VK), and joining words of
//! different lengths into the phrase that is about to be shown to the user.
//!
//! A phrase cannot be cloned or compared:
//!
//! ```compile_fail
//! let vk = qv_crypto::VaultKey::generate().unwrap();
//! let p = qv_crypto::RecoveryPhrase::from_vault_key(&vk).unwrap();
//! let _ = p.clone();
//! ```
//!
//! ```compile_fail
//! let vk = qv_crypto::VaultKey::generate().unwrap();
//! let a = qv_crypto::RecoveryPhrase::from_vault_key(&vk).unwrap();
//! let b = qv_crypto::RecoveryPhrase::from_vault_key(&vk).unwrap();
//! let _ = a == b;
//! ```
//!
//! ```
//! let vk = qv_crypto::VaultKey::generate().unwrap();
//! let p = qv_crypto::RecoveryPhrase::from_vault_key(&vk).unwrap();
//! assert_eq!(p.expose_secret().split(' ').count(), 24);
//! assert_eq!(format!("{p:?}"), "RecoveryPhrase(<redacted>)");
//! ```

use core::fmt;

use ctutils::{Choice, CtAssign, CtEq};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::VaultKey;
use crate::memory::SecretArray;
use crate::primitives::sha256;
use crate::wordlist::{BIP39_MAX_WORD, Bip39List, bip39_english};

/// Words in a recovery phrase.
pub const PHRASE_WORDS: usize = 24;
/// The longest phrase: 24 eight-letter words and 23 spaces.
const PHRASE_CAPACITY: usize = PHRASE_WORDS * BIP39_MAX_WORD + PHRASE_WORDS - 1;
/// Normalized input: 24 zero-padded 8-byte words.
const NORMALIZED_LEN: usize = PHRASE_WORDS * BIP39_MAX_WORD;
/// VK (32 bytes) ‖ checksum (1 byte), plus 2 zero bytes so every 11-bit
/// group can be read and written as 3 whole bytes.
const PACKED_LEN: usize = 35;
const VK_LEN: usize = 32;

/// A recovery phrase: 24 lowercase words separated by single spaces.
///
/// Held in locked, zeroizing memory. No `Clone`, `PartialEq` or `Display`;
/// `Debug` is redacted (0002 §4.2).
pub struct RecoveryPhrase {
    buf: SecretArray<PHRASE_CAPACITY>,
    len: usize,
}

impl RecoveryPhrase {
    /// Encodes VK as its recovery phrase.
    pub fn from_vault_key(vk: &VaultKey) -> Result<Self, CryptoError> {
        let list = bip39_english()?;
        let packed = pack_vault_key(vk)?;
        let mut buf = SecretArray::<PHRASE_CAPACITY>::zeroed();
        let mut len = 0usize;
        let mut word = Zeroizing::new([0u8; BIP39_MAX_WORD]);
        for i in 0..PHRASE_WORDS {
            let index = read_index(packed.expose_secret(), i)?;
            select_word(list, index, &mut word);
            let out = buf.expose_secret_mut();
            if i > 0 {
                *out.get_mut(len).ok_or(CryptoError::Internal)? = b' ';
                len += 1;
            }
            let word_len = word.iter().take_while(|&&b| b != 0).count();
            out.get_mut(len..len + word_len)
                .ok_or(CryptoError::Internal)?
                .copy_from_slice(word.get(..word_len).ok_or(CryptoError::Internal)?);
            len += word_len;
        }
        Ok(Self { buf, len })
    }

    /// The phrase: 24 lowercase words separated by single spaces.
    pub fn expose_secret(&self) -> &str {
        let bytes = self.buf.expose_secret().get(..self.len).unwrap_or_default();
        // Always ASCII by construction.
        core::str::from_utf8(bytes).unwrap_or_default()
    }

    /// Word `index` (0-based), or `None` past the last word.
    pub fn expose_word(&self, index: usize) -> Option<&str> {
        self.expose_secret().split(' ').nth(index)
    }

    /// Checks one typed word against word `index` (0-based) in constant
    /// time, for the confirmation step at vault creation (0002 §4.2). The
    /// typed word is normalized like a decoded phrase.
    ///
    /// A mismatch or malformed input is [`CryptoError::WrongPhrase`]. An
    /// `index` of 24 or more is a caller bug ([`CryptoError::Internal`]).
    pub fn confirm_word(&self, index: usize, typed: &[u8]) -> Result<(), CryptoError> {
        let expected = self.expose_word(index).ok_or(CryptoError::Internal)?;
        let mut want = Zeroizing::new([0u8; BIP39_MAX_WORD]);
        want.get_mut(..expected.len())
            .ok_or(CryptoError::Internal)?
            .copy_from_slice(expected.as_bytes());
        let mut got = Zeroizing::new([0u8; BIP39_MAX_WORD]);
        let mut words = typed
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty());
        let word = words.next().ok_or(CryptoError::WrongPhrase)?;
        if words.next().is_some() {
            return Err(CryptoError::WrongPhrase);
        }
        normalize_word(word, &mut got[..])?;
        if want[..].ct_eq(&got[..]).to_bool() {
            Ok(())
        } else {
            Err(CryptoError::WrongPhrase)
        }
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(<redacted>)")
    }
}

impl VaultKey {
    /// Decodes a recovery phrase to VK (0002 §4.1). `input` is only borrowed;
    /// the caller keeps (and wipes) its own buffer.
    pub fn from_recovery_phrase(input: &[u8]) -> Result<VaultKey, CryptoError> {
        let list = bip39_english()?;
        let mut words = SecretArray::<NORMALIZED_LEN>::zeroed();
        normalize(input, words.expose_secret_mut())?;
        let mut packed = SecretArray::<PACKED_LEN>::zeroed();
        let mut found = Choice::TRUE;
        let (chunks, _) = words.expose_secret().as_chunks::<BIP39_MAX_WORD>();
        for (i, word) in chunks.iter().enumerate() {
            let (hit, index) = lookup(list, word);
            found &= hit;
            write_index(packed.expose_secret_mut(), i, *index)?;
        }
        let packed = packed.expose_secret();
        let (vk, rest) = packed.split_at(VK_LEN);
        let mut digest = SecretArray::<32>::zeroed();
        sha256(vk, digest.expose_secret_mut());
        let checksum = rest.first().ok_or(CryptoError::Internal)?;
        let valid = found & checksum.ct_eq(&digest.expose_secret()[0]);
        if !valid.to_bool() {
            return Err(CryptoError::WrongPhrase);
        }
        let key = SecretArray::<32>::try_init(|out| {
            out.copy_from_slice(vk);
            Ok::<(), CryptoError>(())
        })?;
        Ok(VaultKey::from_secret(key))
    }
}

/// `VK ‖ SHA-256(VK)[0] ‖ 0 0`.
fn pack_vault_key(vk: &VaultKey) -> Result<SecretArray<PACKED_LEN>, CryptoError> {
    let mut digest = SecretArray::<32>::zeroed();
    sha256(vk.expose_secret(), digest.expose_secret_mut());
    SecretArray::try_init(|out| {
        let (key, rest) = out.split_at_mut(VK_LEN);
        key.copy_from_slice(vk.expose_secret());
        *rest.first_mut().ok_or(CryptoError::Internal)? = digest.expose_secret()[0];
        Ok(())
    })
}

/// Bit offset of word `i`, and the shift that aligns its 11 bits inside the
/// 3 bytes starting at `offset / 8`.
fn group(i: usize) -> (usize, u32) {
    let bit = i * 11;
    // 24 − 11 − (bit mod 8) is between 6 and 13.
    (bit / 8, 13 - (bit % 8) as u32)
}

fn read_index(packed: &[u8; PACKED_LEN], i: usize) -> Result<u16, CryptoError> {
    let (byte, shift) = group(i);
    let b = packed.get(byte..byte + 3).ok_or(CryptoError::Internal)?;
    let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
    u16::try_from((v >> shift) & 0x7ff).map_err(|_| CryptoError::Internal)
}

fn write_index(packed: &mut [u8; PACKED_LEN], i: usize, index: u16) -> Result<(), CryptoError> {
    let (byte, shift) = group(i);
    let v = (u32::from(index) & 0x7ff) << shift;
    let b = packed
        .get_mut(byte..byte + 3)
        .ok_or(CryptoError::Internal)?;
    for (dst, src) in b.iter_mut().zip(v.to_be_bytes().into_iter().skip(1)) {
        *dst |= src;
    }
    Ok(())
}

/// Copies list entry `index` into `word`, touching every entry. Entries are
/// compared and selected as `u64`s (8 zero-padded bytes).
fn select_word(list: &Bip39List, index: u16, word: &mut [u8; BIP39_MAX_WORD]) {
    let mut selected = Zeroizing::new(0u64);
    for (j, entry) in (0u16..).zip(list.padded()) {
        selected.ct_assign(&u64::from_le_bytes(*entry), Choice::from_u16_eq(index, j));
    }
    *word = selected.to_le_bytes();
}

/// The index of a padded word, scanning every entry; `found` is false if it
/// is not in the list.
fn lookup(list: &Bip39List, word: &[u8; BIP39_MAX_WORD]) -> (Choice, Zeroizing<u16>) {
    let word = Zeroizing::new(u64::from_le_bytes(*word));
    let mut found = Choice::FALSE;
    let mut index = Zeroizing::new(0u16);
    for (j, entry) in (0u16..).zip(list.padded()) {
        let hit = u64::from_le_bytes(*entry).ct_eq(&*word);
        index.ct_assign(&j, hit);
        found |= hit;
    }
    (found, index)
}

/// Lowercases one word of 1–8 ASCII letters into a zero-padded slot.
fn normalize_word(word: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if word.is_empty() || word.len() > BIP39_MAX_WORD || !word.iter().all(u8::is_ascii_alphabetic) {
        return Err(CryptoError::WrongPhrase);
    }
    for (dst, src) in out.iter_mut().zip(word) {
        *dst = src.to_ascii_lowercase();
    }
    Ok(())
}

/// Splits on ASCII whitespace into exactly 24 normalized, zero-padded words.
fn normalize(input: &[u8], out: &mut [u8; NORMALIZED_LEN]) -> Result<(), CryptoError> {
    let mut count = 0usize;
    for word in input
        .split(u8::is_ascii_whitespace)
        .filter(|w| !w.is_empty())
    {
        let slot = out
            .get_mut(count * BIP39_MAX_WORD..(count + 1) * BIP39_MAX_WORD)
            .ok_or(CryptoError::WrongPhrase)?;
        normalize_word(word, slot)?;
        count += 1;
    }
    if count == PHRASE_WORDS {
        Ok(())
    } else {
        Err(CryptoError::WrongPhrase)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::kat;
    use crate::memory::secrets_test_guard;

    fn vectors() -> Vec<([u8; 32], String)> {
        kat::parse(include_str!(
            "../tests/vectors/bip39-trezor-english-256.txt"
        ))
        .iter()
        .map(|r| {
            (
                r.array::<32>("entropy"),
                String::from_utf8(r.get("mnemonic_utf8").to_vec()).unwrap(),
            )
        })
        .collect()
    }

    #[test]
    fn phrase_trezor_vectors() {
        let _guard = secrets_test_guard();
        let v = vectors();
        assert_eq!(v.len(), 8);
        for (entropy, mnemonic) in &v {
            let vk = VaultKey::from_bytes(*entropy);
            let phrase = RecoveryPhrase::from_vault_key(&vk).unwrap();
            assert_eq!(phrase.expose_secret(), mnemonic);
            let back = VaultKey::from_recovery_phrase(mnemonic.as_bytes()).unwrap();
            assert_eq!(back.bytes(), *entropy);
        }
    }

    proptest! {
        #[test]
        fn phrase_round_trip(bytes in any::<[u8; 32]>()) {
            let _guard = secrets_test_guard();
            let vk = VaultKey::from_bytes(bytes);
            let phrase = RecoveryPhrase::from_vault_key(&vk).unwrap();
            prop_assert_eq!(phrase.expose_secret().split(' ').count(), 24);
            let back = VaultKey::from_recovery_phrase(phrase.expose_secret().as_bytes()).unwrap();
            prop_assert_eq!(back.bytes(), bytes);
        }
    }

    #[test]
    fn phrase_accepts_case_and_whitespace_variants() {
        let _guard = secrets_test_guard();
        let (entropy, mnemonic) = vectors().remove(1);
        let words: Vec<&str> = mnemonic.split(' ').collect();
        let variants = [
            mnemonic.to_uppercase(),
            words
                .iter()
                .enumerate()
                .map(|(i, w)| {
                    if i % 2 == 0 {
                        w.to_uppercase()
                    } else {
                        (*w).to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
            format!("  {}\n", words.join("\t \n")),
            words.join("\r\n"),
        ];
        for v in variants {
            let vk = VaultKey::from_recovery_phrase(v.as_bytes()).unwrap();
            assert_eq!(vk.bytes(), entropy, "{v:?}");
        }
    }

    #[test]
    fn phrase_rejects_malformed_input() {
        let _guard = secrets_test_guard();
        let (_, mnemonic) = vectors().remove(0);
        let words: Vec<&str> = mnemonic.split(' ').collect();
        let wrong = |s: &str| VaultKey::from_recovery_phrase(s.as_bytes()).map(|_| ());
        assert_eq!(wrong(&words[..23].join(" ")), Err(CryptoError::WrongPhrase));
        assert_eq!(
            wrong(&format!("{mnemonic} {}", words[0])),
            Err(CryptoError::WrongPhrase)
        );
        assert_eq!(wrong(""), Err(CryptoError::WrongPhrase));
        assert_eq!(wrong(" \n\t "), Err(CryptoError::WrongPhrase));
        let replace = |i: usize, w: &str| {
            let mut ws = words.clone();
            ws[i] = w;
            ws.join(" ")
        };
        // Not in the list; too long; not letters; not ASCII.
        assert_eq!(wrong(&replace(5, "qwertyu")), Err(CryptoError::WrongPhrase));
        assert_eq!(
            wrong(&replace(5, "abandons")),
            Err(CryptoError::WrongPhrase)
        );
        assert_eq!(
            wrong(&replace(5, "abandonab")),
            Err(CryptoError::WrongPhrase)
        );
        assert_eq!(wrong(&replace(5, "aban1on")), Err(CryptoError::WrongPhrase));
        assert_eq!(wrong(&replace(5, "abandón")), Err(CryptoError::WrongPhrase));
        // A 4-letter abbreviation is not accepted.
        assert_eq!(wrong(&replace(0, "aban")), Err(CryptoError::WrongPhrase));
        let mut nul = mnemonic.clone().into_bytes();
        nul[3] = 0;
        assert_eq!(
            VaultKey::from_recovery_phrase(&nul).map(|_| ()),
            Err(CryptoError::WrongPhrase)
        );
    }

    #[test]
    fn phrase_checksum_is_enforced() {
        let _guard = secrets_test_guard();
        let list = bip39_english().unwrap();
        let word = |j: usize| {
            let e = &list.padded()[j];
            String::from_utf8(e.iter().copied().take_while(|&b| b != 0).collect()).unwrap()
        };
        let (_, mnemonic) = vectors().remove(0);
        let words: Vec<&str> = mnemonic.split(' ').collect();
        // The last word holds 3 entropy bits and the 8 checksum bits: exactly
        // one last word is valid per value of those 3 bits.
        let mut valid = Vec::new();
        for j in 0..2048 {
            let w = word(j);
            let mut ws = words.clone();
            ws[23] = &w;
            if VaultKey::from_recovery_phrase(ws.join(" ").as_bytes()).is_ok() {
                valid.push(w);
            }
        }
        assert_eq!(valid.len(), 8);
        assert!(valid.iter().any(|w| w == words[23]));
        // A substitution in an earlier word breaks the checksum (find one).
        let broken = (0..2048).map(word).filter(|w| w != words[3]).find_map(|w| {
            let mut ws = words.clone();
            ws[3] = &w;
            let s = ws.join(" ");
            (VaultKey::from_recovery_phrase(s.as_bytes()).map(|_| ())
                == Err(CryptoError::WrongPhrase))
            .then_some(s)
        });
        assert!(broken.is_some());
    }

    #[test]
    fn phrase_words_and_confirmation() {
        let _guard = secrets_test_guard();
        let (entropy, mnemonic) = vectors().remove(2);
        let words: Vec<&str> = mnemonic.split(' ').collect();
        let phrase = RecoveryPhrase::from_vault_key(&VaultKey::from_bytes(entropy)).unwrap();
        assert_eq!(phrase.expose_word(0), Some(words[0]));
        assert_eq!(phrase.expose_word(23), Some(words[23]));
        assert_eq!(phrase.expose_word(24), None);
        for (i, w) in words.iter().enumerate() {
            assert_eq!(phrase.confirm_word(i, w.as_bytes()), Ok(()));
        }
        assert_eq!(
            phrase.confirm_word(4, format!(" {}\n", words[4].to_uppercase()).as_bytes()),
            Ok(())
        );
        let other = if words[4] == "zoo" { "abandon" } else { "zoo" };
        assert_eq!(
            phrase.confirm_word(4, other.as_bytes()),
            Err(CryptoError::WrongPhrase)
        );
        // Another position's word, empty input, two words, a prefix.
        let shifted = (0..24).find(|&i| words[i] != words[4]).unwrap();
        assert_eq!(
            phrase.confirm_word(4, words[shifted].as_bytes()),
            Err(CryptoError::WrongPhrase)
        );
        assert_eq!(phrase.confirm_word(4, b""), Err(CryptoError::WrongPhrase));
        assert_eq!(
            phrase.confirm_word(4, format!("{0} {0}", words[4]).as_bytes()),
            Err(CryptoError::WrongPhrase)
        );
        assert_eq!(
            phrase.confirm_word(4, &words[4].as_bytes()[..words[4].len() - 1]),
            Err(CryptoError::WrongPhrase)
        );
        assert_eq!(
            phrase.confirm_word(24, words[0].as_bytes()),
            Err(CryptoError::Internal)
        );
        assert_eq!(format!("{phrase:?}"), "RecoveryPhrase(<redacted>)");
    }

    #[test]
    fn phrase_index_packing_round_trips() {
        let mut packed = [0u8; PACKED_LEN];
        let indices: Vec<u16> = (0..24).map(|i| (i * 89 + 7) % 2048).collect();
        for (i, &x) in indices.iter().enumerate() {
            write_index(&mut packed, i, x).unwrap();
        }
        for (i, &x) in indices.iter().enumerate() {
            assert_eq!(read_index(&packed, i).unwrap(), x);
        }
        assert_eq!(packed[33..], [0, 0]);
    }
}
