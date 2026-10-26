// SPDX-License-Identifier: AGPL-3.0-or-later

//! Embedded word lists (spec 0010 §2.2.2, 0002 §4.1).
//!
//! The files in `data/` are compiled in byte for byte. Before first use, each
//! one's SHA-256 must equal the pinned published hash, and then it must parse
//! strictly. Otherwise the list is unavailable and callers fail closed with
//! [`CryptoError::Internal`]: a corrupted build never generates from, or
//! decodes against, a wrong list. Unit tests pin the same hashes (0010
//! §2.2.2).

use std::sync::OnceLock;

use crate::error::CryptoError;
use crate::primitives::sha256;

const EFF_LARGE: &[u8] = include_bytes!("../data/eff_large_wordlist.txt");
const EFF_LARGE_SHA256: [u8; 32] = [
    0xad, 0xdd, 0x35, 0x53, 0x65, 0x11, 0x59, 0x7a, 0x02, 0xfa, 0x0a, 0x9f, 0xf1, 0xe5, 0x28, 0x46,
    0x77, 0xb8, 0x88, 0x3b, 0x83, 0xe9, 0x86, 0xe4, 0x3f, 0x15, 0xa3, 0xdb, 0x99, 0x6b, 0x90, 0x3e,
];
const BIP39_ENGLISH: &[u8] = include_bytes!("../data/bip39-english.txt");
const BIP39_ENGLISH_SHA256: [u8; 32] = [
    0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
    0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
];

/// Words in the EFF large list (6^5 dice outcomes).
pub(crate) const EFF_LARGE_LEN: usize = 7776;
/// Words in the BIP-39 English list (2^11).
pub(crate) const BIP39_LEN: usize = 2048;
/// The longest BIP-39 English word, in bytes.
pub(crate) const BIP39_MAX_WORD: usize = 8;

/// A parsed word list: words in list order, strictly ascending and unique.
pub(crate) struct WordList<'a> {
    words: Vec<&'a str>,
    /// Bit `b` is set if byte `b` occurs in any word (all bytes are ASCII).
    alphabet: u128,
}

impl<'a> WordList<'a> {
    pub(crate) fn len(&self) -> usize {
        self.words.len()
    }

    pub(crate) fn word(&self, index: usize) -> Option<&'a str> {
        self.words.get(index).copied()
    }

    /// Whether byte `b` occurs in any word.
    pub(crate) fn contains_byte(&self, b: u8) -> bool {
        b < 128 && self.alphabet & (1u128 << b) != 0
    }
}

/// The BIP-39 English list as zero-padded 8-byte entries, for constant-time
/// scans (index = word index).
pub(crate) struct Bip39List {
    padded: Vec<[u8; BIP39_MAX_WORD]>,
}

impl Bip39List {
    pub(crate) fn padded(&self) -> &[[u8; BIP39_MAX_WORD]] {
        &self.padded
    }
}

/// The lines of `bytes`, which must end with exactly one `\n` after the last
/// line.
fn lines(bytes: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
    let body = bytes.strip_suffix(b"\n")?;
    Some(body.split(|&b| b == b'\n'))
}

/// Collects `(word, ...)` lines into a list, requiring strictly ascending
/// words made only of bytes accepted by `allowed`, and exactly `count` of them.
fn build<'a>(
    words: impl Iterator<Item = Option<&'a [u8]>>,
    count: usize,
    allowed: impl Fn(u8) -> bool,
) -> Option<WordList<'a>> {
    let mut list = Vec::with_capacity(count);
    let mut alphabet = 0u128;
    let mut previous: Option<&[u8]> = None;
    for word in words {
        let word = word?;
        if word.is_empty() || !word.iter().all(|&b| allowed(b)) {
            return None;
        }
        if previous.is_some_and(|p| p >= word) {
            return None;
        }
        previous = Some(word);
        for &b in word {
            alphabet |= 1u128 << b;
        }
        list.push(core::str::from_utf8(word).ok()?);
        if list.len() > count {
            return None;
        }
    }
    (list.len() == count).then_some(WordList {
        words: list,
        alphabet,
    })
}

/// Parses the EFF large list: `ddddd\tword` lines, dice numbers `11111` to
/// `66666` in order, words of `a–z` and `-`.
pub(crate) fn parse_eff(bytes: &[u8]) -> Option<WordList<'_>> {
    let mut expected = [b'1'; 5];
    let mut first = true;
    let words = lines(bytes)?.map(move |line| {
        if !first {
            // Advance the expected dice number like a base-6 odometer.
            for d in expected.iter_mut().rev() {
                if *d == b'6' {
                    *d = b'1';
                } else {
                    *d += 1;
                    break;
                }
            }
        }
        first = false;
        let (dice, rest) = line.split_at_checked(5)?;
        let word = rest.strip_prefix(b"\t")?;
        (dice == expected).then_some(word)
    });
    build(words, EFF_LARGE_LEN, |b| {
        b.is_ascii_lowercase() || b == b'-'
    })
}

/// Parses the BIP-39 English list: one word of 1–8 bytes `a–z` per line.
pub(crate) fn parse_bip39(bytes: &[u8]) -> Option<Bip39List> {
    let words = lines(bytes)?.map(|line| (line.len() <= BIP39_MAX_WORD).then_some(line));
    let list = build(words, BIP39_LEN, |b| b.is_ascii_lowercase())?;
    let padded = list
        .words
        .iter()
        .map(|w| {
            let mut entry = [0u8; BIP39_MAX_WORD];
            entry.get_mut(..w.len())?.copy_from_slice(w.as_bytes());
            Some(entry)
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Bip39List { padded })
}

/// Whether `bytes` hash to `expected` (public data; plain comparison).
pub(crate) fn hash_matches(bytes: &[u8], expected: &[u8; 32]) -> bool {
    let mut digest = [0u8; 32];
    sha256(bytes, &mut digest);
    digest == *expected
}

/// The EFF large word list (`eff-large`, 0010 §2.2).
pub(crate) fn eff_large() -> Result<&'static WordList<'static>, CryptoError> {
    static LIST: OnceLock<Option<WordList<'static>>> = OnceLock::new();
    LIST.get_or_init(|| {
        hash_matches(EFF_LARGE, &EFF_LARGE_SHA256)
            .then(|| parse_eff(EFF_LARGE))
            .flatten()
    })
    .as_ref()
    .ok_or(CryptoError::Internal)
}

/// The BIP-39 English word list (0002 §4.1).
pub(crate) fn bip39_english() -> Result<&'static Bip39List, CryptoError> {
    static LIST: OnceLock<Option<Bip39List>> = OnceLock::new();
    LIST.get_or_init(|| {
        hash_matches(BIP39_ENGLISH, &BIP39_ENGLISH_SHA256)
            .then(|| parse_bip39(BIP39_ENGLISH))
            .flatten()
    })
    .as_ref()
    .ok_or(CryptoError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn wordlist_hashes_match_the_published_lists() {
        let mut d = [0u8; 32];
        sha256(EFF_LARGE, &mut d);
        // 0010 §2.2.2.
        assert_eq!(
            hex(&d),
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        sha256(BIP39_ENGLISH, &mut d);
        // bitcoin/bips bip-0039/english.txt.
        assert_eq!(
            hex(&d),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert!(hash_matches(EFF_LARGE, &EFF_LARGE_SHA256));
        assert!(hash_matches(BIP39_ENGLISH, &BIP39_ENGLISH_SHA256));
    }

    #[test]
    fn wordlist_eff_large_structure() {
        let list = eff_large().unwrap();
        assert_eq!(list.len(), EFF_LARGE_LEN);
        assert_eq!(list.word(0), Some("abacus"));
        assert_eq!(list.word(EFF_LARGE_LEN - 1), Some("zoom"));
        assert_eq!(list.word(EFF_LARGE_LEN), None);
        // The alphabet is exactly a–z plus '-' (0010 §2.2.3).
        for b in 0u8..=255 {
            assert_eq!(
                list.contains_byte(b),
                b.is_ascii_lowercase() || b == b'-',
                "byte {b}"
            );
        }
        let hyphenated: Vec<&str> = list
            .words
            .iter()
            .copied()
            .filter(|w| w.contains('-'))
            .collect();
        assert_eq!(hyphenated, ["drop-down", "felt-tip", "t-shirt", "yo-yo"]);
        assert!(
            list.words
                .iter()
                .all(|w| !w.bytes().any(|b| b.is_ascii_digit()))
        );
    }

    #[test]
    fn wordlist_bip39_structure() {
        let list = bip39_english().unwrap();
        assert_eq!(list.padded().len(), BIP39_LEN);
        assert_eq!(&list.padded()[0], b"abandon\0");
        assert_eq!(&list.padded()[BIP39_LEN - 1], b"zoo\0\0\0\0\0");
        // Strictly ascending (so unique), and unique in the first four letters.
        let parsed = build(lines(BIP39_ENGLISH).unwrap().map(Some), BIP39_LEN, |b| {
            b.is_ascii_lowercase()
        })
        .unwrap();
        let prefixes: std::collections::BTreeSet<_> = parsed
            .words
            .iter()
            .map(|w| &w.as_bytes()[..w.len().min(4)])
            .collect();
        assert_eq!(prefixes.len(), BIP39_LEN);
    }

    #[test]
    fn wordlist_rejects_corrupted_copies() {
        // A changed byte breaks the hash.
        let mut changed = EFF_LARGE.to_vec();
        changed[7] ^= 0x01;
        assert!(!hash_matches(&changed, &EFF_LARGE_SHA256));
        let mut changed = BIP39_ENGLISH.to_vec();
        changed[0] = b'b';
        assert!(!hash_matches(&changed, &BIP39_ENGLISH_SHA256));

        // The parsers are strict on their own, too.
        let eff: Vec<&[u8]> = lines(EFF_LARGE).unwrap().collect();
        let join = |ls: &[&[u8]]| {
            let mut v = ls.join(&b'\n');
            v.push(b'\n');
            v
        };
        assert!(parse_eff(&join(&eff)).is_some());
        assert!(parse_eff(&join(&eff[1..])).is_none(), "missing line");
        let mut swapped = eff.clone();
        swapped.swap(10, 11);
        assert!(parse_eff(&join(&swapped)).is_none(), "swapped lines");
        let no_newline = &EFF_LARGE[..EFF_LARGE.len() - 1];
        assert!(parse_eff(no_newline).is_none(), "no final newline");
        let mut digit = EFF_LARGE.to_vec();
        digit[6] = b'1'; // "abacus" → "1bacus"
        assert!(parse_eff(&digit).is_none(), "digit in a word");
        let mut dice = EFF_LARGE.to_vec();
        dice[4] = b'2'; // 11112 on the first line
        assert!(parse_eff(&dice).is_none(), "dice number out of order");

        let bip: Vec<&[u8]> = lines(BIP39_ENGLISH).unwrap().collect();
        assert!(parse_bip39(&join(&bip)).is_some());
        assert!(parse_bip39(&join(&bip[1..])).is_none(), "missing line");
        let mut extra = bip.clone();
        extra.push(b"zzz");
        assert!(parse_bip39(&join(&extra)).is_none(), "extra line");
        let mut swapped = bip.clone();
        swapped.swap(0, 1);
        assert!(parse_bip39(&join(&swapped)).is_none(), "swapped lines");
        let mut long = bip.clone();
        long[2047] = b"zzzzzzzzz";
        assert!(parse_bip39(&join(&long)).is_none(), "9-letter word");
        let mut upper = bip.clone();
        upper[0] = b"Abandon";
        assert!(parse_bip39(&join(&upper)).is_none(), "uppercase");
    }
}
