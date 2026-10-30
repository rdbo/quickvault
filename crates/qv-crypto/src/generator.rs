// SPDX-License-Identifier: AGPL-3.0-or-later

//! The password generator (spec 0010): random characters, passphrases and
//! PINs.
//!
//! - **Randomness** comes only from the OS CSPRNG ([`crate::fill_random`]).
//!   Indices are drawn by rejection sampling (the `arc4random_uniform`
//!   method), never with a bare `% n` (0010 §1.2). The RNG sits behind a
//!   crate-private trait, so deterministic RNGs exist only in this crate's
//!   tests (§1.3).
//! - **Settings are validated in full before any randomness is used**, on
//!   every call, since defaults may come from synced vault metadata
//!   (§2.1.3).
//! - **`require_each_class`** regenerates the whole password until every
//!   enabled class occurs, at most 10,000 times. A missing class is never
//!   patched in (§2.1.2).
//! - **Entropy** is exact (§3.1), including the `require_each_class` case,
//!   by inclusion–exclusion over the enabled classes.
//! - **Generated values** live in locked, zeroizing memory and are never
//!   kept after use: there is no history (§6).
//!
//! Timing: alphabet and word-list lookups are indexed by the secret draw. That
//! is a cache-timing channel only for code running beside us as the same user
//! while unlocked, which the threat model puts out of scope (0001).
//!
//! | [`GeneratorError`] | CLI exit code (0011 §6) |
//! |--------------------|-------------------------|
//! | `LengthOutOfRange`, `NoClassEnabled`, `RequiredClassEmpty`, `TooFewPositions`, `AlphabetTooSmall`, `WordCountOutOfRange`, `InvalidSeparator` | 2 (usage) |
//! | `Exhausted`, `Rng`, `Internal` | 1 |
//!
//! Generated values cannot be cloned, compared or displayed:
//!
//! ```compile_fail
//! let g = qv_crypto::generate(&Default::default()).unwrap();
//! let _ = g.clone();
//! ```
//!
//! ```compile_fail
//! let a = qv_crypto::generate(&Default::default()).unwrap();
//! let b = qv_crypto::generate(&Default::default()).unwrap();
//! let _ = a == b;
//! ```
//!
//! ```compile_fail
//! let g = qv_crypto::generate(&Default::default()).unwrap();
//! let _ = format!("{g}");
//! ```
//!
//! ```
//! let g = qv_crypto::generate(&Default::default()).unwrap();
//! assert_eq!(g.expose_secret().len(), 24);
//! assert_eq!(format!("{g:?}"), "Generated(<redacted>)");
//! ```

use core::fmt;
use core::ops::RangeInclusive;

use zeroize::Zeroizing;

use crate::memory::SecretBytes;
use crate::rng::{RngError, fill_random};
use crate::wordlist::{WordList, eff_large};

const CHARACTER_LENGTH: RangeInclusive<u32> = 8..=256;
const PASSPHRASE_WORDS: RangeInclusive<u32> = 3..=20;
const PIN_LENGTH: RangeInclusive<u32> = 4..=32;
/// The smallest allowed character alphabet (0010 §2.1.3).
const MIN_ALPHABET: usize = 10;
/// Whole-password attempts for `require_each_class` (0010 §2.1.3).
const MAX_ATTEMPTS: u32 = 10_000;
/// Rejected draws per index before giving up. An honest RNG rejects with
/// probability below 2^-16 per draw, so 64 rejections in a row never happen.
const MAX_DRAW_REJECTIONS: u32 = 64;
/// Look-alike characters removed by `exclude_ambiguous` (0010 §2.1).
const AMBIGUOUS: &[u8] = b"0Oo1lI|`'\"";
/// Settings below this many bits get a warning (0010 §4.1).
pub const WARN_BELOW_BITS: f64 = 64.0;

/// What to generate. Revalidated on every use (0010 §2.1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneratorSettings {
    /// Random characters (0010 §2.1).
    Characters(CharacterSettings),
    /// Words from a list (0010 §2.2).
    Passphrase(PassphraseSettings),
    /// Digits only (0010 §2.3).
    Pin(PinSettings),
}

impl Default for GeneratorSettings {
    fn default() -> Self {
        Self::Characters(CharacterSettings::default())
    }
}

/// Random-character settings (0010 §2.1). The defaults are the spec's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CharacterSettings {
    /// 8–256 characters; default 24.
    pub length: u32,
    /// `a–z`.
    pub lowercase: bool,
    /// `A–Z`.
    pub uppercase: bool,
    /// `0–9`.
    pub digits: bool,
    /// The 32 printable ASCII punctuation characters.
    pub symbols: bool,
    /// Removes `0 O o 1 l I | ` ' "`.
    pub exclude_ambiguous: bool,
    /// Characters to remove. Non-ASCII characters match nothing.
    pub exclude_chars: String,
    /// At least one character from every enabled class.
    pub require_each_class: bool,
}

impl Default for CharacterSettings {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            exclude_chars: String::new(),
            require_each_class: true,
        }
    }
}

/// Passphrase settings (0010 §2.2). The defaults are the spec's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseSettings {
    /// 3–20 words; default 6.
    pub words: u32,
    /// The word list; default `eff-large`.
    pub wordlist: WordListId,
    /// One printable ASCII character that occurs in no output word; default `.`.
    pub separator: char,
    /// Capitalization; default none.
    pub capitalize: Capitalization,
    /// Appends one random digit to one random word; default off.
    pub append_digit: bool,
}

impl Default for PassphraseSettings {
    fn default() -> Self {
        Self {
            words: 6,
            wordlist: WordListId::EffLarge,
            separator: '.',
            capitalize: Capitalization::None,
            append_digit: false,
        }
    }
}

/// PIN settings (0010 §2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinSettings {
    /// 4–32 digits; default 6.
    pub length: u32,
}

impl Default for PinSettings {
    fn default() -> Self {
        Self { length: 6 }
    }
}

/// A passphrase word list (0010 §2.2). English only in v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WordListId {
    /// The EFF large list: 7,776 words, ≈ 12.9 bits per word.
    EffLarge,
}

/// Passphrase capitalization (0010 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capitalization {
    /// Words as in the list (lowercase).
    None,
    /// The first letter of each word in uppercase.
    FirstLetter,
}

/// Why generation failed. No variant carries data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneratorError {
    /// A length is outside its allowed range.
    LengthOutOfRange,
    /// No character class is enabled.
    NoClassEnabled,
    /// `require_each_class` is on, but exclusions emptied an enabled class.
    RequiredClassEmpty,
    /// The length is smaller than the number of required classes.
    TooFewPositions,
    /// Fewer than 10 characters remain in the alphabet.
    AlphabetTooSmall,
    /// The word count is outside 3–20.
    WordCountOutOfRange,
    /// The separator is not printable ASCII, or occurs in an output word.
    InvalidSeparator,
    /// The retry bound was reached; nothing was generated.
    Exhausted,
    /// The OS RNG failed (0002 §7.1).
    Rng,
    /// An embedded word list failed its integrity check, or a bug.
    Internal,
}

impl fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LengthOutOfRange => "length out of range",
            Self::NoClassEnabled => "no character class enabled",
            Self::RequiredClassEmpty => "a required character class is empty after exclusions",
            Self::TooFewPositions => "length too short for the required character classes",
            Self::AlphabetTooSmall => "fewer than 10 characters to choose from",
            Self::WordCountOutOfRange => "word count out of range",
            Self::InvalidSeparator => "invalid separator",
            Self::Exhausted => "generation retries exhausted",
            Self::Rng => "random number generator failure",
            Self::Internal => "internal generator error",
        })
    }
}

impl std::error::Error for GeneratorError {}

impl From<RngError> for GeneratorError {
    fn from(_: RngError) -> Self {
        Self::Rng
    }
}

/// Strength labels for exact entropy (0010 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Below 50 bits.
    Weak,
    /// 50 to below 70 bits.
    Fair,
    /// 70 to below 90 bits.
    Strong,
    /// 90 bits or more.
    VeryStrong,
}

impl Strength {
    /// The label for `bits` (NaN counts as weak).
    pub fn from_bits(bits: f64) -> Self {
        if bits >= 90.0 {
            Self::VeryStrong
        } else if bits >= 70.0 {
            Self::Strong
        } else if bits >= 50.0 {
            Self::Fair
        } else {
            Self::Weak
        }
    }
}

/// The exact entropy of some settings, with its label and warning.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Estimate {
    /// Exact entropy in bits (0010 §3.1).
    pub bits: f64,
    /// The label (0010 §3.3).
    pub strength: Strength,
    /// Below [`WARN_BELOW_BITS`]: clients warn but allow (0010 §4.1).
    pub warn: bool,
}

impl Estimate {
    fn from_bits(bits: f64) -> Self {
        Self {
            bits,
            strength: Strength::from_bits(bits),
            warn: bits < WARN_BELOW_BITS || bits.is_nan(),
        }
    }
}

/// A generated password, passphrase or PIN (ASCII), in locked memory.
///
/// No `Clone`, `PartialEq` or `Display`; `Debug` is redacted (0010 §6).
pub struct Generated {
    value: SecretBytes,
    estimate: Estimate,
}

impl Generated {
    /// The generated value.
    pub fn expose_secret(&self) -> &str {
        // Always ASCII by construction.
        core::str::from_utf8(self.value.expose_secret()).unwrap_or_default()
    }

    /// The exact entropy of the settings it was generated with.
    pub fn estimate(&self) -> Estimate {
        self.estimate
    }
}

impl fmt::Debug for Generated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Generated(<redacted>)")
    }
}

/// Validates `settings` and returns their exact entropy. Uses no randomness.
pub fn estimate(settings: &GeneratorSettings) -> Result<Estimate, GeneratorError> {
    let bits = match settings {
        GeneratorSettings::Characters(s) => {
            let alphabet = character_alphabet(s)?;
            char_entropy(&alphabet.class_sizes, s.length, s.require_each_class)
        }
        GeneratorSettings::Passphrase(s) => passphrase_entropy(s, passphrase_list(s)?),
        GeneratorSettings::Pin(s) => {
            check_range(s.length, PIN_LENGTH)?;
            f64::from(s.length) * 10f64.log2()
        }
    };
    Ok(Estimate::from_bits(bits))
}

/// Validates `settings`, then generates a value from the OS CSPRNG.
pub fn generate(settings: &GeneratorSettings) -> Result<Generated, GeneratorError> {
    generate_with(&mut OsRandom, settings)
}

/// A source of uniformly random bytes. Crate-private: production code uses
/// only [`OsRandom`]; deterministic sources exist only in tests (0010 §1.3).
pub(crate) trait RandomSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError>;
}

/// The OS CSPRNG (0010 §1.1).
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        fill_random(out)
    }
}

/// A uniform integer in `0..n` by rejection sampling: draws below
/// `2^32 mod n` are rejected, so every residue is equally likely.
pub(crate) fn uniform_below(rng: &mut impl RandomSource, n: u32) -> Result<u32, GeneratorError> {
    if n == 0 {
        return Err(GeneratorError::Internal);
    }
    let min = n.wrapping_neg() % n;
    let mut draw = Zeroizing::new([0u8; 4]);
    for _ in 0..MAX_DRAW_REJECTIONS {
        rng.fill(&mut draw[..])?;
        let x = u32::from_be_bytes(*draw);
        if x >= min {
            return Ok(x % n);
        }
    }
    Err(GeneratorError::Exhausted)
}

/// Validates `settings`, then generates from `rng`.
pub(crate) fn generate_with(
    rng: &mut impl RandomSource,
    settings: &GeneratorSettings,
) -> Result<Generated, GeneratorError> {
    let estimate = estimate(settings)?;
    let value = match settings {
        GeneratorSettings::Characters(s) => {
            let alphabet = character_alphabet(s)?;
            sample_characters(rng, &alphabet, s.length, s.require_each_class)?
        }
        GeneratorSettings::Passphrase(s) => sample_passphrase(rng, s, passphrase_list(s)?)?,
        GeneratorSettings::Pin(s) => sample_pin(rng, s.length)?,
    };
    Ok(Generated { value, estimate })
}

fn check_range(value: u32, range: RangeInclusive<u32>) -> Result<(), GeneratorError> {
    if range.contains(&value) {
        Ok(())
    } else {
        Err(GeneratorError::LengthOutOfRange)
    }
}

/// The length must cover one position per required class (0010 §2.1.3).
pub(crate) fn check_positions(length: u32, required: usize) -> Result<(), GeneratorError> {
    if usize::try_from(length).is_ok_and(|l| l >= required) {
        Ok(())
    } else {
        Err(GeneratorError::TooFewPositions)
    }
}

/// A character alphabet split into disjoint classes.
pub(crate) struct Alphabet {
    /// Every character, class by class.
    chars: Vec<u8>,
    /// The size of each class, in the same order.
    class_sizes: Vec<usize>,
    /// For each ASCII byte, the bit of its class (0 if not in the alphabet).
    class_bit: [u8; 128],
    /// All class bits set: what `require_each_class` must see.
    all_classes: u8,
}

impl Alphabet {
    /// Builds an alphabet from up to 8 disjoint, nonempty classes of ASCII
    /// bytes.
    pub(crate) fn from_classes(classes: &[Vec<u8>]) -> Result<Self, GeneratorError> {
        let mut alphabet = Self {
            chars: Vec::new(),
            class_sizes: Vec::new(),
            class_bit: [0; 128],
            all_classes: 0,
        };
        for (i, class) in classes.iter().enumerate() {
            let bit = u32::try_from(i)
                .ok()
                .and_then(|i| 1u8.checked_shl(i))
                .ok_or(GeneratorError::Internal)?;
            for &b in class {
                let slot = alphabet
                    .class_bit
                    .get_mut(usize::from(b))
                    .ok_or(GeneratorError::Internal)?;
                if *slot != 0 {
                    return Err(GeneratorError::Internal);
                }
                *slot = bit;
            }
            alphabet.chars.extend_from_slice(class);
            alphabet.class_sizes.push(class.len());
            alphabet.all_classes |= bit;
        }
        Ok(alphabet)
    }
}

/// Whether a byte belongs to a character class.
type ClassMember = fn(&u8) -> bool;

/// Validates character settings and builds the alphabet. Checks run in a
/// fixed order: length, any class enabled, required classes nonempty and
/// enough positions, then the alphabet size.
fn character_alphabet(s: &CharacterSettings) -> Result<Alphabet, GeneratorError> {
    check_range(s.length, CHARACTER_LENGTH)?;
    let members: [(bool, ClassMember); 4] = [
        (s.lowercase, u8::is_ascii_lowercase),
        (s.uppercase, u8::is_ascii_uppercase),
        (s.digits, u8::is_ascii_digit),
        (s.symbols, u8::is_ascii_punctuation),
    ];
    if !members.iter().any(|(on, _)| *on) {
        return Err(GeneratorError::NoClassEnabled);
    }
    let mut excluded = 0u128;
    if s.exclude_ambiguous {
        for &b in AMBIGUOUS {
            excluded |= 1u128 << b;
        }
    }
    for c in s.exclude_chars.chars().filter(char::is_ascii) {
        excluded |= 1u128 << u32::from(c);
    }
    let classes: Vec<Vec<u8>> = members
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, member)| {
            (0x21u8..=0x7e)
                .filter(|b| member(b) && excluded & (1u128 << b) == 0)
                .collect()
        })
        .collect();
    if s.require_each_class {
        if classes.iter().any(Vec::is_empty) {
            return Err(GeneratorError::RequiredClassEmpty);
        }
        check_positions(s.length, classes.len())?;
    }
    let classes: Vec<Vec<u8>> = classes.into_iter().filter(|c| !c.is_empty()).collect();
    let alphabet = Alphabet::from_classes(&classes)?;
    if alphabet.chars.len() < MIN_ALPHABET {
        return Err(GeneratorError::AlphabetTooSmall);
    }
    Ok(alphabet)
}

/// `L·log2 N`, or with `require_each_class` the exact
/// `log2(#strings containing every class)` by inclusion–exclusion.
pub(crate) fn char_entropy(class_sizes: &[usize], length: u32, require: bool) -> f64 {
    let total: usize = class_sizes.iter().sum();
    let n = total as f64;
    let base = f64::from(length) * n.log2();
    if !require {
        return base;
    }
    let k = class_sizes.len();
    let mut fraction = 0.0f64;
    for mask in 0u32..(1 << k) {
        let missing: usize = class_sizes
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, &c)| c)
            .sum();
        let term = (1.0 - missing as f64 / n).powi(i32::try_from(length).unwrap_or(i32::MAX));
        if mask.count_ones() % 2 == 0 {
            fraction += term;
        } else {
            fraction -= term;
        }
    }
    base + fraction.log2()
}

fn sample_characters(
    rng: &mut impl RandomSource,
    alphabet: &Alphabet,
    length: u32,
    require: bool,
) -> Result<SecretBytes, GeneratorError> {
    let n = u32::try_from(alphabet.chars.len()).map_err(|_| GeneratorError::Internal)?;
    let len = usize::try_from(length).map_err(|_| GeneratorError::Internal)?;
    let mut out = SecretBytes::zeroed(len);
    for _ in 0..MAX_ATTEMPTS {
        let mut seen = 0u8;
        for slot in out.expose_secret_mut().iter_mut() {
            let i =
                usize::try_from(uniform_below(rng, n)?).map_err(|_| GeneratorError::Internal)?;
            let c = *alphabet.chars.get(i).ok_or(GeneratorError::Internal)?;
            *slot = c;
            seen |= alphabet
                .class_bit
                .get(usize::from(c))
                .copied()
                .unwrap_or_default();
        }
        if !require || seen == alphabet.all_classes {
            return Ok(out);
        }
        // Discard the whole attempt (the next one overwrites every byte).
    }
    Err(GeneratorError::Exhausted)
}

/// Validates passphrase settings and returns the word list.
fn passphrase_list(s: &PassphraseSettings) -> Result<&'static WordList<'static>, GeneratorError> {
    if !PASSPHRASE_WORDS.contains(&s.words) {
        return Err(GeneratorError::WordCountOutOfRange);
    }
    let list = match s.wordlist {
        WordListId::EffLarge => eff_large().map_err(|_| GeneratorError::Internal)?,
    };
    let sep = u8::try_from(u32::from(s.separator)).map_err(|_| GeneratorError::InvalidSeparator)?;
    let forbidden = !(0x20..=0x7e).contains(&sep)
        || list.contains_byte(sep)
        || (s.capitalize == Capitalization::FirstLetter && sep.is_ascii_uppercase())
        || (s.append_digit && sep.is_ascii_digit());
    if forbidden {
        return Err(GeneratorError::InvalidSeparator);
    }
    Ok(list)
}

fn passphrase_entropy(s: &PassphraseSettings, list: &WordList<'_>) -> f64 {
    let words = f64::from(s.words);
    let mut bits = words * (list.len() as f64).log2();
    if s.append_digit {
        bits += (10.0 * words).log2();
    }
    bits
}

fn sample_passphrase(
    rng: &mut impl RandomSource,
    s: &PassphraseSettings,
    list: &WordList<'_>,
) -> Result<SecretBytes, GeneratorError> {
    let internal = |_| GeneratorError::Internal;
    let words = usize::try_from(s.words).map_err(internal)?;
    let n = u32::try_from(list.len()).map_err(internal)?;
    // Word indices, then the digit's word position and the digit.
    let mut indices = Zeroizing::new([0u16; 20]);
    let mut digit = Zeroizing::new([0u8; 2]);
    for index in indices.get_mut(..words).ok_or(GeneratorError::Internal)? {
        *index = u16::try_from(uniform_below(rng, n)?).map_err(internal)?;
    }
    if s.append_digit {
        digit[0] = u8::try_from(uniform_below(rng, s.words)?).map_err(internal)?;
        digit[1] = u8::try_from(uniform_below(rng, 10)?).map_err(internal)?;
    }
    let chosen = indices.get(..words).ok_or(GeneratorError::Internal)?;
    let mut total = words - 1 + usize::from(s.append_digit);
    for &i in chosen {
        total += list
            .word(usize::from(i))
            .ok_or(GeneratorError::Internal)?
            .len();
    }
    let sep = u8::try_from(u32::from(s.separator)).map_err(internal)?;
    SecretBytes::try_init(total, |out| {
        let mut pos = 0usize;
        for (k, &i) in chosen.iter().enumerate() {
            if k > 0 {
                *out.get_mut(pos).ok_or(GeneratorError::Internal)? = sep;
                pos += 1;
            }
            let word = list.word(usize::from(i)).ok_or(GeneratorError::Internal)?;
            let end = pos + word.len();
            let dst = out.get_mut(pos..end).ok_or(GeneratorError::Internal)?;
            dst.copy_from_slice(word.as_bytes());
            if s.capitalize == Capitalization::FirstLetter
                && let Some(first) = dst.first_mut()
            {
                first.make_ascii_uppercase();
            }
            pos = end;
            if s.append_digit && usize::from(digit[0]) == k {
                *out.get_mut(pos).ok_or(GeneratorError::Internal)? = b'0' + digit[1];
                pos += 1;
            }
        }
        if pos == total {
            Ok(())
        } else {
            Err(GeneratorError::Internal)
        }
    })
}

fn sample_pin(rng: &mut impl RandomSource, length: u32) -> Result<SecretBytes, GeneratorError> {
    let len = usize::try_from(length).map_err(|_| GeneratorError::Internal)?;
    let mut out = SecretBytes::zeroed(len);
    for slot in out.expose_secret_mut().iter_mut() {
        let d = u8::try_from(uniform_below(rng, 10)?).map_err(|_| GeneratorError::Internal)?;
        *slot = b'0' + d;
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod test_rng {
    //! Deterministic and failing RNGs. Test-only (0010 §1.3).

    use super::RandomSource;
    use crate::primitives::sha256;
    use crate::rng::RngError;

    /// SHA-256 counter mode: block i = SHA-256(seed ‖ u64_be(i)).
    pub(crate) struct TestRng {
        seed: [u8; 32],
        counter: u64,
        block: [u8; 32],
        pos: usize,
    }

    impl TestRng {
        pub(crate) fn new(seed: u8) -> Self {
            Self {
                seed: [seed; 32],
                counter: 0,
                block: [0; 32],
                pos: 32,
            }
        }
    }

    impl RandomSource for TestRng {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
            for b in out {
                if self.pos == 32 {
                    let mut msg = self.seed.to_vec();
                    msg.extend_from_slice(&self.counter.to_be_bytes());
                    sha256(&msg, &mut self.block);
                    self.counter += 1;
                    self.pos = 0;
                }
                *b = self.block[self.pos];
                self.pos += 1;
            }
            Ok(())
        }
    }

    /// Counts the bytes drawn from `inner`.
    pub(crate) struct CountingRng<R> {
        pub(crate) inner: R,
        pub(crate) bytes: usize,
    }

    impl<R: RandomSource> RandomSource for CountingRng<R> {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
            self.bytes += out.len();
            self.inner.fill(out)
        }
    }

    /// Repeats one 4-byte draw forever.
    pub(crate) struct ConstRng(pub(crate) u32);

    impl RandomSource for ConstRng {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
            let draw = self.0.to_be_bytes();
            for (i, b) in out.iter_mut().enumerate() {
                *b = draw[i % 4];
            }
            Ok(())
        }
    }

    /// Always fails.
    pub(crate) struct FailingRng;

    impl RandomSource for FailingRng {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), RngError> {
            Err(crate::rng::test_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_rng::{ConstRng, CountingRng, FailingRng, TestRng};
    use super::*;
    use crate::memory::secrets_test_guard;

    fn chars(f: impl FnOnce(&mut CharacterSettings)) -> GeneratorSettings {
        let mut s = CharacterSettings::default();
        f(&mut s);
        GeneratorSettings::Characters(s)
    }

    fn phrase(f: impl FnOnce(&mut PassphraseSettings)) -> GeneratorSettings {
        let mut s = PassphraseSettings::default();
        f(&mut s);
        GeneratorSettings::Passphrase(s)
    }

    fn pin(length: u32) -> GeneratorSettings {
        GeneratorSettings::Pin(PinSettings { length })
    }

    /// Rejected by `estimate`, and by `generate_with` without touching the RNG.
    fn assert_rejected(settings: GeneratorSettings, err: GeneratorError) {
        let _guard = secrets_test_guard();
        assert_eq!(estimate(&settings), Err(err), "{settings:?}");
        let mut rng = CountingRng {
            inner: TestRng::new(1),
            bytes: 0,
        };
        assert_eq!(
            generate_with(&mut rng, &settings).map(|_| ()),
            Err(err),
            "{settings:?}"
        );
        assert_eq!(rng.bytes, 0, "RNG used before validation: {settings:?}");
    }

    fn assert_accepted(settings: GeneratorSettings) {
        let _guard = secrets_test_guard();
        assert!(estimate(&settings).is_ok(), "{settings:?}");
        assert!(
            generate_with(&mut TestRng::new(2), &settings).is_ok(),
            "{settings:?}"
        );
    }

    #[test]
    fn generator_defaults_are_the_spec_defaults() {
        assert_eq!(
            GeneratorSettings::default(),
            GeneratorSettings::Characters(CharacterSettings {
                length: 24,
                lowercase: true,
                uppercase: true,
                digits: true,
                symbols: true,
                exclude_ambiguous: false,
                exclude_chars: String::new(),
                require_each_class: true,
            })
        );
        let p = PassphraseSettings::default();
        assert_eq!(
            (
                p.words,
                p.wordlist,
                p.separator,
                p.capitalize,
                p.append_digit
            ),
            (6, WordListId::EffLarge, '.', Capitalization::None, false)
        );
        assert_eq!(PinSettings::default().length, 6);
    }

    #[test]
    fn generator_range_boundaries() {
        use GeneratorError::{LengthOutOfRange, WordCountOutOfRange};
        for bad in [0, 7, 257, u32::MAX] {
            assert_rejected(chars(|s| s.length = bad), LengthOutOfRange);
        }
        for good in [8, 256] {
            assert_accepted(chars(|s| s.length = good));
        }
        for bad in [0, 2, 21, u32::MAX] {
            assert_rejected(phrase(|s| s.words = bad), WordCountOutOfRange);
        }
        for good in [3, 20] {
            assert_accepted(phrase(|s| s.words = good));
        }
        for bad in [0, 3, 33, u32::MAX] {
            assert_rejected(pin(bad), LengthOutOfRange);
        }
        for good in [4, 32] {
            assert_accepted(pin(good));
        }
    }

    // 0012 §1: Impossible generator
    #[test]
    fn generator_infeasible_character_settings() {
        use GeneratorError::{AlphabetTooSmall, NoClassEnabled, RequiredClassEmpty};
        let only_digits = |s: &mut CharacterSettings| {
            s.lowercase = false;
            s.uppercase = false;
            s.symbols = false;
        };
        assert_rejected(
            chars(|s| {
                only_digits(s);
                s.digits = false;
            }),
            NoClassEnabled,
        );
        // Exactly 10 characters is allowed.
        assert_accepted(chars(only_digits));
        assert_eq!(
            estimate(&chars(only_digits)).unwrap().bits,
            24.0 * 10f64.log2()
        );
        for require in [true, false] {
            assert_rejected(
                chars(|s| {
                    only_digits(s);
                    s.exclude_chars = "0".into();
                    s.require_each_class = require;
                }),
                AlphabetTooSmall,
            );
            // exclude_ambiguous removes 0 and 1: 8 digits left.
            assert_rejected(
                chars(|s| {
                    only_digits(s);
                    s.exclude_ambiguous = true;
                    s.require_each_class = require;
                }),
                AlphabetTooSmall,
            );
        }
        // A required class emptied by exclusions.
        let no_digits = |s: &mut CharacterSettings| {
            s.uppercase = false;
            s.symbols = false;
            s.exclude_chars = "0123456789".into();
        };
        assert_rejected(chars(no_digits), RequiredClassEmpty);
        assert_accepted(chars(|s| {
            no_digits(s);
            s.require_each_class = false;
        }));
        // Emptied, and the rest too small: the required-class error comes first.
        assert_rejected(
            chars(|s| {
                only_digits(s);
                s.symbols = true;
                s.exclude_chars = "0123456789".into();
                s.exclude_ambiguous = true;
            }),
            RequiredClassEmpty,
        );
    }

    // 0012 §1: Impossible generator
    #[test]
    fn generator_too_few_positions() {
        assert_eq!(check_positions(3, 4), Err(GeneratorError::TooFewPositions));
        assert_eq!(check_positions(0, 1), Err(GeneratorError::TooFewPositions));
        assert_eq!(check_positions(4, 4), Ok(()));
        assert_eq!(check_positions(8, 4), Ok(()));
    }

    #[test]
    fn generator_separators() {
        use GeneratorError::InvalidSeparator;
        // '-' occurs in four EFF words (0010 §2.2.3); letters occur everywhere.
        for bad in ['-', 'a', 'z', '\n', '\t', '\u{7f}', '\0', 'é', '€'] {
            assert_rejected(phrase(|s| s.separator = bad), InvalidSeparator);
        }
        for good in [' ', '.', '_', '~', '!', 'A', '5'] {
            assert_accepted(phrase(|s| s.separator = good));
        }
        assert_rejected(
            phrase(|s| {
                s.separator = 'A';
                s.capitalize = Capitalization::FirstLetter;
            }),
            InvalidSeparator,
        );
        assert_rejected(
            phrase(|s| {
                s.separator = '5';
                s.append_digit = true;
            }),
            InvalidSeparator,
        );
        assert_accepted(phrase(|s| {
            s.separator = '5';
            s.capitalize = Capitalization::FirstLetter;
        }));
    }

    fn bits(settings: &GeneratorSettings) -> f64 {
        estimate(settings).unwrap().bits
    }

    #[test]
    fn generator_entropy_values() {
        // Exact log2 of the number of valid default passwords, computed with
        // Python big integers by inclusion–exclusion.
        let exact = 157.208_361_786_151_36;
        let default = bits(&GeneratorSettings::default());
        assert!((default - exact).abs() < 1e-9, "{default}");
        assert!(default < 24.0 * 94f64.log2());
        assert!(
            (bits(&chars(|s| s.require_each_class = false)) - 157.310_132_440_263_32).abs() < 1e-9
        );
        let p = bits(&phrase(|_| {}));
        assert!((p - 77.548_875_021_634_69).abs() < 1e-9, "{p}");
        let p_digit = bits(&phrase(|s| s.append_digit = true));
        assert!((p_digit - p - 60f64.log2()).abs() < 1e-9);
        let pin6 = estimate(&pin(6)).unwrap();
        assert!((pin6.bits - 19.931_568_569_324_174).abs() < 1e-9);
        assert_eq!(pin6.strength, Strength::Weak);
        assert!(pin6.warn);
        let d = estimate(&GeneratorSettings::default()).unwrap();
        assert_eq!((d.strength, d.warn), (Strength::VeryStrong, false));
        let p = estimate(&phrase(|_| {})).unwrap();
        assert_eq!((p.strength, p.warn), (Strength::Strong, false));
        // 0010 §4.1: fewer than 5 words warns.
        assert!(estimate(&phrase(|s| s.words = 4)).unwrap().warn);
        assert!(!estimate(&phrase(|s| s.words = 5)).unwrap().warn);
    }

    #[test]
    fn generator_entropy_matches_a_brute_force_count() {
        let classes: [usize; 3] = [2, 1, 3];
        let n = classes.iter().sum::<usize>();
        // Class of each symbol 0..n.
        let class_of: Vec<usize> = (0..classes.len())
            .flat_map(|c| std::iter::repeat_n(c, classes[c]))
            .collect();
        for length in 3u32..=6 {
            let total = n.pow(length);
            let valid = (0..total)
                .filter(|&mut_code| {
                    let mut code = mut_code;
                    let mut seen = 0u8;
                    for _ in 0..length {
                        seen |= 1 << class_of[code % n];
                        code /= n;
                    }
                    seen == 0b111
                })
                .count();
            let got = char_entropy(&classes, length, true);
            assert!(
                (got - (valid as f64).log2()).abs() < 1e-9,
                "L={length}: {got} vs {valid}"
            );
            assert_eq!(
                char_entropy(&classes, length, false),
                f64::from(length) * (n as f64).log2()
            );
        }
    }

    #[test]
    fn generator_strength_edges() {
        for (bits, label) in [
            (0.0, Strength::Weak),
            (49.99, Strength::Weak),
            (50.0, Strength::Fair),
            (69.99, Strength::Fair),
            (70.0, Strength::Strong),
            (89.99, Strength::Strong),
            (90.0, Strength::VeryStrong),
            (f64::NAN, Strength::Weak),
        ] {
            assert_eq!(Strength::from_bits(bits), label, "{bits}");
        }
        assert!(Estimate::from_bits(63.99).warn);
        assert!(!Estimate::from_bits(64.0).warn);
        assert!(Estimate::from_bits(f64::NAN).warn);
    }

    #[test]
    fn generator_exclusions() {
        // Non-ASCII exclusions match nothing.
        assert_eq!(
            estimate(&chars(|s| s.exclude_chars = "éü€\u{0}".into())),
            estimate(&chars(|s| s.exclude_chars = "\u{0}".into()))
        );
        assert_eq!(
            estimate(&chars(|s| s.exclude_chars = "éü€".into())),
            estimate(&GeneratorSettings::default())
        );
        let s = chars(|s| {
            s.exclude_chars = "abc".into();
            s.require_each_class = false;
        });
        assert!((bits(&s) - 24.0 * 91f64.log2()).abs() < 1e-9);
        let s = chars(|s| {
            s.exclude_ambiguous = true;
            s.require_each_class = false;
        });
        assert!((bits(&s) - 24.0 * 84f64.log2()).abs() < 1e-9);
    }

    // ---- Step 4: sampling ----

    #[test]
    fn generator_uniform_below_bounds() {
        let _guard = secrets_test_guard();
        // 2^32 mod 7776 > 0, so a draw of 0 is always rejected.
        let mut rng = CountingRng {
            inner: ConstRng(0),
            bytes: 0,
        };
        assert_eq!(
            uniform_below(&mut rng, 7776),
            Err(GeneratorError::Exhausted)
        );
        assert_eq!(rng.bytes, 64 * 4);
        // Powers of two reject nothing.
        assert_eq!(uniform_below(&mut ConstRng(0), 8), Ok(0));
        assert_eq!(uniform_below(&mut ConstRng(u32::MAX), 1), Ok(0));
        assert_eq!(
            uniform_below(&mut ConstRng(0), 0),
            Err(GeneratorError::Internal)
        );
        for n in [1u32, 10, 94, 7776, u32::MAX] {
            let mut rng = TestRng::new(3);
            for _ in 0..1000 {
                assert!(uniform_below(&mut rng, n).unwrap() < n);
            }
        }
    }

    // 0012 §1: Impossible generator
    #[test]
    fn generator_require_each_class_exhausts_without_patching() {
        let _guard = secrets_test_guard();
        // Every draw is index 0 ('a'): no candidate ever has all classes.
        let mut rng = CountingRng {
            inner: ConstRng(94 * 1_000_000),
            bytes: 0,
        };
        assert_eq!(
            generate_with(&mut rng, &GeneratorSettings::default()).map(|_| ()),
            Err(GeneratorError::Exhausted)
        );
        assert_eq!(rng.bytes, 10_000 * 24 * 4);
        // Without the requirement, the same RNG gives 24 × 'a'.
        let g = generate_with(
            &mut ConstRng(94 * 1_000_000),
            &chars(|s| s.require_each_class = false),
        )
        .unwrap();
        assert_eq!(g.expose_secret(), "a".repeat(24));
    }

    #[test]
    fn generator_rng_failure_fails_closed() {
        let _guard = secrets_test_guard();
        for s in [GeneratorSettings::default(), phrase(|_| {}), pin(6)] {
            assert_eq!(
                generate_with(&mut FailingRng, &s).map(|_| ()),
                Err(GeneratorError::Rng)
            );
        }
        assert_eq!(
            GeneratorError::from(crate::rng::test_error()),
            GeneratorError::Rng
        );
    }

    #[test]
    fn generator_character_outputs() {
        let _guard = secrets_test_guard();
        let mut rng = TestRng::new(4);
        for _ in 0..1000 {
            let g = generate_with(&mut rng, &GeneratorSettings::default()).unwrap();
            let v = g.expose_secret().as_bytes();
            assert_eq!(v.len(), 24);
            assert!(v.iter().all(|b| (0x21..=0x7e).contains(b)));
            assert!(v.iter().any(u8::is_ascii_lowercase));
            assert!(v.iter().any(u8::is_ascii_uppercase));
            assert!(v.iter().any(u8::is_ascii_digit));
            assert!(v.iter().any(u8::is_ascii_punctuation));
        }
        let s = chars(|s| {
            s.exclude_ambiguous = true;
            s.exclude_chars = "xyzXYZ#".into();
        });
        for _ in 0..1000 {
            let g = generate_with(&mut rng, &s).unwrap();
            assert!(
                g.expose_secret()
                    .bytes()
                    .all(|b| !AMBIGUOUS.contains(&b) && !b"xyzXYZ#".contains(&b))
            );
        }
    }

    #[test]
    fn generator_passphrase_outputs() {
        let _guard = secrets_test_guard();
        let list = eff_large().unwrap();
        let words: std::collections::HashSet<&str> =
            (0..list.len()).map(|i| list.word(i).unwrap()).collect();
        let mut rng = TestRng::new(5);
        for _ in 0..200 {
            let g = generate_with(&mut rng, &phrase(|_| {})).unwrap();
            let parts: Vec<&str> = g.expose_secret().split('.').collect();
            assert_eq!(parts.len(), 6);
            assert!(parts.iter().all(|w| words.contains(w)));
        }
        // Capitalization touches only the first letter.
        let t_shirt = (0..list.len())
            .find(|&i| list.word(i) == Some("t-shirt"))
            .unwrap() as u32;
        let g = generate_with(
            &mut ConstRng(t_shirt + 7776 * 1000),
            &phrase(|s| {
                s.words = 3;
                s.capitalize = Capitalization::FirstLetter;
            }),
        )
        .unwrap();
        assert_eq!(g.expose_secret(), "T-shirt.T-shirt.T-shirt");
        for _ in 0..200 {
            let g = generate_with(
                &mut rng,
                &phrase(|s| {
                    s.capitalize = Capitalization::FirstLetter;
                    s.separator = ' ';
                }),
            )
            .unwrap();
            for w in g.expose_secret().split(' ') {
                assert!(w.as_bytes()[0].is_ascii_uppercase());
                assert!(words.contains(w.to_ascii_lowercase().as_str()));
                assert!(!w[1..].bytes().any(|b| b.is_ascii_uppercase()));
            }
        }
        // append_digit: exactly one digit, at the end of one word.
        for _ in 0..200 {
            let g = generate_with(&mut rng, &phrase(|s| s.append_digit = true)).unwrap();
            let v = g.expose_secret();
            assert_eq!(v.bytes().filter(u8::is_ascii_digit).count(), 1);
            let parts: Vec<&str> = v.split('.').collect();
            assert_eq!(parts.len(), 6);
            let with_digit: Vec<&&str> = parts
                .iter()
                .filter(|w| w.ends_with(|c: char| c.is_ascii_digit()))
                .collect();
            assert_eq!(with_digit.len(), 1);
            assert!(words.contains(&with_digit[0][..with_digit[0].len() - 1]));
        }
    }

    #[test]
    fn generator_pin_outputs() {
        let _guard = secrets_test_guard();
        let mut rng = TestRng::new(6);
        for length in [4, 6, 32] {
            let g = generate_with(&mut rng, &pin(length)).unwrap();
            assert_eq!(g.expose_secret().len(), length as usize);
            assert!(g.expose_secret().bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn generator_generated_value() {
        let _guard = secrets_test_guard();
        for s in [GeneratorSettings::default(), phrase(|_| {}), pin(6)] {
            let g = generate_with(&mut TestRng::new(7), &s).unwrap();
            assert_eq!(g.estimate(), estimate(&s).unwrap());
            assert_eq!(format!("{g:?}"), "Generated(<redacted>)");
            // The real OS RNG, once per mode.
            let g = generate(&s).unwrap();
            assert!(!g.expose_secret().is_empty());
        }
    }

    #[test]
    fn generator_error_strings_are_fixed() {
        assert_eq!(
            GeneratorError::InvalidSeparator.to_string(),
            "invalid separator"
        );
        assert_eq!(
            GeneratorError::Exhausted.to_string(),
            "generation retries exhausted"
        );
    }

    // ---- Step 5: statistics ----

    mod stats {
        use super::super::test_rng::TestRng;
        use super::super::*;
        use super::{phrase, pin};
        use crate::memory::secrets_test_guard;

        fn chi_square(observed: &[u64], expected: f64) -> f64 {
            observed
                .iter()
                .map(|&o| {
                    let d = o as f64 - expected;
                    d * d / expected
                })
                .sum()
        }

        /// Upper critical value at z = 5 (p ≈ 3·10⁻⁷), Wilson–Hilferty.
        fn critical(bins: usize) -> f64 {
            let df = (bins - 1) as f64;
            let a = 2.0 / (9.0 * df);
            df * (1.0 - a + 5.0 * a.sqrt()).powi(3)
        }

        fn assert_uniform(observed: &[u64], what: &str) {
            let total: u64 = observed.iter().sum();
            let expected = total as f64 / observed.len() as f64;
            let x2 = chi_square(observed, expected);
            let crit = critical(observed.len());
            assert!(x2 < crit, "{what}: chi-square {x2:.1} ≥ {crit:.1}");
        }

        #[test]
        fn stats_uniform_below() {
            for (seed, n) in [(10u8, 10u32), (11, 26), (12, 62), (13, 94), (14, 7776)] {
                let mut rng = TestRng::new(seed);
                let mut bins = vec![0u64; n as usize];
                for _ in 0..(n as usize * 100) {
                    bins[uniform_below(&mut rng, n).unwrap() as usize] += 1;
                }
                assert_uniform(&bins, &format!("uniform_below({n})"));
            }
        }

        #[test]
        fn stats_control_detects_modulo_bias() {
            let mut rng = TestRng::new(15);
            let mut bins = vec![0u64; 94];
            let mut b = [0u8; 1];
            for _ in 0..100_000 {
                rng.fill(&mut b).unwrap();
                bins[usize::from(b[0] % 94)] += 1;
            }
            let expected = 100_000.0 / 94.0;
            assert!(chi_square(&bins, expected) > critical(94));
        }

        #[test]
        fn stats_character_positions() {
            let _guard = secrets_test_guard();
            let alphabet = character_alphabet(&CharacterSettings::default()).unwrap();
            let mut index = [usize::MAX; 128];
            for (i, &c) in alphabet.chars.iter().enumerate() {
                index[usize::from(c)] = i;
            }
            let mut bins = vec![vec![0u64; 94]; 24];
            let mut rng = TestRng::new(16);
            for _ in 0..20_000 {
                let g = generate_with(&mut rng, &GeneratorSettings::default()).unwrap();
                for (pos, b) in g.expose_secret().bytes().enumerate() {
                    bins[pos][index[usize::from(b)]] += 1;
                }
            }
            for (pos, b) in bins.iter().enumerate() {
                assert_uniform(b, &format!("character position {pos}"));
            }
        }

        #[test]
        fn stats_require_each_class_is_uniform_over_valid_strings() {
            let _guard = secrets_test_guard();
            let alphabet = Alphabet::from_classes(&[b"ab".to_vec(), b"c".to_vec()]).unwrap();
            let mut counts = std::collections::BTreeMap::<Vec<u8>, u64>::new();
            let mut rng = TestRng::new(17);
            for _ in 0..18_000 {
                let v = sample_characters(&mut rng, &alphabet, 3, true).unwrap();
                *counts.entry(v.expose_secret().to_vec()).or_default() += 1;
            }
            // 27 strings, minus 8 without 'c', minus 1 without 'a'/'b'.
            assert_eq!(counts.len(), 18);
            for s in counts.keys() {
                assert!(s.contains(&b'c') && s.iter().any(|b| b"ab".contains(b)));
            }
            let observed: Vec<u64> = counts.values().copied().collect();
            assert_uniform(&observed, "valid strings");
        }

        #[test]
        fn stats_passphrase_words() {
            let _guard = secrets_test_guard();
            let list = eff_large().unwrap();
            let index: std::collections::HashMap<&str, usize> = (0..list.len())
                .map(|i| (list.word(i).unwrap(), i))
                .collect();
            let mut positions = vec![vec![0u64; 32]; 6];
            let mut pooled = vec![0u64; 7776];
            let mut rng = TestRng::new(18);
            for _ in 0..60_000 {
                let g = generate_with(&mut rng, &phrase(|_| {})).unwrap();
                for (pos, w) in g.expose_secret().split('.').enumerate() {
                    let i = index[w];
                    positions[pos][i / 243] += 1;
                    pooled[i] += 1;
                }
            }
            for (pos, b) in positions.iter().enumerate() {
                assert_uniform(b, &format!("word position {pos}"));
            }
            assert_uniform(&pooled, "pooled words");
        }

        #[test]
        fn stats_append_digit() {
            let _guard = secrets_test_guard();
            let mut bins = vec![0u64; 60];
            let mut rng = TestRng::new(19);
            let s = phrase(|s| s.append_digit = true);
            for _ in 0..60_000 {
                let g = generate_with(&mut rng, &s).unwrap();
                let (pos, digit) = g
                    .expose_secret()
                    .split('.')
                    .enumerate()
                    .find_map(|(p, w)| {
                        w.bytes()
                            .last()
                            .filter(u8::is_ascii_digit)
                            .map(|d| (p, usize::from(d - b'0')))
                    })
                    .unwrap();
                bins[pos * 10 + digit] += 1;
            }
            assert_uniform(&bins, "(position, digit)");
        }

        #[test]
        fn stats_pin_digits() {
            let _guard = secrets_test_guard();
            let mut bins = vec![vec![0u64; 10]; 6];
            let mut rng = TestRng::new(20);
            for _ in 0..20_000 {
                let g = generate_with(&mut rng, &pin(6)).unwrap();
                for (pos, b) in g.expose_secret().bytes().enumerate() {
                    bins[pos][usize::from(b - b'0')] += 1;
                }
            }
            for (pos, b) in bins.iter().enumerate() {
                assert_uniform(b, &format!("PIN position {pos}"));
            }
        }
    }
}
