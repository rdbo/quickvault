# Plan 0006 — Recovery phrase and password generator

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented | 2026-10-25 | 2026-10-25 | 0002 §4, §7.1; 0010 §1–4, §6; 0008 §1–2; 0012 §1 |

## Intent

Roadmap 0002 phase 1.4. The first part is the recovery phrase: encode VK as 24
BIP-39 English words (entropy encoding, not the wallet seed) and decode it
back. The second part is the 0010 generator: unbiased random-character,
passphrase and PIN generation, feasibility checks before any randomness is
used, bounded retries, exact entropy with strength labels and warnings, the
embedded EFF large word list with its SHA-256 check, and generated values held
as secrets. Both live in `qv-crypto`. Frontends will reach them through
`qv-core` from phase 1.8 on.

## Scope

**In scope:**
- `crates/qv-crypto`: modules `wordlist` (embedded lists, integrity check),
  `phrase` (VK ↔ 24 words) and `generator` (settings, validation, entropy,
  strength, sampling). New `CryptoError::WrongPhrase`.
- Embedded data under `crates/qv-crypto/data/`: the published
  `eff_large_wordlist.txt` and the BIP-39 `english.txt`, byte for byte, plus a
  `README.md` with sources, licences and hashes.
- Upstream BIP-39 vectors (Trezor `python-mnemonic`, 256-bit English cases).
- Deterministic statistical tests (chi-square) for every sampling path.
- New dependency `subtle` (roadmap candidate table, phase 1.1 row) for
  constant-time phrase word matching.

**Out of scope:**
- `zxcvbn` estimates for user-typed passwords (0010 §3.2) and the
  master-password acceptance flow (0010 §4.2, 0011 §5.4). Their first
  consumer is the CLI's `init`/`passwd`/`recover` in phase 1.10. `zxcvbn` is not
  in the roadmap's candidate table, so 1.10 must raise it with the owner. The
  roadmap *Revisions* records this.
- Showing the phrase, confirming it or recording a skip (0002 §4.2), and
  redisplay after reauthentication: qv-core (1.8) and the CLI (1.10). This
  phase gives them `RecoveryPhrase::confirm_word`.
- Unlocking a vault with the phrase (the `recover` flow): phase 1.14.
- Storing generator defaults per vault (0010 §5.1) or per entry (§5.2):
  vault settings in 1.5/1.8. This phase defines the settings types and
  revalidates them on every use.
- The UI secret boundary (0010 §6.1, 0008 §4): milestone 2.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| VK's 256 bits + BIP-39 checksum as 24 English words; entropy encoding, not the PBKDF2 seed; no extra passphrase; decode directly to VK | 0002 §4.1 | Accepted | |
| Phrase never logged or persisted in plaintext | 0002 §4.2 | Accepted | Zeroizing types, redacted `Debug`; display/confirm flows later |
| Wrong recovery phrase → exit code 3 | 0011 §6 | Accepted | `CryptoError::WrongPhrase` |
| Randomness from the OS CSPRNG; no user-space PRNG in production | 0010 §1.1, 0002 §7.1 | Accepted | Via `qv_crypto::fill_random` (getrandom, fail closed). 0010 names `rand::rngs::OsRng` as the route; the requirement is the OS CSPRNG, which this is. `rand` is not in the candidate table and adds nothing here |
| Uniform selection by rejection sampling; `% n` forbidden | 0010 §1.2 | Accepted | The `arc4random_uniform` method ("or equivalent" in the spec) |
| RNG behind a trait; deterministic RNG only under `#[cfg(test)]` | 0010 §1.3 | Accepted | Crate-private trait, so no other crate can inject one |
| Character mode: options, ranges, defaults, ASCII only | 0010 §2.1, §2.1.1 | Accepted | |
| `require_each_class` by whole-password rejection, never patching | 0010 §2.1.2 | Accepted | |
| Feasibility before RNG; alphabet ≥ 10; required classes nonempty; length ≥ required classes; ≤ 10,000 attempts, then an error; revalidate at use | 0010 §2.1.3 | Accepted | |
| Passphrase: 3–20 words, eff-large, independent uniform words with repetition, separator, capitalize, append digit | 0010 §2.2, §2.2.1 | Accepted | |
| Embedded EFF list, SHA-256 `addd3553…903e` checked by a unit test | 0010 §2.2.2 | Accepted | Also checked at run time before first use |
| Separator nonempty and absent from all words; forbidden set derived from the embedded list; uniform digit append | 0010 §2.2.3 | Accepted | See *Design*: words as output (after capitalization/digit) |
| PIN: digits, 4–32, default 6; low strength visible | 0010 §2.3 | Accepted | `Estimate::strength` |
| Exact entropy; labels; ≈157 / ≈77 bits for defaults | 0010 §3.1, §3.3, §3.4 | Accepted | `require_each_class` computed exactly (inclusion–exclusion) |
| Warn below 64 bits | 0010 §4.1 | Accepted | `Estimate::warn` |
| Generated values are secrets; no logging; no history | 0010 §6 | Accepted | `Generated` holds `SecretBytes`; nothing kept |
| Zeroizing, redacted buffers; constant-time comparisons | 0008 §1.1, §2 | Draft (D5) | |
| "Impossible generator" row | 0012 §1 | Accepted | |

**Spec changes required:** None. 0010's summary says the generator "is part of
`qv-core`". That describes where frontends reach it, and the cross-phase
invariant already guarantees that. The roadmap's phase entry lets this plan
place the module in `qv-crypto`, next to the RNG and the secret types it needs.
qv-core re-exports it in 1.8. 0010 stays Accepted and not fully implemented
(§3.2, §4.2, §5 storage and §6.1 remain).

## Decisions needed

None. This plan makes the following format and detail choices. Each follows
from the specs; none is an open question:

- **Phrase input normalization.** Split on ASCII whitespace and lowercase ASCII
  letters. Each word must be 1–8 ASCII letters (the longest BIP-39 English
  word has 8). There must be exactly 24 words. Every failure, including the
  checksum, is `WrongPhrase`. Prefix (4-letter) abbreviations are not accepted.
  The encoded phrase is lowercase words separated by single spaces.
- **Separator forbidden set.** 0010 §2.2.3 wants injective output: the
  separator must not occur in any output word. The set is derived from the
  embedded list (for eff-large: `a–z` and `-`), plus `A–Z` when `capitalize`
  is on and `0–9` when `append_digit` is on. The separator must be printable
  ASCII (`0x20–0x7E`, so space is allowed).
- **Strength boundaries for fractional bits.** `< 50` Weak, `< 70` Fair,
  `< 90` Strong, else Very strong. This is the 0010 §3.3 table on real numbers.
- **`exclude_chars`** removes the listed characters. Non-ASCII characters
  match nothing and are ignored.
- **Timing.** Phrase encode and decode look up words with full-table scans
  using `subtle`, with no early exit. The VK checksum comparison is constant
  time. The generator indexes its alphabet and word list directly: a
  secret-indexed table lookup is a cache-timing channel only for a co-resident
  attacker, which is the "malware running as the user while unlocked" case
  that 0001 puts out of scope. The crate docs record this.

## Design

**Components touched:** `qv-crypto` (trusted client; no frontend
dependencies). No new crate, no trust-boundary change. The module graph is
`wordlist` ← `phrase`, `generator`. `phrase` uses `keys::VaultKey`.
`generator` uses `rng` and `memory`.

**Interfaces** (`lib.rs` re-exports the public items):

```rust
// error.rs — one new data-less variant (Display: fixed string).
CryptoError::WrongPhrase, // recovery phrase: word count, unknown word or checksum. CLI 3.

// wordlist.rs (crate-private)
pub(crate) struct WordList {
    words: Vec<&'static str>,      // in list order
    padded: Vec<[u8; 8]>,          // BIP-39 only: zero-padded, for CT scans
    alphabet: u128,                // ASCII bitmask of every byte in any word
}
pub(crate) fn eff_large() -> Result<&'static WordList, CryptoError>;     // Internal if corrupt
pub(crate) fn bip39_english() -> Result<&'static WordList, CryptoError>; // Internal if corrupt
// Each is a `OnceLock<Option<WordList>>`, built on first use: SHA-256 of the
// embedded bytes must equal the pinned constant, then a strict parse.

// phrase.rs
pub const PHRASE_WORDS: usize = 24;
pub struct RecoveryPhrase { /* SecretArray<215>, len */ } // Debug: RecoveryPhrase(<redacted>); no Clone/Display/PartialEq
impl RecoveryPhrase {
    pub fn from_vault_key(vk: &VaultKey) -> Result<Self, CryptoError>;
    pub fn expose_secret(&self) -> &str;                    // "w1 w2 … w24"
    pub fn expose_word(&self, index: usize) -> Option<&str>; // 0-based
    pub fn confirm_word(&self, index: usize, typed: &[u8]) -> Result<(), CryptoError>;
        // normalized like decode; constant-time compare; mismatch → WrongPhrase;
        // index ≥ 24 → Internal (a caller bug)
}
impl VaultKey {
    pub fn from_recovery_phrase(input: &[u8]) -> Result<VaultKey, CryptoError>; // WrongPhrase
}

// generator.rs
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneratorSettings { Characters(CharacterSettings), Passphrase(PassphraseSettings), Pin(PinSettings) }
// Default: Characters(CharacterSettings::default()).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CharacterSettings {
    pub length: u32,              // 8–256, default 24
    pub lowercase: bool, pub uppercase: bool, pub digits: bool, pub symbols: bool, // default on
    pub exclude_ambiguous: bool,  // default off
    pub exclude_chars: String,    // default empty
    pub require_each_class: bool, // default on
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseSettings {
    pub words: u32,               // 3–20, default 6
    pub wordlist: WordListId,     // default EffLarge
    pub separator: char,          // default '.'
    pub capitalize: Capitalization, // default None
    pub append_digit: bool,       // default off
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)] #[non_exhaustive] pub enum WordListId { EffLarge }
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Capitalization { None, FirstLetter }
#[derive(Clone, Debug, PartialEq, Eq)] pub struct PinSettings { pub length: u32 } // 4–32, default 6

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneratorError {      // no data; Display fixed; From<RngError> → Rng
    LengthOutOfRange, NoClassEnabled, RequiredClassEmpty, TooFewPositions, AlphabetTooSmall,
    WordCountOutOfRange, InvalidSeparator,   // settings errors: CLI 2
    Exhausted, Rng, Internal,                // CLI 1
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength { Weak, Fair, Strong, VeryStrong }
impl Strength { pub fn from_bits(bits: f64) -> Self; }
pub const WARN_BELOW_BITS: f64 = 64.0;
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Estimate { pub bits: f64, pub strength: Strength, pub warn: bool }

pub fn estimate(settings: &GeneratorSettings) -> Result<Estimate, GeneratorError>; // validates; no RNG
pub fn generate(settings: &GeneratorSettings) -> Result<Generated, GeneratorError>; // validates, then OS RNG
pub struct Generated { /* SecretBytes (ASCII), Estimate */ } // Debug: Generated(<redacted>); no Clone/Display
impl Generated { pub fn expose_secret(&self) -> &str; pub fn estimate(&self) -> Estimate; }

// crate-private sampling core
pub(crate) trait RandomSource { fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError>; }
pub(crate) struct OsRandom;                     // fill_random; the only production impl
pub(crate) fn uniform_below(rng: &mut impl RandomSource, n: u32) -> Result<u32, GeneratorError>;
pub(crate) fn generate_with(rng: &mut impl RandomSource, s: &GeneratorSettings) -> Result<Generated, GeneratorError>;
```

**Character classes** (exact bytes): lowercase `a–z`, uppercase `A–Z`,
digits `0–9`, symbols the 32 bytes `0x21–0x2F`, `0x3A–0x40`, `0x5B–0x60`,
`0x7B–0x7E`. Ambiguous: `0 O o 1 l I | ` ' "` (10 bytes). With the defaults
the alphabet has 94 characters.

**Data and control flow:**
- **Phrase encode:** `buf = VK ‖ SHA-256(VK)[0]` (33 bytes, in a
  `SecretArray<33>`; the digest goes to a `SecretArray<32>`). Split it into
  twenty-four 11-bit big-endian indices. For each index, scan all 2048 padded
  words with `ConditionallySelectable` and copy out the selected word. Join
  the words with single spaces into the phrase buffer.
- **Phrase decode:** normalize the words into one zero-padded
  `SecretArray<192>` (24 × 8). For each word, scan all 2048 entries with
  `ct_eq` and `conditional_assign` the index, accumulating `found` as a
  `Choice`. Pack the indices back into 33 bytes, recompute
  `SHA-256(entropy)[0]` and compare with `ct_eq`. Branch exactly once on
  `all_found & checksum_ok`: on failure, `WrongPhrase` with every buffer
  wiped. On success, the first 32 bytes go into a `SecretArray<32>` and become
  `VaultKey`. Word-count and per-word length failures exit early: they depend
  on the shape of the typed input, not on VK.
- **`uniform_below(n)`** (`1 ≤ n ≤ 2^16`): `min = n.wrapping_neg() % n`
  (that is, 2^32 mod n). Draw a `u32` from 4 RNG bytes, held in a zeroizing
  array. Accept `x ≥ min` and return `x % n`. Give up after 64 rejections
  with `Exhausted` (the probability for an honest RNG is below 2^-1000).
- **Characters:** validate, then build the alphabet and the class membership.
  Each attempt fills a `SecretBytes` of `length` bytes with
  `alphabet[uniform_below(N)]`. With `require_each_class`, an attempt that
  misses an enabled class is overwritten by the next attempt. After 10,000
  attempts, `Exhausted`. Nothing is ever patched in.
- **Passphrase:** validate (word count, then separator against the forbidden
  set), then draw `words` indices with `uniform_below(7776)`. If
  `append_digit` is on, also draw a word position with `uniform_below(words)`
  and a digit with `uniform_below(10)`. Indices live in a zeroizing
  `[u16; 20]`. Compute the exact output length, then `SecretBytes::try_init`
  writes the words (first letter uppercased if `FirstLetter`), separators and
  the digit appended to the chosen word.
- **PIN:** `length` digits, each `uniform_below(10)`.
- **Entropy** (`estimate`; also attached to every `Generated`). Characters:
  `L·log2 N`. With `require_each_class` and enabled class sizes `c_i`
  (disjoint, summing to `N`), it is
  `L·log2 N + log2 Σ_{S ⊆ classes} (−1)^{|S|} (1 − Σ_{i∈S} c_i / N)^L` in
  `f64` (at most 16 terms). Passphrase: `w·log2 7776`, plus `log2(10·w)` with
  `append_digit`. PIN: `L·log2 10`. `strength = Strength::from_bits(bits)`,
  `warn = bits < 64`.
- **Validation order** (first failure wins; exact variants are tested).
  Characters: length range → `NoClassEnabled` → (with `require_each_class`)
  each enabled class nonempty after exclusions, then `TooFewPositions`
  (length < number of enabled classes) → `AlphabetTooSmall` (< 10).
  Passphrase: `WordCountOutOfRange` → `InvalidSeparator`. PIN: length range.
- No disk writes, no durability ordering.

**Secrets and hostile input:**
- Secret-holding types: `RecoveryPhrase`, normalized phrase input, indices,
  the checksum digest, `Generated`, the RNG draw buffers, the passphrase index
  array. All of these are `SecretArray`/`SecretBytes` or `Zeroizing` arrays.
  They have redacted `Debug` and no `Clone`, `Display` or `PartialEq`.
- Phrase input is borrowed (`&[u8]`). The caller owns its buffer and wipes
  it. Nothing is copied outside zeroizing storage.
- Generator settings may come from synced vault metadata (authenticated but
  written by another device). They are validated in full on every
  `estimate`/`generate` call, before any RNG use.
- The embedded lists are compile-time data. They are still checked by SHA-256
  before parsing, so a corrupted build fails closed (`Internal`) instead of
  generating from a wrong list.

**Errors:** `CryptoError::WrongPhrase` (exit code 3, added to the crate's
error-to-exit-code table). `GeneratorError` is separate because its variants
are settings problems that a frontend reports field by field. Its rustdoc maps
the settings variants to CLI 2 and the rest to 1. No variant carries data.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| `ctutils =0.4.5` (`default-features = false`) — **revised from `subtle`, see *Revisions*** | `CtEq`, `CtAssign`, `Choice` for phrase word scans and the checksum compare | `subtle 2.6.1` (planned first; `BSD-3-Clause` is outside the `deny.toml` allow-list); hand-written masks (the optimizer may reintroduce branches) | RustCrypto (`Apache-2.0 OR MIT`); already in `Cargo.lock` via `hmac 0.13`, whose constant-time verify uses it; already vet-exempted |

The data files are not crates. `eff_large_wordlist.txt` comes from
eff.org (EFF, CC BY 3.0 US; 0010 §2.2.2 already mandates embedding it).
`english.txt` comes from `bitcoin/bips` `bip-0039/` (BIP 39 is under the MIT
licence, per its header). Both are attributed in `data/README.md`.

## Steps

### Step 1 — Embedded word lists and their integrity check

- [x] **Do:** Copy the published files byte for byte into
  `crates/qv-crypto/data/` and confirm the hashes locally:
  `eff_large_wordlist.txt` (SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`,
  7,776 lines) and `bip39-english.txt` (from
  `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt`,
  SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`,
  2,048 lines; identical to Trezor's copy). Write `data/README.md` with the
  source, licence, attribution and hash for each. Write `wordlist.rs` as
  sketched: `include_bytes!`, then SHA-256 compared with the pinned constant
  (through a crate-private `primitives::sha256` wrapper), then a strict parse.
  EFF lines must be `ddddd\tword\n` with the dice numbers in order
  `11111…66666`. BIP-39 lines must be `word\n`, 1–8 bytes `a–z`, strictly
  ascending and unique. Any deviation → `None` → `Internal`.
  Tests: both hashes; counts; the EFF alphabet is exactly `a–z` plus `-`, and
  the four hyphenated words exist; BIP-39 words are sorted and unique, and
  their 4-letter prefixes are unique; a corrupted copy (a changed byte, a
  missing line, swapped lines) passed to the parse/check helper → `None`.
  Then, by hand: flip one byte in each embedded file, run the tests, see them
  fail, restore the file, and log it.
- **Files:** `crates/qv-crypto/data/{eff_large_wordlist.txt,bip39-english.txt,README.md}`, `crates/qv-crypto/src/{wordlist.rs,primitives.rs,lib.rs}`.
- **Done when:** tests pass; `sha256sum` of both data files matches; the
  manual corruption check is logged.
- **Verify:** `cargo test --locked -p qv-crypto --lib -- wordlist`

### Step 2 — Recovery phrase

- [x] **Do:** Add `subtle` (workspace pin, `default-features = false`) and
  run `cargo deny check`, then `cargo vet` (regenerate imports, exempt if no
  audit is imported, prune). Add `CryptoError::WrongPhrase` (fixed string
  "wrong recovery phrase") and its exit-code row. Write `phrase.rs` following
  *Data and control flow*. Save the eight 256-bit English cases of Trezor
  `vectors.json` as `tests/vectors/bip39-trezor-english-256.txt`: a
  `# source:` line, then per record `entropy = hex` and
  `mnemonic_utf8 = hex` (the mnemonic's UTF-8 bytes, so the KAT parser
  stays unchanged), with the readable mnemonic in a `#` comment above. Ignore
  the seed column: it is the PBKDF2 wallet seed, which 0002 §4.1 excludes.
  Tests:
  - Each vector: `from_vault_key(entropy)` equals the mnemonic, and
    `from_recovery_phrase(mnemonic)` gives back the entropy as VK.
  - Proptest: the round trip holds for random VKs.
  - Accepted spellings: upper and mixed case, tabs, newlines, leading,
    trailing and repeated whitespace.
  - `WrongPhrase` for 23 and 25 words, an empty input, a 9-letter word, a
    non-list word, a non-ASCII byte, and a valid-word substitution that breaks
    the checksum (find one deterministically from vector 1). For the last
    word, exactly 8 of the 2,048 words decode (one per value of its 3 entropy
    bits; the other 8 bits are checksum). The original is among them, and the
    other 2,040 → `WrongPhrase`.
  - `confirm_word`: right word (in any case) → `Ok`; wrong word, wrong index or
    empty input → `WrongPhrase`; index 24 → `Internal`.
  - `expose_word` for 0, 23 and 24 (`None`); redacted `Debug`; `compile_fail`
    doctests (with passing twins) for `RecoveryPhrase` `.clone()` and `==`.
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/qv-crypto/{Cargo.toml,src/phrase.rs,src/error.rs,src/kat.rs,src/lib.rs}`, `crates/qv-crypto/tests/vectors/bip39-trezor-english-256.txt`, `supply-chain/*`.
- **Done when:** tests pass; `cargo deny check` and `cargo vet --locked` pass.
  The log lists `subtle`'s licence and vet status.
- **Verify:** `cargo test --locked -p qv-crypto --lib -- phrase kat && cargo test --locked -p qv-crypto --doc`

### Step 3 — Generator settings, validation and entropy (no RNG yet)

- [x] **Do:** `generator.rs`: the settings types with the 0010 defaults
  (`Default` impls), `GeneratorError`, `Strength`, `Estimate`,
  `WARN_BELOW_BITS`, the alphabet/class builder, the separator forbidden set
  (from `eff_large().alphabet` plus the capitalize/digit additions),
  validation in the stated order, and `estimate`. Keep crate-private helpers
  testable: `check_positions(length, required)`, and an inclusion–exclusion
  helper `char_entropy(class_sizes, length, require_each_class)`.
  Tests:
  - Every range boundary: length 7/8/256/257, words 2/3/20/21, PIN 3/4/32/33,
    each with its exact variant.
  - `NoClassEnabled`. `AlphabetTooSmall` for digits only minus `0`, and for
    digits only with `exclude_ambiguous` (8 characters); digits only (10)
    passes.
  - `RequiredClassEmpty` for lowercase and digits with all digits excluded and
    `require_each_class` on. With it off, the same settings are valid.
  - `TooFewPositions` through `check_positions(3, 4)`.
  - Separators: `-` → `InvalidSeparator` (derived from the list), `a`,
    `\n`, `é`, `\u{7f}`; `A` only with `FirstLetter`; `5` only with
    `append_digit`; space, `.` and `_` pass.
  - Entropy: defaults ≈ 157.2 bits (0010 §3.4; `require_each_class` slightly
    below `24·log2 94` = 157.3); passphrase default ≈ 77.5; PIN 6 ≈ 19.93,
    Weak. `char_entropy` equals `log2` of a brute-force count of valid strings
    for small cases (e.g. class sizes {2, 1, 3}, L = 1…6). `append_digit` adds
    exactly `log2(10·w)`.
  - Strength edges: 49.99, 50, 69.99, 70, 89.99 and 90. `warn` at 63.99 and
    64.
  - `exclude_chars` with non-ASCII characters has no effect.
- **Files:** `crates/qv-crypto/src/{generator.rs,lib.rs}`.
- **Done when:** tests pass with exact error variants.
- **Verify:** `cargo test --locked -p qv-crypto --lib -- generator`

### Step 4 — Sampling and generation

- [x] **Do:** `RandomSource`, `OsRandom`, `uniform_below`, `generate_with`
  and `generate` per *Data and control flow*, plus `Generated`. Test-only
  RNGs, all under `#[cfg(test)]`: `TestRng` (SHA-256 counter mode,
  `SHA-256(seed ‖ u64_be(counter))` blocks, fixed seeds), `CountingRng`
  (wraps another RNG and counts bytes), `ConstRng` (repeats one 4-byte draw)
  and `FailingRng`.
  Tests:
  - Invalid settings return their error and the RNG is called **0** times
    (`CountingRng`), for every validation error in step 3.
  - `ConstRng` draws that always map to the same lowercase letter, with all
    classes required → `Exhausted` after exactly 10,000 attempts. That is
    `10,000 × length × 4` bytes read, which shows the bound and shows that
    nothing is patched in.
  - `uniform_below` with a `ConstRng` below `min` → `Exhausted` after 64
    draws. `FailingRng` → `Rng` in every mode.
  - Outputs: correct length; every byte in the alphabet; ASCII only;
    `require_each_class` outputs contain every enabled class (1,000 samples);
    excluded characters never appear.
  - Passphrases split on the separator into `words` list words.
    `FirstLetter` capitalizes only the first letter (`t-shirt` → `T-shirt`).
    `append_digit` adds exactly one digit, at the end of one word.
  - PINs are digits only.
  - `Generated` has a redacted `Debug`, and its estimate equals `estimate()`.
  - `compile_fail` doctests (with passing twins): `Generated` `.clone()`,
    `==`, and `{}` formatting.
  - One `generate` call per mode through the real OS RNG.
- **Files:** `crates/qv-crypto/src/{generator.rs,lib.rs}`.
- **Done when:** tests pass; no `unwrap`/`expect`/`panic` outside tests.
- **Verify:** `cargo test --locked -p qv-crypto --lib -- generator && cargo test --locked -p qv-crypto --doc`

### Step 5 — Statistical uniformity tests

- [x] **Do:** In a `#[cfg(test)] mod stats` in `generator.rs`: a chi-square
  statistic and a critical value from the Wilson–Hilferty approximation at
  `z = 5` (p ≈ 3·10⁻⁷). Everything uses `TestRng` with fixed seeds, so the
  tests are deterministic and never flaky; they test our mapping from uniform
  bits to outputs.
  Tests:
  - `uniform_below` for n ∈ {10, 26, 62, 94, 7776}, at ≥ 100 expected per
    bin.
  - Default character passwords (20,000 samples): each of the 24 positions is
    uniform over the 94 characters.
  - **Conditional uniformity of `require_each_class`:** with the internal
    sampler on classes {a, b} and {c}, L = 3, the 18 valid strings are
    uniform (18,000 samples) and no invalid string appears.
  - Passphrases (60,000 with 6 words): each position is uniform over 32 bins
    of 243 consecutive indices. All word draws pooled are uniform over 7,776
    bins. With `append_digit`, the (position, digit) pair is uniform over 60
    bins.
  - PINs: each position is uniform over 10 digits.
  - **Control:** the same test **rejects** a deliberately biased `byte % 94`
    sampler. That shows the test can detect modulo bias.
  Measure the module's debug test time and log it. If it exceeds 15 s, add
  `[profile.dev.package.sha2] opt-level = 3` (dev/test only, like the argon2
  override), not smaller samples.
- **Files:** `crates/qv-crypto/src/generator.rs`, possibly `Cargo.toml` (dev profile only).
- **Done when:** every uniformity test passes, the control fails as expected,
  and the time is logged.
- **Verify:** `cargo test --locked -p qv-crypto --lib -- stats`

### Step 6 — Crate docs and documentation

- [x] **Do:** Update the `qv-crypto` crate docs: the new modules, the
  `WrongPhrase` exit-code row, `GeneratorError`'s CLI mapping, the timing note
  (phrase lookups are constant-time scans; generator table lookups are not,
  and why), and the embedded data with its integrity check. Update the files
  under *Documentation*. Run the full gates and set the plan to
  `Implemented`.
- **Files:** `crates/qv-crypto/src/lib.rs`, see *Documentation*.
- **Done when:** the docs match the tree and all gates are green.
- **Verify:** `sh scripts/check-spdx.sh && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && cargo deny check && cargo vet --locked`

## Test plan

- **Unit and property tests:** word-list structure and hashes; the phrase
  round trip (proptest) and its normalization; settings validation at every
  boundary; exact entropy against brute-force counts; strength edges.
- **Rejection, malformed-input and crash-path tests:** corrupted lists fail
  closed; wrong word count, unknown, overlong and non-ASCII words, and
  checksum failures → `WrongPhrase`; every infeasible setting fails with its
  exact variant before any RNG use; retry exhaustion at exactly 10,000
  attempts; RNG failure. No durability paths in this phase.
- **Statistics:** chi-square uniformity for every sampling path, including
  the conditional distribution of `require_each_class`, plus a control that
  shows modulo bias is detected.
- **Vectors:** Trezor BIP-39 English 256-bit vectors (upstream); published
  word-list hashes.
- **0012 §1 matrix rows addressed:** "Impossible generator" (empty required
  class, too few positions and exhausted retries yield errors: steps 3–4).

## Risks and stop conditions

- **Supply chain:** if `subtle` brings a licence outside the allow-list or
  has an advisory, stop and ask. Do not widen `deny.toml`.
- **Upstream data:** if a fetched file does not match the hash in this plan
  (or in 0010 §2.2.2), stop and ask. Never "fix" a hash to match a download.
- **Statistics:** if a uniformity test fails, find the bias. Do not change
  the seed, raise the critical value or shrink the sample to make it pass.
- **Spec gaps:** if a 0010 requirement turns out to need behaviour this plan
  does not describe (e.g. zxcvbn for generated values), log it and ask. Do not
  pull the 1.10 scope forward.
- **No `unsafe`**, and no new dependency other than `subtle`.
- Never weaken a test, or turn an exact error variant into "is_err", to make
  it pass.

## Documentation

- [x] `CHANGELOG.md` — Unreleased/Added: recovery phrase, password generator, embedded word lists
- [x] `ARCHITECTURE.md` — §3 "Implemented so far" gains the recovery phrase and the generator (generator lives in `qv-crypto`, exposed via `qv-core`); §6 only if a tech choice differs (check)
- [x] Specs — no change. 0002 and 0010 stay Accepted, not fully implemented
- [x] `AGENTS.md` — *Current state* mentions the recovery phrase and the generator
- [x] `plans/README.md` — index row; roadmap 0002: tick 1.4, plan number, execution log, *Revisions* note on 0010 §3.2/§4.2 → 1.10

## Revisions

- 2026-10-25: Owner decision (option B of the step 2 stop): use `ctutils 0.4.5` instead of `subtle` for constant-time phrase matching. `subtle` is `BSD-3-Clause`, outside the licence allow-list; `ctutils` is `Apache-2.0 OR MIT` and already in the build. `deny.toml` is unchanged. Wherever the steps and *Design* say `subtle`, `ConditionallySelectable`/`ct_eq`/`conditional_assign`, read `ctutils` `CtAssign`/`CtEq`/`ct_assign`.

## Execution log

- 2026-10-25: Approved (standing approval, roadmap 0002): no open decisions, no spec amendment, one new dependency from the candidate table (`subtle`), no `unsafe`, matches phase 1.4 (phrase in `qv-crypto`; the roadmap leaves the generator location to this plan).
- 2026-10-25: Status `In progress`.
- 2026-10-25: Step 1 done. The data files were fetched from the URLs in the plan, and both hashes match (EFF `addd3553…903e`, BIP-39 `2f5eed53…dbda`; the BIP-39 file is byte-identical to Trezor's `python-mnemonic` copy). `data/README.md` records sources, licences (EFF: CC BY 3.0 US; BIP 39: MIT) and hashes. `wordlist.rs`: `include_bytes!`, then a SHA-256 check against pinned constants, then a strict parse, cached in a `OnceLock`. The EFF parser checks the dice odometer `11111…66666`, `a–z`/`-` words, strictly ascending order and exactly 7,776 lines. The BIP-39 parser checks 1–8 bytes of `a–z`, strictly ascending order and exactly 2,048 lines, and gives zero-padded 8-byte entries. Both lists are strictly ascending byte-wise, which also proves uniqueness. `WordList` carries an ASCII bitmask of its bytes, for the separator check. New crate-private `primitives::sha256` (into a caller buffer; the digest temporary is wiped). Tests: published hashes; structure (EFF alphabet exactly `a–z` + `-`, the four hyphenated words, no digits; BIP-39 first and last entries and unique 4-letter prefixes); corrupted copies (a changed byte, a missing line, swapped lines, no final newline, a digit in a word, a wrong dice number, an extra line, a 9-letter word, uppercase) are rejected. Manual check: flipping one byte in each embedded file made 3 of 4 wordlist tests fail (hash and structure); both files were restored, and `sha256sum` matches again. Deviation (small, outside the listed files): new `.gitattributes` with `crates/qv-crypto/data/*.txt -text`, so a Windows checkout with `autocrlf` (milestone 4) cannot change the hashed bytes. The library `dead_code` lint fails clippy until steps 2–3 use the module (as in plans 0004/0005).
- 2026-10-25: Step 2, stop condition hit (supply chain). `subtle 2.6.1` (latest, not yanked) is licensed `BSD-3-Clause`, which is not in the `deny.toml` allow-list. `deny.toml` is not widened. Questions for the owner (pick one): (A) allow `BSD-3-Clause` and add `subtle` as planned (a permissive, OSI-approved licence compatible with AGPL-3.0-or-later; one new crate, plus a vet import or exemption); (B) use `ctutils 0.4.5` instead (RustCrypto, `Apache-2.0 OR MIT`, already in `Cargo.lock` via `hmac 0.13` and already vet-exempted; it has `CtEq`, `CtAssign` and `Choice`, which is all the phrase needs). B is outside the roadmap's candidate table, which is why it is asked too. Recommendation: B. It adds no new code to the build, no licence change and no new vet entry, and `hmac`'s constant-time verify already relies on it. Steps 3–5 (generator) do not use either crate and continue; step 2 and the final gates wait.
- 2026-10-25: Step 3 done. `generator.rs`: settings types with the 0010 defaults, `GeneratorError` (fixed strings, `From<RngError>`), `Strength` (NaN → Weak), `Estimate` (NaN warns), `WARN_BELOW_BITS`, the alphabet builder (classes `a–z`, `A–Z`, `0–9`, `is_ascii_punctuation` = the 32 symbols; exclusions as a 128-bit ASCII mask, non-ASCII ignored), validation in the planned order, `check_positions`, `char_entropy` (inclusion–exclusion in `f64`) and `estimate`. Separator check: printable ASCII `0x20–0x7E`, not in the list's byte set (derived from the embedded list), not `A–Z` with `FirstLetter`, not `0–9` with `append_digit`. Tests: every range boundary (plus 0 and `u32::MAX`) with exact variants; `NoClassEnabled`; `AlphabetTooSmall` (digits minus `0`; digits with `exclude_ambiguous`, both with and without `require_each_class`; exactly 10 digits passes); `RequiredClassEmpty` (and the same settings accepted with the requirement off, and the required-class error coming before the alphabet size); `TooFewPositions` via `check_positions`; separators (`-`, letters, control, DEL, NUL, non-ASCII rejected; space, `.`, `_`, `~`, `!`, `A`, `5` accepted; `A` rejected with capitalization, `5` with `append_digit`). Every rejected setting is checked through `estimate` **and** `generate_with`, and a counting RNG proves 0 bytes are drawn. Entropy: the default is 157.208 361 786 151 36 bits, equal to the exact value computed with Python big integers (`24·log2 94` = 157.31 without the requirement); passphrase 77.549, +log2 60 with a digit; PIN 6 = 19.93, Weak and warned; `char_entropy` equals log2 of a brute-force count for class sizes {2, 1, 3}, L = 3–6. Strength and warning edges; exclusion arithmetic (91 and 84 characters).
- 2026-10-25: Step 4 done. Crate-private `RandomSource`, `OsRandom` (the only production source), `uniform_below` (`min = n.wrapping_neg() % n`, at most 64 draws, `n = 0` → `Internal`), `generate_with` (estimate, i.e. full validation, before any draw), `sample_characters` (whole-attempt rejection, ≤ 10,000 attempts, class bits per byte), `sample_passphrase` (indices and the digit position/value in `Zeroizing` arrays, exact-size `SecretBytes::try_init`), `sample_pin` and `Generated` (redacted `Debug`). Test RNGs in `#[cfg(test)] mod test_rng`: `TestRng` (SHA-256 counter mode), `CountingRng`, `ConstRng`, `FailingRng`. Tests: `uniform_below` exhaustion after exactly 64 draws (256 bytes), no rejection for powers of two, range on 1,000 draws for n up to `u32::MAX`; `require_each_class` → `Exhausted` after exactly 10,000 × 24 × 4 bytes, and without the requirement the same RNG yields 24 × `a` (so nothing is patched in); `FailingRng` → `Rng` in all three modes; 1,000 default passwords (length, printable ASCII, every class) and exclusions never appear; passphrases (6 list words; `T-shirt.T-shirt.T-shirt` via a constant draw; `FirstLetter` capitalizes only the first letter; `append_digit` puts exactly one digit at the end of exactly one word); PINs; `Generated::estimate() == estimate()`; one real OS-RNG `generate` per mode. Module doctests: `compile_fail` for `.clone()`, `==` and `{}` on `Generated`, plus a passing twin.
- 2026-10-25: Step 5 done. A `stats` test module: chi-square with a Wilson–Hilferty critical value at z = 5, and fixed `TestRng` seeds, so the tests are deterministic. All pass: `uniform_below` for n = 10, 26, 62, 94, 7776 (100 expected per bin); 24 character positions over 94 symbols (20,000 passwords); `require_each_class` conditional uniformity (classes {a, b}/{c}, L = 3: exactly the 18 valid strings, uniform over 18,000 samples); passphrase positions (32 bins × 6) and pooled words (7,776 bins) over 60,000 phrases; (position, digit) over 60 bins; PIN positions. The control (`byte % 94`) is rejected. Mutation check: replacing `uniform_below` with `byte % n` made `stats_uniform_below`, `stats_character_positions` and `stats_passphrase_words` fail (the original was restored). Biases with small n (256 mod 10, mod 3) are below these sample sizes' power, so the PIN and 3-symbol tests did not catch the mutation; the control and the large-n tests do. Time: 0.77 s for the stats module (debug), so no `sha2` opt-level override.
- 2026-10-25: Status `Blocked` before step 2 on the `subtle` licence question (entry above). Step 6 (docs, final gates) waits for step 2. Until step 2 uses it, the BIP-39 half of `wordlist` fails the `dead_code` clippy gate; everything else is clippy-clean, and `cargo test -p qv-crypto` passes.
- 2026-10-25: Owner chose option B (`ctutils`), recorded under *Revisions*. Status back to `In progress`.
- 2026-10-25: Step 2 done with `ctutils` (owner decision B). `ctutils = { version = "=0.4.5", default-features = false }` in the workspace and `qv-crypto`. `Cargo.lock` gains only the `qv-crypto → ctutils` edge (no new package). `cargo deny check`: advisories, bans, licenses and sources ok. `cargo vet --locked`: ok, 12 audited and 33 exempted (the existing `ctutils` exemption covers it; no supply-chain change). `CryptoError::WrongPhrase` ("wrong recovery phrase", exit code 3 in the table). `phrase.rs`: `RecoveryPhrase` (`SecretArray<215>` + length; `from_vault_key`, `expose_secret`, `expose_word`, `confirm_word`; redacted `Debug`) and `VaultKey::from_recovery_phrase`, following *Data and control flow*. The 11-bit groups are read and written as 3 bytes in a 35-byte packed buffer (VK ‖ checksum ‖ 2 zero bytes). Lookups scan all 2,048 entries with `ctutils` `CtEq`/`CtAssign` on the concrete `u64` form of each zero-padded 8-byte entry. A first version used the generic slice impls, which compile unoptimized into our crate and made a debug decode take about 5 ms; a dev-only opt-level override for `ctutils`/`cmov` did not help, so it was dropped again. The decoder branches once, on `found & checksum_ok` (`Choice::to_bool`). `confirm_word` compares the padded word with `ct_eq`. Vectors: `tests/vectors/bip39-trezor-english-256.txt`, the eight 256-bit English entries from Trezor `vectors.json` (`entropy`, `mnemonic_utf8` as hex, the text in a comment; the seed column omitted on purpose). Tests: all 8 vectors in both directions; proptest round trip; upper/mixed case, tabs, CRLF, leading/trailing whitespace; `WrongPhrase` for 23 and 25 words, empty and whitespace-only input, a non-list word, a 9-letter word, a digit, a non-ASCII letter, a NUL byte and an abbreviation (`aban`); checksum: exactly 8 of 2,048 last words decode (the original among them), and an earlier substitution fails; `confirm_word` (every position, case and whitespace tolerance, wrong word, another position's word, empty, two words, prefix → `WrongPhrase`; index 24 → `Internal`); `expose_word` 0/23/24; packing round trip; redacted `Debug`. Doctests: `compile_fail` for `.clone()` and `==`, plus a passing twin. The phrase tests take 1.9 s in a debug build.
- 2026-10-25: Step 6 done; plan `Implemented`. Crate docs gain the recovery phrase, the generator (including the timing note), the embedded data and the `WrongPhrase` exit-code row; `generator.rs` docs carry the `GeneratorError` → CLI mapping. `GeneratorError` also implements `std::error::Error`, like `CryptoError`. Docs: `CHANGELOG.md` (this phase, plus the plan 0005 review fix), `ARCHITECTURE.md` §3 "Implemented so far" (§6 unchanged: no tech choice differs), `AGENTS.md` current state, roadmap 0002 (1.4 ticked, *Revisions* note on 0010 §3.2/§4.2 → 1.10 and on `ctutils`, log), `plans/README.md`. Specs unchanged: 0002 (§2, §3.4–3.5, §5–6 remain) and 0010 (§3.2, §4.2, §5 storage, §6.1 UI remain) stay Accepted. Final gates: SPDX ok; fmt ok (root and `fuzz/`); clippy `-D warnings` clean; `cargo test --locked` 182 passed, 0 failed, 1 ignored (the plan 0005 stored-data vector generator); `cargo doc -p qv-crypto` with `-D warnings` ok; `cargo deny check` ok; `cargo vet --locked` ok (12 audited, 33 exempted); `cargo fetch --locked` for `fuzz/` ok; `crosscheck.py` exit 0.
  Found, not fixed: (1) The generator's alphabet and word-list lookups are indexed by secret draws (documented; same-user malware is out of scope in 0001). (2) Joining phrase words of different lengths is not constant time (the phrase is shown right after). (3) The statistical tests have little power against tiny biases at small n (e.g. 256 mod 10); the large-n tests and the control catch modulo bias (see the step 5 mutation check). (4) For 1.8: qv-core must re-export the generator and phrase API and store generator defaults in vault settings (0010 §5.1), revalidating them on use, which `estimate`/`generate` already do. (5) For 1.10: `zxcvbn` (0010 §3.2/§4.2) needs owner approval (not in the candidate table).
