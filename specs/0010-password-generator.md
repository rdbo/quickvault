# 0010 — Password Generator

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0002, 0003, 0008 |

## Summary

Defines how QuickVault generates passwords and passphrases: randomness
source, unbiased selection, character sets, word lists, defaults, limits,
strength estimation, and where settings live. The generator is part of
`qv-core` and is shared by all clients.

## Motivation

A password manager is only as good as the passwords it creates. Common
generator bugs are subtle: modulo bias, a "must contain a digit" rule that
skews the distribution, a weak or seeded RNG, or generated values leaking
through logs and UI state. This spec rules them out.

## Specification

### 1. Randomness

1.1. All randomness MUST come from the operating system CSPRNG (`getrandom`,
via `rand::rngs::OsRng`). User-space PRNGs, seeds and time-based randomness
MUST NOT be used in production code.

1.2. Picking an element from a set of size `n` MUST be uniform: use
rejection sampling (`rand::distributions::Uniform` or equivalent). The
`random_u32() % n` pattern is forbidden because it introduces modulo bias.

1.3. The generator takes its RNG through a trait so tests can inject a
deterministic RNG. The deterministic RNG MUST only be available under
`#[cfg(test)]`.

### 2. Modes

#### 2.1 Random characters

| Option | Values | Default |
|--------|--------|---------|
| `length` | 8–256 | **24** |
| `lowercase` | `a–z` | on |
| `uppercase` | `A–Z` | on |
| `digits` | `0–9` | on |
| `symbols` | the 32 printable ASCII punctuation characters | on |
| `exclude_ambiguous` | removes look-alikes: zero, capital O, small o, one, small L, capital I, pipe, backtick, single and double quote | off |
| `exclude_chars` | user-supplied characters to remove | empty |
| `require_each_class` | at least one character from every enabled class | on |

2.1.1. The alphabet is the union of the enabled classes, minus excluded
characters. The output is ASCII only (websites often reject other input).

2.1.2. **`require_each_class` MUST NOT bias the result.** Generate the whole
password uniformly from the alphabet; if it misses an enabled class, discard
it and generate a new one. This keeps the result uniform over all valid
passwords. Patching a missing class into a random position is forbidden
because it skews the distribution.

2.1.3. At least one class MUST be enabled, and the final alphabet MUST have
at least 10 characters. With require_each_class, every enabled class after
exclusions MUST be nonempty and length MUST cover the number of required classes.
Reject unsatisfiable settings before consuming RNG. Bound whole-password
rejection to 10,000 attempts; on exhaustion return an error, never a biased
patched result. Revalidate synced defaults at use, not only in the settings UI.

#### 2.2 Passphrase

| Option | Values | Default |
|--------|--------|---------|
| `words` | 3–20 | **6** |
| `wordlist` | `eff-large` (7,776 words, ≈12.9 bits/word) | `eff-large` |
| `separator` | one printable ASCII character absent from the word list | `.` |
| `capitalize` | none / first letter of each word | none |
| `append_digit` | add one random digit to one random word | off |

2.2.1. Words are chosen independently and uniformly, with repetition allowed
(that is what the entropy calculation assumes).

2.2.2. The EFF large word list is embedded in the binary. Its SHA-256 MUST
be checked in a unit test against the published list, so a corrupted or
modified list fails the build. The published `eff_large_wordlist.txt`
(dice-number TAB word, 7,776 lines) has SHA-256
`addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.

2.2.3. A nonempty separator absent from all words is required, so output encoding
is injective and the entropy formula remains valid. The EFF large list contains
four hyphenated words (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`), so `-` is
**not** a valid separator for `eff-large`; the list's alphabet is `a–z` plus `-`.
The validity check derives the forbidden set from the embedded list, not from a
hard-coded assumption. Append a digit uniformly
to a chosen word; the word list contains no digits, keeping this choice
unambiguous.

2.2.4. **English only** in v1. Other languages are out of scope for now;
they could be added later as new `wordlist` values.

#### 2.3 PIN

Digits only, length 4–32, default 6. Intended for card PINs and similar;
the UI MUST show its low strength.

### 3. Strength

3.1. **Generated values:** the strength shown is the exact entropy of the
generator settings, not an estimate:
- characters: `length × log2(alphabet size)` (with `require_each_class`
  the true value is slightly lower; the client MUST compute it exactly or
  show the lower bound);
- passphrase: `words × log2(wordlist size)`, plus `log2(10 × words)` if
  `append_digit` is on;
- PIN: `length × log2(10)`.

3.2. **User-typed passwords** (master password, manual entries) are
estimated with `zxcvbn`, because their entropy cannot be computed.

3.3. Labels shown to the user:

| Bits | Label |
|------|-------|
| < 50 | Weak |
| 50–69 | Fair |
| 70–89 | Strong |
| ≥ 90 | Very strong |

3.4. With the defaults, characters give ≈ 157 bits and passphrases ≈ 77
bits.

### 4. Warnings

4.1. Clients MUST warn (but allow) when the settings give less than 64 bits,
e.g. a character password shorter than 10 characters with all classes, or
a passphrase with fewer than 5 words.

4.2. **Master password:** at vault creation, on password change and on
recovery, the client MUST suggest a generated passphrase (6 words). For a
user-typed master password, using the `zxcvbn` estimate and the labels of
§3.3:

| Estimate | Behaviour |
|----------|-----------|
| Strong or Very strong (≥ 70 bits) | Accepted |
| Fair (50–69 bits) | Inline warning next to the field; accepted |
| Weak (< 50 bits) | **Blocking confirmation dialog**: "This password is weak and could be guessed by an attacker who obtains your vault file. Create the vault anyway?" The confirm button stays disabled for **5 seconds** (with a visible countdown) so it can't be clicked by reflex. The default button is "Choose a stronger password". |

Weak master passwords are allowed after confirmation, never silently.
The CLI equivalent is in 0011 §5.4.

### 5. Settings

5.1. Generator defaults are stored **per vault** in the vault metadata
`settings` (0003 §3), so they sync between devices. Every generation can
override them.

5.2. Per-entry overrides (e.g. "this site allows max 16 characters, no
symbols") MAY be stored on the entry as a generator profile, so regenerating
the password later uses the site's rules. Optional in v1.

### 6. Secret handling

6.1. Generated values are secrets from the moment they exist: they live in
zeroizing types (0008 §1) and follow the secret boundary (0008 §4). The UI
gets the value only to display it to the user; copy goes Rust → clipboard
directly.

6.2. Generated values MUST NOT be logged and MUST NOT be kept anywhere after
use, except in the entry they are saved into.

6.3. **No generator history.** QuickVault does not keep a list of previously
generated values. A generated password that the user never saves is gone;
saving it is the user's responsibility. This avoids storing passwords that
may never have been used.

## Security Considerations

- Uniformity (1.2, 2.1.2, 2.2.1) is what makes the shown entropy true. A
  biased generator overstates strength.
- `zxcvbn` estimates are heuristics; they can overestimate unusual but
  guessable passwords. They are used only for user-typed passwords.
- A long, symbol-heavy default can be rejected by some sites; per-entry
  profiles (5.2) handle that without weakening the default.

## Testing Requirements

- Statistical tests (chi-square, large sample) that each character and each
  word position is uniform.
- Tests that `require_each_class` output contains every class, and that its
  distribution matches uniform sampling restricted to valid passwords.
- Word list hash test (2.2.2).
- Boundary tests for every option, including a required class emptied by
  exclusions, too few positions, rare acceptance, retry exhaustion and ambiguous
  separators. Invalid synced settings must fail before RNG sampling.

## Open Questions

None currently.

## Changelog

- 2026-10-14: Initial draft.
- 2026-10-14: Weak master password: inline warning (Fair), confirmation
  dialog with 5 s cooldown (Weak). English-only word list confirmed.
- 2026-10-14: No generator history (§6.3). Status → Accepted.

- 2026-10-15: Amendment: reject impossible constraints, bound rejection sampling,
  validate synced profiles and require unambiguous passphrase separators.
- 2026-10-15: Fix: the previous default separator `-` occurs in four EFF words
  and violated §2.2.3; default is now `.`. Record the word list hash.
