// SPDX-License-Identifier: AGPL-3.0-or-later

//! Master-password strength (spec 0010 §3.2–3.3, §4.2) and the
//! recovery-phrase confirmation positions (0002 §4.2).
//!
//! Generated values have an exact entropy (`qv_crypto::estimate`) and are
//! never passed to [`password_strength`]: zxcvbn rates even a random 6-word
//! passphrase (≈ 77 bits) as Fair, because each word is in its dictionaries.
//! User-typed passwords are estimated with `zxcvbn`, which is a heuristic and
//! can overestimate unusual but guessable passwords (0010 *Security
//! Considerations*).
//!
//! **Reduced hygiene:** `zxcvbn` copies the password into ordinary `String`s
//! (its first 100 characters, lowercased and l33t-substituted variants, and
//! the matched substrings). These copies are freed but not zeroized, a
//! library intermediate of the kind 0008 §1.1 asks to audit. The estimate
//! runs once per typed master password, before the vault exists or the
//! password changes. Its panics (internal invariants) carry no input data.

use qv_crypto::{MasterPassword, PHRASE_WORDS, Strength};

use crate::error::CoreError;

/// What a frontend does with a typed master password (0010 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordVerdict {
    /// Strong or very strong (≥ 70 bits): accept.
    Accept,
    /// Fair (50–69 bits): accept with an inline warning.
    Warn,
    /// Weak (< 50 bits): accept only after the blocking confirmation (a
    /// 5-second delay, then an explicit yes; 0011 §5.4).
    ConfirmWeak,
}

/// The estimate of a typed master password.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PasswordCheck {
    /// Estimated bits: `log2` of zxcvbn's guess count (0 for an empty
    /// password). zxcvbn never estimates above 64 bits; at that ceiling the
    /// strength is Strong (0010 §3.2).
    pub bits: f64,
    /// The label (0010 §3.3).
    pub strength: Strength,
    /// What to do with it.
    pub verdict: PasswordVerdict,
}

/// Estimates a user-typed master password with `zxcvbn` (0010 §3.2).
pub fn password_strength(password: &MasterPassword) -> PasswordCheck {
    let entropy = zxcvbn::zxcvbn(password.expose_secret(), &[]);
    let log10 = entropy.guesses_log10();
    let bits = if log10.is_finite() && log10 > 0.0 {
        log10 * core::f64::consts::LOG2_10
    } else {
        0.0
    };
    if entropy.guesses() == u64::MAX {
        // zxcvbn's ceiling: it found no structure below 2^64 guesses. That
        // counts as Strong (0010 §3.2).
        return PasswordCheck {
            bits,
            strength: Strength::Strong,
            verdict: PasswordVerdict::Accept,
        };
    }
    check_from_bits(bits)
}

fn check_from_bits(bits: f64) -> PasswordCheck {
    let strength = Strength::from_bits(bits);
    let verdict = match strength {
        Strength::Weak => PasswordVerdict::ConfirmWeak,
        Strength::Fair => PasswordVerdict::Warn,
        _ => PasswordVerdict::Accept,
    };
    PasswordCheck {
        bits,
        strength,
        verdict,
    }
}

/// Three distinct random word positions (0-based, below 24) for confirming
/// the recovery phrase at vault creation.
pub fn confirmation_positions() -> Result<[usize; 3], CoreError> {
    let mut out = [usize::MAX; 3];
    let mut n = 0;
    // Rejection sampling over bytes: 240 is the largest multiple of 24
    // below 256, so `b % 24` is uniform for `b < 240`.
    while n < out.len() {
        let bytes = qv_crypto::random_array::<16>().map_err(|_| CoreError::Rng)?;
        for b in bytes {
            if n == out.len() {
                break;
            }
            if b >= 240 {
                continue;
            }
            let pos = usize::from(b) % PHRASE_WORDS;
            if !out.contains(&pos) {
                out[n] = pos;
                n += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(s: &str) -> PasswordCheck {
        password_strength(&MasterPassword::from_utf8(s.as_bytes()).unwrap())
    }

    #[test]
    fn strength_verdicts() {
        assert_eq!(check("password").verdict, PasswordVerdict::ConfirmWeak);
        assert_eq!(check("").verdict, PasswordVerdict::ConfirmWeak);
        assert_eq!(check("").bits, 0.0);
        // A long random-looking string is accepted. (Generated values are
        // judged by their exact entropy, 0010 §3.1, not by zxcvbn, which
        // rates a random 6-word passphrase only Fair: every word is in its
        // dictionaries.)
        let strong = check("v7#Qm!2pZr9&Lw4tX0^sK8@e");
        assert_eq!(strong.verdict, PasswordVerdict::Accept, "{}", strong.bits);
        assert_eq!(strong.strength, Strength::Strong);
        // zxcvbn's ceiling is 64 bits (saturating `u64` guesses).
        assert!((63.9..=64.1).contains(&strong.bits), "{}", strong.bits);
        // A fixed string whose zxcvbn estimate is pinned in the Fair band.
        let fair = check("plumb-tiger-velvet-31");
        assert!((50.0..70.0).contains(&fair.bits), "{}", fair.bits);
        assert_eq!(fair.verdict, PasswordVerdict::Warn);
        assert_eq!(fair.strength, Strength::Fair);
    }

    #[test]
    fn strength_thresholds_follow_the_labels() {
        for (bits, verdict) in [
            (0.0, PasswordVerdict::ConfirmWeak),
            (49.9, PasswordVerdict::ConfirmWeak),
            (50.0, PasswordVerdict::Warn),
            (69.9, PasswordVerdict::Warn),
            (70.0, PasswordVerdict::Accept),
            (95.0, PasswordVerdict::Accept),
        ] {
            assert_eq!(check_from_bits(bits).verdict, verdict, "{bits}");
        }
    }

    #[test]
    fn strength_confirmation_positions_are_distinct() {
        let mut seen = [0u32; PHRASE_WORDS];
        for _ in 0..1000 {
            let p = confirmation_positions().unwrap();
            assert!(p.iter().all(|&i| i < PHRASE_WORDS));
            assert!(p[0] != p[1] && p[1] != p[2] && p[0] != p[2]);
            for i in p {
                seen[i] += 1;
            }
        }
        // Every position comes up (expected 125 each).
        assert!(seen.iter().all(|&c| c > 50), "{seen:?}");
    }
}
