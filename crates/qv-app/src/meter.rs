// SPDX-License-Identifier: AGPL-3.0-or-later

//! The live strength display for a new master password (0010 §4.2, plan
//! 0072). The page asks for a rating once typing pauses; Rust rates the
//! protected input only if it changed since the last rating, and the page
//! receives the label and bits, never the password. `zxcvbn`'s unzeroized
//! copies (`qv_core::strength`) therefore occur once per pause, not per
//! keystroke.
use ctutils::CtEq;
use qv_core::{Generated, MasterPassword, Strength};

/// A rating of the typed password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meter {
    /// The label (0010 §3.3).
    pub strength: Strength,
    /// Whole estimated bits.
    pub bits: u32,
}

/// The rating state of one new-password field.
#[derive(Default)]
pub(crate) struct Rating {
    pub(crate) meter: Option<Meter>,
    /// The field changed since `meter` was computed.
    stale: bool,
}
impl Rating {
    /// The field changed; an emptied field shows no rating at once.
    pub(crate) fn typed(&mut self, empty: bool) {
        self.stale = true;
        if empty {
            self.meter = None;
        }
    }
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
    /// Rates `typed` if it changed since the last rating; `true` when the
    /// shown rating changed.
    pub(crate) fn rate(&mut self, typed: &[u8], suggestion: Option<&Generated>) -> bool {
        if !self.stale {
            return false;
        }
        self.stale = false;
        let meter = rate(typed, suggestion);
        let changed = meter != self.meter;
        self.meter = meter;
        changed
    }
}

/// `None` for an empty or invalid password. A typed copy of the shown
/// suggestion has the suggestion's exact entropy (0010 §3.1).
pub(crate) fn rate(typed: &[u8], suggestion: Option<&Generated>) -> Option<Meter> {
    if typed.is_empty() {
        return None;
    }
    let password = MasterPassword::from_utf8(typed).ok()?;
    let (bits, strength) =
        match suggestion.filter(|g| g.expose_secret().as_bytes().ct_eq(typed).to_bool()) {
            Some(g) => (g.estimate().bits, g.estimate().strength),
            None => {
                let check = qv_core::password_strength(&password);
                (check.bits, check.strength)
            }
        };
    Some(Meter {
        strength,
        // Finite and non-negative by construction; at most a few hundred.
        bits: bits.clamp(0.0, 4096.0) as u32,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn rates_once_per_change_and_never_an_empty_field() {
        let mut r = Rating::default();
        assert!(
            !r.rate(b"anything", None),
            "nothing typed since the last rating"
        );
        r.typed(false);
        assert!(r.rate(b"password", None));
        assert_eq!(r.meter.unwrap().strength, Strength::Weak);
        assert!(
            !r.rate(b"password", None),
            "unchanged input is not rated again"
        );
        r.typed(false);
        assert!(r.rate(b"correct horse battery staple tumbles over quietly", None));
        assert!(r.meter.unwrap().bits >= 50);
        r.typed(true);
        assert_eq!(r.meter, None, "an emptied field clears the rating at once");
        assert!(!r.rate(b"", None));
        r.typed(false);
        r.clear();
        assert_eq!(r.meter, None);
        assert!(!r.rate(b"password", None));
    }

    #[test]
    fn a_typed_suggestion_has_its_exact_entropy() {
        let g = qv_core::generate(&qv_core::GeneratorSettings::Passphrase(
            qv_core::PassphraseSettings::default(),
        ))
        .unwrap();
        let typed = g.expose_secret().as_bytes().to_vec();
        let m = rate(&typed, Some(&g)).unwrap();
        assert_eq!(m.strength, g.estimate().strength);
        assert_eq!(m.bits, g.estimate().bits as u32);
        assert!(rate(b"", Some(&g)).is_none());
    }
}
