// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault metadata (spec 0003 §3).
//!
//! | Key | Field | CBOR | |
//! |-----|-------|------|---|
//! | 0 | name | text | required |
//! | 1 | description | text | optional |
//! | 2 | root_group | bstr 16 | required |
//! | 3 | settings | map | required |
//!
//! Settings: 0 `history_depth` (uint, optional, default 10, 0007 §1.1),
//! 1 `trash_retention_days` (uint, optional, default 30, 0007 §2.1),
//! 2 `generator` (map, optional; the password generator defaults, 0010 §5.1),
//! 3 `recovery_skipped_at` (uint ms, optional; when the recovery-phrase
//! confirmation was explicitly skipped, 0002 §4.2; development value).
//!
//! A known settings field replaces an unknown value kept at its key: a new
//! `generator` drops the unreadable key-2 value in [`Settings::ext`] instead
//! of writing key 2 twice (review of plan 0010, finding 1).
//! Generator defaults (key 2), a map whose key 0 is the mode and whose other
//! keys depend on it; every key of the mode is required:
//!
//! | Mode (key 0) | Keys |
//! |--------------|------|
//! | 0 characters | 1 length, 2 lowercase, 3 uppercase, 4 digits, 5 symbols, 6 exclude_ambiguous, 7 exclude_chars (text), 8 require_each_class |
//! | 1 passphrase | 1 words, 2 wordlist (0 = eff-large), 3 separator (text, one character), 4 capitalize (0 none, 1 first letter), 5 append_digit |
//! | 2 PIN | 1 length |
//!
//! Flags are CBOR booleans and counts are `u32`. Ranges are not checked
//! here; `qv-crypto` revalidates the settings at every use (0010 §2.1.3).
//! Unknown keys inside the map are kept ([`GeneratorDefaults::ext`]). An
//! unknown mode, word list or capitalization is not a security or control
//! kind, so it does not fail: the whole key-2 value is kept unchanged in
//! [`Settings::ext`] and [`Settings::generator`] is `None` (the spec
//! defaults apply).

use qv_crypto::{
    Capitalization, CharacterSettings, GeneratorSettings, PassphraseSettings, PinSettings,
    WordListId,
};
use qv_encoding::{Decoder, EncodeError, Encoder, MapEncoder};

use crate::codec::{
    keep, put_bool, put_ext, put_id, put_opt_text, put_opt_time, put_opt_uint, put_text, put_uint,
    read_id, read_map_len, read_text, read_time, read_u32, req,
};
use crate::error::ModelError;
use crate::ids::RecordId;
use crate::text::{Extensions, Text};
use crate::time::Timestamp;

/// The default number of retained historical versions (0007 §1.1).
pub const DEFAULT_HISTORY_DEPTH: u32 = 10;
/// The default trash retention in days (0007 §2.1).
pub const DEFAULT_TRASH_RETENTION_DAYS: u32 = 30;

/// The vault metadata record's payload. Exactly one per vault.
pub struct VaultMeta {
    /// The vault's name.
    pub name: Text,
    /// An optional description.
    pub description: Option<Text>,
    /// The root group, fixed at vault creation (0003 §2.3).
    pub root_group: RecordId,
    /// Vault-wide settings.
    pub settings: Settings,
    /// Unknown keys.
    pub ext: Extensions,
}

/// Vault-wide settings (0003 §3). `None` means "the default".
#[derive(Default)]
pub struct Settings {
    /// Historical versions to keep per record.
    pub history_depth: Option<u32>,
    /// Days before trashed items are offered for final deletion.
    pub trash_retention_days: Option<u32>,
    /// The password generator defaults; `None` means the 0010 defaults.
    pub generator: Option<GeneratorDefaults>,
    /// When the user explicitly skipped confirming the recovery phrase
    /// (0002 §4.2); `None` if it was confirmed (or never asked).
    pub recovery_skipped_at: Option<Timestamp>,
    /// Unknown keys (and a key-2 value this version cannot read).
    pub ext: Extensions,
}

/// The vault's password generator defaults (0010 §5.1).
pub struct GeneratorDefaults {
    /// The settings; revalidated by `qv-crypto` at every use.
    pub settings: GeneratorSettings,
    /// Unknown keys of the generator map.
    pub ext: Extensions,
}

impl Settings {
    /// The history depth, or [`DEFAULT_HISTORY_DEPTH`].
    pub fn history_depth_or_default(&self) -> u32 {
        self.history_depth.unwrap_or(DEFAULT_HISTORY_DEPTH)
    }

    /// The trash retention, or [`DEFAULT_TRASH_RETENTION_DAYS`].
    pub fn trash_retention_days_or_default(&self) -> u32 {
        self.trash_retention_days
            .unwrap_or(DEFAULT_TRASH_RETENTION_DAYS)
    }
}

crate::redacted_debug!(VaultMeta, Settings, GeneratorDefaults);

pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<VaultMeta, ModelError> {
    let (mut name, mut description, mut root, mut settings) = (None, None, None, None);
    let mut ext = Extensions::new();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => name = Some(read_text(d)?),
            1 => description = Some(read_text(d)?),
            2 => root = Some(read_id(d)?),
            3 => settings = Some(decode_settings(d)?),
            k => keep(&mut ext, k, d)?,
        }
    }
    Ok(VaultMeta {
        name: req(name)?,
        description,
        root_group: req(root)?,
        settings: req(settings)?,
        ext,
    })
}

fn decode_settings(d: &mut Decoder<'_>) -> Result<Settings, ModelError> {
    let mut s = Settings::default();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => s.history_depth = Some(read_u32(d)?),
            1 => s.trash_retention_days = Some(read_u32(d)?),
            2 => {
                let raw = d.raw_value()?;
                match decode_generator(&mut raw.decoder())? {
                    Some(g) => s.generator = Some(g),
                    None => s.ext.push(2, raw),
                }
            }
            3 => s.recovery_skipped_at = Some(read_time(d)?),
            k => keep(&mut s.ext, k, d)?,
        }
    }
    Ok(s)
}

fn read_bool(d: &mut Decoder<'_>) -> Result<bool, ModelError> {
    Ok(d.bool()?)
}

/// One character as a one-character text string.
fn read_char(d: &mut Decoder<'_>) -> Result<char, ModelError> {
    let mut chars = d.text()?.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => Ok(c),
        _ => Err(ModelError::Malformed),
    }
}

/// The generator map; `None` for a mode, word list or capitalization this
/// version does not know.
fn decode_generator(d: &mut Decoder<'_>) -> Result<Option<GeneratorDefaults>, ModelError> {
    let n = read_map_len(d)?;
    // Key 0 sorts first in a canonical map with integer keys.
    if n == 0 || d.int()? != 0 {
        return Err(ModelError::Malformed);
    }
    let mode = d.uint()?;
    let mut ext = Extensions::new();
    let settings = match mode {
        0 => {
            let (mut length, mut lower, mut upper, mut digits, mut symbols) =
                (None, None, None, None, None);
            let (mut ambiguous, mut exclude, mut each) = (None, None, None);
            for _ in 1..n {
                match d.int()? {
                    1 => length = Some(read_u32(d)?),
                    2 => lower = Some(read_bool(d)?),
                    3 => upper = Some(read_bool(d)?),
                    4 => digits = Some(read_bool(d)?),
                    5 => symbols = Some(read_bool(d)?),
                    6 => ambiguous = Some(read_bool(d)?),
                    7 => exclude = Some(read_text(d)?),
                    8 => each = Some(read_bool(d)?),
                    k => keep(&mut ext, k, d)?,
                }
            }
            GeneratorSettings::Characters(CharacterSettings {
                length: req(length)?,
                lowercase: req(lower)?,
                uppercase: req(upper)?,
                digits: req(digits)?,
                symbols: req(symbols)?,
                exclude_ambiguous: req(ambiguous)?,
                exclude_chars: req(exclude)?.expose().to_owned(),
                require_each_class: req(each)?,
            })
        }
        1 => {
            let (mut words, mut list, mut sep, mut cap, mut digit) = (None, None, None, None, None);
            for _ in 1..n {
                match d.int()? {
                    1 => words = Some(read_u32(d)?),
                    2 => list = Some(d.uint()?),
                    3 => sep = Some(read_char(d)?),
                    4 => cap = Some(d.uint()?),
                    5 => digit = Some(read_bool(d)?),
                    k => keep(&mut ext, k, d)?,
                }
            }
            let wordlist = match req(list)? {
                0 => WordListId::EffLarge,
                _ => return Ok(None),
            };
            let capitalize = match req(cap)? {
                0 => Capitalization::None,
                1 => Capitalization::FirstLetter,
                _ => return Ok(None),
            };
            GeneratorSettings::Passphrase(PassphraseSettings {
                words: req(words)?,
                wordlist,
                separator: req(sep)?,
                capitalize,
                append_digit: req(digit)?,
            })
        }
        2 => {
            let mut length = None;
            for _ in 1..n {
                match d.int()? {
                    1 => length = Some(read_u32(d)?),
                    k => keep(&mut ext, k, d)?,
                }
            }
            GeneratorSettings::Pin(PinSettings {
                length: req(length)?,
            })
        }
        _ => return Ok(None),
    };
    Ok(Some(GeneratorDefaults { settings, ext }))
}

fn encode_generator(g: &GeneratorDefaults, m: &mut MapEncoder) -> Result<(), EncodeError> {
    match &g.settings {
        GeneratorSettings::Characters(c) => {
            put_uint(m, 0, 0)?;
            put_uint(m, 1, u64::from(c.length))?;
            put_bool(m, 2, c.lowercase)?;
            put_bool(m, 3, c.uppercase)?;
            put_bool(m, 4, c.digits)?;
            put_bool(m, 5, c.symbols)?;
            put_bool(m, 6, c.exclude_ambiguous)?;
            m.entry(7, |v| {
                v.text(&c.exclude_chars);
                Ok(())
            })?;
            put_bool(m, 8, c.require_each_class)?;
        }
        GeneratorSettings::Passphrase(p) => {
            put_uint(m, 0, 1)?;
            put_uint(m, 1, u64::from(p.words))?;
            let list = match p.wordlist {
                WordListId::EffLarge => 0,
                // `WordListId` is non-exhaustive; a list without a registry
                // value here cannot be stored.
                _ => return Err(EncodeError::ItemCount),
            };
            put_uint(m, 2, list)?;
            m.entry(3, |v| {
                v.text(p.separator.encode_utf8(&mut [0; 4]));
                Ok(())
            })?;
            let cap = match p.capitalize {
                Capitalization::None => 0,
                Capitalization::FirstLetter => 1,
            };
            put_uint(m, 4, cap)?;
            put_bool(m, 5, p.append_digit)?;
        }
        GeneratorSettings::Pin(p) => {
            put_uint(m, 0, 2)?;
            put_uint(m, 1, u64::from(p.length))?;
        }
    }
    put_ext(m, &g.ext)
}

pub(crate) fn encode(p: &VaultMeta, e: &mut Encoder) -> Result<(), EncodeError> {
    e.map(|m| {
        put_text(m, 0, &p.name)?;
        put_opt_text(m, 1, p.description.as_ref())?;
        put_id(m, 2, &p.root_group)?;
        m.entry(3, |v| {
            v.map(|s| {
                put_opt_uint(s, 0, p.settings.history_depth.map(u64::from))?;
                put_opt_uint(s, 1, p.settings.trash_retention_days.map(u64::from))?;
                if let Some(g) = &p.settings.generator {
                    s.entry(2, |v| v.map(|m| encode_generator(g, m)))?;
                }
                put_opt_time(s, 3, p.settings.recovery_skipped_at)?;
                // A known field written above replaces a kept unknown value.
                for (k, v) in p.settings.ext.iter() {
                    let known = match *k {
                        2 => p.settings.generator.is_some(),
                        3 => p.settings.recovery_skipped_at.is_some(),
                        _ => false,
                    };
                    if !known {
                        s.raw_entry(*k, v)?;
                    }
                }
                Ok(())
            })
        })?;
        put_ext(m, &p.ext)
    })
}

#[cfg(test)]
mod tests {
    use qv_crypto::{Capitalization, CharacterSettings, GeneratorSettings, PinSettings};
    use qv_encoding::{Decoder, Encoder};

    use super::*;
    use crate::ids::test_ids::rid;

    fn meta(generator: Option<GeneratorSettings>) -> VaultMeta {
        VaultMeta {
            name: Text::new("v").unwrap(),
            description: None,
            root_group: rid(1),
            settings: Settings {
                history_depth: None,
                trash_retention_days: Some(7),
                generator: generator.map(|settings| GeneratorDefaults {
                    settings,
                    ext: Extensions::new(),
                }),
                recovery_skipped_at: None,
                ext: Extensions::new(),
            },
            ext: Extensions::new(),
        }
    }

    fn enc(m: &VaultMeta) -> Vec<u8> {
        let mut e = Encoder::new();
        encode(m, &mut e).unwrap();
        e.finish().unwrap().to_vec()
    }

    fn dec(bytes: &[u8]) -> Result<VaultMeta, ModelError> {
        let mut d = Decoder::new(bytes)?;
        let m = decode(&mut d)?;
        d.finish()?;
        Ok(m)
    }

    /// A vault metadata map whose settings hold `generator` (raw CBOR) at key 2.
    fn with_generator(generator: &[u8]) -> Vec<u8> {
        let mut out = vec![0xa3, 0x00, 0x61, b'v', 0x02, 0x50];
        out.extend_from_slice(&rid(1).0);
        out.extend_from_slice(&[0x03, 0xa1, 0x02]);
        out.extend_from_slice(generator);
        out
    }

    #[test]
    fn settings_generator_round_trip() {
        let passphrase = GeneratorSettings::Passphrase(qv_crypto::PassphraseSettings {
            words: 7,
            separator: '_',
            capitalize: Capitalization::FirstLetter,
            append_digit: true,
            ..Default::default()
        });
        let chars = GeneratorSettings::Characters(CharacterSettings {
            length: 30,
            symbols: false,
            exclude_chars: "xyz".into(),
            ..Default::default()
        });
        for g in [
            None,
            Some(chars),
            Some(passphrase),
            Some(GeneratorSettings::Pin(PinSettings { length: 8 })),
        ] {
            let bytes = enc(&meta(g.clone()));
            let back = dec(&bytes).unwrap();
            assert_eq!(
                back.settings.generator.as_ref().map(|x| &x.settings),
                g.as_ref()
            );
            assert_eq!(back.settings.trash_retention_days, Some(7));
            assert_eq!(enc(&back), bytes);
        }
    }

    #[test]
    fn settings_generator_unknown_parts_are_kept() {
        // A PIN map with an unknown key 9: decoded, the key kept.
        let pin = encode_map(&[(0, &[0x02]), (1, &[0x06]), (9, &[0xf5])]);
        let bytes = with_generator(&pin);
        let m = dec(&bytes).unwrap();
        let g = m.settings.generator.as_ref().unwrap();
        assert_eq!(
            g.settings,
            GeneratorSettings::Pin(PinSettings { length: 6 })
        );
        assert_eq!(g.ext.len(), 1);
        assert_eq!(enc(&m), bytes);

        // An unknown mode, word list or capitalization: kept raw, no defaults.
        let unknown = [
            encode_map(&[(0, &[0x07]), (1, &[0x06])]),
            encode_map(&[
                (0, &[0x01]),
                (1, &[0x06]),
                (2, &[0x05]),
                (3, &[0x61, b'.']),
                (4, &[0x00]),
                (5, &[0xf4]),
            ]),
            encode_map(&[
                (0, &[0x01]),
                (1, &[0x06]),
                (2, &[0x00]),
                (3, &[0x61, b'.']),
                (4, &[0x02]),
                (5, &[0xf4]),
            ]),
        ];
        for g in unknown {
            let bytes = with_generator(&g);
            let m = dec(&bytes).unwrap();
            assert!(m.settings.generator.is_none());
            assert_eq!(m.settings.ext.len(), 1);
            assert_eq!(enc(&m), bytes);
        }
    }

    #[test]
    fn settings_recovery_skip_round_trip() {
        let mut m = meta(None);
        let none = enc(&m);
        assert!(dec(&none).unwrap().settings.recovery_skipped_at.is_none());
        m.settings.recovery_skipped_at = Some(Timestamp(1_700_000_000_000));
        let bytes = enc(&m);
        assert_ne!(bytes, none);
        let back = dec(&bytes).unwrap();
        assert_eq!(
            back.settings.recovery_skipped_at,
            Some(Timestamp(1_700_000_000_000))
        );
        assert_eq!(enc(&back), bytes);
        // A non-integer value at key 3 is malformed.
        let bad = {
            let mut out = vec![0xa3, 0x00, 0x61, b'v', 0x02, 0x50];
            out.extend_from_slice(&rid(1).0);
            out.extend_from_slice(&[0x03, 0xa1, 0x03, 0x61, b'x']);
            out
        };
        assert!(matches!(dec(&bad), Err(ModelError::Malformed)));
    }

    #[test]
    fn settings_new_generator_replaces_an_unreadable_one() {
        // Review of plan 0010, finding 1: an unknown mode is kept raw at
        // key 2; setting new defaults must replace it, not write key 2 twice.
        let unknown = encode_map(&[(0, &[0x07]), (1, &[0x06])]);
        let mut m = dec(&with_generator(&unknown)).unwrap();
        assert!(m.settings.generator.is_none());
        m.settings.generator = Some(GeneratorDefaults {
            settings: GeneratorSettings::Pin(PinSettings { length: 8 }),
            ext: Extensions::new(),
        });
        let bytes = enc(&m);
        let back = dec(&bytes).unwrap();
        assert_eq!(
            back.settings.generator.as_ref().map(|g| &g.settings),
            Some(&GeneratorSettings::Pin(PinSettings { length: 8 }))
        );
        assert!(back.settings.ext.is_empty());
        // Exactly the encoding of a vault meta that only ever had the PIN.
        let pin = encode_map(&[(0, &[0x02]), (1, &[0x08])]);
        assert_eq!(bytes, with_generator(&pin));
    }

    #[test]
    fn settings_generator_rejections() {
        let pp = |sep: &[u8], digit: &[u8]| {
            encode_map(&[
                (0, &[0x01]),
                (1, &[0x06]),
                (2, &[0x00]),
                (3, sep),
                (4, &[0x00]),
                (5, digit),
            ])
        };
        let bad = [
            // Two-character separator, an empty one, a non-bool flag.
            pp(&[0x62, b'.', b'.'], &[0xf4]),
            pp(&[0x60], &[0xf4]),
            pp(&[0x61, b'.'], &[0x00]),
            // A missing key of the mode, no mode, a mode that is not key 0.
            encode_map(&[(0, &[0x02])]),
            encode_map(&[]),
            encode_map(&[(1, &[0x06])]),
        ];
        for g in bad {
            assert_eq!(
                dec(&with_generator(&g)).map(|_| ()),
                Err(ModelError::Malformed)
            );
        }
        // Ranges are checked at use, not here.
        let huge = encode_map(&[(0, &[0x02]), (1, &[0x19, 0x03, 0xe8])]);
        let m = dec(&with_generator(&huge)).unwrap();
        assert_eq!(
            m.settings.generator.unwrap().settings,
            GeneratorSettings::Pin(PinSettings { length: 1000 })
        );
    }

    /// A canonical map of small integer keys to raw values.
    fn encode_map(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = vec![0xa0 | u8::try_from(entries.len()).unwrap()];
        for (k, v) in entries {
            out.push(*k);
            out.extend_from_slice(v);
        }
        out
    }
}
