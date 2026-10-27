// SPDX-License-Identifier: AGPL-3.0-or-later

//! The config file (spec 0011 §1.3): non-secret preferences only.
//!
//! `$XDG_CONFIG_HOME/quickvault/config.toml` (when `XDG_CONFIG_HOME` is an
//! absolute path), else `$HOME/.config/quickvault/config.toml`. A missing
//! file is an empty config.
//!
//! The parser accepts a strict subset of TOML 1.0, and every file it accepts
//! means the same in TOML: blank lines, `# comments`, and top-level
//! `key = value` lines with a bare key and a basic string (`"…"`, escapes
//! `\b \t \n \f \r \" \\ \uXXXX \UXXXXXXXX`), a literal string (`'…'`), a
//! decimal integer or a boolean, optionally followed by a comment. Anything
//! else (tables, arrays, inline tables, dotted, quoted, duplicate or unknown
//! keys, floats, dates) is an error naming the line and, where known, the
//! key, never the value. The file is at most [`MAX_CONFIG_BYTES`].
//!
//! | Key | Type | Meaning |
//! |-----|------|---------|
//! | `default_vault` | string, absolute path | the vault used when neither `--vault` nor `QVAULT_PATH` is given |
//! | `clipboard_timeout` | integer, 1–300 | seconds before `copy` clears the clipboard (phase 1.10c) |
//! | `color` | `"auto"` or `"never"` | colour output; qvault emits no colour yet, so both behave the same |

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::exit::CliError;

/// The largest config file read.
pub(crate) const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Colour preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Color {
    Auto,
    Never,
}

/// The parsed config.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) default_vault: Option<PathBuf>,
    pub(crate) clipboard_timeout: Option<u32>,
    #[allow(dead_code)] // no colour output yet (0011 §5.1 only restricts it)
    pub(crate) color: Option<Color>,
}

enum Value {
    Str(String),
    Int(i64),
    /// No key takes a boolean yet; parsed so the subset stays TOML.
    Bool,
}

fn err(line: usize, what: &str) -> CliError {
    CliError::usage(format!("config file line {line}: {what}"))
}

fn is_ws(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Reads and parses the config at `path`; a missing file is empty.
pub(crate) fn load(path: &Path) -> Result<Config, CliError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(_) => return Err(CliError::usage("cannot read the config file")),
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_CONFIG_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::usage("cannot read the config file"))?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(CliError::usage("the config file is larger than 64 KiB"));
    }
    let text =
        String::from_utf8(bytes).map_err(|_| CliError::usage("the config file is not UTF-8"))?;
    parse(&text)
}

/// Parses config text.
pub(crate) fn parse(text: &str) -> Result<Config, CliError> {
    let mut config = Config::default();
    let mut seen: Vec<String> = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        let n = i + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let rest = line.trim_start_matches(is_ws);
        if rest.is_empty() || rest.starts_with('#') {
            check_comment(rest, n)?;
            continue;
        }
        let key_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(rest.len());
        if key_len == 0 {
            return Err(err(
                n,
                "expected `key = value` (tables and quoted keys are not supported)",
            ));
        }
        let (key, after) = rest.split_at(key_len);
        let after = after.trim_start_matches(is_ws);
        let Some(after) = after.strip_prefix('=') else {
            return Err(err(
                n,
                &format!("expected `=` after `{key}` (dotted keys are not supported)"),
            ));
        };
        let (value, tail) = parse_value(after.trim_start_matches(is_ws), n, key)?;
        let tail = tail.trim_start_matches(is_ws);
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(err(
                n,
                &format!("unexpected text after the value of `{key}`"),
            ));
        }
        check_comment(tail, n)?;
        if seen.iter().any(|k| k == key) {
            return Err(err(n, &format!("duplicate key `{key}`")));
        }
        seen.push(key.to_owned());
        apply(&mut config, key, value, n)?;
    }
    Ok(config)
}

/// TOML forbids control characters other than tab in comments.
fn check_comment(s: &str, n: usize) -> Result<(), CliError> {
    if s.chars().any(|c| c != '\t' && (c.is_control())) {
        return Err(err(n, "control character in a comment"));
    }
    Ok(())
}

fn parse_value<'a>(s: &'a str, n: usize, key: &str) -> Result<(Value, &'a str), CliError> {
    let bad = || err(n, &format!("unsupported or invalid value for `{key}`"));
    if let Some(body) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = body.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Ok((Value::Str(out), &body[i + 1..])),
                '\\' => {
                    let (_, e) = chars.next().ok_or_else(bad)?;
                    let simple = match e {
                        'b' => Some('\u{8}'),
                        't' => Some('\t'),
                        'n' => Some('\n'),
                        'f' => Some('\u{c}'),
                        'r' => Some('\r'),
                        '"' => Some('"'),
                        '\\' => Some('\\'),
                        _ => None,
                    };
                    if let Some(c) = simple {
                        out.push(c);
                        continue;
                    }
                    let digits = match e {
                        'u' => 4,
                        'U' => 8,
                        _ => return Err(bad()),
                    };
                    let mut v = 0u32;
                    for _ in 0..digits {
                        let (_, h) = chars.next().ok_or_else(bad)?;
                        v = v * 16 + h.to_digit(16).ok_or_else(bad)?;
                    }
                    out.push(char::from_u32(v).ok_or_else(bad)?);
                }
                c if c != '\t' && c.is_control() => return Err(bad()),
                c => out.push(c),
            }
        }
        return Err(bad());
    }
    if let Some(body) = s.strip_prefix('\'') {
        let end = body.find('\'').ok_or_else(bad)?;
        let text = &body[..end];
        if text.chars().any(|c| c != '\t' && c.is_control()) {
            return Err(bad());
        }
        return Ok((Value::Str(text.to_owned()), &body[end + 1..]));
    }
    let end = s.find(|c: char| is_ws(c) || c == '#').unwrap_or(s.len());
    let (word, tail) = s.split_at(end);
    match word {
        "true" | "false" => return Ok((Value::Bool, tail)),
        _ => {}
    }
    Ok((Value::Int(parse_int(word).ok_or_else(bad)?), tail))
}

/// A TOML decimal integer: optional sign, no leading zeros, `_` only
/// between digits.
fn parse_int(word: &str) -> Option<i64> {
    let digits = word.strip_prefix(['+', '-']).unwrap_or(word);
    let b = digits.as_bytes();
    if b.is_empty() || !b[0].is_ascii_digit() || !b[b.len() - 1].is_ascii_digit() {
        return None;
    }
    if b.len() > 1 && b[0] == b'0' {
        return None;
    }
    if b.windows(2).any(|w| w[0] == b'_' && w[1] == b'_') {
        return None;
    }
    if !b.iter().all(|c| c.is_ascii_digit() || *c == b'_') {
        return None;
    }
    let clean: String = word.chars().filter(|c| *c != '_').collect();
    clean.parse().ok()
}

fn apply(config: &mut Config, key: &str, value: Value, n: usize) -> Result<(), CliError> {
    let invalid = || err(n, &format!("invalid value for `{key}`"));
    match (key, value) {
        ("default_vault", Value::Str(s)) => {
            let p = PathBuf::from(s);
            if !p.is_absolute() {
                return Err(err(n, "`default_vault` must be an absolute path"));
            }
            config.default_vault = Some(p);
        }
        ("clipboard_timeout", Value::Int(t)) => {
            let t = u32::try_from(t).map_err(|_| invalid())?;
            if !(1..=300).contains(&t) {
                return Err(err(n, "`clipboard_timeout` must be 1 to 300 seconds"));
            }
            config.clipboard_timeout = Some(t);
        }
        ("color", Value::Str(s)) => {
            config.color = Some(match s.as_str() {
                "auto" => Color::Auto,
                "never" => Color::Never,
                _ => return Err(err(n, "`color` must be \"auto\" or \"never\"")),
            });
        }
        ("default_vault" | "clipboard_timeout" | "color", _) => return Err(invalid()),
        _ => {
            return Err(err(
                n,
                &format!("unknown key `{}`", crate::out::escape_str(key)),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Config {
        parse(s).unwrap()
    }

    fn fails(s: &str) -> String {
        let e = parse(s).unwrap_err();
        assert_eq!(e.code, 2, "{s}");
        e.message
    }

    #[test]
    fn config_accepts_the_subset() {
        assert_eq!(ok(""), Config::default());
        assert_eq!(ok("# only a comment\n\n   \n"), Config::default());
        let c = ok(
            "default_vault = \"/home/a/v.qvault\" # mine\r\nclipboard_timeout=20\ncolor = 'never'\n",
        );
        assert_eq!(c.default_vault, Some(PathBuf::from("/home/a/v.qvault")));
        assert_eq!(c.clipboard_timeout, Some(20));
        assert_eq!(c.color, Some(Color::Never));
        assert_eq!(
            ok("default_vault = \"/a\\u00e9/b\\\\c\\\"d\"").default_vault,
            Some(PathBuf::from("/a\u{e9}/b\\c\"d"))
        );
        assert_eq!(
            ok("default_vault = '/x\\y'").default_vault,
            Some(PathBuf::from("/x\\y"))
        );
        assert_eq!(ok("clipboard_timeout = +3_0").clipboard_timeout, Some(30));
        assert_eq!(ok("color = \"auto\"").color, Some(Color::Auto));
    }

    #[test]
    fn config_rejects_everything_else() {
        let secret = "s3cr3t-value";
        for (text, needle) in [
            ("[table]", "line 1"),
            ("a.b = 1", "dotted"),
            ("\"default_vault\" = \"/x\"", "quoted"),
            ("default_vault = [\"/x\"]", "default_vault"),
            ("default_vault = { a = 1 }", "default_vault"),
            (
                "color = \"auto\"\ncolor = \"never\"",
                "line 2: duplicate key `color`",
            ),
            ("token = \"s3cr3t-value\"", "unknown key `token`"),
            ("default_vault = \"relative/v.qvault\"", "absolute"),
            ("clipboard_timeout = 0", "1 to 300"),
            ("clipboard_timeout = 301", "1 to 300"),
            ("clipboard_timeout = -1", "clipboard_timeout"),
            ("clipboard_timeout = 020", "clipboard_timeout"),
            ("clipboard_timeout = 1__0", "clipboard_timeout"),
            ("clipboard_timeout = 0x10", "clipboard_timeout"),
            ("clipboard_timeout = 1.5", "clipboard_timeout"),
            ("clipboard_timeout = \"20\"", "clipboard_timeout"),
            ("color = true", "color"),
            ("color = \"always\"", "color"),
            ("default_vault = \"/x\\q\"", "default_vault"),
            ("default_vault = \"/x", "default_vault"),
            ("default_vault = \"/x\" trailing", "after the value"),
            ("default_vault = \"/x\u{1}\"", "default_vault"),
            ("# bell \u{7}", "control"),
        ] {
            let m = fails(text);
            assert!(m.contains(needle), "{text:?} → {m}");
            assert!(!m.contains(secret), "{m}");
        }
    }

    #[test]
    fn config_load_bounds() {
        let dir = std::env::temp_dir().join(format!("qv-cli-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.toml");
        assert_eq!(load(&p).unwrap(), Config::default());
        std::fs::write(&p, "#".repeat(MAX_CONFIG_BYTES)).unwrap();
        assert_eq!(load(&p).unwrap(), Config::default());
        std::fs::write(&p, "#".repeat(MAX_CONFIG_BYTES + 1)).unwrap();
        assert!(load(&p).unwrap_err().message.contains("64 KiB"));
        std::fs::write(&p, b"color = \"\xff\"").unwrap();
        assert!(load(&p).unwrap_err().message.contains("UTF-8"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
