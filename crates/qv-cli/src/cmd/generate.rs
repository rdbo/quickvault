// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault generate [options]` (spec 0011 §4; 0010).
//!
//! Without options, the selected vault's defaults are used (the vault is
//! unlocked for them); with no vault selected, the 0010 defaults. Any
//! option decides the mode and starts from the 0010 defaults of that mode;
//! options of different modes together are a usage error.
//!
//! The value goes to standard output (escaped on a terminal, exactly as
//! generated on a pipe); its exact entropy, label and the below-64-bit
//! warning (0010 §4.1) go to standard error. Nothing is saved, and there is
//! no generator history (0010 §6.3).

use clap::ArgMatches;
use qv_core::{
    Capitalization, CharacterSettings, Generated, GeneratorSettings, PassphraseSettings,
    PinSettings,
};

use crate::cli::Ctx;
use crate::cmd::init::label;
use crate::exit::CliError;
use crate::json::Json;
use crate::out::Out;
use crate::term;

const CHAR_FLAGS: [&str; 5] = [
    "no-lower",
    "no-upper",
    "no-digits",
    "no-symbols",
    "exclude-ambiguous",
];
const PASSPHRASE_FLAGS: [&str; 1] = ["capitalize"];

/// The settings the options ask for, or `None` without options.
pub(crate) fn from_options(m: &ArgMatches) -> Result<Option<GeneratorSettings>, CliError> {
    let chars = m.contains_id("length")
        || m.contains_id("exclude")
        || CHAR_FLAGS.iter().any(|f| m.get_flag(f));
    let words = m.contains_id("words")
        || m.contains_id("separator")
        || PASSPHRASE_FLAGS.iter().any(|f| m.get_flag(f));
    let pin = m.contains_id("pin");
    if usize::from(chars) + usize::from(words) + usize::from(pin) > 1 {
        return Err(CliError::usage(
            "character, passphrase and PIN options cannot be combined",
        ));
    }
    if chars {
        let mut c = CharacterSettings::default();
        if let Some(n) = m.get_one::<u32>("length") {
            c.length = *n;
        }
        c.lowercase &= !m.get_flag("no-lower");
        c.uppercase &= !m.get_flag("no-upper");
        c.digits &= !m.get_flag("no-digits");
        c.symbols &= !m.get_flag("no-symbols");
        c.exclude_ambiguous |= m.get_flag("exclude-ambiguous");
        if let Some(x) = m.get_one::<String>("exclude") {
            c.exclude_chars = x.clone();
        }
        return Ok(Some(GeneratorSettings::Characters(c)));
    }
    if words {
        let mut p = PassphraseSettings::default();
        if let Some(n) = m.get_one::<u32>("words") {
            p.words = *n;
        }
        if let Some(s) = m.get_one::<String>("separator") {
            let mut it = s.chars();
            p.separator = match (it.next(), it.next()) {
                (Some(c), None) => c,
                _ => return Err(CliError::usage("--separator takes exactly one character")),
            };
        }
        if m.get_flag("capitalize") {
            p.capitalize = Capitalization::FirstLetter;
        }
        return Ok(Some(GeneratorSettings::Passphrase(p)));
    }
    if let Some(n) = m.get_one::<u32>("pin") {
        return Ok(Some(GeneratorSettings::Pin(PinSettings { length: *n })));
    }
    Ok(None)
}

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let copy_options = if m.get_flag("copy") {
        Some(crate::clipboard::options(ctx, m)?)
    } else {
        None
    };
    let generated: Generated = match from_options(m)? {
        Some(settings) => qv_core::generate(&settings)?,
        None => match crate::select::selected_vault(ctx.vault.as_deref(), &ctx.env)? {
            Some(path) => {
                let session = ctx.unlock_path(&path)?;
                let g = session.generate(None)?;
                session.lock();
                g
            }
            None => qv_core::generate(&GeneratorSettings::default())?,
        },
    };
    let estimate = generated.estimate();
    if let Some(options) = copy_options {
        let value = super::copy::protected_copy(generated.expose_secret().as_bytes())?;
        drop(generated);
        let mut err = Out::stderr();
        err.raw(&format!(
            "{:.1} bits ({})\n",
            estimate.bits,
            label(estimate.strength)
        ));
        if estimate.bits < 64.0 {
            err.raw("warning: less than 64 bits; a longer password or more words is safer\n");
        }
        err.flush()?;
        return crate::clipboard::hold(value, options);
    }
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj();
        j.key("value").str(generated.expose_secret());
        j.key("bits").bits(estimate.bits);
        j.key("strength").str(label(estimate.strength));
        j.end_obj();
    } else if term::stdout_is_tty() {
        out.text(generated.expose_secret());
    } else {
        out.verbatim(generated.expose_secret().as_bytes());
    }
    out.raw("\n");
    out.flush()?;
    drop(generated);
    let mut err = Out::stderr();
    err.raw(&format!(
        "{:.1} bits ({})\n",
        estimate.bits,
        label(estimate.strength)
    ));
    if estimate.bits < 64.0 {
        err.raw("warning: less than 64 bits; a longer password or more words is safer\n");
    }
    err.flush()
}
