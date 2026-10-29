// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault init <path> [--name <name>]` (spec 0011 §4, §3.7, §5.4; 0010
//! §4.2; 0002 §4.2).
//!
//! 1. A generated 6-word passphrase is suggested on the alternate screen.
//!    If accepted, it is the master password; it is judged by its exact
//!    entropy and never passed to zxcvbn.
//! 2. Otherwise the password is typed twice, and the zxcvbn verdict
//!    applies: Fair prints a warning; Weak prints a warning, counts down
//!    5 seconds and asks for an explicit yes (`--yes` does not skip this).
//! 3. The vault is created; the recovery phrase is shown on the alternate
//!    screen until a key is pressed, so it does not stay in the scrollback.
//! 4. Three words at random positions are checked. An empty line offers
//!    to show the phrase again or to skip the check. (Typed commands would
//!    be ambiguous: `skip` and `show` are themselves BIP-39 words, or close
//!    to them.) A skip asks for confirmation and is recorded in the vault
//!    settings.
//!
//! `init` needs a terminal on standard input and output, and never reads
//! the password from standard input.

use std::path::{Path, PathBuf};

use clap::ArgMatches;
use qv_core::{
    GeneratorSettings, MasterPassword, PHRASE_WORDS, PassphraseSettings, PasswordVerdict,
    RecoveryPhrase, Session, Strength,
};

use crate::cli::Ctx;
use crate::exit::{CliError, OTHER};
use crate::out::{Out, escape_str};
use crate::term::{self, AltScreen, MAX_ANSWER_BYTES, MAX_PASSWORD_BYTES, Tty};

const WEAK_TEXT: &str = "This password is weak and could be guessed by an attacker who obtains \
your vault file.\n";

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let path = m
        .get_one::<PathBuf>("path")
        .ok_or_else(|| CliError::usage("missing path"))?;
    if ctx.password_stdin {
        return Err(CliError::usage(
            "init does not read the master password from standard input",
        ));
    }
    let tty = term::stdio_tty()?;
    if !term::stdout_is_tty() {
        return Err(CliError::usage(
            "init shows the recovery phrase and needs a terminal on standard output",
        ));
    }
    if path.extension().and_then(|e| e.to_str()) != Some(qv_core::VAULT_EXTENSION) {
        return Err(CliError::usage("the vault file name must end in .qvault"));
    }
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(CliError::new(OTHER, "path already exists"));
    }
    let name = match m.get_one::<String>("name") {
        Some(n) => n.clone(),
        None => path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Vault")
            .to_owned(),
    };
    let core = crate::select::core()?;

    let password = choose_password(&tty)?;
    let created = match core.create(path, &password, &name) {
        Ok(c) => c,
        Err(e) => return Err(create_failed(e.into(), path)),
    };
    drop(password);
    let session = created.session;
    crate::cli::warn_location(session.warnings()?);
    let phrase = created.recovery_phrase;
    show_phrase(&tty, &phrase)?;
    if !check_phrase(&tty, &phrase)? {
        session.record_recovery_skip()?;
    }
    drop(phrase);
    finish(&session, path)
}

/// A failure after the vault file may already exist (review of plan 0008).
fn create_failed(mut e: CliError, path: &Path) -> CliError {
    if std::fs::symlink_metadata(path).is_ok() {
        e.message.push_str(&format!(
            "\nhint: a vault file may still have been created at {}; check it with `qvault info`",
            escape_str(&path.to_string_lossy())
        ));
    }
    e
}

fn finish(session: &Session, path: &Path) -> Result<(), CliError> {
    let o = session.overview()?;
    let mut out = Out::stdout();
    out.raw("Created vault \"")
        .text(o.name.expose())
        .raw("\" at ")
        .text(&path.to_string_lossy())
        .raw(".\n");
    out.flush()?;
    session.lock();
    Ok(())
}

/// The master password: the accepted suggestion, or a typed one that
/// passed the strength rules.
pub(crate) fn choose_password(tty: &Tty<'_>) -> Result<MasterPassword, CliError> {
    let suggestion = qv_core::generate(&GeneratorSettings::Passphrase(PassphraseSettings {
        words: 6,
        ..Default::default()
    }))?;
    let use_it = {
        let _alt = AltScreen::enter()?;
        let mut o = Out::stdout();
        o.raw(&format!(
            "Suggested master password: {} random words, about {:.0} bits.\r\n\r\n    ",
            6,
            suggestion.estimate().bits
        ));
        o.text(suggestion.expose_secret());
        o.raw(
            "\r\n\r\nIt is shown only now. If you use it, learn it or write it down and keep \
             it safe.\r\n\r\n",
        );
        o.flush()?;
        tty.confirm("Use this passphrase?")?
    };
    if use_it {
        return Ok(MasterPassword::from_utf8(
            suggestion.expose_secret().as_bytes(),
        )?);
    }
    drop(suggestion);
    loop {
        let first = tty.secret("New master password: ", MAX_PASSWORD_BYTES)?;
        let again = tty.secret("Repeat the master password: ", MAX_PASSWORD_BYTES)?;
        if first.expose() != again.expose() {
            tty.say("The passwords do not match; try again.\n")?;
            continue;
        }
        drop(again);
        let password = MasterPassword::from_utf8(first.expose())?;
        drop(first);
        let check = qv_core::password_strength(&password);
        match check.verdict {
            PasswordVerdict::Accept => return Ok(password),
            PasswordVerdict::Warn => {
                tty.say(&format!(
                    "Warning: this password is only {} (about {:.0} bits). A longer one, or a \
                     generated passphrase, is safer.\n",
                    label(check.strength),
                    check.bits
                ))?;
                return Ok(password);
            }
            PasswordVerdict::ConfirmWeak => {
                tty.say(WEAK_TEXT)?;
                tty.countdown("You can answer in", 5)?;
                if tty.confirm("Create the vault with this weak password anyway?")? {
                    return Ok(password);
                }
                tty.say("Choose a stronger password.\n")?;
            }
        }
    }
}

pub(crate) fn label(s: Strength) -> &'static str {
    match s {
        Strength::Weak => "weak",
        Strength::Fair => "fair",
        Strength::Strong => "strong",
        _ => "very strong",
    }
}

/// Shows the phrase on the alternate screen until a key is pressed.
pub(crate) fn show_phrase(tty: &Tty<'_>, phrase: &RecoveryPhrase) -> Result<(), CliError> {
    let _alt = AltScreen::enter()?;
    let mut o = Out::stdout();
    o.raw(
        "Recovery phrase. Write these 24 words down, in order, and keep them safe:\r\n\
         they open the vault without the master password.\r\n\r\n",
    );
    for row in 0..6 {
        for col in 0..4 {
            let i = col * 6 + row;
            let word = phrase.expose_word(i).unwrap_or_default();
            o.raw(&format!("  {:>2}. ", i + 1));
            o.text(word);
            o.raw(&" ".repeat(10usize.saturating_sub(word.len())));
        }
        o.raw("\r\n");
    }
    o.raw("\r\n");
    o.flush()?;
    tty.wait_key("Press any key when you have written them down.")
}

/// Checks three words. `false` if the user skipped the check.
fn check_phrase(tty: &Tty<'_>, phrase: &RecoveryPhrase) -> Result<bool, CliError> {
    let positions = qv_core::confirmation_positions()?;
    tty.say(
        "Check the recovery phrase: type the words asked for. Press Enter on an empty line \
         for other options.\n",
    )?;
    let mut done = 0;
    while done < positions.len() {
        let pos = positions[done];
        debug_assert!(pos < PHRASE_WORDS);
        let typed = tty.secret(&format!("Word #{}: ", pos + 1), MAX_ANSWER_BYTES)?;
        if typed.expose().iter().all(u8::is_ascii_whitespace) {
            drop(typed);
            if tty.confirm("Show the recovery phrase again?")? {
                show_phrase(tty, phrase)?;
                continue;
            }
            if tty.confirm("Skip checking the recovery phrase?")? {
                tty.say(
                    "Without a checked recovery phrase you may be unable to open the vault if \
                     you forget the master password.\n",
                )?;
                if tty.confirm("Skip anyway?")? {
                    tty.say("Skipped; the vault records that the phrase was not checked.\n")?;
                    return Ok(false);
                }
            }
            continue;
        }
        if phrase.confirm_word(pos, typed.expose()).is_ok() {
            done += 1;
        } else {
            tty.say(&format!("That is not word #{}.\n", pos + 1))?;
        }
    }
    tty.say("The recovery phrase is checked.\n")?;
    Ok(true)
}
