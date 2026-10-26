// SPDX-License-Identifier: AGPL-3.0-or-later

//! The command tree (clap builder API) and dispatch (spec 0011 §1, §4).
//!
//! No option takes a secret value (0011 §3.1); a test walks the tree to
//! check it. Paths, titles, field names and search queries given as
//! arguments are visible to other local users and the shell history.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use qv_core::{MasterPassword, Session};

use crate::exit::{CliError, OTHER};
use crate::out::{Out, escape_str};
use crate::select::{self, Environment};
use crate::term;

const ARGV_NOTE: &str = "Values given as arguments (paths, titles, usernames, URLs, queries) are \
visible to other local users and stay in the shell history. Secrets are never accepted as \
arguments or environment variables.";

const STDIN_HELP: &str = "Read the master password from the first line of standard input \
(for scripts; prefer piping from a keyring tool over echo or script files)";

const REVEAL_HELP: &str =
    "Print protected values (they stay in the terminal scrollback and any terminal log)";

/// The full command tree.
pub(crate) fn command() -> Command {
    Command::new("qvault")
        .about("QuickVault: an offline-first, end-to-end encrypted password manager")
        .after_help(ARGV_NOTE)
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg(
            Arg::new("vault")
                .short('v')
                .long("vault")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .global(true)
                .help("The vault file (else QVAULT_PATH, else default_vault in the config file)"),
        )
        .arg(
            Arg::new("password-stdin")
                .long("password-stdin")
                .action(ArgAction::SetTrue)
                .global(true)
                .help(STDIN_HELP),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .global(true)
                .help("Machine-readable JSON output (read commands)"),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .action(ArgAction::SetTrue)
                .global(true)
                .help("Skip confirmations of destructive commands (never the weak-password one)"),
        )
        .subcommand(
            Command::new("init")
                .about("Create a vault; shows its recovery phrase once")
                .arg(
                    Arg::new("path")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("The new vault file (must end in .qvault and not exist)"),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_name("NAME")
                        .help("The vault's name (default: the file name)"),
                ),
        )
        .subcommand(
            Command::new("info")
                .about("Show the vault's public header (unverified, no password)")
                .arg(
                    Arg::new("full")
                        .long("full")
                        .action(ArgAction::SetTrue)
                        .help("Also unlock and show the name, counts and last change"),
                ),
        )
        .subcommand(
            Command::new("ls")
                .about("List groups and entries (title, username, URL)")
                .arg(Arg::new("group").help("A group path or @id (default: the root)"))
                .arg(
                    Arg::new("recursive")
                        .short('r')
                        .long("recursive")
                        .action(ArgAction::SetTrue)
                        .help("Include subgroups"),
                ),
        )
        .subcommand(
            Command::new("search")
                .about("Search titles, usernames, URLs and group names (not protected values)")
                .arg(
                    Arg::new("query")
                        .required(true)
                        .help("Text to look for (case-insensitive)"),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Show an entry; protected values are masked")
                .arg(
                    Arg::new("entry")
                        .required(true)
                        .help("An entry path or @id"),
                )
                .arg(
                    Arg::new("reveal")
                        .long("reveal")
                        .action(ArgAction::SetTrue)
                        .help(REVEAL_HELP),
                )
                .arg(
                    Arg::new("field")
                        .long("field")
                        .value_name("NAME")
                        .help("Print only this field's value (protected ones need --reveal)"),
                ),
        )
        .subcommand(
            Command::new("totp")
                .about("Print the entry's current TOTP code and the seconds left")
                .arg(
                    Arg::new("entry")
                        .required(true)
                        .help("An entry path or @id"),
                ),
        )
        .subcommand(generate_command())
}

fn count(name: &'static str, long: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(long)
        .value_name("N")
        .value_parser(value_parser!(u32))
        .help(help)
}

fn flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .action(ArgAction::SetTrue)
        .help(help)
}

fn generate_command() -> Command {
    Command::new("generate")
        .about("Generate a password, passphrase or PIN without saving it")
        .after_help(
            "Without options, uses the selected vault's defaults (unlocking it) or the built-in \
             defaults. Any option starts from the built-in defaults of its mode.",
        )
        .arg(count("length", "length", "Characters: password length"))
        .arg(flag("no-lower", "Characters: no lowercase letters"))
        .arg(flag("no-upper", "Characters: no uppercase letters"))
        .arg(flag("no-digits", "Characters: no digits"))
        .arg(flag("no-symbols", "Characters: no symbols"))
        .arg(flag(
            "exclude-ambiguous",
            "Characters: no look-alike characters",
        ))
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .value_name("CHARS")
                .help("Characters: never use these characters"),
        )
        .arg(count("words", "words", "Passphrase: number of words"))
        .arg(
            Arg::new("separator")
                .long("separator")
                .value_name("C")
                .help("Passphrase: the separator (one character)"),
        )
        .arg(flag(
            "capitalize",
            "Passphrase: capitalize each word's first letter",
        ))
        .arg(count("pin", "pin", "A PIN of N digits"))
}

/// Global options and the environment, shared by every command.
pub(crate) struct Ctx {
    pub(crate) vault: Option<PathBuf>,
    pub(crate) password_stdin: bool,
    pub(crate) json: bool,
    // Read by the destructive commands of phase 1.10b (`trash empty`); no
    // 1.10a command confirms anything `--yes` may skip.
    #[allow(dead_code)]
    pub(crate) yes: bool,
    pub(crate) env: Environment,
}

impl Ctx {
    /// The selected vault (0011 §1.2), or exit 2.
    pub(crate) fn vault_path(&self) -> Result<PathBuf, CliError> {
        select::require_vault(self.vault.as_deref(), &self.env)
    }

    /// Reads the master password from the terminal or, with
    /// `--password-stdin`, from standard input.
    pub(crate) fn master_password(&self) -> Result<MasterPassword, CliError> {
        let label = "Master password: ";
        let typed = if self.password_stdin {
            term::password_from_stdin(label)?
        } else {
            term::stdio_tty()?.secret(label, term::MAX_PASSWORD_BYTES)?
        };
        Ok(MasterPassword::from_utf8(typed.expose())?)
    }

    /// Unlocks the selected vault, printing its location warnings.
    pub(crate) fn unlock(&self) -> Result<Session, CliError> {
        let path = self.vault_path()?;
        self.unlock_path(&path)
    }

    /// Unlocks the vault at `path`.
    pub(crate) fn unlock_path(&self, path: &std::path::Path) -> Result<Session, CliError> {
        let core = select::core()?;
        let password = self.master_password()?;
        let session = core.unlock(path, &password, None)?;
        drop(password);
        warn_location(session.warnings()?);
        Ok(session)
    }
}

/// Location warnings (0004 §1.1, 0011 *Security Considerations*).
pub(crate) fn warn_location(w: qv_core::LocationWarnings) {
    if w.sync_folder {
        crate::out::eprint(
            "qvault: warning: the vault is in a file-sync folder; synced copies can be rolled back or forked\n",
        );
    }
    if w.network_fs {
        crate::out::eprint("qvault: warning: the vault is on a network filesystem\n");
    }
    if w.removable {
        crate::out::eprint("qvault: warning: the vault is on removable media\n");
    }
}

/// Parses `args` and runs the command; returns the exit code.
pub(crate) fn run(args: impl IntoIterator<Item = OsString>, env: Environment) -> u8 {
    let matches = match command().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            let code = if e.use_stderr() {
                crate::exit::USAGE
            } else {
                0
            };
            let _ = e.print();
            return code;
        }
    };
    let ctx = Ctx {
        vault: matches.get_one::<PathBuf>("vault").cloned(),
        password_stdin: matches.get_flag("password-stdin"),
        json: matches.get_flag("json"),
        yes: matches.get_flag("yes"),
        env,
    };
    let result = dispatch(&ctx, &matches);
    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            report(&e);
            e.code
        }
    };
    let memory = qv_core::harden().memory;
    if memory.is_reduced() {
        crate::out::eprint(&format!(
            "qvault: warning: reduced protection: {} secret buffer(s) could not be locked in \
             memory and may be written to swap\n",
            memory.lock_failures
        ));
    }
    code
}

fn dispatch(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    match m.subcommand() {
        Some(("init", s)) => crate::cmd::init::run(ctx, s),
        Some(("info", s)) => crate::cmd::info::run(ctx, s),
        Some(("ls", s)) => crate::cmd::ls::run(ctx, s),
        Some(("search", s)) => crate::cmd::search::run(ctx, s),
        Some(("show", s)) => crate::cmd::show::run(ctx, s),
        Some(("totp", s)) => crate::cmd::totp::run(ctx, s),
        Some(("generate", s)) => crate::cmd::generate::run(ctx, s),
        _ => Err(CliError::new(OTHER, "unknown command")),
    }
}

/// Prints an error on stderr: `qvault: error: …`, each line escaped.
pub(crate) fn report(e: &CliError) {
    let mut o = Out::stderr();
    for (i, line) in e.message.split('\n').enumerate() {
        o.raw(if i == 0 {
            "qvault: error: "
        } else {
            "qvault: "
        });
        // The message is fixed text plus already escaped context; escaping
        // it again would double the backslashes, so only stray controls
        // are escaped here.
        if line.chars().any(|c| c.is_control()) {
            o.raw(&escape_str(line));
        } else {
            o.raw(line);
        }
        o.raw("\n");
    }
    let _ = o.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_tree_is_valid() {
        command().debug_assert();
    }

    #[test]
    fn cli_no_option_takes_a_secret() {
        fn walk(c: &Command, path: &str) {
            for a in c.get_arguments() {
                let id = a.get_id().as_str().to_ascii_lowercase();
                let takes_value = a.get_num_args().is_some_and(|n| n.takes_values())
                    || matches!(a.get_action(), ArgAction::Set | ArgAction::Append);
                if !takes_value {
                    continue;
                }
                for word in [
                    "password", "secret", "phrase", "note", "token", "seed", "pin-code", "key",
                ] {
                    assert!(!id.contains(word), "{path} --{id} takes a value");
                }
            }
            for s in c.get_subcommands() {
                walk(s, &format!("{path} {}", s.get_name()));
            }
        }
        walk(&command(), "qvault");
        // `--password-stdin` is a flag.
        let c = command();
        let a = c
            .get_arguments()
            .find(|a| a.get_id() == "password-stdin")
            .unwrap();
        assert!(matches!(a.get_action(), ArgAction::SetTrue));
    }

    #[test]
    fn cli_usage_and_help_codes() {
        let env = Environment::default();
        assert_eq!(
            run(["qvault", "--help"].map(OsString::from), env.clone()),
            0
        );
        assert_eq!(
            run(["qvault", "--version"].map(OsString::from), env.clone()),
            0
        );
        assert_eq!(
            run(["qvault", "--frobnicate"].map(OsString::from), env.clone()),
            2
        );
        assert_eq!(run(["qvault"].map(OsString::from), env.clone()), 2);
        assert_eq!(run(["qvault", "show"].map(OsString::from), env.clone()), 2);
        assert_eq!(
            run(
                ["qvault", "generate", "--pin", "x"].map(OsString::from),
                env
            ),
            2
        );
    }
}
