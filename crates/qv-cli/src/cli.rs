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

const ARGV_NOTE: &str = "Values given as arguments (paths, titles, usernames, URLs, field values, queries) are \
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
                .help("Skip destructive-action and plaintext-export confirmations (never the weak-password one)"),
        )
        .subcommand(attach_command())
        .subcommand(history_command())
        .subcommand(Command::new("restore").about("Restore a retained entry version as a new causal edit")
            .arg(Arg::new("entry").required(true)).arg(Arg::new("version").required(true))
            .arg(flag("resolve-conflicts", "Explicitly replace all known conflicting heads with this historical value")))
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
                .arg(flag("copy", "Copy instead of printing; stay in the foreground until expiry"))
                .about("Print the entry's current TOTP code and the seconds left")
                .arg(
                    Arg::new("entry")
                        .required(true)
                        .help("An entry path or @id"),
                ),
        )
        .subcommand(
            Command::new("copy")
                .about("Copy a field using local X11; close the vault, then stay in the foreground")
                .after_help("Clipboard recipients/managers may retain copies despite sensitive hints. Native Wayland requires XWayland. Ctrl-C clears only this command's ownership.")
                .arg(Arg::new("entry").required(true).help("An entry path or @id"))
                .arg(Arg::new("field").help("Unique field name; defaults to the first secret field"))
                .arg(count("timeout", "timeout", "Clipboard lifetime in seconds (1–300, default: config or 20)")),
        )
        .subcommand(generate_command())
        .subcommand(edit_command(false))
        .subcommand(edit_command(true))
        .subcommand(
            Command::new("mv")
                .about("Move an entry or group")
                .arg(Arg::new("item").required(true))
                .arg(Arg::new("group").required(true)),
        )
        .subcommand(
            Command::new("mkdir")
                .about("Create a group")
                .arg(Arg::new("path").required(true))
                .arg(flag("parents", "Create missing parents").short('p')),
        )
        .subcommand(
            Command::new("rm")
                .about("Move an entry or group to trash")
                .arg(Arg::new("item").required(true))
                .arg(flag("recursive", "Include all group contents").short('r')),
        )
        .subcommand(
            Command::new("trash")
                .about("Manage the trash")
                .subcommand_required(true)
                .subcommand(Command::new("ls").about("List trash"))
                .subcommand(
                    Command::new("restore")
                        .about("Restore a trashed item")
                        .arg(Arg::new("item").required(true)),
                )
                .subcommand(Command::new("empty").about("Permanently delete non-conflicted trash")),
        )
        .subcommand(
            Command::new("snapshot")
                .about("Local snapshot archives of the verified vault state")
                .subcommand_required(true)
                .subcommand(
                    Command::new("ls")
                        .about("List local snapshots (authenticates every header)"),
                )
                .subcommand(Command::new("restore")
                    .about("Restore into a new vault path and explicit recovery baseline; may be old")
                    .arg(Arg::new("id").required(true))
                    .arg(Arg::new("path").required(true).value_parser(value_parser!(std::path::PathBuf)))),
        )
        .subcommand(Command::new("verify").about(
            "Re-hash and authenticate the whole vault and report the anchor (never repairs)",
        ))
}

fn attach_command() -> Command {
    let entry = || Arg::new("entry").required(true);
    let attachment = || Arg::new("attachment").required(true);
    let path = |name| {
        Arg::new(name)
            .required(true)
            .value_parser(value_parser!(PathBuf))
    };
    Command::new("attach").about("Import, list, explicitly export or permanently remove attachments")
        .subcommand_required(true)
        .subcommand(Command::new("add").arg(entry()).arg(path("file"))
            .arg(Arg::new("name").long("name")).arg(Arg::new("mime").long("mime")))
        .subcommand(Command::new("ls").arg(entry()))
        .subcommand(Command::new("save").about("Export plaintext to a NEW explicit file; failure/crash can leave incomplete plaintext")
            .arg(entry()).arg(attachment()).arg(path("path")))
        .subcommand(Command::new("rm").about("Permanently remove; independent copies may remain, with no secure-erasure guarantee")
            .arg(entry()).arg(attachment()))
}

fn history_command() -> Command {
    Command::new("history")
        .about("List retained history or explicitly show/purge it")
        .arg(Arg::new("entry"))
        .subcommand(
            Command::new("show")
                .arg(Arg::new("entry").required(true))
                .arg(Arg::new("version").required(true))
                .arg(flag("reveal", REVEAL_HELP)),
        )
        .subcommand(
            Command::new("purge")
                .about("Suppress local history; independent copies may remain, no secure erasure")
                .arg(Arg::new("entry").required(true)),
        )
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
    generator_args(Command::new("generate")
        .arg(flag("copy", "Copy instead of printing; stay in the foreground until expiry"))
        .about("Generate a password, passphrase or PIN without saving it")
        .after_help(
            "Without options, uses the selected vault's defaults (unlocking it) or the built-in \
             defaults. Any option starts from the built-in defaults of its mode.",
        ))
}

fn generator_args(c: Command) -> Command {
    c.arg(count("length", "length", "Characters: password length"))
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

fn edit_command(edit: bool) -> Command {
    let mut c = Command::new(if edit { "edit" } else { "add" })
        .about(if edit {
            "Edit an entry"
        } else {
            "Create an entry"
        })
        .after_help(ARGV_NOTE)
        .arg(
            Arg::new("entry")
                .required(true)
                .help("Entry path or @id (new path for add)"),
        )
        .arg(Arg::new("type").long("type").value_name("HINT"))
        .arg(
            Arg::new("username")
                .long("username")
                .value_name("VALUE")
                .num_args(0..=1)
                .default_missing_value(""),
        )
        .arg(
            Arg::new("url")
                .long("url")
                .value_name("VALUE")
                .num_args(0..=1)
                .default_missing_value(""),
        )
        .arg(flag(
            "notes",
            "Prompt for multiline notes (Ctrl-D ends input; never argv)",
        ))
        .arg(
            flag(
                "interactive",
                "Prompt for all field values; argv values are visible in process lists",
            )
            .short('i'),
        )
        .arg(
            Arg::new("field")
                .long("field")
                .action(ArgAction::Append)
                .value_name("NAME=VALUE")
                .help("Set an unprotected text field; with -i use NAME to prompt instead"),
        )
        .arg(
            Arg::new("secret-field")
                .long("secret-field")
                .action(ArgAction::Append)
                .value_name("NAME")
                .help("Name of a secret field to prompt for (never its value)"),
        )
        .arg(flag(
            "generate",
            "Generate the password using vault defaults or generator flags",
        ));
    if edit {
        c = c.arg(Arg::new("title").long("title").value_name("TITLE"));
        for name in ["remove-field", "protect", "unprotect"] {
            c = c.arg(
                Arg::new(name)
                    .long(name)
                    .action(ArgAction::Append)
                    .value_name("NAME"),
            );
        }
    }
    generator_args(c)
}

/// Global options and the environment, shared by every command.
pub(crate) struct Ctx {
    pub(crate) vault: Option<PathBuf>,
    pub(crate) password_stdin: bool,
    pub(crate) json: bool,
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
        crate::signals::check()?;
        warn_location(session.warnings()?);
        warn_snapshots(&session);
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

/// The automatic-snapshot outcome as stderr warnings (0011 §4). Failures and
/// budget skips never fail the requested command and never touch stdout.
pub(crate) fn warn_snapshots(session: &Session) {
    let Some(report) = session.snapshot_status() else {
        return;
    };
    if report.failed {
        crate::out::eprint(
            "qvault: warning: the automatic snapshot could not be written; the vault is unchanged\n",
        );
    }
    match report.skipped {
        Some(qv_core::SnapshotSkip::OverBudget { needed }) => crate::out::eprint(&format!(
            "qvault: warning: the automatic snapshot needs {needed} bytes and was skipped: it does \
             not fit the snapshot budget\n"
        )),
        Some(qv_core::SnapshotSkip::Disabled) => crate::out::eprint(
            "qvault: warning: local snapshots are disabled: no usable private snapshot directory\n",
        ),
        _ => {}
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
        Some(("copy", s)) => crate::cmd::copy::run(ctx, s),
        Some(("generate", s)) => crate::cmd::generate::run(ctx, s),
        Some(("add", s)) => crate::cmd::edit::run(ctx, s, false),
        Some(("edit", s)) => crate::cmd::edit::run(ctx, s, true),
        Some(("mv" | "mkdir" | "rm", s)) => {
            crate::cmd::groups::run(ctx, m.subcommand_name().unwrap_or_default(), s)
        }
        Some(("attach", s)) => crate::cmd::attach::run(ctx, s),
        Some(("history", s)) => crate::cmd::history::run(ctx, s, false),
        Some(("restore", s)) => crate::cmd::history::run(ctx, s, true),
        Some(("trash", s)) => crate::cmd::trash::run(ctx, s),
        Some(("snapshot", s)) => crate::cmd::snapshot::run(ctx, s),
        Some(("verify", s)) => crate::cmd::verify::run(ctx, s),
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
                if id == "secret-field" {
                    assert!(path.ends_with(" add") || path.ends_with(" edit"));
                    assert_eq!(a.get_value_names().unwrap(), &["NAME"]);
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
