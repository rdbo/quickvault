// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qv lan open|sync|join` (spec 0011 §4 *LAN command contracts*, 0013;
//! plan 0042).
//!
//! The code is a secret. It is shown only on the alternate screen
//! (0011 §3.7) and typed only at a no-echo prompt, never in argv or the
//! environment. Endpoints are IP literals and are not secret. Nothing here
//! starts a window or a session without the command (0005 §0.5), and nothing
//! about the other device is stored. Signals and
//! session lock cancel through the signal token.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::ArgMatches;
use qv_core::{
    ApproverUi, JoinCode, JoinerUi, LocalAcceptance, MasterPassword, Sas, Served, SyncOptions,
    SyncReport, SyncWindowOptions,
};

use crate::cli::Ctx;
use crate::exit::{CliError, LAN};
use crate::out::{Out, escape_str};
use crate::term::{self, Tty};

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let (name, s) = m
        .subcommand()
        .ok_or_else(|| CliError::usage("missing lan subcommand"))?;
    if ctx.json {
        return Err(CliError::usage(format!(
            "lan {name} does not support --json"
        )));
    }
    match name {
        "open" => open(ctx, s),
        "sync" => sync(ctx, s),
        "join" => join(ctx, s),
        _ => Err(CliError::usage("unknown lan subcommand")),
    }
}

/// Every LAN command prompts for more than the master password (0011 §3.2).
fn refuse_stdin(ctx: &Ctx, name: &str) -> Result<(), CliError> {
    if ctx.password_stdin {
        return Err(CliError::usage(format!(
            "lan {name} prompts on the terminal and cannot be combined with --password-stdin"
        )));
    }
    Ok(())
}

fn minutes(s: &ArgMatches, default: u64, max: u64) -> Result<Duration, CliError> {
    let m = s.get_one::<u64>("minutes").copied().unwrap_or(default);
    if m == 0 || m > max {
        return Err(CliError::usage(format!(
            "--minutes must be between 1 and {max}"
        )));
    }
    Ok(Duration::from_secs(m * 60))
}

fn endpoints(s: &ArgMatches) -> Result<Vec<SocketAddr>, CliError> {
    let list: Vec<&String> = s
        .get_many::<String>("endpoint")
        .map(Iterator::collect)
        .unwrap_or_default();
    if list.is_empty() {
        return Err(CliError::usage(
            "give the other device's address with --endpoint <ip:port>",
        ));
    }
    list.into_iter()
        .map(|e| {
            qv_core::parse_endpoint(e).map_err(|_| {
                CliError::usage(format!(
                    "invalid endpoint {:?}: use a.b.c.d:port or [v6]:port (IP addresses only)",
                    escape_str(e)
                ))
            })
        })
        .collect()
}

/// The comparison code as two groups of three digits.
fn grouped(digits: &str) -> String {
    match (digits.get(..3), digits.get(3..)) {
        (Some(a), Some(b)) => format!("{a} {b}"),
        _ => digits.to_owned(),
    }
}

fn sas_text(sas: &Sas) -> String {
    let d: String = sas.digits().iter().map(|b| char::from(*b)).collect();
    grouped(&d)
}

/// The sync lines of 0011 *LAN command contracts*.
fn print_report(out: &mut Out, r: &SyncReport) {
    out.raw(match r.local {
        LocalAcceptance::Committed => "local acceptance: committed\n",
        LocalAcceptance::Unchanged => "local acceptance: unchanged\n",
    });
    out.raw(&format!("conflicts: {}\n", r.conflicts));
    out.raw(if r.peer_confirmed {
        "peer receipt: confirmed\n"
    } else {
        "peer receipt: unconfirmed\n"
    });
}

/// Prints a round's lines; an error after the local commit follows them.
fn finish_report(r: &SyncReport) -> Result<(), CliError> {
    let mut out = Out::stdout();
    print_report(&mut out, r);
    out.flush()?;
    match r.completion_error {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

/// The offering user's terminal: a new device's comparison code (0013 §4.5).
struct ApproverTty<'t> {
    tty: &'t Tty<'t>,
}

impl ApproverUi for ApproverTty<'_> {
    fn confirm(&mut self, sas: &str, vault_name: &str) -> bool {
        let shown = format!(
            "\nA new device asks to join vault \"{}\" (it will receive this vault).\n",
            escape_str(vault_name)
        );
        self.tty.say(&shown).is_ok()
            && self
                .tty
                .confirm(&format!("Do both devices show {}?", grouped(sas)))
                .unwrap_or(false)
    }
}

/// `lan open [--port <n>] [--minutes <1-10>]`.
fn open(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    refuse_stdin(ctx, "open")?;
    let limit = minutes(s, 10, 10)?;
    let tty = term::stdio_tty()?;
    if !term::stdout_is_tty() {
        return Err(CliError::usage(
            "lan open shows the code on the terminal (standard output is not a terminal)",
        ));
    }
    let session = ctx.unlock()?;
    let result = (|| {
        let window = session.open_sync_window(SyncWindowOptions {
            port: s.get_one::<u16>("port").copied(),
            limit,
            ..SyncWindowOptions::new()
        })?;
        let addrs = qv_core::local_addresses();
        let code = window.code(&addrs)?;
        let cancel = crate::signals::token();
        let served = {
            let _alt = term::AltScreen::enter()?;
            let mut out = Out::stdout();
            out.raw("Code (type it on the other device; it works once):\n\n    ");
            out.bytes(code.manual.expose_secret());
            out.raw("\n\nThis device's address:\n");
            if addrs.is_empty() {
                out.raw(&format!(
                    "    (none found; use this device's IP address with port {})\n",
                    code.port
                ));
            }
            for ip in &addrs {
                out.raw(&format!("    {}\n", SocketAddr::new(*ip, code.port)));
            }
            out.raw(&format!(
                "\nWaiting up to {} minutes for the other device (Ctrl-C cancels).\n",
                limit.as_secs() / 60
            ));
            out.flush()?;
            let locked = || session.is_locked();
            let bounded_tty = tty.until(window.expires_at()).with_cancel(&locked);
            let mut ui = ApproverTty { tty: &bounded_tty };
            match window.run(&session, &mut ui, Some(&cancel)) {
                Err(qv_core::CoreError::Lan(qv_core::LanError::WindowExpired)) => {
                    return Err(CliError::new(
                        LAN,
                        "the code expired before another device used it",
                    ));
                }
                other => other?,
            }
        };
        match served {
            Served::Synced(r) => finish_report(&r),
            Served::Joined {
                peer_confirmed,
                failure,
            } => {
                let mut out = Out::stdout();
                out.raw("joined\n");
                out.raw(if peer_confirmed {
                    "peer receipt: confirmed\n"
                } else {
                    "peer receipt: unconfirmed (the other device may not have finished joining)\n"
                });
                out.flush()?;
                match failure {
                    Some(e) => Err(qv_core::CoreError::Lan(e).into()),
                    None => Ok(()),
                }
            }
        }
    })();
    session.lock();
    result
}

/// The joining user's terminal (0013 §4.5, §10 step 4).
struct JoinerTty<'t> {
    tty: &'t Tty<'static>,
    attempts: usize,
}

impl JoinerUi for JoinerTty<'_> {
    fn show_code(&mut self, sas: &Sas) -> bool {
        let code = sas_text(sas);
        self.tty
            .say(&format!(
                "comparison code: {code} (the other device must show the same code)\n\
                 Receiving the vault…\n"
            ))
            .is_ok()
    }

    fn confirm_vault(&mut self, vault_name: &[u8], sas: &Sas) -> bool {
        let name = escape_str(&String::from_utf8_lossy(vault_name));
        self.tty
            .confirm(&format!(
                "Join vault \"{name}\"? Comparison code {}",
                sas_text(sas)
            ))
            .unwrap_or(false)
    }

    fn master_password(&mut self) -> Option<MasterPassword> {
        if self.attempts > 0 {
            let _ = self
                .tty
                .say("Wrong password; try again (Ctrl-D cancels).\n");
        }
        self.attempts += 1;
        let typed = self
            .tty
            .secret(
                "Master password of the joined vault: ",
                term::MAX_PASSWORD_BYTES,
            )
            .ok()?;
        MasterPassword::from_utf8(typed.expose()).ok()
    }
}

fn sync_options(extra: Vec<SocketAddr>) -> SyncOptions {
    SyncOptions {
        extra_endpoints: extra,
        ..SyncOptions::default()
    }
}

/// `lan sync --endpoint <ip:port>...`: one sync-mode session.
fn sync(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    refuse_stdin(ctx, "sync")?;
    let endpoints = endpoints(s)?;
    let tty = term::stdio_tty()?;
    let cancel = crate::signals::token();
    let session = ctx.unlock()?;
    let result = (|| {
        let code = read_code(&tty)?;
        let report = session.sync_with_code(code, sync_options(endpoints), Some(&cancel))?;
        finish_report(&report)
    })();
    session.lock();
    result
}

/// `lan join --endpoint <ip:port>... --new <path>`.
fn join(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    refuse_stdin(ctx, "join")?;
    let endpoints = endpoints(s)?;
    let path = s
        .get_one::<PathBuf>("new")
        .ok_or_else(|| CliError::usage("missing --new <path> for the joined vault"))?;
    // The destination must not exist (checked before connecting, 0013 §10
    // step 5).
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(CliError::usage(format!(
            "{} already exists; choose a new path",
            escape_str(&path.to_string_lossy())
        )));
    }
    let tty = term::stdio_tty()?;
    let cancel = crate::signals::token();
    let code = read_code(&tty)?;
    let core = crate::select::core()?;
    let mut ui = JoinerTty {
        tty: &tty,
        attempts: 0,
    };
    let session =
        core.join_new_device(code, path, sync_options(endpoints), &mut ui, Some(&cancel))?;
    session.lock();
    let mut out = Out::stdout();
    out.raw("created: ");
    out.path(&path.to_string_lossy());
    out.raw("\n");
    out.flush()
}

/// The code from a no-echo prompt (0011 §3.1).
fn read_code(tty: &Tty<'static>) -> Result<JoinCode, CliError> {
    let typed = tty.secret("Code: ", MAX_CODE_INPUT)?;
    let text = core::str::from_utf8(typed.expose()).map_err(|_| CliError::usage("invalid code"))?;
    JoinCode::from_manual(text).map_err(|_| CliError::usage("invalid code"))
}

/// The longest manual-code input: 26 symbols with separators fit in 64.
const MAX_CODE_INPUT: usize = 64;
