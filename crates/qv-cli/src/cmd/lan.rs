// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault lan pair|join|receive|sync|links|unlink` (spec 0011 §4 *LAN command
//! contracts*, 0013).
//!
//! The pairing code is a secret. It is shown only on the alternate screen
//! (0011 §3.7) and typed only at a no-echo prompt, never in argv or the
//! environment. Endpoints are IP literals and are not secret. Nothing here
//! starts a window or a round without the command (0005 §0.5). Signals and
//! session lock cancel through the signal token.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::ArgMatches;
use qv_core::{
    ApproverUi, JoinCode, JoinMode, JoinOptions, JoinerUi, LanLinkHandle, LanLinkSummary,
    LocalAcceptance, MasterPassword, PairingOptions, ReceiveEvent, ReceiveOptions, Sas,
    SyncOptions, SyncReport, WindowEnd,
};

use crate::cli::Ctx;
use crate::exit::{AMBIGUOUS, CliError, LAN, NOT_FOUND, USAGE};
use crate::out::{Out, escape_str};
use crate::term::{self, Tty};

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let (name, s) = m
        .subcommand()
        .ok_or_else(|| CliError::usage("missing lan subcommand"))?;
    if ctx.json && name != "links" {
        return Err(CliError::usage(format!(
            "lan {name} does not support --json"
        )));
    }
    match name {
        "pair" => pair(ctx, s),
        "join" => join(ctx, s),
        "receive" => receive(ctx, s),
        "sync" => sync(ctx, s),
        "links" => links(ctx),
        "unlink" => unlink(ctx, s),
        _ => Err(CliError::usage("unknown lan subcommand")),
    }
}

/// `pair` and `join` prompt for more than the master password (0011 §3.2).
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

fn label(s: &ArgMatches) -> Result<String, CliError> {
    s.get_one::<String>("label")
        .cloned()
        .ok_or_else(|| CliError::usage("missing --label"))
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

/// The approving user's terminal (0013 §4.5).
struct ApproverTty<'t> {
    tty: &'t Tty<'t>,
}

impl ApproverUi for ApproverTty<'_> {
    fn confirm(&mut self, sas: &str, mode: JoinMode, vault_name: &str) -> bool {
        let mode = match mode {
            JoinMode::NewDevice => "a new device (it will receive this vault)",
            JoinMode::Link => "a device with a copy of this vault",
        };
        let shown = format!(
            "\nA device asks to pair with vault \"{}\": {mode}.\n",
            escape_str(vault_name)
        );
        self.tty.say(&shown).is_ok()
            && self
                .tty
                .confirm(&format!("Do both devices show {}?", grouped(sas)))
                .unwrap_or(false)
    }
}

/// `lan pair --label <name> [--port <n>] [--minutes <1-10>]`.
fn pair(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    refuse_stdin(ctx, "pair")?;
    let peer_label = label(s)?;
    let limit = minutes(s, 10, 10)?;
    let tty = term::stdio_tty()?;
    if !term::stdout_is_tty() {
        return Err(CliError::usage(
            "lan pair shows the pairing code on the terminal (standard output is not a terminal)",
        ));
    }
    let session = ctx.unlock()?;
    let result = (|| {
        let window = session.open_pairing_window(PairingOptions {
            port: s.get_one::<u16>("port").copied(),
            limit,
            ..PairingOptions::new(&peer_label)
        })?;
        let addrs = qv_core::local_addresses();
        let code = window.code(&addrs)?;
        let cancel = crate::signals::token();
        let report = {
            let _alt = term::AltScreen::enter()?;
            let mut out = Out::stdout();
            out.raw("Pairing code (type it on the other device):\n\n    ");
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
            window.run(&session, &mut ui, Some(&cancel))?
        };
        let mut out = Out::stdout();
        out.raw(&format!("paired: {}\n", report.link.id_hex()));
        out.raw(if report.peer_confirmed {
            "peer receipt: confirmed\n"
        } else {
            "peer receipt: unconfirmed (pairing may be incomplete on the other device)\n"
        });
        out.flush()?;
        match report.sync {
            Some(Ok(r)) => finish_report(&r),
            Some(Err(e)) => Err(e.into()),
            None => Ok(()),
        }
    })();
    session.lock();
    result
}

/// The joining user's terminal (0013 §4.5, §10 step 4).
struct JoinerTty<'t> {
    tty: &'t Tty<'static>,
    new_device: bool,
    attempts: usize,
}

impl JoinerUi for JoinerTty<'_> {
    fn show_code(&mut self, sas: &Sas) -> bool {
        let code = sas_text(sas);
        if self.new_device {
            self.tty
                .say(&format!(
                    "comparison code: {code} (the other device must show the same code)\n\
                     Receiving the vault…\n"
                ))
                .is_ok()
        } else {
            self.tty.say(&format!("comparison code: {code}\n")).is_ok()
                && self
                    .tty
                    .confirm(&format!("Does the other device show {code}?"))
                    .unwrap_or(false)
        }
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

fn join_options(label: String, extra: Vec<SocketAddr>) -> JoinOptions {
    JoinOptions {
        extra_endpoints: extra,
        ..JoinOptions::new(&label)
    }
}

/// `lan join --endpoint <ip:port>... --label <name> [--new <path>]`.
fn join(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    refuse_stdin(ctx, "join")?;
    let label = label(s)?;
    let endpoints = endpoints(s)?;
    let tty = term::stdio_tty()?;
    let cancel = crate::signals::token();
    if let Some(path) = s.get_one::<PathBuf>("new") {
        // A new device: the destination must not exist (checked before
        // pairing, 0013 §10 step 5).
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(CliError::usage(format!(
                "{} already exists; choose a new path",
                escape_str(&path.to_string_lossy())
            )));
        }
        let code = read_code(&tty)?;
        let core = crate::select::core()?;
        let mut ui = JoinerTty {
            tty: &tty,
            new_device: true,
            attempts: 0,
        };
        let session = core.join_new_device(
            code,
            path,
            join_options(label, endpoints),
            &mut ui,
            Some(&cancel),
        )?;
        let link = session
            .lan_links()?
            .into_iter()
            .next()
            .map(|l| l.handle.id_hex());
        session.lock();
        let mut out = Out::stdout();
        out.raw("created: ");
        out.path(&path.to_string_lossy());
        out.raw("\n");
        if let Some(id) = link {
            out.raw(&format!("paired: {id}\n"));
        }
        return out.flush();
    }
    let session = ctx.unlock()?;
    let result = (|| {
        let code = read_code(&tty)?;
        let mut ui = JoinerTty {
            tty: &tty,
            new_device: false,
            attempts: 0,
        };
        let report =
            session.join_link(code, join_options(label, endpoints), &mut ui, Some(&cancel))?;
        let mut out = Out::stdout();
        out.raw(&format!("paired: {}\n", report.link.id_hex()));
        out.flush()?;
        finish_report(&report.sync?)
    })();
    session.lock();
    result
}

/// The pairing code from a no-echo prompt (0011 §3.1).
fn read_code(tty: &Tty<'static>) -> Result<JoinCode, CliError> {
    let typed = tty.secret("Pairing code: ", MAX_CODE_INPUT)?;
    let text = core::str::from_utf8(typed.expose())
        .map_err(|_| CliError::usage("invalid pairing code"))?;
    JoinCode::from_manual(text).map_err(|_| CliError::usage("invalid pairing code"))
}

/// The longest manual-code input: 26 symbols with separators fit in 64.
const MAX_CODE_INPUT: usize = 64;

/// `lan receive [--port <n>] [--minutes <1-15>] [--stay]`.
fn receive(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    let limit = minutes(s, 2, 15)?;
    let session = ctx.unlock()?;
    let result = (|| {
        let window = session.open_receive_window(ReceiveOptions {
            port: s.get_one::<u16>("port").copied(),
            limit,
            stay_open: s.get_flag("stay"),
            ..ReceiveOptions::new()
        })?;
        let code = window.code(&qv_core::local_addresses())?;
        let mut out = Out::stdout();
        out.raw("endpoints:\n");
        if code.endpoints.is_empty() {
            out.raw(&format!(
                "  (none found; use this device's IP address with port {})\n",
                code.port
            ));
        }
        for e in &code.endpoints {
            out.raw(&format!("  {e}\n"));
        }
        out.raw(&format!(
            "waiting up to {} minutes (Ctrl-C cancels)\n",
            limit.as_secs() / 60
        ));
        out.flush()?;
        let cancel = crate::signals::token();
        let mut first_error = None;
        let report = window.run(
            &session,
            &mut |e| match e {
                ReceiveEvent::Round(Ok(r)) => {
                    let mut out = Out::stdout();
                    print_report(&mut out, &r);
                    let _ = out.flush();
                    if let Some(e) = r.completion_error {
                        first_error.get_or_insert(e);
                    }
                }
                ReceiveEvent::Round(Err(e)) => {
                    crate::out::eprint(&format!("qvault: a sync round failed: {e}\n"));
                }
            },
            Some(&cancel),
        )?;
        if let Some(e) = first_error {
            return Err(e.into());
        }
        if report.rounds > 0 {
            return Ok(());
        }
        Err(match report.end {
            WindowEnd::Cancelled => CliError::cancelled(),
            WindowEnd::TooManyAttempts => CliError::new(
                LAN,
                "unexpected connection attempts closed the receive window",
            ),
            _ => CliError::new(LAN, "the receive window closed without a sync round"),
        })
    })();
    session.lock();
    result
}

/// The link named by an ID prefix, or the vault's only link.
fn pick_link(links: Vec<LanLinkSummary>, prefix: Option<&str>) -> Result<LanLinkHandle, CliError> {
    if let Some(p) = prefix {
        check_prefix(p)?;
    }
    let p = prefix.map(str::to_ascii_lowercase);
    let matches: Vec<LanLinkSummary> = links
        .into_iter()
        .filter(|l| {
            p.as_deref()
                .is_none_or(|p| l.handle.id_hex().starts_with(p))
        })
        .collect();
    match matches.len() {
        0 if prefix.is_none() => Err(CliError::new(
            NOT_FOUND,
            "this vault has no LAN links; pair a device first (qvault lan pair)",
        )),
        0 => Err(CliError::new(NOT_FOUND, "no LAN link matches")),
        1 => Ok(matches
            .into_iter()
            .next()
            .map(|l| l.handle)
            .ok_or_else(|| CliError::new(NOT_FOUND, "no LAN link matches"))?),
        _ => {
            let mut msg = String::from("several LAN links match; choose one with --link:");
            for l in &matches {
                msg.push_str(&format!(
                    "\n  {}  {}",
                    l.handle.id_hex(),
                    escape_str(l.label.expose())
                ));
            }
            Err(CliError::new(AMBIGUOUS, msg))
        }
    }
}

fn check_prefix(p: &str) -> Result<(), CliError> {
    if !(6..=32).contains(&p.len()) || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::usage("a link ID prefix is 6–32 hex digits"));
    }
    Ok(())
}

/// `lan sync --endpoint <ip:port>... [--link <6-32 hex>]`.
fn sync(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    let endpoints = endpoints(s)?;
    if let Some(p) = s.get_one::<String>("link") {
        check_prefix(p)?;
    }
    let session = ctx.unlock()?;
    let result = (|| {
        let link = pick_link(
            session.lan_links()?,
            s.get_one::<String>("link").map(String::as_str),
        )?;
        let cancel = crate::signals::token();
        let report = session.sync_lan(&link, &endpoints, SyncOptions::default(), Some(&cancel))?;
        finish_report(&report)
    })();
    session.lock();
    result
}

/// `lan links [--json]`.
fn links(ctx: &Ctx) -> Result<(), CliError> {
    let session = ctx.unlock()?;
    let result = (|| {
        let links = session.lan_links()?;
        let mut out = Out::stdout();
        if ctx.json {
            out.raw("{\"links\":[");
            for (i, l) in links.iter().enumerate() {
                if i > 0 {
                    out.raw(",");
                }
                out.raw(&format!("{{\"id\":\"{}\",\"label\":", l.handle.id_hex()));
                out.json_str(l.label.expose().as_bytes());
                out.raw(&format!(",\"created_at\":{}}}", l.created_at.0));
            }
            out.raw("]}\n");
        } else {
            for l in &links {
                out.raw(&format!("{}  ", l.handle.id_hex()));
                out.text(l.label.expose());
                out.raw(&format!("  {}\n", crate::out::rfc3339(l.created_at.0)));
            }
        }
        out.flush()
    })();
    session.lock();
    result
}

/// `lan unlink <6-32 hex> [--yes]`.
fn unlink(ctx: &Ctx, s: &ArgMatches) -> Result<(), CliError> {
    let prefix = s
        .get_one::<String>("link")
        .ok_or_else(|| CliError::usage("missing link ID prefix"))?;
    check_prefix(prefix)?;
    if !ctx.yes && ctx.password_stdin {
        return Err(CliError::new(
            USAGE,
            "lan unlink asks for confirmation on the terminal; add --yes with --password-stdin",
        ));
    }
    let session = ctx.unlock()?;
    let result = (|| {
        let link = pick_link(session.lan_links()?, Some(prefix))?;
        if !ctx.yes {
            let tty = term::stdio_tty()?;
            if !tty.confirm(&format!(
                "Remove LAN link {}? The other device is not notified",
                link.id_hex()
            ))? {
                return Err(CliError::cancelled());
            }
        }
        session.remove_lan_link(&link)?;
        let mut out = Out::stdout();
        out.raw(&format!("removed: {}\n", link.id_hex()));
        out.flush()?;
        crate::out::eprint(
            "qvault: the other device was not notified; removal is not compromise recovery \
             (rotate the vault key for that)\n",
        );
        Ok(())
    })();
    session.lock();
    result
}
