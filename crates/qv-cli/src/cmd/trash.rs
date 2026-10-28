// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trash is a separate address scope; permanent deletion always confirms.
use crate::{
    cli::Ctx,
    exit::{AMBIGUOUS, CliError, LIMIT, NOT_FOUND, OTHER},
    json::Json,
    out::{Out, escape_str},
    term,
};
use clap::ArgMatches;
use qv_core::{CoreError, ItemHandle, Session, SnapshotSkip};

fn resolve(s: &Session, addr: &str) -> Result<ItemHandle, CliError> {
    let trash = s.trash()?;
    let hits: Vec<_> = if let Some(prefix) = addr.strip_prefix('@') {
        let ids = s.find_id(prefix, true).map_err(|e| match e {
            qv_core::CoreError::InvalidInput => CliError::usage("an @id needs 6 to 32 hex digits"),
            e => e.into(),
        })?;
        trash.iter().filter(|t| ids.contains(&t.item)).collect()
    } else {
        trash.iter().filter(|t| t.name.expose() == addr).collect()
    };
    match hits.as_slice() {
        [one] => Ok(one.item),
        [] => Err(CliError::new(NOT_FOUND, "trashed item not found")),
        many => {
            let mut message = format!(
                "{} matches multiple trashed items; use an ID:",
                escape_str(addr)
            );
            for t in many {
                message.push_str(&format!(
                    "\n  @{}  {}",
                    t.item.id_hex(),
                    escape_str(t.name.expose())
                ));
            }
            Err(CliError::new(AMBIGUOUS, message))
        }
    }
}

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let (cmd, args) = m
        .subcommand()
        .ok_or_else(|| CliError::usage("missing trash command"))?;
    if cmd == "empty" && !ctx.yes {
        if ctx.password_stdin {
            return Err(CliError::usage(
                "trash empty with --password-stdin needs --yes",
            ));
        }
        term::stdio_tty()?;
    }
    let s = ctx.unlock()?;
    match cmd {
        "ls" => {
            let items = s.trash()?;
            let mut out = Out::stdout();
            if ctx.json {
                let mut j = Json::new(&mut out);
                j.begin_obj().key("items").begin_arr();
                for t in items {
                    let kind = match t.item {
                        ItemHandle::Entry(_) => "entry",
                        ItemHandle::Group(_) => "group",
                    };
                    j.begin_obj()
                        .key("id")
                        .str(&t.item.id_hex())
                        .key("kind")
                        .str(kind)
                        .key("name")
                        .str(t.name.expose())
                        .key("deleted_at")
                        .time(t.deleted_at.map(|t| t.0))
                        .key("conflict")
                        .bool(t.conflict)
                        .end_obj();
                    j.flush()?;
                }
                j.end_arr().end_obj();
            } else {
                for t in items {
                    out.raw("@");
                    out.raw(&t.item.id_hex());
                    out.raw("  ");
                    out.raw(match t.item {
                        ItemHandle::Entry(_) => "entry",
                        ItemHandle::Group(_) => "group",
                    });
                    out.raw("  ");
                    out.text(t.name.expose());
                    out.raw("  ");
                    if let Some(at) = t.deleted_at {
                        out.raw(&crate::out::rfc3339(at.0));
                    } else {
                        out.raw("unknown");
                    }
                    if t.conflict {
                        out.raw("  [conflict]");
                    }
                    out.raw("\n");
                    out.flush()?;
                }
            }
            if ctx.json {
                out.raw("\n");
            }
            out.flush()?;
        }
        "restore" => {
            let item = resolve(
                &s,
                args.get_one::<String>("item")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )?;
            crate::signals::check()?;
            s.restore(item)?;
        }
        "empty" => {
            // The mandatory recovery snapshot comes first, before any vault
            // change (0007 §3.2, 0011 §4).
            if matches!(s.snapshot_status(), Some(r) if r.skipped == Some(SnapshotSkip::Disabled)) {
                return Err(CliError::new(
                    OTHER,
                    "cannot take the recovery snapshot before emptying the trash: no usable \
                     private snapshot directory; nothing was deleted",
                ));
            }
            if s.expired_trash()?.clock_anomaly {
                crate::out::eprint(
                    "qvault: warning: vault dates are ahead of this clock; check it before deletion\n",
                );
            }
            if !ctx.yes
                && !term::stdio_tty()?.confirm(
                    "Permanently delete all non-conflicted trash? Independent copies may remain.",
                )?
            {
                return Err(CliError::cancelled());
            }
            crate::signals::check()?;
            // `--yes` approves exceeding the snapshot budget too; otherwise a
            // budget refusal asks once and retries with explicit approval.
            let snapshot = match s.begin_destructive(ctx.yes, None) {
                Ok(snapshot) => snapshot,
                Err(CoreError::SnapshotOverBudget { needed }) => {
                    crate::out::eprint(&format!(
                        "qvault: the recovery snapshot needs {needed} bytes and does not fit the \
                         snapshot budget\n"
                    ));
                    if !term::stdio_tty()?.confirm(
                        "Take the recovery snapshot beyond the ordinary snapshot budget?",
                    )? {
                        return Err(CliError::new(
                            LIMIT,
                            "the recovery snapshot does not fit the snapshot budget; nothing was \
                             deleted",
                        ));
                    }
                    s.begin_destructive(true, None)?
                }
                Err(e) => return Err(e.into()),
            };
            crate::signals::check()?;
            let report = s.empty_trash();
            let finished = s.finish_destructive(snapshot);
            let report = match report {
                Ok(report) => report,
                Err(e) => {
                    // A failure before the commit leaves the trash intact; the
                    // pre-deletion copy stays as a `recover-` file that the
                    // next policy pass reclassifies (0007 §3.2).
                    let _ = finished;
                    return Err(e.into());
                }
            };
            if let Err(e) = finished {
                // The deletion is durable; only the reclassification failed.
                let mut error = CliError::from(e);
                error.message.push_str("; the deletion was committed");
                return Err(error);
            }
            if report.skipped_conflicts != 0 {
                crate::out::eprint(&format!(
                    "qvault: {} conflicted item(s) kept in trash\n",
                    report.skipped_conflicts
                ));
            }
        }
        _ => return Err(CliError::usage("unknown trash command")),
    }
    s.lock();
    Ok(())
}
