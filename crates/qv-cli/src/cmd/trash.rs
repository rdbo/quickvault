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

/// Shared explicit budget flow for all destructive CLI operations.
pub(crate) fn recovery_copy(
    ctx: &Ctx,
    s: &Session,
    cancel: Option<&qv_core::CancelToken>,
) -> Result<qv_core::RecoverySnapshot, CliError> {
    match s.begin_destructive(ctx.yes, cancel) {
        Ok(copy) => Ok(copy),
        Err(CoreError::SnapshotOverBudget { needed }) => {
            crate::out::eprint(&format!(
                "qv: the recovery snapshot needs {needed} bytes and exceeds the ordinary budget\n"
            ));
            if !term::stdio_tty()?
                .confirm("Allow this necessary recovery copy to exceed the ordinary budget?")?
            {
                return Err(CoreError::SnapshotOverBudget { needed }.into());
            }
            Ok(s.begin_destructive(true, cancel)?)
        }
        Err(e) => Err(e.into()),
    }
}

fn resolve(s: &Session, addr: &str) -> Result<ItemHandle, CliError> {
    let ids = addr
        .strip_prefix('@')
        .map(|prefix| {
            s.find_id(prefix, true).map_err(|e| match e {
                CoreError::InvalidInput => CliError::usage("an @id needs 6 to 32 hex digits"),
                e => e.into(),
            })
        })
        .transpose()?;
    let mut hits = Vec::new();
    each(s, |t| {
        if ids
            .as_ref()
            .map_or_else(|| t.name.expose() == addr, |ids| ids.contains(&t.item))
        {
            hits.push(t.item);
        }
        Ok(())
    })?;
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(CliError::new(NOT_FOUND, "trashed item not found")),
        many => {
            let mut message = format!(
                "{} matches multiple trashed items; use an ID:",
                escape_str(addr)
            );
            for item in many {
                message.push_str(&format!("\n  @{}", item.id_hex()));
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
            let mut out = Out::stdout();
            if ctx.json {
                let mut j = Json::new(&mut out);
                j.begin_obj().key("items").begin_arr();
                each(&s, |t| {
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
                    j.flush()
                })?;
                j.end_arr().end_obj();
            } else {
                each(&s, |t| {
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
                    out.flush()
                })?;
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
            if s.expiry_summary()?.clock_anomaly {
                crate::out::eprint(
                    "qv: warning: vault dates are ahead of this clock; check it before deletion\n",
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
                        "qv: the recovery snapshot needs {needed} bytes and does not fit the \
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
                    "qv: {} conflicted item(s) kept in trash\n",
                    report.skipped_conflicts
                ));
            }
        }
        _ => return Err(CliError::usage("unknown trash command")),
    }
    s.lock();
    Ok(())
}

fn each(
    s: &Session,
    mut write: impl FnMut(qv_core::TrashItem) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let revision = s.view_revision()?;
    let mut cursor = None;
    loop {
        let page = s.trash_page(
            cursor,
            qv_core::PageLimit::default(),
            &crate::signals::token(),
        )?;
        if page.revision != revision {
            return Err(CoreError::StaleHandle.into());
        }
        for item in page.items {
            write(item)?;
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    if s.view_revision()? != revision {
        return Err(CoreError::StaleHandle.into());
    }
    Ok(())
}
