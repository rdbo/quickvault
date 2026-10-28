// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault snapshot ls [--json]` / `restore <id> <new-path>` (spec 0011 §4–5, 0007 §3).
//!
//! Listing authenticates each file's archive header with the vault key, so
//! only this vault ID and key generation appear. Files that do not
//! authenticate (damage, another vault, a slot-bearing archive) are warnings
//! on stderr and never rows, so one damaged file cannot hide the healthy
//! ones; that case does not change the exit code.

use clap::ArgMatches;
use qv_core::SnapshotSummary;

use crate::cli::Ctx;
use crate::exit::CliError;
use crate::json::Json;
use crate::out::{Out, rfc3339};

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let (cmd, args) = m
        .subcommand()
        .ok_or_else(|| CliError::usage("missing snapshot command"))?;
    match cmd {
        "ls" => list(ctx),
        "restore" => restore(ctx, args),
        _ => Err(CliError::usage("unknown snapshot command")),
    }
}

fn restore(ctx: &Ctx, args: &ArgMatches) -> Result<(), CliError> {
    if ctx.json {
        return Err(CliError::usage("snapshot restore does not support --json"));
    }
    let id = args
        .get_one::<String>("id")
        .map(String::as_str)
        .unwrap_or_default();
    let prefix = id.strip_prefix('@').unwrap_or(id);
    if !(6..=32).contains(&prefix.len()) || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::usage("a snapshot ID needs 6 to 32 hex digits"));
    }
    let target = args
        .get_one::<std::path::PathBuf>("path")
        .ok_or_else(|| CliError::usage("missing restore path"))?;
    let source = ctx.vault_path()?;
    let core = crate::select::core()?;
    let password = ctx.master_password()?;
    let cancel = crate::signals::token();
    let session = core.unlock_for_snapshot_restore(&source, &password, Some(&cancel))?;
    drop(password);
    crate::signals::check()?;
    crate::cli::warn_location(session.warnings()?);
    if matches!(session.snapshot_status(), Some(r) if r.skipped == Some(qv_core::SnapshotSkip::Disabled))
    {
        return Err(CliError::new(
            crate::exit::OTHER,
            "no usable private snapshot directory",
        ));
    }
    let ids = session.snapshot_matches(id)?;
    let selected = match ids.as_slice() {
        [] => return Err(CliError::new(crate::exit::NOT_FOUND, "snapshot not found")),
        [one] => one,
        many => {
            return Err(CliError::new(
                crate::exit::AMBIGUOUS,
                format!("ambiguous snapshot ID; matches: {}", many.join(", ")),
            ));
        }
    };
    crate::signals::check()?;
    session.restore_snapshot(selected, target, Some(&cancel))?;
    crate::cli::warn_snapshots(&session);
    session.lock();
    crate::out::eprint(
        "qvault: restored a new recovery baseline; the snapshot may be old and does not establish the latest global state. Unlock it with the password current when the snapshot was created.\n",
    );
    Ok(())
}

fn list(ctx: &Ctx) -> Result<(), CliError> {
    let session = ctx.unlock()?;
    let listing = session.snapshots()?;
    if listing.unreadable != 0 {
        crate::out::eprint(&format!(
            "qvault: warning: {} snapshot file(s) could not be authenticated and were skipped\n",
            listing.unreadable
        ));
    }
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj().key("snapshots").begin_arr();
        for s in &listing.snapshots {
            row(&mut j, s);
            j.flush()?;
        }
        j.end_arr().end_obj();
        out.raw("\n");
    } else {
        for s in &listing.snapshots {
            human(&mut out, s);
            out.flush()?;
        }
    }
    out.flush()?;
    session.lock();
    Ok(())
}

fn row(j: &mut Json<'_>, s: &SnapshotSummary) {
    j.begin_obj()
        .key("id")
        .str(&s.archive_id)
        .key("created_at")
        .time(Some(s.created_at.0))
        .key("kind")
        .str(s.kind.label())
        .key("size")
        .uint(s.size)
        .key("objects")
        .uint(s.objects)
        .key("total_bytes")
        .uint(s.total_bytes)
        .end_obj();
}

/// One row: archive ID, authenticated date, kind and sizes. Nothing here is
/// vault text, so it is printed as program text.
fn human(o: &mut Out, s: &SnapshotSummary) {
    o.raw(&s.archive_id);
    o.raw("  ");
    o.raw(&rfc3339(s.created_at.0));
    o.raw("  ");
    o.raw(s.kind.label());
    o.raw(&format!(
        "  {} bytes on disk  {} objects  {} bytes referenced\n",
        s.size, s.objects, s.total_bytes
    ));
}
