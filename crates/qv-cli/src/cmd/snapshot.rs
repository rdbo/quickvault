// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault snapshot ls [--json]` (spec 0011 §4–5, 0007 §3).
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
    let (cmd, _args) = m
        .subcommand()
        .ok_or_else(|| CliError::usage("missing snapshot command"))?;
    match cmd {
        "ls" => list(ctx),
        _ => Err(CliError::usage("unknown snapshot command")),
    }
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
