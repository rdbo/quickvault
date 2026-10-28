// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault verify [--json]` (spec 0011 §4–5, 0004 §3.6).
//!
//! One read-only full pass over the vault: every referenced object, the
//! manifest, every active head, every retained history version and every
//! attachment chunk. It never mutates or repairs anything; the documented
//! remedy for a failure is restoring a snapshot.
//!
//! The vault is unlocked with the recovery-anchor semantics, so a missing or
//! mismatched anchor is still checked and *reported* (with exit 7) instead of
//! refusing before the report exists.

use clap::ArgMatches;
use qv_core::{AnchorStatus, VerifyReport};

use crate::cli::Ctx;
use crate::exit::{CliError, INTEGRITY};
use crate::json::Json;
use crate::out::Out;

/// The fixed anchor label (0011 §4).
fn anchor_label(a: AnchorStatus) -> &'static str {
    match a {
        AnchorStatus::Verified => "verified",
        AnchorStatus::Advanced => "advanced",
        AnchorStatus::Missing => "missing",
        AnchorStatus::Mismatch => "mismatch",
        _ => "unknown",
    }
}

pub(crate) fn run(ctx: &Ctx, _m: &ArgMatches) -> Result<(), CliError> {
    let path = ctx.vault_path()?;
    let core = crate::select::core()?;
    let password = ctx.master_password()?;
    let (session, _anchor) = core.unlock_for_recovery(&path, &password, None)?;
    drop(password);
    crate::signals::check()?;
    crate::cli::warn_location(session.warnings()?);
    crate::cli::warn_snapshots(&session);
    let report = session.verify(None)?;
    let mut out = Out::stdout();
    if ctx.json {
        json(&mut out, &report);
        out.raw("\n");
    } else {
        human(&mut out, &report);
    }
    out.flush()?;
    let ok = report.ok();
    let anchor = report.anchor;
    session.lock();
    if ok {
        return Ok(());
    }
    Err(CliError::new(
        INTEGRITY,
        format!(
            "integrity check failed: the external anchor is {}",
            anchor_label(anchor)
        ),
    ))
}

/// One line per check group plus the summary (0011 §4).
fn human(o: &mut Out, r: &VerifyReport) {
    o.raw("vault: ");
    o.raw(&r.vault_id);
    o.raw(&format!(
        " (key generation {}, local seq {})\n",
        r.key_generation, r.local_seq
    ));
    o.raw(&format!(
        "objects: {} referenced objects re-hashed, {} bytes\n",
        r.counts.objects, r.counts.total_bytes
    ));
    o.raw(&format!(
        "records: {} records, {} active heads, {} retained versions, {} tombstones\n",
        r.counts.records, r.counts.active_heads, r.counts.retained_versions, r.counts.tombstones
    ));
    o.raw("anchor: ").raw(anchor_label(r.anchor)).raw("\n");
    if !r.notes.is_empty() {
        o.raw("notes:");
        for n in &r.notes {
            o.raw(" ").raw(n.label());
        }
        o.raw("\n");
    }
    o.raw("summary: ").raw(if r.ok() {
        "ok\n"
    } else {
        "integrity check failed\n"
    });
}

fn json(o: &mut Out, r: &VerifyReport) {
    let mut j = Json::new(o);
    j.begin_obj();
    j.key("vault_id").str(&r.vault_id);
    j.key("key_generation").uint(u64::from(r.key_generation));
    j.key("local_seq").uint(r.local_seq);
    j.key("anchor").str(anchor_label(r.anchor));
    j.key("objects").uint(r.counts.objects);
    j.key("records").uint(r.counts.records);
    j.key("active_heads").uint(r.counts.active_heads);
    j.key("retained_versions").uint(r.counts.retained_versions);
    j.key("tombstones").uint(r.counts.tombstones);
    j.key("total_bytes").uint(r.counts.total_bytes);
    j.key("ok").bool(r.ok());
    j.key("notes").begin_arr();
    for n in &r.notes {
        j.str(n.label());
    }
    j.end_arr();
    j.end_obj();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_anchor_labels() {
        assert_eq!(anchor_label(AnchorStatus::Verified), "verified");
        assert_eq!(anchor_label(AnchorStatus::Advanced), "advanced");
        assert_eq!(anchor_label(AnchorStatus::Missing), "missing");
        assert_eq!(anchor_label(AnchorStatus::Mismatch), "mismatch");
    }
}
