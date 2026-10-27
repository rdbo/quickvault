// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit retained-history commands (0011 §4).
use crate::{
    address,
    cli::Ctx,
    exit::{AMBIGUOUS, CliError, NOT_FOUND},
    json::Json,
    out::{Out, escape_str, rfc3339},
    term,
};
use clap::ArgMatches;
use qv_core::{HistoryHandle, HistorySummary, RandomId};

fn arg<'a>(m: &'a ArgMatches, key: &str) -> &'a str {
    m.get_one::<String>(key).map_or("", String::as_str)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn prefix(value: &str) -> Result<String, CliError> {
    let p = value.strip_prefix('@').unwrap_or(value);
    if !(6..=32).contains(&p.len()) || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::usage(
            "a version needs 6 to 32 hex digits, optionally prefixed with @",
        ));
    }
    Ok(p.to_ascii_lowercase())
}
fn resolve(rows: &[HistorySummary], p: &str) -> Result<HistoryHandle, CliError> {
    let ids: Vec<_> = rows.iter().map(|r| r.handle.version_hex()).collect();
    let index = select(&ids, p)?;
    Ok(rows[index].handle)
}
fn select(ids: &[String], p: &str) -> Result<usize, CliError> {
    let hits: Vec<_> = ids
        .iter()
        .enumerate()
        .filter(|(_, id)| id.starts_with(p))
        .collect();
    match hits.as_slice() {
        [] => Err(CliError::new(
            NOT_FOUND,
            "retained historical version not found",
        )),
        [(index, _)] => Ok(*index),
        many => Err(CliError::new(
            AMBIGUOUS,
            format!(
                "version prefix matches multiple retained versions:\n{}",
                many.iter()
                    .map(|(_, id)| id.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )),
    }
}

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches, restore: bool) -> Result<(), CliError> {
    let (cmd, args) = if restore {
        ("restore", m)
    } else {
        m.subcommand().unwrap_or(("list", m))
    };
    let name = arg(args, "entry");
    if name.is_empty() {
        return Err(CliError::usage(
            "history needs an entry or show/purge subcommand",
        ));
    }
    if matches!(cmd, "restore" | "purge") && ctx.json {
        return Err(CliError::usage("history mutations do not accept --json"));
    }
    let p = if matches!(cmd, "show" | "restore") {
        Some(prefix(arg(args, "version"))?)
    } else {
        None
    };
    if cmd == "purge" && !ctx.yes {
        if ctx.password_stdin {
            return Err(CliError::usage(
                "history purge with --password-stdin needs --yes",
            ));
        }
        term::stdio_tty()?;
    }
    let s = ctx.unlock()?;
    let e = address::entry(&s, name)?;
    if cmd == "purge" {
        if !ctx.yes && !term::stdio_tty()?.confirm("Purge local history, including current heads if later dominated? Unseen concurrent history and independent copies may remain; no secure erasure.")? { return Err(CliError::cancelled()); }
        crate::signals::check()?;
        s.purge_history(e)?;
        let mut out = Out::stdout();
        out.raw("Local history suppressed. Active heads remain; they are suppressed if later dominated.\nNo server acknowledgement applies; snapshots, unseen concurrent history and independent copies may remain. No secure-erasure guarantee.\n");
        out.flush()?;
    } else {
        let rows = s.history(e)?;
        match cmd {
            "show" | "restore" => {
                let h = resolve(&rows, p.as_deref().unwrap_or_default())?;
                if cmd == "restore" {
                    crate::signals::check()?;
                    s.restore_history(h, args.get_flag("resolve-conflicts"))?;
                } else {
                    let d = s.history_entry(h)?;
                    super::show::whole_version(ctx, &s, &d, 1, args.get_flag("reveal"), Some(h))?;
                }
            }
            _ => list(ctx, &rows)?,
        }
    }
    s.lock();
    Ok(())
}
fn list(ctx: &Ctx, rows: &[HistorySummary]) -> Result<(), CliError> {
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj().key("versions").begin_arr();
        for r in rows {
            j.begin_obj()
                .key("version_id")
                .str(&r.handle.version_hex())
                .key("modified_at")
                .time(Some(r.modified_at.0))
                .key("device")
                .null()
                .key("writers")
                .begin_arr();
            for (id, counter) in &r.writers {
                j.begin_obj()
                    .key("id")
                    .str(&hex(&id.to_bytes()))
                    .key("counter")
                    .uint(*counter)
                    .end_obj();
            }
            j.end_arr()
                .key("conflict")
                .bool(r.conflict)
                .key("compared_to")
                .str(&hex(&r.compared_to.to_bytes()))
                .key("changed_properties")
                .begin_arr();
            for prop in &r.changed_properties {
                j.str(prop.expose());
            }
            j.end_arr().key("changed_fields").begin_arr();
            for (id, name) in &r.changed_fields {
                j.begin_obj()
                    .key("id")
                    .str(&hex(&id.to_bytes()))
                    .key("name")
                    .str(name.expose())
                    .end_obj();
            }
            j.end_arr()
                .key("unknown_extensions_changed")
                .bool(r.unknown_extensions_changed)
                .end_obj();
            j.flush()?;
        }
        j.end_arr().end_obj();
        out.raw("\n");
    } else {
        for r in rows {
            out.raw("@")
                .raw(&r.handle.version_hex())
                .raw("  ")
                .raw(&rfc3339(r.modified_at.0))
                .raw("  device: unknown")
                .raw(if r.conflict { " [conflict]" } else { "" })
                .raw("\n  compared_to: ")
                .raw(&hex(&r.compared_to.to_bytes()))
                .raw("\n  changed:");
            for prop in &r.changed_properties {
                out.raw(" ").text(prop.expose());
            }
            for (_, name) in &r.changed_fields {
                out.raw(" field=").raw(&escape_str(name.expose()));
            }
            if r.unknown_extensions_changed {
                out.raw(" unknown-extensions");
            }
            out.raw("\n  writers:");
            for (id, counter) in &r.writers {
                out.raw(&format!(" {}:{counter}", hex(&id.to_bytes())));
            }
            out.raw("\n");
            out.flush()?;
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    #[test]
    fn history_version_prefix_syntax() {
        assert_eq!(super::prefix("@ABCDEF").unwrap(), "abcdef");
        assert_eq!(
            super::prefix("0123456789abcdef0123456789abcdef")
                .unwrap()
                .len(),
            32
        );
        for bad in [
            "",
            "abcde",
            "@@@@@@",
            "abcdefg",
            "0123456789abcdef0123456789abcdef0",
        ] {
            assert_eq!(super::prefix(bad).unwrap_err().code, 2);
        }
    }
    #[test]
    fn history_version_selection_is_exact_scoped_and_ambiguous() {
        let ids = vec![
            "abcdef00000040008000000000000001".to_owned(),
            "abcdef00000040008000000000000002".to_owned(),
        ];
        assert_eq!(super::select(&ids, &ids[0]).unwrap(), 0);
        let error = super::select(&ids, "abcdef").unwrap_err();
        assert_eq!(error.code, 5);
        assert!(ids.iter().all(|id| error.message.contains(id)));
        assert_eq!(super::select(&ids[..1], "abcdef").unwrap(), 0);
        assert_eq!(super::select(&ids[..1], &ids[1]).unwrap_err().code, 4);
    }
}
