// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault show <entry> [--reveal] [--field <name>]` (spec 0011 §4, §3.3,
//! §5.2).
//!
//! Protected values print as `••••••••` unless `--reveal` is given; their
//! JSON value is `null` with `"protected": true`. `--field` prints only one
//! value: escaped when standard output is a terminal, exactly as stored
//! otherwise (for scripts). For an entry with conflicting versions, `show`
//! displays one of them and says how many exist; `--field` needs a version
//! choice and fails with exit 8 (0005 §2.3).

use clap::ArgMatches;
use qv_core::{EntryDetail, FieldDetail, FieldKind, ItemHandle, Session};

use crate::address::{self, Paths};
use crate::cli::Ctx;
use crate::exit::{CliError, OTHER};
use crate::json::Json;
use crate::out::{Out, rfc3339};
use crate::term;

const MASK: &str = "••••••••";

/// A field kind's name in output.
pub(crate) fn kind_name(k: FieldKind) -> &'static str {
    match k {
        FieldKind::Text => "text",
        FieldKind::Secret => "secret",
        FieldKind::Url => "url",
        FieldKind::Email => "email",
        FieldKind::Totp => "totp",
        FieldKind::Multiline => "multiline",
        FieldKind::Date => "date",
        _ => "unknown",
    }
}

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let session = ctx.unlock()?;
    let addr = m.get_one::<String>("entry").map_or("", String::as_str);
    let handle = address::entry(&session, addr)?;
    let detail = session.entry(handle)?;
    let versions = session.entry_versions(handle)?.len();
    let reveal = m.get_flag("reveal");
    let r = match m.get_one::<String>("field") {
        Some(name) => one_field(ctx, &session, &detail, name, versions, reveal),
        None => whole(ctx, &session, &detail, versions, reveal),
    };
    session.lock();
    r
}

/// The value of a field: the detail's own, or a reveal for a protected one.
fn value(s: &Session, f: &FieldDetail) -> Result<qv_core::FieldValue, CliError> {
    Ok(s.reveal(f.handle)?)
}

fn one_field(
    ctx: &Ctx,
    s: &Session,
    d: &EntryDetail,
    name: &str,
    versions: usize,
    reveal: bool,
) -> Result<(), CliError> {
    if versions > 1 {
        return Err(qv_core::CoreError::Conflict.into());
    }
    let f = d
        .fields
        .iter()
        .find(|f| f.name.expose() == name)
        .ok_or_else(|| {
            CliError::new(
                crate::exit::NOT_FOUND,
                format!(
                    "the entry has no field named {}",
                    crate::out::escape_str(name)
                ),
            )
        })?;
    if f.protected && !reveal {
        return Err(CliError::new(
            OTHER,
            "the field is protected; add --reveal to print it",
        ));
    }
    let v = value(s, f)?;
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj();
        j.key("name").str(f.name.expose());
        j.key("kind").str(kind_name(f.kind));
        j.key("protected").bool(f.protected);
        j.key("value").bytes(v.expose_secret());
        j.end_obj();
    } else if term::stdout_is_tty() {
        out.bytes(v.expose_secret());
    } else {
        out.verbatim(v.expose_secret());
    }
    out.raw("\n");
    out.flush()
}

fn whole(
    ctx: &Ctx,
    s: &Session,
    d: &EntryDetail,
    versions: usize,
    reveal: bool,
) -> Result<(), CliError> {
    let paths = Paths::walk(s)?;
    let path = paths.get(ItemHandle::Entry(d.handle));
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj();
        j.key("id").str(&d.handle.id_hex());
        j.key("path").opt_str(path);
        j.key("title").str(d.title.expose());
        j.key("type").str(d.type_hint.expose());
        j.key("notes").opt_str(d.notes.as_ref().map(|n| n.expose()));
        j.key("created").time(Some(d.created_at.0));
        j.key("modified").time(Some(d.modified_at.0));
        j.key("expires").time(d.expires_at.map(|t| t.0));
        j.key("versions").uint(versions as u64);
        j.key("fields").begin_arr();
        for f in &d.fields {
            j.begin_obj();
            j.key("name").str(f.name.expose());
            j.key("kind").str(kind_name(f.kind));
            j.key("protected").bool(f.protected);
            j.key("value");
            if f.protected && !reveal {
                j.null();
            } else {
                j.bytes(value(s, f)?.expose_secret());
            }
            j.end_obj();
        }
        j.end_arr();
        j.end_obj();
        out.raw("\n");
        return out.flush();
    }
    if versions > 1 {
        out.raw(&format!(
            "Note: this entry has {versions} conflicting versions; this is one of them.\n"
        ));
    }
    out.raw("Title:     ").text(d.title.expose()).raw("\n");
    out.raw("Path:      ");
    match path {
        Some(p) => out.path(p),
        None => out.raw("(recovered items)"),
    };
    out.raw("\nID:        @").raw(&d.handle.id_hex()).raw("\n");
    out.raw("Type:      ").text(d.type_hint.expose()).raw("\n");
    for f in &d.fields {
        out.text(f.name.expose()).raw(": ");
        if f.protected && !reveal {
            out.raw(MASK).raw("  (protected)");
        } else {
            let v = value(s, f)?;
            match (f.kind, core::str::from_utf8(v.expose_secret())) {
                (FieldKind::Multiline, Ok(text)) => {
                    out.multiline(text, "  ");
                }
                _ => {
                    out.bytes(v.expose_secret());
                }
            }
        }
        out.raw("\n");
    }
    if let Some(n) = &d.notes {
        out.raw("Notes:\n  ").multiline(n.expose(), "  ").raw("\n");
    }
    out.raw(&format!("Created:   {}\n", rfc3339(d.created_at.0)));
    out.raw(&format!("Modified:  {}\n", rfc3339(d.modified_at.0)));
    if let Some(t) = d.expires_at {
        out.raw(&format!("Expires:   {}\n", rfc3339(t.0)));
    }
    out.flush()
}
