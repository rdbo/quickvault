// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault ls [<group>] [-r]` (spec 0011 §4 *Browsing*; 0003 §4).
//!
//! One line per item, with full paths (paste-able as addresses): a group
//! as `path/`, an entry as `path  username  url`. The username is the first
//! listed field named `username`, `user`, `login` or `email`
//! (case-insensitive), else the first `email` field; the URL is the first
//! `url` field. These are template conventions (0003 §5.2). Listing the
//! root also shows recovered items (entries whose group is missing or
//! deleted, 0003 §4.2), which only `@id` can address.

use clap::ArgMatches;
use qv_core::{EntrySummary, FieldKind, GroupHandle, ItemHandle, Session};

use crate::address::{self, Paths};
use crate::cli::Ctx;
use crate::exit::CliError;
use crate::json::Json;
use crate::out::Out;

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let session = ctx.unlock()?;
    let addr = m.get_one::<String>("group").map_or("", String::as_str);
    let group = address::group(&session, addr)?;
    let recursive = m.get_flag("recursive");
    let paths = Paths::walk(&session)?;
    let mut groups = Vec::new();
    let mut entries = Vec::new();
    collect(&session, group, recursive, &mut groups, &mut entries)?;
    let recovered = if group == session.root()? {
        session.recovered()?
    } else {
        Vec::new()
    };
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj();
        j.key("groups").begin_arr();
        for (g, name) in &groups {
            j.begin_obj();
            j.key("id").str(&g.id_hex());
            j.key("path").opt_str(paths.get(ItemHandle::Group(*g)));
            j.key("name").str(name.expose());
            j.end_obj();
        }
        j.end_arr();
        j.key("entries").begin_arr();
        for e in &entries {
            json_entry(&mut j, e, &paths);
        }
        j.end_arr();
        if group == session.root()? {
            j.key("recovered").begin_arr();
            for e in &recovered {
                json_entry(&mut j, e, &paths);
            }
            j.end_arr();
        }
        j.end_obj();
        out.raw("\n");
    } else {
        for (g, _) in &groups {
            out.path(paths.get(ItemHandle::Group(*g)).unwrap_or_default())
                .raw("/\n");
        }
        for e in &entries {
            entry_line(&mut out, e, &paths);
        }
        if !recovered.is_empty() {
            out.raw("Recovered items (their group is missing or deleted; address them by @id):\n");
            for e in &recovered {
                entry_line(&mut out, e, &paths);
            }
        }
    }
    session.lock();
    out.flush()
}

/// Groups and entries under `group`, depth first (groups in order, each
/// followed by its contents with `-r`, then the group's entries).
fn collect(
    s: &Session,
    group: GroupHandle,
    recursive: bool,
    groups: &mut Vec<(GroupHandle, qv_core::Text)>,
    entries: &mut Vec<EntrySummary>,
) -> Result<(), CliError> {
    let listing = s.list(group)?;
    for g in listing.groups {
        groups.push((g.handle, g.name));
        if recursive {
            collect(s, g.handle, true, groups, entries)?;
        }
    }
    entries.extend(listing.entries);
    Ok(())
}

/// The username and URL shown for an entry.
pub(crate) fn columns(e: &EntrySummary) -> (Option<&str>, Option<&str>) {
    let named = e.fields.iter().find(|f| {
        matches!(f.kind, FieldKind::Text | FieldKind::Email)
            && matches!(
                f.name.expose().to_lowercase().as_str(),
                "username" | "user" | "login" | "email"
            )
    });
    let user = named
        .or_else(|| e.fields.iter().find(|f| f.kind == FieldKind::Email))
        .map(|f| f.value.expose());
    let url = e
        .fields
        .iter()
        .find(|f| f.kind == FieldKind::Url)
        .map(|f| f.value.expose());
    (user, url)
}

/// `path  username  url` (or `@id  title …` for a recovered entry).
pub(crate) fn entry_line(out: &mut Out, e: &EntrySummary, paths: &Paths) {
    match paths.get(ItemHandle::Entry(e.handle)) {
        Some(p) => {
            out.path(p);
        }
        None => {
            out.raw("@")
                .raw(&e.handle.id_hex()[..12])
                .raw("  ")
                .text(e.title.expose());
        }
    }
    let (user, url) = columns(e);
    if let Some(u) = user {
        out.raw("  ").text(u);
    }
    if let Some(u) = url {
        out.raw("  ").text(u);
    }
    if e.conflict {
        out.raw("  (conflicting versions)");
    }
    out.raw("\n");
}

pub(crate) fn json_entry(j: &mut Json<'_>, e: &EntrySummary, paths: &Paths) {
    let (user, url) = columns(e);
    j.begin_obj();
    j.key("id").str(&e.handle.id_hex());
    j.key("path")
        .opt_str(paths.get(ItemHandle::Entry(e.handle)));
    j.key("title").str(e.title.expose());
    j.key("type").str(e.type_hint.expose());
    j.key("username").opt_str(user);
    j.key("url").opt_str(url);
    j.key("conflict").bool(e.conflict);
    j.end_obj();
}
