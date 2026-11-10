// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qv ls [<group>] [-r]` (spec 0011 §4 *Browsing*; 0003 §4).
//!
//! One line per item, with full paths (paste-able as addresses): a group
//! as `path/`, an entry as `path  username  url`. The username is the first
//! listed field named `username`, `user`, `login` or `email`
//! (case-insensitive), else the first `email` field; the URL is the first
//! `url` field. These are template conventions (0003 §5.2). Listing the
//! root also shows recovered items (entries whose group is missing or
//! deleted, 0003 §4.2), which only `@id` can address.

use clap::ArgMatches;
use qv_core::{EntrySummary, FieldKind, GroupHandle, ItemHandle, SearchHit, Session};

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
    let root = session.root()?;
    let mut out = Out::stdout();
    let groups = |write: &mut dyn FnMut(SearchHit) -> Result<(), CliError>| {
        walk(&session, &paths, group, recursive, |hit| {
            if matches!(hit, SearchHit::Group(_)) {
                write(hit)?;
            }
            Ok(())
        })
    };
    let entries = |write: &mut dyn FnMut(SearchHit) -> Result<(), CliError>| {
        walk(&session, &paths, group, recursive, |hit| {
            if matches!(hit, SearchHit::Entry(_)) {
                write(hit)?;
            }
            Ok(())
        })
    };
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj().key("groups").begin_arr();
        groups(&mut |hit| {
            if let SearchHit::Group(g) = hit {
                j.begin_obj().key("id").str(&g.handle.id_hex()).key("path");
                paths.json(&mut j, ItemHandle::Group(g.handle))?;
                j.key("name").str(g.name.expose()).end_obj();
                j.flush()?;
            }
            Ok(())
        })?;
        j.end_arr().key("entries").begin_arr();
        entries(&mut |hit| {
            if let SearchHit::Entry(e) = hit {
                json_entry(&mut j, &e, &paths)?;
                j.flush()?;
            }
            Ok(())
        })?;
        j.end_arr();
        if group == root {
            j.key("recovered").begin_arr();
            recovered(&session, &paths, |e| {
                json_entry(&mut j, &e, &paths)?;
                j.flush()
            })?;
            j.end_arr();
        }
        j.end_obj();
        out.raw("\n");
    } else {
        groups(&mut |hit| {
            if let SearchHit::Group(g) = hit {
                paths.human(&mut out, ItemHandle::Group(g.handle))?;
                out.raw("/\n");
                out.flush()?;
            }
            Ok(())
        })?;
        entries(&mut |hit| {
            if let SearchHit::Entry(e) = hit {
                entry_line(&mut out, &e, &paths)?;
                out.flush()?;
            }
            Ok(())
        })?;
        if group == root {
            let mut first = true;
            recovered(&session, &paths, |e| {
                if first {
                    out.raw("Recovered items (their group is missing or deleted; address them by @id):\n");
                    first = false;
                }
                entry_line(&mut out, &e, &paths)?;
                out.flush()
            })?;
        }
    }
    paths.check()?;
    session.lock();
    out.flush()
}

/// Depth-first traversal holds one bounded page and IDs per ancestor.
/// A parent resumes by ID after descending, rather than retaining its page/text.
pub(crate) fn visit(
    group: GroupHandle,
    recursive: bool,
    mut source: impl FnMut(GroupHandle, Option<ItemHandle>) -> Result<Vec<SearchHit>, CliError>,
    mut write: impl FnMut(SearchHit) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let mut stack = vec![(group, None)];
    let mut pending = std::collections::VecDeque::new();
    while let Some((group, after)) = stack.last_mut() {
        if let Some(hit) = pending.pop_front() {
            match &hit {
                SearchHit::Group(g) => {
                    let child = g.handle;
                    *after = Some(ItemHandle::Group(child));
                    write(hit)?;
                    if recursive {
                        stack.push((child, None));
                        pending.clear();
                    }
                }
                SearchHit::Entry(e) => {
                    *after = Some(ItemHandle::Entry(e.handle));
                    write(hit)?;
                }
            }
        } else {
            let page = source(*group, *after)?;
            if page.is_empty() {
                stack.pop();
            } else {
                pending.extend(page);
            }
        }
    }
    Ok(())
}
fn walk(
    s: &Session,
    paths: &Paths<'_>,
    group: GroupHandle,
    recursive: bool,
    write: impl FnMut(SearchHit) -> Result<(), CliError>,
) -> Result<(), CliError> {
    visit(
        group,
        recursive,
        |g, after| {
            paths.check()?;
            let cursor = after
                .map(|item| s.list_resume(g, item, paths.revision()))
                .transpose()?;
            let page = s.list_page(
                g,
                cursor,
                qv_core::PageLimit::default(),
                &crate::signals::token(),
            )?;
            paths.check()?;
            Ok(page.items)
        },
        write,
    )
}
fn recovered(
    s: &Session,
    paths: &Paths<'_>,
    mut write: impl FnMut(EntrySummary) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let mut cursor = None;
    loop {
        let page = s.recovered_page(
            cursor,
            qv_core::PageLimit::default(),
            &crate::signals::token(),
        )?;
        paths.check()?;
        for e in page.items {
            write(e)?;
        }
        cursor = page.next;
        if cursor.is_none() {
            return Ok(());
        }
    }
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
pub(crate) fn entry_line(
    out: &mut Out,
    e: &EntrySummary,
    paths: &Paths<'_>,
) -> Result<(), CliError> {
    if !paths.human(out, ItemHandle::Entry(e.handle))? {
        out.raw("@")
            .raw(&e.handle.id_hex()[..12])
            .raw("  ")
            .text(e.title.expose());
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
    Ok(())
}

pub(crate) fn json_entry(
    j: &mut Json<'_>,
    e: &EntrySummary,
    paths: &Paths<'_>,
) -> Result<(), CliError> {
    let (user, url) = columns(e);
    j.begin_obj();
    j.key("id").str(&e.handle.id_hex());
    j.key("path");
    paths.json(j, ItemHandle::Entry(e.handle))?;
    j.key("title").str(e.title.expose());
    j.key("type").str(e.type_hint.expose());
    j.key("username").opt_str(user);
    j.key("url").opt_str(url);
    j.key("conflict").bool(e.conflict);
    j.end_obj();
    Ok(())
}
