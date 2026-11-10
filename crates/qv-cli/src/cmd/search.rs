// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qv search <query>` (spec 0011 §4 *Browsing*).
//!
//! Case-insensitive, over titles, group names and non-protected text, URL
//! and e-mail fields (`qv-core`); protected values and notes are never
//! searched. Output lines are as in `ls`.

use clap::ArgMatches;
use qv_core::{ItemHandle, MAX_QUERY_BYTES, SearchHit};

use crate::address::Paths;
use crate::cli::Ctx;
use crate::cmd::ls::{entry_line, json_entry};
use crate::exit::{CliError, LIMIT};
use crate::json::Json;
use crate::out::Out;

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let query = m.get_one::<String>("query").map_or("", String::as_str);
    if query.is_empty() {
        return Err(CliError::usage("the search query is empty"));
    }
    if query.len() > MAX_QUERY_BYTES {
        return Err(CliError::new(
            LIMIT,
            "the search query is longer than 1024 bytes",
        ));
    }
    let session = ctx.unlock()?;
    let paths = Paths::walk(&session)?;
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj().key("hits").begin_arr();
        each(&session, query, &paths, |h| {
            match h {
                SearchHit::Group(g) => {
                    j.begin_obj();
                    j.key("kind").str("group");
                    j.key("id").str(&g.handle.id_hex());
                    j.key("path");
                    paths.json(&mut j, ItemHandle::Group(g.handle))?;
                    j.key("name").str(g.name.expose());
                    j.end_obj();
                }
                SearchHit::Entry(e) => {
                    // The entry object of `ls`, with its kind first.
                    j.begin_obj();
                    j.key("kind").str("entry");
                    j.key("entry");
                    json_entry(&mut j, &e, &paths)?;
                    j.end_obj();
                }
            }
            j.flush()
        })?;
        j.end_arr().end_obj();
        out.raw("\n");
    } else {
        each(&session, query, &paths, |h| {
            match h {
                SearchHit::Group(g) => {
                    paths.human(&mut out, ItemHandle::Group(g.handle))?;
                    out.raw("/\n");
                }
                SearchHit::Entry(e) => entry_line(&mut out, &e, &paths)?,
            }
            out.flush()
        })?;
    }
    paths.check()?;
    session.lock();
    out.flush()
}

fn each(
    s: &qv_core::Session,
    query: &str,
    paths: &Paths<'_>,
    mut write: impl FnMut(SearchHit) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let mut cursor = None;
    loop {
        let page = s.search_page(
            query,
            cursor,
            qv_core::PageLimit::default(),
            &crate::signals::token(),
        )?;
        paths.check()?;
        for hit in page.items {
            write(hit)?;
        }
        cursor = page.next;
        if cursor.is_none() {
            return Ok(());
        }
    }
}
