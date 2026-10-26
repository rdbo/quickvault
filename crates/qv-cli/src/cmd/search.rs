// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault search <query>` (spec 0011 §4 *Browsing*).
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
    let hits = session.search(query)?;
    let paths = Paths::walk(&session)?;
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj().key("hits").begin_arr();
        for h in &hits {
            match h {
                SearchHit::Group(g) => {
                    j.begin_obj();
                    j.key("kind").str("group");
                    j.key("id").str(&g.handle.id_hex());
                    j.key("path").opt_str(
                        paths
                            .get(ItemHandle::Group(g.handle))
                            .as_deref()
                            .map(String::as_str),
                    );
                    j.key("name").str(g.name.expose());
                    j.end_obj();
                }
                SearchHit::Entry(e) => {
                    // The entry object of `ls`, with its kind first.
                    j.begin_obj();
                    j.key("kind").str("entry");
                    j.key("entry");
                    json_entry(&mut j, e, &paths);
                    j.end_obj();
                }
            }
            j.flush()?;
        }
        j.end_arr().end_obj();
        out.raw("\n");
    } else {
        for h in &hits {
            match h {
                SearchHit::Group(g) => {
                    out.path(&paths.get(ItemHandle::Group(g.handle)).unwrap_or_default())
                        .raw("/\n");
                }
                SearchHit::Entry(e) => entry_line(&mut out, e, &paths),
            }
            out.flush()?;
        }
    }
    session.lock();
    out.flush()
}
