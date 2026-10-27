// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault totp <entry>` (spec 0011 §4): the current code of the entry's
//! first TOTP field and the seconds left. The code is printed (it is
//! short-lived); the seed never is. An entry with conflicting versions needs
//! a version choice (exit 8).

use clap::ArgMatches;
use qv_core::FieldKind;

use crate::address;
use crate::cli::Ctx;
use crate::exit::{CliError, OTHER};
use crate::json::Json;
use crate::out::Out;

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let copy_options = if m.get_flag("copy") {
        Some(crate::clipboard::options(ctx, m)?)
    } else {
        None
    };
    let session = ctx.unlock()?;
    let addr = m.get_one::<String>("entry").map_or("", String::as_str);
    let handle = address::entry(&session, addr)?;
    if session.entry_versions(handle)?.len() > 1 {
        return Err(qv_core::CoreError::Conflict.into());
    }
    let detail = session.entry(handle)?;
    let field = detail
        .fields
        .iter()
        .find(|f| f.kind == FieldKind::Totp)
        .ok_or_else(|| CliError::new(OTHER, "the entry has no TOTP field"))?;
    let now = session.totp(field.handle)?;
    session.lock();
    if let Some(options) = copy_options {
        let value = super::copy::protected_copy(now.code.expose_secret().as_bytes())?;
        drop(now);
        drop(detail);
        drop(session);
        return crate::clipboard::hold(value, options);
    }
    let mut out = Out::stdout();
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj();
        j.key("code").str(now.code.expose_secret());
        j.key("seconds_remaining")
            .uint(u64::from(now.seconds_remaining));
        j.end_obj();
        out.raw("\n");
    } else {
        out.text(now.code.expose_secret())
            .raw(&format!("  ({} s left)\n", now.seconds_remaining));
    }
    out.flush()
}
