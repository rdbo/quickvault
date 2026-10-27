// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group creation, moves and soft deletion through the core's durable path.
use crate::{
    address,
    cli::Ctx,
    exit::{AMBIGUOUS, CliError, NOT_FOUND},
    out::escape_str,
};
use clap::ArgMatches;
use qv_core::{GroupHandle, Session};
use zeroize::Zeroizing;

/// Iterative parent traversal. Each missing parent is a separate durable core
/// operation; later refusal may leave previously created parents intact.
pub(crate) fn walk(
    s: &Session,
    parts: &[Zeroizing<String>],
    create: bool,
) -> Result<GroupHandle, CliError> {
    let mut group = s.root()?;
    for name in parts {
        let listing = s.list(group)?;
        let hits: Vec<_> = listing
            .groups
            .iter()
            .filter(|g| g.name.expose() == name.as_str())
            .collect();
        group = match hits.as_slice() {
            [one] => one.handle,
            [] if create => {
                crate::signals::check()?;
                s.save_group(s.new_group(group, name)?)?
            }
            [] => return Err(CliError::new(NOT_FOUND, "parent group not found")),
            many => {
                let mut message =
                    format!("ambiguous group {}: use one of these IDs", escape_str(name));
                for g in many {
                    message.push_str(&format!("\n  @{}", g.handle.id_hex()));
                }
                return Err(CliError::new(AMBIGUOUS, message));
            }
        };
    }
    Ok(group)
}
fn arg<'a>(m: &'a ArgMatches, name: &str) -> &'a str {
    m.get_one::<String>(name)
        .map(String::as_str)
        .unwrap_or_default()
}
pub(crate) fn run(ctx: &Ctx, cmd: &str, m: &ArgMatches) -> Result<(), CliError> {
    if cmd == "mkdir" {
        let p = address::parse_path(arg(m, "path"))?;
        if p.segments.is_empty() || arg(m, "path").starts_with('@') {
            return Err(CliError::usage("mkdir needs a new group path"));
        }
        let s = ctx.unlock()?;
        if m.get_flag("parents") {
            walk(&s, &p.segments, true)?;
        } else {
            let (last, parents) = p
                .segments
                .split_last()
                .ok_or_else(|| CliError::usage("missing name"))?;
            let parent = walk(&s, parents, false)?;
            crate::signals::check()?;
            s.save_group(s.new_group(parent, last)?)?;
        }
        s.lock();
        return Ok(());
    }
    let s = ctx.unlock()?;
    let item = address::resolve(&s, arg(m, "item"), address::Want::Any)?;
    crate::signals::check()?;
    if cmd == "mv" {
        s.move_item(item, address::group(&s, arg(m, "group"))?)?;
    } else {
        s.delete(item, m.get_flag("recursive"))?;
    }
    s.lock();
    Ok(())
}
