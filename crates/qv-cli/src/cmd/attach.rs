// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit attachment file operations; plaintext never goes to command output.
use crate::{
    address,
    attachment_files::{Input, Output},
    cli::Ctx,
    exit::{AMBIGUOUS, CliError, NOT_FOUND, OTHER},
    json::Json,
    out::{Out, escape_str},
    term,
};
use clap::ArgMatches;
use qv_core::{AttachmentHandle, AttachmentSummary};
use std::path::{Path, PathBuf};
fn arg<'a>(m: &'a ArgMatches, key: &str) -> &'a str {
    m.get_one::<String>(key).map_or("", String::as_str)
}
fn resolve(items: &[AttachmentSummary], address: &str) -> Result<AttachmentHandle, CliError> {
    let prefix = address.strip_prefix('@');
    if let Some(p) = prefix
        && (!(6..=32).contains(&p.len()) || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(CliError::usage("an @id needs 6 to 32 hex digits"));
    }
    let mut hits: Vec<_> = items
        .iter()
        .filter(|i| match prefix {
            Some(p) => i.handle.id_hex().starts_with(&p.to_ascii_lowercase()),
            None => i.name.expose() == address,
        })
        .collect();
    hits.dedup_by_key(|i| i.handle.id_hex());
    match hits.as_slice() {
        [] => Err(CliError::new(NOT_FOUND, "attachment not found")),
        [one] => Ok(one.handle),
        many => {
            let mut message = format!(
                "{} matches multiple attachments; use an ID:",
                escape_str(address)
            );
            for i in many {
                message.push_str(&format!(
                    "\n  @{}  {}",
                    i.handle.id_hex(),
                    escape_str(i.name.expose())
                ));
            }
            Err(CliError::new(AMBIGUOUS, message))
        }
    }
}
pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let (cmd, m) = m
        .subcommand()
        .ok_or_else(|| CliError::usage("missing attachment command"))?;
    if cmd != "ls" && ctx.json {
        return Err(CliError::usage("only attach ls accepts --json"));
    }
    if matches!(cmd, "save" | "rm") && !ctx.yes {
        if ctx.password_stdin {
            return Err(CliError::usage(
                "attach save/rm with --password-stdin needs --yes",
            ));
        }
        term::stdio_tty()?;
    }
    // Invalid input metadata and file type/size fail before unlocking.
    let path = m.try_get_one::<PathBuf>("file").ok().flatten();
    let name = if cmd == "add" {
        Some(match m.get_one::<String>("name") {
            Some(s) => s.as_str(),
            None => path
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .ok_or_else(|| CliError::usage("input needs a UTF-8 basename or --name"))?,
        })
    } else {
        None
    };
    let mime = m
        .try_get_one::<String>("mime")
        .ok()
        .flatten()
        .map_or("application/octet-stream", String::as_str);
    if let Some(name) = name {
        qv_core::Text::new(name).map_err(|_| CliError::usage("invalid attachment name"))?;
        qv_core::Text::new(mime).map_err(|_| CliError::usage("invalid attachment MIME"))?;
    }
    let mut input = path.map(|p| Input::open(p)).transpose()?;
    let session = ctx.unlock()?;
    let entry = address::entry(&session, arg(m, "entry"))?;
    if cmd == "add" {
        let handle = session.add_attachment(
            entry,
            name.unwrap_or_default(),
            mime,
            input
                .as_mut()
                .ok_or_else(|| CliError::usage("missing input file"))?,
            None,
        )?;
        let mut out = Out::stdout();
        out.raw("@").raw(&handle.id_hex()).raw("\n");
        out.flush()?;
    } else {
        let items = session.attachments(entry)?;
        if cmd == "ls" {
            let mut out = Out::stdout();
            if ctx.json {
                let mut j = Json::new(&mut out);
                j.begin_arr();
                for i in items {
                    j.begin_obj()
                        .key("id")
                        .str(&i.handle.id_hex())
                        .key("version_id")
                        .str(&i.handle.version_hex())
                        .key("name")
                        .str(i.name.expose())
                        .key("mime")
                        .str(i.mime.expose())
                        .key("size")
                        .uint(i.size)
                        .key("conflicted")
                        .bool(i.conflicted)
                        .end_obj();
                    j.flush()?;
                }
                j.end_arr();
                out.raw("\n");
            } else {
                for i in items {
                    out.raw("@")
                        .raw(&i.handle.id_hex())
                        .raw("  ")
                        .text(i.name.expose())
                        .raw("  ")
                        .text(i.mime.expose())
                        .raw(&format!(
                            "  {} bytes{}\n",
                            i.size,
                            if i.conflicted { " [conflict]" } else { "" }
                        ));
                    out.flush()?;
                }
            }
            out.flush()?;
        } else {
            let handle = resolve(&items, arg(m, "attachment"))?;
            let prompt = if cmd == "save" {
                "Export plaintext attachment to the explicit new file?"
            } else {
                "Permanently remove attachment? Independent copies may remain; no secure-erasure guarantee."
            };
            if !ctx.yes && !term::stdio_tty()?.confirm(prompt)? {
                return Err(CliError::cancelled());
            }
            crate::signals::check()?;
            match cmd {
                "save" => {
                    session.verify_attachment(handle, None)?;
                    crate::signals::check()?;
                    let path = m
                        .get_one::<PathBuf>("path")
                        .map(PathBuf::as_path)
                        .unwrap_or(Path::new(""));
                    let mut output = Output::create(path)?;
                    let result = session
                        .save_attachment(handle, &mut output, None)
                        .map_err(CliError::from)
                        .and_then(|()| output.finish());
                    if let Err(e) = result {
                        return Err(CliError::new(
                            e.code,
                            "attachment export failed; the explicit destination may contain incomplete plaintext",
                        ));
                    }
                }
                "rm" => session.remove_attachment(handle)?,
                _ => return Err(CliError::new(OTHER, "unknown attachment command")),
            }
        }
    }
    session.lock();
    Ok(())
}
