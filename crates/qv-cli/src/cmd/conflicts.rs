// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit all-kind inspection and complete-version selection.

use crate::{
    cli::Ctx,
    exit::CliError,
    json::Json,
    out::{Out, rfc3339},
};
use clap::ArgMatches;
use qv_core::{
    ConflictDetails, ConflictRecordHandle, ConflictVersion, Deletion, RecordKind, Session,
};

fn kind(k: RecordKind) -> &'static str {
    match k {
        RecordKind::Entry => "entry",
        RecordKind::Group => "group",
        RecordKind::VaultMeta => "vault_meta",
        RecordKind::AttachmentMeta => "attachment",
        RecordKind::PasswordKeyslot => "password_keyslot",
    }
}
fn state(s: Deletion) -> &'static str {
    match s {
        Deletion::Live => "live",
        Deletion::SoftDeleted => "soft_deleted",
        Deletion::Final => "final",
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn valid_prefix(s: &str) -> bool {
    (6..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn preflight_target(s: Option<&String>) -> Result<(), CliError> {
    if s.is_some_and(|s| s.strip_prefix('@').is_some_and(|p| !valid_prefix(p))) {
        return Err(CliError::usage("a record ID needs 6 to 32 hex digits"));
    }
    Ok(())
}
fn target(s: &Session, name: &str) -> Result<ConflictRecordHandle, CliError> {
    let id = if name.starts_with('@') {
        name.to_owned()
    } else {
        crate::address::resolve(s, name, crate::address::Want::Any)?.id_hex()
    };
    let found = s.conflict_matches(&id)?;
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(CliError::new(crate::exit::NOT_FOUND, "record not found")),
        many => Err(CliError::new(
            crate::exit::AMBIGUOUS,
            format!(
                "ambiguous record ID; matches: {}",
                many.iter()
                    .map(|r| r.id_hex())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

pub(crate) fn inspect(ctx: &Ctx, args: &ArgMatches) -> Result<(), CliError> {
    let name = args.get_one::<String>("target");
    let reveal = args.get_flag("reveal");
    preflight_target(name)?;
    if reveal && name.is_none() {
        return Err(CliError::usage("--reveal requires a conflict target"));
    }
    let s = ctx.unlock()?;
    let result = inspect_in(ctx, args, &s);
    s.lock();
    result
}
fn inspect_in(ctx: &Ctx, args: &ArgMatches, s: &Session) -> Result<(), CliError> {
    let mut out = Out::stdout();
    let Some(name) = args.get_one::<String>("target") else {
        let rows = s.conflict_records()?;
        if ctx.json {
            let mut j = Json::new(&mut out);
            j.begin_obj().key("conflicts").begin_arr();
            for r in rows {
                j.begin_obj()
                    .key("id")
                    .str(&r.handle.id_hex())
                    .key("kind")
                    .str(kind(r.kind))
                    .key("versions")
                    .uint(r.versions as u64)
                    .end_obj();
                j.flush()?;
            }
            j.end_arr().end_obj();
            out.raw("\n");
        } else {
            for r in rows {
                out.raw("@")
                    .raw(&r.handle.id_hex())
                    .raw("  ")
                    .raw(kind(r.kind))
                    .raw(&format!("  {} versions\n", r.versions));
                out.flush()?;
            }
        }
        return out.flush();
    };
    let record = target(s, name)?;
    let versions = s.conflict_versions(record)?;
    let reveal = args.get_flag("reveal");
    if ctx.json {
        let mut j = Json::new(&mut out);
        j.begin_obj()
            .key("record_id")
            .str(&record.id_hex())
            .key("versions")
            .begin_arr();
        for handle in versions {
            let v = s.conflict_version(&handle)?;
            j.begin_obj()
                .key("version_id")
                .str(&handle.version_hex())
                .key("kind")
                .str(details_kind(&v.details))
                .key("state")
                .str(state(v.state))
                .key("modified_at")
                .time(Some(v.modified_at.0))
                .key("clock")
                .begin_arr();
            for (writer, counter) in &v.clock {
                use qv_core::RandomId;
                j.begin_arr()
                    .str(&hex(&writer.to_bytes()))
                    .uint(*counter)
                    .end_arr();
            }
            j.end_arr()
                .key("unknown_extensions")
                .bool(v.unknown_extensions)
                .key("details");
            details_json(&mut j, s, &v.details, reveal)?;
            j.end_obj();
            j.flush()?;
        }
        j.end_arr().end_obj();
        out.raw("\n");
        out.flush()
    } else {
        out.raw("Record: @").raw(&record.id_hex()).raw("\n");
        out.flush()?;
        for handle in versions {
            let v = s.conflict_version(&handle)?;
            out.raw("Version: @")
                .raw(&handle.version_hex())
                .raw("  ")
                .raw(details_kind(&v.details))
                .raw("  ")
                .raw(state(v.state))
                .raw("  ")
                .raw(&rfc3339(v.modified_at.0))
                .raw("\n");
            out.raw("Clock:");
            for (writer, counter) in &v.clock {
                use qv_core::RandomId;
                out.raw(" ")
                    .raw(&hex(&writer.to_bytes()))
                    .raw(&format!(":{counter}"));
            }
            out.raw("\n");
            if v.unknown_extensions {
                out.raw("Unknown optional values are present and will be preserved.\n");
            }
            out.flush()?;
            human(ctx, s, &v, reveal)?;
        }
        Ok(())
    }
}
fn details_kind(d: &ConflictDetails) -> &'static str {
    match d {
        ConflictDetails::Entry { .. } => "entry",
        ConflictDetails::Group(_) => "group",
        ConflictDetails::VaultMeta(_) => "vault_meta",
        ConflictDetails::Attachment { .. } => "attachment",
        ConflictDetails::PasswordSlot { .. } => "password_keyslot",
        ConflictDetails::Tombstone(k) => kind(*k),
    }
}
fn settings(j: &mut Json<'_>, s: &qv_core::Settings) {
    use qv_core::{Capitalization, GeneratorSettings};
    j.begin_obj().key("history_depth");
    if let Some(n) = s.history_depth {
        j.uint(n as u64);
    } else {
        j.null();
    }
    j.key("trash_retention_days");
    if let Some(n) = s.trash_retention_days {
        j.uint(n as u64);
    } else {
        j.null();
    }
    j.key("recovery_skipped_at")
        .time(s.recovery_skipped_at.map(|t| t.0))
        .key("generator");
    if let Some(g) = &s.generator {
        j.begin_obj();
        match &g.settings {
            GeneratorSettings::Characters(c) => {
                j.key("type")
                    .str("characters")
                    .key("length")
                    .uint(c.length as u64)
                    .key("lowercase")
                    .bool(c.lowercase)
                    .key("uppercase")
                    .bool(c.uppercase)
                    .key("digits")
                    .bool(c.digits)
                    .key("symbols")
                    .bool(c.symbols)
                    .key("exclude_ambiguous")
                    .bool(c.exclude_ambiguous)
                    .key("exclude_chars")
                    .str(&c.exclude_chars)
                    .key("require_each_class")
                    .bool(c.require_each_class);
            }
            GeneratorSettings::Passphrase(p) => {
                j.key("type")
                    .str("passphrase")
                    .key("words")
                    .uint(p.words as u64)
                    .key("wordlist")
                    .str("eff-large")
                    .key("separator")
                    .str(&p.separator.to_string())
                    .key("capitalize")
                    .str(match p.capitalize {
                        Capitalization::None => "none",
                        Capitalization::FirstLetter => "first_letter",
                    })
                    .key("append_digit")
                    .bool(p.append_digit);
            }
            GeneratorSettings::Pin(p) => {
                j.key("type").str("pin").key("length").uint(p.length as u64);
            }
        }
        j.end_obj();
    } else {
        j.null();
    }
    j.end_obj();
}
fn details_json(
    j: &mut Json<'_>,
    s: &Session,
    d: &ConflictDetails,
    reveal: bool,
) -> Result<(), CliError> {
    j.begin_obj();
    match d {
        ConflictDetails::Entry { detail: e, group } => {
            j.key("title")
                .str(e.title.expose())
                .key("type")
                .str(e.type_hint.expose())
                .key("group")
                .str(&hex(&group.0))
                .key("notes")
                .opt_str(e.notes.as_ref().map(|t| t.expose()))
                .key("icon")
                .opt_str(e.icon.as_ref().map(|t| t.expose()))
                .key("created_at")
                .time(Some(e.created_at.0))
                .key("modified_at")
                .time(Some(e.modified_at.0))
                .key("expires_at")
                .time(e.expires_at.map(|t| t.0))
                .key("deleted_at")
                .time(e.deleted_at.map(|t| t.0))
                .key("fields")
                .begin_arr();
            for f in &e.fields {
                use qv_core::RandomId;
                j.begin_obj()
                    .key("id")
                    .str(&hex(&f.handle.field_id().to_bytes()))
                    .key("name")
                    .str(f.name.expose())
                    .key("kind")
                    .str(crate::cmd::show::kind_name(f.kind))
                    .key("protected")
                    .bool(f.protected)
                    .key("value");
                if f.protected && !reveal {
                    j.null();
                } else {
                    j.bytes(s.reveal(f.handle)?.expose_secret());
                }
                j.end_obj();
            }
            j.end_arr();
        }
        ConflictDetails::Group(g) => {
            j.key("name")
                .str(g.name.expose())
                .key("parent")
                .opt_str(g.parent.map(|r| hex(&r.0)).as_deref())
                .key("notes")
                .opt_str(g.notes.as_ref().map(|t| t.expose()))
                .key("icon")
                .opt_str(g.icon.as_ref().map(|t| t.expose()))
                .key("order")
                .str(g.order.expose())
                .key("deleted_at")
                .time(g.deleted_at.map(|t| t.0));
        }
        ConflictDetails::VaultMeta(m) => {
            j.key("name")
                .str(m.name.expose())
                .key("description")
                .opt_str(m.description.as_ref().map(|t| t.expose()))
                .key("root")
                .str(&hex(&m.root_group.0))
                .key("settings");
            settings(j, &m.settings);
        }
        ConflictDetails::Attachment {
            entry,
            name,
            mime,
            size,
            chunks,
        } => {
            j.key("entry")
                .str(&hex(&entry.0))
                .key("name")
                .str(name.expose())
                .key("mime")
                .str(mime.expose())
                .key("size")
                .uint(*size)
                .key("chunks")
                .uint(*chunks as u64);
        }
        ConflictDetails::PasswordSlot {
            slot_id,
            kdf_profile,
            wrap_profile,
        } => {
            j.key("slot_id")
                .str(slot_id)
                .key("kdf_profile")
                .uint(*kdf_profile as u64)
                .key("wrap_profile")
                .uint(*wrap_profile as u64);
        }
        ConflictDetails::Tombstone(_) => {}
    }
    j.end_obj();
    Ok(())
}
fn human(ctx: &Ctx, s: &Session, v: &ConflictVersion, reveal: bool) -> Result<(), CliError> {
    let mut o = Out::stdout();
    match &v.details {
        ConflictDetails::Entry { detail: e, group } => {
            o.raw("Stored group: @").raw(&hex(&group.0)).raw("\n");
            if let Some(icon) = &e.icon {
                o.raw("Icon: ").text(icon.expose()).raw("\n");
            }
            if let Some(time) = e.deleted_at {
                o.raw("Deleted at: ").raw(&rfc3339(time.0)).raw("\n");
            }
            o.flush()?;
            return crate::cmd::show::whole(ctx, s, e, 1, reveal);
        }
        ConflictDetails::Group(g) => {
            o.raw("Name: ")
                .text(g.name.expose())
                .raw("\nParent: ")
                .raw(
                    &g.parent
                        .map(|r| hex(&r.0))
                        .unwrap_or_else(|| "(root)".into()),
                )
                .raw("\nOrder: ")
                .text(g.order.expose())
                .raw("\n");
            if let Some(n) = &g.notes {
                o.raw("Notes: ").text(n.expose()).raw("\n");
            }
            if let Some(i) = &g.icon {
                o.raw("Icon: ").text(i.expose()).raw("\n");
            }
            if let Some(t) = g.deleted_at {
                o.raw("Deleted at: ").raw(&rfc3339(t.0)).raw("\n");
            }
        }
        ConflictDetails::VaultMeta(m) => {
            o.raw("Name: ")
                .text(m.name.expose())
                .raw("\nRoot: ")
                .raw(&hex(&m.root_group.0))
                .raw("\n");
            if let Some(d) = &m.description {
                o.raw("Description: ").text(d.expose()).raw("\n");
            }
            o.raw("Settings: ");
            settings(&mut Json::new(&mut o), &m.settings);
            o.raw("\n");
        }
        ConflictDetails::Attachment {
            entry,
            name,
            mime,
            size,
            chunks,
        } => {
            o.raw("Owner: @")
                .raw(&hex(&entry.0))
                .raw("\nName: ")
                .text(name.expose())
                .raw("\nMIME: ")
                .text(mime.expose())
                .raw(&format!("\nSize: {size} bytes\nChunks: {chunks}\n"));
        }
        ConflictDetails::PasswordSlot {
            slot_id,
            kdf_profile,
            wrap_profile,
        } => {
            o.raw("Slot: @").raw(slot_id).raw(&format!("\nKDF profile: {kdf_profile}\nWrap profile: {wrap_profile}\nSelected-slot password proof is required before adoption.\n"));
        }
        ConflictDetails::Tombstone(_) => {
            o.raw("Permanent deletion; no payload.\n");
        }
    }
    o.flush()
}

pub(crate) fn resolve(ctx: &Ctx, args: &ArgMatches) -> Result<(), CliError> {
    if ctx.json {
        return Err(CliError::usage("resolve does not support --json"));
    }
    let version = args.get_one::<String>("version").map_or("", String::as_str);
    let version = version.strip_prefix('@').unwrap_or(version);
    if !valid_prefix(version) {
        return Err(CliError::usage("a version ID needs 6 to 32 hex digits"));
    }
    preflight_target(args.get_one::<String>("target"))?;
    let s = ctx.unlock()?;
    let result = resolve_in(ctx, args, &s);
    s.lock();
    result
}
fn resolve_in(ctx: &Ctx, args: &ArgMatches, s: &Session) -> Result<(), CliError> {
    let name = args.get_one::<String>("target").map_or("", String::as_str);
    let record = target(s, name)?;
    let prefix = args.get_one::<String>("version").map_or("", String::as_str);
    let prefix = prefix
        .strip_prefix('@')
        .unwrap_or(prefix)
        .to_ascii_lowercase();
    let matches: Vec<_> = s
        .conflict_versions(record)?
        .into_iter()
        .filter(|v| v.version_hex().starts_with(&prefix))
        .collect();
    let h = match matches.as_slice() {
        [] => {
            return Err(CliError::new(
                crate::exit::NOT_FOUND,
                "active version not found",
            ));
        }
        [one] => one,
        _ => {
            return Err(CliError::new(
                crate::exit::AMBIGUOUS,
                "ambiguous active version ID",
            ));
        }
    };
    let v = s.conflict_version(h)?;
    crate::out::eprint(
        "qvault: this creates a new complete version covering all inspected heads; unseen edits may still conflict\n",
    );
    if v.state == Deletion::Final {
        crate::out::eprint(
            "qvault: choosing permanent deletion removes payload/history; independent copies may remain\n",
        );
    }
    if !ctx.yes && !crate::term::stdio_tty()?.confirm("Create this complete-version resolution?")? {
        return Err(CliError::new(crate::exit::OTHER, "resolution cancelled"));
    }
    let password = if matches!(v.details, ConflictDetails::PasswordSlot { .. }) {
        let value = crate::term::stdio_tty()?.secret(
            "Selected version's master password: ",
            crate::term::MAX_PASSWORD_BYTES,
        )?;
        Some(qv_core::MasterPassword::from_utf8(value.expose())?)
    } else {
        None
    };
    let cancel = crate::signals::token();
    let result = s.resolve_version(h, password.as_ref(), Some(&cancel))?;
    let mut out = Out::stdout();
    out.raw("local resolution: committed\n")
        .raw(&format!("conflicts: {}\n", result.conflicts));
    out.flush()?;
    if let Some(e) = result.completion_error {
        return Err(e.into());
    }
    Ok(())
}
