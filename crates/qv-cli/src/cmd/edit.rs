// SPDX-License-Identifier: AGPL-3.0-or-later

//! Entry changes are prepared in a protected core draft and saved once, after
//! every option and prompt succeeds. No editor or plaintext temporary file.
use std::collections::HashSet;

use clap::ArgMatches;
use qv_core::{EntryDraft, FieldKind, FieldValue, Text};
use zeroize::Zeroizing;

use crate::{
    address,
    cli::Ctx,
    exit::{CliError, LIMIT},
    term,
};

const MAX_VALUE: usize = 256 * 1024;

pub(crate) fn values<'a>(m: &'a ArgMatches, name: &str) -> Vec<&'a str> {
    m.try_get_many::<String>(name)
        .ok()
        .flatten()
        .map(|v| v.map(String::as_str).collect())
        .unwrap_or_default()
}

fn text(s: &str) -> Result<Text, CliError> {
    bounded(s)?;
    Text::new(s).map_err(|_| CliError::usage("invalid text"))
}
fn bounded(s: &str) -> Result<(), CliError> {
    if s.len() > MAX_VALUE {
        Err(CliError::new(LIMIT, "field exceeds model limit"))
    } else {
        Ok(())
    }
}
fn field_value(s: &str) -> Result<FieldValue, CliError> {
    bounded(s)?;
    FieldValue::text(s).map_err(|_| CliError::usage("invalid field value"))
}
fn prompt(label: &str, notes: bool) -> Result<term::Typed, CliError> {
    let tty = term::stdio_tty()?;
    let label = Zeroizing::new(format!("{}: ", crate::out::escape_str(label)));
    if notes {
        tty.multiline(&label, MAX_VALUE)
    } else {
        tty.secret(&label, MAX_VALUE)
    }
}
fn utf8(typed: &term::Typed) -> Result<&str, CliError> {
    core::str::from_utf8(typed.expose()).map_err(|_| CliError::usage("input is not UTF-8"))
}
fn index(d: &EntryDraft, name: &str) -> Result<Option<usize>, CliError> {
    let mut hits = d
        .entry()
        .fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.name.expose() == name);
    let first = hits.next().map(|(i, _)| i);
    if hits.next().is_some() {
        return Err(CliError::usage("field name is ambiguous"));
    }
    Ok(first)
}
fn set(d: &mut EntryDraft, name: &str, value: FieldValue, kind: FieldKind) -> Result<(), CliError> {
    match index(d, name)? {
        Some(i) => d.entry_mut().fields[i].value = value,
        None => {
            d.add_field(name, kind, value)?;
        }
    }
    Ok(())
}

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches, edit: bool) -> Result<(), CliError> {
    let interactive = m.get_flag("interactive");
    let generate = m.get_flag("generate");
    let fields = values(m, "field");
    let secrets = values(m, "secret-field");
    let settings = super::generate::from_options(m)?;
    if settings.is_some() && !generate {
        return Err(CliError::usage("generator flags need --generate"));
    }
    let mut changes = HashSet::new();
    let mut plain = Vec::new();
    for f in fields {
        let (name, value) = match f.split_once('=') {
            Some(pair) => pair,
            None if interactive => (f, ""),
            None => {
                return Err(CliError::usage(
                    "--field needs NAME=VALUE (or NAME with -i)",
                ));
            }
        };
        plain.push((name, value));
    }
    for name in ["username", "url"] {
        if let Some(value) = m.get_one::<String>(name) {
            plain.push((name, value));
        }
    }
    // Validate all change names and overlaps before reading the master password.
    for name in plain
        .iter()
        .map(|(n, _)| *n)
        .chain(secrets.iter().copied())
        .chain(values(m, "remove-field"))
        .chain(if generate { vec!["password"] } else { vec![] })
    {
        if name.is_empty() || name.contains('=') || !changes.insert(name) {
            return Err(CliError::usage(
                "empty, repeated or contradictory field change",
            ));
        }
        bounded(name)?;
    }
    let protect = values(m, "protect");
    let unprotect = values(m, "unprotect");
    let removed = values(m, "remove-field");
    let mut policies = HashSet::new();
    for name in protect.iter().chain(&unprotect) {
        if name.is_empty() || !policies.insert(*name) || removed.contains(name) {
            return Err(CliError::usage("repeated or contradictory field policy"));
        }
    }
    if !edit && plain.iter().any(|(name, _)| *name == "password") {
        return Err(CliError::usage(
            "new passwords require --generate or --secret-field password",
        ));
    }
    let prompts = interactive || m.get_flag("notes") || !secrets.is_empty() || (!edit && !generate);
    if prompts && ctx.password_stdin {
        return Err(CliError::usage(
            "--password-stdin cannot be combined with value prompts",
        ));
    }
    if prompts {
        term::stdio_tty()?;
    }
    let addr = m
        .get_one::<String>("entry")
        .map(String::as_str)
        .unwrap_or_default();
    let parsed = if !edit {
        let p = address::parse_path(addr)?;
        if p.trailing_slash || p.segments.is_empty() || addr.starts_with('@') {
            return Err(CliError::usage("add needs a new entry path"));
        }
        Some(p)
    } else {
        None
    };
    for (_, value) in &plain {
        bounded(value)?;
    }
    let session = ctx.unlock()?;
    let mut draft = if edit {
        session.edit_entry(address::entry(&session, addr)?)?
    } else {
        let p = parsed
            .as_ref()
            .ok_or_else(|| CliError::usage("missing entry path"))?;
        let (last, parents) = p
            .segments
            .split_last()
            .ok_or_else(|| CliError::usage("missing title"))?;
        let parent = super::groups::walk(&session, parents, false)?;
        session.new_entry(
            parent,
            m.get_one::<String>("type")
                .map(String::as_str)
                .unwrap_or("login"),
            last,
        )?
    };
    // Refuse argv replacement of protected fields based on the ORIGINAL policy,
    // including simultaneous --unprotect. Validate every target before prompting.
    for (name, _) in &plain {
        if let Some(i) = index(&draft, name)? {
            let f = &draft.entry().fields[i];
            if !interactive
                && (f.protected || matches!(f.kind, FieldKind::Secret | FieldKind::Totp))
            {
                return Err(CliError::usage(
                    "protected fields require -i or --secret-field",
                ));
            }
        }
    }
    for name in &secrets {
        index(&draft, name)?;
    }
    if generate {
        index(&draft, "password")?;
    }
    for name in removed.iter().chain(&protect).chain(&unprotect) {
        if index(&draft, name)?.is_none() {
            return Err(CliError::new(crate::exit::NOT_FOUND, "field not found"));
        }
    }
    if let Some(title) = m.try_get_one::<String>("title").ok().flatten() {
        draft.entry_mut().title = if interactive {
            let input = prompt("Title", false)?;
            text(utf8(&input)?)?
        } else {
            text(title)?
        };
    }
    if let Some(hint) = m.get_one::<String>("type") {
        draft.entry_mut().type_hint = text(hint)?;
    }
    for (name, value) in plain {
        let kind = if name == "url" {
            FieldKind::Url
        } else {
            FieldKind::Text
        };
        let value = if interactive {
            let input = prompt(name, false)?;
            field_value(utf8(&input)?)?
        } else {
            field_value(value)?
        };
        set(&mut draft, name, value, kind)?;
    }
    for name in &secrets {
        let input = prompt(name, false)?;
        set(
            &mut draft,
            name,
            field_value(utf8(&input)?)?,
            FieldKind::Secret,
        )?;
        if let Some(i) = index(&draft, name)? {
            draft.entry_mut().fields[i].protected = true;
        }
    }
    if generate {
        let generated = session.generate(settings.as_ref())?;
        set(
            &mut draft,
            "password",
            field_value(generated.expose_secret())?,
            FieldKind::Secret,
        )?;
    } else if !edit && !secrets.contains(&"password") {
        if changes.contains("password") {
            return Err(CliError::usage("password must be prompted or generated"));
        }
        let input = prompt("password", false)?;
        set(
            &mut draft,
            "password",
            field_value(utf8(&input)?)?,
            FieldKind::Secret,
        )?;
    }
    if m.get_flag("notes") {
        let input = prompt("Notes (Ctrl-D to finish)", true)?;
        draft.entry_mut().notes = Some(text(utf8(&input)?)?);
    }
    for name in protect {
        if let Some(i) = index(&draft, name)? {
            draft.entry_mut().fields[i].protected = true;
        }
    }
    for name in unprotect {
        if let Some(i) = index(&draft, name)? {
            draft.entry_mut().fields[i].protected = false;
        }
    }
    for name in removed {
        if let Some(i) = index(&draft, name)? {
            draft.entry_mut().fields.remove(i);
        }
    }
    crate::signals::check()?;
    session.save_entry(draft)?;
    session.lock();
    Ok(())
}
