// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit field copy through core, dropping the unlocked session before serving.
use crate::{
    address,
    cli::Ctx,
    clipboard,
    exit::{AMBIGUOUS, CliError, LIMIT, NOT_FOUND},
};
use clap::ArgMatches;
use qv_core::{FieldKind, SecretBytes};

pub(crate) fn protected_copy(bytes: &[u8]) -> Result<SecretBytes, CliError> {
    if bytes.len() > 256 * 1024 {
        return Err(CliError::new(LIMIT, "clipboard value exceeds model limit"));
    }
    SecretBytes::try_init(bytes.len(), |dest| {
        dest.copy_from_slice(bytes);
        Ok(())
    })
}
pub(crate) fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), CliError> {
    let options = clipboard::options(ctx, matches)?;
    let value = {
        let session = ctx.unlock()?;
        let addr = matches
            .get_one::<String>("entry")
            .map(String::as_str)
            .unwrap_or_default();
        let handle = address::entry(&session, addr)?;
        if session.entry_versions(handle)?.len() > 1 {
            return Err(qv_core::CoreError::Conflict.into());
        }
        let detail = session.entry(handle)?;
        let selected = if let Some(name) = matches.get_one::<String>("field") {
            let mut fields = detail.fields.iter().filter(|f| f.name.expose() == name);
            let first = fields
                .next()
                .ok_or_else(|| CliError::new(NOT_FOUND, "field not found"))?;
            if fields.next().is_some() {
                return Err(CliError::new(
                    AMBIGUOUS,
                    "field name matches multiple fields",
                ));
            }
            first
        } else {
            detail
                .fields
                .iter()
                .find(|f| f.kind == FieldKind::Secret)
                .ok_or_else(|| CliError::new(NOT_FOUND, "entry has no secret field"))?
        };
        let value = protected_copy(session.reveal(selected.handle)?.expose_secret())?;
        session.lock();
        value
    }; // all session/details/metadata are gone before clipboard ownership
    clipboard::hold(value, options)
}
