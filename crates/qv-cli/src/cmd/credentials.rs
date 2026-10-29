// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit password change and phrase recovery (0002 §2–4; 0011 §3–6).
use clap::ArgMatches;
use qv_core::{CancelToken, CoreError, Session, SnapshotSkip};

use crate::{
    cli::Ctx,
    exit::{CliError, OTHER},
    term::{self, Tty},
};

fn password_tty(ctx: &Ctx) -> Result<Tty<'static>, CliError> {
    if ctx.json {
        return Err(CliError::usage("this command does not support --json"));
    }
    if ctx.password_stdin {
        return Err(CliError::usage(
            "this command prompts for further secrets and cannot use --password-stdin",
        ));
    }
    if !term::stdout_is_tty() {
        return Err(CliError::usage(
            "password selection needs a terminal on standard output",
        ));
    }
    term::stdio_tty()
}

fn old_snapshots(s: &Session) -> Result<Vec<String>, CliError> {
    Ok(s.snapshots()?
        .snapshots
        .into_iter()
        .map(|s| s.archive_id)
        .collect())
}

fn changed_error(e: CoreError) -> CliError {
    let mut e = CliError::from(e);
    e.message.push_str("\nThe password change may already be committed if durability or anchor reporting failed; try the new password before retrying.");
    e
}

fn offer_snapshots(tty: &Tty<'_>, s: &Session, ids: &[String]) -> Result<(), CliError> {
    if ids.is_empty() {
        return Ok(());
    }
    tty.say(&format!("{} local snapshots were created before this password change. Copies elsewhere and anyone holding an old slot or vault key remain unaffected; deletion is not cryptographic erasure.\n", ids.len()))?;
    // --yes never supplies this separate post-change consent (0007 §3.5).
    if tty.confirm("Delete these pre-change local snapshots?")? {
        let deleted = s.delete_snapshots(ids)?;
        tty.say(&format!("Deleted {deleted} local snapshots.\n"))?;
    }
    Ok(())
}

pub(crate) fn passwd(ctx: &Ctx) -> Result<(), CliError> {
    let tty = password_tty(ctx)?;
    let s = ctx.unlock()?;
    let ids = old_snapshots(&s)?;
    let new = crate::cmd::init::choose_password(&tty)?;
    let cancel = crate::signals::token();
    crate::signals::check()?;
    s.change_password(&new, Some(&cancel))
        .map_err(changed_error)?;
    drop(new);
    tty.say("Master password changed. Existing copies of the old password slot can still unlock this key generation; suspected compromise requires key rotation.\n")?;
    offer_snapshots(&tty, &s, &ids)?;
    s.lock();
    Ok(())
}

pub(crate) fn show(ctx: &Ctx) -> Result<(), CliError> {
    if ctx.json {
        return Err(CliError::usage("recovery show does not support --json"));
    }
    if !term::stdout_is_tty() {
        return Err(CliError::usage(
            "recovery show needs a terminal on standard output",
        ));
    }
    let tty = term::stdio_tty()?;
    let password = ctx.master_password()?;
    let core = crate::select::core()?;
    let s = core.unlock(
        &ctx.vault_path()?,
        &password,
        Some(&crate::signals::token()),
    )?;
    let phrase = s.recovery_phrase(&password)?;
    drop(password);
    crate::signals::check()?;
    crate::cmd::init::show_phrase(&tty, &phrase)?;
    drop(phrase);
    crate::cli::warn_snapshots(&s);
    s.lock();
    Ok(())
}

fn recovery_copy(
    s: &Session,
    tty: &Tty<'_>,
    cancel: &CancelToken,
) -> Result<qv_core::RecoverySnapshot, CliError> {
    match s.begin_destructive(false, Some(cancel)) {
        Ok(copy) => Ok(copy),
        Err(CoreError::SnapshotOverBudget { needed }) => {
            tty.say(&format!("A mandatory recovery snapshot needs {needed} bytes and exceeds ordinary snapshot budgets.\n"))?;
            if !tty.confirm("Allow this necessary recovery copy to exceed the ordinary budget?")? {
                return Err(CliError::from(CoreError::SnapshotOverBudget { needed }));
            }
            Ok(s.begin_destructive(true, Some(cancel))?)
        }
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn recover(ctx: &Ctx, args: &ArgMatches) -> Result<(), CliError> {
    let tty = password_tty(ctx)?;
    let path = args
        .get_one::<std::path::PathBuf>("path")
        .ok_or_else(|| CliError::usage("missing recovery path"))?;
    let phrase = tty.secret("Recovery phrase (24 words): ", 1024)?;
    let cancel = crate::signals::token();
    let core = crate::select::core()?;
    let (s, _anchor) = core.unlock_with_phrase(path, phrase.expose(), Some(&cancel))?;
    drop(phrase);
    crate::cli::warn_location(s.warnings()?);
    if matches!(s.snapshot_status(), Some(r) if r.skipped == Some(SnapshotSkip::Disabled)) {
        crate::out::eprint("qvault: local snapshots are unavailable.\n");
    }
    let new = crate::cmd::init::choose_password(&tty)?;
    let recovery = if s.is_read_only()? {
        tty.say("The vault's external anchor is missing or mismatched. Accepting this verified file establishes a new local recovery baseline and does not prove it is the latest global state.\n")?;
        if !tty.confirm("Accept this file as the new local recovery baseline?")? {
            return Err(CliError::new(
                OTHER,
                "recovery baseline was declined; nothing changed",
            ));
        }
        let copy = recovery_copy(&s, &tty, &cancel)?;
        crate::signals::check()?;
        s.adopt_baseline()?;
        Some(copy)
    } else {
        None
    };
    let ids = old_snapshots(&s)?;
    crate::signals::check()?;
    s.change_password(&new, Some(&cancel))
        .map_err(changed_error)?;
    drop(new);
    tty.say("Vault recovered and master password changed. Old slots and copies still enable access to this key generation.\n")?;
    if let Some(copy) = recovery
        && s.finish_destructive(copy).is_err()
    {
        crate::out::eprint(
            "qvault: the password reset committed, but its recovery snapshot could not be reclassified; it remains on disk.\n",
        );
    }
    offer_snapshots(&tty, &s, &ids)?;
    s.lock();
    Ok(())
}
