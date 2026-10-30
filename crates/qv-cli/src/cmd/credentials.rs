// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit password change, phrase recovery and key rotation (0002 §2–4;
//! 0011 §3–6).
//!
//! `recovery rotate` (0002 §3.5; plan 0023) always asks the user to type
//! `rotate`, even with `--yes` (0011 §5.5). It takes a recovery snapshot,
//! builds and verifies the next generation, shows the new phrase on the
//! alternate screen and installs only after three of its words are typed
//! correctly; there is no skip, because cancelling changes nothing. If an
//! interrupted rotation exists, the same command asks for the passwords it
//! needs and for a typed `complete` or `rollback`.
use std::path::Path;

use clap::ArgMatches;
use qv_core::{
    CancelToken, Core, CoreError, MasterPassword, Rotation, RotationChoice, RotationState, Session,
    SnapshotSkip,
};

use crate::{
    cli::Ctx,
    exit::{CliError, OTHER},
    term::{self, MAX_ANSWER_BYTES, MAX_PASSWORD_BYTES, Tty},
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
    let path = ctx.vault_path()?;
    let s = core
        .unlock(&path, &password, Some(&crate::signals::token()))
        .map_err(|e| crate::cli::rotation_hint(&core, &path, e))?;
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
    let (s, _anchor) = core
        .unlock_with_phrase(path, phrase.expose(), Some(&cancel))
        .map_err(|e| crate::cli::rotation_hint(&core, path, e))?;
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

const ROTATE_TEXT: &str = "Key rotation replaces this vault's key, recovery phrase and master \
password, and re-encrypts all data under the new key. It protects the new key generation only: \
old copies of the vault file, existing snapshots, old password slots and the old recovery phrase \
still open the data as it was. Earlier snapshots stay under the snapshot budgets and open only \
with the old recovery phrase. A recovery snapshot is taken first.\n";

const PARTIAL: &str = "\nThe key rotation may be partly applied. Do not delete or rename any \
`.qvrotate` file; run `qvault recovery rotate` again and enter both master passwords.";

/// Types `word` exactly, or the operation is declined (nothing changed).
fn typed(tty: &Tty<'_>, label: &str, word: &str) -> Result<bool, CliError> {
    let answer = tty.line(label, MAX_ANSWER_BYTES, true)?;
    Ok(answer.expose() == word.as_bytes())
}

fn ask_password(tty: &Tty<'_>, label: &str) -> Result<MasterPassword, CliError> {
    let typed = tty.secret(label, MAX_PASSWORD_BYTES)?;
    Ok(MasterPassword::from_utf8(typed.expose())?)
}

fn begin_rotation(
    s: &Session,
    tty: &Tty<'_>,
    new: &MasterPassword,
    cancel: &CancelToken,
) -> Result<Rotation, CliError> {
    match s.begin_rotation(new, false, Some(cancel)) {
        Ok(r) => Ok(r),
        Err(CoreError::SnapshotOverBudget { needed }) => {
            tty.say(&format!("The mandatory recovery snapshot needs {needed} bytes and exceeds ordinary snapshot budgets.\n"))?;
            if !tty.confirm("Allow this necessary recovery copy to exceed the ordinary budget?")? {
                return Err(CliError::from(CoreError::SnapshotOverBudget { needed }));
            }
            Ok(s.begin_rotation(new, true, Some(cancel))?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Three words of the new phrase. `false` if the user cancelled the rotation
/// (an empty line offers to show the phrase again or to cancel).
fn check_rotation_phrase(tty: &Tty<'_>, rotation: &mut Rotation) -> Result<bool, CliError> {
    let positions = qv_core::confirmation_positions()?;
    tty.say(
        "Check the new recovery phrase: type the words asked for. Press Enter on an empty line \
         for other options.\n",
    )?;
    let mut done = 0;
    while done < positions.len() {
        let pos = positions[done];
        let word = tty.secret(&format!("Word #{}: ", pos + 1), MAX_ANSWER_BYTES)?;
        if word.expose().iter().all(u8::is_ascii_whitespace) {
            drop(word);
            if tty.confirm("Show the new recovery phrase again?")? {
                crate::cmd::init::show_phrase(tty, rotation.phrase())?;
            } else if tty.confirm("Cancel the key rotation? Nothing will change.")? {
                return Ok(false);
            }
            continue;
        }
        if rotation.confirm_word(pos, word.expose())? {
            done += 1;
        } else {
            tty.say(&format!("That is not word #{}.\n", pos + 1))?;
        }
    }
    tty.say("The new recovery phrase is checked.\n")?;
    Ok(true)
}

pub(crate) fn rotate(ctx: &Ctx) -> Result<(), CliError> {
    let tty = password_tty(ctx)?;
    let path = ctx.vault_path()?;
    let core = crate::select::core()?;
    if core.rotation_pending(&path)? {
        return resume(&tty, &core, &path);
    }
    let s = ctx.unlock_path(&path)?;
    tty.say(ROTATE_TEXT)?;
    // --yes never supplies this confirmation (0011 §5.5).
    if !typed(&tty, "Type rotate to continue: ", "rotate")? {
        return Err(CliError::new(
            OTHER,
            "key rotation was not confirmed; nothing changed",
        ));
    }
    let new = crate::cmd::init::choose_password(&tty)?;
    let cancel = crate::signals::token();
    crate::signals::check()?;
    let mut rotation = begin_rotation(&s, &tty, &new, &cancel)?;
    drop(new);
    let left = rotation.leftovers();
    if left.removed > 0 {
        tty.say(&format!(
            "Removed {} unused files of an earlier interrupted rotation.\n",
            left.removed
        ))?;
    }
    if left.retained_old > 0 {
        tty.say(&format!("{} retained old-generation vault copies (`.qvrotate-old-` files) were left in place.\n", left.retained_old))?;
    }
    crate::cmd::init::show_phrase(&tty, rotation.phrase())?;
    if !check_rotation_phrase(&tty, &mut rotation)? {
        drop(rotation);
        return Err(CliError::new(
            OTHER,
            "key rotation cancelled; nothing changed",
        ));
    }
    crate::signals::check()?;
    match rotation.install(Some(&cancel)) {
        Ok(done) => {
            tty.say(&format!(
                "Key rotation complete: the vault is now key generation {}. Use the new master password and the new recovery phrase from now on.\n",
                done.new_generation.0
            ))?;
            if done.cleanup_pending {
                tty.say("Some files of the old generation could not be removed yet; run `qvault recovery rotate` again with the new master password to finish.\n")?;
            }
            Ok(())
        }
        Err(e) => {
            let mut err = CliError::from(e.error);
            if e.journal_published {
                err.message.push_str(PARTIAL);
            }
            Err(err)
        }
    }
}

/// Finishes an interrupted rotation with the passwords it needs.
fn resume(tty: &Tty<'_>, core: &Core, path: &Path) -> Result<(), CliError> {
    tty.say("An interrupted key rotation was found for this vault.\n")?;
    let need = core.rotation_passwords(path)?;
    let new = if need.new {
        Some(ask_password(
            tty,
            "New master password (chosen for the rotation): ",
        )?)
    } else {
        None
    };
    let old = if need.old {
        Some(ask_password(tty, "Previous master password: ")?)
    } else {
        None
    };
    let cancel = crate::signals::token();
    let t = core.resume_rotation(path, old.as_ref(), new.as_ref(), Some(&cancel))?;
    drop((old, new));
    let (from, to) = (t.old_generation().0, t.new_generation().0);
    let choice = match t.state() {
        RotationState::Committed => {
            tty.say(&format!(
                "Key generation {to} is installed; only cleanup of generation {from} remains.\n"
            ))?;
            if !typed(tty, "Type complete to finish: ", "complete")? {
                return Err(CliError::new(OTHER, "nothing changed"));
            }
            RotationChoice::Complete
        }
        RotationState::RollbackPending => {
            tty.say(&format!(
                "A rollback to key generation {from} was interrupted.\n"
            ))?;
            if !typed(tty, "Type rollback to finish it: ", "rollback")? {
                return Err(CliError::new(OTHER, "nothing changed"));
            }
            RotationChoice::RollBack
        }
        _ => {
            tty.say(&format!("The rotation from key generation {from} to {to} was not finished. Completing installs generation {to} (new master password and phrase); rolling back keeps generation {from} (previous password and phrase).\n"))?;
            let answer = tty.line("Type complete or rollback: ", MAX_ANSWER_BYTES, true)?;
            match answer.expose() {
                b"complete" => RotationChoice::Complete,
                b"rollback" => RotationChoice::RollBack,
                _ => return Err(CliError::new(OTHER, "nothing changed")),
            }
        }
    };
    crate::signals::check()?;
    core.finish_rotation(t, choice, Some(&cancel))?;
    tty.say(match choice {
        RotationChoice::Complete => "Key rotation complete.\n",
        RotationChoice::RollBack => {
            "Key rotation rolled back; the previous generation is active.\n"
        }
    })?;
    Ok(())
}
