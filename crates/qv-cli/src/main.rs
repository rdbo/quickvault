// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault`, the QuickVault command-line client (spec 0011).
//!
//! A thin layer over `qv-core`: every command that needs vault contents
//! prompts for the master password, unlocks, does its work, and drops
//! (zeroizes) the session before it exits (0011 §1.4, 0009 §3). The process
//! is hardened (no core dumps, no debugger attachment) before arguments are
//! parsed (0011 §3.5).
//!
//! | Module | Contents | Spec |
//! |--------|----------|------|
//! | `cli` | the command tree, global options, dispatch | 0011 §1, §4 |
//! | `config` | the config file (strict TOML subset) | 0011 §1.3 |
//! | `select` | vault selection, the core's set-up | 0011 §1.2 |
//! | `term` | prompts, `--password-stdin`, the alternate screen | 0011 §3 |
//! | `out` | zeroizing output, escaping, timestamps | 0011 §5, 0008 §1 |
//! | `json` | the JSON writer and the documented schemas | 0011 §5.2 |
//! | `address` | paths and `@id` prefixes | 0011 §2 |
//! | `exit` | exit codes and messages | 0011 §6 |
//! | `cmd` | the commands | 0011 §4 |
//! | `clipboard` | private X11 owner, protected transport and deadlines | 0011 §3.6, 0008 §1–3 |
//!
//! Editing/group/trash commands use core drafts and durable transactions;
//! notes and protected values are prompted. SIGINT/TERM/HUP cancel prompts
//! through atomic flags with terminal/alternate-screen RAII cleanup.
//! `trash empty` writes and verifies a recovery snapshot before its deletion
//! commits (0011 §4), and `snapshot ls`/`verify` authenticate archive headers
//! and the whole committed state without repairing anything.
//!
//! Clipboard commands close the vault before serving a copied value in the
//! foreground. The private X11 adapter uses a maintained protected-buffer x11rb
//! patch, sensitive hints, bounded INCR transfers and ownership-safe release.
//! OS/recipient copies may persist; native Wayland requires usable XWayland.
//!
//! `snapshot restore` writes a new vault and explicit recovery baseline,
//! preserving the active vault and its anchor; it does not establish freshness.
//!
//! `passwd`, `recovery show` and `recover <existing.qvault>` provide protected
//! password replacement, reauthenticated phrase redisplay and phrase unlock.
//! Existing snapshot deletion is offered separately after password replacement;
//! old slots and independent copies are not revoked by a password change.
//!
//! **Not in this phase:** `recovery rotate` (1.15), standalone phrase/archive
//! import, sync (2–3), colour output.

#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

mod address;
mod attachment_files;
mod cli;
mod clipboard;
mod cmd;
mod config;
mod exit;
mod json;
mod out;
mod select;
mod signals;
mod term;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Before anything else, and before any secret is read.
    let protection = qv_core::harden();
    if protection.process.is_reduced() {
        out::eprint(
            "qvault: warning: reduced protection: core dumps or debugger attachment could not \
             be disabled\n",
        );
    }
    if let Err(error) = signals::install() {
        cli::report(&error);
        return ExitCode::from(error.code);
    }
    ExitCode::from(cli::run(
        std::env::args_os(),
        select::Environment::from_process(),
    ))
}
