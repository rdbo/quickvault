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
//!
//! **Not in this phase:** `add`, `edit`, `mv`, `mkdir`, `rm`, `trash`,
//! `copy` and the `--copy` variants (1.10b); `passwd`, `recover`,
//! `recovery` (1.14–1.15); `verify` (1.13); history and snapshots
//! (1.12–1.13); colour output.

#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

mod address;
mod cli;
mod cmd;
mod config;
mod exit;
mod json;
mod out;
mod select;
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
    ExitCode::from(cli::run(
        std::env::args_os(),
        select::Environment::from_process(),
    ))
}
