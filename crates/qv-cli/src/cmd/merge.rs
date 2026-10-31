// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit local archive acceptance, independently of conflict resolution.

use clap::ArgMatches;

use crate::{cli::Ctx, exit::CliError, out::Out};

pub(crate) fn run(ctx: &Ctx, args: &ArgMatches) -> Result<(), CliError> {
    if ctx.json {
        return Err(CliError::usage("merge does not support --json"));
    }
    let source = args
        .get_one::<std::path::PathBuf>("archive")
        .ok_or_else(|| CliError::usage("missing archive path"))?;
    let over_budget = args.get_flag("allow-over-budget");
    if over_budget {
        crate::out::eprint(
            "qvault: the necessary recovery copy may exceed ordinary snapshot budgets\n",
        );
    }
    let session = ctx.unlock()?;
    let cancel = crate::signals::token();
    let result = session.merge_archive(source, over_budget, Some(&cancel));
    session.lock();
    let report = result?;
    let mut out = Out::stdout();
    out.raw(if report.accepted {
        "local acceptance: committed\n"
    } else {
        "local acceptance: already accepted\n"
    });
    out.raw(&format!("conflicts: {}\n", report.conflicts));
    out.flush()?;
    if let Some(error) = report.completion_error {
        return Err(error.into());
    }
    Ok(())
}
