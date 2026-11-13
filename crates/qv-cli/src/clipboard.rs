// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foreground clipboard owner (X11 on Linux, Win32 on Windows). No clipboard
//! readback or manager handover.
use crate::{
    cli::Ctx,
    exit::{CliError, LIMIT, OTHER},
    out::Out,
};
use clap::ArgMatches;
use qv_core::SecretBytes;
use std::time::Duration;
const MAX_VALUE: usize = 256 * 1024;
#[derive(Clone, Copy)]
pub(crate) struct ClipboardOptions {
    timeout: Duration,
}
pub(crate) fn options(ctx: &Ctx, matches: &ArgMatches) -> Result<ClipboardOptions, CliError> {
    if ctx.json {
        return Err(CliError::usage(
            "--json cannot be combined with clipboard output",
        ));
    }
    let config = ctx.env.config()?;
    let seconds = matches
        .try_get_one::<u32>("timeout")
        .ok()
        .flatten()
        .copied()
        .or(config.clipboard_timeout)
        .unwrap_or(20);
    if !(1..=300).contains(&seconds) {
        return Err(CliError::usage(
            "clipboard timeout must be 1 to 300 seconds",
        ));
    }
    Ok(ClipboardOptions {
        timeout: Duration::from_secs(u64::from(seconds)),
    })
}
fn backend<T, E>(value: Result<T, E>) -> Result<T, CliError> {
    value.map_err(|_| {
        CliError::new(
            OTHER,
            if cfg!(windows) {
                "clipboard backend failed or is unavailable (requires a desktop session)"
            } else {
                "clipboard backend failed or is unavailable (requires a Wayland or X11 desktop session)"
            },
        )
    })
}
pub(crate) fn hold(value: SecretBytes, options: ClipboardOptions) -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    use qv_core::platform::SessionClipboard as Backend;
    #[cfg(windows)]
    use qv_core::platform::WinClipboard as Backend;
    use qv_core::platform::{Clipboard, PlatformError};
    if value.len() > MAX_VALUE {
        return Err(CliError::new(LIMIT, "clipboard value exceeds model limit"));
    }
    if std::str::from_utf8(value.expose_secret()).is_err() {
        return Err(CliError::usage("clipboard value is not UTF-8 text"));
    }
    crate::signals::check()?;
    if qv_core::harden().memory.is_reduced() {
        crate::out::eprint(
            "qv: warning: reduced protection: secret buffers could not all be locked in memory and may reach swap\n",
        );
    }
    let tty = crate::term::stderr_is_tty();
    let token = crate::signals::token();
    let mut last = None;
    let result = Backend.hold(
        value,
        options.timeout,
        std::sync::Arc::new(move || token.is_cancelled()),
        &mut |left| {
            if tty || last.is_none() {
                let mut out = Out::stderr();
                out.raw(&format!(
                    "{}Clipboard available: {left} s{}",
                    if tty { "\r" } else { "" },
                    if tty { " " } else { "\n" }
                ));
                out.flush().map_err(|_| PlatformError::Io)?;
            }
            last = Some(left);
            Ok(())
        },
    );
    if tty {
        crate::out::eprint("\rClipboard session ended.              \n");
    }
    match result {
        Err(PlatformError::Cancelled) => Err(CliError::cancelled()),
        Err(PlatformError::ClipboardReplaced) => Err(qv_core::CoreError::ClipboardReplaced.into()),
        Err(PlatformError::LimitExceeded) => {
            Err(CliError::new(LIMIT, "clipboard value exceeds model limit"))
        }
        other => backend(other),
    }
}
