// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signal callbacks only set an atomic flag. Ordinary control flow performs
//! cancellation, zeroization and terminal restoration through existing guards.
use crate::exit::CliError;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

static CANCELLED: OnceLock<Arc<AtomicBool>> = OnceLock::new();

pub(crate) fn install() -> Result<(), CliError> {
    let flag = CANCELLED.get_or_init(|| Arc::new(AtomicBool::new(false)));
    for signal in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(signal, flag.clone())
            .map_err(|_| CliError::new(crate::exit::OTHER, "could not install signal handlers"))?;
    }
    Ok(())
}

pub(crate) fn check() -> Result<(), CliError> {
    if CANCELLED.get().is_some_and(|f| f.load(Ordering::SeqCst)) {
        Err(CliError::cancelled())
    } else {
        Ok(())
    }
}
