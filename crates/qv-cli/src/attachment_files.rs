// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit attachment files through the shared no-follow helpers, with CLI
//! signal cancellation and the existing exit codes.
use crate::exit::{CliError, LIMIT, OTHER};
use qv_core::platform::{PlatformError, files};
use std::{path::Path, sync::Arc};
fn error(e: PlatformError) -> CliError {
    if e == PlatformError::StorageCapacity {
        CliError::from(qv_core::StoreError::StorageCapacity)
    } else if e == PlatformError::LimitExceeded {
        CliError::new(LIMIT, "attachment exceeds 10 MiB limit")
    } else {
        CliError::new(OTHER, "attachment file I/O failed or path is unsafe")
    }
}
fn cancel() -> qv_core::platform::Cancellation {
    Arc::new(|| crate::signals::check().is_err())
}
pub(crate) type Input = files::Input;
pub(crate) type Output = files::Output;
/// Open a regular attachment input of at most 10 MiB.
pub(crate) fn open(path: &Path) -> Result<Input, CliError> {
    Input::open(path, 10 * 1024 * 1024, cancel()).map_err(error)
}
/// Exclusively create an owner-only output; never overwrite.
pub(crate) fn create(path: &Path) -> Result<Output, CliError> {
    Output::create(path, cancel()).map_err(error)
}
/// Verify identity and sync the output and its directory.
pub(crate) fn finish(output: &Output) -> Result<(), CliError> {
    output.finish().map_err(error)
}
