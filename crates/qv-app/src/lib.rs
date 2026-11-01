// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared Android/Linux app, using core as its only vault boundary.
#[cfg(all(feature = "desktop", target_os = "android"))]
mod android;
pub mod controller;
#[cfg(feature = "desktop")]
mod runtime;
#[cfg(feature = "desktop")]
mod ui;
#[cfg(feature = "desktop")]
pub use runtime::run;

#[cfg(feature = "validation")]
pub use runtime::run_preview;

#[cfg(feature = "validation")]
pub use runtime::run_flow_fixture;
