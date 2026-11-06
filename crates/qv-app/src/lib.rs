// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared Android/Linux app, using core as its only vault boundary.
#[cfg(all(feature = "desktop", target_os = "android"))]
mod android;
pub mod autofill;
pub mod controller;
mod documents;
pub mod editor;
#[cfg(test)]
mod editor_tests;
pub mod lan;
#[cfg(test)]
mod lan_tests;
mod ops;
pub mod prefs;
pub mod qr;
#[cfg(feature = "desktop")]
mod runtime;
#[cfg(feature = "desktop")]
mod ui;
pub mod vaults;
pub mod views;
pub mod workspace;
#[cfg(test)]
mod workspace_tests;
#[cfg(feature = "desktop")]
pub use runtime::run;

#[cfg(feature = "validation")]
pub use runtime::run_preview;

#[cfg(feature = "validation")]
pub use runtime::run_flow_fixture;
