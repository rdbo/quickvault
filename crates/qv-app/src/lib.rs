// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared Android/Linux app, using core as its only vault boundary.
#[cfg(all(feature = "ui", target_os = "android"))]
mod android;
pub mod autofill;
#[cfg(feature = "desktop")]
mod bridge;
pub mod controller;
mod documents;
pub mod editor;
#[cfg(test)]
mod editor_tests;
pub mod lan;
#[cfg(test)]
mod lan_tests;
mod last_view;
mod meter;
mod ops;
// Native UI read workers are exercised headlessly in tests, but unused in the headless library.
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
mod page_read;
#[cfg(all(feature = "ui", target_os = "linux"))]
pub mod picker;
pub mod prefs;
pub mod preview;
pub mod qr;
#[cfg(feature = "fixture")]
mod validation_media;
pub mod vaults;
pub mod views;
pub mod workspace;
#[cfg(test)]
mod workspace_tests;
#[cfg(feature = "desktop")]
pub use bridge::run;

#[cfg(feature = "validation")]
pub use bridge::{run_boundary, run_flow_fixture, run_preview};
