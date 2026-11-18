// SPDX-License-Identifier: AGPL-3.0-or-later

//! Desktop entry point of the plan 0070 prototype.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    qv_proto_app::run();
}
