// SPDX-License-Identifier: AGPL-3.0-or-later
// Loads the Leptos page. A file, not inline code: the CSP allows no inline
// scripts (0008 §4.2).
import init from "./pkg/qv_ui.js";
init({ module_or_path: new URL("./pkg/qv_ui_bg.wasm", import.meta.url) });
