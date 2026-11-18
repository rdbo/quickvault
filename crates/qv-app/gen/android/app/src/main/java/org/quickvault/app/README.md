<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
tauri-cli generates its Android classes (`TauriActivity`, `WryActivity`, IPC)
into `generated/` here at build time (git-ignored). The app's own activity,
autofill service and handoff live in `../../../dev/dioxus/main/`, under their
original component names (plan 0071).
