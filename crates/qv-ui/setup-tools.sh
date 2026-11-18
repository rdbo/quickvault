#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Installs what crates/qv-ui/build.sh needs when it is missing: the wasm32
# target for the pinned toolchain and wasm-bindgen-cli 0.2.129 (the version
# Cargo.lock pins for wasm-bindgen). For CI and the packaging containers.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
rustup target add wasm32-unknown-unknown
case "$(wasm-bindgen --version 2>/dev/null || true)" in
"wasm-bindgen 0.2.129") ;;
*) cargo install --locked wasm-bindgen-cli --version 0.2.129 ;;
esac
