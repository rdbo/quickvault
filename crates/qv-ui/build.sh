#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the app page into crates/qv-app/dist/ui, which tauri.conf.json
# embeds (plan 0071): this crate for wasm32, wasm-bindgen at the locked
# version, then the app's CSS and scripts. Nothing is downloaded; set
# WASM_BINDGEN to the wasm-bindgen 0.2.129 binary if it is not on PATH.
# QV_UI_PROFILE=dev builds faster, unoptimized.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
dist="$repo/crates/qv-app/dist/ui"
profile=${QV_UI_PROFILE:-wasm}
wb=${WASM_BINDGEN:-wasm-bindgen}
case "$("$wb" --version)" in
"wasm-bindgen 0.2.129") ;;
*) echo "need wasm-bindgen 0.2.129" >&2; exit 1 ;;
esac
target=${CARGO_TARGET_DIR:-$repo/target}
cd "$repo"
cargo build --locked --profile "$profile" -p qv-ui --target wasm32-unknown-unknown "$@"
[ "$profile" = dev ] && profile=debug
rm -rf "$dist"
mkdir -p "$dist/pkg"
"$wb" --target web --no-typescript --out-dir "$dist/pkg" \
    "$target/wasm32-unknown-unknown/$profile/qv_ui.wasm"
cp "$here/index.html" "$here/static/boot.js" "$dist/"
for f in app.css app.js player.js; do
    cp "$repo/crates/qv-app/assets/$f" "$dist/"
done
