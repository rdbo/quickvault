#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the prototype page into ui/dist (plan 0070, decision 4): the Leptos
# crate for wasm32, then wasm-bindgen at the locked version, then the app's
# own CSS and scripts. No tool or source is downloaded; set WASM_BINDGEN to
# the wasm-bindgen 0.2.129 binary if it is not on PATH.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
dist="$here/ui/dist"
profile=${QV_PROTO_PROFILE:-wasm}
wb=${WASM_BINDGEN:-wasm-bindgen}
case "$("$wb" --version)" in
"wasm-bindgen 0.2.129") ;;
*) echo "need wasm-bindgen 0.2.129" >&2; exit 1 ;;
esac
cd "$here"
cargo build --locked --profile "$profile" -p qv-proto-ui --target wasm32-unknown-unknown "$@"
[ "$profile" = dev ] && profile=debug
rm -rf "$dist"
mkdir -p "$dist/pkg"
"$wb" --target web --no-typescript --out-dir "$dist/pkg" \
    "$here/target/wasm32-unknown-unknown/$profile/qv_proto_ui.wasm"
# player.js: the app's copy with range-by-range fetching (see its "Plan 0070" notes).
cp "$here/ui/index.html" "$here/ui/static/boot.js" "$here/ui/static/proto.css" "$here/ui/static/player.js" "$dist/"
for f in app.css app.js; do
    cp "$repo/crates/qv-app/assets/$f" "$dist/"
done
