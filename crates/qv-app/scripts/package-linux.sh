#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the Linux release tarball (plan 0056): quickvault (the desktop app),
# qv (the CLI), a desktop entry and icons, the licence, a short README and
# SHA256SUMS, then the .tar.gz and its checksum, under target/dist/.
# Run from any directory. The artifacts are unsigned: signing with the
# owner's key is a release step (plans/0056-release-1-0), not this script.
set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"

cargo build --release --locked -p qv-cli --bin qv
cargo build --release --locked -p qv-app --features desktop --bin quickvault

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$version" ] || { echo 'cannot read the workspace version' >&2; exit 1; }
arch=$(uname -m)
name="quickvault-$version-linux-$arch"
dist="$root/target/dist"
dir="$dist/$name"
rm -rf "$dir"
mkdir -p "$dir/share/applications" "$dir/share/icons/hicolor/256x256/apps" \
    "$dir/share/icons/hicolor/scalable/apps"

install -m 0755 target/release/quickvault "$dir/quickvault"
install -m 0755 target/release/qv "$dir/qv"
install -m 0644 LICENSE "$dir/LICENSE"
install -m 0644 crates/qv-app/linux/org.quickvault.QuickVault.desktop \
    "$dir/share/applications/org.quickvault.QuickVault.desktop"
install -m 0644 crates/qv-app/assets/icon-256.png \
    "$dir/share/icons/hicolor/256x256/apps/org.quickvault.QuickVault.png"
install -m 0644 docs/logo/logo.svg \
    "$dir/share/icons/hicolor/scalable/apps/org.quickvault.QuickVault.svg"
cat > "$dir/README.txt" <<README
QuickVault $version for Linux ($arch)

quickvault  the desktop app (needs GTK 3 and WebKitGTK 4.1)
qv          the command-line client

To install for one user:
  install -Dm755 quickvault qv -t ~/.local/bin
  cp -r share/. ~/.local/share/

Vaults live in ~/.local/share/quickvault/vaults and private state in
\$XDG_STATE_HOME/quickvault. Check these files against SHA256SUMS.
Licence: AGPL-3.0-or-later (LICENSE).
README

(cd "$dir" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r f; do sha256sum "$f"; done > SHA256SUMS)

tarball="$dist/$name.tar.gz"
# Reproducible archive metadata: sorted names, fixed owner and times.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
    -C "$dist" -cf - "$name" | gzip -n -9 > "$tarball"
(cd "$dist" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
echo "Built $tarball"
cat "$tarball.sha256"
