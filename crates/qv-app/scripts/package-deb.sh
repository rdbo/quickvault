#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the Debian package (plan 0056): quickvault (the desktop app) and qv
# (the CLI) with the desktop entry and icons, as target/dist/
# quickvault_<version>_<arch>.deb. Meant for a clean Debian container (the
# release workflow uses debian:12): it installs the build dependencies and
# the pinned toolchain. Unsigned (0012 §3): install with
# `sudo apt install ./quickvault_<version>_<arch>.deb`.
set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config \
    libgtk-3-dev libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev libssl-dev \
    dpkg-dev
if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal
fi
PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install
# The app's page (plan 0071), embedded into quickvault at compile time.
sh crates/qv-ui/setup-tools.sh
sh crates/qv-ui/build.sh

cargo build --release --locked -p qv-cli --bin qv
cargo build --release --locked -p qv-app --features desktop --bin quickvault

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$version" ] || { echo 'cannot read the workspace version' >&2; exit 1; }
# A pre-release (1.0.0-rc.1) becomes 1.0.0~rc.1, which Debian sorts before 1.0.0.
version=$(printf '%s' "$version" | sed 's/-/~/')
arch=$(dpkg --print-architecture)
stage="$root/target/deb/quickvault"
rm -rf "$root/target/deb"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/applications" \
    "$stage/usr/share/icons/hicolor/256x256/apps" "$stage/usr/share/icons/hicolor/scalable/apps" \
    "$stage/usr/share/doc/quickvault"

install -m 0755 -s target/release/quickvault target/release/qv "$stage/usr/bin/"
install -m 0644 crates/qv-app/linux/org.quickvault.QuickVault.desktop "$stage/usr/share/applications/"
install -m 0644 crates/qv-app/assets/icon-256.png \
    "$stage/usr/share/icons/hicolor/256x256/apps/org.quickvault.QuickVault.png"
install -m 0644 docs/logo/logo.svg \
    "$stage/usr/share/icons/hicolor/scalable/apps/org.quickvault.QuickVault.svg"
install -m 0644 LICENSE "$stage/usr/share/doc/quickvault/copyright"

# Runtime dependencies from the binaries' linked libraries.
mkdir -p "$root/target/deb/debian"
printf 'Source: quickvault\n\nPackage: quickvault\nArchitecture: %s\n' "$arch" > "$root/target/deb/debian/control"
# Keep diagnostics visible and check dpkg-shlibdeps before filtering its output:
# a POSIX shell pipeline would otherwise report only sed's exit status.
depends=$(cd "$root/target/deb" && dpkg-shlibdeps -O "quickvault/usr/bin/quickvault" "quickvault/usr/bin/qv")
depends=$(printf '%s\n' "$depends" | sed -n 's/^shlibs:Depends=//p')
[ -n "$depends" ] || { echo 'cannot work out the package dependencies' >&2; exit 1; }
size=$(du -sk "$stage/usr" | cut -f1)
cat > "$stage/DEBIAN/control" <<CONTROL
Package: quickvault
Version: $version
Architecture: $arch
Maintainer: QuickVault <noreply@quickvault.invalid>
Installed-Size: $size
Depends: $depends
Section: utils
Priority: optional
Description: Offline-first, end-to-end encrypted password manager
 QuickVault keeps passwords and notes in an encrypted vault on this device,
 with optional sync over the local network. Includes the desktop app
 (quickvault) and the command-line client (qv).
CONTROL

mkdir -p "$root/target/dist"
out="$root/target/dist/quickvault_${version}_${arch}.deb"
dpkg-deb --root-owner-group --build "$stage" "$out"
echo "Built $out"
