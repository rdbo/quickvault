#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the Alpine package (plan 0056): quickvault (the desktop app) and qv
# (the CLI) with the desktop entry and icons, as target/dist/
# quickvault-<version>-r0-alpine-<branch>-<arch>.apk. Pass 3.22 (default) or
# edge inside the matching clean Alpine container: it installs the build
# dependencies and the pinned toolchain. abuild signs every package, so each
# build signs with a throwaway key made here and discarded; nobody can verify
# it, which matches the unsigned release policy (0012 §3). Install with
# `apk add --allow-untrusted ./quickvault-<version>-r0-alpine-<branch>-<arch>.apk`.
set -eu

usage() {
    echo 'usage: package-alpine.sh [3.22|edge]' >&2
    exit 2
}
[ "$#" -le 1 ] || usage
alpine_branch=${1-3.22}
case "$alpine_branch" in
    3.22|edge) ;;
    *) usage ;;
esac

root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"

apk add --no-cache build-base pkgconf curl bash abuild \
    gtk+3.0-dev webkit2gtk-4.1-dev xdotool-dev libayatana-appindicator-dev openssl-dev
if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal
fi
PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install
# musl targets link statically by default; the app needs the system GTK and
# WebKitGTK shared libraries.
export RUSTFLAGS="-C target-feature=-crt-static"
# The app's page (plan 0071), embedded into quickvault at compile time. The
# host flag above is for the native binaries, not the wasm32 page.
sh crates/qv-ui/setup-tools.sh
RUSTFLAGS= sh crates/qv-ui/build.sh

cargo build --release --locked -p qv-cli --bin qv
cargo build --release --locked -p qv-app --features desktop --bin quickvault

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$version" ] || { echo 'cannot read the workspace version' >&2; exit 1; }
# Alpine spells a pre-release 1.0.0_rc1 (from 1.0.0-rc.1).
version=$(printf '%s' "$version" | sed 's/-\([a-z]*\)\.\{0,1\}\([0-9]*\)$/_\1\2/')
arch=$(apk --print-arch)

# abuild runs (as root in the throwaway container, `-F`) from a directory of
# its own holding the APKBUILD and the built files.
work="$root/target/alpine"
rm -rf "$work"
mkdir -p "$work/files"
cp target/release/quickvault target/release/qv "$work/files/"
cp crates/qv-app/linux/org.quickvault.QuickVault.desktop crates/qv-app/assets/icon-256.png \
    docs/logo/logo.svg LICENSE "$work/files/"
cat > "$work/APKBUILD" <<APKBUILD
pkgname=quickvault
pkgver=$version
pkgrel=0
pkgdesc="Offline-first, end-to-end encrypted password manager"
url="https://quickvault.invalid"
arch="$arch"
license="AGPL-3.0-or-later"
options="!check"
source=""

package() {
	install -Dm755 "\$startdir/files/quickvault" "\$pkgdir/usr/bin/quickvault"
	install -Dm755 "\$startdir/files/qv" "\$pkgdir/usr/bin/qv"
	install -Dm644 "\$startdir/files/org.quickvault.QuickVault.desktop" \\
		"\$pkgdir/usr/share/applications/org.quickvault.QuickVault.desktop"
	install -Dm644 "\$startdir/files/icon-256.png" \\
		"\$pkgdir/usr/share/icons/hicolor/256x256/apps/org.quickvault.QuickVault.png"
	install -Dm644 "\$startdir/files/logo.svg" \\
		"\$pkgdir/usr/share/icons/hicolor/scalable/apps/org.quickvault.QuickVault.svg"
	install -Dm644 "\$startdir/files/LICENSE" "\$pkgdir/usr/share/licenses/quickvault/LICENSE"
}
APKBUILD

# Trust the throwaway public key inside this disposable build container so
# abuild can verify its package while generating the repository index.
# The container already runs as root; key installation needs no sudo/doas.
(cd "$work" && SUDO= abuild-keygen -a -i -n -q && abuild -F -P "$work/out")

pkg=$(find "$work/out" -name "quickvault-$version-r0.apk" | head -n 1)
[ -n "$pkg" ] || { echo 'abuild produced no package' >&2; exit 1; }
mkdir -p "$root/target/dist"
out="$root/target/dist/quickvault-$version-r0-alpine-$alpine_branch-$arch.apk"
cp "$pkg" "$out"
# The throwaway signing key goes with the container.
rm -rf "$HOME/.abuild"
echo "Built $out"
