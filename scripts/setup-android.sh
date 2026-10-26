#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Installs the Android SDK and NDK for QuickVault's Android builds (roadmap
# phase 1.9 on), and the Rust Android targets for the pinned toolchain.
#
#   sh scripts/setup-android.sh [--accept-licenses]
#   sh scripts/setup-android.sh --print-env
#
# ANDROID_HOME selects the SDK directory. The default is $HOME/Android/Sdk,
# or .android-sdk/ in the repository (git-ignored) when $HOME is not
# writable, as in the agent sandbox. --print-env uses the same rule. The
# command-line tools archive is checked against the SHA-256 that Google
# publishes on developer.android.com/studio; sdkmanager verifies every
# package it installs against Google's repository index. Without
# --accept-licenses, sdkmanager asks you to accept each SDK licence.
# Running it again skips what is already installed.
#
# Needs: curl, unzip, sha256sum, Java 17 or later, rustup. On musl hosts
# (Alpine) the prebuilt SDK/NDK binaries also need glibc compatibility
# (`gcompat`).
#
# Supported device baseline: arm64, Android 10 (API 29) or later, at least
# 4 GB of RAM (spec 0009 §2).

set -eu

# Pinned versions (update together, deliberately).
CMDLINE_TOOLS_BUILD=15859902
CMDLINE_TOOLS_SHA256=4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583
PLATFORM="platforms;android-35"
BUILD_TOOLS="build-tools;35.0.0"
NDK_VERSION=27.3.13750724 # NDK r27, the long-term-support release
MIN_API=29                # Android 10, the supported baseline
RUST_TARGETS="aarch64-linux-android x86_64-linux-android"

repo=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${ANDROID_HOME:-}" ]; then
    if [ -d "$HOME/Android/Sdk" ] || { mkdir -p "$HOME/Android" 2>/dev/null && [ -w "$HOME/Android" ]; }; then
        ANDROID_HOME=$HOME/Android/Sdk
    else
        ANDROID_HOME=$repo/.android-sdk
    fi
fi
# The SDK tools keep caches and preferences in ~/.android; use the SDK
# directory instead when $HOME is read-only.
if [ -z "${ANDROID_USER_HOME:-}" ]; then
    if mkdir -p "$HOME/.android" 2>/dev/null && [ -w "$HOME/.android" ]; then
        ANDROID_USER_HOME=$HOME/.android
    else
        ANDROID_USER_HOME=$ANDROID_HOME/.android-user
    fi
fi
export ANDROID_USER_HOME
NDK_HOME=$ANDROID_HOME/ndk/$NDK_VERSION
SDKMANAGER=$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager

print_env() {
    prebuilt=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
    cat <<EOF
export ANDROID_HOME='$ANDROID_HOME'
export ANDROID_SDK_ROOT='$ANDROID_HOME'
export ANDROID_USER_HOME='$ANDROID_USER_HOME'
export ANDROID_NDK_HOME='$NDK_HOME'
export ANDROID_NDK_ROOT='$NDK_HOME'
export PATH="\$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin"
export CC_aarch64_linux_android='$prebuilt/aarch64-linux-android$MIN_API-clang'
export AR_aarch64_linux_android='$prebuilt/llvm-ar'
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER='$prebuilt/aarch64-linux-android$MIN_API-clang'
export CC_x86_64_linux_android='$prebuilt/x86_64-linux-android$MIN_API-clang'
export AR_x86_64_linux_android='$prebuilt/llvm-ar'
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER='$prebuilt/x86_64-linux-android$MIN_API-clang'
EOF
}

accept=0
case "${1:-}" in
--print-env) print_env; exit 0 ;;
--accept-licenses) accept=1 ;;
"") ;;
*) echo "usage: $0 [--accept-licenses | --print-env]" >&2; exit 2 ;;
esac

die() { echo "setup-android: $*" >&2; exit 1; }

for tool in curl unzip sha256sum java rustup; do
    command -v "$tool" >/dev/null 2>&1 || die "missing $tool"
done
java_major=$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -n 1)
[ "${java_major:-0}" -ge 17 ] || die "Java 17 or later is required (found ${java_major:-none})"
if [ -f /etc/alpine-release ] && [ ! -e /lib/ld-linux-x86-64.so.2 ]; then
    die "Alpine needs glibc compatibility for the SDK binaries: apk add gcompat"
fi

mkdir -p "$ANDROID_HOME" "$ANDROID_USER_HOME"

# 1. Command-line tools (sdkmanager).
if [ ! -x "$SDKMANAGER" ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    zip="$work/cmdline-tools.zip"
    echo "Downloading command-line tools $CMDLINE_TOOLS_BUILD..."
    curl -fSL --proto '=https' --tlsv1.2 -o "$zip" \
        "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip"
    echo "$CMDLINE_TOOLS_SHA256  $zip" | sha256sum -c - >/dev/null ||
        die "checksum mismatch for the command-line tools archive"
    mkdir -p "$work/unzip"
    unzip -q "$zip" -d "$work/unzip"
    [ -x "$work/unzip/cmdline-tools/bin/sdkmanager" ] || die "unexpected archive layout"
    mkdir -p "$ANDROID_HOME/cmdline-tools"
    rm -rf "$ANDROID_HOME/cmdline-tools/latest"
    mv "$work/unzip/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
fi

# 2. Licences and packages.
if [ "$accept" -eq 1 ]; then
    yes | "$SDKMANAGER" --sdk_root="$ANDROID_HOME" --licenses >/dev/null
else
    "$SDKMANAGER" --sdk_root="$ANDROID_HOME" --licenses
fi
echo "Installing platform-tools, $PLATFORM, $BUILD_TOOLS, ndk;$NDK_VERSION..."
"$SDKMANAGER" --sdk_root="$ANDROID_HOME" --install \
    "platform-tools" "$PLATFORM" "$BUILD_TOOLS" "ndk;$NDK_VERSION"

# 3. Rust targets for the pinned toolchain (run from the repository, so
# rust-toolchain.toml applies).
cd "$repo"
# shellcheck disable=SC2086 # a list of targets
rustup target add $RUST_TARGETS

# 4. The NDK compiler must run on this host.
"$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" --version >/dev/null ||
    die "the NDK compiler does not run on this host"

echo
echo "Done (SDK in $ANDROID_HOME). Add this to your environment, or run"
echo "eval \"\$(sh scripts/setup-android.sh --print-env)\":"
echo
print_env
