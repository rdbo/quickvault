#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Exercise checker rejection without changing the real repository index/tree.
set -eu

checker=$(pwd)/scripts/check-spdx.sh
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/third-party/x11rb" "$fixture/third-party/other"
cat > "$fixture/bin/git" <<'EOF'
#!/bin/sh
printf '%s\n' "$QV_SPDX_TEST_FILES"
EOF
chmod +x "$fixture/bin/git"
PATH=$fixture/bin:$PATH
export PATH
cd "$fixture"

check() {
    expected=$1
    QV_SPDX_TEST_FILES=$2
    export QV_SPDX_TEST_FILES
    if sh "$checker" > result.log 2>&1; then
        actual=0
    else
        actual=1
    fi
    if [ "$actual" != "$expected" ]; then
        cat result.log
        echo "unexpected checker result: expected $expected, got $actual"
        exit 1
    fi
}

printf 'fn main() {}\n' > product.rs
check 1 product.rs
printf '// SPDX-License-Identifier: AGPL-3.0-or-later\n' > product.rs
check 0 product.rs
printf '// Upstream header\n' > third-party/x11rb/lib.rs
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
printf '%s\n' 9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414 > third-party/x11rb/UPSTREAM.sha256
check 0 third-party/x11rb/lib.rs
printf '[package]\nname = "other"\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0.13.3"\n[dependencies.protocol]\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0x13x2"\n' > third-party/x11rb/Cargo.toml
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
printf 'wrong-hash\n' > third-party/x11rb/UPSTREAM.sha256
check 1 third-party/x11rb/lib.rs
printf '// Upstream header\n' > third-party/other/lib.rs
check 1 third-party/other/lib.rs
printf 'fn main() {}\n' > product.rs
check 1 product.rs
mkdir -p third-party/dioxus-desktop
printf '// Upstream header\n' > third-party/dioxus-desktop/lib.rs
printf '[package]\nname = "dioxus-desktop"\nversion = "0.7.10"\n' > third-party/dioxus-desktop/Cargo.toml
printf '236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d\n' > third-party/dioxus-desktop/UPSTREAM.sha256
check 0 third-party/dioxus-desktop/lib.rs
printf 'wrong-hash\n' > third-party/dioxus-desktop/UPSTREAM.sha256
check 1 third-party/dioxus-desktop/lib.rs
mkdir -p third-party/glib
printf '// Upstream header\n' > third-party/glib/lib.rs
printf '[package]\nname = "glib"\nversion = "0.18.5"\n' > third-party/glib/Cargo.toml
printf '233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5\n' > third-party/glib/UPSTREAM.sha256
check 0 third-party/glib/lib.rs
printf 'wrong-hash\n' > third-party/glib/UPSTREAM.sha256
check 1 third-party/glib/lib.rs
mkdir -p third-party/glib-macros
printf '// Upstream header\n' > third-party/glib-macros/lib.rs
printf '[package]\nname = "glib-macros"\nversion = "0.18.5"\n' > third-party/glib-macros/Cargo.toml
printf '0bb0228f477c0900c880fd78c8759b95c7636dbd7842707f49e132378aa2acdc\n' > third-party/glib-macros/UPSTREAM.sha256
check 0 third-party/glib-macros/lib.rs
printf 'wrong-hash\n' > third-party/glib-macros/UPSTREAM.sha256
check 1 third-party/glib-macros/lib.rs
mkdir -p third-party/gtk3-macros
printf '// Upstream header\n' > third-party/gtk3-macros/lib.rs
printf '[package]\nname = "gtk3-macros"\nversion = "0.18.2"\n' > third-party/gtk3-macros/Cargo.toml
printf '52ff3c5b21f14f0736fed6dcfc0bfb4225ebf5725f3c0209edeec181e4d73e9d\n' > third-party/gtk3-macros/UPSTREAM.sha256
check 0 third-party/gtk3-macros/lib.rs
printf 'wrong-hash\n' > third-party/gtk3-macros/UPSTREAM.sha256
check 1 third-party/gtk3-macros/lib.rs
mkdir -p third-party/selectors
printf '// Upstream header\n' > third-party/selectors/lib.rs
printf '[package]\nname = "selectors"\nversion = "0.24.0"\n' > third-party/selectors/Cargo.toml
printf '0c37578180969d00692904465fb7f6b3d50b9a2b952b87c23d0e2e5cb5013416\n' > third-party/selectors/UPSTREAM.sha256
check 0 third-party/selectors/lib.rs
printf 'wrong-hash\n' > third-party/selectors/UPSTREAM.sha256
check 1 third-party/selectors/lib.rs
printf 'SPDX checker rejection tests passed\n'
