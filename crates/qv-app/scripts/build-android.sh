#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build and inspect only; this script never connects to or installs on a phone.
#
# The Android project is crates/qv-app/gen/android (Tauri 2, plan 0071). The
# page is built first (crates/qv-ui/build.sh), then the pinned tauri-cli
# builds the Rust library and the APK through Gradle.
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repo=$(CDPATH= cd -- "$app_dir/../.." && pwd)
cd "$app_dir"
# Keep tooling caches and the debug signing key out of read-only user homes.
qv_cache=${QV_APP_BUILD_CACHE:-$app_dir/dist/.build-cache}
mkdir -p "$qv_cache" dist
export GRADLE_USER_HOME=${GRADLE_USER_HOME:-$qv_cache/gradle}
export ANDROID_USER_HOME=${QV_ANDROID_USER_HOME:-$qv_cache/android-user}
export GRADLE_OPTS="${GRADLE_OPTS:-} -Duser.home=$ANDROID_USER_HOME"
mkdir -p "$ANDROID_USER_HOME"
qv_tauri=${QV_TAURI:-cargo-tauri}
case "$("$qv_tauri" --version)" in
    'tauri-cli 2.12.4'*) ;;
    *) echo 'Use the pinned tauri-cli 2.12.4 (QV_TAURI selects its path).' >&2; exit 1 ;;
esac
: "${ANDROID_HOME:?Source scripts/setup-android.sh --print-env first}"
# tauri-cli reads NDK_HOME; scripts/setup-android.sh exports ANDROID_NDK_HOME.
export NDK_HOME="${NDK_HOME:-${ANDROID_NDK_HOME:-}}"
: "${NDK_HOME:?Source scripts/setup-android.sh --print-env first}"
: "${JAVA_HOME:?Select a supported JDK (validated with JDK 21)}"
qv_features=mobile
qv_artifact=quickvault
if [ "${QV_APP_DEVICE_VALIDATION:-0}" = 1 ]; then
    qv_features=mobile,validation
    qv_artifact=quickvault-validation
fi
# QV_APP_RELEASE=1 builds the non-debuggable release APK (plan 0056) and signs
# it with the owner's keystore: QV_ANDROID_KEYSTORE (path) and
# QV_ANDROID_KEY_ALIAS. apksigner prompts for the password unless
# QV_ANDROID_KS_PASS names an apksigner password source (for example
# `file:/path` or `env:VAR`). Published APKs use the one stable project key
# kept in the CI secrets (docs/RELEASE.md); never a key in the repository.
qv_release=${QV_APP_RELEASE:-0}
if [ "$qv_release" = 1 ]; then
    if [ "${QV_APP_DEVICE_VALIDATION:-0}" = 1 ] || [ "${QV_APP_MEDIA_VALIDATION:-0}" = 1 ]; then
        echo 'A release APK never includes validation features.' >&2
        exit 1
    fi
    : "${QV_ANDROID_KEYSTORE:?Set QV_ANDROID_KEYSTORE to the owner release keystore}"
    : "${QV_ANDROID_KEY_ALIAS:?Set QV_ANDROID_KEY_ALIAS to the release key alias}"
    [ -f "$QV_ANDROID_KEYSTORE" ] || { echo 'QV_ANDROID_KEYSTORE is not a file' >&2; exit 1; }
    export QV_APP_BUILT_APK="dist/$qv_artifact-release.apk"
else
    export QV_APP_BUILT_APK="dist/$qv_artifact-debug.apk"
fi
# The version code follows the workspace version: major*10000 + minor*100 +
# patch (plan 0069; 1.0.0 shipped as 1), so installers accept each update.
qv_version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)"$/\1 \2 \3/p' "$repo/Cargo.toml")
set -- $qv_version
[ $# = 3 ] || { echo 'No workspace version in Cargo.toml' >&2; exit 1; }
if [ "$2" -gt 99 ] || [ "$3" -gt 99 ] || [ "$1" -lt 1 ] || [ "$1" -gt 20000 ]; then
    echo 'Workspace version does not fit the Android version code' >&2
    exit 1
fi
qv_code=$(($1 * 10000 + $2 * 100 + $3))
qv_name="$1.$2.$3"
# QR camera scanning (0009 §1.7) is on in every package by default (owner
# decision 2026-11-07, plan 0043). QV_APP_QR_CAMERA=0 builds an ordinary
# package without it; validation packages always keep it.
qv_qr=true
if [ "${QV_APP_QR_CAMERA:-1}" = 0 ] && [ "${QV_APP_DEVICE_VALIDATION:-0}" != 1 ]; then
    qv_qr=false
fi
export ORG_GRADLE_PROJECT_qvQrCamera=$qv_qr
# The page, embedded into the library at compile time.
QV_UI_PROFILE=wasm sh "$repo/crates/qv-ui/build.sh"
qv_config="{\"version\":\"$qv_name\",\"bundle\":{\"android\":{\"versionCode\":$qv_code}}}"
qv_flavor="$app_dir/gen/android/app/build/outputs/apk/universal"
qv_tools="$ANDROID_HOME/build-tools/35.0.0"
if [ "$qv_release" = 1 ]; then
    "$qv_tauri" android build --ci --apk --target aarch64 --features "$qv_features" --config "$qv_config"
    qv_unsigned="$qv_flavor/release/app-universal-release-unsigned.apk"
    rm -f "$QV_APP_BUILT_APK"
    "$qv_tools/zipalign" -p -f 4 "$qv_unsigned" "$QV_APP_BUILT_APK.aligned"
    # shellcheck disable=SC2086 # the optional password source is one word
    "$qv_tools/apksigner" sign --ks "$QV_ANDROID_KEYSTORE" --ks-key-alias "$QV_ANDROID_KEY_ALIAS" \
        ${QV_ANDROID_KS_PASS:+--ks-pass "$QV_ANDROID_KS_PASS"} \
        --out "$QV_APP_BUILT_APK" "$QV_APP_BUILT_APK.aligned"
    rm -f "$QV_APP_BUILT_APK.aligned"
    "$qv_tools/apksigner" verify --print-certs "$QV_APP_BUILT_APK" > dist/apk-certs.txt
    if "$qv_tools/aapt" dump xmltree "$QV_APP_BUILT_APK" AndroidManifest.xml | grep -q 'android:debuggable([^)]*)=(type 0x12)0xffffffff'; then
        echo 'The release APK is debuggable; refusing it.' >&2
        rm -f "$QV_APP_BUILT_APK"
        exit 1
    fi
else
    # A debug package with optimized Rust: unoptimized Argon2id and decoding
    # make the app unusably slow on a phone.
    CARGO_PROFILE_DEV_OPT_LEVEL=2 CARGO_PROFILE_DEV_DEBUG=false \
        "$qv_tauri" android build --ci --apk --debug --target aarch64 --features "$qv_features" --config "$qv_config"
    # The instrumentation package, against the library just built.
    sh gen/android/gradlew -p gen/android :app:assembleUniversalDebugAndroidTest --no-daemon \
        -PabiList=arm64-v8a -ParchList=arm64 -PtargetList=aarch64 -x rustBuildUniversalDebug
    cp "$qv_flavor/debug/app-universal-debug.apk" "$QV_APP_BUILT_APK"
    cp "$app_dir/gen/android/app/build/outputs/apk/androidTest/universal/debug/app-universal-debug-androidTest.apk" \
        "dist/$qv_artifact-tests.apk"
fi
"$qv_tools/aapt" dump badging "$QV_APP_BUILT_APK" > dist/apk-badging.txt
"$qv_tools/aapt" dump permissions "$QV_APP_BUILT_APK" > dist/apk-permissions.txt
QV_CODE=$qv_code QV_NAME=$qv_name QV_QR=$qv_qr python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
import hashlib,os
badging=Path('dist/apk-badging.txt').read_text()
permissions=Path('dist/apk-permissions.txt').read_text()
if "package: name='org.quickvault.app'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit('Unexpected package or minimum SDK')
if f"versionCode='{os.environ['QV_CODE']}' versionName='{os.environ['QV_NAME']}'" not in badging:
    raise SystemExit('The APK does not carry the workspace version code')
for line in permissions.splitlines():
    if line.startswith('uses-permission:') and not any(allowed in line for allowed in (
        "name='org.quickvault.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'",
        "name='android.permission.USE_BIOMETRIC'",
        "name='android.permission.CAMERA'",  # explicit QR scan action only
        "name='android.permission.INTERNET'",  # explicit LAN sync actions only
    )):
        raise SystemExit('Unexpected requested permission; inspect before installing')
manifest=ET.parse('gen/android/app/src/main/AndroidManifest.xml')
ns='{http://schemas.android.com/apk/res/android}'
for feature in ('android.hardware.camera.any','android.hardware.camera','android.hardware.camera.autofocus'):
    declared=[f for f in manifest.findall('uses-feature') if f.get(ns+'name')==feature]
    if len(declared)!=1 or declared[0].get(ns+'required')!='false':
        raise SystemExit('Camera and autofocus must remain optional')
    if "uses-feature: name='"+feature+"'" in badging:
        raise SystemExit('Final package unexpectedly requires camera hardware')
app=manifest.find('application')
if app is None or app.get(ns+'allowBackup')!='false':
    raise SystemExit('Backup policy is not disabled')
if app.get(ns+'usesCleartextTraffic')!='false':
    raise SystemExit('Cleartext traffic must stay disabled')
auth=[a for a in app.findall('activity') if a.get(ns+'name')=='dev.dioxus.main.AutofillAuthActivity']
if len(auth)!=1 or auth[0].get(ns+'exported')!='false':
    raise SystemExit('Autofill handoff activity must exist and stay non-exported')
service=[s for s in app.findall('service') if s.get(ns+'name')=='dev.dioxus.main.QvAutofillService']
if len(service)!=1 or service[0].get(ns+'permission')!='android.permission.BIND_AUTOFILL_SERVICE':
    raise SystemExit('Autofill service must be bindable only by the system')
main=[a for a in app.findall('activity') if a.get(ns+'name')=='dev.dioxus.main.MainActivity']
if len(main)!=1 or main[0].get(ns+'launchMode')!='singleTask':
    raise SystemExit('The Rust-bridged activity must stay single-instance')
p=Path(os.environ['QV_APP_BUILT_APK'])
print('APK SHA-256:',hashlib.sha256(p.read_bytes()).hexdigest())
if os.environ['QV_QR']=='false':
    print('QR camera: OFF in this package (QV_APP_QR_CAMERA=0).')
else:
    print('QR camera: on.')
print('Built only. Inspect the final manifest/signature before any device install.')
PY
