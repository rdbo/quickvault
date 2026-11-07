#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build and inspect only; this script never connects to or installs on a phone.
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$app_dir"
# Keep tooling caches and the debug signing key out of read-only user homes.
qv_cache=${QV_APP_BUILD_CACHE:-$app_dir/dist/.build-cache}
mkdir -p "$qv_cache"
export DX_HOME=${DX_HOME:-$qv_cache/dx}
export GRADLE_USER_HOME=${GRADLE_USER_HOME:-$qv_cache/gradle}
export ANDROID_USER_HOME=${QV_ANDROID_USER_HOME:-$qv_cache/android-user}
qv_dx=${QV_DX:-dx}
case "$("$qv_dx" --version)" in
    'dioxus 0.7.10'*) ;;
    *) echo 'Use the pinned Dioxus CLI 0.7.10 (QV_DX selects its path).' >&2; exit 1 ;;
esac
: "${ANDROID_HOME:?Source scripts/setup-android.sh --print-env first}"
: "${JAVA_HOME:?Select a supported JDK (validated with JDK 21)}"
qv_features=mobile
qv_artifact=quickvault
if [ "${QV_APP_DEVICE_VALIDATION:-0}" = 1 ]; then
    qv_features=mobile,validation
    qv_artifact=quickvault-validation
fi
export QV_APP_BUILT_APK="dist/$qv_artifact-debug.apk"
"$qv_dx" build --platform android --target aarch64-linux-android --release \
    --features "$qv_features" --package qv-app --bin quickvault --cargo-args=--locked
# Dioxus 0.7.10 uses android_min_sdk_version for native linking but hardcodes
# minSdk=24 in Gradle. Copy its generated package and enforce the baseline in
# the APK as well, without patching the framework or its registry source.
qv_project=$(python3 - <<'PY'
from pathlib import Path
import shutil,time,re,os
root=Path.cwd()
source=root.parent.parent/'target/dx/quickvault/release/android/app'
# One reusable generated copy; earlier timestamped copies are not created.
destination=root/'dist'/'android-project'
if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
    raise SystemExit('Unexpected android-project path')
if destination.exists():
    shutil.rmtree(destination)
shutil.copytree(source,destination,ignore=shutil.ignore_patterns('build','.gradle'))
p=destination/'app/build.gradle.kts'
s=p.read_text()
if len(re.findall(r"minSdk = (?:24|29)\b",s))!=1:
    raise SystemExit('Unexpected upstream minSdk template; review it before packaging')
s=re.sub(r'minSdk = (?:24|29)\b','minSdk = 29',s,count=1)
s=s.replace('android {','android {\n    useLibrary("android.test.runner")\n    useLibrary("android.test.base")\n    useLibrary("android.test.mock")',1)
s=s.replace('defaultConfig {','defaultConfig {\n        testInstrumentationRunner = "android.test.InstrumentationTestRunner"',1)
p.write_text(s)
# Plan 0040: the shared CSS follows the OS light/dark setting. A Light parent
# theme makes the WebView report light always; DayNight follows the system.
# No WebView force-dark (it would recolour the app's own dark palette).
styles=destination/'app/src/main/res/values/styles.xml'
s=styles.read_text()
if s.count('Theme.AppCompat.Light.NoActionBar')!=1:
    raise SystemExit('Unexpected upstream AppTheme template; review it before packaging')
styles.write_text(s.replace('Theme.AppCompat.Light.NoActionBar','Theme.AppCompat.DayNight.NoActionBar'))
tests=destination/'app/src/androidTest/java/org/quickvault/app'
tests.mkdir(parents=True)
shutil.copyfile(root/'android/tests/PlatformTest.java',tests/'PlatformTest.java')
shutil.copyfile(root/'android/tests/QuickUnlockTest.java',tests/'QuickUnlockTest.java')
shutil.copyfile(root/'android/tests/QuickUnlockUiTest.java',tests/'QuickUnlockUiTest.java')
fixture_assets=destination/'app/src/androidTest/assets'
fixture_assets.mkdir(parents=True)
shutil.copyfile(root/'android/tests/flows.js',fixture_assets/'flows.js')
shutil.copyfile(root/'android/tests/AndroidManifest.xml',destination/'app/src/androidTest/AndroidManifest.xml')
# Preserve the framework's required loopback transport exception, explicitly
# disallowing cleartext to remote hosts. The custom manifest references it.
shutil.copyfile(root/'android/network_security_config.xml',
                destination/'app/src/main/res/xml/network_security_config.xml')
# The launcher icon from LOGO.svg (plan 0043), replacing the template's
# adaptive icon files in place; refuse a changed template layout.
res=destination/'app/src/main/res'
icons={'mipmap-anydpi-v26/ic_launcher.xml':'ic_launcher.xml',
       'drawable/ic_launcher_background.xml':'ic_launcher_background.xml',
       'drawable-v24/ic_launcher_foreground.xml':'ic_launcher_foreground.xml'}
for target,name in icons.items():
    if not (res/target).is_file():
        raise SystemExit('Unexpected upstream launcher icon template; review it before packaging')
    shutil.copyfile(root/'android/res'/name,res/target)
# Autofill gate (plan 0034): only the marked validation build opens it.
main_activity=destination/'app/src/main/kotlin/dev/dioxus/main/MainActivity.kt'
source=main_activity.read_text()
if source.count('const val VALIDATION = false')!=1:
    raise SystemExit('Unexpected autofill gate source')
if os.environ.get('QV_APP_DEVICE_VALIDATION')=='1':
    main_activity.write_text(source.replace('const val VALIDATION = false','const val VALIDATION = true'))
if source.count('const val QR_CAMERA = true')!=1:
    raise SystemExit('Unexpected QR camera source')
# QR camera scanning (0009 §1.7) is on in every package by default (owner
# decision 2026-11-07, plan 0043). QV_APP_QR_CAMERA=0 builds an ordinary
# package without it; validation packages always keep it.
if os.environ.get('QV_APP_QR_CAMERA')=='0' and os.environ.get('QV_APP_DEVICE_VALIDATION')!='1':
    main_activity.write_text(main_activity.read_text().replace('const val QR_CAMERA = true','const val QR_CAMERA = false'))
shutil.copyfile(root/'android/tests/QrTest.java',tests/'QrTest.java')
shutil.copyfile(root/'android/tests/AutofillTest.java',tests/'AutofillTest.java')
print(destination)
PY
)
sh "$qv_project/gradlew" -p "$qv_project" :app:assembleDebug :app:assembleDebugAndroidTest --no-daemon
cp "$qv_project/app/build/outputs/apk/debug/app-debug.apk" "dist/$qv_artifact-debug.apk"
cp "$qv_project/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" "dist/$qv_artifact-tests.apk"
"$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "dist/$qv_artifact-debug.apk" > dist/apk-badging.txt
"$ANDROID_HOME/build-tools/35.0.0/aapt" dump permissions "dist/$qv_artifact-debug.apk" > dist/apk-permissions.txt
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
import hashlib,os
badging=Path('dist/apk-badging.txt').read_text()
permissions=Path('dist/apk-permissions.txt').read_text()
if "package: name='org.quickvault.app'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit('Unexpected package or minimum SDK')
for line in permissions.splitlines():
    if line.startswith('uses-permission:') and not any(allowed in line for allowed in (
        "name='org.quickvault.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'",
        "name='android.permission.USE_BIOMETRIC'",
        "name='android.permission.CAMERA'",  # explicit QR scan action only
        "name='android.permission.INTERNET'",  # Dioxus loopback UI transport
    )):
        raise SystemExit('Unexpected requested permission; inspect before installing')
manifest=ET.parse('android/AndroidManifest.xml')
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
if os.environ.get('QV_APP_QR_CAMERA')=='0' and os.environ.get('QV_APP_DEVICE_VALIDATION')!='1':
    print('QR camera: OFF in this package (QV_APP_QR_CAMERA=0).')
else:
    print('QR camera: on.')
print('Built only. Inspect the final manifest/signature before any device install.')
PY
