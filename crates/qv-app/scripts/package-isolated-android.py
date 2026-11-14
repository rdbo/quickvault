#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repackage a built APK under a disposable application ID; never install it.

The ordinary `org.quickvault.app` on a test phone may hold real data, so full
instrumentation runs use a separate UID with fresh app state (plans 0048-0050).
Build the selected baseline first with `build-android.sh`:

  ordinary    QV_APP_DEVICE_VALIDATION=0 QV_APP_MEDIA_VALIDATION=0 (default)
  validation  QV_APP_DEVICE_VALIDATION=1 (and QV_APP_MEDIA_VALIDATION=1 for media)

The script only rewrites the application ID and the instrumentation target,
rebuilds with Gradle and checks that the native libraries are byte-identical
to the baseline, plus the app/test identities. Install the printed pair with
`adb install -r -t` and remove it afterwards.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--baseline", choices=["ordinary", "validation"], default="ordinary")
parser.add_argument("--uid", default="org.quickvault.isolated",
                    help="disposable application ID (default: %(default)s)")
args = parser.parse_args()
if not re.fullmatch(r"org\.quickvault\.[a-z][a-z0-9]*", args.uid) or args.uid == "org.quickvault.app":
    raise SystemExit("--uid must be org.quickvault.<name>, not the ordinary app")
uid = args.uid
name = uid.rsplit(".", 1)[1]

app = Path(__file__).resolve().parents[1]
repo = app.parents[1]
baseline = app / ("dist/quickvault-debug.apk" if args.baseline == "ordinary"
                  else "dist/quickvault-validation-debug.apk")
if not baseline.is_file():
    raise SystemExit(f"Build the {args.baseline} APK first ({baseline} is missing)")
if "ANDROID_HOME" not in os.environ:
    raise SystemExit('Run eval "$(sh scripts/setup-android.sh --print-env)" first')
work = Path(tempfile.mkdtemp(prefix=f"qv-{name}-android-", dir="/var/tmp"))
project = work / "project"
shutil.copytree(app / "dist/android-project", project,
                ignore=shutil.ignore_patterns("build", ".gradle"))
build = project / "app/build.gradle.kts"
text = build.read_text()
old = 'applicationId = "org.quickvault.app"'
if text.count(old) != 1:
    raise SystemExit("Unexpected application ID template; review it before packaging")
build.write_text(text.replace(old, f'applicationId = "{uid}"'))
# Keep the namespace, resources, JNI class names and compiled native library;
# only the instrumentation target package differs. Test classes that pin a
# historical disposable ID (validation49 import, validation50 media) follow it.
historical = re.compile(r"org\.quickvault\.validation[0-9]+")
tests = project / "app/src/androidTest"
for path in [*(tests / "java/org/quickvault/app").glob("*.java"), tests / "AndroidManifest.xml"]:
    source = path.read_text()
    if path.suffix == ".java":
        source = source.replace('"org.quickvault.app"', f'"{uid}"')
    path.write_text(historical.sub(uid, source))
env = dict(os.environ, GRADLE_USER_HOME=str(app / "dist/.build-cache/gradle"),
           ANDROID_USER_HOME=str(app / "dist/.build-cache/android-user"))
with (work / "build.log").open("w") as log:
    result = subprocess.run(["sh", str(project / "gradlew"), "-p", str(project),
                             ":app:assembleDebug", ":app:assembleDebugAndroidTest", "--no-daemon"],
                            cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT)
if result.returncode:
    raise SystemExit(f"Build failed: {work / 'build.log'}")
apk = project / "app/build/outputs/apk/debug/app-debug.apk"
test_apk = project / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"


def native_hashes(path):
    with zipfile.ZipFile(path) as archive:
        return {entry: hashlib.sha256(archive.read(entry)).hexdigest()
                for entry in archive.namelist() if entry.startswith("lib/") and entry.endswith(".so")}


native = native_hashes(apk)
if not native or native != native_hashes(baseline):
    raise SystemExit(f"Native libraries differ from the {args.baseline} APK")
aapt = str(Path(env["ANDROID_HOME"]) / "build-tools/35.0.0/aapt")
badging = subprocess.check_output([aapt, "dump", "badging", str(apk)], text=True)
if f"package: name='{uid}'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit("Unexpected app identity/API baseline")
manifest = subprocess.check_output([aapt, "dump", "xmltree", str(test_apk), "AndroidManifest.xml"], text=True)
if (f'package="{uid}.test"' not in manifest
        or f'android:targetPackage(0x01010021)="{uid}"' not in manifest):
    raise SystemExit("Unexpected instrumentation identity/target")
if f"{uid}.test.vault-import" not in manifest:
    raise SystemExit("Unexpected fixture-provider authority")
main_manifest = subprocess.check_output([aapt, "dump", "xmltree", str(apk), "AndroidManifest.xml"], text=True)
if "VaultImportProvider" in main_manifest:
    raise SystemExit("Test provider leaked into the product APK")
(work / "app-badging.txt").write_text(badging)
(work / "test-manifest.txt").write_text(manifest)
for built, out in [(apk, f"quickvault-{name}-debug.apk"), (test_apk, f"quickvault-{name}-tests.apk")]:
    destination = app / "dist" / out
    shutil.copyfile(built, destination)
    with destination.open("rb") as data:
        print(hashlib.file_digest(data, "sha256").hexdigest(), destination, flush=True)
print(f"Native bytes match the {args.baseline} APK; no install performed.", work, flush=True)
print(f"Run: adb shell am instrument -w -r -e class org.quickvault.app.PlatformTest "
      f"{uid}.test/android.test.InstrumentationTestRunner", flush=True)
