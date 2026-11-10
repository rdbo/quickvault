#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Package a prebuilt native app under a disposable Android UID.

Default: validation build. --normal-ui selects the prebuilt regular native UI.
This script builds only; it never installs.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--normal-ui", action="store_true")
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
app = repo / "crates/qv-app"
source = app / "dist/android-project"
baseline = app / ("dist/quickvault-debug.apk" if args.normal_ui else "dist/quickvault-validation-debug.apk")
if not baseline.is_file():
    raise SystemExit("Build the selected current APK first")
work = Path(tempfile.mkdtemp(prefix="qv-0048-android-", dir="/var/tmp"))
project = work / "project"
shutil.copytree(source, project, ignore=shutil.ignore_patterns("build", ".gradle"))
if args.normal_ui:
    # Reuse the exact compiled regular UI; do not infer feature parity from a
    # validation build. Keep resources/JNI names from the generated project.
    with zipfile.ZipFile(baseline) as archive:
        for name in archive.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                relative = Path(name).relative_to("lib")
                if ".." in relative.parts:
                    raise SystemExit("Unexpected native library path")
                destination = project / "app/src/main/jniLibs" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(name))
build = project / "app/build.gradle.kts"
text = build.read_text()
old = 'applicationId = "org.quickvault.app"'
if text.count(old) != 1:
    raise SystemExit("Unexpected application ID template; review before packaging")
build.write_text(text.replace(old, 'applicationId = "org.quickvault.validation48"'))
# Keep namespace, resources, JNI class names and the compiled native library.
# Only the instrumentation Intent's target package differs.
tests = project / "app/src/androidTest/java/org/quickvault/app"
for java in tests.glob("*.java"):
    java.write_text(java.read_text().replace('"org.quickvault.app"', '"org.quickvault.validation48"'))
# A focused current-UI check. The original PlatformTest remains in the APK and
# its full-flow failure remains open; this method does not claim that coverage.
(tests / "IsolatedBoundaryTest.java").write_text('''// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;
import android.app.Instrumentation;
import android.content.Intent;
import android.webkit.WebView;
import dev.dioxus.main.MainActivity;
public class IsolatedBoundaryTest extends PlatformTest {
    public void testIsolatedWindowInputAndLifecycleBoundary() throws Exception {
        Instrumentation ins=getInstrumentation();
        assertEquals("Separate synthetic UID", "org.quickvault.validation48", ins.getTargetContext().getPackageName());
        Intent intent=new Intent().setClassName("org.quickvault.validation48", "dev.dioxus.main.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        MainActivity main=(MainActivity)ins.startActivitySync(intent);
        ins.runOnMainSync(()->main.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        try {
            long deadline=System.currentTimeMillis()+15000;
            while((main.qvStatus()&8)==0 && System.currentTimeMillis()<deadline)Thread.sleep(100);
            assertEquals("Unlocked test phone",2,main.qvStatus()&2);
            assertEquals("Secure window",4,main.qvStatus()&4);
            assertEquals("Hardened native webview",8,main.qvStatus()&8);
            WebView[] found=new WebView[1];
            ins.runOnMainSync(()->found[0]=find(main.getWindow().getDecorView()));
            assertNotNull(found[0]); WebView view=found[0];
            ins.runOnMainSync(()->{
                assertFalse(view.getSettings().getAllowFileAccess());
                assertFalse(view.getSettings().getAllowContentAccess());
                assertFalse(view.getSettings().getJavaScriptCanOpenWindowsAutomatically());
                assertFalse(view.getSettings().getDomStorageEnabled());
            });
            awaitJs(ins,view,"!!document.querySelector('#welcome-create') && document.body.textContent.includes('Synthetic validation build')","isolated empty welcome");
            js(ins,view,"document.querySelector('#welcome-create').click()");
            awaitJs(ins,view,"!!document.querySelector('#create-submit') && !!document.querySelector('#password')","create input");
            assertEquals("true",js(ins,view,"(()=>{try{eval('1');return false}catch(e){return true}})()"));
            assertEquals("true",js(ins,view,"(()=>{let s=document.createElement('script');s.textContent='window.inlineBad=true';document.body.append(s);return !window.inlineBad})()"));
            assertEquals("true",js(ins,view,"document.querySelector('#password').autocomplete==='off'"));
            js(ins,view,"(()=>{const el=document.querySelector('#password');el.value='synthetic-input';el.dispatchEvent(new Event('input',{bubbles:true}))})()");
            long generation=main.qvGeneration();
            ins.runOnMainSync(()->ins.callActivityOnPause(main));Thread.sleep(500);
            assertEquals("Background metadata",0,main.qvStatus()&1);
            ins.runOnMainSync(()->ins.callActivityOnResume(main));
            assertTrue("Pause generation",main.qvGeneration()>generation);
            awaitJs(ins,view,"Array.from(document.querySelectorAll('input')).every(i=>i.type==='checkbox'||i.type==='radio'?!i.checked:!i.value)","input and consent cleanup");
            assertEquals("No vault opened","true",js(ins,view,"!document.querySelector('.shell')"));
        } finally {ins.runOnMainSync(()->main.getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));}
    }
}
''')
if args.normal_ui:
    boundary = tests / "IsolatedBoundaryTest.java"
    text = boundary.read_text().replace(
        " && document.body.textContent.includes('Synthetic validation build')", "")
    marker = '            assertEquals("true",js(ins,view,"document.querySelector(\'#password\').autocomplete===\'off\'"));\n'
    if text.count(marker) != 1:
        raise SystemExit("Normal-UI assertion insertion point changed")
    assertion = '            assertEquals("No raw vault path control in regular UI","true",js(ins,view,"!document.querySelector(\'#vault-path\') && !document.body.textContent.includes(\'Vault file (full path)\')"));\n'
    boundary.write_text(text.replace(marker, marker + assertion))
env = os.environ.copy()
env["GRADLE_USER_HOME"] = str(app / "dist/.build-cache/gradle")
env["ANDROID_USER_HOME"] = str(app / "dist/.build-cache/android-user")
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
        return {name: hashlib.sha256(archive.read(name)).hexdigest()
                for name in archive.namelist() if name.startswith("lib/") and name.endswith(".so")}


native = native_hashes(apk)
if not native or native != native_hashes(baseline):
    raise SystemExit("Native library differs from the selected baseline APK; refusing qualification")
aapt = str(Path(env["ANDROID_HOME"]) / "build-tools/35.0.0/aapt")
badging = subprocess.check_output([aapt, "dump", "badging", str(apk)], text=True)
if "package: name='org.quickvault.validation48'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit("Unexpected isolated package identity/baseline")
(work / "apk-badging.txt").write_text(badging)
for path in [apk, test_apk]:
    print(hashlib.file_digest(path.open("rb"), "sha256").hexdigest(), path, flush=True)
print(f"Native .so bytes match the {'regular' if args.normal_ui else 'validation'} baseline; no install performed.", flush=True)
