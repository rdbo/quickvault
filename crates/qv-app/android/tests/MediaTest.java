// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.app.Instrumentation;
import android.content.Intent;
import dev.dioxus.main.MainActivity;

/** Bounded synthetic native media flow; requires the dedicated media APK. */
@SuppressWarnings("deprecation")
public final class MediaTest extends PlatformTest {
    public void testSyntheticMediaPlaybackSeekConsentAndRevocation() throws Exception {
        Instrumentation os=getInstrumentation();
        assertEquals("Dedicated disposable UID", "org.quickvault.validation50", os.getTargetContext().getPackageName());
        java.io.File fixture=new java.io.File(os.getTargetContext().getNoBackupFilesDir(),"quickvault/validation-current");
        assertFalse("Only a fresh isolated fixture may be used", fixture.exists());
        Intent intent=new Intent().setClassName("org.quickvault.validation50","dev.dioxus.main.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        MainActivity activity=(MainActivity)os.startActivitySync(intent);
        os.runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        try {
            java.io.File result=new java.io.File(fixture,"media-result");
            long deadline=android.os.SystemClock.elapsedRealtime()+180000;
            while(!result.isFile() && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
            assertTrue("Native media flow completed within deadline", result.isFile());
            assertTrue("Fixed result length", result.length()==4);
            assertEquals("Playback, seeking, image consent, close and lock revocation", "PASS", new String(java.nio.file.Files.readAllBytes(result.toPath()),java.nio.charset.StandardCharsets.US_ASCII));
            assertFalse("Synthetic vault removed after lock", new java.io.File(fixture,"media-fixture").exists());
        } finally {
            os.runOnMainSync(()->activity.getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
            os.runOnMainSync(activity::finish);
            if(fixture.exists())removeFixture(fixture,fixture);
        }
    }
}
