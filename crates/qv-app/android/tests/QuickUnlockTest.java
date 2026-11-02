// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.app.Instrumentation;
import android.content.Intent;
import android.test.InstrumentationTestCase;
import dev.dioxus.main.MainActivity;
import java.util.Arrays;

/** Explicit interactive tests, separate from PlatformTest's automatic runner.
 * Synthetic bytes only. A human must authenticate each requested operation.
 */
@SuppressWarnings("deprecation")
public final class QuickUnlockTest extends InstrumentationTestCase {
    private MainActivity launch() throws Exception {
        Instrumentation os=getInstrumentation();
        MainActivity activity=(MainActivity)os.startActivitySync(new Intent().setClassName("org.quickvault.app","dev.dioxus.main.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        os.runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        long deadline=android.os.SystemClock.elapsedRealtime()+60000;
        while((activity.qvStatus()&15)!=15 && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
        assertEquals("Foreground, unlocked, hardened window required",15,activity.qvStatus()&15);
        // Initializes cleanup before creating any test handles.
        activity.qvQuickAvailable();
        return activity;
    }
    private int await(MainActivity activity,long id) throws Exception {
        assertTrue("Native operation accepted",id>0);
        long deadline=android.os.SystemClock.elapsedRealtime()+60000;
        int state;String previous="";
        while((state=activity.qvQuickState(id))==0 && android.os.SystemClock.elapsedRealtime()<deadline) {
            String evidence=activity.qvQuickEvidence(id);
            if(!evidence.equals(previous)){android.os.Bundle report=new android.os.Bundle();report.putString("qvQuickEvidence",evidence);getInstrumentation().sendStatus(0,report);previous=evidence;}
            Thread.sleep(100);
        }
        return activity.qvQuickState(id);
    }
    private byte[] operation(MainActivity activity,boolean encrypt,byte[] context,int policy,byte[] input) throws Exception {
        long id=activity.qvQuickStart(encrypt,context,policy,input.clone());
        boolean success=false;
        try {
            int state=await(activity,id);
            assertEquals("Hardware operation: "+activity.qvQuickEvidence(id),1,state);
            byte[] result=activity.qvQuickResult(id);
            assertNotNull("Bounded native result",result);
            assertTrue(result.length>0 && result.length<=(encrypt?1536:1024));
            byte[] copy=result.clone();success=true;return copy;
        } finally { activity.qvQuickFinish(id,success);Thread.sleep(1000); }
    }
    private void roundTrip(int policy) throws Exception {
        MainActivity activity=launch();
        byte[] context=new byte[36];context[19]=1;
        byte[] plain="synthetic hardware wrapping canary".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] envelope=null;
        try {
            envelope=operation(activity,true,context,policy,plain);
            assertEquals(1,envelope[0]);assertEquals(1,envelope[1]);assertEquals(policy,envelope[2]);
            byte[] out=operation(activity,false,context,policy,envelope);
            assertTrue("Exact hardware-authenticated round trip",Arrays.equals(plain,out));Arrays.fill(out,(byte)0);
            context[0]^=1;
            long wrong=activity.qvQuickStart(false,context,policy,envelope.clone());
            try {
                assertEquals("Wrong vault AAD must fail after authentication",2,await(activity,wrong));
                assertTrue("The exact authenticated cipher must reject the tag",activity.qvQuickEvidence(wrong).contains("stage=70,") && activity.qvQuickEvidence(wrong).contains("tagRejected=true"));
            }
            finally { activity.qvQuickFinish(wrong,false); }
        } finally {
            if(envelope!=null){assertTrue("Hardware handle deleted",activity.qvQuickDelete(envelope));Arrays.fill(envelope,(byte)0);}
            Arrays.fill(plain,(byte)0);/* Leave the activity: destroy ends the process (plan 0035); the run ends it anyway. */
        }
    }
    public void testClass3RoundTripAndWrongVaultAAD() throws Exception { roundTrip(1); }
    public void testReducedDeviceCredentialRoundTripAndWrongVaultAAD() throws Exception { roundTrip(2); }
    /** Backdates only this test's in-memory policy; never changes the OS clock. */
    @SuppressWarnings("unchecked")
    private java.util.Map<String,Long> birthPolicy(MainActivity activity) throws Exception {
        java.lang.reflect.Field lazy=MainActivity.class.getDeclaredField("quick$delegate");lazy.setAccessible(true);
        Object nativePolicy=((kotlin.Lazy<?>)lazy.get(activity)).getValue();
        java.lang.reflect.Field born=nativePolicy.getClass().getDeclaredField("born");born.setAccessible(true);
        return (java.util.Map<String,Long>)born.get(nativePolicy);
    }
    public void testExpiredAndLostNativePolicyRefusesBeforeAuthentication() throws Exception {
        MainActivity activity=launch();byte[] context=new byte[36];context[19]=1;
        byte[] envelope=operation(activity,true,context,1,"synthetic expiry canary".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try {
            java.util.Map<String,Long> born=birthPolicy(activity);
            assertEquals("One synthetic policy only",1,born.size());
            born.replaceAll((key,value)->android.os.SystemClock.elapsedRealtime()-7L*24*60*60*1000);
            long expired=activity.qvQuickStart(false,context,1,envelope.clone());
            try { assertEquals("Expired policy refuses before prompting",2,activity.qvQuickState(expired)); }
            finally { activity.qvQuickFinish(expired,false); }
            born.clear();
            long lost=activity.qvQuickStart(false,context,1,envelope.clone());
            try { assertEquals("Lost policy refuses before prompting",2,activity.qvQuickState(lost)); }
            finally { activity.qvQuickFinish(lost,false); }
        } finally { activity.qvQuickDelete(envelope);Arrays.fill(envelope,(byte)0);/* Leave the activity: destroy ends the process (plan 0035); the run ends it anyway. */ }
    }
    public void testBiometricEnrollmentInvalidatesTheHardwareKey() throws Exception {
        MainActivity activity=launch();byte[] context=new byte[36];context[19]=1;
        byte[] envelope=operation(activity,true,context,1,"synthetic enrollment canary".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try {
            System.out.println("Add a new biometric in system security settings, then return to QuickVault. Do not remove existing biometrics.");
            getInstrumentation().runOnMainSync(()->activity.startActivity(new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)));
            long deadline=android.os.SystemClock.elapsedRealtime()+180000;
            while((activity.qvStatus()&1)!=0 && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
            while((activity.qvStatus()&1)==0 && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
            assertTrue("Return from settings before the deadline",android.os.SystemClock.elapsedRealtime()<deadline);
            long id=activity.qvQuickStart(false,context,1,envelope.clone());
            try {
                assertEquals("Enrollment invalidation before any authentication fallback",2,activity.qvQuickState(id));
                assertTrue("KeyStore must report permanent invalidation, not merely missing state",activity.qvQuickEvidence(id).contains("invalidatedKey=true"));
            }
            finally { activity.qvQuickFinish(id,false); }
        } finally { activity.qvQuickDelete(envelope);Arrays.fill(envelope,(byte)0);/* Leave the activity: destroy ends the process (plan 0035); the run ends it anyway. */ }
    }
}
