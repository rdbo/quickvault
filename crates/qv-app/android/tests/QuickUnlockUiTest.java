// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.app.Instrumentation;
import android.content.Intent;
import android.webkit.WebView;
import dev.dioxus.main.MainActivity;

/** Actual shared UI -> core -> Rust policy -> native hardware. Synthetic build only. */
@SuppressWarnings({"deprecation","unchecked"})
public final class QuickUnlockUiTest extends PlatformTest {
    private static final String PASSWORD="K4L!c8vP2zR9qT7W6nM5";
    private static final String CHANGED="Zq7!mV2#wL9$kR4^tB6&";
    private MainActivity activity;
    private WebView view;
    private Instrumentation os;
    private java.io.File fixture;
    private void stage(String name) {
        android.os.Bundle status=new android.os.Bundle();status.putString("stream","Synthetic app stage: "+name+"\n");os.sendStatus(2,status);
    }
    private void awaitHardware(String condition,String stage) throws Exception {
        long deadline=android.os.SystemClock.elapsedRealtime()+80000;
        while(android.os.SystemClock.elapsedRealtime()<deadline) {
            if("true".equals(js(os,view,condition)))return;
            Thread.sleep(100);
        }
        fail("Synthetic hardware stage: "+stage+"; "+js(os,view,"document.querySelector('.error')?.textContent || 'no app error'"));
    }
    private void input(String id,String value) throws Exception {
        assertEquals("Synthetic input control exists", "true",js(os,view,"(()=>{let e=document.getElementById("+org.json.JSONObject.quote(id)+");if(!e)return false;e.value="+org.json.JSONObject.quote(value)+";e.dispatchEvent(new Event('input',{bubbles:true}));return true})()"));
    }
    private Object nativePolicy() throws Exception {
        java.lang.reflect.Field field=MainActivity.class.getDeclaredField("quick$delegate");field.setAccessible(true);
        return ((kotlin.Lazy<?>)field.get(activity)).getValue();
    }
    private boolean quickButton() throws Exception {
        return "true".equals(js(os,view,"Array.from(document.querySelectorAll('button')).some(b=>b.textContent.startsWith('Unlock with fingerprint'))"));
    }
    private void launch(boolean fresh) throws Exception {
        os=getInstrumentation();
        activity=(MainActivity)os.startActivitySync(new Intent().setClassName("org.quickvault.app","dev.dioxus.main.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        os.runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        long deadline=android.os.SystemClock.elapsedRealtime()+60000;
        while((activity.qvStatus()&15)!=15 && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
        assertEquals("Foreground unlocked hardened test window",15,activity.qvStatus()&15);
        WebView[] found=new WebView[1];os.runOnMainSync(()->found[0]=find(activity.getWindow().getDecorView()));view=found[0];assertNotNull(view);
        awaitJs(os,view,"document.body.textContent.includes('Synthetic validation build')","explicit isolated validation build");
        fixture=new java.io.File(new java.io.File(activity.getNoBackupFilesDir(),"quickvault"),"validation-current");
        if(fresh && fixture.exists())removeFixture(fixture,fixture);
        java.io.ByteArrayOutputStream code=new java.io.ByteArrayOutputStream();
        try(java.io.InputStream in=os.getContext().getAssets().open("flows.js")) {
            byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1){code.write(b,0,n);assertTrue("Bounded driver",code.size()<=32768);}
        }
        js(os,view,"window.qvDeviceFixturePath='';"+new String(code.toByteArray(),java.nio.charset.StandardCharsets.UTF_8));
        awaitHeading(os,view,"Welcome back");
    }
    private void create() throws Exception {
        awaitJs(os,view,"window.qvDeviceFixture.tab(1)","mode 1");awaitJs(os,view,"!!document.getElementById('vault-name')","creation form");
        js(os,view,"window.qvDeviceFixture.create(false)");submitFixture(os,view);
        awaitHeading(os,view,"Your recovery phrase");assertEquals("Synthetic phrase captured","true",js(os,view,"window.qvDeviceFixture.capture()"));
        awaitJs(os,view,"window.qvDeviceFixture.confirm()","phrase words");js(os,view,"window.qvDeviceFixture.submit()");awaitUnlocked(os,view);
    }
    private void enroll(int policy,String password) throws Exception {
        js(os,view,"window.qvDeviceFixture.nav('Settings')");awaitHeading(os,view,"Settings");click(os,view,"Quick unlock and autofill");
        awaitJs(os,view,"!!document.getElementById('ws-password')","quick enrollment reauth");input("ws-password",password);
        click(os,view,policy==1?"Enable biometric quick unlock":"Device credential");
        if(policy==2)click(os,view,"Continue");
        // Human authenticates the real hardware operation.
        awaitHardware("(document.querySelector('.notice')?.textContent||'').startsWith('Quick unlock enabled')","hardware enrollment completed");
    }
    private void quickOpen() throws Exception {
        awaitJs(os,view,"window.qvDeviceFixture.consent()","protection acknowledged");click(os,view,"Unlock with fingerprint");
        awaitHardware("!!document.querySelector('.shell') && !document.querySelector('.busy-toast')","hardware unlock completed");
    }
    private void passwordOpen(String password) throws Exception {
        input("password",password);submitFixture(os,view);awaitUnlocked(os,view);
    }
    private void cancelPrompt() throws Exception {
        Object nativeState=nativePolicy();
        java.lang.reflect.Field current=nativeState.getClass().getDeclaredField("current");current.setAccessible(true);
        java.lang.reflect.Field signal=nativeState.getClass().getDeclaredField("signal");signal.setAccessible(true);
        long deadline=android.os.SystemClock.elapsedRealtime()+15000;
        while(android.os.SystemClock.elapsedRealtime()<deadline) {
            long id=current.getLong(nativeState);
            if(activity.qvQuickState(id)==0 && activity.qvQuickEvidence(id).contains("stage=50,")) {
                android.os.CancellationSignal pending=(android.os.CancellationSignal)signal.get(nativeState);
                if(pending!=null){
                    // The main thread must finish authenticate() before this
                    // cancellation, just as a real user waits for the prompt.
                    os.runOnMainSync(pending::cancel);
                    long ended=android.os.SystemClock.elapsedRealtime()+10000;
                    while(activity.qvQuickState(id)==0 && android.os.SystemClock.elapsedRealtime()<ended)Thread.sleep(50);
                    assertEquals("Native authentication cancellation is transient: "+activity.qvQuickEvidence(id),1,activity.qvQuickFailureKind(id));
                    return;
                }
            }
            Thread.sleep(50);
        }
        fail("Native authentication prompt did not start");
    }
    private void cancellations() throws Exception {
        for(int attempt=1;attempt<=3;attempt++) {
            js(os,view,"window.qvCancelledEpoch=document.querySelector('[data-qv-epoch]').getAttribute('data-qv-epoch');true");
            awaitJs(os,view,"window.qvDeviceFixture.consent()","protection acknowledged");click(os,view,"Unlock with fingerprint");cancelPrompt();
            awaitJs(os,view,"document.querySelector('[data-qv-epoch]').getAttribute('data-qv-epoch')!==window.qvCancelledEpoch && window.qvDeviceFixture.at('Welcome back') && !document.querySelector('#password').disabled && !document.querySelector('#unlock-submit').disabled && !document.querySelector('.shell')","cancelled attempt completed and remained locked");
            assertEquals("Three failed/cancelled attempts require password",attempt<3,quickButton());
            stage("cancelled attempt "+attempt+" counted; vault remains locked");
            Thread.sleep(1000);
        }
        stage("three cancelled attempts revoked quick unlock");
    }
    private void runPolicy(int policy,boolean cancellationOnly) throws Exception {
        launch(true);
        try {
            input("vault-path",new java.io.File(activity.getNoBackupFilesDir(),"quickvault/vaults/main.qvault").getAbsolutePath());
            input("password",PASSWORD);submitFixture(os,view);
            awaitJs(os,view,"!!document.querySelector('.error')","outside fixture path refused");
            input("vault-path","");stage("isolated path guard passed");
            create();stage("vault created");enroll(policy,PASSWORD);stage("enrollment passed");
            lockFixture(os,view);assertTrue("Enrolled quick action",quickButton());
            if(cancellationOnly) {cancellations();passwordOpen(PASSWORD);lockFixture(os,view);return;}
            quickOpen();stage("quick unlock passed");
            js(os,view,"window.qvDeviceFixture.nav('Settings')");awaitHeading(os,view,"Settings");click(os,view,"Change master password");
            awaitJs(os,view,"!!document.getElementById('ws-new-password') && !!document.getElementById('ws-repeat')","password change form ready");
            input("ws-new-password",CHANGED);input("ws-repeat",CHANGED);click(os,view,"Change master password");
            awaitJs(os,view,"(document.querySelector('.notice')?.textContent||'').startsWith('Master password changed')","password changed");
            lockFixture(os,view);assertFalse("Password change removes quick action",quickButton());
            stage("password change revoked quick unlock");
            passwordOpen(CHANGED);lockFixture(os,view);
        } finally { if(fixture!=null && fixture.exists())removeFixture(fixture,fixture);/* Leave the activity: destroy ends the process (plan 0035); the run ends it anyway. */ }
    }
    public void testBiometricAppEnrollUnlockAndPasswordChange() throws Exception {runPolicy(1,false);}
    public void testCredentialAppEnrollUnlockAndPasswordChange() throws Exception {runPolicy(2,false);}
    public void testBiometricAppThreeCancellations() throws Exception {runPolicy(1,true);}
    public void testCredentialAppThreeCancellations() throws Exception {runPolicy(2,true);}
}
