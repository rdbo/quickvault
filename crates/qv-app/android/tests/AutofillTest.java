// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.app.Instrumentation;
import android.content.Intent;
import android.view.autofill.AutofillId;
import android.webkit.WebView;
import dev.dioxus.main.AutofillIdentity;
import dev.dioxus.main.AutofillRegistry;
import dev.dioxus.main.MainActivity;

/**
 * In-process handoff: native registry -> JNI poll -> Rust validation and exact
 * matching -> shared UI -> explicit choice -> registry result. Synthetic,
 * fixture-restricted validation build only. The OS autofill framework round
 * trip from a foreign app is an attended row in plan 0034 VALIDATION.md.
 */
public final class AutofillTest extends PlatformTest {
    private static final String PASSWORD="K4L!c8vP2zR9qT7W6nM5";
    // A preinstalled system package: its package name and real signer set
    // stand in for a verified requester; nothing is filled into it.
    private static final String REQUESTER="com.android.shell";
    private MainActivity activity;
    private WebView view;
    private Instrumentation os;
    private java.io.File fixture;

    private void stage(String name) {
        android.os.Bundle status=new android.os.Bundle();status.putString("stream","Synthetic autofill stage: "+name+"\n");os.sendStatus(2,status);
    }
    private void input(String id,String value) throws Exception {
        assertEquals("Synthetic input control exists","true",js(os,view,"(()=>{let e=document.getElementById("+org.json.JSONObject.quote(id)+");if(!e)return false;e.value="+org.json.JSONObject.quote(value)+";e.dispatchEvent(new Event('input',{bubbles:true}));return true})()"));
    }
    private void launch() throws Exception {
        os=getInstrumentation();
        // MIUI refuses an app's own activity start while another app is on
        // top, so the runner starts QuickVault from adb shell (VALIDATION.md).
        Instrumentation.ActivityMonitor monitor=os.addMonitor(MainActivity.class.getName(),null,false);
        try {
            try { os.getTargetContext().startActivity(new Intent().setClassName("org.quickvault.app","dev.dioxus.main.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); } catch (Exception ignored) {}
            activity=(MainActivity)os.waitForMonitorWithTimeout(monitor,120000);
        } finally { os.removeMonitor(monitor); }
        assertNotNull("QuickVault started (runner must start it on MIUI)",activity);
        os.runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        foreground();
        WebView[] found=new WebView[1];os.runOnMainSync(()->found[0]=find(activity.getWindow().getDecorView()));view=found[0];assertNotNull(view);
        awaitJs(os,view,"document.body.textContent.includes('Synthetic validation build')","explicit isolated validation build");
        assertTrue("Validation build opens the autofill gate",activity.qvAutofillAvailable());
        fixture=new java.io.File(new java.io.File(activity.getNoBackupFilesDir(),"quickvault"),"validation-current");
        if(fixture.exists())removeFixture(fixture,fixture);
        java.io.ByteArrayOutputStream code=new java.io.ByteArrayOutputStream();
        try(java.io.InputStream in=os.getContext().getAssets().open("flows.js")) {
            byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1){code.write(b,0,n);assertTrue("Bounded driver",code.size()<=32768);}
        }
        js(os,view,"window.qvDeviceFixturePath='';"+new String(code.toByteArray(),java.nio.charset.StandardCharsets.UTF_8));
        awaitHeading(os,view,"Welcome back");
    }
    private void foreground() throws Exception {
        long deadline=android.os.SystemClock.elapsedRealtime()+120000;
        while((activity.qvStatus()&15)!=15 && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
        assertEquals("Foreground unlocked hardened test window",15,activity.qvStatus()&15);
    }
    private void create() throws Exception {
        awaitJs(os,view,"window.qvDeviceFixture.tab(1)","mode 1");awaitJs(os,view,"!!document.getElementById('vault-name')","creation form");
        js(os,view,"window.qvDeviceFixture.create(false)");submitFixture(os,view);
        awaitHeading(os,view,"Your recovery phrase");assertEquals("Synthetic phrase captured","true",js(os,view,"window.qvDeviceFixture.capture()"));
        awaitJs(os,view,"window.qvDeviceFixture.confirm()","phrase words");js(os,view,"window.qvDeviceFixture.submit()");awaitUnlocked(os,view);
    }
    /** An entry whose title names the requester: titles must never match. */
    private void spoofTitledEntry() throws Exception {
        click(os,view,"New item");
        awaitJs(os,view,"!!document.getElementById('ws-title')","entry form");
        js(os,view,"window.qvDeviceFixture.entryForm()");input("ws-title",REQUESTER+" Shell");
        click(os,view,"Generate");click(os,view,"Save");
        awaitJs(os,view,"window.qvDeviceFixture.at("+org.json.JSONObject.quote(REQUESTER+" Shell")+") && !document.querySelector('.busy-toast')","saved entry");
    }
    private AutofillRegistry.Request offer() throws Exception {
        byte[] signers=AutofillIdentity.INSTANCE.signers(activity,REQUESTER);
        assertNotNull("Requester signer set readable",signers);
        AutofillId[] ids=new AutofillId[2];
        os.runOnMainSync(()->{ids[0]=new android.view.View(activity).getAutofillId();ids[1]=new android.view.View(activity).getAutofillId();});
        AutofillRegistry.Request r=AutofillRegistry.INSTANCE.register(REQUESTER,signers,null,null,ids[0],ids[1]);
        byte[] wrong=r.getToken().clone();wrong[0]^=1;
        assertFalse("Wrong token refused",AutofillRegistry.INSTANCE.claim(wrong));
        assertTrue("Token claims once",AutofillRegistry.INSTANCE.claim(r.getToken()));
        assertFalse("Token is one-shot",AutofillRegistry.INSTANCE.claim(r.getToken()));
        return r;
    }
    private boolean claimed(AutofillRegistry.Request r) {
        return AutofillRegistry.INSTANCE.claimed(r.getId())!=null;
    }

    /**
     * Cold start: the handoff activity claims the request before MainActivity
     * and its Rust runtime exist. The request must wait for the controller and
     * then for unlock, not be cancelled by the first poll.
     */
    public void testColdStartRequestWaitsForControllerAndUnlock() throws Exception {
        os=getInstrumentation();
        android.content.Context target=os.getTargetContext();
        byte[] signers=AutofillIdentity.INSTANCE.signers(target,REQUESTER);
        assertNotNull("Requester signer set readable",signers);
        AutofillId[] ids=new AutofillId[2];
        os.runOnMainSync(()->{ids[0]=new android.view.View(target).getAutofillId();ids[1]=new android.view.View(target).getAutofillId();});
        AutofillRegistry.Request r=AutofillRegistry.INSTANCE.register(REQUESTER,signers,null,null,ids[0],ids[1]);
        assertTrue("Token claims once",AutofillRegistry.INSTANCE.claim(r.getToken()));
        launch();
        try {
            create();
            assertTrue("Request survives controller startup",claimed(r));
            stage("request survived controller startup");
            lockFixture(os,view);
            awaitJs(os,view,"(document.querySelector('[data-qv-autofill=banner]')?.textContent||'').includes("+org.json.JSONObject.quote(REQUESTER)+")","locked request banner");
            input("password",PASSWORD);submitFixture(os,view);
            awaitHeading(os,view,"Fill a login");
            stage("cold-start request bound after unlock");
            js(os,view,"document.querySelector('[data-qv-autofill=cancel]').click();true");
            long deadline=android.os.SystemClock.elapsedRealtime()+30000;
            while(claimed(r) && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
            assertFalse("Cancel abandons the request",claimed(r));
            assertNull("Cancelled request yields no result",AutofillRegistry.INSTANCE.take(r.getToken()));
            stage("cancel abandoned the request");
        } finally { if(fixture!=null && fixture.exists())removeFixture(fixture,fixture); }
    }

    public void testAutofillHandoffNeedsVerifiedLinkExplicitChoiceAndLockCancels() throws Exception {
        launch();
        try {
            create();stage("vault created");spoofTitledEntry();stage("title spoof entry saved");
            lockFixture(os,view);
            AutofillRegistry.Request r=offer();
            awaitJs(os,view,"(document.querySelector('[data-qv-autofill=banner]')?.textContent||'').includes("+org.json.JSONObject.quote(REQUESTER)+")","locked request banner");
            stage("request waits on lock screen");
            input("password",PASSWORD);submitFixture(os,view);
            awaitHeading(os,view,"Fill a login");
            assertEquals("Title naming the app is not a candidate","true",js(os,view,"document.querySelectorAll('[data-qv-autofill=candidate]').length===0 && document.body.textContent.includes('No entry matches this verified identity.')"));
            stage("label spoof refused");
            js(os,view,"document.querySelector('details').open=true;true");
            input("ws-query","Shell");
            awaitJs(os,view,"!!document.querySelector('[data-qv-autofill=link]')","link candidate search");
            js(os,view,"document.querySelector('[data-qv-autofill=link]').click();true");
            awaitJs(os,view,"!!document.querySelector('[role=alertdialog]')","link confirmation required");
            assertTrue("Link alone fills nothing",claimed(r));
            click(os,view,"Continue");
            awaitJs(os,view,"document.querySelectorAll('[data-qv-autofill=candidate]').length===1 && !document.querySelector('.busy-toast')","linked candidate");
            assertTrue("Still waiting for an explicit choice",claimed(r));
            stage("verified link confirmed");
            js(os,view,"document.querySelector('[data-qv-autofill=candidate]').click();true");
            long deadline=android.os.SystemClock.elapsedRealtime()+30000;
            while(claimed(r) && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
            AutofillRegistry.Request done=AutofillRegistry.INSTANCE.take(r.getToken());
            assertNotNull("Explicit choice completed the request",done);
            assertEquals("Username for the chosen entry","phone@example.test",new String(done.getUser(),java.nio.charset.StandardCharsets.UTF_8));
            assertTrue("Password released only after choice",done.getPass()!=null && done.getPass().length>=8);
            AutofillRegistry.INSTANCE.wipe(done);
            stage("explicit fill completed");

            // A bound request is cancelled by a lock and never completes later.
            // singleTask: the runner's next start re-enters this same instance.
            foreground();
            awaitJs(os,view,"window.qvDeviceFixture.at('Welcome back') || !!document.querySelector('.shell')","app foreground again");
            if("true".equals(js(os,view,"!!document.querySelector('.shell')")))lockFixture(os,view);
            AutofillRegistry.Request second=offer();
            input("password",PASSWORD);submitFixture(os,view);
            awaitHeading(os,view,"Fill a login");
            awaitJs(os,view,"document.querySelectorAll('[data-qv-autofill=candidate]').length===1","linked candidate after relaunch");
            lockFixture(os,view);
            assertFalse("Lock cancels the bound request",claimed(second));
            assertNull("Cancelled request yields no result",AutofillRegistry.INSTANCE.take(second.getToken()));
            stage("lock cancelled bound request");
        } finally { if(fixture!=null && fixture.exists())removeFixture(fixture,fixture);/* Leave the activity: destroy ends the process (plan 0035); the run ends it anyway. */ }
    }
}
