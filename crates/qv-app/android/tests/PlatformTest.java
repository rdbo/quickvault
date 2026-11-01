// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.test.InstrumentationTestCase;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import dev.dioxus.main.MainActivity;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Synthetic device checks. Never selects or opens an existing vault. */
@SuppressWarnings("deprecation")
public final class PlatformTest extends InstrumentationTestCase {
    private WebView find(View view) {
        if (view instanceof WebView) return (WebView)view;
        if (view instanceof ViewGroup) {
            ViewGroup group=(ViewGroup)view;
            for(int i=0;i<group.getChildCount();i++) {WebView found=find(group.getChildAt(i));if(found!=null)return found;}
        }
        return null;
    }
    private String js(Instrumentation instrumentation,WebView view,String script) throws Exception {
        ArrayBlockingQueue<String> result=new ArrayBlockingQueue<>(1);
        instrumentation.runOnMainSync(()->view.evaluateJavascript(script,value->result.offer(value)));
        String value=result.poll(10,TimeUnit.SECONDS);
        assertNotNull("Engine response deadline",value);return value;
    }
    private void removeFixture(java.io.File root, java.io.File file) throws Exception {
        // Only the newly created private test directory may be removed.
        assertTrue("Fixture remains inside its private root", file.getCanonicalPath().equals(root.getCanonicalPath()) || file.getCanonicalPath().startsWith(root.getCanonicalPath()+java.io.File.separator));
        if(file.isDirectory()) {
            java.io.File[] children=file.listFiles();assertNotNull("Fixture listing",children);
            for(java.io.File child:children)removeFixture(root,child);
        }
        assertTrue("Fixture cleanup",file.delete());
    }
    private void awaitJs(Instrumentation instrumentation,WebView view,String condition,String stage) throws Exception {
        long deadline=System.currentTimeMillis()+30000;
        while(System.currentTimeMillis()<deadline) {
            if("true".equals(js(instrumentation,view,condition)))return;
            Thread.sleep(50);
        }
        // AppError messages are fixed, data-free categories, never input text.
        fail("Synthetic device stage: "+stage+"; "+js(instrumentation,view,"document.querySelector('.error')?.textContent || 'no app error'"));
    }
    private void submitFixture(Instrumentation instrumentation,WebView view) throws Exception {
        js(instrumentation,view,"window.qvDeviceFixture.consent()");
        awaitJs(instrumentation,view,"!document.querySelector('.primary').disabled","consent enabled submission");
        js(instrumentation,view,"window.qvDeviceFixture.submit()");
    }
    private void awaitHeading(Instrumentation instrumentation,WebView view,String heading) throws Exception {
        awaitJs(instrumentation,view,"document.querySelector('h2')?.textContent === "+org.json.JSONObject.quote(heading),heading);
    }
    private void lockFixture(Instrumentation instrumentation,WebView view) throws Exception {
        js(instrumentation,view,"window.qvDeviceFixture.submit()");
        awaitHeading(instrumentation,view,"Welcome back");
    }
    private void runSyntheticFlows(Instrumentation instrumentation, MainActivity main, WebView view) throws Exception {
        java.io.File root=new java.io.File(main.getNoBackupFilesDir(),"qv-device-test-"+System.nanoTime());
        assertTrue("New private fixture",root.mkdir());
        try {
            java.io.ByteArrayOutputStream source=new java.io.ByteArrayOutputStream();
            try(java.io.InputStream input=instrumentation.getContext().getAssets().open("flows.js")) {
                byte[] buffer=new byte[4096];int count;
                while((count=input.read(buffer))!=-1) {source.write(buffer,0,count);assertTrue("Bounded fixture script",source.size()<=32768);}
            }
            String script=new String(source.toByteArray(),java.nio.charset.StandardCharsets.UTF_8);
            js(instrumentation,view,"window.qvDeviceFixturePath="+org.json.JSONObject.quote(new java.io.File(root,"vault.qvault").getCanonicalPath())+";"+script);
            awaitHeading(instrumentation,view,"Welcome back");
            js(instrumentation,view,"window.qvDeviceFixture.tab(1)");
            awaitJs(instrumentation,view,"!!document.querySelector('#vault-name')","create form");
            js(instrumentation,view,"window.qvDeviceFixture.create(false)");
            submitFixture(instrumentation,view);
            awaitHeading(instrumentation,view,"Your recovery phrase");
            assertEquals("24 synthetic recovery words","true",js(instrumentation,view,"window.qvDeviceFixture.capture()"));
            js(instrumentation,view,"window.qvDeviceFixture.confirm();window.qvDeviceFixture.submit()");
            awaitHeading(instrumentation,view,"Your vault is open");
            lockFixture(instrumentation,view);
            assertEquals("Phrase display removed","true",js(instrumentation,view,"!document.querySelector('.phrase')"));
            js(instrumentation,view,"window.qvDeviceFixture.unlock(true)");
            submitFixture(instrumentation,view);
            awaitJs(instrumentation,view,"!!document.querySelector('.error')","wrong password refused");
            assertEquals("Wrong-password control cleared","true",js(instrumentation,view,"!document.querySelector('#password').value"));
            js(instrumentation,view,"window.qvDeviceFixture.unlock(false)");
            submitFixture(instrumentation,view);
            awaitHeading(instrumentation,view,"Your vault is open");
            lockFixture(instrumentation,view);
            js(instrumentation,view,"window.qvDeviceFixture.tab(2)");
            awaitJs(instrumentation,view,"!!document.querySelector('#phrase')","recovery form");
            js(instrumentation,view,"window.qvDeviceFixture.recover()");
            submitFixture(instrumentation,view);
            awaitHeading(instrumentation,view,"Your vault is open");
            lockFixture(instrumentation,view);
            js(instrumentation,view,"window.qvDeviceFixture.unlock(false)");
            submitFixture(instrumentation,view);
            awaitJs(instrumentation,view,"document.querySelector('.primary').textContent.includes('Opening')","opening before pause");
            instrumentation.runOnMainSync(()->instrumentation.callActivityOnPause(main));
            Thread.sleep(500);
            instrumentation.runOnMainSync(()->instrumentation.callActivityOnResume(main));
            awaitHeading(instrumentation,view,"Welcome back");
            awaitJs(instrumentation,view,"!document.querySelector('.primary').textContent.includes('Opening')","cancelled worker finished");
            Thread.sleep(5000);
            assertEquals("Late success cannot reopen","true",js(instrumentation,view,"document.querySelector('h2').textContent==='Welcome back'"));
            assertEquals("Cancelled controls cleared","true",js(instrumentation,view,"Array.from(document.querySelectorAll('input')).every(i=>i.type==='checkbox'||i.type==='radio'?!i.checked:!i.value)"));
            js(instrumentation,view,"window.qvDeviceFixture.tab(1)");
            awaitJs(instrumentation,view,"!!document.querySelector('#vault-name')","second create form");
            js(instrumentation,view,"window.qvDeviceFixture.create(true)");
            submitFixture(instrumentation,view);
            awaitHeading(instrumentation,view,"Your recovery phrase");
            js(instrumentation,view,"window.qvDeviceFixture.chooseSkip()");
            awaitJs(instrumentation,view,"!document.querySelector('details button').disabled","explicit skip consent");
            js(instrumentation,view,"window.qvDeviceFixture.skip()");
            awaitHeading(instrumentation,view,"Your vault is open");
            lockFixture(instrumentation,view);
            js(instrumentation,view,"window.qvDeviceFixture.clear();delete window.qvDeviceFixture");
        } finally {
            // Ensure no fixture session remains live before deleting only its files.
            instrumentation.runOnMainSync(()->instrumentation.callActivityOnPause(main));
            Thread.sleep(300);
            instrumentation.runOnMainSync(()->instrumentation.callActivityOnResume(main));
            removeFixture(root,root);
        }
    }
    public void testSecureWindowKeyboardSettingsLifecycleAndEngineBoundary() throws Exception {
        Instrumentation instrumentation=getInstrumentation();
        Intent intent=new Intent().setClassName("org.quickvault.app","dev.dioxus.main.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Activity activity=instrumentation.startActivitySync(intent);
        try {
            // Only this test window stays awake; do not change device settings
            // or the production app's ordinary screen-lock behavior.
            instrumentation.runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
            MainActivity main=(MainActivity)activity;
            long unlockedDeadline=System.currentTimeMillis()+30000;
            while((main.qvStatus()&2)==0 && System.currentTimeMillis()<unlockedDeadline)Thread.sleep(100);
            assertEquals("Unlock the test phone before running instrumentation",2,main.qvStatus()&2);
            long deadline=System.currentTimeMillis()+15000;
            while((main.qvStatus()&8)==0 && System.currentTimeMillis()<deadline) Thread.sleep(100);
            assertEquals("FLAG_SECURE installed",4,main.qvStatus()&4);
            assertEquals("Native webview hardening installed",8,main.qvStatus()&8);
            WebView[] view=new WebView[1];
            instrumentation.runOnMainSync(()->view[0]=find(activity.getWindow().getDecorView()));
            assertNotNull(view[0]);
            instrumentation.runOnMainSync(()->{
                assertFalse(view[0].getSettings().getAllowFileAccess());
                assertFalse(view[0].getSettings().getAllowContentAccess());
                assertFalse(view[0].getSettings().getJavaScriptCanOpenWindowsAutomatically());
                assertFalse(view[0].getSettings().getDomStorageEnabled());
            });
            awaitJs(instrumentation,view[0],"document.readyState === 'complete' && !!document.querySelector('input[type=password]')","initial password form ready");
            assertEquals("true",js(instrumentation,view[0],"(()=>{try{eval('1');return false}catch(e){return true}})()"));
            assertEquals("true",js(instrumentation,view[0],"(()=>{let s=document.createElement('script');s.textContent='window.inlineBad=true';document.body.append(s);return !window.inlineBad})()"));
            assertEquals("true",js(instrumentation,view[0],"document.querySelector('input[type=password]').autocomplete === 'off'"));
            assertEquals("true",js(instrumentation,view[0],"(()=>{const el=document.querySelector('input[type=password]');el.value='synthetic-input';el.dispatchEvent(new Event('input',{bubbles:true}));return true})()"));
            long generation=main.qvGeneration();
            instrumentation.runOnMainSync(()->instrumentation.callActivityOnPause(activity));
            Thread.sleep(500);
            assertEquals("Background metadata observed",0,main.qvStatus()&1);
            instrumentation.runOnMainSync(()->instrumentation.callActivityOnResume(activity));
            assertTrue("Pause transition retained",main.qvGeneration()>generation);
            Thread.sleep(500);
            // Checkbox value defaults to "on" even when unchecked. Check state
            // separately so text clearing and epoch-scoped consent both matter.
            assertEquals("Controls and consent cleared after background", "true",js(instrumentation,view[0],"Array.from(document.querySelectorAll('input')).every(i=>i.type==='checkbox'||i.type==='radio'?!i.checked:!i.value)"));
            runSyntheticFlows(instrumentation, main, view[0]);
        } finally {instrumentation.runOnMainSync(()->{
            activity.getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            activity.finish();
        });}
    }
}
