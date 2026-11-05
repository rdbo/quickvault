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
public class PlatformTest extends InstrumentationTestCase {
    protected WebView find(View view) {
        if (view instanceof WebView) return (WebView)view;
        if (view instanceof ViewGroup) {
            ViewGroup group=(ViewGroup)view;
            for(int i=0;i<group.getChildCount();i++) {WebView found=find(group.getChildAt(i));if(found!=null)return found;}
        }
        return null;
    }
    protected String js(Instrumentation instrumentation,WebView view,String script) throws Exception {
        ArrayBlockingQueue<String> result=new ArrayBlockingQueue<>(1);
        instrumentation.runOnMainSync(()->view.evaluateJavascript(script,value->result.offer(value)));
        String value=result.poll(10,TimeUnit.SECONDS);
        assertNotNull("Engine response deadline",value);return value;
    }
    protected void removeFixture(java.io.File root, java.io.File file) throws Exception {
        // Only the newly created private test directory may be removed.
        assertTrue("Fixture remains inside its private root", file.getCanonicalPath().equals(root.getCanonicalPath()) || file.getCanonicalPath().startsWith(root.getCanonicalPath()+java.io.File.separator));
        if(file.isDirectory()) {
            java.io.File[] children=file.listFiles();assertNotNull("Fixture listing",children);
            for(java.io.File child:children)removeFixture(root,child);
        }
        assertTrue("Fixture cleanup",file.delete());
    }
    protected void awaitJs(Instrumentation instrumentation,WebView view,String condition,String stage) throws Exception {
        long deadline=System.currentTimeMillis()+30000;
        while(System.currentTimeMillis()<deadline) {
            if("true".equals(js(instrumentation,view,condition)))return;
            Thread.sleep(50);
        }
        // AppError messages are fixed, data-free categories, never input text.
        fail("Synthetic device stage: "+stage+"; "+js(instrumentation,view,"document.querySelector('.error')?.textContent || 'no app error'")+"; "+js(instrumentation,view,"window.qvDeviceFixture?.summary?.() || ''"));
    }
    protected void submitFixture(Instrumentation instrumentation,WebView view) throws Exception {
        js(instrumentation,view,"window.qvDeviceFixture.consent()");
        awaitJs(instrumentation,view,"!document.querySelector('.primary').disabled","consent enabled submission");
        js(instrumentation,view,"window.qvDeviceFixture.submit()");
    }
    protected void awaitHeading(Instrumentation instrumentation,WebView view,String heading) throws Exception {
        awaitJs(instrumentation,view,"document.querySelector('h2')?.textContent === "+org.json.JSONObject.quote(heading),heading);
    }
    protected void lockFixture(Instrumentation instrumentation,WebView view) throws Exception {
        js(instrumentation,view,"window.qvDeviceFixture.lock()");
        awaitHeading(instrumentation,view,"Welcome back");
    }
    protected void awaitUnlocked(Instrumentation instrumentation,WebView view) throws Exception {
        awaitJs(instrumentation,view,"!!document.querySelector('.ws') && !document.querySelector('.busy')","unlocked workspace");
    }
    protected void click(Instrumentation instrumentation,WebView view,String text) throws Exception {
        awaitJs(instrumentation,view,"window.qvDeviceFixture.button("+org.json.JSONObject.quote(text)+")","button "+text);
    }
    private android.content.ClipData clip(Instrumentation instrumentation) throws Exception {
        android.content.ClipData[] out=new android.content.ClipData[1];
        instrumentation.runOnMainSync(()->out[0]=instrumentation.getTargetContext().getSystemService(android.content.ClipboardManager.class).getPrimaryClip());
        return out[0];
    }
    private boolean clipEmpty(Instrumentation instrumentation) throws Exception {
        android.content.ClipData c=clip(instrumentation);
        return c==null || c.getItemCount()==0 || c.getItemAt(0).getText()==null || c.getItemAt(0).getText().length()==0;
    }
    private void pick(Instrumentation instrumentation,WebView view,String button,java.io.File file,String stage) throws Exception {
        // Answer the picker intent with a private test file; no system UI.
        Intent result=new Intent().setData(android.net.Uri.fromFile(file));
        Instrumentation.ActivityMonitor monitor=instrumentation.addMonitor((android.content.IntentFilter)null,new Instrumentation.ActivityResult(Activity.RESULT_OK,result),true);
        try {
            click(instrumentation,view,button);
            awaitJs(instrumentation,view,"Array.from(document.querySelectorAll('.hint')).some(h=>h.textContent==="+org.json.JSONObject.quote("Chosen: "+file.getName())+")",stage);
        } finally { instrumentation.removeMonitor(monitor); }
    }
    private void workspaceFlows(Instrumentation instrumentation,MainActivity main,WebView view,java.io.File root) throws Exception {
        click(instrumentation,view,"New entry");
        awaitJs(instrumentation,view,"!!document.getElementById('ws-title')","entry form");
        js(instrumentation,view,"window.qvDeviceFixture.entryForm()");
        click(instrumentation,view,"Generate");
        click(instrumentation,view,"Save");
        awaitJs(instrumentation,view,"document.querySelector('h2')?.textContent==='Synthetic phone entry' && !document.querySelector('.busy')","saved entry");
        assertEquals("Protected value masked","true",js(instrumentation,view,"Array.from(document.querySelectorAll('.field-value')).some(v=>v.textContent==='••••••••')"));
        click(instrumentation,view,"Reveal 30 s");
        awaitJs(instrumentation,view,"(document.querySelector('.field-value.revealed')?.textContent||'').length>=8","reveal");
        click(instrumentation,view,"Hide");
        awaitJs(instrumentation,view,"!document.querySelector('.field-value.revealed')","hide");
        // Copy goes Rust → OS clipboard, marked sensitive, and expires when owned.
        js(instrumentation,view,"Array.from(document.querySelectorAll('.field-line')).find(l=>l.textContent.includes('password')).querySelector('.field-actions button:last-child').click()");
        awaitJs(instrumentation,view,"!!document.querySelector('.toast')","clipboard hold");
        android.content.ClipData copied=clip(instrumentation);
        assertNotNull("Copied clip",copied);
        assertEquals("QuickVault",copied.getDescription().getLabel().toString());
        assertTrue("Sensitive clip",copied.getDescription().getExtras()!=null && copied.getDescription().getExtras().getBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE));
        assertTrue("Copied value present",copied.getItemAt(0).getText().length()>=8);
        long end=System.currentTimeMillis()+30000;
        while(System.currentTimeMillis()<end && !clipEmpty(instrumentation)) Thread.sleep(250);
        assertTrue("Owned clip cleared at expiry",clipEmpty(instrumentation));
        // Background during a foreground hold defers only background expiry.
        js(instrumentation,view,"Array.from(document.querySelectorAll('.field-line')).find(l=>l.textContent.includes('password')).querySelector('.field-actions button:last-child').click()");
        awaitJs(instrumentation,view,"!!document.querySelector('.toast')","second clipboard hold");
        instrumentation.runOnMainSync(()->instrumentation.callActivityOnPause(main));
        Thread.sleep(1500);
        assertEquals("Deferred while copying","true",js(instrumentation,view,"!!document.querySelector('.ws')"));
        awaitHeading(instrumentation,view,"Welcome back");
        instrumentation.runOnMainSync(()->instrumentation.callActivityOnResume(main));
        js(instrumentation,view,"window.qvDeviceFixture.unlock(false)");
        submitFixture(instrumentation,view);
        awaitUnlocked(instrumentation,view);
        // Edit, then restore the older complete version through the shared UI.
        click(instrumentation,view,"Synthetic phone entry");click(instrumentation,view,"Edit");
        awaitHeading(instrumentation,view,"Edit entry");
        js(instrumentation,view,"document.getElementById('ws-title').value='Edited phone entry';document.getElementById('ws-title').dispatchEvent(new Event('input',{bubbles:true}))");
        click(instrumentation,view,"Save");awaitHeading(instrumentation,view,"Edited phone entry");
        click(instrumentation,view,"History");awaitHeading(instrumentation,view,"History");
        awaitJs(instrumentation,view,"!!document.querySelector('.detail-pane .row-button')","history retained");
        js(instrumentation,view,"document.querySelector('.detail-pane .row-button').click()");
        click(instrumentation,view,"Restore this version");
        awaitJs(instrumentation,view,"(document.querySelector('.notice')?.textContent||'')==='Restored as a new version.'","history restored");
        awaitJs(instrumentation,view,"window.qvDeviceFixture.nav('Vault')","vault after restore");
        // Attachment round trip through the picker path, no plaintext temp file.
        java.io.File input=new java.io.File(root,"input.bin");
        try(java.io.FileOutputStream out=new java.io.FileOutputStream(input)){out.write("phone-attachment-canary".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
        click(instrumentation,view,"Synthetic phone entry");
        click(instrumentation,view,"Attachments");
        pick(instrumentation,view,"Choose a file",input,"picked input");
        js(instrumentation,view,"window.qvDeviceFixture.attachmentFields()");
        click(instrumentation,view,"Add attachment");
        awaitJs(instrumentation,view,"Array.from(document.querySelectorAll('.row-title')).some(t=>t.textContent==='phone-canary.bin')","attachment added");
        java.io.File output=new java.io.File(root,"output.bin");
        pick(instrumentation,view,"Choose where to save",output,"picked output");
        // Back and a late native result must not carry a destination to a new screen.
        click(instrumentation,view,"Back");awaitHeading(instrumentation,view,"Synthetic phone entry");
        assertNull("Back forgets the native document",main.qvPickedName());
        click(instrumentation,view,"Attachments");
        awaitJs(instrumentation,view,"!Array.from(document.querySelectorAll('.hint')).some(h=>h.textContent.startsWith('Chosen:'))","Back cleared chosen hint");
        pick(instrumentation,view,"Choose where to save",output,"picked replacement output");
        click(instrumentation,view,"Save…");
        click(instrumentation,view,"Continue");
        awaitJs(instrumentation,view,"(document.querySelector('.notice')?.textContent||'')==='Attachment saved.'","attachment saved");
        assertEquals("phone-attachment-canary",new String(java.nio.file.Files.readAllBytes(output.toPath()),java.nio.charset.StandardCharsets.UTF_8));
        // Archive export then merge back through staged ciphertext.
        awaitJs(instrumentation,view,"window.qvDeviceFixture.nav('Archives')","archives");
        awaitHeading(instrumentation,view,"Archive exchange");
        java.io.File archive=new java.io.File(root,"export.qvsnap");
        pick(instrumentation,view,"Choose where to save",archive,"picked archive output");
        click(instrumentation,view,"Export archive");
        awaitJs(instrumentation,view,"(document.querySelector('.report')?.textContent||'').includes('Archive published')","archive exported");
        assertTrue("Exported archive bytes: exists="+archive.exists()+" files="+java.util.Arrays.toString(root.list())+" report="+js(instrumentation,view,"(document.querySelector('.report')?.textContent||'').slice(0,120)"),archive.length()>0);
        pick(instrumentation,view,"Choose a file",archive,"picked archive input");
        click(instrumentation,view,"Merge archive");
        // Own fresh export: core may record a new acceptance or report it as known.
        awaitJs(instrumentation,view,"!document.querySelector('.error') && /Archive merged|already accepted/.test(document.querySelector('.report')?.textContent||'')","archive merged");
        java.io.File staging=new java.io.File(new java.io.File(main.getNoBackupFilesDir(),"quickvault"),"staging");
        String[] left=staging.list();
        assertTrue("Staged ciphertext removed",left==null || left.length==0);
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
            awaitUnlocked(instrumentation,view);
            workspaceFlows(instrumentation,main,view,root);
            lockFixture(instrumentation,view);
            assertEquals("Phrase display removed","true",js(instrumentation,view,"!document.querySelector('.phrase')"));
            js(instrumentation,view,"window.qvDeviceFixture.unlock(true)");
            submitFixture(instrumentation,view);
            awaitJs(instrumentation,view,"!!document.querySelector('.error')","wrong password refused");
            assertEquals("Wrong-password control cleared","true",js(instrumentation,view,"!document.querySelector('#password').value"));
            js(instrumentation,view,"window.qvDeviceFixture.unlock(false)");
            submitFixture(instrumentation,view);
            awaitUnlocked(instrumentation,view);
            lockFixture(instrumentation,view);
            js(instrumentation,view,"window.qvDeviceFixture.tab(2)");
            awaitJs(instrumentation,view,"!!document.querySelector('#phrase')","recovery form");
            js(instrumentation,view,"window.qvDeviceFixture.recover()");
            submitFixture(instrumentation,view);
            awaitUnlocked(instrumentation,view);
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
            awaitUnlocked(instrumentation,view);
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
            assertFalse("No unvalidated hardware backend is enabled",main.qvQuickAvailable());
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
            /* Leave the activity: destroy ends the process (plan 0035); the run ends it anyway. */
        });}
    }
}
