// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.webkit.WebView;
import dev.dioxus.main.MainActivity;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

/** Regular UI plus actual content-provider streams. Never runs in the owner's app. */
@SuppressWarnings("deprecation")
public final class VaultImportTest extends PlatformTest {
    private static final String PASSWORD = "K4L!c8vP2zR9qT7W6nM5";
    private MainActivity activity;
    private long lastPick;
    private long previousPick;
    private void input(Instrumentation os, WebView web, String id, String value) throws Exception {
        js(os, web, "(()=>{const e=document.getElementById("+org.json.JSONObject.quote(id)+");e.value="+org.json.JSONObject.quote(value)+";e.dispatchEvent(new Event('input',{bubbles:true}));})()");
    }
    private byte[] digest(File file) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] chunk = new byte[65536]; int count;
            while ((count = input.read(chunk)) != -1) hash.update(chunk, 0, count);
        }
        return hash.digest();
    }
    private void pick(Instrumentation os, WebView web, Uri uri, boolean cancel) throws Exception {
        if ("true".equals(js(os,web,"!!document.getElementById('password')"))) {
            input(os,web,"password","");
            awaitJs(os,web,"!document.querySelector('.error')", "previous error cleared");
        }
        js(os, web, "document.getElementById('vault-menu').click()");
        awaitJs(os, web, "!!document.getElementById('menu-open-file')", "vault picker menu");
        Intent result = new Intent().setData(uri);
        IntentFilter filter = new IntentFilter(Intent.ACTION_OPEN_DOCUMENT);
        filter.addCategory(Intent.CATEGORY_OPENABLE); filter.addDataType("*/*");
        Instrumentation.ActivityMonitor monitor = os.addMonitor(filter,
            new Instrumentation.ActivityResult(cancel ? Activity.RESULT_CANCELED : Activity.RESULT_OK, result), true);
        try {
            click(os, web, "Open a vault file");
            long deadline = android.os.SystemClock.elapsedRealtime()+15000;
            while (monitor.getHits()==0 && android.os.SystemClock.elapsedRealtime()<deadline) Thread.sleep(20);
            assertTrue("System document intent intercepted", monitor.getHits()>0);
            // Wait for the real result callback, including a cancelled choice.
            java.lang.reflect.Field field = MainActivity.class.getDeclaredField("pickId");
            field.setAccessible(true); long id = field.getLong(activity);
            previousPick = lastPick; lastPick = id;
            while (activity.qvPickState(id)==0 && android.os.SystemClock.elapsedRealtime()<deadline) Thread.sleep(20);
            assertTrue("Native picker callback completed", activity.qvPickState(id)!=0);
        }
        finally { os.removeMonitor(monitor); }
    }
    private int opens(Instrumentation os, Uri provider) {
        return os.getTargetContext().getContentResolver().call(provider, "stats", null, null).getInt("opens");
    }
    public void testContentProviderImportRetriesFailuresCancellationAndDurableReopen() throws Exception {
        Instrumentation os = getInstrumentation();
        assertEquals("Dedicated disposable UID", "org.quickvault.validation49", os.getTargetContext().getPackageName());
        File root = new File(os.getTargetContext().getNoBackupFilesDir(), "quickvault");
        assertFalse("Fresh isolated app state required", root.exists());
        // Isolate this provider test from the separate attended Class3 matrix.
        // This is the ordinary optional preference, not a validation build flag.
        assertTrue("Private fixture root", root.mkdir());
        File prefs = new File(root,"preferences");
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(prefs)) {
            out.write("quick=off\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            out.getFD().sync();
        }
        assertTrue("Private fixture preference",prefs.setReadable(false,false) && prefs.setWritable(false,false)
            && prefs.setReadable(true,true) && prefs.setWritable(true,true));
        Uri provider = Uri.parse("content://"+os.getContext().getPackageName()+".vault-import");
        MainActivity main = (MainActivity)os.startActivitySync(new Intent().setClassName("org.quickvault.validation49", "dev.dioxus.main.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        activity = main;
        WebView[] found = new WebView[1];
        os.runOnMainSync(() -> main.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        try {
            long deadline = android.os.SystemClock.elapsedRealtime() + 30000;
            while (found[0] == null && android.os.SystemClock.elapsedRealtime() < deadline) {
                os.runOnMainSync(() -> found[0] = find(main.getWindow().getDecorView())); Thread.sleep(50);
            }
            assertNotNull("Webview created", found[0]);
            WebView web = found[0];
            String script;
            try (java.io.InputStream in = os.getContext().getAssets().open("flows.js")) {
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[4096]; int count;
                while ((count = in.read(chunk)) != -1) { out.write(chunk,0,count); assertTrue("Bounded driver", out.size() <= 32768); }
                script = new String(out.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
            }
            js(os, web, script);
            awaitJs(os, web, "!!document.getElementById('welcome-create')", "regular welcome");
            assertEquals("No typed path", "false", js(os, web, "!!document.getElementById('vault-path')"));
            click(os, web, "Create a new vault");
            awaitJs(os, web, "!!document.getElementById('vault-name')", "create form");
            input(os,web,"vault-name","Import fixture"); input(os,web,"password",PASSWORD); input(os,web,"repeat",PASSWORD);
            submitFixture(os,web);
            awaitHeading(os,web,"Your recovery phrase");
            awaitJs(os,web,"window.qvDeviceFixture.capture()", "capture synthetic words");
            awaitJs(os,web,"window.qvDeviceFixture.confirm()", "confirm synthetic words");
            js(os,web,"window.qvDeviceFixture.submit()"); awaitUnlocked(os,web);
            lockFixture(os,web);
            File source = new File(root,"vaults/Import fixture.qvault");
            assertTrue("Synthetic source exists", source.isFile());
            byte[] original = digest(source);
            try (ParcelFileDescriptor fd = ParcelFileDescriptor.open(source, ParcelFileDescriptor.MODE_READ_ONLY)) {
                Bundle setup = new Bundle(); setup.putParcelable("source",fd);
                os.getTargetContext().getContentResolver().call(provider,"source",null,setup);
            }
            pick(os,web,Uri.withAppendedPath(provider,"pipe"),true);
            awaitJs(os,web,"!!document.getElementById('password') && !document.querySelector('.error')", "picker cancellation");
            for (String kind : new String[]{"refused","denied","malformed","short"}) {
                pick(os,web,Uri.withAppendedPath(provider,kind),false);
                awaitJs(os,web,"!!document.querySelector('.error') && !!document.getElementById('password') && !document.getElementById('unlock-submit').disabled", "hostile provider refused");
                assertTrue("Source unchanged after refusal", java.util.Arrays.equals(original,digest(source)));
            }
            int beforeSlow = opens(os,provider);
            pick(os,web,Uri.withAppendedPath(provider,"slow"),false);
            deadline = android.os.SystemClock.elapsedRealtime()+15000;
            while (opens(os,provider)==beforeSlow && android.os.SystemClock.elapsedRealtime()<deadline) Thread.sleep(50);
            assertTrue("Slow stream opened",opens(os,provider)>beforeSlow);
            os.runOnMainSync(() -> main.qvForgetPickFor(previousPick));
            assertEquals("Old cleanup cannot clear the current selection",1,main.qvPickState(lastPick));
            os.runOnMainSync(() -> os.callActivityOnPause(main)); Thread.sleep(1000);
            os.runOnMainSync(() -> {
                try {
                    java.lang.reflect.Method callback = MainActivity.class.getDeclaredMethod("onActivityResult",int.class,int.class,Intent.class);
                    callback.setAccessible(true);
                    callback.invoke(main,(int)lastPick,Activity.RESULT_OK,new Intent().setData(Uri.withAppendedPath(provider,"slow")));
                } catch (ReflectiveOperationException e) { throw new AssertionError("Late fixture callback",e); }
            });
            assertEquals("Late result cannot restore a locked selection",2,main.qvPickState(lastPick));
            assertNull("Locked native selection cleared",main.qvPickedName());
            os.runOnMainSync(() -> os.callActivityOnResume(main));
            awaitJs(os,web,"!!document.getElementById('password') && !document.getElementById('import-password') && !document.getElementById('unlock-submit').disabled", "background cancellation");
            pick(os,web,Uri.withAppendedPath(provider,"pipe"),false);
            awaitJs(os,web,"!!document.getElementById('import-password')", "unknown-size pipe staged");
            int selectedOpens = opens(os,provider);
            assertEquals("Consent required", "true", js(os,web,"document.getElementById('import-submit').disabled"));
            input(os,web,"import-name","Imported fixture"); input(os,web,"import-password","wrong password");
            js(os,web,"document.getElementById('import-ack').click()"); click(os,web,"Verify and import");
            awaitJs(os,web,"!!document.querySelector('.error') && !!document.getElementById('import-password')", "wrong password refused");
            assertEquals("Password cleared", "true", js(os,web,"!document.getElementById('import-password').value"));
            assertEquals("Candidate not reread", selectedOpens, opens(os,provider));
            input(os,web,"import-password",PASSWORD); click(os,web,"Verify and import"); awaitUnlocked(os,web);
            File imported = new File(root,"vaults/Imported fixture.qvault");
            assertTrue("Imported file published", imported.isFile());
            click(os,web,"New item"); awaitJs(os,web,"window.qvDeviceFixture.startLogin()", "entry form");
            js(os,web,"window.qvDeviceFixture.entryForm()"); click(os,web,"Create");
            awaitJs(os,web,"window.qvDeviceFixture.at('Synthetic phone entry')", "imported copy editable");
            lockFixture(os,web); input(os,web,"password",PASSWORD); submitFixture(os,web); awaitUnlocked(os,web);
            awaitJs(os,web,"document.body.textContent.includes('Synthetic phone entry')", "durable imported contents");
            lockFixture(os,web);
            assertTrue("Selected source unchanged after imported edits", java.util.Arrays.equals(original,digest(source)));
            assertEquals("No plaintext path field", "false", js(os,web,"!!document.getElementById('vault-path')"));
        } finally {
            if (found[0] != null) js(os,found[0],"document.getElementById('lock')?.click();window.qvDeviceFixture?.clear()");
            os.getTargetContext().getContentResolver().call(provider,"clear",null,null);
            if (root.exists()) removeFixture(root,root);
            os.runOnMainSync(main::finish);
        }
    }
}
