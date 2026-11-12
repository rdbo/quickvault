// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.app.Instrumentation;
import android.content.Intent;
import android.test.InstrumentationTestCase;
import dev.dioxus.main.MainActivity;
import dev.dioxus.main.NativeQrCamera;
import java.nio.ByteBuffer;
import java.util.Arrays;

/** Camera adapter checks use synthetic luminance; attended optics/permission tests remain separate. */
@SuppressWarnings("deprecation")
public class QrTest extends InstrumentationTestCase {
    private android.webkit.WebView find(android.view.View view) {
        if(view instanceof android.webkit.WebView)return (android.webkit.WebView)view;
        if(view instanceof android.view.ViewGroup) {
            android.view.ViewGroup group=(android.view.ViewGroup)view;
            for(int i=0;i<group.getChildCount();i++) {
                android.webkit.WebView found=find(group.getChildAt(i));if(found!=null)return found;
            }
        }
        return null;
    }
    private String js(Instrumentation ins,android.webkit.WebView view,String script) throws Exception {
        java.util.concurrent.ArrayBlockingQueue<String> result=new java.util.concurrent.ArrayBlockingQueue<>(1);
        ins.runOnMainSync(()->view.evaluateJavascript(script,value->result.offer(value)));
        String value=result.poll(10,java.util.concurrent.TimeUnit.SECONDS);
        assertNotNull("Bounded optical fixture engine response",value);return value;
    }
    private void await(Instrumentation ins,android.webkit.WebView view,String condition,String label) throws Exception {
        long deadline=android.os.SystemClock.elapsedRealtime()+15000;
        while(android.os.SystemClock.elapsedRealtime()<deadline) {
            if("true".equals(js(ins,view,condition)))return;
            Thread.sleep(50);
        }
        fail("Optical fixture stage: "+label);
    }
    private void opticalScan(Instrumentation ins,MainActivity main) throws Exception {
        assertTrue("Optical fixture requires a camera-enabled package",main.qvQrCamera());
        android.webkit.WebView[] found=new android.webkit.WebView[1];
        ins.runOnMainSync(()->found[0]=find(main.getWindow().getDecorView()));
        android.webkit.WebView view=found[0];assertNotNull("Shared app webview",view);
        await(ins,view,"document.body.textContent.includes('Synthetic validation build') && (!!document.getElementById('welcome-join') || !!document.getElementById('vault-menu'))","isolated locked form");
        await(ins,view,"!!document.querySelector('#lan-join-code') || ((()=>{for(const id of ['welcome-join','menu-join']){const b=document.getElementById(id);if(b){b.click();return true}}document.getElementById('vault-menu')?.click();return false})() && false)","Join form");
        stage(ins,"aim at the known synthetic QR fixture; scan fills Join only");
        String click="(()=>{const b=Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Scan a code'&&!b.disabled);if(!b)return false;b.click();return true})()";
        assertEquals("Explicit Scan action","true",js(ins,view,click));
        long deadline=android.os.SystemClock.elapsedRealtime()+75000;
        boolean retried=false,permissionObserved=false,scanned=false;
        while(android.os.SystemClock.elapsedRealtime()<deadline) {
            if(main.checkSelfPermission(android.Manifest.permission.CAMERA)==android.content.pm.PackageManager.PERMISSION_GRANTED) {
                if(!permissionObserved){permissionObserved=true;Thread.sleep(250);}
                if("true".equals(js(ins,view,"!!document.getElementById('lan-code-scanned') && document.body.textContent.includes('Code scanned. Type the other device\\'s address and choose Join.')"))) {scanned=true;break;}
                // A permission activity pause may cancel the initial Scan.
                // Lock resets the form to Unlock, so select Join again before
                // making the fresh explicit Scan action.
                if(!retried && "true".equals(js(ins,view,"!document.querySelector('#lan-join-code') && (!!document.getElementById('welcome-join') || !!document.getElementById('vault-menu'))"))) {
                    await(ins,view,"!!document.querySelector('#lan-join-code') || ((()=>{for(const id of ['welcome-join','menu-join']){const b=document.getElementById(id);if(b){b.click();return true}}document.getElementById('vault-menu')?.click();return false})() && false)","Join after permission pause");
                }
                if(!retried && "true".equals(js(ins,view,"!document.querySelector('.busy-toast') && !!Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Scan a code'&&!b.disabled)"))) {
                    retried=true;assertEquals("Explicit retry after permission/cancel","true",js(ins,view,click));
                }
            }
            Thread.sleep(100);
        }
        assertTrue("Optical check needs camera permission granted on the phone",permissionObserved);
        assertTrue("Camera -> JNI -> Rust decode -> core -> current Join form",scanned);
        assertEquals("The scanned code is never rendered; only marked","true",js(ins,view,"!document.querySelector('#lan-join-code') && !!document.getElementById('lan-code-scanned') && document.querySelector('#lan-join-endpoint').value===''"));
        assertEquals("A code without an address has not started Join","true",js(ins,view,"!document.querySelector('.busy-toast') && !!document.querySelector('#lan-join-endpoint')"));
        js(ins,view,"Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Back').click()");
        await(ins,view,"(!!document.querySelector('#password') || !!document.getElementById('welcome-join')) && !document.getElementById('lan-code-scanned') && !document.querySelector('#lan-join-endpoint')","navigation clears scanned form");
        stage(ins,"optical Join fill and navigation cleanup passed");
    }
    private void stage(Instrumentation ins,String text) {
        android.os.Bundle report=new android.os.Bundle();
        report.putString("stream","QR adapter stage: "+text+"\n");
        ins.sendStatus(2,report);
    }
    private void liveFrame(MainActivity main,long request) throws Exception {
        byte[] frame=null;
        try {
            long deadline=android.os.SystemClock.elapsedRealtime()+15000;
            while(frame==null && main.qvQrState(request)==0 && android.os.SystemClock.elapsedRealtime()<deadline) {
                frame=main.qvQrFrame(request);
                if(frame==null)Thread.sleep(50);
            }
            assertNotNull("Live bounded camera frame within deadline",frame);
            assertTrue("Frame header",frame.length>=8);
            java.nio.ByteBuffer header=java.nio.ByteBuffer.wrap(frame).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int width=header.getInt(),height=header.getInt();
            assertTrue("Bounded live axes",width>0 && height>0 && width<=NativeQrCamera.MAX_AXIS && height<=NativeQrCamera.MAX_AXIS);
            assertTrue("Bounded live area",(long)width*height<=NativeQrCamera.MAX_PIXELS);
            assertEquals("Packed live luminance length",8+width*height,frame.length);
        } finally {if(frame!=null)Arrays.fill(frame,(byte)0);}
    }
    private void liveCamera(Instrumentation ins,MainActivity main) throws Exception {
        assertTrue("Live capture requires a camera-enabled package",main.qvQrCamera());
        long ready=android.os.SystemClock.elapsedRealtime()+15000;
        while((main.qvStatus()&15)!=15 && android.os.SystemClock.elapsedRealtime()<ready)Thread.sleep(50);
        assertEquals("Unlocked foreground hardened window",15,main.qvStatus()&15);
        assertTrue("Device exposes a camera",main.qvQrAvailable());
        if(main.checkSelfPermission(android.Manifest.permission.CAMERA)!=android.content.pm.PackageManager.PERMISSION_GRANTED) {
            stage(ins,"grant camera permission on the phone");
            long permission=main.qvQrStart();assertTrue("Explicit permission action starts",permission>0);
            try {
                long deadline=android.os.SystemClock.elapsedRealtime()+60000;
                while(main.checkSelfPermission(android.Manifest.permission.CAMERA)!=android.content.pm.PackageManager.PERMISSION_GRANTED && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
                assertEquals("Camera permission granted on the phone within deadline",
                    android.content.pm.PackageManager.PERMISSION_GRANTED,main.checkSelfPermission(android.Manifest.permission.CAMERA));
            } finally {main.qvQrFinish(permission);ins.runOnMainSync(()->{});}
            // Permission UI may pause the activity and cancel its first scan.
            // A fresh explicit action tests capture after permission returns.
            ready=android.os.SystemClock.elapsedRealtime()+15000;
            while((main.qvStatus()&15)!=15 && android.os.SystemClock.elapsedRealtime()<ready)Thread.sleep(50);
            assertEquals("Foreground restored after permission prompt",15,main.qvStatus()&15);
        }
        long request=0;
        try {
            stage(ins,"live frame and cancellation");
            request=main.qvQrStart();assertTrue("Explicit camera session starts",request>0);
            liveFrame(main,request);
            long previous=request;
            main.qvQrFinish(request);ins.runOnMainSync(()->{});
            assertEquals("Finish closes capture",1,main.qvQrState(request));
            assertNull("Finished session has no frame",main.qvQrFrame(request));

            stage(ins,"stale completion and pause cleanup");
            request=main.qvQrStart();assertTrue("Fresh request id",request>previous);
            main.qvQrFinish(previous);ins.runOnMainSync(()->{});
            assertEquals("Old completion cannot close new capture",0,main.qvQrState(request));
            assertNull("Old request cannot consume new frame",main.qvQrFrame(previous));
            liveFrame(main,request);
            ins.runOnMainSync(()->ins.callActivityOnPause(main));
            assertEquals("Pause closes capture",1,main.qvQrState(request));
            assertNull("Pause erases pending frame",main.qvQrFrame(request));
            main.qvQrFinish(request);ins.runOnMainSync(()->ins.callActivityOnResume(main));

            stage(ins,"30 second native timeout");
            request=main.qvQrStart();assertTrue("Timeout session starts",request>previous);
            liveFrame(main,request);
            long deadline=android.os.SystemClock.elapsedRealtime()+33000;
            while(main.qvQrState(request)==0 && android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
            assertEquals("Native deadline closes capture",1,main.qvQrState(request));
            assertNull("Expired session has no frame",main.qvQrFrame(request));
        } finally {
            if(request>0)main.qvQrFinish(request);
            ins.runOnMainSync(()->{});
        }
    }
    public void testStrideBoundsAndNoImplicitCameraSession() throws Exception {
        ByteBuffer plane=ByteBuffer.allocate(14);
        plane.position(2);
        for(int y=0;y<2;y++)for(int x=0;x<3;x++)plane.put(2+y*6+x*2,(byte)(11+y*10+x));
        byte[] packed=NativeQrCamera.packFrame(3,2,6,2,plane);
        assertNotNull("Padded/pixel-strided plane",packed);
        assertEquals(14,packed.length);
        assertEquals(3,packed[0]);assertEquals(2,packed[4]);
        assertTrue(Arrays.equals(new byte[]{11,12,13,21,22,23},Arrays.copyOfRange(packed,8,14)));
        assertNull(NativeQrCamera.packFrame(1025,1,1025,1,ByteBuffer.allocate(1)));
        assertNull(NativeQrCamera.packFrame(1024,1024,1024,1,ByteBuffer.allocate(1)));
        assertNull(NativeQrCamera.packFrame(3,2,6,2,ByteBuffer.allocate(10)));
        assertNull(NativeQrCamera.packFrame(3,2,1,2,plane));
        assertNull(NativeQrCamera.packFrame(3,2,Integer.MAX_VALUE,2,plane));
        Arrays.fill(packed,(byte)0);
        Instrumentation ins=getInstrumentation();
        // Some vendor ROMs can hold startActivitySync indefinitely for the singleTask
        // activity. Match AutofillTest's bounded monitor and shell foreground
        // launch, which the runner issues when it observes this stage.
        Instrumentation.ActivityMonitor monitor=ins.addMonitor(MainActivity.class.getName(),null,false);
        MainActivity main;
        try {
            stage(ins,"waiting for activity");
            try {
                ins.getTargetContext().startActivity(new Intent()
                    .setClassName("org.quickvault.app","dev.dioxus.main.MainActivity")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            } catch (Exception ignored) { /* Runner performs the shell launch. */ }
            main=(MainActivity)ins.waitForMonitorWithTimeout(monitor,30000);
        } finally { ins.removeMonitor(monitor); }
        assertNotNull("Unlocked QuickVault activity started within deadline",main);
        ins.runOnMainSync(()->main.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        try {
            assertEquals("Startup never opens capture",1,main.qvQrState(1));
            assertNull("Stale request has no frame",main.qvQrFrame(Long.MAX_VALUE));
            if(!main.qvQrCamera()) {
                assertFalse("A package built without the camera keeps it closed",main.qvQrAvailable());
                assertEquals(0,main.qvQrStart());
            }
            main.qvQrFinish(Long.MAX_VALUE); // a stale completion is harmless
            if("true".equals(((android.test.InstrumentationTestRunner)ins).getArguments().getString("qv_camera"))) {
                liveCamera(ins,main);
            }
            if("true".equals(((android.test.InstrumentationTestRunner)ins).getArguments().getString("qv_optics"))) {
                opticalScan(ins,main);
            }
        } finally {
            ins.runOnMainSync(()->main.getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        }
    }
}
