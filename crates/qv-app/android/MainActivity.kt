// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.dioxus.main

import android.os.Bundle
import android.os.PowerManager
import android.app.KeyguardManager
import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.WebView
import android.webkit.WebChromeClient
import android.webkit.PermissionRequest
import android.webkit.ValueCallback
import android.net.Uri

typealias BuildConfig = org.quickvault.app.BuildConfig

class MainActivity : WryActivity() {
    @Volatile private var foreground = false
    @Volatile private var destroyed = false
    @Volatile private var hardened = false
    @Volatile private var secureWindow = false
    @Volatile private var lifecycleGeneration = 0L
    private val screenEvents = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: Context, intent: android.content.Intent) { lifecycleGeneration++ }
    }
    override fun onCreate(state: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        secureWindow = window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        super.onCreate(state)
        val events=android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF)
        if(android.os.Build.VERSION.SDK_INT>=33)registerReceiver(screenEvents,events,Context.RECEIVER_NOT_EXPORTED) else registerReceiver(screenEvents,events)
        // Polling is on the UI thread. Rust reads metadata only, never a View.
        val handler = android.os.Handler(mainLooper)
        val harden = object : Runnable {
            override fun run() {
                if (destroyed) return
                findWebview(window.decorView)?.let { view ->
                    if (!hardened) {
                        view.settings.apply {
                            allowFileAccess = false
                            allowContentAccess = false
                            javaScriptCanOpenWindowsAutomatically = false
                            setSupportMultipleWindows(false)
                            setGeolocationEnabled(false)
                            databaseEnabled = false
                            domStorageEnabled = false
                            saveFormData = false
                            cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
                            mediaPlaybackRequiresUserGesture = true
                        }
                        view.isLongClickable = false
                        view.setOnLongClickListener { true }
                        view.setDownloadListener { _,_,_,_,_ -> }
                        view.webChromeClient = object : WebChromeClient() {
                            override fun onPermissionRequest(request: PermissionRequest) { request.deny() }
                            override fun onCreateWindow(v: WebView, dialog: Boolean, gesture: Boolean, message: android.os.Message): Boolean = false
                            override fun onShowFileChooser(v: WebView, callback: ValueCallback<Array<Uri>>, params: FileChooserParams): Boolean {
                                callback.onReceiveValue(null); return true
                            }
                        }
                        WebView.setWebContentsDebuggingEnabled(false)
                        hardened = true
                    }
                }
                handler.postDelayed(this, 50)
            }
        }
        handler.post(harden)
    }
    private fun findWebview(view: View): WebView? {
        if (view is WebView) return view
        if (view is ViewGroup) for (i in 0 until view.childCount) {
            findWebview(view.getChildAt(i))?.let { return it }
        }
        return null
    }
    override fun onResume() { super.onResume(); foreground = true }
    override fun onPause() { foreground = false; lifecycleGeneration++; super.onPause() }
    override fun onDestroy() { foreground = false; destroyed = true; lifecycleGeneration++; unregisterReceiver(screenEvents); super.onDestroy() }
    fun qvGeneration(): Long = lifecycleGeneration
    fun qvPrivateRoot(): String = noBackupFilesDir.absolutePath
    fun qvStatus(): Int {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        var flags = 0
        if (foreground) flags = flags or 1
        if (power.isInteractive && !keyguard.isKeyguardLocked) flags = flags or 2
        if (secureWindow) flags = flags or 4
        if (hardened) flags = flags or 8
        if (destroyed) flags = flags or 16
        return flags
    }
}
