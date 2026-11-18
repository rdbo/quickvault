// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.prototype

// Plan 0070 prototype activity. The lifecycle, clipboard, back and window
// rules are copied from crates/qv-app/android/MainActivity.kt; Tauri's
// activity derives from WryActivity just as the app's does today.
import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.PersistableBundle
import android.os.PowerManager
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.WebView

class MainActivity : TauriActivity() {
    @Volatile private var foreground = false
    @Volatile private var destroyed = false
    @Volatile private var secureWindow = false
    @Volatile private var lifecycleGeneration = 0L
    @Volatile private var screenGeneration = 0L
    @Volatile private var pausedAt = 0L
    @Volatile private var pausedUptime = 0L
    private var rootBackAt = 0L
    private val screenEvents = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: Context, intent: android.content.Intent) { screenGeneration++; lifecycleGeneration++ }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        secureWindow = window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        super.onCreate(savedInstanceState)
        val events = android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF)
        if (android.os.Build.VERSION.SDK_INT >= 33) registerReceiver(screenEvents, events, Context.RECEIVER_NOT_EXPORTED) else registerReceiver(screenEvents, events)
        val bg = 0xFF0E1113.toInt()
        window.decorView.setBackgroundColor(bg)
        // Edge-to-edge from targetSdk 35: pad the content by the system bars,
        // cutout and keyboard, so the keyboard never covers the field.
        val content = findViewById<View>(android.R.id.content)
        content.setBackgroundColor(bg)
        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(content) { v, insets ->
            val types = androidx.core.view.WindowInsetsCompat.Type.systemBars() or androidx.core.view.WindowInsetsCompat.Type.displayCutout()
            val bars = insets.getInsets(types)
            val ime = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            androidx.core.view.WindowInsetsCompat.CONSUMED
        }
        // Back does what Escape does in the page; at the root the page asks
        // Rust, which calls qvBackAtRoot.
        onBackPressedDispatcher.addCallback(this, object : androidx.activity.OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val view = findWebview(window.decorView) ?: return
                val now = SystemClock.uptimeMillis()
                view.requestFocus()
                view.dispatchKeyEvent(android.view.KeyEvent(now, now, android.view.KeyEvent.ACTION_DOWN, android.view.KeyEvent.KEYCODE_ESCAPE, 0))
                view.dispatchKeyEvent(android.view.KeyEvent(now, now, android.view.KeyEvent.ACTION_UP, android.view.KeyEvent.KEYCODE_ESCAPE, 0))
            }
        })
    }

    override fun onWebViewCreate(webView: WebView) {
        super.onWebViewCreate(webView)
        webView.settings.apply {
            allowFileAccess = false
            allowContentAccess = false
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(false)
            setGeolocationEnabled(false)
            saveFormData = false
            cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
        }
        webView.setDownloadListener { _, _, _, _, _ -> }
        WebView.setWebContentsDebuggingEnabled(false)
    }

    fun qvBackAtRoot() = runOnUiThread {
        val now = SystemClock.elapsedRealtime()
        if (rootBackAt != 0L && now - rootBackAt <= 2000) {
            rootBackAt = 0L
            finish()
        } else {
            rootBackAt = now
            android.widget.Toast.makeText(this, "Press back again to close", android.widget.Toast.LENGTH_SHORT).show()
        }
    }

    private fun findWebview(view: View): WebView? {
        if (view is WebView) return view
        if (view is ViewGroup) for (i in 0 until view.childCount) {
            findWebview(view.getChildAt(i))?.let { return it }
        }
        return null
    }

    // Background time by the boot clock, which counts deep sleep and frozen
    // time (plan 0069). A device that slept meanwhile counts as a screen lock.
    override fun onResume() {
        super.onResume()
        if (pausedAt != 0L) {
            val slept = (SystemClock.elapsedRealtime() - pausedAt) - (SystemClock.uptimeMillis() - pausedUptime)
            if (slept > 1000) screenGeneration++
        }
        foreground = true
    }
    override fun onPause() {
        pausedAt = SystemClock.elapsedRealtime(); pausedUptime = SystemClock.uptimeMillis()
        foreground = false; lifecycleGeneration++; super.onPause()
    }
    override fun onDestroy() {
        foreground = false; destroyed = true; lifecycleGeneration++; unregisterReceiver(screenEvents); super.onDestroy()
    }
    fun qvBackgroundMillis(): Long {
        val since = pausedAt
        return if (foreground || since == 0L) 0L else (SystemClock.elapsedRealtime() - since).coerceAtLeast(0L)
    }
    fun qvGeneration(): Long = lifecycleGeneration
    fun qvScreenGeneration(): Long = screenGeneration
    fun qvStatus(): Int {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        var flags = 0
        if (foreground) flags = flags or 1
        if (power.isInteractive && !keyguard.isKeyguardLocked) flags = flags or 2
        if (secureWindow) flags = flags or 4
        if (destroyed) flags = flags or 16
        return flags
    }

    // Clipboard: Rust owns the hold policy; these calls carry only the copied
    // text (a documented JVM intermediate) or metadata.
    private val clipLabel = "QuickVault"
    fun qvCopy(text: String): Long {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(clipLabel, text)
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
        return cm.primaryClipDescription?.timestamp ?: -1L
    }
    /** 1 = still ours, 0 = replaced, -1 = not verifiable (hidden while unfocused). */
    fun qvClipOwned(token: Long): Int {
        val description = try { getSystemService(ClipboardManager::class.java).primaryClipDescription } catch (e: Exception) { null } ?: return -1
        return if (token > 0 && description.label == clipLabel && description.timestamp == token) 1 else 0
    }
    fun qvClipClear() { getSystemService(ClipboardManager::class.java).clearPrimaryClip() }
}
