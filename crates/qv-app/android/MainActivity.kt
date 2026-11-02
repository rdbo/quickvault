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
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.os.PersistableBundle
import android.provider.OpenableColumns

typealias BuildConfig = org.quickvault.app.BuildConfig

class MainActivity : WryActivity() {
    @Volatile private var foreground = false
    @Volatile private var destroyed = false
    @Volatile private var hardened = false
    @Volatile private var secureWindow = false
    @Volatile private var lifecycleGeneration = 0L
    @Volatile private var screenGeneration = 0L
    private val screenEvents = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: Context, intent: android.content.Intent) { screenGeneration++; lifecycleGeneration++ }
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

    // Storage Access Framework documents chosen by the user. Rust sees only a
    // request id, a display name and bounded byte chunks; Uris stay here.
    private val pickCode = 0x5156
    @Volatile private var pickId = 0L
    @Volatile private var pickState = 2
    @Volatile private var pickedUri: Uri? = null
    @Volatile private var pickedName: String? = null
    private var reader: java.io.InputStream? = null
    private var writer: java.io.FileOutputStream? = null
    private var writerFd: android.os.ParcelFileDescriptor? = null
    fun qvPick(create: Boolean, archive: Boolean): Long {
        pickId += 1; pickState = 0; pickedUri = null; pickedName = null
        val intent = Intent(if (create) Intent.ACTION_CREATE_DOCUMENT else Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        if (create) intent.setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, if (archive) "quickvault-archive.qvsnap" else "attachment")
        runOnUiThread { try { startActivityForResult(intent, pickCode) } catch (e: Exception) { pickState = 2 } }
        return pickId
    }
    @Deprecated("Platform result callback for the document picker")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pickCode) return
        val uri = data?.data
        if (resultCode != RESULT_OK || uri == null) { pickState = 2; return }
        pickedName = try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
        } catch (e: Exception) { null } ?: uri.lastPathSegment
        pickedUri = uri; pickState = 1
    }
    fun qvPickState(id: Long): Int = if (id == pickId) pickState else 2
    fun qvPickedName(): String? = pickedName?.take(255)
    fun qvOpenRead(id: Long): Boolean {
        qvCloseDoc(false)
        val uri = pickedUri ?: return false
        if (id != pickId || pickState != 1) return false
        reader = try { contentResolver.openInputStream(uri) } catch (e: Exception) { null }
        return reader != null
    }
    fun qvRead(max: Int): ByteArray? {
        val input = reader ?: return null
        val buffer = ByteArray(max.coerceIn(1, 65536))
        val n = try { input.read(buffer) } catch (e: Exception) { return null }
        if (n <= 0) return ByteArray(0)
        return buffer.copyOf(n).also { java.util.Arrays.fill(buffer, 0) }
    }
    fun qvOpenWrite(id: Long): Boolean {
        qvCloseDoc(false)
        val uri = pickedUri ?: return false
        if (id != pickId || pickState != 1) return false
        writerFd = try { contentResolver.openFileDescriptor(uri, "wt") } catch (e: Exception) { null }
        writer = writerFd?.let { java.io.FileOutputStream(it.fileDescriptor) }
        return writer != null
    }
    fun qvWrite(bytes: ByteArray): Boolean = try { writer?.write(bytes); java.util.Arrays.fill(bytes, 0); writer != null } catch (e: Exception) { false }
    fun qvCloseDoc(sync: Boolean): Boolean {
        var ok = true
        try { reader?.close() } catch (e: Exception) { ok = false }
        try { writer?.let { it.flush(); if (sync) it.fd.sync(); it.close() } } catch (e: Exception) { ok = false }
        try { writerFd?.close() } catch (e: Exception) { ok = false }
        reader = null; writer = null; writerFd = null
        return ok
    }
    fun qvForgetPick() { qvCloseDoc(false); pickState = 2; pickedUri = null; pickedName = null }

    fun qvGeneration(): Long = lifecycleGeneration
    fun qvScreenGeneration(): Long = screenGeneration
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
