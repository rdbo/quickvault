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

import android.app.Activity
import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.os.SystemClock
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

typealias BuildConfig = org.quickvault.app.BuildConfig

class MainActivity : WryActivity() {
    private val qr by lazy { NativeQrCamera(this) }
    fun qvQrAvailable(): Boolean = qr.available()
    fun qvQrCamera(): Boolean = NativeQrCamera.QR_CAMERA
    fun qvQrStart(): Long = qr.start()
    fun qvQrState(id: Long): Int = qr.state(id)
    fun qvQrFrame(id: Long): ByteArray? = qr.takeFrame(id)
    fun qvQrFinish(id: Long) = qr.finish(id)
    override fun onRequestPermissionsResult(code: Int, permissions: Array<out String>, results: IntArray) {
        super.onRequestPermissionsResult(code, permissions, results)
        if (code == NativeQrCamera.PERMISSION) qr.permission(results.isNotEmpty() && results[0] == android.content.pm.PackageManager.PERMISSION_GRANTED)
    }
    private val quick by lazy { NativeQuickUnlock(this) }
    fun qvQuickAvailable(): Boolean = quick.available()
    fun qvQuickStart(encrypt:Boolean,binding:ByteArray,policy:Int,payload:ByteArray):Long = quick.start(encrypt,binding,policy,payload)
    fun qvQuickState(id:Long):Int = quick.status(id)
    fun qvQuickEvidence(id:Long):String = quick.evidence(id)
    fun qvQuickFailureKind(id:Long):Int = quick.failureKind(id)
    fun qvQuickResult(id:Long):ByteArray? = quick.result(id)
    fun qvQuickFinish(id:Long,keep:Boolean) = quick.finish(id,keep)
    fun qvQuickDelete(envelope:ByteArray):Boolean = quick.delete(envelope)

    // Autofill handoff (0009 §4.4): Rust polls the in-process registry; only
    // bounded metadata and the explicitly chosen values cross this boundary.
    fun qvAutofillAvailable(): Boolean = AutofillGate.enabled()
    fun qvAutofillPending(): Long = AutofillRegistry.pending()
    fun qvAutofillPackage(id: Long): String? = AutofillRegistry.claimed(id)?.pkg
    fun qvAutofillSigners(id: Long): ByteArray? = AutofillRegistry.claimed(id)?.signers?.copyOf()
    fun qvAutofillScheme(id: Long): String? = AutofillRegistry.claimed(id)?.scheme
    fun qvAutofillHost(id: Long): String? = AutofillRegistry.claimed(id)?.host
    fun qvAutofillRoles(id: Long): Int = AutofillRegistry.claimed(id)?.let { (if (it.userId != null) 1 else 0) or (if (it.passId != null) 2 else 0) } ?: 0
    fun qvAutofillComplete(id: Long, user: ByteArray?, pass: ByteArray?): Boolean {
        val ok = AutofillRegistry.complete(id, user, pass)
        // Return to the requesting app, where the handoff activity delivers.
        if (ok) runOnUiThread { moveTaskToBack(true) }
        return ok
    }
    fun qvAutofillCancel(id: Long) = AutofillRegistry.cancel(id)
    fun qvOwnSigners(): ByteArray? = AutofillIdentity.signers(this, packageName)
    fun qvOpenAutofillSettings() = runOnUiThread {
        try {
            startActivity(Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:" + packageName)))
        } catch (_: Exception) {}
    }

    @Volatile private var foreground = false
    @Volatile private var destroyed = false
    @Volatile private var hardened = false
    @Volatile private var secureWindow = false
    @Volatile private var lifecycleGeneration = 0L
    @Volatile private var screenGeneration = 0L
    private val screenEvents = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: Context, intent: android.content.Intent) { screenGeneration++; lifecycleGeneration++; qr.cancel() }
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
    // The camera permission prompt that Scan opens pauses this activity; that
    // pause keeps the scan (Rust defers the background lock for it, as for the
    // document picker). Any other pause ends the scan.
    override fun onPause() { foreground = false; lifecycleGeneration++; if (!qr.awaitingPermission()) qr.cancel(); super.onPause() }
    // The Rust/Dioxus runtime starts once per process (wry/ndk-context, and
    // this app's own bridge). After destroy, Rust locks and acknowledges, then
    // the process ends so any later activity starts fresh (plan 0035).
    @Volatile private var runtimeStopped = false
    fun qvRuntimeStopped() { runtimeStopped = true }
    override fun onDestroy() {
        foreground = false; destroyed = true; lifecycleGeneration++; qr.cancel(); unregisterReceiver(screenEvents); super.onDestroy()
        val handler = android.os.Handler(mainLooper)
        val deadline = android.os.SystemClock.elapsedRealtime() + 2000
        handler.post(object : Runnable {
            override fun run() {
                if (!runtimeStopped && android.os.SystemClock.elapsedRealtime() < deadline) { handler.postDelayed(this, 50); return }
                AutofillRegistry.wipeAll()
                android.os.Process.killProcess(android.os.Process.myPid())
            }
        })
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

    // Storage Access Framework documents chosen by the user. Rust sees only a
    // request id, a display name and bounded byte chunks; Uris stay here.
    @Volatile private var pickCode = 0
    // Keep the request-code range separate from framework activity results.
    @Volatile private var pickId = 0x5155L
    @Volatile private var pickState = 2
    @Volatile private var pickedUri: Uri? = null
    @Volatile private var pickedName: String? = null
    private var reader: java.io.InputStream? = null
    private var writer: java.io.FileOutputStream? = null
    private var writerFd: android.os.ParcelFileDescriptor? = null
    fun qvPick(create: Boolean, archive: Boolean): Long {
        if (pickState == 0 || pickId >= 65534) return -1L
        pickId += 1; pickCode = pickId.toInt(); pickState = 0; pickedUri = null; pickedName = null
        val intent = Intent(if (create) Intent.ACTION_CREATE_DOCUMENT else Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        if (create) intent.setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, if (archive) "quickvault-archive.qvsnap" else "attachment")
        runOnUiThread { try { startActivityForResult(intent, pickCode) } catch (e: Exception) { pickState = 2 } }
        return pickId
    }
    @Deprecated("Platform result callback for the document picker")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pickCode || pickState != 0) return
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

/** Hardware operations only. Trusted attempt/age/session policy is Rust-owned.
 * JVM arrays and provider buffers are best-effort intermediates (0008 §4.4).
 */
private class NativeQuickUnlock(private val activity: MainActivity) {
    private val store = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val random = java.security.SecureRandom()
    private val device = ByteArray(16).also { random.nextBytes(it) }
    private val prefix = "qv.quick.v1."
    // No device is enabled without the physical validation matrix in plan 0033.
    private val validatedFingerprints = emptySet<String>()
    private val born = mutableMapOf<String,Long>()
    private var next = 0L
    private var current = 0L
    private var state = 2
    @Volatile private var retryableAuthFailure = false
    @Volatile private var tagRejected = false
    @Volatile private var invalidatedKey = false
    @Volatile private var stage = 0
    @Volatile private var keyEvidence = "not-inspected"
    private var output: ByteArray? = null
    private var input: ByteArray? = null
    private var signal: android.os.CancellationSignal? = null
    private var created: String? = null
    init { store.aliases().toList().filter { it.startsWith(prefix) }.forEach { store.deleteEntry(it) } }
    fun available(): Boolean {
        if(android.os.Build.VERSION.SDK_INT < 30 || !validatedFingerprints.contains(android.os.Build.FINGERPRINT))return false
        val manager=activity.getSystemService(android.hardware.biometrics.BiometricManager::class.java)
        return manager.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)==android.hardware.biometrics.BiometricManager.BIOMETRIC_SUCCESS || manager.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL)==android.hardware.biometrics.BiometricManager.BIOMETRIC_SUCCESS
    }
    private fun alias(header: ByteArray): String = prefix + header.copyOfRange(19,35).joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun validate(key: javax.crypto.SecretKey, policy: Int) {
        check(android.os.Build.VERSION.SDK_INT >= 30)
        val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
        val required = if (policy == 1) android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG else android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL
        val level=if(android.os.Build.VERSION.SDK_INT>=31)info.securityLevel else if(info.isInsideSecureHardware)1 else 0
        keyEvidence="level=$level,size=${info.keySize},auth=${info.userAuthenticationType},duration=${info.userAuthenticationValidityDurationSeconds},hardwareAuth=${info.isUserAuthenticationRequirementEnforcedBySecureHardware},invalidates=${info.isInvalidatedByBiometricEnrollment}"
        stage=21
        check(key.encoded == null && key.algorithm == "AES" && info.keySize == 256)
        check(info.origin == android.security.keystore.KeyProperties.ORIGIN_GENERATED)
        stage=22
        check(info.isInsideSecureHardware && info.isUserAuthenticationRequirementEnforcedBySecureHardware)
        if (android.os.Build.VERSION.SDK_INT >= 31) check(info.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT || info.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX)
        stage=23
        check(info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds <= 0 && info.userAuthenticationType == required)
        stage=24
        check(info.blockModes.contentEquals(arrayOf("GCM")) && info.encryptionPaddings.contentEquals(arrayOf("NoPadding")))
        check(info.purposes == (android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT))
        stage=25
        if (policy == 1) check(info.isInvalidatedByBiometricEnrollment)
    }
    private fun generate(name: String, policy: Int): javax.crypto.SecretKey {
        val flags = android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
        fun make(strongBox: Boolean): javax.crypto.SecretKey {
            val auth = if (policy == 1) android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG else android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL
            val spec = android.security.keystore.KeyGenParameterSpec.Builder(name, flags)
                .setKeySize(256).setBlockModes("GCM").setEncryptionPaddings("NoPadding")
                .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, auth).setInvalidatedByBiometricEnrollment(true)
                .setIsStrongBoxBacked(strongBox).build()
            return javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore").run { init(spec); generateKey() }
        }
        return try { make(true) } catch (_: android.security.keystore.StrongBoxUnavailableException) { make(false) }
    }
    @Synchronized fun start(encrypt: Boolean, binding: ByteArray, policy: Int, payload: ByteArray): Long {
        if (android.os.Build.VERSION.SDK_INT < 30 || state == 0 || binding.size != 36 || policy !in 1..2 || payload.isEmpty() || payload.size > (if(encrypt)1024 else 1536) || next == Long.MAX_VALUE) {
            java.util.Arrays.fill(payload,0); return -1
        }
        output?.let { java.util.Arrays.fill(it,0) }; output=null
        current=++next; val id=current; state=0;stage=10;keyEvidence="not-inspected";tagRejected=false;invalidatedKey=false;retryableAuthFailure=false
        try {
            val header: ByteArray
            val key: javax.crypto.SecretKey
            val cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            if (encrypt) {
                header=ByteArray(35); header[0]=1; header[1]=1; header[2]=policy.toByte(); device.copyInto(header,3)
                val handle=ByteArray(16).also { random.nextBytes(it) }; handle.copyInto(header,19)
                val name=alias(header); created=name
                key=generate(name,policy); stage=20; born[name]=android.os.SystemClock.elapsedRealtime(); validate(key,policy)
                stage=30
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,key)
                check(cipher.iv.size==12)
                input=payload.copyOf()
            } else {
                check(payload.size>=63)
                header=payload.copyOfRange(0,35)
                check(header[0].toInt()==1 && header[1].toInt()==1 && header[2].toInt()==policy)
                check(java.security.MessageDigest.isEqual(device,header.copyOfRange(3,19)))
                val since=born[alias(header)] ?: error("lost policy")
                val age=android.os.SystemClock.elapsedRealtime()-since
                check(age>=0 && age<7L*24*60*60*1000)
                key=store.getKey(alias(header),null) as javax.crypto.SecretKey; validate(key,policy)
                stage=30
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE,key,javax.crypto.spec.GCMParameterSpec(128,payload.copyOfRange(35,47)))
                input=payload.copyOfRange(47,payload.size)
            }
            val aad="qv/android-quick/v1".toByteArray(Charsets.US_ASCII)+binding+header
            val cancellation=android.os.CancellationSignal(); signal=cancellation
            stage=40
            activity.runOnUiThread {
                try {
                    val auth=if(policy==1)android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG else android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    val builder=android.hardware.biometrics.BiometricPrompt.Builder(activity)
                        .setTitle(if(policy==1)"QuickVault biometric authentication" else "QuickVault device credential · reduced protection")
                        .setAllowedAuthenticators(auth)
                    if(policy==1)builder.setNegativeButton("Cancel",activity.mainExecutor){_,_-> authenticationFailure(id)}
                    stage=50
                    builder.build().authenticate(android.hardware.biometrics.BiometricPrompt.CryptoObject(cipher),cancellation,activity.mainExecutor,
                        object:android.hardware.biometrics.BiometricPrompt.AuthenticationCallback(){
                            override fun onAuthenticationSucceeded(result:android.hardware.biometrics.BiometricPrompt.AuthenticationResult) {
                                synchronized(this@NativeQuickUnlock) {
                                    if(current!=id || state!=0)return
                                    try {
                                        stage=60
                                        check(result.cryptoObject?.cipher === cipher)
                                        val plain=input ?: error("missing operation")
                                        stage=65
                                        cipher.updateAAD(aad)
                                        stage=70
                                        val bytes=cipher.doFinal(plain)
                                        check(bytes.isNotEmpty() && bytes.size<=(if(encrypt)1040 else 1024))
                                        output=if(encrypt)header+cipher.iv+bytes else bytes
                                        if(encrypt)java.util.Arrays.fill(bytes,0)
                                        java.util.Arrays.fill(plain,0); input=null; state=1;stage=100
                                    } catch (error:Exception){ tagRejected=error is javax.crypto.AEADBadTagException;invalidatedKey=permanentlyInvalidated(error);fail(id) }
                                }
                            }
                            override fun onAuthenticationFailed(){ authenticationFailure(id) }
                            override fun onAuthenticationError(code:Int,message:CharSequence){ authenticationFailure(id) }
                        })
                } catch (_:Exception) { fail(id) }
            }
        } catch (error:Exception) { invalidatedKey=permanentlyInvalidated(error);fail(id) }
        finally { java.util.Arrays.fill(payload,0) }
        return id
    }
    private fun permanentlyInvalidated(error:Throwable):Boolean = error is android.security.keystore.KeyPermanentlyInvalidatedException || error.cause is android.security.keystore.KeyPermanentlyInvalidatedException
    @Synchronized fun failureKind(id:Long):Int = if(id==current && retryableAuthFailure)1 else 2
    @Synchronized private fun authenticationFailure(id:Long) {
        if(current!=id || state!=0)return
        retryableAuthFailure=true;fail(id)
    }
    @Synchronized private fun fail(id: Long) {
        if(current!=id)return
        state=2; input?.let{java.util.Arrays.fill(it,0)};input=null
        output?.let{java.util.Arrays.fill(it,0)};output=null
        created?.let{ born.remove(it); try { store.deleteEntry(it) }catch(_:Exception){} };created=null
        signal?.cancel();signal=null
    }
    @Synchronized fun evidence(id:Long):String = if(id==current)"stage=$stage,$keyEvidence,tagRejected=$tagRejected,invalidatedKey=$invalidatedKey" else "unknown-operation"
    @Synchronized fun status(id: Long): Int = if(id==current)state else 2
    @Synchronized fun result(id: Long): ByteArray? = if(id==current && state==1)output else null
    @Synchronized fun finish(id: Long, keep: Boolean) {
        if(current!=id)return
        if(keep && state==1)created=null
        fail(id)
    }
    @Synchronized fun delete(envelope: ByteArray): Boolean = try {
        check(envelope.size in 63..1536 && envelope[0].toInt()==1 && envelope[1].toInt()==1)
        check(java.security.MessageDigest.isEqual(device,envelope.copyOfRange(3,19)))
        born.remove(alias(envelope));store.deleteEntry(alias(envelope));true
    }catch(_:Exception){false}
}

// ---- Autofill (plan 0034, 0009 §4.4). Kept in this file because the Dioxus
// CLI compiles only the configured main-activity source in its own build.

/**
 * Autofill answers no request unless this device's build is recorded as
 * validated (plan 0034 VALIDATION.md). The build script sets VALIDATION only
 * for the explicitly marked, fixture-restricted device-validation build.
 */
object AutofillGate {
    const val VALIDATION = false
    private val validatedFingerprints = emptySet<String>()
    fun enabled(): Boolean = android.os.Build.VERSION.SDK_INT >= 30 &&
        (VALIDATION || validatedFingerprints.contains(android.os.Build.FINGERPRINT))
}

/** Thin OS glue (0009 §4.4): detect fields and hand off. Matching is Rust's. */
class QvAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellation: CancellationSignal, callback: FillCallback) {
        val response = try { respond(request) } catch (_: Exception) { null }
        callback.onSuccess(response)
    }
    // No save support; nothing is stored from other apps.
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) { callback.onSuccess() }

    private fun respond(request: FillRequest): FillResponse? {
        if (!AutofillGate.enabled()) return null
        val structure = request.fillContexts.lastOrNull()?.structure ?: return null
        // The activity component is set by the system, not by the app.
        val pkg = structure.activityComponent?.packageName ?: return null
        if (pkg == packageName || pkg.length > AutofillRegistry.MAX_PACKAGE) return null
        val signers = AutofillIdentity.signers(this, pkg) ?: return null
        val found = Detected()
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode, 0, null, null, found)
        }
        if (found.conflict || (found.user == null && found.pass == null)) return null
        val r = AutofillRegistry.register(pkg, signers, found.scheme, found.host, found.user, found.pass)
        val intent = Intent(this, AutofillAuthActivity::class.java).putExtra(AutofillAuthActivity.EXTRA_TOKEN, r.token)
        val sender = PendingIntent.getActivity(this, (r.id and 0x7fffffff).toInt(), intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT).intentSender
        // Generic label: no titles, usernames or counts reach the other app's UI.
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "Unlock QuickVault to fill")
        }
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(presentation).apply {
            found.user?.let { setValue(it, null) }
            found.pass?.let { setValue(it, null) }
            setAuthentication(sender)
        }.build()
        return FillResponse.Builder().addDataset(dataset).build()
    }

    private class Detected {
        var user: AutofillId? = null
        var pass: AutofillId? = null
        var scheme: String? = null
        var host: String? = null
        var conflict = false
        var nodes = 0
    }
    private fun walk(node: AssistStructure.ViewNode, depth: Int, scheme: String?, host: String?, f: Detected) {
        if (depth > 64 || f.nodes >= 512) return
        f.nodes++
        var s = scheme
        var h = host
        node.webDomain?.let { h = it; s = if (android.os.Build.VERSION.SDK_INT >= 28) node.webScheme else null }
        val id = node.autofillId
        if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT && node.visibility == View.VISIBLE) {
            val role = role(node)
            if (role == 2 && f.pass == null) { f.pass = id; origin(f, s, h) }
            if (role == 1 && f.user == null) { f.user = id; origin(f, s, h) }
        }
        for (i in 0 until node.childCount) walk(node.getChildAt(i), depth + 1, s, h, f)
    }
    // Both detected fields must come from the same claimed origin (or none).
    private fun origin(f: Detected, scheme: String?, host: String?) {
        val first = f.user == null || f.pass == null
        if (first) { f.scheme = scheme; f.host = host }
        else if (f.scheme != scheme || f.host != host) f.conflict = true
    }
    /** 1 = username, 2 = password, 0 = neither. Detection only, never matching. */
    private fun role(node: AssistStructure.ViewNode): Int {
        val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
        val type = node.inputType
        val cls = type and InputType.TYPE_MASK_CLASS
        val variation = type and InputType.TYPE_MASK_VARIATION
        val html = node.htmlInfo?.attributes?.associate { it.first.lowercase() to it.second.lowercase() } ?: emptyMap()
        val password = hints.any { it.contains("password") } || html["type"] == "password" ||
            (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) ||
            (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD)
        if (password) return 2
        val user = hints.any { it == View.AUTOFILL_HINT_USERNAME.lowercase() || it == View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase() } ||
            html["autocomplete"] == "username" || html["autocomplete"] == "email" || html["type"] == "email" ||
            (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS))
        return if (user) 1 else 0
    }
}

/** OS-verified identity: SHA-256 of every current APK-contents signer. */
object AutofillIdentity {
    fun signers(context: Context, pkg: String): ByteArray? = try {
        val info = context.packageManager.getPackageInfo(pkg, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
        val certs = info.signingInfo?.apkContentsSigners
        if (certs == null || certs.isEmpty() || certs.size > 8) null else {
            val out = java.io.ByteArrayOutputStream()
            for (c in certs) out.write(java.security.MessageDigest.getInstance("SHA-256").digest(c.toByteArray()))
            out.toByteArray()
        }
    } catch (_: Exception) { null }
}

/**
 * The single in-process pending request. Intents carry only its one-shot
 * token; identity and results never travel in extras. Pending requests expire
 * after 120 s, any request after 10 minutes. Results are zeroed when replaced,
 * cancelled, consumed or expired. A cancel never revokes a completed result:
 * that fill was explicitly chosen and only the auth activity can consume it.
 */
object AutofillRegistry {
    const val MAX_PACKAGE = 255
    const val MAX_HOST = 253
    const val MAX_VALUE = 8 * 1024
    private const val PENDING_MS = 120_000L
    private const val TOTAL_MS = 600_000L
    const val PENDING = 0; const val CLAIMED = 1; const val COMPLETED = 2
    class Request(val id: Long, val token: ByteArray, val pkg: String, val signers: ByteArray,
                  val scheme: String?, val host: String?, val userId: AutofillId?, val passId: AutofillId?) {
        val created = SystemClock.elapsedRealtime()
        var state = PENDING
        var delivered = false
        var user: ByteArray? = null
        var pass: ByteArray? = null
    }
    private val random = java.security.SecureRandom()
    private var next = 0L
    private var current: Request? = null

    @Synchronized fun register(pkg: String, signers: ByteArray, scheme: String?, host: String?, user: AutofillId?, pass: AutofillId?): Request {
        drop()
        val token = ByteArray(16).also { random.nextBytes(it) }
        val usable = host != null && host.length <= MAX_HOST && scheme != null && scheme.length <= 8
        return Request(++next, token, pkg, signers, if (usable) scheme else null, if (usable) host else null, user, pass).also { current = it }
    }
    private fun expired(r: Request): Boolean {
        val age = SystemClock.elapsedRealtime() - r.created
        return age < 0 || age >= TOTAL_MS || (r.state == PENDING && age >= PENDING_MS)
    }
    private fun clear(r: Request) {
        r.user?.fill(0); r.pass?.fill(0); r.user = null; r.pass = null
    }
    private fun drop() { current?.let { clear(it) }; current = null }
    private fun live(): Request? { val r = current ?: return null; if (expired(r)) { drop(); return null }; return r }

    /** Auth activity: claim a pending request exactly once. */
    @Synchronized fun claim(token: ByteArray): Boolean {
        val r = live() ?: return false
        if (r.state != PENDING || !java.security.MessageDigest.isEqual(token, r.token)) return false
        r.state = CLAIMED
        return true
    }
    /** Rust poll: the id of a newly claimed request, else 0. */
    @Synchronized fun pending(): Long {
        val r = live() ?: return 0
        if (r.state != CLAIMED || r.delivered) return 0
        r.delivered = true
        return r.id
    }
    @Synchronized fun claimed(id: Long): Request? = live()?.takeIf { it.id == id && it.state == CLAIMED }
    @Synchronized fun complete(id: Long, user: ByteArray?, pass: ByteArray?): Boolean {
        try {
            val r = claimed(id) ?: return false
            if ((user?.size ?: 0) > MAX_VALUE || (pass?.size ?: 0) > MAX_VALUE) return false
            if ((r.userId == null || user == null) && (r.passId == null || pass == null)) return false
            r.user = if (r.userId != null) user?.copyOf() else null
            r.pass = if (r.passId != null) pass?.copyOf() else null
            r.state = COMPLETED
            return true
        } finally { user?.fill(0); pass?.fill(0) }
    }
    @Synchronized fun cancel(id: Long) { if (current?.id == id && current?.state != COMPLETED) drop() }
    /** Auth activity: remove and return a completed request for this token. */
    @Synchronized fun take(token: ByteArray): Request? {
        val r = live() ?: return null
        if (!java.security.MessageDigest.isEqual(token, r.token)) return null
        current = null
        if (r.state != COMPLETED) { clear(r); return null }
        return r
    }
    fun wipe(r: Request) = clear(r)
    @Synchronized fun wipeAll() = drop()
}

/**
 * Non-exported handoff (0009 §4.4): started only through the immutable
 * PendingIntent from QvAutofillService. It claims the one-shot token, brings
 * the shared app forward for unlock and choice, and on return delivers only a
 * completed result for the same, re-verified requester.
 */
class AutofillAuthActivity : Activity() {
    companion object { const val EXTRA_TOKEN = "org.quickvault.autofill.token" }
    private var token: ByteArray? = null

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val t = intent.getByteArrayExtra(EXTRA_TOKEN)
        // A recreated instance has lost the handoff; never resume it.
        if (state != null || t == null || t.size != 16 || !AutofillRegistry.claim(t)) { abandon(); return }
        token = t
        startActivity(Intent(this, MainActivity::class.java)
            .setAction(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
    // Back in the requesting app's task after the shared app finished or was left.
    override fun onRestart() {
        super.onRestart()
        deliver()
    }
    private fun deliver() {
        val t = token ?: return abandon()
        token = null
        val r = AutofillRegistry.take(t) ?: return abandon()
        try {
            // The requester must still be the same signed package.
            val now = AutofillIdentity.signers(this, r.pkg)
            if (now == null || !java.security.MessageDigest.isEqual(now, r.signers)) return abandon()
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, "QuickVault")
            }
            @Suppress("DEPRECATION")
            val builder = Dataset.Builder(presentation)
            var any = false
            val user = r.user
            val pass = r.pass
            if (r.userId != null && user != null) { builder.setValue(r.userId, AutofillValue.forText(String(user, Charsets.UTF_8))); any = true }
            if (r.passId != null && pass != null) { builder.setValue(r.passId, AutofillValue.forText(String(pass, Charsets.UTF_8))); any = true }
            if (!any) return abandon()
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, builder.build()))
            finish()
        } finally { AutofillRegistry.wipe(r) }
    }
    private fun abandon() {
        token?.let { AutofillRegistry.take(it) }
        token = null
        setResult(RESULT_CANCELED)
        finish()
    }
}

/** In-memory Camera2 adapter. No bitmap file, external activity or webview camera. */
class NativeQrCamera(private val activity: MainActivity) {
    companion object {
        /** On by default (owner 2026-11-07); `QV_APP_QR_CAMERA=0` builds a package without it. */
        const val QR_CAMERA = true
        const val PERMISSION = 0x5143
        const val MAX_AXIS = 1024
        const val MAX_PIXELS = 786432
        /** Copy only bounded luminance, honoring row/pixel strides and buffer position. */
        @JvmStatic fun packFrame(w:Int,h:Int,row:Int,pixel:Int,source:java.nio.ByteBuffer):ByteArray? {
            if(w<=0 || h<=0 || w>MAX_AXIS || h>MAX_AXIS || w.toLong()*h>MAX_PIXELS || row<=0 || pixel<=0) return null
            if((w.toLong()-1)*pixel>=row) return null
            val start=source.position()
            val last=start.toLong()+(h.toLong()-1)*row+(w.toLong()-1)*pixel
            if(last>=source.limit()) return null
            val out=ByteArray(8+w*h)
            for(i in 0..3) {out[i]=(w ushr (8*i)).toByte();out[4+i]=(h ushr (8*i)).toByte()}
            for(y in 0 until h) for(x in 0 until w) out[8+y*w+x]=source.get(start+y*row+x*pixel)
            return out
        }
    }
    private val handler=android.os.Handler(android.os.Looper.getMainLooper())
    private var next=0L
    private var id=0L
    private var status=1
    private var permissionId=0L
    private var deadline=0L
    private var offered=0L
    private var frame:ByteArray?=null
    // Camera resources below are owned by the UI thread; callback frames use the monitor.
    private var dialog:android.app.Dialog?=null
    private var texture:android.view.TextureView?=null
    private var camera:android.hardware.camera2.CameraDevice?=null
    private var session:android.hardware.camera2.CameraCaptureSession?=null
    private var reader:android.media.ImageReader?=null
    private var surface:android.view.Surface?=null
    private var thread:android.os.HandlerThread?=null
    fun available():Boolean = QR_CAMERA && try {
        activity.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_CAMERA_ANY) &&
            activity.getSystemService(android.hardware.camera2.CameraManager::class.java).cameraIdList.isNotEmpty()
    } catch(_:Exception) {false}
    @Synchronized fun state(request:Long):Int = if(request==id && id>0) status else 1
    @Synchronized private fun running(request:Long):Boolean = request==id && id>0 && status==0 && android.os.SystemClock.elapsedRealtime()<deadline
    @Synchronized fun takeFrame(request:Long):ByteArray? = if(running(request)) frame.also{frame=null} else null
    fun start():Long {
        if(!available()) return 0
        val request=synchronized(this) {
            if(id!=0L || permissionId!=0L) return 0
            next++; id=next; status=0; deadline=android.os.SystemClock.elapsedRealtime()+30000; offered=0
            frame?.fill(0);frame=null;id
        }
        activity.runOnUiThread {
            if(!running(request)) return@runOnUiThread
            if((activity.qvStatus() and 7)!=7){end(request,1);return@runOnUiThread}
            handler.postDelayed({end(request,1)},30000)
            if(activity.checkSelfPermission(android.Manifest.permission.CAMERA)!=android.content.pm.PackageManager.PERMISSION_GRANTED) {
                synchronized(this){permissionId=request}
                try {activity.requestPermissions(arrayOf(android.Manifest.permission.CAMERA),PERMISSION)} catch(_:Exception){end(request,2)}
            } else show(request)
        }
        return request
    }
    @Synchronized fun awaitingPermission():Boolean = permissionId!=0L
    fun permission(granted:Boolean) {
        val request=synchronized(this){permissionId.also{permissionId=0}}
        if(!running(request)) return
        if(!granted){end(request,2);return}
        // The result arrives before onResume: open the camera once the activity
        // is in front again, or end the scan if it is not.
        handler.post {
            if(!running(request)) return@post
            if((activity.qvStatus() and 7) == 7) show(request) else end(request,1)
        }
    }
    fun cancel() {val request=synchronized(this){id};if(request>0) end(request,1)}
    fun finish(request:Long) = activity.runOnUiThread {
        end(request,1)
        synchronized(this) {if(id==request){id=0;frame?.fill(0);frame=null}}
    }
    private fun end(request:Long,result:Int) {
        synchronized(this) {
            if(request!=id || id==0L) return
            status=result;frame?.fill(0);frame=null
        }
        var clean=true
        fun attempt(close:()->Unit){try{close()}catch(_:Exception){clean=false}}
        attempt{session?.close()};session=null
        attempt{camera?.close()};camera=null
        attempt{reader?.close()};reader=null
        attempt{surface?.release()};surface=null
        attempt{thread?.quitSafely()};thread=null
        attempt{texture?.surfaceTextureListener=null};texture=null
        attempt{dialog?.setOnDismissListener(null)}
        attempt{dialog?.dismiss()};dialog=null
        if(!clean)synchronized(this){if(id==request)status=2}
    }
    private fun show(request:Long) {
        if(!running(request)) return
        try {
        val layout=android.widget.LinearLayout(activity).apply{orientation=android.widget.LinearLayout.VERTICAL}
        layout.addView(android.widget.TextView(activity).apply{text="Scan the other device's QuickVault QR code. No image is saved."})
        val preview=android.view.TextureView(activity)
        layout.addView(preview,android.widget.LinearLayout.LayoutParams(-1,0,1f))
        layout.addView(android.widget.Button(activity).apply{text="Cancel scan";setOnClickListener{end(request,1)}})
        val window=android.app.Dialog(activity)
        dialog=window
        window.setContentView(layout)
        val protected=window.window
        if(protected==null){end(request,2);return}
        protected.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if((protected.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE)==0){end(request,2);return}
        window.setOnCancelListener{end(request,1)}
        window.setOnDismissListener{end(request,1)}
        dialog=window;texture=preview
        preview.surfaceTextureListener=object:android.view.TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(t:android.graphics.SurfaceTexture,w:Int,h:Int){open(request,t)}
            override fun onSurfaceTextureSizeChanged(t:android.graphics.SurfaceTexture,w:Int,h:Int){}
            override fun onSurfaceTextureUpdated(t:android.graphics.SurfaceTexture){}
            override fun onSurfaceTextureDestroyed(t:android.graphics.SurfaceTexture):Boolean{end(request,1);return true}
        }
        window.show()
        window.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.MATCH_PARENT)
        } catch(_:Exception){end(request,2)}
    }
    @Suppress("DEPRECATION")
    private fun open(request:Long,t:android.graphics.SurfaceTexture) {
        if(!running(request)) return
        try {
            val manager=activity.getSystemService(android.hardware.camera2.CameraManager::class.java)
            val cameras=manager.cameraIdList
            val selected=cameras.firstOrNull{manager.getCameraCharacteristics(it).get(android.hardware.camera2.CameraCharacteristics.LENS_FACING)==android.hardware.camera2.CameraCharacteristics.LENS_FACING_BACK}?:cameras.firstOrNull()
            if(selected==null){end(request,2);return}
            val chars=manager.getCameraCharacteristics(selected)
            val sizes=chars.get(android.hardware.camera2.CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)?.getOutputSizes(android.graphics.ImageFormat.YUV_420_888)
            val size=sizes?.filter{it.width in 160..MAX_AXIS && it.height in 120..MAX_AXIS && it.width.toLong()*it.height<=MAX_PIXELS}
                ?.minByOrNull{kotlin.math.abs(it.width-640)+kotlin.math.abs(it.height-480)}
            if(size==null){end(request,2);return}
            t.setDefaultBufferSize(size.width,size.height)
            val target=android.view.Surface(t);surface=target
            val images=android.media.ImageReader.newInstance(size.width,size.height,android.graphics.ImageFormat.YUV_420_888,2);reader=images
            val worker=android.os.HandlerThread("qv-camera").apply{start()};thread=worker
            images.setOnImageAvailableListener({source->
                var image:android.media.Image?=null
                try {
                    image=source.acquireLatestImage()
                    val current=image
                    if(current!=null && running(request)) {
                        val now=android.os.SystemClock.elapsedRealtime()
                        val ready=synchronized(this){now-offered>=500 && frame==null}
                        if(ready) {
                            val p=current.planes[0]
                            val bytes=packFrame(current.width,current.height,p.rowStride,p.pixelStride,p.buffer)
                            if(bytes==null) activity.runOnUiThread{end(request,2)}
                            else synchronized(this) {
                                if(running(request)){frame?.fill(0);frame=bytes;offered=now}else bytes.fill(0)
                            }
                        }
                    }
                } catch(_:Exception){activity.runOnUiThread{if(running(request))end(request,2)}}
                finally {image?.close()}
            },android.os.Handler(worker.looper))
            manager.openCamera(selected,object:android.hardware.camera2.CameraDevice.StateCallback(){
                override fun onOpened(device:android.hardware.camera2.CameraDevice){
                    if(!running(request)){device.close();return}
                    camera=device
                    try { device.createCaptureSession(listOf(target,images.surface),object:android.hardware.camera2.CameraCaptureSession.StateCallback(){
                        override fun onConfigured(active:android.hardware.camera2.CameraCaptureSession){
                            if(!running(request)){active.close();return}
                            try {
                                session=active
                                val capture=device.createCaptureRequest(android.hardware.camera2.CameraDevice.TEMPLATE_PREVIEW)
                                capture.addTarget(target);capture.addTarget(images.surface)
                                val modes=chars.get(android.hardware.camera2.CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES)
                                if(modes?.contains(android.hardware.camera2.CameraMetadata.CONTROL_AF_MODE_CONTINUOUS_PICTURE)==true)
                                    capture.set(android.hardware.camera2.CaptureRequest.CONTROL_AF_MODE,android.hardware.camera2.CameraMetadata.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                                active.setRepeatingRequest(capture.build(),null,handler)
                            }catch(_:Exception){end(request,2)}
                        }
                        override fun onConfigureFailed(active:android.hardware.camera2.CameraCaptureSession){runCatching{active.close()};end(request,2)}
                    },handler) } catch(_:Exception){end(request,2)}
                }
                override fun onDisconnected(device:android.hardware.camera2.CameraDevice){runCatching{device.close()};end(request,2)}
                override fun onError(device:android.hardware.camera2.CameraDevice,error:Int){runCatching{device.close()};end(request,2)}
            },handler)
        } catch(_:Exception){end(request,2)}
    }
}
