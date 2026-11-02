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
    private val quick by lazy { NativeQuickUnlock(this) }
    fun qvQuickAvailable(): Boolean = quick.available()
    fun qvQuickStart(encrypt:Boolean,binding:ByteArray,policy:Int,payload:ByteArray):Long = quick.start(encrypt,binding,policy,payload)
    fun qvQuickState(id:Long):Int = quick.status(id)
    fun qvQuickEvidence(id:Long):String = quick.evidence(id)
    fun qvQuickFailureKind(id:Long):Int = quick.failureKind(id)
    fun qvQuickResult(id:Long):ByteArray? = quick.result(id)
    fun qvQuickFinish(id:Long,keep:Boolean) = quick.finish(id,keep)
    fun qvQuickDelete(envelope:ByteArray):Boolean = quick.delete(envelope)

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
