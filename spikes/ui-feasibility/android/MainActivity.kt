// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.dioxus.main

import android.os.Bundle
import android.view.WindowManager
import android.content.Context
import android.content.pm.PackageManager
import android.service.autofill.AutofillService
import android.service.autofill.FillRequest
import android.service.autofill.FillCallback
import android.service.autofill.SaveRequest
import android.service.autofill.SaveCallback
import android.os.CancellationSignal

typealias BuildConfig = org.quickvault.feasibility.BuildConfig

// Only lifecycle flags and public API availability; never secret text.
class MainActivity : WryActivity() {
    @Volatile private var background = false
    @Volatile private var destroyed = false
    override fun onCreate(state: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(state)
    }
    override fun onPause() { background = true; super.onPause() }
    override fun onResume() { super.onResume(); background = false }
    override fun onDestroy() { background = true; destroyed = true; super.onDestroy() }
    fun qvIsBackground(): Boolean = background
    fun qvIsDestroyed(): Boolean = destroyed
    fun qvProbeSummary(): String {
        val keyStore = runCatching {
            java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            true
        }.getOrDefault(false)
        val fingerprint = packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        val face = packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) != null
        val autofill = packageManager.hasSystemFeature(PackageManager.FEATURE_AUTOFILL)
        // No key generation, authentication, clipboard read/write or provider activation.
        return "Keystore API=$keyStore; fingerprint API=$fingerprint; face API=$face; clipboard API=$clipboard; autofill API=$autofill. Availability only; quick unlock/autofill disabled."
    }
}

// Registration/packaging probe only: never inspect a requesting app or save/fill data.
class FeasibilityAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, signal: CancellationSignal, callback: FillCallback) {
        callback.onFailure("Feasibility probe is disabled")
    }
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onFailure("Feasibility probe is disabled")
    }
}
