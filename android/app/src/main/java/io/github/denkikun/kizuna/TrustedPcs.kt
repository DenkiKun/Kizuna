package io.github.denkikun.kizuna

import android.content.Context

/** Paired PCs, stored by fingerprint (hex) → name in the app's private storage. */
class TrustedPcs(context: Context) {
    private val prefs = context.getSharedPreferences("trusted_pcs", Context.MODE_PRIVATE)

    fun nameOf(fingerprint: ByteArray): String? = prefs.getString(Hex.encode(fingerprint), null)

    /** `true` if a paired PC has this device ID (the start of its fingerprint). */
    fun isPaired(deviceId: String): Boolean = prefs.all.keys.any { it.startsWith(deviceId) }

    fun add(fingerprint: ByteArray, name: String) {
        prefs.edit().putString(Hex.encode(fingerprint), name).apply()
    }
}
