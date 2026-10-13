package io.github.denkikun.kizuna

import android.content.Context

/** Small user choices that persist between launches. */
object AppSettings {
    private const val FILE = "settings"
    private const val AUTO_CONNECT = "auto_connect"

    /** Whether to keep connected to the paired PC (off after the user disconnects). */
    fun autoConnect(context: Context): Boolean =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(AUTO_CONNECT, true)

    fun setAutoConnect(context: Context, enabled: Boolean) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putBoolean(AUTO_CONNECT, enabled).apply()
    }
}
