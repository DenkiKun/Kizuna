package io.github.denkikun.kizuna

import android.content.Context

/** Small user choices that persist between launches. */
object AppSettings {
    private const val FILE = "settings"
    private const val AUTO_CONNECT = "auto_connect"
    private const val FORWARD_NOTIFICATIONS = "forward_notifications"
    private const val SYNC_CLIPBOARD = "sync_clipboard"

    /** Whether to keep connected to the paired PC (off after the user disconnects). */
    fun autoConnect(context: Context): Boolean =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(AUTO_CONNECT, true)

    fun setAutoConnect(context: Context, enabled: Boolean) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putBoolean(AUTO_CONNECT, enabled).apply()
    }

    /** Whether to forward the phone's notifications to the PC (needs notification access too). */
    fun forwardNotifications(context: Context): Boolean =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(FORWARD_NOTIFICATIONS, true)

    /** Whether to keep the clipboard in step with the PC. */
    fun syncClipboard(context: Context): Boolean =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(SYNC_CLIPBOARD, true)

    fun setSyncClipboard(context: Context, enabled: Boolean) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putBoolean(SYNC_CLIPBOARD, enabled).apply()
    }

    fun setForwardNotifications(context: Context, enabled: Boolean) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putBoolean(FORWARD_NOTIFICATIONS, enabled).apply()
    }
}
