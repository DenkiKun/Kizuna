package io.github.denkikun.kizuna

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

/**
 * Forwards the phone's notifications to the connected PC, and tells it when
 * they are dismissed here. Only runs after the user grants notification access
 * in the system settings, and only while the forwarding setting is on.
 */
class NotificationForwarder : NotificationListenerService() {
    /** Last (title, text) sent per notification key, so updates that change nothing are not resent. */
    private val lastSent = object : LinkedHashMap<String, Pair<String, String>>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Pair<String, String>>?) = size > 200
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (!AppSettings.forwardNotifications(this)) return
        val posted = toMessage(sbn) ?: return
        synchronized(lastSent) {
            if (lastSent[posted.id] == posted.title to posted.text) return
            lastSent[posted.id] = posted.title to posted.text
        }
        if (!Link.send(posted)) Log.d(TAG, "not connected; dropped notification from ${sbn.packageName}")
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        val known = synchronized(lastSent) { lastSent.remove(sbn.key) != null }
        if (known) Link.send(Message.NotificationDismissed(sbn.key))
    }

    /** What to forward, or `null` for notifications that are not worth it. */
    private fun toMessage(sbn: StatusBarNotification): Message.NotificationPosted? {
        val notification = sbn.notification
        val flags = notification.flags
        if (sbn.packageName == packageName) return null
        if (sbn.isOngoing || !sbn.isClearable) return null
        if (flags and Notification.FLAG_GROUP_SUMMARY != 0) return null
        if (flags and Notification.FLAG_FOREGROUND_SERVICE != 0) return null
        if (notification.visibility == Notification.VISIBILITY_SECRET) return null

        val extras = notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()?.trim().orEmpty()
        val text = (extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_TEXT))?.toString()?.trim().orEmpty()
        if (title.isEmpty() && text.isEmpty()) return null
        return Message.NotificationPosted(sbn.key, appName(sbn.packageName), title, text)
    }

    private fun appName(packageName: String): String = try {
        val info = packageManager.getApplicationInfo(packageName, 0)
        packageManager.getApplicationLabel(info).toString()
    } catch (e: PackageManager.NameNotFoundException) {
        packageName
    }

    companion object {
        private const val TAG = "KizunaNotifications"

        /** Whether the user granted notification access to Kizuna. */
        fun hasAccess(context: Context): Boolean {
            val component = ComponentName(context, NotificationForwarder::class.java)
            return context.getSystemService(android.app.NotificationManager::class.java)
                .isNotificationListenerAccessGranted(component)
        }
    }
}
