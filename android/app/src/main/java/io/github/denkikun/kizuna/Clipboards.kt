package io.github.denkikun.kizuna

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context

/** Longer texts are not sent (the PC applies the same limit). */
const val MAX_CLIPBOARD_CHARS = 200_000

/**
 * The phone's clipboard, kept in step with the computer's.
 *
 * Text from the computer is applied right away. Text copied here is sent
 * while Kizuna is in front (Android lets no app read the clipboard in the
 * background), or when the user asks, from the notification or the quick
 * settings tile.
 */
object Clipboards {
    /** The last text received from, or sent to, the computer: not sent back. */
    @Volatile
    private var last: String? = null

    enum class SendResult { SENT, UNCHANGED, EMPTY, TOO_LONG, NOT_CONNECTED }

    fun apply(context: Context, text: String) {
        if (!AppSettings.syncClipboard(context)) return
        last = text
        val manager = context.getSystemService(ClipboardManager::class.java)
        manager.setPrimaryClip(ClipData.newPlainText("Kizuna", text))
    }

    /** Sends the current clipboard text; the caller must be in front to read it. */
    fun sendCurrent(context: Context): SendResult {
        if (!AppSettings.syncClipboard(context)) return SendResult.NOT_CONNECTED
        val manager = context.getSystemService(ClipboardManager::class.java)
        val clip = manager.primaryClip?.takeIf { it.itemCount > 0 } ?: return SendResult.EMPTY
        val text = clip.getItemAt(0).coerceToText(context)?.toString().orEmpty()
        return when {
            text.isEmpty() -> SendResult.EMPTY
            text.length > MAX_CLIPBOARD_CHARS -> SendResult.TOO_LONG
            text == last -> SendResult.UNCHANGED
            Link.send(Message.ClipboardUpdate(text)) -> {
                last = text
                SendResult.SENT
            }
            else -> SendResult.NOT_CONNECTED
        }
    }
}
