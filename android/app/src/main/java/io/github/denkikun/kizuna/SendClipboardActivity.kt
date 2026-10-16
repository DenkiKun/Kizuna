package io.github.denkikun.kizuna

import android.app.Activity
import android.util.Log
import android.widget.Toast

/**
 * Invisible activity that sends the clipboard to the computer and closes.
 * Reading the clipboard needs a window in front, which is why this exists:
 * the notification action and the quick settings tile open it.
 */
class SendClipboardActivity : Activity() {
    private var done = false

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || done) return
        done = true
        val result = Clipboards.sendCurrent(this)
        Log.i("KizunaClipboard", "send from notification/tile: $result")
        val message = when (result) {
            Clipboards.SendResult.SENT -> R.string.clipboard_sent
            Clipboards.SendResult.UNCHANGED -> R.string.clipboard_unchanged
            Clipboards.SendResult.EMPTY -> R.string.clipboard_empty
            Clipboards.SendResult.TOO_LONG -> R.string.clipboard_too_long
            Clipboards.SendResult.NOT_CONNECTED -> R.string.clipboard_not_connected
        }
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        finish()
    }
}
