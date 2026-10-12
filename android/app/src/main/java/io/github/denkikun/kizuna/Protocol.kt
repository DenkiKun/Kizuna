package io.github.denkikun.kizuna

import org.json.JSONException
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

/** Maximum size of a message (one line), so a malicious peer cannot exhaust memory. */
const val MAX_MESSAGE_LEN = 1024 * 1024

/** Maximum length of a device name, in characters (Unicode code points). */
private const val MAX_NAME_CHARS = 64

class ProtocolException(message: String) : Exception(message)

/** Protocol messages (see docs/PROTOCOL.md). One per line, in JSON. */
sealed class Message(val type: String) {
    data class PairRequest(val deviceName: String) : Message("pair.request")
    data class PairCommit(val deviceName: String, val commitment: String) : Message("pair.commit")
    data class PairNonce(val nonce: String) : Message("pair.nonce")
    data object PairAccept : Message("pair.accept")
    data object PairReject : Message("pair.reject")

    /** A valid message this version of the app does not handle yet. */
    data class Other(val kind: String) : Message(kind)

    fun toJson(): String {
        val body = when (this) {
            is PairRequest -> JSONObject().put("device_name", deviceName)
            is PairCommit -> JSONObject().put("device_name", deviceName).put("commitment", commitment)
            is PairNonce -> JSONObject().put("nonce", nonce)
            PairAccept, PairReject -> null
            is Other -> throw IllegalStateException("cannot send $kind")
        }
        val json = JSONObject().put("type", type)
        if (body != null) json.put("body", body)
        return json.toString()
    }

    companion object {
        fun parse(line: String): Message {
            try {
                val json = JSONObject(line)
                val body = json.optJSONObject("body")
                return when (val type = json.getString("type")) {
                    "pair.request" -> PairRequest(body!!.getString("device_name"))
                    "pair.commit" -> PairCommit(body!!.getString("device_name"), body.getString("commitment"))
                    "pair.nonce" -> PairNonce(body!!.getString("nonce"))
                    "pair.accept" -> PairAccept
                    "pair.reject" -> PairReject
                    else -> Other(type)
                }
            } catch (e: JSONException) {
                throw ProtocolException("invalid message")
            } catch (e: NullPointerException) {
                throw ProtocolException("invalid message: missing body")
            }
        }
    }
}

/** Newline-delimited JSON over a pair of streams. */
class LineChannel(input: InputStream, private val output: OutputStream) {
    private val input = BufferedInputStream(input)

    fun send(message: Message) {
        val line = (message.toJson() + "\n").toByteArray(Charsets.UTF_8)
        synchronized(output) {
            output.write(line)
            output.flush()
        }
    }

    /** Next message; `null` if the connection was closed between messages. */
    fun receive(): Message? {
        val line = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b == -1) {
                if (line.size() == 0) return null
                throw ProtocolException("connection closed in the middle of a message")
            }
            if (b == '\n'.code) break
            if (line.size() >= MAX_MESSAGE_LEN) throw ProtocolException("message too large")
            line.write(b)
        }
        return Message.parse(line.toString(Charsets.UTF_8.name()))
    }
}

/**
 * Cleans a device name received from the network before showing it: removes
 * control and bidirectional control characters and limits the length. Same
 * rules as the PC.
 */
fun cleanDeviceName(name: String): String {
    val cleaned = StringBuilder()
    var count = 0
    var i = 0
    while (i < name.length && count < MAX_NAME_CHARS) {
        val cp = name.codePointAt(i)
        i += Character.charCount(cp)
        if (isUnsafe(cp)) continue
        cleaned.appendCodePoint(cp)
        count++
    }
    val result = cleaned.toString().trim()
    return result.ifEmpty { "Unnamed device" }
}

private fun isUnsafe(cp: Int): Boolean =
    Character.isISOControl(cp) ||
        cp in 0x200B..0x200F || cp in 0x202A..0x202E || cp in 0x2066..0x2069
