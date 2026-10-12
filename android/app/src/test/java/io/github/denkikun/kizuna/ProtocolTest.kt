package io.github.denkikun.kizuna

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class ProtocolTest {
    @Test
    fun jsonFormatMatchesThePc() {
        val request = JSONObject(Message.PairRequest("Pixel").toJson())
        assertEquals("pair.request", request.getString("type"))
        assertEquals("Pixel", request.getJSONObject("body").getString("device_name"))

        val accept = JSONObject(Message.PairAccept.toJson())
        assertEquals("pair.accept", accept.getString("type"))
        assertFalse(accept.has("body"))
    }

    @Test
    fun parsesMessagesSentByThePc() {
        assertEquals(
            Message.PairCommit("PC", "ab"),
            Message.parse("""{"type":"pair.commit","body":{"device_name":"PC","commitment":"ab"}}"""),
        )
        assertEquals(Message.PairReject, Message.parse("""{"type":"pair.reject"}"""))
        assertEquals(Message.Other("clipboard.update"), Message.parse("""{"type":"clipboard.update","body":{"text":"x"}}"""))
    }

    @Test(expected = ProtocolException::class)
    fun invalidJsonIsAnError() {
        Message.parse("""{"type":""")
    }

    @Test
    fun severalMessagesOnOneChannel() {
        val out = ByteArrayOutputStream()
        val writer = LineChannel(ByteArrayInputStream(ByteArray(0)), out)
        writer.send(Message.PairNonce("ab"))
        writer.send(Message.PairAccept)

        val reader = LineChannel(ByteArrayInputStream(out.toByteArray()), ByteArrayOutputStream())
        assertEquals(Message.PairNonce("ab"), reader.receive())
        assertEquals(Message.PairAccept, reader.receive())
        assertNull(reader.receive())
    }

    @Test(expected = ProtocolException::class)
    fun truncatedMessageIsAnError() {
        LineChannel(ByteArrayInputStream("""{"type":"pair.accept"}""".toByteArray()), ByteArrayOutputStream()).receive()
    }

    @Test(expected = ProtocolException::class)
    fun oversizedMessageIsRejected() {
        val huge = ByteArray(MAX_MESSAGE_LEN + 10) { 'x'.code.toByte() }
        LineChannel(ByteArrayInputStream(huge), ByteArrayOutputStream()).receive()
    }

    @Test
    fun namesFromTheNetworkAreCleaned() {
        assertEquals("Pixel 8", cleanDeviceName("  Pixel 8  "))
        assertEquals("[2J[31mPC", cleanDeviceName("\u001b[2J\u001b[31mPC\n"))
        assertEquals("abcfdp.exe", cleanDeviceName("abc\u202Efdp.exe"))
        assertEquals("Unnamed device", cleanDeviceName("\u0007\t"))
        assertEquals(64, cleanDeviceName("é".repeat(100)).codePointCount(0, 64))
    }
}
