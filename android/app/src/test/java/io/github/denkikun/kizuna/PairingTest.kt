package io.github.denkikun.kizuna

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** The phone's pairing against an in-memory PC that follows docs/PROTOCOL.md. */
class PairingTest {
    private val phoneFp = ByteArray(32) { 0xaa.toByte() }
    private val pcFp = ByteArray(32) { 0xbb.toByte() }

    private class Link {
        private val toPc = PipedOutputStream()
        private val toPhone = PipedOutputStream()
        val phone = LineChannel(PipedInputStream(toPhone, 1 shl 16), toPc)
        val pc = LineChannel(PipedInputStream(toPc, 1 shl 16), toPhone)
    }

    /** A PC responder; `decision` = null means its user never answers. */
    private fun pc(link: Link, decision: Boolean?, honest: Boolean = true): CompletableFuture<Pair<Int?, Message?>> {
        val result = CompletableFuture<Pair<Int?, Message?>>()
        thread(isDaemon = true) {
            try {
                val request = link.pc.receive() as Message.PairRequest
                assertEquals("Phone", request.deviceName)
                val nb = PairingCrypto.randomNonce()
                val committed = if (honest) nb else PairingCrypto.randomNonce()
                link.pc.send(Message.PairCommit("PC", Hex.encode(PairingCrypto.commitment(committed, pcFp, phoneFp))))
                val na = Hex.decode((link.pc.receive() as Message.PairNonce).nonce, 32)!!
                link.pc.send(Message.PairNonce(Hex.encode(nb)))
                val code = PairingCrypto.code(phoneFp, pcFp, na, nb)
                when (decision) {
                    true -> link.pc.send(Message.PairAccept)
                    false -> link.pc.send(Message.PairReject)
                    null -> Unit
                }
                result.complete(code to link.pc.receive())
            } catch (e: Throwable) {
                result.completeExceptionally(e)
            }
        }
        return result
    }

    private fun pairing(link: Link) = Pairing(link.phone, {}, phoneFp, pcFp, "Phone")

    @Test
    fun bothAcceptAndSeeTheSameCode() {
        val link = Link()
        val pc = pc(link, decision = true)
        val pairing = pairing(link)
        var shownCode: Int? = null
        val outcome = pairing.run { prompt ->
            shownCode = prompt.code
            assertEquals("PC", prompt.peerName)
            pairing.decide(true)
        }
        assertEquals(PairingOutcome.Paired("PC"), outcome)
        val (pcCode, last) = pc.get(5, TimeUnit.SECONDS)
        assertEquals(pcCode, shownCode)
        assertEquals(Message.PairAccept, last)
    }

    @Test
    fun phoneRejects() {
        val link = Link()
        val pc = pc(link, decision = true)
        val pairing = pairing(link)
        assertEquals(PairingOutcome.RejectedLocally, pairing.run { pairing.decide(false) })
        assertEquals(Message.PairReject, pc.get(5, TimeUnit.SECONDS).second)
    }

    @Test
    fun pcRejectionEndsPairingWhileTheUserIsStillDeciding() {
        val link = Link()
        pc(link, decision = false)
        val started = System.nanoTime()
        // The phone user never answers.
        val outcome = pairing(link).run { }
        assertEquals(PairingOutcome.RejectedByPeer, outcome)
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(5))
    }

    @Test
    fun nonceThatDoesNotMatchTheCommitmentIsDetected() {
        val link = Link()
        val pc = pc(link, decision = true, honest = false)
        try {
            pairing(link).run { fail("must not ask the user") }
            fail("expected PairingException")
        } catch (e: PairingException) {
            assertTrue(e.message!!.contains("commitment"))
        }
        assertEquals(Message.PairReject, pc.get(5, TimeUnit.SECONDS).second)
    }
}
