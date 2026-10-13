package io.github.denkikun.kizuna

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class SessionTest {
    /** The phone's channel and the PC's end of the same connection. */
    private class Link {
        private val toPc = PipedOutputStream()
        private val toPhone = PipedOutputStream()
        val phone = LineChannel(PipedInputStream(toPhone, 1 shl 16), toPc)
        val pc = LineChannel(PipedInputStream(toPc, 1 shl 16), toPhone)
        fun closeFromPc() = toPhone.close()
    }

    @Test
    fun answersPingsSendsPingsAndEndsWhenThePcCloses() {
        val link = Link()
        val received = CopyOnWriteArrayList<Message>()
        val session = thread { Session(link.phone, pingIntervalMs = 200, onMessage = { received += it }).run() }

        link.pc.send(Message.Ping)
        assertEquals(Message.Pong, link.pc.receive())
        // The next thing the phone sends unprompted is its own ping.
        assertEquals(Message.Ping, link.pc.receive())

        link.pc.send(Message.Pong)
        link.pc.send(Message.PairNonce("ab"))
        link.closeFromPc()
        session.join(TimeUnit.SECONDS.toMillis(5))

        assertTrue("session should end when the PC closes", !session.isAlive)
        assertEquals(listOf<Message>(Message.PairNonce("ab")), received.toList())
    }
}
