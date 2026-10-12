package io.github.denkikun.kizuna

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Maximum time for each automatic step of the protocol. */
const val STEP_TIMEOUT_MS = 10_000

/** Time for the users to compare the code and decide. */
const val DECISION_TIMEOUT_MS = 90_000

class PairingException(message: String) : Exception(message)

/** What the user has to confirm. */
class PairingPrompt(val peerName: String, val peerFingerprint: ByteArray, val code: Int)

sealed class PairingOutcome {
    data class Paired(val peerName: String) : PairingOutcome()
    data object RejectedLocally : PairingOutcome()
    data object RejectedByPeer : PairingOutcome()
}

/**
 * Pairs as the initiator (the side that opened the connection), following
 * docs/PROTOCOL.md. [run] blocks, so it must be called on a background thread;
 * the UI shows the code from `onCode` and reports the user's answer with
 * [decide].
 *
 * @param setReadTimeout sets the read timeout of the underlying socket.
 */
class Pairing(
    private val channel: LineChannel,
    private val setReadTimeout: (Int) -> Unit,
    private val ownFingerprint: ByteArray,
    private val peerFingerprint: ByteArray,
    private val ownName: String,
) {
    private sealed class Event {
        class User(val accepted: Boolean) : Event()
        class Peer(val message: Message?, val error: Exception?) : Event()
    }

    private val events = LinkedBlockingQueue<Event>()

    /** Reports the local user's decision (from any thread). */
    fun decide(accepted: Boolean) {
        events.offer(Event.User(accepted))
    }

    fun run(onCode: (PairingPrompt) -> Unit): PairingOutcome {
        setReadTimeout(STEP_TIMEOUT_MS)
        channel.send(Message.PairRequest(ownName))

        val (peerName, commitment) = when (val m = receive()) {
            is Message.PairCommit -> cleanDeviceName(m.deviceName) to
                (Hex.decode(m.commitment, 32) ?: throw PairingException("invalid commitment"))
            Message.PairReject -> return PairingOutcome.RejectedByPeer
            else -> throw PairingException("expected pair.commit, got ${m.type}")
        }

        val ownNonce = PairingCrypto.randomNonce()
        channel.send(Message.PairNonce(Hex.encode(ownNonce)))
        val peerNonce = when (val m = receive()) {
            is Message.PairNonce -> Hex.decode(m.nonce, PairingCrypto.NONCE_LEN)
                ?: throw PairingException("invalid nonce")
            Message.PairReject -> return PairingOutcome.RejectedByPeer
            else -> throw PairingException("expected pair.nonce, got ${m.type}")
        }

        if (!PairingCrypto.commitment(peerNonce, peerFingerprint, ownFingerprint).contentEquals(commitment)) {
            runCatching { channel.send(Message.PairReject) }
            throw PairingException("the nonce does not match the commitment (possible attack)")
        }

        val code = PairingCrypto.code(ownFingerprint, peerFingerprint, ownNonce, peerNonce)
        return decide(peerName, code, onCode)
    }

    /** Waits for the local user's decision and for the other side's, in any order. */
    private fun decide(peerName: String, code: Int, onCode: (PairingPrompt) -> Unit): PairingOutcome {
        setReadTimeout(DECISION_TIMEOUT_MS)
        thread(name = "kizuna-pairing-reader", isDaemon = true) {
            val event = try {
                Event.Peer(channel.receive(), null)
            } catch (e: Exception) {
                Event.Peer(null, e)
            }
            events.offer(event)
        }
        onCode(PairingPrompt(peerName, peerFingerprint, code))

        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(DECISION_TIMEOUT_MS.toLong())
        var peerAccepted = false
        var localAccepted: Boolean? = null
        while (true) {
            val remaining = deadline - System.nanoTime()
            val event = events.poll(remaining.coerceAtLeast(0), TimeUnit.NANOSECONDS)
                ?: if (localAccepted == null) Event.User(false) else throw PairingException("the other device stopped responding")
            when (event) {
                is Event.Peer -> {
                    when (val m = event.message) {
                        Message.PairAccept -> peerAccepted = true
                        Message.PairReject -> return PairingOutcome.RejectedByPeer
                        null -> throw PairingException(
                            event.error?.message ?: "connection closed during pairing",
                        )
                        else -> throw PairingException("expected pair.accept or pair.reject, got ${m.type}")
                    }
                    if (localAccepted == true) return PairingOutcome.Paired(peerName)
                }
                is Event.User -> {
                    if (localAccepted != null) continue
                    if (!event.accepted) {
                        runCatching { channel.send(Message.PairReject) }
                        return PairingOutcome.RejectedLocally
                    }
                    localAccepted = true
                    channel.send(Message.PairAccept)
                    if (peerAccepted) return PairingOutcome.Paired(peerName)
                }
            }
        }
    }

    private fun receive(): Message =
        channel.receive() ?: throw PairingException("connection closed during pairing")
}
