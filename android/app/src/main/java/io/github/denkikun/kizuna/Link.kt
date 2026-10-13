package io.github.denkikun.kizuna

import java.io.IOException
import java.util.concurrent.CopyOnWriteArraySet
import kotlin.concurrent.thread

/** How often the phone pings the PC while connected. */
const val PING_INTERVAL_MS = 30_000L

/** A PC that sends nothing (not even `pong`) for this long is considered gone. */
const val IDLE_TIMEOUT_MS = 90_000

/** State of the connection to the paired PC, shown in the notification and the app. */
sealed class LinkState {
    /** The connection service is not running. */
    data object Off : LinkState()
    data object Searching : LinkState()
    data class Connecting(val name: String) : LinkState()
    data class Connected(val name: String, val address: String) : LinkState()
    data class Retrying(val name: String, val seconds: Int) : LinkState()
}

/** Current [LinkState], for the service to publish and the UI to observe. */
object Link {
    @Volatile
    var state: LinkState = LinkState.Off
        private set

    private val observers = CopyOnWriteArraySet<(LinkState) -> Unit>()

    /** Calls `observer` now and on every change (on the publishing thread). */
    fun observe(observer: (LinkState) -> Unit) {
        observers += observer
        observer(state)
    }

    fun stopObserving(observer: (LinkState) -> Unit) {
        observers -= observer
    }

    fun publish(newState: LinkState) {
        if (newState == state) return
        state = newState
        observers.forEach { it(newState) }
    }
}

/**
 * A session with a paired PC: pings every [pingIntervalMs], answers the PC's
 * pings and hands other messages to [onMessage]. [run] blocks until the PC
 * closes the connection or the channel fails (e.g. the read timeout expires).
 */
class Session(
    private val channel: LineChannel,
    private val pingIntervalMs: Long = PING_INTERVAL_MS,
    private val onMessage: (Message) -> Unit = {},
) {
    @Volatile
    private var open = true

    fun run() {
        val pinger = thread(name = "kizuna-ping", isDaemon = true) {
            try {
                while (open) {
                    Thread.sleep(pingIntervalMs)
                    if (open) channel.send(Message.Ping)
                }
            } catch (e: InterruptedException) {
                // Session over.
            } catch (e: IOException) {
                // The reader will notice the broken connection too.
            }
        }
        try {
            while (true) {
                when (val message = channel.receive() ?: return) {
                    Message.Ping -> channel.send(Message.Pong)
                    Message.Pong -> Unit
                    else -> onMessage(message)
                }
            }
        } finally {
            open = false
            pinger.interrupt()
        }
    }
}
