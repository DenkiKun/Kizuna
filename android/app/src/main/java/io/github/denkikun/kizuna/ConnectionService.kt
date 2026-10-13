package io.github.denkikun.kizuna

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.net.Socket
import kotlin.concurrent.thread

/**
 * Keeps the connection to the paired PC: finds it on the network, connects,
 * keeps the session alive and reconnects when it drops. Runs as a foreground
 * service, so its notification is always visible while it is active.
 */
class ConnectionService : Service() {
    private lateinit var trusted: TrustedPcs
    private lateinit var discovery: Discovery
    private lateinit var notifications: NotificationManager
    private val lock = Object()
    private var found: List<FoundPc> = emptyList()
    @Volatile private var running = false
    @Volatile private var socket: Socket? = null
    private var worker: Thread? = null
    private val showState: (LinkState) -> Unit = { notifications.notify(NOTIFICATION_ID, notification(it)) }

    override fun onCreate() {
        super.onCreate()
        trusted = TrustedPcs(this)
        notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.channel_connection), NotificationManager.IMPORTANCE_LOW)
                .apply { description = getString(R.string.channel_connection_description) },
        )
        Link.publish(LinkState.Searching)
        startForeground(
            NOTIFICATION_ID,
            notification(Link.state),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
        )
        Link.observe(showState)
        discovery = Discovery(this) { pcs ->
            synchronized(lock) {
                found = pcs
                lock.notifyAll()
            }
        }
        discovery.start()
        running = true
        worker = thread(name = "kizuna-link", isDaemon = true) { keepConnected() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // "Disconnect" from the notification: stay off until the user connects again.
            AppSettings.setAutoConnect(this, false)
            stopSelf()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        runCatching { socket?.close() }
        synchronized(lock) { lock.notifyAll() }
        worker?.interrupt()
        discovery.stop()
        Link.stopObserving(showState)
        Link.publish(LinkState.Off)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun keepConnected() {
        val identity = DeviceIdentity.loadOrCreate()
        var delayMs = MIN_RETRY_MS
        while (running) {
            val pc = pairedPcOnNetwork()
            if (pc == null) {
                Link.publish(LinkState.Searching)
                waitForChange(SEARCH_POLL_MS)
                continue
            }
            try {
                Link.publish(LinkState.Connecting(pc.name))
                Tls.connect(pc.host, pc.port, identity).use { conn ->
                    val fingerprint = Hex.encode(conn.peerFingerprint)
                    val name = trusted.nameOf(conn.peerFingerprint)
                    // Only a PC we paired with, and the one that was announced.
                    if (name == null || !fingerprint.startsWith(pc.id)) return@use
                    socket = conn.socket
                    conn.socket.soTimeout = IDLE_TIMEOUT_MS
                    Link.publish(LinkState.Connected(name, pc.host.hostAddress ?: ""))
                    delayMs = MIN_RETRY_MS
                    Session(conn.channel).run()
                }
            } catch (e: Exception) {
                if (running) Log.i(TAG, "connection to ${pc.name} ended: ${e.message}")
            } finally {
                socket = null
            }
            if (!running) break
            Link.publish(LinkState.Retrying(pc.name, (delayMs / 1000).toInt()))
            waitForChange(delayMs)
            delayMs = (delayMs * 2).coerceAtMost(MAX_RETRY_MS)
        }
    }

    /** A PC on the network whose device ID matches a paired PC. */
    private fun pairedPcOnNetwork(): FoundPc? = synchronized(lock) {
        found.firstOrNull { trusted.isPaired(it.id) }
    }

    private fun waitForChange(timeoutMs: Long) {
        synchronized(lock) {
            try {
                lock.wait(timeoutMs)
            } catch (e: InterruptedException) {
                // Stopping.
            }
        }
    }

    private fun notification(state: LinkState): Notification {
        val (title, text) = when (state) {
            is LinkState.Connected -> getString(R.string.state_connected, state.name) to
                getString(R.string.state_connected_detail)
            is LinkState.Connecting -> getString(R.string.state_connecting, state.name) to ""
            is LinkState.Retrying -> getString(R.string.state_retrying, state.name) to
                getString(R.string.state_retrying_detail, state.seconds)
            LinkState.Searching, LinkState.Off -> getString(R.string.state_searching) to
                getString(R.string.state_searching_detail)
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ConnectionService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(null, getString(R.string.disconnect), stop).build())
            .build()
    }

    companion object {
        private const val TAG = "KizunaLink"
        private const val CHANNEL = "connection"
        private const val NOTIFICATION_ID = 1
        private const val ACTION_STOP = "io.github.denkikun.kizuna.STOP"
        private const val MIN_RETRY_MS = 2_000L
        private const val MAX_RETRY_MS = 30_000L
        private const val SEARCH_POLL_MS = 5_000L

        fun start(context: Context) {
            context.startForegroundService(Intent(context, ConnectionService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ConnectionService::class.java))
        }
    }
}
