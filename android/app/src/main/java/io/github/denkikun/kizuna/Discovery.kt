package io.github.denkikun.kizuna

import android.annotation.TargetApi
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/** A Kizuna PC found on the local network. */
data class FoundPc(val id: String, val name: String, val host: InetAddress, val port: Int)

/**
 * Looks for Kizuna PCs over mDNS (`_kizuna._tcp`) and, for networks that block
 * multicast (e.g. phone hotspots), over UDP broadcast (see docs/PROTOCOL.md).
 * `onChange` is called on a background thread with the current list.
 */
class Discovery(context: Context, private val onChange: (List<FoundPc>) -> Unit) {
    private val nsd = context.getSystemService(NsdManager::class.java)
    private val executor = Executors.newSingleThreadExecutor()
    private val found = LinkedHashMap<String, FoundPc>()
    private var listener: NsdManager.DiscoveryListener? = null

    /** Before Android 14 only one resolve may run at a time, so they are queued. */
    private val pendingResolves = ArrayDeque<NsdServiceInfo>()
    private var resolving = false

    /** When each PC found by broadcast last answered (they have no "lost" event). */
    private val lastAnswer = HashMap<String, Long>()
    @Volatile private var probing = false
    private var prober: Thread? = null

    fun start() {
        if (listener != null) return
        startProbing()
        val l = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onDiscoveryStopped(serviceType: String) = Unit
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.w(TAG, "discovery failed to start: $errorCode")
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
            override fun onServiceFound(info: NsdServiceInfo) = executor.execute { resolve(info) }
            override fun onServiceLost(info: NsdServiceInfo) = executor.execute {
                if (found.remove(info.serviceName) != null) publish()
            }
        }
        listener = l
        nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, l)
    }

    fun stop() {
        listener?.let { runCatching { nsd.stopServiceDiscovery(it) } }
        listener = null
        probing = false
        prober?.interrupt()
        prober = null
        executor.execute {
            found.clear()
            lastAnswer.clear()
            pendingResolves.clear()
            publish()
        }
    }

    /** Broadcasts a probe every few seconds and collects the PCs' replies. */
    private fun startProbing() {
        probing = true
        prober = thread(name = "kizuna-probe", isDaemon = true) {
            try {
                DatagramSocket(null).use { socket ->
                    socket.broadcast = true
                    socket.soTimeout = 1000
                    socket.bind(InetSocketAddress(0))
                    val buffer = ByteArray(2048)
                    var nextProbe = 0L
                    while (probing) {
                        val now = System.currentTimeMillis()
                        if (now >= nextProbe) {
                            sendProbes(socket)
                            nextProbe = now + PROBE_INTERVAL_MS
                            executor.execute { forgetSilentPcs(now) }
                        }
                        val packet = DatagramPacket(buffer, buffer.size)
                        try {
                            socket.receive(packet)
                        } catch (e: SocketTimeoutException) {
                            continue
                        }
                        val host = packet.address as? Inet4Address ?: continue
                        val announcement = BroadcastDiscovery.parseAnnouncement(packet.data.copyOf(packet.length))
                            ?: continue
                        executor.execute { acceptAnnouncement(announcement, host) }
                    }
                }
            } catch (e: Exception) {
                if (probing) Log.w(TAG, "broadcast discovery stopped", e)
            }
        }
    }

    private fun sendProbes(socket: DatagramSocket) {
        val probe = BroadcastDiscovery.probe()
        val targets = linkedSetOf<InetAddress>(InetAddress.getByName("255.255.255.255"))
        // Also each interface's subnet broadcast: some networks drop 255.255.255.255.
        runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .filter { it.isUp && !it.isLoopback }
                .flatMap { it.interfaceAddresses }
                .mapNotNullTo(targets) { it.broadcast }
        }
        for (target in targets) {
            runCatching { socket.send(DatagramPacket(probe, probe.size, target, BroadcastDiscovery.PORT)) }
        }
    }

    private fun acceptAnnouncement(announcement: BroadcastDiscovery.Announcement, host: InetAddress) {
        lastAnswer[announcement.id] = System.currentTimeMillis()
        val pc = FoundPc(announcement.id, announcement.name, host, announcement.port)
        if (found[pc.id] != pc) {
            found[pc.id] = pc
            publish()
        }
    }

    private fun forgetSilentPcs(now: Long) {
        val silent = lastAnswer.filterValues { now - it > 3 * PROBE_INTERVAL_MS }.keys
        if (silent.isEmpty()) return
        silent.forEach { lastAnswer.remove(it); found.remove(it) }
        publish()
    }

    private fun resolve(info: NsdServiceInfo) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            resolveWithCallback(info)
        } else {
            pendingResolves.addLast(info)
            resolveNext()
        }
    }

    @TargetApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private fun resolveWithCallback(info: NsdServiceInfo) {
        nsd.registerServiceInfoCallback(info, executor, object : NsdManager.ServiceInfoCallback {
            override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {
                Log.w(TAG, "resolve failed: $errorCode")
            }
            override fun onServiceUpdated(resolved: NsdServiceInfo) {
                val host = resolved.hostAddresses.firstOrNull { it is Inet4Address }
                accept(resolved, host)
                runCatching { nsd.unregisterServiceInfoCallback(this) }
            }
            override fun onServiceLost() = Unit
            override fun onServiceInfoCallbackUnregistered() = Unit
        })
    }

    @Suppress("DEPRECATION")
    private fun resolveNext() {
        if (resolving) return
        val info = pendingResolves.removeFirstOrNull() ?: return
        resolving = true
        nsd.resolveService(info, object : NsdManager.ResolveListener {
            override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) = executor.execute {
                resolving = false
                resolveNext()
            }
            override fun onServiceResolved(resolved: NsdServiceInfo) = executor.execute {
                resolving = false
                accept(resolved, resolved.host?.takeIf { it is Inet4Address })
                resolveNext()
            }
        })
    }

    /** Keeps the service if it is a valid announcement of a compatible PC. */
    private fun accept(info: NsdServiceInfo, host: InetAddress?) {
        val id = info.serviceName
        val attributes = info.attributes
        val version = attributes["v"]?.toString(Charsets.UTF_8)
        if (host == null || info.port == 0 || version != PROTOCOL_VERSION || !isDeviceId(id)) return
        val name = attributes["name"]?.toString(Charsets.UTF_8)
            ?.takeIf { it.isNotBlank() }?.let(::cleanDeviceName) ?: id
        found[id] = FoundPc(id, name, host, info.port)
        publish()
    }

    private fun publish() = onChange(found.values.toList())

    companion object {
        private const val TAG = "KizunaDiscovery"
        const val SERVICE_TYPE = "_kizuna._tcp"
        const val PROTOCOL_VERSION = "0"
        private const val PROBE_INTERVAL_MS = 5_000L

        fun isDeviceId(id: String) = id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' }
    }
}
