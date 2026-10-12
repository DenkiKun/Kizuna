package io.github.denkikun.kizuna

import android.annotation.TargetApi
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.util.Log
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.Executors

/** A Kizuna PC found on the local network. */
data class FoundPc(val id: String, val name: String, val host: InetAddress, val port: Int)

/**
 * Looks for Kizuna PCs over mDNS (`_kizuna._tcp`, see docs/PROTOCOL.md).
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

    fun start() {
        if (listener != null) return
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
        executor.execute {
            found.clear()
            pendingResolves.clear()
            publish()
        }
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

        fun isDeviceId(id: String) = id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' }
    }
}
