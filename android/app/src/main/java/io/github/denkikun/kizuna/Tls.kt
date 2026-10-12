package io.github.denkikun.kizuna

import android.annotation.SuppressLint
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/** Established TLS 1.3 connection to a PC. */
class PeerConnection(val socket: SSLSocket, val peerFingerprint: ByteArray) : Closeable {
    val channel = LineChannel(socket.inputStream, socket.outputStream)

    override fun close() = socket.close()
}

object Tls {
    /**
     * Connects to a Kizuna PC, presenting this phone's certificate.
     *
     * The server's certificate is not validated here: the caller must check
     * [PeerConnection.peerFingerprint] (against the paired list, or by pairing).
     */
    fun connect(host: InetAddress, port: Int, identity: DeviceIdentity): PeerConnection {
        val context = SSLContext.getInstance("TLSv1.3")
        context.init(arrayOf(identity.keyManager()), arrayOf(AnyServerCertificate), SecureRandom())
        val socket = context.socketFactory.createSocket() as SSLSocket
        try {
            socket.enabledProtocols = arrayOf("TLSv1.3")
            socket.connect(InetSocketAddress(host, port), STEP_TIMEOUT_MS)
            socket.soTimeout = STEP_TIMEOUT_MS
            socket.startHandshake()
            val cert = socket.session.peerCertificates.first()
            return PeerConnection(socket, sha256(cert.encoded))
        } catch (e: Exception) {
            socket.close()
            throw e
        }
    }

    /**
     * Accepts any server certificate, including self-signed ones.
     *
     * Devices have no common certificate authority: trust comes from pairing,
     * which compares fingerprints. Here TLS only guarantees that the PC holds
     * the private key of the certificate it presented.
     */
    @SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager")
    private object AnyServerCertificate : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            throw UnsupportedOperationException("client only")

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            require(!chain.isNullOrEmpty()) { "the PC did not present a certificate" }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
