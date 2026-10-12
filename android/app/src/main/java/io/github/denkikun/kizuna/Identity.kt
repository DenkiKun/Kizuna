package io.github.denkikun.kizuna

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import javax.security.auth.x500.X500Principal

/**
 * This phone's identity: an ECDSA P-256 key in the Android Keystore (it never
 * leaves the device) and the self-signed certificate the Keystore creates for
 * it. See "Identity" in docs/PROTOCOL.md.
 */
class DeviceIdentity private constructor(
    private val privateKey: PrivateKey,
    val certificate: X509Certificate,
) {
    /** SHA-256 of the certificate (DER). */
    val fingerprint: ByteArray = sha256(certificate.encoded)

    /** Presents this identity as the TLS client certificate. */
    fun keyManager(): X509ExtendedKeyManager = object : X509ExtendedKeyManager() {
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) = ALIAS
        override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) = ALIAS
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(ALIAS)
        override fun getCertificateChain(alias: String?) = arrayOf(certificate)
        override fun getPrivateKey(alias: String?) = privateKey
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?) = null
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = null
    }

    companion object {
        private const val ALIAS = "kizuna-identity"
        private const val KEYSTORE = "AndroidKeyStore"

        /** Loads the identity, or generates it on first run. */
        fun loadOrCreate(): DeviceIdentity {
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (!keyStore.containsAlias(ALIAS)) generate()
            val entry = keyStore.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
            return DeviceIdentity(entry.privateKey, entry.certificate as X509Certificate)
        }

        private fun generate() {
            val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                // The name is not used for trust (fingerprints are), so it stays generic.
                .setCertificateSubject(X500Principal("CN=Kizuna Android"))
                .setCertificateSerialNumber(BigInteger(63, SecureRandom()))
                .setCertificateNotBefore(Date(System.currentTimeMillis() - DAY_MS))
                .setCertificateNotAfter(Date(YEAR_2100_MS))
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
                initialize(spec)
                generateKeyPair()
            }
        }

        private const val DAY_MS = 24L * 60 * 60 * 1000
        private const val YEAR_2100_MS = 4_102_444_800_000L
    }
}
