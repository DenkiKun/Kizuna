package io.github.denkikun.kizuna

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale

/**
 * Pairing math shared with the PC (see docs/PROTOCOL.md). Plain JVM code, so
 * it is unit-tested against the protocol test vector.
 */
object PairingCrypto {
    const val NONCE_LEN = 32

    private val COMMIT_TAG = "kizuna/v0/pair-commit".toByteArray(Charsets.US_ASCII)
    private val CODE_TAG = "kizuna/v0/pair-code".toByteArray(Charsets.US_ASCII)
    private val random = SecureRandom()

    /** Responder's commitment: SHA-256(tag ‖ Nb ‖ fp_responder ‖ fp_initiator). */
    fun commitment(responderNonce: ByteArray, responder: ByteArray, initiator: ByteArray): ByteArray =
        sha256(COMMIT_TAG, responderNonce, responder, initiator)

    /**
     * Code: SHA-256(tag ‖ fp_initiator ‖ fp_responder ‖ Na ‖ Nb), first 4 bytes
     * as a big-endian integer, modulo 1,000,000.
     */
    fun code(
        initiator: ByteArray,
        responder: ByteArray,
        initiatorNonce: ByteArray,
        responderNonce: ByteArray,
    ): Int {
        val hash = sha256(CODE_TAG, initiator, responder, initiatorNonce, responderNonce)
        var prefix = 0L
        for (i in 0 until 4) {
            prefix = (prefix shl 8) or (hash[i].toLong() and 0xff)
        }
        return (prefix % 1_000_000).toInt()
    }

    /** Shows a code as `012 345`. */
    fun formatCode(code: Int): String =
        String.format(Locale.ROOT, "%03d %03d", code / 1000, code % 1000)

    fun randomNonce(): ByteArray = ByteArray(NONCE_LEN).also(random::nextBytes)
}

fun sha256(vararg parts: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    parts.forEach(digest::update)
    return digest.digest()
}

object Hex {
    fun encode(bytes: ByteArray): String =
        bytes.joinToString("") { String.format(Locale.ROOT, "%02x", it) }

    /** Decodes lowercase hexadecimal of exactly `length` bytes; `null` if invalid. */
    fun decode(text: String, length: Int): ByteArray? {
        if (text.length != 2 * length || text.any { it !in '0'..'9' && it !in 'a'..'f' }) {
            return null
        }
        return ByteArray(length) { i -> text.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
