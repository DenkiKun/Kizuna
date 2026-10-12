package io.github.denkikun.kizuna

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingCryptoTest {
    private fun bytes(b: Int) = ByteArray(32) { b.toByte() }

    /** Shared test vector (docs/PROTOCOL.md); the PC checks the same values. */
    @Test
    fun matchesTheProtocolTestVector() {
        val initiator = bytes(0x11)
        val responder = bytes(0x22)
        val na = bytes(0x33)
        val nb = bytes(0x44)
        assertEquals(
            "6923165278d40d25bce69f08e8857bf93f90dc4eedf9077d6ea6e695fbf708a0",
            Hex.encode(PairingCrypto.commitment(nb, responder, initiator)),
        )
        assertEquals(158474, PairingCrypto.code(initiator, responder, na, nb))
    }

    @Test
    fun codeIsShownWithSixDigits() {
        assertEquals("000 042", PairingCrypto.formatCode(42))
        assertEquals("999 999", PairingCrypto.formatCode(999_999))
    }

    @Test
    fun hexRoundTripAndValidation() {
        val value = bytes(0xab)
        assertArrayEquals(value, Hex.decode(Hex.encode(value), 32))
        assertNull(Hex.decode("AB".repeat(32), 32))
        assertNull(Hex.decode("abcd", 32))
        assertNull(Hex.decode("zz".repeat(32), 32))
    }
}
