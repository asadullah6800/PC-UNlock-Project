package com.mobileunlock

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Arrays

class DerToP1363ConverterTest {

    private fun buildDer(rBytes: ByteArray, sBytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val rDer = ByteArrayOutputStream()
        rDer.write(0x02)
        rDer.write(rBytes.size)
        rDer.write(rBytes)

        val sDer = ByteArrayOutputStream()
        sDer.write(0x02)
        sDer.write(sBytes.size)
        sDer.write(sBytes)

        val totalLen = rDer.size() + sDer.size()
        out.write(0x30)
        out.write(totalLen)
        out.write(rDer.toByteArray())
        out.write(sDer.toByteArray())
        return out.toByteArray()
    }

    // 1. r exactly 32 bytes, s exactly 32 bytes
    @Test
    fun testExact32ByteRAndS() {
        val r = ByteArray(32) { (it + 1).toByte() }
        val s = ByteArray(32) { (it + 33).toByte() }
        val der = buildDer(r, s)

        val p1363 = DerToP1363Converter.derToP1363(der)
        assertEquals(64, p1363.size)

        val extractedR = p1363.copyOfRange(0, 32)
        val extractedS = p1363.copyOfRange(32, 64)
        assertArrayEquals(r, extractedR)
        assertArrayEquals(s, extractedS)
    }

    // 2. r shorter than 32 bytes (e.g. 31 bytes)
    @Test
    fun testShortRIsZeroPadded() {
        val rShort = ByteArray(31) { (it + 1).toByte() }
        val s = ByteArray(32) { 0x55.toByte() }
        val der = buildDer(rShort, s)

        val p1363 = DerToP1363Converter.derToP1363(der)
        assertEquals(64, p1363.size)

        // First byte of r must be 0x00 padding
        assertEquals(0x00.toByte(), p1363[0])
        val extractedRData = p1363.copyOfRange(1, 32)
        assertArrayEquals(rShort, extractedRData)
    }

    // 3. r requiring DER leading sign byte (33 bytes: 0x00 + 32 bytes with high bit set)
    @Test
    fun testRWithLeadingSignByteIsStripped() {
        val rBody = ByteArray(32) { 0x80.toByte() } // High bit set (0x80)
        val rDerBytes = ByteArray(33)
        rDerBytes[0] = 0x00.toByte()
        System.arraycopy(rBody, 0, rDerBytes, 1, 32)

        val s = ByteArray(32) { 0x11.toByte() }
        val der = buildDer(rDerBytes, s)

        val p1363 = DerToP1363Converter.derToP1363(der)
        assertEquals(64, p1363.size)

        val extractedR = p1363.copyOfRange(0, 32)
        assertArrayEquals(rBody, extractedR)
    }

    // 4. s exactly 32 bytes
    @Test
    fun testExact32ByteS() {
        val r = ByteArray(32) { 0x22.toByte() }
        val s = ByteArray(32) { (it + 10).toByte() }
        val der = buildDer(r, s)

        val p1363 = DerToP1363Converter.derToP1363(der)
        assertEquals(64, p1363.size)
        assertArrayEquals(s, p1363.copyOfRange(32, 64))
    }

    // 5. s shorter than 32 bytes (e.g. 30 bytes)
    @Test
    fun testShortSIsZeroPadded() {
        val r = ByteArray(32) { 0x33.toByte() }
        val sShort = ByteArray(30) { (it + 1).toByte() }
        val der = buildDer(r, sShort)

        val p1363 = DerToP1363Converter.derToP1363(der)
        assertEquals(64, p1363.size)

        assertEquals(0x00.toByte(), p1363[32])
        assertEquals(0x00.toByte(), p1363[33])
        val extractedSData = p1363.copyOfRange(34, 64)
        assertArrayEquals(sShort, extractedSData)
    }

    // 6. s requiring DER leading sign byte (33 bytes)
    @Test
    fun testSWithLeadingSignByteIsStripped() {
        val r = ByteArray(32) { 0x44.toByte() }
        val sBody = ByteArray(32) { 0xFF.toByte() } // High bit set
        val sDerBytes = ByteArray(33)
        sDerBytes[0] = 0x00.toByte()
        System.arraycopy(sBody, 0, sDerBytes, 1, 32)

        val der = buildDer(r, sDerBytes)
        val p1363 = DerToP1363Converter.derToP1363(der)
        assertEquals(64, p1363.size)
        assertArrayEquals(sBody, p1363.copyOfRange(32, 64))
    }

    // 7. Malformed DER (invalid sequence tag, bad integer tag, bad lengths)
    @Test
    fun testMalformedDerThrows() {
        // Bad sequence tag (0x31 instead of 0x30)
        val badTag = byteArrayOf(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)
        try {
            DerToP1363Converter.derToP1363(badTag)
            fail("Expected IllegalArgumentException on bad tag")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Expected SEQUENCE tag"))
        }

        // Bad integer tag (0x03 instead of 0x02)
        val badIntTag = byteArrayOf(0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02)
        try {
            DerToP1363Converter.derToP1363(badIntTag)
            fail("Expected IllegalArgumentException on bad integer tag")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Expected INTEGER tag"))
        }
    }

    // 8. Truncated DER
    @Test
    fun testTruncatedDerThrows() {
        val validDer = buildDer(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val truncated = validDer.copyOfRange(0, validDer.size - 5)
        try {
            DerToP1363Converter.derToP1363(truncated)
            fail("Expected IllegalArgumentException on truncated DER")
        } catch (e: IllegalArgumentException) {
            assertNotNull(e.message)
        }
    }

    // 9. Oversized r (>32 non-zero bytes)
    @Test
    fun testOversizedRThrows() {
        val rOversized = ByteArray(34) { 0x01.toByte() } // 34 bytes without leading zero
        val s = ByteArray(32) { 0x02.toByte() }
        val der = buildDer(rOversized, s)

        try {
            DerToP1363Converter.derToP1363(der)
            fail("Expected IllegalArgumentException on oversized r")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("oversized"))
        }
    }

    // 10. Oversized s (>32 non-zero bytes)
    @Test
    fun testOversizedSThrows() {
        val r = ByteArray(32) { 0x01.toByte() }
        val sOversized = ByteArray(35) { 0x02.toByte() }
        val der = buildDer(r, sOversized)

        try {
            DerToP1363Converter.derToP1363(der)
            fail("Expected IllegalArgumentException on oversized s")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("oversized"))
        }
    }

    // Roundtrip test: P1363 -> DER -> P1363
    @Test
    fun testRoundtripConversion() {
        val originalP1363 = ByteArray(64)
        for (i in 0 until 64) {
            originalP1363[i] = ((i * 7 + 13) and 0xFF).toByte()
        }

        val der = DerToP1363Converter.p1363ToDer(originalP1363)
        val reconstructed = DerToP1363Converter.derToP1363(der)
        assertArrayEquals(originalP1363, reconstructed)
    }
}
