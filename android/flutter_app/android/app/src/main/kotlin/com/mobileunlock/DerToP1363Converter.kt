package com.mobileunlock

import java.io.ByteArrayOutputStream
import java.security.SignatureException

/**
 * Utility to convert between ASN.1 DER encoded ECDSA signatures and
 * fixed-width 64-byte IEEE P1363 (r || s) encoding for ECDSA P-256.
 */
object DerToP1363Converter {

    private const val ASN1_SEQUENCE = 0x30
    private const val ASN1_INTEGER = 0x02
    private const val COMPONENT_LEN = 32
    private const val P1363_SIGNATURE_LEN = 64

    /**
     * Converts an ASN.1 DER encoded ECDSA signature into a 64-byte IEEE P1363 (r || s) signature.
     *
     * @param der The ASN.1 DER encoded signature bytes.
     * @return Exactly 64 bytes (32 bytes r, Big-Endian || 32 bytes s, Big-Endian).
     * @throws IllegalArgumentException if the DER bytes are malformed, truncated, or invalid.
     */
    @Throws(IllegalArgumentException::class)
    fun derToP1363(der: ByteArray): ByteArray {
        if (der.size < 8 || der.size > 74) {
            throw IllegalArgumentException("Invalid DER signature length: ${der.size}")
        }

        var offset = 0

        // 1. SEQUENCE tag
        val seqTag = der[offset++].toInt() and 0xFF
        if (seqTag != ASN1_SEQUENCE) {
            throw IllegalArgumentException("Expected SEQUENCE tag 0x30, got 0x${seqTag.toString(16)}")
        }

        // SEQUENCE length
        var seqLen = der[offset++].toInt() and 0xFF
        if (seqLen and 0x80 != 0) {
            val numLenBytes = seqLen and 0x7F
            if (numLenBytes != 1 || offset >= der.size) {
                throw IllegalArgumentException("Unsupported or invalid DER sequence length encoding")
            }
            seqLen = der[offset++].toInt() and 0xFF
        }

        if (offset + seqLen != der.size) {
            throw IllegalArgumentException("DER sequence length $seqLen does not match remaining payload ${der.size - offset}")
        }

        // 2. Parse Integer r
        val rBytes = parseDerInteger(der, offset)
        offset = rBytes.nextOffset

        // 3. Parse Integer s
        val sBytes = parseDerInteger(der, offset)
        offset = sBytes.nextOffset

        if (offset != der.size) {
            throw IllegalArgumentException("Unexpected trailing bytes in DER signature: ${der.size - offset} bytes remain")
        }

        // 4. Normalize r and s to 32 bytes
        val normalizedR = normalizeTo32Bytes(rBytes.data, "r")
        val normalizedS = normalizeTo32Bytes(sBytes.data, "s")

        val result = ByteArray(P1363_SIGNATURE_LEN)
        System.arraycopy(normalizedR, 0, result, 0, COMPONENT_LEN)
        System.arraycopy(normalizedS, 0, result, COMPONENT_LEN, COMPONENT_LEN)
        return result
    }

    /**
     * Converts a 64-byte IEEE P1363 (r || s) signature to standard ASN.1 DER format.
     *
     * @param p1363 The 64-byte IEEE P1363 signature.
     * @return ASN.1 DER encoded signature bytes.
     * @throws IllegalArgumentException if the input is not exactly 64 bytes.
     */
    @Throws(IllegalArgumentException::class)
    fun p1363ToDer(p1363: ByteArray): ByteArray {
        if (p1363.size != P1363_SIGNATURE_LEN) {
            throw IllegalArgumentException("IEEE P1363 signature must be exactly 64 bytes, got ${p1363.size}")
        }

        val r = p1363.copyOfRange(0, COMPONENT_LEN)
        val s = p1363.copyOfRange(COMPONENT_LEN, P1363_SIGNATURE_LEN)

        val rDer = encodeIntegerToDer(r)
        val sDer = encodeIntegerToDer(s)

        val totalLen = rDer.size + sDer.size
        val out = ByteArrayOutputStream()
        out.write(ASN1_SEQUENCE)
        if (totalLen < 128) {
            out.write(totalLen)
        } else {
            out.write(0x81)
            out.write(totalLen)
        }
        out.write(rDer)
        out.write(sDer)
        return out.toByteArray()
    }

    private data class ParsedInteger(val data: ByteArray, val nextOffset: Int)

    private fun parseDerInteger(der: ByteArray, startOffset: Int): ParsedInteger {
        var offset = startOffset
        if (offset >= der.size) {
            throw IllegalArgumentException("Truncated DER signature before INTEGER tag")
        }

        val tag = der[offset++].toInt() and 0xFF
        if (tag != ASN1_INTEGER) {
            throw IllegalArgumentException("Expected INTEGER tag 0x02, got 0x${tag.toString(16)}")
        }

        if (offset >= der.size) {
            throw IllegalArgumentException("Truncated DER signature before INTEGER length")
        }

        var len = der[offset++].toInt() and 0xFF
        if (len and 0x80 != 0) {
            throw IllegalArgumentException("Multi-byte INTEGER lengths not supported for ECDSA P-256")
        }

        if (len == 0) {
            throw IllegalArgumentException("INTEGER length cannot be zero")
        }

        if (offset + len > der.size) {
            throw IllegalArgumentException("Truncated DER signature inside INTEGER data")
        }

        val intBytes = der.copyOfRange(offset, offset + len)
        return ParsedInteger(intBytes, offset + len)
    }

    private fun normalizeTo32Bytes(raw: ByteArray, name: String): ByteArray {
        var src = raw

        // Strip leading 0x00 if present (positive sign byte)
        if (src.size > COMPONENT_LEN && src[0] == 0x00.toByte()) {
            src = src.copyOfRange(1, src.size)
        }

        // If there are multiple leading 0x00 bytes, strip them all as long as size > COMPONENT_LEN
        while (src.size > COMPONENT_LEN && src[0] == 0x00.toByte()) {
            src = src.copyOfRange(1, src.size)
        }

        if (src.size > COMPONENT_LEN) {
            throw IllegalArgumentException("Component $name is oversized (${src.size} bytes > $COMPONENT_LEN bytes)")
        }

        if (src.size == COMPONENT_LEN) {
            return src
        }

        // If shorter than 32 bytes, pad with leading zeros
        val padded = ByteArray(COMPONENT_LEN)
        System.arraycopy(src, 0, padded, COMPONENT_LEN - src.size, src.size)
        return padded
    }

    private fun encodeIntegerToDer(component: ByteArray): ByteArray {
        // Strip leading zeros
        var start = 0
        while (start < component.size - 1 && component[start] == 0x00.toByte()) {
            start++
        }
        val trimmed = component.copyOfRange(start, component.size)

        val out = ByteArrayOutputStream()
        out.write(ASN1_INTEGER)

        // If highest bit is 1, prepend 0x00 to ensure positive integer in two's complement DER
        if ((trimmed[0].toInt() and 0x80) != 0) {
            out.write(trimmed.size + 1)
            out.write(0x00)
        } else {
            out.write(trimmed.size)
        }
        out.write(trimmed)
        return out.toByteArray()
    }
}
