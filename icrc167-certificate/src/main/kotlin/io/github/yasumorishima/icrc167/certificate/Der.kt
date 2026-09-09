package io.github.yasumorishima.icrc167.certificate

/**
 * Just enough DER to read the two public-key shapes an IC certificate chain involves.
 *
 * Not a general ASN.1 reader, and it should not become one. Keys arrive from whoever is
 * driving the sign-in, so every encoding this accepts is one more thing that has to be
 * reasoned about: indefinite lengths, non-minimal lengths and multi-byte tags are refused
 * outright rather than normalised.
 */
internal object Der {
    const val SEQUENCE: Int = 0x30
    const val BIT_STRING: Int = 0x03
    const val OBJECT_IDENTIFIER: Int = 0x06

    /** One tag-length-value, described by where its contents sit in the buffer. */
    class Tlv(val tag: Int, val start: Int, val end: Int)

    /**
     * Reads the TLV beginning at [from], which must end at or before [limit].
     *
     * @throws KeyFormatException on anything that is not definite-length, minimally encoded DER
     */
    fun read(bytes: ByteArray, from: Int, limit: Int): Tlv {
        if (limit - from < 2) throw KeyFormatException("truncated DER header")
        val tag = bytes[from].toInt() and 0xff
        // 0x1f in the low bits introduces a multi-byte tag number. Nothing here uses one.
        if (tag and 0x1f == 0x1f) throw KeyFormatException("multi-byte DER tag")

        val first = bytes[from + 1].toInt() and 0xff
        var pos = from + 2
        val length: Int
        if (first < 0x80) {
            length = first
        } else {
            val count = first and 0x7f
            // 0 is the indefinite-length marker, which DER forbids; beyond 3 bytes the
            // length could not be honoured by an in-memory buffer anyway.
            if (count == 0 || count > 3) throw KeyFormatException("bad DER length header 0x" + first.toString(16))
            if (limit - pos < count) throw KeyFormatException("truncated DER length")
            if (bytes[pos].toInt() and 0xff == 0) throw KeyFormatException("non-minimal DER length")
            var value = 0
            for (i in 0 until count) value = (value shl 8) or (bytes[pos + i].toInt() and 0xff)
            // A value that would have fitted in the short form must use the short form.
            if (value < 0x80) throw KeyFormatException("non-minimal DER length")
            length = value
            pos += count
        }

        if (limit - pos < length) throw KeyFormatException("DER value runs past the buffer")
        return Tlv(tag, pos, pos + length)
    }

    /** Reads the TLV at [from] and requires it to be [tag] and to fill the buffer exactly. */
    fun readExactly(bytes: ByteArray, tag: Int, from: Int, limit: Int, what: String): Tlv {
        val tlv = read(bytes, from, limit)
        if (tlv.tag != tag) {
            throw KeyFormatException(
                "expected $what (tag 0x" + tag.toString(16) + "), found tag 0x" + tlv.tag.toString(16),
            )
        }
        if (tlv.end != limit) throw KeyFormatException("$what does not fill its container")
        return tlv
    }

    fun contentEquals(bytes: ByteArray, tlv: Tlv, expected: ByteArray): Boolean {
        if (tlv.end - tlv.start != expected.size) return false
        for (i in expected.indices) {
            if (bytes[tlv.start + i] != expected[i]) return false
        }
        return true
    }
}
