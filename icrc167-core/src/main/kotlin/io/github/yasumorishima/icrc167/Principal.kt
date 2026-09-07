package io.github.yasumorishima.icrc167

import java.security.MessageDigest
import java.util.zip.CRC32

/**
 * An IC principal.
 *
 * The only derivation this library needs is the *self-authenticating* one, which is how a
 * delegation chain's root public key becomes the principal a canister sees as `msg_caller`.
 */
public class Principal private constructor(private val raw: ByteArray) {

    public val bytes: ByteArray get() = raw.copyOf()

    public fun toText(): String {
        val crc = CRC32().apply { update(raw) }.value
        val checksum = byteArrayOf(
            (crc ushr 24).toByte(), (crc ushr 16).toByte(), (crc ushr 8).toByte(), crc.toByte(),
        )
        return Base32.encode(checksum + raw).chunked(GROUP_SIZE).joinToString("-")
    }

    override fun toString(): String = toText()

    override fun equals(other: Any?): Boolean = other is Principal && raw.contentEquals(other.raw)

    override fun hashCode(): Int = raw.contentHashCode()

    public companion object {
        private const val GROUP_SIZE = 5
        private const val MAX_LENGTH_BYTES = 29
        private const val SELF_AUTHENTICATING_TAG: Byte = 0x02

        public fun ofBytes(bytes: ByteArray): Principal {
            require(bytes.size <= MAX_LENGTH_BYTES) {
                "a principal is at most $MAX_LENGTH_BYTES bytes, got ${bytes.size}"
            }
            return Principal(bytes.copyOf())
        }

        /**
         * `SHA-224(derPublicKey) || 0x02`.
         *
         * This is the identity a canister attributes the call to, so it is derived from the
         * *root* of a delegation chain — never from the session key the chain ends at.
         */
        public fun selfAuthenticating(derPublicKey: ByteArray): Principal {
            val digest = MessageDigest.getInstance("SHA-224").digest(derPublicKey)
            return Principal(digest + SELF_AUTHENTICATING_TAG)
        }

        public fun fromText(text: String): Principal {
            val decoded = Base32.decode(text.replace("-", ""))
            require(decoded.size >= 4) { "principal text is too short: '$text'" }

            val body = decoded.copyOfRange(4, decoded.size)
            val expected = CRC32().apply { update(body) }.value
            val actual = ((decoded[0].toLong() and 0xff) shl 24) or
                ((decoded[1].toLong() and 0xff) shl 16) or
                ((decoded[2].toLong() and 0xff) shl 8) or
                (decoded[3].toLong() and 0xff)
            require(expected == actual) { "principal checksum mismatch for '$text'" }

            // Re-encoding must reproduce the input exactly; this rejects non-canonical text
            // such as wrong grouping or stray padding.
            val principal = ofBytes(body)
            require(principal.toText() == text) { "non-canonical principal text: '$text'" }
            return principal
        }
    }
}

/** RFC 4648 base32 without padding, lower-case — the encoding used by principal text. */
internal object Base32 {
    private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

    fun encode(input: ByteArray): String {
        val out = StringBuilder()
        var buffer = 0
        var bitsInBuffer = 0
        for (byte in input) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bitsInBuffer += 8
            while (bitsInBuffer >= 5) {
                out.append(ALPHABET[(buffer ushr (bitsInBuffer - 5)) and 0x1f])
                bitsInBuffer -= 5
            }
        }
        if (bitsInBuffer > 0) {
            out.append(ALPHABET[(buffer shl (5 - bitsInBuffer)) and 0x1f])
        }
        return out.toString()
    }

    fun decode(input: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var buffer = 0
        var bitsInBuffer = 0
        for (char in input.lowercase()) {
            val index = ALPHABET.indexOf(char)
            require(index >= 0) { "invalid base32 character '$char'" }
            buffer = (buffer shl 5) or index
            bitsInBuffer += 5
            if (bitsInBuffer >= 8) {
                out.write((buffer ushr (bitsInBuffer - 8)) and 0xff)
                bitsInBuffer -= 8
            }
        }
        return out.toByteArray()
    }
}
