package io.github.yasumorishima.icrc167.certificate

/**
 * A CBOR value, restricted to the shapes an IC certificate is built from.
 *
 * Nothing here is a general-purpose CBOR implementation, and it should not become one: the
 * input is attacker-supplied, so every construct the format allows but a certificate never
 * uses is one more thing that has to be reasoned about. Indefinite lengths, negative
 * integers, floats and simple values are rejected outright.
 */
public sealed interface CborValue {
    public class Unsigned(public val value: Long) : CborValue
    public class Bytes(public val value: ByteArray) : CborValue
    public class Text(public val value: String) : CborValue
    public class Items(public val items: List<CborValue>) : CborValue
    public class Entries(public val entries: List<Pair<CborValue, CborValue>>) : CborValue
    public class Tagged(public val tag: Long, public val value: CborValue) : CborValue
}

public class CborException(message: String) : IllegalArgumentException(message)

/** A strict, minimal CBOR reader. */
public object Cbor {

    /** The self-describe tag every IC certificate and canister signature is wrapped in. */
    public const val SELF_DESCRIBE_TAG: Long = 55799

    /** Decodes exactly one value and requires the input to end there. */
    public fun decode(bytes: ByteArray): CborValue {
        val reader = Reader(bytes)
        val value = reader.readValue(depth = 0)
        if (reader.remaining() != 0) {
            throw CborException("${reader.remaining()} trailing bytes after the value")
        }
        return value
    }

    private class Reader(private val bytes: ByteArray) {
        private var offset = 0

        fun remaining(): Int = bytes.size - offset

        fun readValue(depth: Int): CborValue {
            // Nesting alone must not exhaust the stack. The bound is generous because a
            // certificate over a large subnet is a balanced fork tree — depth grows with the
            // log of the number of canisters — and rejecting a legitimate one would be a
            // failure to sign in, not a defence. Allocation is bounded separately, by the
            // input length, so depth costs nothing on its own.
            if (depth > MAX_DEPTH) throw CborException("nested deeper than $MAX_DEPTH")

            val initial = readByte().toInt() and 0xff
            val major = initial shr 5
            val argument = readArgument(initial and 0x1f)

            return when (major) {
                MAJOR_UNSIGNED -> CborValue.Unsigned(argument)
                MAJOR_BYTES -> CborValue.Bytes(readBytes(argument))
                MAJOR_TEXT -> CborValue.Text(decodeUtf8(readBytes(argument)))
                MAJOR_ARRAY -> CborValue.Items(
                    (0 until checkedCount(argument)).map { readValue(depth + 1) },
                )
                MAJOR_MAP -> CborValue.Entries(
                    (0 until checkedCount(argument)).map {
                        readValue(depth + 1) to readValue(depth + 1)
                    },
                )
                MAJOR_TAG -> CborValue.Tagged(argument, readValue(depth + 1))
                else -> throw CborException("unsupported CBOR major type $major")
            }
        }

        /** The additional-information field, or the value it points at. */
        private fun readArgument(additional: Int): Long = when {
            additional < 24 -> additional.toLong()
            additional == 24 -> (readByte().toLong() and 0xff)
            additional == 25 -> readUnsigned(2)
            additional == 26 -> readUnsigned(4)
            additional == 27 -> readUnsigned(8)
            // 28..30 are reserved, 31 is the indefinite-length marker.
            else -> throw CborException("additional information $additional is not allowed here")
        }

        private fun readUnsigned(width: Int): Long {
            var value = 0L
            repeat(width) { value = (value shl 8) or (readByte().toLong() and 0xff) }
            if (value < 0) throw CborException("length does not fit in a signed 64-bit value")
            return value
        }

        private fun checkedCount(count: Long): Int {
            // A count is only credible if the remaining input could possibly hold that many
            // items; without this a two-byte header can ask for a billion allocations.
            if (count < 0 || count > remaining()) {
                throw CborException("declared $count items but only ${remaining()} bytes remain")
            }
            return count.toInt()
        }

        private fun readBytes(length: Long): ByteArray {
            if (length < 0 || length > remaining()) {
                throw CborException("declared $length bytes but only ${remaining()} remain")
            }
            val slice = bytes.copyOfRange(offset, offset + length.toInt())
            offset += length.toInt()
            return slice
        }

        /**
         * Rejects malformed UTF-8 rather than replacing it with U+FFFD. Two different byte
         * strings must not decode to the same key.
         */
        private fun decodeUtf8(bytes: ByteArray): String = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes))
                .toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw CborException("text string is not valid UTF-8")
        }

        private fun readByte(): Byte {
            if (offset >= bytes.size) throw CborException("input ended in the middle of a value")
            return bytes[offset++]
        }
    }

    private const val MAX_DEPTH = 128
    private const val MAJOR_UNSIGNED = 0
    private const val MAJOR_BYTES = 2
    private const val MAJOR_TEXT = 3
    private const val MAJOR_ARRAY = 4
    private const val MAJOR_MAP = 5
    private const val MAJOR_TAG = 6
}
