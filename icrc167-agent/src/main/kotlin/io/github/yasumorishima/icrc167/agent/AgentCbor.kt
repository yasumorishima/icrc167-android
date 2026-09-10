package io.github.yasumorishima.icrc167.agent

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/** A CBOR value, restricted to the shapes an IC agent sends and receives. */
public sealed interface CborItem {
    public class Uint(public val value: BigInteger) : CborItem
    public class Blob(public val bytes: ByteArray) : CborItem
    public class Text(public val value: String) : CborItem
    public class Arr(public val items: List<CborItem>) : CborItem

    /** A map. The entry order is kept: it is what the encoder writes and the fixtures pin. */
    public class Dict(public val entries: List<Pair<CborItem, CborItem>>) : CborItem
    public class Tagged(public val tag: BigInteger, public val value: CborItem) : CborItem
}

public class AgentCborException(message: String) : IllegalArgumentException(message)

/**
 * The CBOR codec for the agent wire format.
 *
 * This is deliberately *not* the reader in `icrc167-certificate`. That one refuses
 * indefinite lengths on purpose, and a certificate never uses them -- but a replica's query
 * reply does: every reply measured against mainnet on 2026-09-10 arrives as tag 55799
 * followed by an indefinite-length map (`d9d9f7 bf ... ff`). Teaching the certificate reader
 * to accept `bf` to make a *reply* parse would widen the parser that guards signatures, for
 * the benefit of bytes that carry no authority at all. So the two stay apart.
 *
 * Everything the format allows but the agent never needs -- negative integers, floats,
 * simple values, indefinite-length strings -- is still rejected here.
 */
public object AgentCbor {

    /** The self-describe tag the replica wraps its answers in. */
    public val SELF_DESCRIBE_TAG: BigInteger = BigInteger.valueOf(55799)

    private val TWO_POW_64: BigInteger = BigInteger.ONE.shiftLeft(64)
    private const val MAX_DEPTH = 16

    public fun encode(item: CborItem): ByteArray {
        val out = ByteArrayOutputStream()
        write(out, item, depth = 0)
        return out.toByteArray()
    }

    /** Decodes exactly one value and requires the input to end there. */
    public fun decode(bytes: ByteArray): CborItem {
        val reader = Reader(bytes)
        val value = reader.read(depth = 0)
        if (reader.remaining() != 0) {
            throw AgentCborException("${reader.remaining()} trailing bytes after the value")
        }
        return value
    }

    /** The entries of a text-keyed map, or null when [item] is not one. */
    public fun textMap(item: CborItem): Map<String, CborItem>? {
        val dict = item as? CborItem.Dict ?: return null
        val out = LinkedHashMap<String, CborItem>(dict.entries.size)
        for ((key, value) in dict.entries) {
            val name = (key as? CborItem.Text)?.value ?: return null
            out[name] = value
        }
        return out
    }

    /** Strips the self-describe tag if there is one. */
    public fun untag(item: CborItem): CborItem =
        if (item is CborItem.Tagged && item.tag == SELF_DESCRIBE_TAG) item.value else item

    private fun write(out: ByteArrayOutputStream, item: CborItem, depth: Int) {
        if (depth > MAX_DEPTH) throw AgentCborException("nested deeper than $MAX_DEPTH")
        when (item) {
            is CborItem.Uint -> head(out, major = 0, argument = item.value)
            is CborItem.Blob -> {
                head(out, major = 2, argument = BigInteger.valueOf(item.bytes.size.toLong()))
                out.write(item.bytes)
            }
            is CborItem.Text -> {
                val utf8 = item.value.toByteArray(Charsets.UTF_8)
                head(out, major = 3, argument = BigInteger.valueOf(utf8.size.toLong()))
                out.write(utf8)
            }
            is CborItem.Arr -> {
                head(out, major = 4, argument = BigInteger.valueOf(item.items.size.toLong()))
                item.items.forEach { write(out, it, depth + 1) }
            }
            is CborItem.Dict -> {
                head(out, major = 5, argument = BigInteger.valueOf(item.entries.size.toLong()))
                item.entries.forEach { (key, value) ->
                    write(out, key, depth + 1)
                    write(out, value, depth + 1)
                }
            }
            is CborItem.Tagged -> {
                head(out, major = 6, argument = item.tag)
                write(out, item.value, depth + 1)
            }
        }
    }

    private fun head(out: ByteArrayOutputStream, major: Int, argument: BigInteger) {
        if (argument.signum() < 0 || argument >= TWO_POW_64) {
            throw AgentCborException("$argument does not fit an unsigned 64-bit argument")
        }
        val value = argument.toLong()
        val prefix = major shl 5
        when {
            argument < BigInteger.valueOf(24) -> out.write(prefix or value.toInt())
            argument < BigInteger.valueOf(1L shl 8) -> {
                out.write(prefix or 24)
                out.write(value.toInt())
            }
            argument < BigInteger.valueOf(1L shl 16) -> {
                out.write(prefix or 25)
                writeBigEndian(out, value, 2)
            }
            argument < BigInteger.valueOf(1L shl 32) -> {
                out.write(prefix or 26)
                writeBigEndian(out, value, 4)
            }
            else -> {
                out.write(prefix or 27)
                // toLong() wraps above 2^63, which is exactly the two-complement byte
                // pattern an unsigned 64-bit argument needs.
                writeBigEndian(out, argument.toLong(), 8)
            }
        }
    }

    private fun writeBigEndian(out: ByteArrayOutputStream, value: Long, width: Int) {
        for (shift in (width - 1) downTo 0) {
            out.write(((value ushr (shift * 8)) and 0xFF).toInt())
        }
    }

    private class Reader(private val bytes: ByteArray) {
        private var offset = 0

        fun remaining(): Int = bytes.size - offset

        fun read(depth: Int): CborItem {
            if (depth > MAX_DEPTH) throw AgentCborException("nested deeper than $MAX_DEPTH")
            val initial = readByte().toInt() and 0xFF
            val major = initial ushr 5
            val additional = initial and 31
            if (additional == 31) {
                return when (major) {
                    4 -> CborItem.Arr(readItemsUntilBreak(depth))
                    5 -> CborItem.Dict(readEntriesUntilBreak(depth))
                    else -> throw AgentCborException(
                        "indefinite length is only defined here for arrays and maps, not major type $major",
                    )
                }
            }
            val argument = readArgument(additional)
            return when (major) {
                0 -> CborItem.Uint(argument)
                2 -> CborItem.Blob(readBytes(argument))
                3 -> CborItem.Text(decodeUtf8(readBytes(argument)))
                4 -> CborItem.Arr((0 until count(argument)).map { read(depth + 1) })
                5 -> CborItem.Dict(
                    (0 until count(argument)).map {
                        val key = read(depth + 1)
                        key to read(depth + 1)
                    },
                )
                6 -> CborItem.Tagged(argument, read(depth + 1))
                else -> throw AgentCborException("major type $major is not part of the agent wire format")
            }
        }

        private fun readItemsUntilBreak(depth: Int): List<CborItem> {
            val items = ArrayList<CborItem>()
            while (!atBreak()) items.add(read(depth + 1))
            offset++
            return items
        }

        private fun readEntriesUntilBreak(depth: Int): List<Pair<CborItem, CborItem>> {
            val entries = ArrayList<Pair<CborItem, CborItem>>()
            while (!atBreak()) {
                val key = read(depth + 1)
                entries.add(key to read(depth + 1))
            }
            offset++
            return entries
        }

        private fun atBreak(): Boolean {
            if (remaining() == 0) throw AgentCborException("input ended before the break byte")
            return bytes[offset] == 0xFF.toByte()
        }

        private fun readArgument(additional: Int): BigInteger = when {
            additional < 24 -> BigInteger.valueOf(additional.toLong())
            additional == 24 -> readUnsigned(1)
            additional == 25 -> readUnsigned(2)
            additional == 26 -> readUnsigned(4)
            additional == 27 -> readUnsigned(8)
            else -> throw AgentCborException("reserved additional information $additional")
        }

        private fun readUnsigned(width: Int): BigInteger =
            BigInteger(1, byteArrayOf(0) + readBytes(BigInteger.valueOf(width.toLong())))

        private fun count(argument: BigInteger): Int {
            if (argument > BigInteger.valueOf(remaining().toLong())) {
                throw AgentCborException("$argument items do not fit in ${remaining()} bytes")
            }
            return argument.toInt()
        }

        private fun readBytes(length: BigInteger): ByteArray {
            if (length > BigInteger.valueOf(remaining().toLong())) {
                throw AgentCborException("$length bytes do not fit in the ${remaining()} that are left")
            }
            val size = length.toInt()
            val slice = bytes.copyOfRange(offset, offset + size)
            offset += size
            return slice
        }

        private fun decodeUtf8(raw: ByteArray): String {
            val decoder = Charsets.UTF_8.newDecoder()
            return try {
                decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString()
            } catch (e: java.nio.charset.CharacterCodingException) {
                throw AgentCborException("a text string is not valid UTF-8: ${e.message}")
            }
        }

        private fun readByte(): Byte {
            if (remaining() == 0) throw AgentCborException("the input ended mid-value")
            return bytes[offset++]
        }
    }
}
