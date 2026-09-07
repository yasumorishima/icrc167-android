package io.github.yasumorishima.icrc167

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Representation-independent hashing of a map, as defined by the IC interface specification
 * ("Hash of map").
 *
 * This is what a delegation signature actually covers: the signed bytes are
 * `ic-request-auth-delegation || ofMap(delegation)` — see [Delegation.signableBytes].
 */
public object ReprHash {

    /** The subset of IC value shapes a delegation map can contain. */
    public sealed interface Value {
        public class Blob(public val bytes: ByteArray) : Value
        public class Text(public val value: String) : Value
        public class Nat(public val value: BigInteger) : Value
        public class Arr(public val items: List<Value>) : Value
    }

    public fun nat(value: Long): Value.Nat = Value.Nat(BigInteger.valueOf(value))

    /**
     * SHA-256 over the concatenation of `sha256(key) || hash(value)` pairs,
     * sorted by their unsigned byte order.
     */
    public fun ofMap(fields: Map<String, Value>): ByteArray {
        val pairs = fields.entries
            .map { (key, value) -> sha256(key.toByteArray(Charsets.UTF_8)) + hashValue(value) }
            .sortedWith(UnsignedLexicographic)

        val digest = MessageDigest.getInstance("SHA-256")
        for (pair in pairs) digest.update(pair)
        return digest.digest()
    }

    internal fun hashValue(value: Value): ByteArray = when (value) {
        is Value.Blob -> sha256(value.bytes)
        is Value.Text -> sha256(value.value.toByteArray(Charsets.UTF_8))
        is Value.Nat -> sha256(Leb128.encodeUnsigned(value.value))
        is Value.Arr -> sha256(*value.items.map { hashValue(it) }.toTypedArray())
    }

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in parts) digest.update(part)
        return digest.digest()
    }

    /**
     * Kotlin's `Byte` is signed, so the natural ordering would sort 0x80.. before 0x00..
     * and silently produce a different hash. Compare as unsigned.
     */
    private object UnsignedLexicographic : Comparator<ByteArray> {
        override fun compare(a: ByteArray, b: ByteArray): Int {
            val shared = minOf(a.size, b.size)
            for (i in 0 until shared) {
                val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
                if (diff != 0) return diff
            }
            return a.size - b.size
        }
    }
}
