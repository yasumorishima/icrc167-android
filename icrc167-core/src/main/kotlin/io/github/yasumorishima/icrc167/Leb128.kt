package io.github.yasumorishima.icrc167

import java.math.BigInteger

/**
 * Unsigned LEB128, as used by the IC's representation-independent hash for `nat` values.
 *
 * See the IC interface specification, "Hash of map".
 */
internal object Leb128 {

    fun encodeUnsigned(value: BigInteger): ByteArray {
        require(value.signum() >= 0) { "unsigned LEB128 requires a non-negative value, got $value" }
        if (value.signum() == 0) return byteArrayOf(0)

        val out = ArrayList<Byte>()
        var remaining = value
        val lowSevenBits = BigInteger.valueOf(0x7f)
        while (true) {
            val chunk = remaining.and(lowSevenBits).toInt()
            remaining = remaining.shiftRight(7)
            if (remaining.signum() == 0) {
                out.add(chunk.toByte())
                break
            }
            out.add((chunk or 0x80).toByte())
        }
        return out.toByteArray()
    }
}
