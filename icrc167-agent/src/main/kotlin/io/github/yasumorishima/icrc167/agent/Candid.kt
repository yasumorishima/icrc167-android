package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Principal

public class CandidException(message: String) : IllegalArgumentException(message)

/**
 * The sliver of Candid an authentication round trip needs: no arguments in, one principal out.
 *
 * This is not a Candid implementation and should not grow into one. It exists so that an app
 * can ask a canister who it thinks the caller is -- the one call that checks the whole
 * delegation path from the outside -- without pulling in a code generator. Anything else the
 * app calls is its own business, and it can hand [IcAgent] the encoded argument itself.
 */
public object Candid {

    /** `DIDL` with an empty type table and no arguments: the encoding of `()`. */
    public val EMPTY_ARGS: ByteArray
        get() = byteArrayOf(0x44, 0x49, 0x44, 0x4C, 0x00, 0x00)

    private const val PRINCIPAL_TYPE = 0x68

    /**
     * Reads a reply of exactly one `principal`, as `whoami : () -> (principal) query` returns.
     *
     * The value carries a one-byte form tag before the bytes. Only form 1 -- a concrete
     * principal -- is accepted; form 0 is an opaque service reference, which is a different
     * thing and never an identity.
     */
    public fun decodePrincipal(arg: ByteArray): Principal {
        if (arg.size < 4 || arg[0] != 0x44.toByte() || arg[1] != 0x49.toByte() ||
            arg[2] != 0x44.toByte() || arg[3] != 0x4C.toByte()
        ) {
            throw CandidException("not a Candid message: it does not start with DIDL")
        }
        var offset = 4
        val typeTable = readLeb(arg, offset).also { offset = it.next }
        if (typeTable.value != 0) {
            throw CandidException("expected a primitive-only reply, got a type table of ${typeTable.value}")
        }
        val values = readLeb(arg, offset).also { offset = it.next }
        if (values.value != 1) {
            throw CandidException("expected exactly one return value, got ${values.value}")
        }
        val type = byteAt(arg, offset).also { offset++ }
        if (type != PRINCIPAL_TYPE) {
            throw CandidException("expected a principal (0x68), got 0x${type.toString(16)}")
        }
        val form = byteAt(arg, offset).also { offset++ }
        if (form != 1) {
            throw CandidException("expected a concrete principal (form 1), got form $form")
        }
        val length = readLeb(arg, offset).also { offset = it.next }
        if (length.value > 29) {
            throw CandidException("a principal is at most 29 bytes, this one claims ${length.value}")
        }
        if (arg.size - offset != length.value) {
            throw CandidException("the reply carries ${arg.size - offset} bytes where ${length.value} were announced")
        }
        return Principal.ofBytes(arg.copyOfRange(offset, arg.size))
    }

    private class Leb(val value: Int, val next: Int)

    private fun readLeb(bytes: ByteArray, from: Int): Leb {
        var result = 0
        var shift = 0
        var offset = from
        while (true) {
            val byte = byteAt(bytes, offset)
            offset++
            result = result or ((byte and 0x7F) shl shift)
            if (byte and 0x80 == 0) return Leb(result, offset)
            shift += 7
            if (shift > 21) throw CandidException("an unreasonably long LEB128 at offset $from")
        }
    }

    private fun byteAt(bytes: ByteArray, offset: Int): Int {
        if (offset >= bytes.size) throw CandidException("the reply ended at offset $offset")
        return bytes[offset].toInt() and 0xFF
    }
}
