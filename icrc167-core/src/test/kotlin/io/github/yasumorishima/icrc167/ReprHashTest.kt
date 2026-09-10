package io.github.yasumorishima.icrc167

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Known answers taken from the IC interface specification.
 *
 * These matter more than they look. Everywhere else in this repository the same function
 * produces the bytes that get signed *and* the bytes that get verified, so a hash that
 * disagreed with the IC would still pass every round-trip test while being unusable against
 * a real replica. Only an externally supplied digest can catch that.
 */
class ReprHashTest {

    @Test
    fun `matches the specification's worked request-id example`() {
        // hash_of_map({ request_type: "call", sender: 0x04,
        //               ingress_expiry: 1685570400000000000,
        //               canister_id: 0x00000000000004D2, method_name: "hello",
        //               arg: "DIDL\x00\xFD*" })
        val fields = mapOf(
            "request_type" to ReprHash.Value.Text("call"),
            "sender" to ReprHash.Value.Blob(byteArrayOf(0x04)),
            "ingress_expiry" to ReprHash.Value.Nat(BigInteger("1685570400000000000")),
            "canister_id" to ReprHash.Value.Blob(
                byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xD2.toByte()),
            ),
            "method_name" to ReprHash.Value.Text("hello"),
            "arg" to ReprHash.Value.Blob(
                byteArrayOf(0x44, 0x49, 0x44, 0x4C, 0x00, 0xFD.toByte(), 0x2A),
            ),
        )

        assertEquals(
            "1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101",
            ReprHash.ofMap(fields).toHex(),
        )
    }

    @Test
    fun `a nested map hashes to its own digest, not to a hash of it`() {
        // The distinction this test exists for: a map value contributes ofMap(fields) as it
        // stands. Wrapping that digest in a Blob hashes it a second time and produces a
        // different, wrong answer - measured against a live node signature, which accepts the
        // first and refuses the second (see the agent module response-hash vector).
        val arg = byteArrayOf(0x44, 0x49, 0x44, 0x4C, 0x00, 0x00)
        val inner = mapOf("arg" to ReprHash.Value.Blob(arg))
        val nested = ReprHash.ofMap(mapOf("reply" to ReprHash.Value.Map(inner)))
        val rehashed = ReprHash.ofMap(mapOf("reply" to ReprHash.Value.Blob(ReprHash.ofMap(inner))))
        assertEquals(32, nested.size)
        assertNotEquals(nested.toHex(), rehashed.toHex())
    }

    @Test
    fun `encodes naturals as the shortest unsigned LEB128`() {
        // Both examples are given verbatim in the interface specification.
        assertEquals("00", Leb128.encodeUnsigned(BigInteger.ZERO).toHex())
        assertEquals("e58e26", Leb128.encodeUnsigned(BigInteger.valueOf(624485)).toHex())
    }

    @Test
    fun `the delegation domain separator is the 27 bytes the specification names`() {
        val separator = Delegation.DOMAIN_SEPARATOR
        assertEquals(27, separator.size)
        assertEquals(0x1A.toByte(), separator[0])
        assertEquals(
            "ic-request-auth-delegation",
            String(separator, 1, separator.size - 1, Charsets.UTF_8),
        )
        // The prefix byte is the length of the name, which is what makes 0x1A correct
        // and 0x0A — a plausible-looking typo — silently wrong.
        assertEquals(separator.size - 1, separator[0].toInt())
    }

    @Test
    fun `field order does not change the hash`() {
        val a = mapOf(
            "alpha" to ReprHash.Value.Text("1"),
            "beta" to ReprHash.Value.Nat(BigInteger.TEN),
        )
        val b = mapOf(
            "beta" to ReprHash.Value.Nat(BigInteger.TEN),
            "alpha" to ReprHash.Value.Text("1"),
        )
        assertEquals(ReprHash.ofMap(a).toHex(), ReprHash.ofMap(b).toHex())
    }
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
