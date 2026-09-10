package io.github.yasumorishima.icrc167.agent

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Known answers from RFC 8949 appendix A, plus the two shapes mainnet actually sends.
 *
 * The appendix matters for the same reason the specification digests matter elsewhere here:
 * encoder and decoder are used together everywhere else, so a shared misreading of the format
 * would round-trip perfectly and still be rejected by every replica.
 */
class AgentCborTest {

    private fun uint(value: Long) = CborItem.Uint(BigInteger.valueOf(value))

    @Test
    fun `encodes the appendix A unsigned integers`() {
        assertEquals("00", AgentCbor.encode(uint(0)).toHex())
        assertEquals("17", AgentCbor.encode(uint(23)).toHex())
        assertEquals("1818", AgentCbor.encode(uint(24)).toHex())
        assertEquals("1903e8", AgentCbor.encode(uint(1000)).toHex())
        assertEquals("1a000f4240", AgentCbor.encode(uint(1000000)).toHex())
        assertEquals("1b000000e8d4a51000", AgentCbor.encode(uint(1000000000000)).toHex())
        assertEquals(
            "1bffffffffffffffff",
            AgentCbor.encode(CborItem.Uint(BigInteger("18446744073709551615"))).toHex(),
        )
    }

    @Test
    fun `encodes the appendix A strings and containers`() {
        assertEquals("40", AgentCbor.encode(CborItem.Blob(ByteArray(0))).toHex())
        assertEquals("4401020304", AgentCbor.encode(CborItem.Blob("01020304".fromHex())).toHex())
        assertEquals("60", AgentCbor.encode(CborItem.Text("")).toHex())
        assertEquals("6449455446", AgentCbor.encode(CborItem.Text("IETF")).toHex())
        assertEquals("63e6b0b4", AgentCbor.encode(CborItem.Text("水")).toHex())
        assertEquals(
            "83010203",
            AgentCbor.encode(CborItem.Arr(listOf(uint(1), uint(2), uint(3)))).toHex(),
        )
        assertEquals(
            "a26161016162820203",
            AgentCbor.encode(
                CborItem.Dict(
                    listOf(
                        CborItem.Text("a") to uint(1),
                        CborItem.Text("b") to CborItem.Arr(listOf(uint(2), uint(3))),
                    ),
                ),
            ).toHex(),
        )
        assertEquals("d9d9f700", AgentCbor.encode(CborItem.Tagged(AgentCbor.SELF_DESCRIBE_TAG, uint(0))).toHex())
    }

    @Test
    fun `a value beyond an unsigned 64-bit argument is refused rather than truncated`() {
        val tooBig = CborItem.Uint(BigInteger("18446744073709551616"))
        assertFailsWith<AgentCborException> { AgentCbor.encode(tooBig) }
    }

    @Test
    fun `reads the indefinite-length map a replica answers with`() {
        val body = AgentCbor.textMap(AgentCbor.untag(AgentCbor.decode(vector("whoami-anonymous-reply.cbor"))))
        checkNotNull(body)
        assertEquals("replied", (body["status"] as CborItem.Text).value)
        assertTrue(body.containsKey("signatures"))
    }

    @Test
    fun `refuses everything outside the agent wire format`() {
        // A negative integer, a float, an indefinite-length text string, a break byte where
        // a value belongs (major type 7 has no indefinite form), and a reserved additional
        // information value.
        listOf("20", "f97e00", "7f6161ff", "ff", "1c").forEach { hex ->
            assertFailsWith<AgentCborException>(hex) { AgentCbor.decode(hex.fromHex()) }
        }
    }

    @Test
    fun `refuses a length the input cannot hold`() {
        assertFailsWith<AgentCborException> { AgentCbor.decode("5bffffffffffffffff".fromHex()) }
        assertFailsWith<AgentCborException> { AgentCbor.decode("9bffffffffffffffff".fromHex()) }
    }

    @Test
    fun `refuses trailing bytes and truncated input`() {
        assertFailsWith<AgentCborException> { AgentCbor.decode("0000".fromHex()) }
        assertFailsWith<AgentCborException> { AgentCbor.decode("18".fromHex()) }
        assertFailsWith<AgentCborException> { AgentCbor.decode("42ab".fromHex()) }
    }

    @Test
    fun `decodes the appendix A values, not just encodes them`() {
        // The encoder assertions above cannot see a reader that misreads a width: everything
        // else in this module hands the reader bytes the encoder never wrote.
        fun uintOf(hex: String) = (AgentCbor.decode(hex.fromHex()) as CborItem.Uint).value
        assertEquals(BigInteger.ZERO, uintOf("00"))
        assertEquals(BigInteger.valueOf(24), uintOf("1818"))
        assertEquals(BigInteger.valueOf(1000), uintOf("1903e8"))
        assertEquals(BigInteger.valueOf(1000000), uintOf("1a000f4240"))
        assertEquals(BigInteger.valueOf(1000000000000), uintOf("1b000000e8d4a51000"))
        assertEquals(BigInteger("18446744073709551615"), uintOf("1bffffffffffffffff"))
        assertEquals("IETF", (AgentCbor.decode("6449455446".fromHex()) as CborItem.Text).value)
        assertEquals("水", (AgentCbor.decode("63e6b0b4".fromHex()) as CborItem.Text).value)
        assertEquals("01020304", (AgentCbor.decode("4401020304".fromHex()) as CborItem.Blob).bytes.toHex())
        assertEquals(3, (AgentCbor.decode("83010203".fromHex()) as CborItem.Arr).items.size)
        val map = checkNotNull(AgentCbor.textMap(AgentCbor.decode("a26161016162820203".fromHex())))
        assertEquals(listOf("a", "b"), map.keys.toList())
    }

    @Test
    fun `refuses a map that gives the same key twice`() {
        // Two `a` keys. Last-one-wins would make the meaning depend on the reader.
        assertFailsWith<AgentCborException> {
            AgentCbor.textMap(AgentCbor.decode("a2616101616102".fromHex()))
        }
    }

    @Test
    fun `refuses text that is not UTF-8`() {
        assertFailsWith<AgentCborException> { AgentCbor.decode("62c328".fromHex()) }
    }
}
