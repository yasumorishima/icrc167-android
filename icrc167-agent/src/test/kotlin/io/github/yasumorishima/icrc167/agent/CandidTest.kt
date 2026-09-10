package io.github.yasumorishima.icrc167.agent

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CandidTest {

    @Test
    fun `reads the principal mainnet answered whoami with`() {
        // 4449444c 00 01 68 | 01 01 04 -- DIDL, no type table, one value of type principal,
        // then form 1 and one byte: the anonymous principal.
        val arg = "4449444c000168010104".fromHex()
        assertEquals("2vxsx-fae", Candid.decodePrincipal(arg).toText())
    }

    @Test
    fun `reads a self-authenticating principal`() {
        // 28 bytes of digest and the 0x02 tag: the shape a delegation chain resolves to.
        val id = ByteArray(28) { (it + 1).toByte() } + byteArrayOf(0x02)
        val arg = "4449444c0001680101".fromHex().dropLast(1).toByteArray() +
            byteArrayOf(29) + id
        assertEquals(id.toHex(), Candid.decodePrincipal(arg).bytes.toHex())
    }

    @Test
    fun `refuses a message that is not Candid`() {
        assertFailsWith<CandidException> { Candid.decodePrincipal("00".fromHex()) }
        assertFailsWith<CandidException> { Candid.decodePrincipal("4449444d000168010104".fromHex()) }
    }

    @Test
    fun `refuses anything but exactly one principal`() {
        // A non-empty type table, then two return values, then a nat where a principal belongs.
        assertFailsWith<CandidException> { Candid.decodePrincipal("4449444c0101680104".fromHex()) }
        assertFailsWith<CandidException> { Candid.decodePrincipal("4449444c00026868010104".fromHex()) }
        assertFailsWith<CandidException> { Candid.decodePrincipal("4449444c00017d01".fromHex()) }
    }

    @Test
    fun `refuses the opaque reference form`() {
        // Form 0 is a service reference the caller cannot name. It is not an identity, and
        // reading it as one would turn "I could not tell you who" into a principal.
        val e = assertFailsWith<CandidException> { Candid.decodePrincipal("4449444c00016800".fromHex()) }
        assertEquals(true, e.message!!.contains("form 0"))
    }

    @Test
    fun `refuses a length that disagrees with the message`() {
        assertFailsWith<CandidException> { Candid.decodePrincipal("4449444c00016801030400".fromHex()) }
        assertFailsWith<CandidException> { Candid.decodePrincipal("4449444c000168010104ff".fromHex()) }
        assertFailsWith<CandidException> { Candid.decodePrincipal("4449444c0001680101".fromHex()) }
    }

    @Test
    fun `refuses a principal longer than the specification allows`() {
        val arg = "4449444c00016801".fromHex() + byteArrayOf(30) + ByteArray(30)
        assertFailsWith<CandidException> { Candid.decodePrincipal(arg) }
    }
}
