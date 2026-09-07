package io.github.yasumorishima.icrc167.certificate

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/** The reader is a security boundary, so what it refuses matters as much as what it reads. */
class CborTest {

    @Test
    fun `reads the shapes a certificate is made of`() {
        assertEquals(42L, (Cbor.decode("182a".hexToBytes()) as CborValue.Unsigned).value)
        assertEquals("hello", (Cbor.decode("6568656c6c6f".hexToBytes()) as CborValue.Text).value)
        assertEquals(3, (Cbor.decode("83010203".hexToBytes()) as CborValue.Items).items.size)
        // a1 4161 01 = a one-entry map from the byte string "a" to 1
        assertEquals(1, (Cbor.decode("a1416101".hexToBytes()) as CborValue.Entries).entries.size)
    }

    @Test
    fun `reads the self-describe tag every certificate is wrapped in`() {
        // d9d9f7 is tag 55799, followed by an empty map.
        val tagged = Cbor.decode("d9d9f7a0".hexToBytes())
        assertIs<CborValue.Tagged>(tagged)
        assertEquals(Cbor.SELF_DESCRIBE_TAG, tagged.tag)
    }

    @Test
    fun `refuses trailing bytes`() {
        // Otherwise two different encodings could be accepted as the same value.
        assertFailsWith<CborException> { Cbor.decode("01ff".hexToBytes()) }
    }

    @Test
    fun `refuses indefinite lengths`() {
        assertFailsWith<CborException> { Cbor.decode("9f01ff".hexToBytes()) }
        assertFailsWith<CborException> { Cbor.decode("5f42010243030405ff".hexToBytes()) }
    }

    @Test
    fun `refuses a length the input cannot possibly satisfy`() {
        // A four-byte header asking for four billion items must not become four billion
        // allocations before the input runs out.
        assertFailsWith<CborException> { Cbor.decode("9affffffff".hexToBytes()) }
        assertFailsWith<CborException> { Cbor.decode("5affffffff".hexToBytes()) }
    }

    @Test
    fun `refuses a value that ends mid-way`() {
        assertFailsWith<CborException> { Cbor.decode("8301".hexToBytes()) }
    }

    @Test
    fun `refuses major types a certificate never uses`() {
        assertFailsWith<CborException> { Cbor.decode("20".hexToBytes()) } // negative integer
        assertFailsWith<CborException> { Cbor.decode("f6".hexToBytes()) } // null
    }
}
