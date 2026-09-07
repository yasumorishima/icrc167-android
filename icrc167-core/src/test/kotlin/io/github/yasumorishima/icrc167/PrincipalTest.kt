package io.github.yasumorishima.icrc167

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PrincipalTest {

    // Known answers from the IC itself, so the base32 + CRC32 encoding is pinned to
    // something outside this repository.
    @Test
    fun `encodes the management canister`() {
        assertEquals("aaaaa-aa", Principal.ofBytes(ByteArray(0)).toText())
    }

    @Test
    fun `encodes the anonymous principal`() {
        assertEquals("2vxsx-fae", Principal.ofBytes(byteArrayOf(0x04)).toText())
    }

    @Test
    fun `round trips a canister id`() {
        val text = "kvusz-kaaaa-aaaad-aabwa-cai"
        assertEquals(text, Principal.fromText(text).toText())
    }

    @Test
    fun `rejects a principal whose checksum does not match`() {
        assertFailsWith<IllegalArgumentException> {
            Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cak")
        }
    }

    @Test
    fun `a self authenticating principal is 29 bytes and ends with the 0x02 tag`() {
        val principal = Principal.selfAuthenticating(TestKey.generate().der)
        val bytes = principal.bytes
        assertEquals(29, bytes.size)
        assertEquals(0x02.toByte(), bytes[28])
        assertEquals(principal, Principal.fromText(principal.toText()))
    }

    @Test
    fun `distinct keys give distinct principals`() {
        val a = Principal.selfAuthenticating(TestKey.generate().der)
        val b = Principal.selfAuthenticating(TestKey.generate().der)
        assert(a != b)
    }
}
