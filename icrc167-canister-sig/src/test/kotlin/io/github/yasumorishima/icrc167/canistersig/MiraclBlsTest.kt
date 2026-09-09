package io.github.yasumorishima.icrc167.canistersig

import io.github.yasumorishima.icrc167.certificate.Certificate
import io.github.yasumorishima.icrc167.certificate.IcBlsPublicKey
import io.github.yasumorishima.icrc167.certificate.Lookup
import io.github.yasumorishima.icrc167.certificate.lookupPath
import io.github.yasumorishima.icrc167.certificate.reconstruct
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.miracl.core.BLS12381.BIG
import org.miracl.core.BLS12381.CONFIG_BIG
import org.miracl.core.BLS12381.PAIR

/**
 * Fixes the message-to-curve step against RFC 9380's own vectors.
 *
 * This is the step that cannot be checked by looking at it: the map is a page of field
 * arithmetic, the domain separation tag disappears into a hash, and getting either wrong
 * produces a perfectly well-formed point that no signature will ever match. The end-to-end
 * vectors in [CanisterSignatureVerifierTest] would catch that too, but only as "nothing
 * verifies", which is the same symptom as a dozen other mistakes. These pin the arithmetic on
 * its own, with answers computed by somebody else.
 *
 * RFC 9380, appendix J.9.1, suite BLS12381G1_XMD:SHA-256_SSWU_RO_.
 */
class MiraclBlsTest {

    private val rfcDst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"

    @Test
    fun `hashes the empty message to the point RFC 9380 says`() {
        assertPoint(
            message = "",
            x = "052926add2207b76ca4fa57a8734416c8dc95e24501772c8142787" +
                "00eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
            y = "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c6" +
                "7e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
        )
    }

    @Test
    fun `hashes abc to the point RFC 9380 says`() {
        assertPoint(
            message = "abc",
            x = "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a794" +
                "3388a49a3aee664ba5379a7655d3c68900be2f6903",
            y = "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67" +
                "af215533311f0b8dfaaa154fa6b88176c229f2885d",
        )
    }

    /**
     * The tag is part of the answer, not decoration. If MIRACL's own `BLS.java` tag were used
     * instead of the IC's, this is the difference that would go unnoticed.
     */
    @Test
    fun `a different domain separation tag gives a different point`() {
        val withRfcTag = MiraclBls.hashToPoint("abc".toByteArray(), rfcDst)
        val withIcTag = MiraclBls.hashToPoint("abc".toByteArray())
        assertNotEquals(hex(withRfcTag.x), hex(withIcTag.x), "the tag did not reach the hash")
    }

    @Test
    fun `refuses public keys and signatures of the wrong size`() {
        assertFalse(MiraclBls.verify(ByteArray(95), byteArrayOf(1), ByteArray(48)))
        assertFalse(MiraclBls.verify(ByteArray(96), byteArrayOf(1), ByteArray(47)))
    }

    /** Every IC point is compressed; an uncompressed one is not a shorter path, it is a lie. */
    @Test
    fun `refuses a point that is not flagged compressed`() {
        val key = ByteArray(96).also { it[0] = 0x40 }
        assertFalse(MiraclBls.verify(key, byteArrayOf(1), ByteArray(48).also { it[0] = 0xC0.toByte() }))
    }

    /** Infinity has exactly one encoding, and it is not a public key. */
    @Test
    fun `refuses the identity as a public key`() {
        val key = ByteArray(96).also { it[0] = 0xC0.toByte() }
        val signature = ByteArray(48).also { it[0] = 0xC0.toByte() }
        assertFalse(MiraclBls.verify(key, byteArrayOf(1), signature))
    }

    @Test
    fun `refuses an infinity encoding with bits set after the flags`() {
        val key = ByteArray(96).also { it[0] = 0xC0.toByte(); it[95] = 1 }
        assertFalse(MiraclBls.verify(key, byteArrayOf(1), ByteArray(48).also { it[0] = 0xC0.toByte() }))
    }

    // The pairing itself. Every other negative case in this repository stops earlier — a
    // flipped byte lands in a coordinate, so the point either fails to decode or fails the
    // subgroup check — which left `verify` able to return true unconditionally with the whole
    // suite still green. Measured, not guessed: the mutation was pushed to CI. These four use
    // points that all decode and are all in their subgroups, so only the equation can decide.

    /** The root subnet signed the delegation inside the captured certificate. */
    private val delegated = Certificate.fromCbor(
        requireNotNull(Certificate.fromCbor(Vectors.hex("live-certificate")).delegation).certificate,
    )

    private val outer = Certificate.fromCbor(Vectors.hex("live-certificate"))

    /** `domain_sep("ic-state-root")`, the prefix a subnet signs before the root hash. */
    private val stateRoot = byteArrayOf(0x0D) + "ic-state-root".toByteArray()

    private fun signed(certificate: Certificate) = stateRoot + certificate.tree.reconstruct()

    private val subnetKey: ByteArray
        get() {
            val lookup = delegated.tree.lookupPath(
                listOf(
                    "subnet".toByteArray(),
                    requireNotNull(outer.delegation).subnetId,
                    "public_key".toByteArray(),
                ),
            )
            return IcBlsPublicKey.extractRaw(assertIs<Lookup.Found>(lookup).value)
        }

    @Test
    fun `verifies a signature the root subnet really made`() {
        assertTrue(
            MiraclBls.verify(IcBlsPublicKey.MAINNET_ROOT_KEY_RAW, signed(delegated), delegated.signature),
        )
    }

    @Test
    fun `verifies a signature the delegated subnet really made`() {
        assertTrue(MiraclBls.verify(subnetKey, signed(outer), outer.signature))
    }

    @Test
    fun `refuses a genuine signature over a message it does not cover`() {
        val elsewhere = signed(delegated).also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertFalse(
            MiraclBls.verify(IcBlsPublicKey.MAINNET_ROOT_KEY_RAW, elsewhere, delegated.signature),
        )
    }

    /** Both keys are real subnet keys, in the subgroup; only one of them made this signature. */
    @Test
    fun `refuses a genuine signature under the wrong genuine key`() {
        assertFalse(MiraclBls.verify(subnetKey, signed(delegated), delegated.signature))
        assertFalse(
            MiraclBls.verify(IcBlsPublicKey.MAINNET_ROOT_KEY_RAW, signed(outer), outer.signature),
        )
    }

    // The public key decoder.

    @Test
    fun `reads the mainnet root key`() {
        val key = assertNotNull(MiraclBls.decodeG2(IcBlsPublicKey.MAINNET_ROOT_KEY_RAW))
        assertFalse(key.is_infinity())
        assertTrue(PAIR.G2member(key), "a published subnet key is in the prime-order subgroup")
    }

    @Test
    fun `refuses a public key whose real part is not a field element`() {
        val encoded = IcBlsPublicKey.MAINNET_ROOT_KEY_RAW.copyOf()
        for (i in 48 until 96) encoded[i] = 0xff.toByte()
        assertNull(MiraclBls.decodeG2(encoded))
    }

    @Test
    fun `refuses an uncompressed public key encoding`() {
        assertNull(MiraclBls.decodeG2(ByteArray(96)))
    }

    @Test
    fun `reads the one encoding of infinity in G2`() {
        assertTrue(assertNotNull(MiraclBls.decodeG2(ByteArray(96).also { it[0] = 0xc0.toByte() })).is_infinity())
        assertNull(MiraclBls.decodeG2(ByteArray(96).also { it[0] = 0xc0.toByte(); it[95] = 1 }))
    }

    // The signature decoder. `verify` reads the public key first, so nothing below would be
    // reached through it; these call the decoder directly and say what it returned.

    @Test
    fun `reads a signature that is a point on the curve`() {
        // x = 0 satisfies y^2 = x^3 + 4 with y = 2, so this is a well-formed encoding.
        val encoded = ByteArray(48).also { it[0] = 0x80.toByte() }
        val point = assertNotNull(MiraclBls.decodeG1(encoded), "x = 0 is on the curve")
        assertEquals("00".repeat(48), hex(point.x))
        // ...and it is not in the prime-order subgroup, which is the reason `verify` checks.
        assertFalse(PAIR.G1member(point), "a curve point is not automatically a group element")
    }

    @Test
    fun `refuses a signature whose x is not a field element`() {
        // 381 bits of ones, which is larger than the modulus.
        val encoded = ByteArray(48) { 0xff.toByte() }.also { it[0] = 0x9f.toByte() }
        assertNull(MiraclBls.decodeG1(encoded))
    }

    @Test
    fun `refuses a signature whose x is on no point of the curve`() {
        // x = 1 gives y^2 = 5, and 5 is not a square modulo the BLS12-381 field prime.
        val encoded = ByteArray(48).also { it[0] = 0x80.toByte(); it[47] = 1 }
        assertNull(MiraclBls.decodeG1(encoded))
    }

    /** The sign bit picks between y and p - y, and both encodings must decode to their own. */
    @Test
    fun `the sign bit chooses which root of y is meant`() {
        val low = ByteArray(48).also { it[0] = 0x80.toByte() }
        val high = ByteArray(48).also { it[0] = 0xa0.toByte() }
        val yLow = assertNotNull(MiraclBls.decodeG1(low)).y
        val yHigh = assertNotNull(MiraclBls.decodeG1(high)).y
        assertNotEquals(hex(yLow), hex(yHigh))
        // Exactly one of them is the larger; that is what the bit records.
        assertTrue(hex(yHigh) > hex(yLow), "the set bit must select the larger root")
    }

    @Test
    fun `refuses an uncompressed signature encoding`() {
        assertNull(MiraclBls.decodeG1(ByteArray(48)))
    }

    @Test
    fun `reads the one encoding of infinity`() {
        val infinity = ByteArray(48).also { it[0] = 0xc0.toByte() }
        assertTrue(assertNotNull(MiraclBls.decodeG1(infinity)).is_infinity())
        // The sign bit has nothing to sign.
        assertNull(MiraclBls.decodeG1(ByteArray(48).also { it[0] = 0xe0.toByte() }))
    }

    private fun assertPoint(message: String, x: String, y: String) {
        val point = MiraclBls.hashToPoint(message.toByteArray(Charsets.UTF_8), rfcDst)
        assertEquals(x, hex(point.x), "x")
        assertEquals(y, hex(point.y), "y")
    }

    /** Spelled out rather than via String.format, whose digits are locale-dependent. */
    private fun hex(value: BIG): String {
        val bytes = ByteArray(CONFIG_BIG.MODBYTES)
        value.toBytes(bytes)
        val digits = "0123456789abcdef"
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(digits[v shr 4]).append(digits[v and 0x0f])
        }
        return out.toString()
    }
}
