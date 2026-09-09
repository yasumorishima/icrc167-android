package io.github.yasumorishima.icrc167.certificate

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PublicKeysTest {

    /**
     * The canister-signature key from the Internet Identity chain in
     * dfinity/internet-identity's own test: canister `fgte5-ciaaa-aaaad-aaatq-cai`, and a
     * 32-byte seed.
     */
    private val iiKey = hex(
        "303c300c060a2b0601040183b8430102032c000a00000000006000270101" +
            "f3ffab2278616508ad5ebfa0cb79a21e08dbb7132f6875b95f81e72067f31302",
    )

    @Test
    fun `reads the canister id and seed out of a real key`() {
        val key = CanisterSigPublicKey.fromDer(iiKey)
        assertContentEquals(hex("00000000006000270101"), key.canisterId)
        assertContentEquals(
            hex("f3ffab2278616508ad5ebfa0cb79a21e08dbb7132f6875b95f81e72067f31302"),
            key.seed,
        )
    }

    /** The builder below has to produce the real key, or the negative cases prove nothing. */
    @Test
    fun `the key builder agrees with the real key`() {
        assertContentEquals(
            iiKey,
            canisterSigKey(hex("0a00000000006000270101f3ffab2278616508ad5ebfa0cb79a21e08dbb7132f6875b95f81e72067f31302")),
        )
    }

    @Test
    fun `recognises the scheme by its algorithm identifier`() {
        assertTrue(CanisterSigPublicKey.isCanisterSignatureKey(iiKey))
        // An Ed25519 SubjectPublicKeyInfo: same shape, different OID.
        assertFalse(
            CanisterSigPublicKey.isCanisterSignatureKey(hex("302a300506032b6570032100" + "00".repeat(32))),
        )
    }

    /**
     * A key that names this scheme but is broken inside must still be recognised as ours, so
     * it comes back as a bad signature rather than being passed to a verifier that would call
     * it unsupported.
     */
    @Test
    fun `a truncated canister signature key still names the scheme`() {
        // The length byte promises ten bytes of canister id; two follow.
        val truncated = canisterSigKey(byteArrayOf(10, 1, 2))
        assertTrue(CanisterSigPublicKey.isCanisterSignatureKey(truncated))
        assertFailsWith<KeyFormatException> { CanisterSigPublicKey.fromDer(truncated) }
    }

    @Test
    fun `refuses a canister id longer than a principal can be`() {
        assertFailsWith<KeyFormatException> {
            CanisterSigPublicKey.fromDer(canisterSigKey(byteArrayOf(40) + ByteArray(40)))
        }
    }

    @Test
    fun `refuses trailing bytes after the key`() {
        assertFailsWith<KeyFormatException> { CanisterSigPublicKey.fromDer(iiKey + byteArrayOf(0)) }
    }

    @Test
    fun `refuses a bit string with unused bits`() {
        assertFailsWith<KeyFormatException> {
            CanisterSigPublicKey.fromDer(canisterSigKey(byteArrayOf(1, 9), unusedBits = 1))
        }
    }

    @Test
    fun `refuses an algorithm identifier that carries parameters`() {
        // The same OID followed by NULL parameters, which this algorithm does not have.
        val algorithm = hex("300e060a2b0601040183b84301020500")
        val bitString = byteArrayOf(0x03, 0x03, 0x00, 0x01, 0x02)
        val body = algorithm + bitString
        val der = byteArrayOf(0x30, body.size.toByte()) + body
        assertTrue(CanisterSigPublicKey.isCanisterSignatureKey(der))
        assertFailsWith<KeyFormatException> { CanisterSigPublicKey.fromDer(der) }
    }

    @Test
    fun `refuses non-minimal DER lengths`() {
        // The real key with its outer length written in the long form: valid BER, not DER.
        val body = iiKey.copyOfRange(2, iiKey.size)
        val longForm = byteArrayOf(0x30, 0x81.toByte(), body.size.toByte()) + body
        assertFailsWith<KeyFormatException> { CanisterSigPublicKey.fromDer(longForm) }
    }

    @Test
    fun `unwraps the mainnet root key`() {
        val raw = IcBlsPublicKey.extractRaw(IcBlsPublicKey.MAINNET_ROOT_KEY_DER)
        assertEquals(IcBlsPublicKey.RAW_LENGTH, raw.size)
        assertContentEquals(IcBlsPublicKey.MAINNET_ROOT_KEY_RAW, raw)
    }

    @Test
    fun `the mainnet root key is the published one`() {
        // Reproduced from IC_ROOT_PK_DER in DFINITY's ic-canister-sig-creation crate. If this
        // ever fails the root of trust has been edited, which is the one change in this
        // repository that no other test could catch.
        assertEquals(
            "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14" +
                "fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb71" +
                "7112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae",
            toHex(IcBlsPublicKey.MAINNET_ROOT_KEY_RAW),
        )
    }

    @Test
    fun `refuses a BLS key of the wrong length or prefix`() {
        assertFailsWith<KeyFormatException> { IcBlsPublicKey.extractRaw(ByteArray(132)) }
        val wrongOid = IcBlsPublicKey.MAINNET_ROOT_KEY_DER.copyOf().also { it[6] = 0x0c }
        assertFailsWith<KeyFormatException> { IcBlsPublicKey.extractRaw(wrongOid) }
    }

    /** A SubjectPublicKeyInfo for OID 1.3.6.1.4.1.56387.1.2 around an arbitrary payload. */
    private fun canisterSigKey(payload: ByteArray, unusedBits: Int = 0): ByteArray {
        val algorithm = hex("300c060a2b0601040183b8430102")
        val bitString = byteArrayOf(0x03, (payload.size + 1).toByte(), unusedBits.toByte()) + payload
        val body = algorithm + bitString
        check(body.size < 0x80) { "the short-form length below only covers small keys" }
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun toHex(value: ByteArray): String {
        val digits = "0123456789abcdef"
        val out = StringBuilder(value.size * 2)
        for (b in value) {
            val v = b.toInt() and 0xff
            out.append(digits[v shr 4]).append(digits[v and 0x0f])
        }
        return out.toString()
    }
}
