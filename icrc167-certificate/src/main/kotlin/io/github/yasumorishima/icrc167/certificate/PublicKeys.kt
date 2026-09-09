package io.github.yasumorishima.icrc167.certificate

/** A public key that is not the shape this transport accepts. */
public class KeyFormatException(message: String) : IllegalArgumentException(message)

/**
 * The public key of an IC canister signature.
 *
 * A `SubjectPublicKeyInfo` with OID 1.3.6.1.4.1.56387.1.2 whose bit string is
 * `|signing_canister_id| · signing_canister_id · seed`. The seed is chosen by the signing
 * canister — Internet Identity puts a per-origin user id in it — so one canister has as many
 * of these keys as it has users.
 *
 * See the IC interface specification, "Canister signatures".
 */
public class CanisterSigPublicKey internal constructor(
    canisterId: ByteArray,
    seed: ByteArray,
) {
    private val rawCanisterId: ByteArray = canisterId.copyOf()
    private val rawSeed: ByteArray = seed.copyOf()

    /** The signing canister's principal, in its byte form. */
    public val canisterId: ByteArray get() = rawCanisterId.copyOf()

    public val seed: ByteArray get() = rawSeed.copyOf()

    public companion object {
        /** 1.3.6.1.4.1.56387.1.2, the canister-signature algorithm identifier. */
        private val OID = byteArrayOf(
            0x2B, 0x06, 0x01, 0x04, 0x01, 0x83.toByte(), 0xB8.toByte(), 0x43, 0x01, 0x02,
        )

        /** A principal is at most 29 bytes, so the length byte cannot legitimately exceed that. */
        private const val MAX_PRINCIPAL_BYTES = 29

        /**
         * True when [der] names the canister-signature scheme.
         *
         * Answers on the algorithm identifier alone, so a key that says "canister signature"
         * but is malformed inside still reports true: it must be rejected as a bad signature,
         * not quietly handed to some other verifier.
         */
        public fun isCanisterSignatureKey(der: ByteArray): Boolean = try {
            namesCanisterSignatures(der)
        } catch (_: KeyFormatException) {
            false
        }

        /** @throws KeyFormatException if [der] is not a well-formed canister-signature key */
        public fun fromDer(der: ByteArray): CanisterSigPublicKey {
            val bitString = bitStringOf(der) ?: throw KeyFormatException("not a canister signature public key")

            // The BIT STRING's first content byte counts the unused trailing bits. A key is a
            // whole number of bytes, so anything but zero is a different value than intended.
            if (bitString.end - bitString.start < 1 || der[bitString.start].toInt() != 0) {
                throw KeyFormatException("the key bit string must have no unused bits")
            }
            val raw = der.copyOfRange(bitString.start + 1, bitString.end)
            if (raw.isEmpty()) throw KeyFormatException("empty canister signature key")

            val idLength = raw[0].toInt() and 0xff
            if (idLength > MAX_PRINCIPAL_BYTES) {
                throw KeyFormatException("$idLength is longer than a principal can be")
            }
            if (raw.size < 1 + idLength) throw KeyFormatException("canister signature key is truncated")

            return CanisterSigPublicKey(
                canisterId = raw.copyOfRange(1, 1 + idLength),
                seed = raw.copyOfRange(1 + idLength, raw.size),
            )
        }

        /**
         * True when the algorithm identifier is ours.
         *
         * Deliberately looks no further: a key whose OID says "canister signature" belongs to
         * this verifier even if the rest of it is nonsense, and must come back as a bad
         * signature rather than being passed along to a verifier that would call it
         * unsupported.
         */
        private fun namesCanisterSignatures(der: ByteArray): Boolean {
            val spki = Der.readExactly(der, Der.SEQUENCE, 0, der.size, "SubjectPublicKeyInfo")
            val algorithm = Der.read(der, spki.start, spki.end)
            if (algorithm.tag != Der.SEQUENCE) throw KeyFormatException("missing algorithm identifier")
            val oid = Der.read(der, algorithm.start, algorithm.end)
            if (oid.tag != Der.OBJECT_IDENTIFIER) throw KeyFormatException("missing algorithm OID")
            return Der.contentEquals(der, oid, OID)
        }

        /** Returns the key's BIT STRING when the OID matches, null when it names another scheme. */
        private fun bitStringOf(der: ByteArray): Der.Tlv? {
            val spki = Der.readExactly(der, Der.SEQUENCE, 0, der.size, "SubjectPublicKeyInfo")
            val algorithm = Der.read(der, spki.start, spki.end)
            if (algorithm.tag != Der.SEQUENCE) throw KeyFormatException("missing algorithm identifier")
            val oid = Der.read(der, algorithm.start, algorithm.end)
            if (oid.tag != Der.OBJECT_IDENTIFIER) throw KeyFormatException("missing algorithm OID")
            if (!Der.contentEquals(der, oid, OID)) return null
            // The specification gives this algorithm no parameters. A key that carries some
            // is not the key the specification describes.
            if (oid.end != algorithm.end) throw KeyFormatException("the algorithm identifier carries parameters")
            return Der.readExactly(der, Der.BIT_STRING, algorithm.end, spki.end, "subjectPublicKey")
        }
    }
}

/**
 * The BLS keys that sign IC certificates: the root key, and the subnet keys it delegates to.
 *
 * Both are DER with OID 1.3.6.1.4.1.44668.5.3.1.2.1 over curve 1.3.6.1.4.1.44668.5.3.2.1, and
 * both are exactly 133 bytes because the key inside is a fixed-width 96-byte compressed G2
 * point. That makes the whole prefix a constant, which is how the reference implementation
 * reads it and is stricter than parsing the structure would be.
 */
public object IcBlsPublicKey {

    /** A raw (unwrapped) BLS12-381 public key: one compressed G2 point. */
    public const val RAW_LENGTH: Int = 96

    private val DER_PREFIX = byteArrayOf(
        0x30, 0x81.toByte(), 0x82.toByte(), 0x30, 0x1d, 0x06, 0x0d,
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82.toByte(), 0xdc.toByte(), 0x7c, 0x05, 0x03, 0x01, 0x02, 0x01,
        0x06, 0x0c,
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82.toByte(), 0xdc.toByte(), 0x7c, 0x05, 0x03, 0x02, 0x01,
        0x03, 0x61, 0x00,
    )

    /**
     * The IC mainnet root key, DER-encoded.
     *
     * This is the root of trust: everything a certificate proves, it proves relative to this
     * value. It is a constant of the network, not a configuration knob, and is reproduced here
     * from `IC_ROOT_PK_DER` in DFINITY's `ic-canister-sig-creation` crate.
     */
    public val MAINNET_ROOT_KEY_DER: ByteArray
        get() = MAINNET_ROOT_KEY_DER_BYTES.copyOf()

    /** [MAINNET_ROOT_KEY_DER] with the DER wrapper removed. */
    public val MAINNET_ROOT_KEY_RAW: ByteArray
        get() = MAINNET_ROOT_KEY_DER_BYTES.copyOfRange(DER_PREFIX.size, MAINNET_ROOT_KEY_DER_BYTES.size)

    private val MAINNET_ROOT_KEY_DER_BYTES: ByteArray = DER_PREFIX + hexToBytes(
        "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14" +
            "fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb71" +
            "7112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae",
    )

    /** @throws KeyFormatException if [der] is not a 133-byte IC BLS public key */
    public fun extractRaw(der: ByteArray): ByteArray {
        if (der.size != DER_PREFIX.size + RAW_LENGTH) {
            throw KeyFormatException("an IC BLS public key is ${DER_PREFIX.size + RAW_LENGTH} bytes, got ${der.size}")
        }
        for (i in DER_PREFIX.indices) {
            if (der[i] != DER_PREFIX[i]) throw KeyFormatException("not an IC BLS public key")
        }
        return der.copyOfRange(DER_PREFIX.size, der.size)
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
