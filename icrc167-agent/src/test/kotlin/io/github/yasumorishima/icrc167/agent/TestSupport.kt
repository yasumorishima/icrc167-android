package io.github.yasumorishima.icrc167.agent

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

internal fun String.fromHex(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

internal fun vector(name: String): ByteArray =
    checkNotNull(object {}.javaClass.getResourceAsStream("/vectors/$name")) {
        "missing test vector $name"
    }.use { it.readBytes() }

/**
 * An Ed25519 key that can be pinned to a seed, so an envelope built here is byte-for-byte the
 * one the capture script built. Ed25519 signatures are deterministic, which is what makes a
 * whole-envelope fixture possible at all.
 */
internal class TestKey(private val privateKey: org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters) {

    val der: ByteArray get() = SPKI_PREFIX + privateKey.generatePublicKey().encoded

    fun sign(message: ByteArray): ByteArray {
        val signer = org.bouncycastle.crypto.signers.Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun signer(): Signer = Signer { sign(it) }

    companion object {
        val SPKI_PREFIX: ByteArray = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )

        fun ofSeed(seed: ByteArray): TestKey =
            TestKey(org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0))

        fun counting(from: Int): TestKey = ofSeed(ByteArray(32) { (from + it).toByte() })

        fun random(): TestKey {
            val seed = ByteArray(32)
            java.security.SecureRandom().nextBytes(seed)
            return ofSeed(seed)
        }
    }
}

internal fun ed25519Verify(der: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    val raw = der.copyOfRange(TestKey.SPKI_PREFIX.size, der.size)
    val verifier = org.bouncycastle.crypto.signers.Ed25519Signer()
    verifier.init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(raw, 0))
    verifier.update(message, 0, message.size)
    return verifier.verifySignature(signature)
}

internal fun vectorText(name: String): String = String(vector(name), Charsets.UTF_8).trim()
