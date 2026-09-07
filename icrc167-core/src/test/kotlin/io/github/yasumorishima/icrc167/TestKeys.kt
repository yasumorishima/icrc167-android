package io.github.yasumorishima.icrc167

import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Ed25519 helpers for building synthetic delegation chains.
 *
 * Real chains from Internet Identity also contain canister signatures and P-256 intermediate
 * keys; those need the IC certificate machinery and are exercised separately. Ed25519 is
 * enough to pin down the chain-walking rules, which is what these tests are about.
 */
internal class TestKey private constructor(
    private val privateKey: Ed25519PrivateKeyParameters,
    private val publicKey: Ed25519PublicKeyParameters,
) {
    /** DER SubjectPublicKeyInfo: the fixed Ed25519 prefix followed by the 32 raw bytes. */
    val der: ByteArray get() = SPKI_PREFIX + publicKey.encoded

    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    companion object {
        val SPKI_PREFIX: ByteArray = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )

        fun generate(): TestKey {
            val generator = Ed25519KeyPairGenerator()
            generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
            val pair = generator.generateKeyPair()
            return TestKey(
                pair.private as Ed25519PrivateKeyParameters,
                pair.public as Ed25519PublicKeyParameters,
            )
        }
    }
}

/** Verifies Ed25519 SPKI keys; anything else is reported as unsupported, not as a forgery. */
internal val ed25519Verifier = SignatureVerifier { der, message, signature ->
    if (der.size != TestKey.SPKI_PREFIX.size + 32 ||
        !der.copyOfRange(0, TestKey.SPKI_PREFIX.size).contentEquals(TestKey.SPKI_PREFIX)
    ) {
        return@SignatureVerifier SignatureCheck.UNSUPPORTED_KEY
    }
    val raw = der.copyOfRange(TestKey.SPKI_PREFIX.size, der.size)
    val verifier = Ed25519Signer()
    verifier.init(false, Ed25519PublicKeyParameters(raw, 0))
    verifier.update(message, 0, message.size)
    if (verifier.verifySignature(signature)) SignatureCheck.VALID else SignatureCheck.INVALID
}

internal fun nanosFromNow(seconds: Long): BigInteger =
    BigInteger.valueOf(System.currentTimeMillis())
        .multiply(BigInteger.valueOf(1_000_000))
        .add(BigInteger.valueOf(seconds).multiply(BigInteger.valueOf(1_000_000_000)))

internal fun nowNanos(): BigInteger = nanosFromNow(0)

/** Builds `root -> ... -> session`, signing each hop with the key it follows. */
internal fun buildChain(
    root: TestKey,
    hops: List<TestKey>,
    expiration: BigInteger = nanosFromNow(3600),
    targets: List<Principal>? = null,
): DelegationChain {
    var signer = root
    val delegations = hops.map { next ->
        val delegation = Delegation(next.der, expiration, targets)
        val signed = SignedDelegation(delegation, signer.sign(delegation.signableBytes()))
        signer = next
        signed
    }
    return DelegationChain(root.der, delegations)
}
