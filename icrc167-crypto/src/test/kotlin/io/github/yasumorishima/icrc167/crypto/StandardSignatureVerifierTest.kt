package io.github.yasumorishima.icrc167.crypto

import io.github.yasumorishima.icrc167.ChainVerification
import io.github.yasumorishima.icrc167.Delegation
import io.github.yasumorishima.icrc167.DelegationChain
import io.github.yasumorishima.icrc167.DelegationChainVerifier
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.SignatureCheck
import io.github.yasumorishima.icrc167.SignedDelegation
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory

class StandardSignatureVerifierTest {

    private val verifier = StandardSignatureVerifier()
    private val message = "the delegation being signed".toByteArray()

    // ---- Ed25519 -----------------------------------------------------------------

    @Test
    fun `accepts a valid Ed25519 signature`() {
        val key = Ed25519TestKey()
        assertEquals(SignatureCheck.VALID, verifier.verify(key.der, message, key.sign(message)))
    }

    @Test
    fun `rejects an Ed25519 signature over a different message`() {
        val key = Ed25519TestKey()
        assertEquals(
            SignatureCheck.INVALID,
            verifier.verify(key.der, message, key.sign("something else".toByteArray())),
        )
    }

    @Test
    fun `rejects an Ed25519 signature verified against another key`() {
        val signer = Ed25519TestKey()
        val other = Ed25519TestKey()
        assertEquals(
            SignatureCheck.INVALID,
            verifier.verify(other.der, message, signer.sign(message)),
        )
    }

    // ---- ECDSA P-256 -------------------------------------------------------------

    @Test
    fun `recognises Ed25519 and P-256 keys as supported`() {
        // The negative tests pass just as well when a key is not recognised at all, so
        // assert recognition on its own.
        assertTrue(verifier.supports(Ed25519TestKey().der))
        assertTrue(verifier.supports(P256TestKey().der))
    }

    @Test
    fun `accepts a valid P-256 signature in IEEE P1363 form`() {
        val key = P256TestKey()
        assertEquals(
            SignatureCheck.VALID,
            verifier.verify(key.der, message, key.signP1363(message)),
        )
    }

    @Test
    fun `rejects a P-256 signature in DER form`() {
        // WebCrypto — and therefore Internet Identity — emits r||s. Accepting DER as well
        // would mean guessing the encoding from attacker-controlled bytes.
        val key = P256TestKey()
        assertEquals(
            SignatureCheck.INVALID,
            verifier.verify(key.der, message, key.signDer(message)),
        )
    }

    @Test
    fun `rejects a P-256 signature made by another key`() {
        val signer = P256TestKey()
        val other = P256TestKey()
        assertEquals(
            SignatureCheck.INVALID,
            verifier.verify(other.der, message, signer.signP1363(message)),
        )
    }

    @Test
    fun `rejects a P-256 signature over a different message`() {
        val key = P256TestKey()
        assertEquals(
            SignatureCheck.INVALID,
            verifier.verify(key.der, message, key.signP1363("elsewhere".toByteArray())),
        )
    }

    @Test
    fun `rejects a P-256 signature whose r or s is out of range`() {
        val key = P256TestKey()
        assertEquals(SignatureCheck.INVALID, verifier.verify(key.der, message, ByteArray(64)))
    }

    @Test
    fun `refuses a P-256 key carrying explicit curve parameters`() {
        // Valid X.509, but not an encoding WebCrypto produces. Reported as unsupported
        // rather than invalid, so it can never be mistaken for a failed signature check.
        val key = P256TestKey(named = false)
        assertFalse(verifier.supports(key.der))
        assertEquals(
            SignatureCheck.UNSUPPORTED_KEY,
            verifier.verify(key.der, message, key.signP1363(message)),
        )
    }

    // ---- dispatch ----------------------------------------------------------------

    @Test
    fun `reports a canister signature key as unsupported, not as a forgery`() {
        // This is the key at the root of every real Internet Identity chain. Calling it a
        // bad signature would invite somebody to conclude the check itself is broken.
        val canisterSignatureKey = SubjectPublicKeyInfo(
            AlgorithmIdentifier(ASN1ObjectIdentifier("1.3.6.1.4.1.56387.1.2"), DERSequence()),
            ByteArray(32),
        ).encoded

        assertFalse(verifier.supports(canisterSignatureKey))
        assertEquals(
            SignatureCheck.UNSUPPORTED_KEY,
            verifier.verify(canisterSignatureKey, message, ByteArray(64)),
        )
    }

    @Test
    fun `refuses malformed key bytes instead of throwing`() {
        assertEquals(
            SignatureCheck.UNSUPPORTED_KEY,
            verifier.verify(byteArrayOf(1, 2, 3), message, ByteArray(64)),
        )
    }

    // ---- the shape Internet Identity actually returns -----------------------------

    @Test
    fun `verifies a chain whose intermediate key is P-256, as Internet Identity issues`() {
        // II signs over an ephemeral key of its own and adds a hop to our session key.
        // That intermediate comes from WebCrypto, so it is P-256 while the ends are not.
        val root = Ed25519TestKey()
        val intermediate = P256TestKey()
        val session = Ed25519TestKey()
        val expiration = nowNanos().add(BigInteger.valueOf(3_600_000_000_000L))

        val first = Delegation(intermediate.der, expiration)
        val second = Delegation(session.der, expiration)
        val chain = DelegationChain(
            root.der,
            listOf(
                SignedDelegation(first, root.sign(first.signableBytes())),
                SignedDelegation(second, intermediate.signP1363(second.signableBytes())),
            ),
        )

        val result = DelegationChainVerifier(verifier).verify(chain, session.der, nowNanos())

        assertIs<ChainVerification.Valid>(result)
        assertEquals(Principal.selfAuthenticating(root.der), result.principal)
    }

    private fun nowNanos(): BigInteger =
        BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(1_000_000))
}

private class Ed25519TestKey {
    private val privateKey: Ed25519PrivateKeyParameters
    private val publicKey: Ed25519PublicKeyParameters

    init {
        val generator = Ed25519KeyPairGenerator()
        generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val pair = generator.generateKeyPair()
        privateKey = pair.private as Ed25519PrivateKeyParameters
        publicKey = pair.public as Ed25519PublicKeyParameters
    }

    val der: ByteArray get() = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).encoded

    fun sign(message: ByteArray): ByteArray = Ed25519Signer().apply {
        init(true, privateKey)
        update(message, 0, message.size)
    }.generateSignature()
}

/**
 * @param named when true the SubjectPublicKeyInfo names the curve by OID, which is what
 *   WebCrypto emits. Given plain [ECDomainParameters] instead, Bouncy Castle writes the whole
 *   curve out as explicit parameters — an encoding this library deliberately refuses, and one
 *   a fixture must be able to produce in order to test that refusal.
 */
private class P256TestKey(named: Boolean = true) {
    private val curve = CustomNamedCurves.getByName("secp256r1")
    private val domain: ECDomainParameters = if (named) {
        ECNamedDomainParameters(ASN1ObjectIdentifier("1.2.840.10045.3.1.7"), curve)
    } else {
        ECDomainParameters(curve.curve, curve.g, curve.n, curve.h, curve.seed)
    }
    private val privateKey: ECPrivateKeyParameters
    private val publicKey: ECPublicKeyParameters

    init {
        val generator = ECKeyPairGenerator()
        generator.init(ECKeyGenerationParameters(domain, SecureRandom()))
        val pair = generator.generateKeyPair()
        privateKey = pair.private as ECPrivateKeyParameters
        publicKey = pair.public as ECPublicKeyParameters
    }

    val der: ByteArray get() = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).encoded

    private fun rawSignature(message: ByteArray): Array<BigInteger> {
        val digest = MessageDigest.getInstance("SHA-256").digest(message)
        val signer = ECDSASigner()
        signer.init(true, ParametersWithRandom(privateKey, SecureRandom()))
        return signer.generateSignature(digest)
    }

    fun signP1363(message: ByteArray): ByteArray {
        val (r, s) = rawSignature(message)
        return pad32(r) + pad32(s)
    }

    fun signDer(message: ByteArray): ByteArray {
        val (r, s) = rawSignature(message)
        return DERSequence(
            arrayOf(
                org.bouncycastle.asn1.ASN1Integer(r),
                org.bouncycastle.asn1.ASN1Integer(s),
            ),
        ).encoded
    }

    private fun pad32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
            .let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return ByteArray(32 - bytes.size) + bytes
    }
}
