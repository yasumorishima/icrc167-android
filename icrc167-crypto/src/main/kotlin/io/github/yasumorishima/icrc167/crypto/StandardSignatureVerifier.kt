package io.github.yasumorishima.icrc167.crypto

import io.github.yasumorishima.icrc167.SignatureVerifier
import java.math.BigInteger
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.ec.CustomNamedCurves

/**
 * Verifies the delegation signature schemes Internet Identity actually returns.
 *
 * Which one applies is decided by the algorithm identifier inside the DER SubjectPublicKeyInfo,
 * never by the length of the signature — a chain is attacker-supplied, and guessing the scheme
 * from the payload is how a verifier gets talked into using the wrong one.
 *
 * Canister signatures are **not** handled here: verifying one means verifying an IC state-tree
 * certificate against the root key, which needs BLS and belongs in the agent layer. They are
 * reported as unverifiable rather than quietly accepted.
 */
public class StandardSignatureVerifier : SignatureVerifier {

    override fun verify(derPublicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val spki = try {
            SubjectPublicKeyInfo.getInstance(derPublicKey)
        } catch (_: Exception) {
            return false
        }

        return when (spki.algorithm.algorithm) {
            EdECObjectIdentifiers.id_Ed25519 -> verifyEd25519(spki, message, signature)
            X9ObjectIdentifiers.id_ecPublicKey -> verifyP256(spki, message, signature)
            else -> false
        }
    }

    /** True when [derPublicKey] names a scheme this verifier can check at all. */
    public fun supports(derPublicKey: ByteArray): Boolean = try {
        val algorithm = SubjectPublicKeyInfo.getInstance(derPublicKey).algorithm
        algorithm.algorithm == EdECObjectIdentifiers.id_Ed25519 ||
            (algorithm.algorithm == X9ObjectIdentifiers.id_ecPublicKey && isP256(algorithm.parameters))
    } catch (_: Exception) {
        false
    }

    private fun verifyEd25519(
        spki: SubjectPublicKeyInfo,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val raw = spki.publicKeyData.bytes
        if (raw.size != ED25519_PUBLIC_KEY_BYTES) return false
        if (signature.size != ED25519_SIGNATURE_BYTES) return false
        return try {
            Ed25519Signer().apply {
                init(false, Ed25519PublicKeyParameters(raw, 0))
                update(message, 0, message.size)
            }.verifySignature(signature)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * ECDSA on P-256 over SHA-256, with the signature in IEEE P1363 form (`r || s`, 32 bytes
     * each). That is what WebCrypto produces, and Internet Identity's intermediate keys come
     * from WebCrypto — a verifier expecting DER would reject every one of them.
     */
    private fun verifyP256(
        spki: SubjectPublicKeyInfo,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (!isP256(spki.algorithm.parameters)) return false
        if (signature.size != P256_SIGNATURE_BYTES) return false

        return try {
            val curve = CustomNamedCurves.getByName(P256_CURVE)
            val point = curve.curve.decodePoint(spki.publicKeyData.bytes)
            if (!point.isValid) return false

            val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h, curve.seed)
            val half = P256_SIGNATURE_BYTES / 2
            val r = BigInteger(1, signature.copyOfRange(0, half))
            val s = BigInteger(1, signature.copyOfRange(half, P256_SIGNATURE_BYTES))
            if (r.signum() <= 0 || s.signum() <= 0) return false
            if (r >= curve.n || s >= curve.n) return false

            val digest = MessageDigest.getInstance("SHA-256").digest(message)
            ECDSASigner().apply { init(false, ECPublicKeyParameters(point, domain)) }
                .verifySignature(digest, r, s)
        } catch (_: Exception) {
            false
        }
    }

    private fun isP256(parameters: Any?): Boolean =
        (parameters as? ASN1ObjectIdentifier) == X9ObjectIdentifiers.prime256v1

    private companion object {
        const val P256_CURVE = "P-256"
        const val ED25519_PUBLIC_KEY_BYTES = 32
        const val ED25519_SIGNATURE_BYTES = 64
        const val P256_SIGNATURE_BYTES = 64
    }
}
