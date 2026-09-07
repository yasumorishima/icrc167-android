package io.github.yasumorishima.icrc167.crypto

import io.github.yasumorishima.icrc167.SignatureCheck
import io.github.yasumorishima.icrc167.SignatureVerifier
import java.math.BigInteger
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Verifies the delegation signature schemes Internet Identity actually returns.
 *
 * Which one applies is decided by the algorithm identifier inside the DER SubjectPublicKeyInfo,
 * never by the length of the signature — a chain is attacker-supplied, and guessing the scheme
 * from the payload is how a verifier gets talked into using the wrong one.
 *
 * Canister signatures are **not** handled here: verifying one means verifying an IC state-tree
 * certificate against the root key, which needs BLS and belongs in the agent layer. They come
 * back as [SignatureCheck.UNSUPPORTED_KEY] — never as valid, and never confused with a forgery.
 * A genuine Internet Identity chain is signed at its root by exactly such a key, so this is the
 * expected answer for hop 0 until certificate verification exists.
 */
public class StandardSignatureVerifier : SignatureVerifier {

    override fun verify(
        derPublicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): SignatureCheck {
        val spki = try {
            SubjectPublicKeyInfo.getInstance(derPublicKey)
        } catch (_: Exception) {
            return SignatureCheck.UNSUPPORTED_KEY
        }

        return when (spki.algorithm.algorithm) {
            ED25519 -> verifyEd25519(spki, message, signature)
            EC_PUBLIC_KEY ->
                if (isP256(spki.algorithm.parameters)) {
                    verifyP256(spki, message, signature)
                } else {
                    // An EC key on another curve, or one carrying explicit curve parameters.
                    // WebCrypto emits neither.
                    SignatureCheck.UNSUPPORTED_KEY
                }
            else -> SignatureCheck.UNSUPPORTED_KEY
        }
    }

    /** True when [derPublicKey] names a scheme this verifier can check at all. */
    public fun supports(derPublicKey: ByteArray): Boolean = try {
        val algorithm = SubjectPublicKeyInfo.getInstance(derPublicKey).algorithm
        algorithm.algorithm == ED25519 ||
            (algorithm.algorithm == EC_PUBLIC_KEY && isP256(algorithm.parameters))
    } catch (_: Exception) {
        false
    }

    private fun verifyEd25519(
        spki: SubjectPublicKeyInfo,
        message: ByteArray,
        signature: ByteArray,
    ): SignatureCheck {
        val raw = spki.publicKeyData.bytes
        if (raw.size != ED25519_PUBLIC_KEY_BYTES) return SignatureCheck.UNSUPPORTED_KEY
        if (signature.size != ED25519_SIGNATURE_BYTES) return SignatureCheck.INVALID
        return try {
            val ok = Ed25519Signer().apply {
                init(false, Ed25519PublicKeyParameters(raw, 0))
                update(message, 0, message.size)
            }.verifySignature(signature)
            if (ok) SignatureCheck.VALID else SignatureCheck.INVALID
        } catch (_: Exception) {
            SignatureCheck.INVALID
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
    ): SignatureCheck {
        if (signature.size != P256_SIGNATURE_BYTES) return SignatureCheck.INVALID

        return try {
            val curve = CustomNamedCurves.getByName(P256_CURVE)
                ?: return SignatureCheck.UNSUPPORTED_KEY
            val point = curve.curve.decodePoint(spki.publicKeyData.bytes)
            // The point at infinity encodes fine but is not a usable public key.
            if (point.isInfinity || !point.isValid) return SignatureCheck.UNSUPPORTED_KEY

            val half = P256_SIGNATURE_BYTES / 2
            val r = BigInteger(1, signature.copyOfRange(0, half))
            val s = BigInteger(1, signature.copyOfRange(half, P256_SIGNATURE_BYTES))
            if (r.signum() <= 0 || s.signum() <= 0) return SignatureCheck.INVALID
            if (r >= curve.n || s >= curve.n) return SignatureCheck.INVALID

            val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h, curve.seed)
            val digest = MessageDigest.getInstance("SHA-256").digest(message)
            val ok = ECDSASigner().apply { init(false, ECPublicKeyParameters(point, domain)) }
                .verifySignature(digest, r, s)
            if (ok) SignatureCheck.VALID else SignatureCheck.INVALID
        } catch (_: Exception) {
            SignatureCheck.INVALID
        }
    }

    /**
     * The curve lives in the algorithm identifier's parameters. Compare the ASN.1 primitive
     * rather than casting the wrapper: for a named curve the parameters are an X9.62 CHOICE,
     * so the runtime type is not necessarily [ASN1ObjectIdentifier] even though it encodes
     * as one. Casting instead of unwrapping makes every P-256 key look unsupported, which
     * fails as a silent rejection rather than an error.
     *
     * Only the named-curve encoding is accepted. A key carrying explicit curve parameters is
     * refused: WebCrypto does not produce one, so anything that does is not a key this
     * transport should be honouring.
     */
    private fun isP256(parameters: ASN1Encodable?): Boolean =
        parameters?.toASN1Primitive() == PRIME256V1

    private companion object {
        // Spelled out rather than taken from a library constant: these OIDs are part of the
        // wire format being implemented, and the tests below encode real keys with an
        // independent implementation, so a wrong value here fails loudly.
        /** id-Ed25519, RFC 8410. */
        val ED25519 = ASN1ObjectIdentifier("1.3.101.112")

        /** id-ecPublicKey, RFC 5480. */
        val EC_PUBLIC_KEY = ASN1ObjectIdentifier("1.2.840.10045.2.1")

        /** secp256r1 / prime256v1 / NIST P-256, RFC 5480. */
        val PRIME256V1 = ASN1ObjectIdentifier("1.2.840.10045.3.1.7")

        const val P256_CURVE = "secp256r1"
        const val ED25519_PUBLIC_KEY_BYTES = 32
        const val ED25519_SIGNATURE_BYTES = 64
        const val P256_SIGNATURE_BYTES = 64
    }
}
