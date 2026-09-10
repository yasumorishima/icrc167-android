package io.github.yasumorishima.icrc167.canistersig

import io.github.yasumorishima.icrc167.SignatureCheck
import io.github.yasumorishima.icrc167.SignatureVerifier
import io.github.yasumorishima.icrc167.certificate.BlsSignatureVerifier
import io.github.yasumorishima.icrc167.certificate.CanisterSigPublicKey
import io.github.yasumorishima.icrc167.certificate.CanisterSigVerification
import io.github.yasumorishima.icrc167.certificate.CanisterSignatureValidator
import io.github.yasumorishima.icrc167.certificate.IcBlsPublicKey

/**
 * The [SignatureVerifier] for IC canister signatures — the scheme a real Internet Identity
 * chain is signed with at its root.
 *
 * Combine it with the Ed25519/P-256 verifier to check a whole chain:
 *
 * ```
 * CompositeSignatureVerifier(StandardSignatureVerifier(), CanisterSignatureVerifier())
 * ```
 *
 * It lives in its own module because verifying one of these means pairing arithmetic on
 * BLS12-381, which JVM code that checks no certificates at all need not carry.
 * The Android module does depend on it: every Internet Identity chain has a canister signature
 * at its root, so an app that signs in cannot do without it.
 *
 * This class is stateless and safe to share. Use [CanisterSignatureValidator] directly when
 * the reason for a rejection is wanted; the reason is deliberately not reachable from here,
 * because it describes an attacker-supplied structure and belongs in a log, not in a decision.
 *
 * @param rootPublicKeyRaw the root of trust. Defaults to the IC mainnet root key; pass a
 *   different one only to verify against a test network, and never one taken from the same
 *   response as the chain being checked.
 */
public class CanisterSignatureVerifier(
    rootPublicKeyRaw: ByteArray = IcBlsPublicKey.MAINNET_ROOT_KEY_RAW,
    bls: BlsSignatureVerifier = MiraclBls,
) : SignatureVerifier {

    private val validator = CanisterSignatureValidator(bls, rootPublicKeyRaw)

    override fun verify(
        derPublicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): SignatureCheck {
        // Dispatch on what the key says it is, never on the shape of the signature. A key
        // that names this scheme belongs here even when the rest of it is malformed —
        // reporting "unsupported" for that would let a broken canister signature fall through
        // to a verifier that has no opinion about it.
        if (!CanisterSigPublicKey.isCanisterSignatureKey(derPublicKey)) {
            return SignatureCheck.UNSUPPORTED_KEY
        }
        return when (validator.verify(message, signature, derPublicKey)) {
            CanisterSigVerification.Valid -> SignatureCheck.VALID
            is CanisterSigVerification.Invalid -> SignatureCheck.INVALID
        }
    }
}
