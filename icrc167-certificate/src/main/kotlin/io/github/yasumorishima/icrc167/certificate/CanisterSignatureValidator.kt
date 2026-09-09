package io.github.yasumorishima.icrc167.certificate

import java.security.MessageDigest

/** The outcome of checking a canister signature. */
public sealed interface CanisterSigVerification {
    public object Valid : CanisterSigVerification

    /** [reason] is for logs and tests. It is never shown to the person signing in. */
    public data class Invalid(public val reason: String) : CanisterSigVerification
}

/**
 * Verifies IC canister signatures.
 *
 * A canister signature is not a signature by a key anybody holds. It is a claim that the
 * signing canister published a hash tree containing `sig/<H(seed)>/<H(message)>`, certified by
 * its subnet, whose authority in turn traces back to the network's root key. So checking one
 * means checking a certificate chain, not a curve equation.
 *
 * See "Canister signatures" in the IC interface specification.
 */
public class CanisterSignatureValidator(
    bls: BlsSignatureVerifier,
    rootPublicKeyRaw: ByteArray = IcBlsPublicKey.MAINNET_ROOT_KEY_RAW,
) {
    private val certificates = CertificateVerifier(bls, rootPublicKeyRaw)

    public fun verify(
        message: ByteArray,
        signatureCbor: ByteArray,
        publicKeyDer: ByteArray,
    ): CanisterSigVerification = try {
        checkSignature(message, signatureCbor, publicKeyDer)
    } catch (e: CborException) {
        CanisterSigVerification.Invalid("malformed: ${e.message}")
    } catch (e: KeyFormatException) {
        CanisterSigVerification.Invalid("malformed public key: ${e.message}")
    }

    private fun checkSignature(
        message: ByteArray,
        signatureCbor: ByteArray,
        publicKeyDer: ByteArray,
    ): CanisterSigVerification {
        val key = CanisterSigPublicKey.fromDer(publicKeyDer)
        val signature = CanisterSignature.fromCbor(signatureCbor)

        // 1. The network vouches for the certificate. Nothing is read out of it before this.
        val certified = when (val result = certificates.verify(signature.certificate, key.canisterId)) {
            is CertificateVerification.Valid -> result.tree
            is CertificateVerification.Invalid -> return CanisterSigVerification.Invalid(result.reason)
        }

        // 2. The subnet says the canister published exactly this witness.
        val certifiedData = certified.lookupPath(listOf(CANISTER, key.canisterId, CERTIFIED_DATA))
        if (certifiedData !is Lookup.Found) {
            return invalid("no certified_data for the signing canister (${describe(certifiedData)})")
        }
        if (!certifiedData.value.contentEquals(signature.tree.reconstruct())) {
            return invalid("certified_data does not cover the signature witness")
        }

        // 3. The witness is read by path, and absence is only meaningful in a tree whose
        //    labels are ordered. Check the shape before believing anything it says.
        if (!signature.tree.isWellFormed()) {
            return invalid("the signature witness is not well formed")
        }

        // 4. The canister says "I signed this": an empty leaf at sig/<H(seed)>/<H(message)>.
        val sigLeaf = signature.tree.lookupPath(listOf(SIG, sha256(key.seed), sha256(message)))
        if (sigLeaf !is Lookup.Found) {
            return invalid("no sig entry for this message (${describe(sigLeaf)})")
        }
        if (sigLeaf.value.isNotEmpty()) {
            return invalid("the sig entry is not an empty leaf")
        }

        return CanisterSigVerification.Valid
    }

    private fun invalid(reason: String): CanisterSigVerification = CanisterSigVerification.Invalid(reason)

    private fun describe(lookup: Lookup): String = CertificateVerifier.describe(lookup)

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private companion object {
        val SIG: ByteArray = "sig".toByteArray(Charsets.UTF_8)
        val CANISTER: ByteArray = "canister".toByteArray(Charsets.UTF_8)
        val CERTIFIED_DATA: ByteArray = "certified_data".toByteArray(Charsets.UTF_8)
    }
}
