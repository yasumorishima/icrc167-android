package io.github.yasumorishima.icrc167

/**
 * Tries each verifier in turn and uses the first one that recognises the key's scheme.
 *
 * A delegation chain mixes schemes: Internet Identity signs the root hop with a canister
 * signature and the rest with keys WebCrypto produced, so no single verifier can check a whole
 * chain. [SignatureCheck.UNSUPPORTED_KEY] is the only answer that moves on to the next
 * verifier — it means "not my scheme". A verifier that recognised the key and said
 * [SignatureCheck.INVALID] ends the search, because letting a later verifier answer for the
 * same key would turn a rejection into an accept as soon as two verifiers disagree.
 */
public class CompositeSignatureVerifier(
    private val verifiers: List<SignatureVerifier>,
) : SignatureVerifier {

    public constructor(vararg verifiers: SignatureVerifier) : this(verifiers.toList())

    override fun verify(
        derPublicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): SignatureCheck {
        for (verifier in verifiers) {
            val check = verifier.verify(derPublicKey, message, signature)
            if (check != SignatureCheck.UNSUPPORTED_KEY) return check
        }
        return SignatureCheck.UNSUPPORTED_KEY
    }
}
