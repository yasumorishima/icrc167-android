package io.github.yasumorishima.icrc167

import java.math.BigInteger

/** The outcome of checking one signature. */
public enum class SignatureCheck {
    VALID,
    INVALID,

    /**
     * The key names a scheme this verifier cannot check at all — an IC canister signature,
     * say, which needs a state-tree certificate and BLS.
     *
     * Distinct from [INVALID] on purpose. A real Internet Identity chain is signed at its
     * root by a canister signature, so a verifier that only knows Ed25519 and P-256 reports
     * this for every genuine login. Calling that "bad signature" invites somebody to decide
     * the check is broken and remove it.
     */
    UNSUPPORTED_KEY,
}

/**
 * Verifies one signature. Implementations dispatch on the SPKI algorithm identifier of
 * [derPublicKey]: Ed25519, ECDSA P-256 (IEEE P1363 `r||s`, as WebCrypto produces), or an
 * IC canister signature.
 *
 * Kept as an interface so the core stays free of a crypto provider and can be tested with
 * synthetic chains.
 */
public fun interface SignatureVerifier {
    public fun verify(
        derPublicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): SignatureCheck
}

/** Why a chain was rejected. Never surfaced to the user as-is; it is for logs and tests. */
public sealed interface ChainRejection {
    public data class Empty(val detail: String = "chain has no delegations") : ChainRejection
    public data class TooLong(val length: Int, val max: Int) : ChainRejection
    public data class Expired(val index: Int, val expiration: BigInteger, val now: BigInteger) : ChainRejection
    public data class BadSignature(val index: Int) : ChainRejection
    public data class UnsupportedKey(val index: Int) : ChainRejection
    public data class SessionKeyMismatch(val detail: String = "chain does not end at our session key") : ChainRejection
    public data class TargetNotPermitted(val target: Principal) : ChainRejection
}

public sealed interface ChainVerification {
    public data class Valid(val principal: Principal) : ChainVerification
    public data class Invalid(val reason: ChainRejection) : ChainVerification
}

/**
 * Checks a delegation chain end to end.
 *
 * This is defence in depth, not the authority: the replica re-checks everything when the
 * chain is actually used. The point of verifying locally is to refuse a chain that would
 * bind us to a key we do not hold, before it is ever stored.
 */
public class DelegationChainVerifier(
    private val signatureVerifier: SignatureVerifier,
    private val maxChainLength: Int = DEFAULT_MAX_CHAIN_LENGTH,
) {

    public fun verify(
        chain: DelegationChain,
        sessionPublicKeyDer: ByteArray,
        nowNanos: BigInteger,
        callTarget: Principal? = null,
    ): ChainVerification {
        if (chain.delegations.isEmpty()) {
            return ChainVerification.Invalid(ChainRejection.Empty())
        }
        if (chain.delegations.size > maxChainLength) {
            return ChainVerification.Invalid(
                ChainRejection.TooLong(chain.delegations.size, maxChainLength),
            )
        }

        // Walk from the root outwards: hop i is signed by the key hop i-1 delegated to.
        var signingKey = chain.publicKey
        chain.delegations.forEachIndexed { index, signed ->
            if (signed.delegation.expiration <= nowNanos) {
                return ChainVerification.Invalid(
                    ChainRejection.Expired(index, signed.delegation.expiration, nowNanos),
                )
            }
            val check = signatureVerifier.verify(
                derPublicKey = signingKey,
                message = signed.delegation.signableBytes(),
                signature = signed.signature,
            )
            when (check) {
                SignatureCheck.VALID -> Unit
                SignatureCheck.INVALID ->
                    return ChainVerification.Invalid(ChainRejection.BadSignature(index))
                SignatureCheck.UNSUPPORTED_KEY ->
                    return ChainVerification.Invalid(ChainRejection.UnsupportedKey(index))
            }
            signingKey = signed.delegation.pubkey
        }

        // The chain is only useful to us if it terminates at the key we hold.
        if (!signingKey.contentEquals(sessionPublicKeyDer)) {
            return ChainVerification.Invalid(ChainRejection.SessionKeyMismatch())
        }

        if (callTarget != null && !permits(chain, callTarget)) {
            return ChainVerification.Invalid(ChainRejection.TargetNotPermitted(callTarget))
        }

        return ChainVerification.Valid(chain.principal())
    }

    /**
     * A scoped delegation narrows what the chain may call. Scopes compose by intersection:
     * every hop that declares `targets` must allow the canister.
     */
    private fun permits(chain: DelegationChain, target: Principal): Boolean =
        chain.delegations.all { signed ->
            val targets = signed.delegation.targets ?: return@all true
            targets.contains(target)
        }

    public companion object {
        public const val DEFAULT_MAX_CHAIN_LENGTH: Int = 20
    }
}
