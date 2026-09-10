package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.DelegationChain
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.SignedDelegation

/**
 * Signs the bytes that authenticate a request.
 *
 * The key never has to leave wherever it lives: on Android the session key is held by
 * `SessionKey`, so an app passes `sessionKey::sign` and nothing else moves.
 */
public fun interface Signer {
    public fun sign(message: ByteArray): ByteArray
}

/** What an envelope carries beyond its content when the request is signed. */
public class RequestAuth(
    senderPublicKey: ByteArray,
    signature: ByteArray,
    public val delegations: List<SignedDelegation>,
) {
    private val publicKeyBytes = senderPublicKey.copyOf()
    private val signatureBytes = signature.copyOf()

    /** DER-encoded public key the principal is derived from. */
    public val senderPublicKey: ByteArray get() = publicKeyBytes.copyOf()
    public val signature: ByteArray get() = signatureBytes.copyOf()
}

/** How a request is attributed to a caller. */
public sealed interface Identity {
    public val sender: Principal

    /** The authentication for [requestId], or null when the request goes out unsigned. */
    public fun authenticate(requestId: ByteArray): RequestAuth?
}

/**
 * The caller nobody vouched for: `2vxsx-fae`.
 *
 * Worth keeping usable. A canister that answers an anonymous call the same way it answers a
 * signed one is not authenticating anything, and the cheapest way to find that out is to ask
 * it anonymously.
 */
public object AnonymousIdentity : Identity {
    override val sender: Principal = Principal.ofBytes(byteArrayOf(0x04))
    override fun authenticate(requestId: ByteArray): RequestAuth? = null
}

/** A key that speaks for itself: the principal is the self-authenticating id of [publicKeyDer]. */
public class KeyIdentity(
    publicKeyDer: ByteArray,
    private val signer: Signer,
) : Identity {
    private val publicKeyBytes = publicKeyDer.copyOf()
    override val sender: Principal = Principal.selfAuthenticating(publicKeyBytes)

    override fun authenticate(requestId: ByteArray): RequestAuth = RequestAuth(
        senderPublicKey = publicKeyBytes,
        signature = signer.sign(requestDomainSeparator() + requestId),
        delegations = emptyList(),
    )
}

/**
 * A chain from the identity the canister sees down to the key this app holds.
 *
 * [signer] must hold the key the *last* delegation in the chain points at -- the session key.
 * The principal comes from the root of the chain, which is the whole point: the app signs
 * with a key it generated, and the canister still sees the user.
 */
public class DelegatedIdentity(
    public val chain: DelegationChain,
    private val signer: Signer,
) : Identity {
    override val sender: Principal = chain.principal()

    override fun authenticate(requestId: ByteArray): RequestAuth = RequestAuth(
        senderPublicKey = chain.publicKey,
        signature = signer.sign(requestDomainSeparator() + requestId),
        delegations = chain.delegations,
    )
}

/**
 * `\x0Aic-request`, the prefix a request signature covers. The leading byte is the length of
 * the string that follows, per the interface specification's domain separator convention.
 */
public fun requestDomainSeparator(): ByteArray =
    byteArrayOf(0x0A) + "ic-request".toByteArray(Charsets.UTF_8)
