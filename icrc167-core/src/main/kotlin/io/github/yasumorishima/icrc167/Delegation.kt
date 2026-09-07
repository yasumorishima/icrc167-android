package io.github.yasumorishima.icrc167

import java.math.BigInteger

/**
 * One hop of a delegation chain: "the holder of [pubkey] may act for me until [expiration]".
 */
public class Delegation(
    pubkey: ByteArray,
    public val expiration: BigInteger,
    public val targets: List<Principal>? = null,
) {
    private val pubkeyBytes = pubkey.copyOf()

    /** DER-encoded SubjectPublicKeyInfo of the key being delegated **to**. */
    public val pubkey: ByteArray get() = pubkeyBytes.copyOf()

    /**
     * The exact bytes a signature over this delegation covers:
     * `\x1Aic-request-auth-delegation || reprHash(delegation)`.
     *
     * The 0x1A prefix is the length of the separator string (26), per the IC interface
     * specification's domain separator convention.
     */
    public fun signableBytes(): ByteArray {
        val fields = LinkedHashMap<String, ReprHash.Value>()
        fields["pubkey"] = ReprHash.Value.Blob(pubkeyBytes)
        fields["expiration"] = ReprHash.Value.Nat(expiration)
        // `targets` must be absent from the hashed map when the delegation is unscoped —
        // an empty array is a different delegation and hashes differently.
        if (targets != null) {
            fields["targets"] = ReprHash.Value.Arr(targets.map { ReprHash.Value.Blob(it.bytes) })
        }
        return DOMAIN_SEPARATOR + ReprHash.ofMap(fields)
    }

    public companion object {
        internal val DOMAIN_SEPARATOR: ByteArray =
            byteArrayOf(0x1A) + "ic-request-auth-delegation".toByteArray(Charsets.UTF_8)
    }
}

/** A [Delegation] together with the signature produced by the *previous* key in the chain. */
public class SignedDelegation(
    public val delegation: Delegation,
    signature: ByteArray,
) {
    private val signatureBytes = signature.copyOf()
    public val signature: ByteArray get() = signatureBytes.copyOf()
}

/**
 * A chain rooted at [publicKey] (the identity the canister will see) and ending at the
 * session key held by this app.
 *
 * Internet Identity inserts an intermediate key of its own, so a chain returned by II has
 * at least two hops. Nothing here assumes a particular length.
 */
public class DelegationChain(
    publicKey: ByteArray,
    public val delegations: List<SignedDelegation>,
) {
    private val publicKeyBytes = publicKey.copyOf()

    /** DER-encoded public key at the root of the chain. */
    public val publicKey: ByteArray get() = publicKeyBytes.copyOf()

    /** The principal a canister attributes calls to when this chain is used. */
    public fun principal(): Principal = Principal.selfAuthenticating(publicKeyBytes)
}
