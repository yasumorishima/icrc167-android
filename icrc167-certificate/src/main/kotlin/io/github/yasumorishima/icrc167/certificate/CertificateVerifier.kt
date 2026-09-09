package io.github.yasumorishima.icrc167.certificate

/**
 * Checks one BLS12-381 signature against a raw (unwrapped) 96-byte public key.
 *
 * Kept as an interface so this module stays dependency-free: everything here is parsing,
 * SHA-256 and tree arithmetic, and the pairing arithmetic lives in a module a caller can
 * choose not to ship.
 *
 * The ciphersuite is `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` — signatures in G1,
 * public keys in G2 — as the IC interface specification requires.
 */
public fun interface BlsSignatureVerifier {
    public fun verify(publicKeyRaw: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}

/** The outcome of checking a certificate. */
public sealed interface CertificateVerification {
    /**
     * The subnet's signature covers [tree], and the subnet was entitled to certify for the
     * canister that was asked about. Only now is anything in the tree worth reading.
     */
    public class Valid(public val tree: HashTree) : CertificateVerification

    /** [reason] is for logs and tests. It is never shown to the person signing in. */
    public data class Invalid(public val reason: String) : CertificateVerification
}

/**
 * Verifies an IC certificate against the network's root key, following `verify_cert` in the
 * interface specification.
 *
 * A certificate is a witness of part of the IC state tree plus a subnet's BLS signature over
 * that tree's root hash. The subnet is usually not the root subnet, so the certificate carries
 * a *delegation*: a second certificate, signed by the root key, saying which key may certify
 * for which canisters. This class walks that and hands back the tree only once the signature
 * over it has been checked — reading first and verifying afterwards would mean acting on
 * whatever an attacker chose to put in the bytes.
 *
 * @param rootPublicKeyRaw the root of trust. Defaults to the IC mainnet root key; pass a
 *   different one only to verify against a test network, and never one taken from the same
 *   response as the certificate being checked.
 * @throws IllegalArgumentException if [rootPublicKeyRaw] is not 96 bytes. A root key is
 *   configuration, not input, so a wrong one is a mistake in the calling code rather than
 *   something to report as a failed verification.
 */
public class CertificateVerifier(
    private val bls: BlsSignatureVerifier,
    rootPublicKeyRaw: ByteArray = IcBlsPublicKey.MAINNET_ROOT_KEY_RAW,
) {
    private val rootKey: ByteArray = rootPublicKeyRaw.copyOf()

    init {
        require(rootKey.size == IcBlsPublicKey.RAW_LENGTH) {
            "a root key is ${IcBlsPublicKey.RAW_LENGTH} raw bytes, got ${rootKey.size}"
        }
    }

    /**
     * @param signingCanisterId the canister whose data is about to be read out of the tree. A
     *   delegated subnet may only certify for canisters in the range the root subnet gave it,
     *   so this is part of the check, not of the reading.
     */
    public fun verify(certificateCbor: ByteArray, signingCanisterId: ByteArray): CertificateVerification = try {
        checkCertificate(certificateCbor, signingCanisterId)
    } catch (e: CborException) {
        CertificateVerification.Invalid("malformed certificate: ${e.message}")
    } catch (e: KeyFormatException) {
        CertificateVerification.Invalid("malformed subnet key: ${e.message}")
    }

    private fun checkCertificate(
        certificateCbor: ByteArray,
        signingCanisterId: ByteArray,
    ): CertificateVerification {
        val certificate = Certificate.fromCbor(certificateCbor)

        val signingKey = when (val delegation = certificate.delegation) {
            null -> rootKey
            else -> when (val resolved = subnetKey(delegation, signingCanisterId)) {
                is Resolved.Key -> resolved.raw
                is Resolved.Rejected -> return resolved.result
            }
        }

        if (!verifySignature(certificate, signingKey)) {
            return invalid("the certificate's BLS signature does not verify")
        }
        return CertificateVerification.Valid(certificate.tree)
    }

    private sealed interface Resolved {
        class Key(val raw: ByteArray) : Resolved
        class Rejected(val result: CertificateVerification) : Resolved
    }

    /**
     * Follows a subnet delegation and returns the key it delegates to.
     *
     * The delegation is itself a certificate signed by the root key, so this is where the
     * chain bottoms out. Its own certificate must not delegate again — otherwise the range
     * check below could be satisfied by a subnet the root never authorised.
     */
    private fun subnetKey(delegation: CertificateDelegation, canisterId: ByteArray): Resolved {
        val certificate = Certificate.fromCbor(delegation.certificate)
        if (certificate.delegation != null) {
            return Resolved.Rejected(invalid("a delegation's certificate delegates again"))
        }
        if (!verifySignature(certificate, rootKey)) {
            return Resolved.Rejected(invalid("the delegation's BLS signature does not verify"))
        }

        val subnetId = delegation.subnetId
        if (!canisterIsInRange(certificate.tree, subnetId, canisterId)) {
            return Resolved.Rejected(invalid("the signing canister is outside the delegated ranges"))
        }
        subnetTypeRejection(certificate.tree, subnetId)?.let { return it }

        val keyLookup = certificate.tree.lookupPath(
            listOf(SUBNET, subnetId, PUBLIC_KEY),
        )
        if (keyLookup !is Lookup.Found) {
            return Resolved.Rejected(invalid("the delegation carries no subnet public key (${describe(keyLookup)})"))
        }
        return Resolved.Key(IcBlsPublicKey.extractRaw(keyLookup.value))
    }

    /** The sharded form is the current one; the single-blob form is still what older certificates carry. */
    private fun canisterIsInRange(tree: HashTree, subnetId: ByteArray, canisterId: ByteArray): Boolean {
        val sharded = tree.lookupSubtree(listOf(CANISTER_RANGES, subnetId))
        if (sharded is SubtreeLookup.Found) {
            val shard = CanisterRanges.shardFor(sharded.subtree, canisterId) ?: return false
            return CanisterRanges.contains(CanisterRanges.decode(shard), canisterId)
        }

        val whole = tree.lookupPath(listOf(SUBNET, subnetId, CANISTER_RANGES))
        if (whole !is Lookup.Found) return false
        return CanisterRanges.contains(CanisterRanges.decode(whole.value), canisterId)
    }

    /**
     * The delegated subnet must say what kind of subnet it is, and it must not be a cloud
     * engine — nodes that are not part of consensus and must not vouch for identities.
     *
     * Absent counts as a refusal, which matters more than it looks: pruning a node is the one
     * edit an attacker can always make to a witness without disturbing the root hash the
     * subnet signed. "Refuse only when it says cloud_engine" would therefore enforce nothing
     * at all, since a cloud engine can simply prune the label away. The IC's own
     * `verify_certified_data_with_cache_for_canister_sig` rejects both absent and
     * `cloud_engine` for exactly this reason.
     *
     * Certificates issued before the type was added to the state tree in 2026 have no such
     * label and are refused here. That is the intended behaviour: they are not certificates
     * the network is issuing any more.
     */
    private fun subnetTypeRejection(tree: HashTree, subnetId: ByteArray): Resolved.Rejected? {
        val type = tree.lookupPath(listOf(SUBNET, subnetId, TYPE))
        if (type !is Lookup.Found) {
            return Resolved.Rejected(
                invalid("the delegation does not state the subnet's type (${describe(type)})"),
            )
        }
        if (type.value.contentEquals(CLOUD_ENGINE)) {
            return Resolved.Rejected(invalid("a cloud_engine subnet may not certify for canisters"))
        }
        return null
    }

    private fun verifySignature(certificate: Certificate, publicKeyRaw: ByteArray): Boolean =
        bls.verify(
            publicKeyRaw,
            STATE_ROOT_DOMAIN + certificate.tree.reconstruct(),
            certificate.signature,
        )

    private fun invalid(reason: String): CertificateVerification = CertificateVerification.Invalid(reason)

    internal companion object {
        val SUBNET: ByteArray = "subnet".toByteArray(Charsets.UTF_8)
        val PUBLIC_KEY: ByteArray = "public_key".toByteArray(Charsets.UTF_8)
        val CANISTER_RANGES: ByteArray = "canister_ranges".toByteArray(Charsets.UTF_8)
        val TYPE: ByteArray = "type".toByteArray(Charsets.UTF_8)
        val CLOUD_ENGINE: ByteArray = "cloud_engine".toByteArray(Charsets.UTF_8)

        /** `domain_sep("ic-state-root")`, the prefix a subnet signs before the root hash. */
        val STATE_ROOT_DOMAIN: ByteArray = domainSeparator("ic-state-root")

        /** Says which of the "not Found" answers came back; they are not interchangeable. */
        fun describe(lookup: Lookup): String = when (lookup) {
            is Lookup.Found -> "found"
            Lookup.Absent -> "proved absent"
            Lookup.Unknown -> "pruned away"
            Lookup.Error -> "the path is not a leaf"
        }
    }
}
