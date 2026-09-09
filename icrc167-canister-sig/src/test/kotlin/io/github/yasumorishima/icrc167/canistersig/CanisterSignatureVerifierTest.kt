package io.github.yasumorishima.icrc167.canistersig

import io.github.yasumorishima.icrc167.ChainVerification
import io.github.yasumorishima.icrc167.CompositeSignatureVerifier
import io.github.yasumorishima.icrc167.Delegation
import io.github.yasumorishima.icrc167.DelegationChain
import io.github.yasumorishima.icrc167.DelegationChainVerifier
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.SignatureCheck
import io.github.yasumorishima.icrc167.SignedDelegation
import io.github.yasumorishima.icrc167.certificate.BlsSignatureVerifier
import io.github.yasumorishima.icrc167.certificate.CanisterSigVerification
import io.github.yasumorishima.icrc167.certificate.CanisterSignatureValidator
import io.github.yasumorishima.icrc167.certificate.HashTree
import io.github.yasumorishima.icrc167.certificate.IcBlsPublicKey
import io.github.yasumorishima.icrc167.certificate.reconstruct
import io.github.yasumorishima.icrc167.crypto.StandardSignatureVerifier
import java.math.BigInteger
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The canister-signature wrapper: the parts on top of certificate verification, which is
 * covered against a live certificate in [CertificateVerifierTest].
 *
 * Two historical canister signatures are checked here with the real arithmetic. Both are
 * refused, and *where* they are refused is the assertion: they were issued before the state
 * tree carried `/subnet/<id>/type`, so they get all the way through CBOR, the canister's own
 * witness, the delegation's BLS signature under the real root key and the canister ranges, and
 * stop at the one thing a certificate issued today does carry. There is no canister signature
 * in the public record that postdates that rule, so the positive path is exercised structurally
 * with the pairing arithmetic stubbed out — the arithmetic itself has RFC 9380 vectors in
 * [MiraclBlsTest] and a live certificate in [CertificateVerifierTest].
 */
class CanisterSignatureVerifierTest {

    // A real Internet Identity login on mainnet, from dfinity/internet-identity's own test.
    private val iiPublicKey = Vectors.hex("ii-public-key")
    private val iiSignature = Vectors.hex("ii-signature")
    private val iiChallenge = Vectors.hex("ii-challenge")
    private val iiExpiration = BigInteger("1708469015156620577")

    // DFINITY's vector for the sharded canister-ranges shape, under its own test root key.
    private val shardedPublicKey = Vectors.hex("sharded-public-key")
    private val shardedSignature = Vectors.hex("sharded-signature")
    private val shardedMessage = Vectors.hex("sharded-message")
    private val shardedRootKey = Vectors.hex("sharded-root-key")

    private val mainnet = CanisterSignatureVerifier()

    @Test
    fun `a mainnet chain from 2024 passes every check except the subnet type`() {
        val result = CanisterSignatureValidator(MiraclBls).verify(iiMessage(), iiSignature, iiPublicKey)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        // Reaching this message means the delegation's signature verified under the real
        // mainnet root key and the signing canister was inside the delegated ranges.
        assertTrue("subnet's type" in invalid.reason, invalid.reason)
        assertTrue("proved absent" in invalid.reason, invalid.reason)
    }

    /**
     * The same, one shape of certificate later. Its witness does prune part of the subnet
     * subtree, but the pruning sits to the left of `public_key`, and `type` sorts after it, so
     * the tree still proves the label is not there rather than leaving it unknown.
     */
    @Test
    fun `the sharded vector likewise stops at the subnet type`() {
        val validator = CanisterSignatureValidator(MiraclBls, shardedRootKey)
        val result = validator.verify(shardedMessage, shardedSignature, shardedPublicKey)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        assertTrue("subnet's type" in invalid.reason, invalid.reason)
        assertTrue("proved absent" in invalid.reason, invalid.reason)
    }

    /**
     * The composite is not decoration: the verifier that handles every other scheme has
     * nothing to say about this key, so without the canister-signature verifier a login is
     * rejected as "unsupported" rather than checked.
     */
    @Test
    fun `the standard verifier cannot check a canister signature key at all`() {
        assertEquals(
            SignatureCheck.UNSUPPORTED_KEY,
            StandardSignatureVerifier().verify(iiPublicKey, iiMessage(), iiSignature),
        )
    }

    @Test
    fun `rejects a signature whose certificate is not covered by the root key given`() {
        assertEquals(
            SignatureCheck.INVALID,
            mainnet.verify(shardedPublicKey, shardedMessage, shardedSignature),
        )
    }

    @Test
    fun `rejects a canister signature whose bytes are not CBOR`() {
        assertEquals(
            SignatureCheck.INVALID,
            mainnet.verify(iiPublicKey, iiMessage(), byteArrayOf(1, 2, 3)),
        )
    }

    // Everything below builds its own certificate, so the pairing arithmetic is stubbed and
    // the structure is what is under test.

    private val canisterId = Vectors.parse("00000000006000270101")
    private val seed = "a seed the canister chose".toByteArray()
    private val message = "the delegation being signed".toByteArray()
    private val key = CertificateFixtures.canisterSigKeyDer(canisterId, seed)
    private val stubbed = CanisterSignatureValidator(BlsSignatureVerifier { _, _, _ -> true })

    @Test
    fun `accepts a signature the canister really published`() {
        assertEquals(CanisterSigVerification.Valid, stubbed.verify(message, signature(), key))
    }

    /**
     * The step that ties the two trees together. Without it a certificate for the right
     * canister could be paired with any witness at all.
     */
    @Test
    fun `rejects a witness the canister did not certify`() {
        val other = sigTree(sha256(seed), sha256("something else".toByteArray()))
        val bytes = CertificateFixtures.canisterSignature(
            certificateFor(reconstruct = sigTree(sha256(seed), sha256(message)).reconstruct()),
            other,
        )
        val result = stubbed.verify("something else".toByteArray(), bytes, key)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        assertTrue("does not cover" in invalid.reason, invalid.reason)
    }

    @Test
    fun `rejects a message the canister did not sign`() {
        val result = stubbed.verify("a different message".toByteArray(), signature(), key)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        assertTrue("no sig entry" in invalid.reason, invalid.reason)
    }

    /** A seed is per-user, so the same canister's signature for somebody else must not pass. */
    @Test
    fun `rejects a signature made under a different seed`() {
        val otherKey = CertificateFixtures.canisterSigKeyDer(canisterId, "another seed".toByteArray())
        val result = stubbed.verify(message, signature(), otherKey)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        assertTrue("no sig entry" in invalid.reason, invalid.reason)
    }

    @Test
    fun `rejects a sig entry that carries a value`() {
        val tree = CertificateFixtures.forest(
            "sig" to CertificateFixtures.labelled(
                sha256(seed) to CertificateFixtures.labelled(
                    sha256(message) to HashTree.Leaf(byteArrayOf(1)),
                ),
            ),
        )
        val bytes = CertificateFixtures.canisterSignature(
            certificateFor(tree.reconstruct()),
            tree,
        )
        val result = stubbed.verify(message, bytes, key)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        assertTrue("empty leaf" in invalid.reason, invalid.reason)
    }

    /**
     * Labels out of order break the only thing that makes absence provable, so a witness that
     * is not well formed is refused before it is read.
     */
    @Test
    fun `rejects a witness whose labels are out of order`() {
        val tree = HashTree.Fork(
            HashTree.Labeled("sig".toByteArray(), HashTree.Leaf(ByteArray(0))),
            HashTree.Labeled("canister".toByteArray(), HashTree.Leaf(ByteArray(0))),
        )
        val bytes = CertificateFixtures.canisterSignature(certificateFor(tree.reconstruct()), tree)
        val result = stubbed.verify(message, bytes, key)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        assertTrue("well formed" in invalid.reason, invalid.reason)
    }

    @Test
    fun `rejects a certificate that certifies a different canister`() {
        val bytes = CertificateFixtures.canisterSignature(
            certificateFor(
                reconstruct = sigTree(sha256(seed), sha256(message)).reconstruct(),
                canister = Vectors.parse("00000000021000060101"),
            ),
            sigTree(sha256(seed), sha256(message)),
        )
        val result = stubbed.verify(message, bytes, key)
        val invalid = assertIs<CanisterSigVerification.Invalid>(result)
        assertTrue("certified_data" in invalid.reason, invalid.reason)
    }

    // Through a subnet delegation, which is the shape every real login has. Without these
    // the certificate verifier contributes nothing to any canister-signature test: a
    // root-signed certificate never reaches the delegation, the ranges or the subnet type.

    @Test
    fun `accepts a signature whose certificate comes through a subnet delegation`() {
        val tree = sigTree(sha256(seed), sha256(message))
        val bytes = CertificateFixtures.canisterSignature(
            delegatedCertificateFor(tree.reconstruct()),
            tree,
        )
        assertEquals(CanisterSigVerification.Valid, stubbed.verify(message, bytes, key))
    }

    @Test
    fun `rejects it when the delegation does not cover the signing canister`() {
        val tree = sigTree(sha256(seed), sha256(message))
        val elsewhere = Vectors.parse("00000000021000060101")
        val bytes = CertificateFixtures.canisterSignature(
            delegatedCertificateFor(tree.reconstruct(), covering = elsewhere to elsewhere),
            tree,
        )
        val invalid = assertIs<CanisterSigVerification.Invalid>(stubbed.verify(message, bytes, key))
        assertTrue("outside the delegated ranges" in invalid.reason, invalid.reason)
    }

    @Test
    fun `rejects it when the delegation does not state the subnet type`() {
        val tree = sigTree(sha256(seed), sha256(message))
        val bytes = CertificateFixtures.canisterSignature(
            delegatedCertificateFor(tree.reconstruct(), type = null),
            tree,
        )
        val invalid = assertIs<CanisterSigVerification.Invalid>(stubbed.verify(message, bytes, key))
        assertTrue("subnet's type" in invalid.reason, invalid.reason)
    }

    @Test
    fun `rejects it when the delegating subnet is a cloud engine`() {
        val tree = sigTree(sha256(seed), sha256(message))
        val bytes = CertificateFixtures.canisterSignature(
            delegatedCertificateFor(tree.reconstruct(), type = "cloud_engine"),
            tree,
        )
        val invalid = assertIs<CanisterSigVerification.Invalid>(stubbed.verify(message, bytes, key))
        assertTrue("cloud_engine" in invalid.reason, invalid.reason)
    }

    /**
     * Records a decision rather than discovering one: when the sharded subtree is there but
     * readable to no shard, the answer is no, and the older single-blob form is *not* consulted
     * as a second chance.
     *
     * That is what `ic-signature-verification` does — its `lookup_subtree` also hands back a
     * pruned node as `Found`, and it only falls back when the path is absent or unknown — and
     * it is fail-closed either way, so the difference is availability, not safety. A reviewer
     * suggested making the pruned case fall through; it was not taken, because the gain is a
     * certificate nobody has seen (one carrying the legacy blob *and* a pruned shard) and the
     * cost is diverging from the reference on the meaning of a pruned lookup.
     */
    @Test
    fun `a pruned shard is an answer of no, not a reason to read the older blob`() {
        val tree = sigTree(sha256(seed), sha256(message))
        val bytes = CertificateFixtures.canisterSignature(
            delegatedCertificateFor(tree.reconstruct(), prunedShard = true, legacyBlob = true),
            tree,
        )
        val invalid = assertIs<CanisterSigVerification.Invalid>(stubbed.verify(message, bytes, key))
        assertTrue("outside the delegated ranges" in invalid.reason, invalid.reason)
    }

    /** The whole way through: a chain whose root hop is a canister signature. */
    @Test
    fun `a delegation chain rooted in a canister signature yields the canister's principal`() {
        val session = ByteArray(32) { it.toByte() }
        val expiration = BigInteger.valueOf(2_000_000_000_000_000_000L)
        val delegation = Delegation(session, expiration)
        val bytes = CertificateFixtures.canisterSignature(
            certificateFor(sigTree(sha256(seed), sha256(delegation.signableBytes())).reconstruct()),
            sigTree(sha256(seed), sha256(delegation.signableBytes())),
        )

        val verifier = DelegationChainVerifier(
            CompositeSignatureVerifier(
                StandardSignatureVerifier(),
                CanisterSignatureVerifier(bls = BlsSignatureVerifier { _, _, _ -> true }),
            ),
        )
        val result = verifier.verify(
            chain = DelegationChain(key, listOf(SignedDelegation(delegation, bytes))),
            sessionPublicKeyDer = session,
            nowNanos = expiration - BigInteger.ONE,
        )

        val valid = assertIs<ChainVerification.Valid>(result)
        assertEquals(Principal.selfAuthenticating(key), valid.principal)
    }

    /** What the chain's one hop actually signs: the delegation, not the challenge. */
    private fun iiMessage(): ByteArray = Delegation(iiChallenge, iiExpiration).signableBytes()

    private fun signature(): ByteArray {
        val tree = sigTree(sha256(seed), sha256(message))
        return CertificateFixtures.canisterSignature(certificateFor(tree.reconstruct()), tree)
    }

    private fun sigTree(seedHash: ByteArray, messageHash: ByteArray): HashTree =
        CertificateFixtures.forest(
            "sig" to CertificateFixtures.labelled(
                seedHash to CertificateFixtures.labelled(messageHash to HashTree.Leaf(ByteArray(0))),
            ),
        )

    /**
     * A root-signed certificate publishing [reconstruct] as [canister]'s certified data.
     *
     * Nothing beyond what is read: a `/time` leaf would sit here looking as though freshness
     * were part of the check, and it is not — `verify_cert` has no validity window.
     */
    private fun certificateFor(reconstruct: ByteArray, canister: ByteArray = canisterId): ByteArray =
        CertificateFixtures.certificate(
            CertificateFixtures.forest(
                "canister" to CertificateFixtures.labelled(
                    canister to CertificateFixtures.forest("certified_data" to HashTree.Leaf(reconstruct)),
                ),
            ),
            signature = ByteArray(48),
        )

    /**
     * The shape a real login has: the canister's subnet is not the root subnet, so the
     * certificate carries a delegation the root subnet signed.
     *
     * @param covering the range the delegation grants, which is what decides whether this
     *   subnet was allowed to certify for the canister at all
     * @param type the subnet type, or null to leave the label out entirely
     */
    private fun delegatedCertificateFor(
        reconstruct: ByteArray,
        covering: Pair<ByteArray, ByteArray> = canisterId to canisterId,
        type: String? = "system",
        prunedShard: Boolean = false,
        legacyBlob: Boolean = false,
    ): ByteArray {
        val subnet = mutableListOf<Pair<String, HashTree>>(
            // Any well-formed IC BLS key will do: the pairing is stubbed in these tests.
            "public_key" to HashTree.Leaf(IcBlsPublicKey.MAINNET_ROOT_KEY_DER),
        )
        if (type != null) subnet.add("type" to HashTree.Leaf(type.toByteArray()))
        if (legacyBlob) subnet.add("canister_ranges" to HashTree.Leaf(CertificateFixtures.ranges(covering)))

        val shard: HashTree = HashTree.Leaf(CertificateFixtures.ranges(covering))
        val delegationCertificate = CertificateFixtures.certificate(
            CertificateFixtures.forest(
                "canister_ranges" to CertificateFixtures.labelled(
                    subnetId to CertificateFixtures.labelled(
                        covering.first to if (prunedShard) HashTree.Pruned(shard.reconstruct()) else shard,
                    ),
                ),
                "subnet" to CertificateFixtures.labelled(
                    subnetId to CertificateFixtures.forest(*subnet.toTypedArray()),
                ),
            ),
            signature = ByteArray(48),
        )
        return CertificateFixtures.certificate(
            CertificateFixtures.forest(
                "canister" to CertificateFixtures.labelled(
                    canisterId to CertificateFixtures.forest("certified_data" to HashTree.Leaf(reconstruct)),
                ),
            ),
            signature = ByteArray(48),
            delegation = CertificateFixtures.delegation(subnetId, delegationCertificate),
        )
    }

    private val subnetId = Vectors.parse("2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd02")

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
