package io.github.yasumorishima.icrc167.canistersig

import io.github.yasumorishima.icrc167.certificate.BlsSignatureVerifier
import io.github.yasumorishima.icrc167.certificate.Certificate
import io.github.yasumorishima.icrc167.certificate.CertificateVerification
import io.github.yasumorishima.icrc167.certificate.CertificateVerifier
import io.github.yasumorishima.icrc167.certificate.HashTree
import io.github.yasumorishima.icrc167.certificate.IcBlsPublicKey
import io.github.yasumorishima.icrc167.certificate.Lookup
import io.github.yasumorishima.icrc167.certificate.isWellFormed
import io.github.yasumorishima.icrc167.certificate.lookupPath
import io.github.yasumorishima.icrc167.certificate.reconstruct
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Certificate verification against a certificate the IC issued, with the real pairing
 * arithmetic and the real mainnet root key.
 *
 * The fixture is a live capture rather than a constructed example on purpose: what a
 * certificate contains has changed — `/subnet/<id>/type` was added to the state tree in 2026,
 * and the canister ranges moved into shards — and a verifier written against older examples
 * agrees with the older examples and refuses the network.
 */
class CertificateVerifierTest {

    private val live = Vectors.hex("live-certificate")

    /** The canister the captured certificate is about, read out of its own tree. */
    private val canisterId = Vectors.hex("live-canister-id")

    private val verifier = CertificateVerifier(MiraclBls)

    @Test
    fun `verifies a certificate the IC issued`() {
        val result = verifier.verify(live, canisterId)
        val valid = assertIs<CertificateVerification.Valid>(result, reasonOf(result))
        val data = valid.tree.lookupPath(
            listOf("canister".toByteArray(), canisterId, "certified_data".toByteArray()),
        )
        assertIs<Lookup.Found>(data)
    }

    /**
     * The delegated subnet does say what it is. This is the measurement the strict reading of
     * the specification rests on, so it is asserted rather than assumed: if a future capture
     * lost the label, the rule would start refusing real logins and this says so first.
     */
    @Test
    fun `the delegation states the subnet type`() {
        val delegation = requireNotNull(Certificate.fromCbor(live).delegation)
        val inner = Certificate.fromCbor(delegation.certificate)
        val type = inner.tree.lookupPath(
            listOf("subnet".toByteArray(), delegation.subnetId, "type".toByteArray()),
        )
        val found = assertIs<Lookup.Found>(type)
        assertContentEquals("system".toByteArray(), found.value)
    }

    /**
     * Everything below rebuilds the certificate to change one thing in it. If the rebuilding
     * were lossy, every one of those tests would "pass" for the wrong reason, so the untouched
     * rebuild has to verify too.
     */
    @Test
    fun `rebuilding the certificate byte for byte changes nothing it proves`() {
        val result = verifier.verify(rebuilt { it }, canisterId)
        assertIs<CertificateVerification.Valid>(result, reasonOf(result))
    }

    /**
     * The attack the strict rule exists to stop. Pruning a subtree replaces it with its own
     * digest, so the root hash — and therefore the subnet's signature — is untouched, and a
     * verifier that only refuses the word `cloud_engine` would be talked out of ever seeing
     * it. Asserting the root hash here is the point: this is not a corrupted certificate.
     */
    @Test
    fun `refuses the certificate when the subnet type is pruned away`() {
        val delegation = requireNotNull(Certificate.fromCbor(live).delegation)
        val original = Certificate.fromCbor(delegation.certificate).tree
        val pruned = CertificateFixtures.pruneAt(
            original,
            listOf("subnet".toByteArray(), delegation.subnetId, "type".toByteArray()),
        )
        assertContentEquals(
            original.reconstruct(),
            pruned.reconstruct(),
            "pruning must not disturb what the subnet signed, or this proves nothing",
        )

        val result = verifier.verify(rebuilt { pruned }, canisterId)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("subnet's type" in invalid.reason, invalid.reason)
    }

    /**
     * The `cloud_engine` branch itself. Changing the label's value does move the root hash, so
     * the real subnet signature cannot cover it; the arithmetic is stubbed out to reach the
     * branch, which is the only thing under test here.
     */
    @Test
    fun `refuses a subnet that says it is a cloud engine`() {
        val delegation = requireNotNull(Certificate.fromCbor(live).delegation)
        val edited = CertificateFixtures.replaceAt(
            Certificate.fromCbor(delegation.certificate).tree,
            listOf("subnet".toByteArray(), delegation.subnetId, "type".toByteArray()),
        ) { HashTree.Leaf("cloud_engine".toByteArray()) }

        val result = CertificateVerifier(alwaysValid).verify(rebuilt { edited }, canisterId)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("cloud_engine" in invalid.reason, invalid.reason)
    }

    @Test
    fun `refuses a certificate whose own signature has been altered`() {
        val certificate = Certificate.fromCbor(live)
        val delegation = requireNotNull(certificate.delegation)
        val tampered = certificate.signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val bytes = CertificateFixtures.certificate(
            certificate.tree,
            tampered,
            CertificateFixtures.delegation(delegation.subnetId, delegation.certificate),
        )

        val result = verifier.verify(bytes, canisterId)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("certificate's BLS signature" in invalid.reason, invalid.reason)
    }

    /**
     * A signature that is a real, in-subgroup point and simply covers something else. The
     * altered-byte cases above stop at the decoder or the subgroup check, so this is the one
     * that reaches the pairing.
     */
    @Test
    fun `refuses a certificate signed for a different tree`() {
        val certificate = Certificate.fromCbor(live)
        val delegation = requireNotNull(certificate.delegation)
        val borrowed = Certificate.fromCbor(delegation.certificate).signature
        val bytes = CertificateFixtures.certificate(
            certificate.tree,
            borrowed,
            CertificateFixtures.delegation(delegation.subnetId, delegation.certificate),
        )

        val result = verifier.verify(bytes, canisterId)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("certificate's BLS signature" in invalid.reason, invalid.reason)
    }

    /**
     * Recorded rather than enforced. Both trees are well formed, so nothing here depends on
     * refusing one that is not — but if the IC ever certifies a tree with out-of-order or
     * repeated labels, `lookupPath` could conclude absence it has not proved, and this says so
     * before that becomes a security question.
     */
    @Test
    fun `the captured certificate and its delegation are both well formed`() {
        val certificate = Certificate.fromCbor(live)
        assertTrue(certificate.tree.isWellFormed())
        assertTrue(Certificate.fromCbor(requireNotNull(certificate.delegation).certificate).tree.isWellFormed())
    }

    @Test
    fun `refuses a delegation whose signature is not the root subnet's`() {
        val delegation = requireNotNull(Certificate.fromCbor(live).delegation)
        val inner = Certificate.fromCbor(delegation.certificate)
        val tampered = inner.signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val innerBytes = CertificateFixtures.certificate(inner.tree, tampered)

        val outer = Certificate.fromCbor(live)
        val bytes = CertificateFixtures.certificate(
            outer.tree,
            outer.signature,
            CertificateFixtures.delegation(delegation.subnetId, innerBytes),
        )

        val result = verifier.verify(bytes, canisterId)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("delegation's BLS signature" in invalid.reason, invalid.reason)
    }

    /**
     * A delegated subnet may only certify for the canisters the root subnet gave it. Nothing
     * about the signature changes here — only which canister is being asked about.
     */
    @Test
    fun `refuses a canister outside the delegated ranges`() {
        val elsewhere = Vectors.parse("00000000006000270101")
        val result = verifier.verify(live, elsewhere)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("outside the delegated ranges" in invalid.reason, invalid.reason)
    }

    @Test
    fun `refuses the certificate under a root key that is not the network's`() {
        val wrongRoot = IcBlsPublicKey.MAINNET_ROOT_KEY_RAW.copyOf()
        wrongRoot[0] = (wrongRoot[0].toInt() xor 0x01).toByte()

        val result = CertificateVerifier(MiraclBls, wrongRoot).verify(live, canisterId)
        assertIs<CertificateVerification.Invalid>(result)
    }

    @Test
    fun `refuses a delegation that delegates again`() {
        val outer = Certificate.fromCbor(live)
        val delegation = requireNotNull(outer.delegation)
        val nested = Certificate.fromCbor(delegation.certificate)
        val innerBytes = CertificateFixtures.certificate(
            nested.tree,
            nested.signature,
            CertificateFixtures.delegation(delegation.subnetId, delegation.certificate),
        )
        val bytes = CertificateFixtures.certificate(
            outer.tree,
            outer.signature,
            CertificateFixtures.delegation(delegation.subnetId, innerBytes),
        )

        val result = CertificateVerifier(alwaysValid).verify(bytes, canisterId)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("delegates again" in invalid.reason, invalid.reason)
    }

    @Test
    fun `refuses a delegation with no subnet public key`() {
        val delegation = requireNotNull(Certificate.fromCbor(live).delegation)
        val pruned = CertificateFixtures.pruneAt(
            Certificate.fromCbor(delegation.certificate).tree,
            listOf("subnet".toByteArray(), delegation.subnetId, "public_key".toByteArray()),
        )

        val result = CertificateVerifier(alwaysValid).verify(rebuilt { pruned }, canisterId)
        val invalid = assertIs<CertificateVerification.Invalid>(result)
        assertTrue("subnet public key" in invalid.reason, invalid.reason)
    }

    /** Rebuilds the live certificate with [editDelegationTree] applied to the delegation's tree. */
    private fun rebuilt(editDelegationTree: (HashTree) -> HashTree): ByteArray {
        val outer = Certificate.fromCbor(live)
        val delegation = requireNotNull(outer.delegation)
        val inner = Certificate.fromCbor(delegation.certificate)
        val innerBytes = CertificateFixtures.certificate(
            editDelegationTree(inner.tree),
            inner.signature,
        )
        return CertificateFixtures.certificate(
            outer.tree,
            outer.signature,
            CertificateFixtures.delegation(delegation.subnetId, innerBytes),
        )
    }

    private fun reasonOf(result: CertificateVerification): String =
        (result as? CertificateVerification.Invalid)?.reason ?: "valid"

    /** Reaches branches that sit behind a signature this test cannot produce. */
    private val alwaysValid = BlsSignatureVerifier { _, _, _ -> true }
}
