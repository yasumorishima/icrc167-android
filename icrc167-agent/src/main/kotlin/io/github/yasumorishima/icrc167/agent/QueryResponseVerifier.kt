package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.ReprHash
import io.github.yasumorishima.icrc167.SignatureCheck
import io.github.yasumorishima.icrc167.SignatureVerifier
import io.github.yasumorishima.icrc167.certificate.Certificate
import io.github.yasumorishima.icrc167.certificate.CertificateVerification
import io.github.yasumorishima.icrc167.certificate.CertificateVerifier
import io.github.yasumorishima.icrc167.certificate.HashTree
import io.github.yasumorishima.icrc167.certificate.Lookup
import io.github.yasumorishima.icrc167.certificate.SubtreeLookup
import io.github.yasumorishima.icrc167.certificate.lookupPath
import io.github.yasumorishima.icrc167.certificate.lookupSubtree
import java.math.BigInteger

/** Whether a query response really came from a node allowed to answer for that subnet. */
public sealed interface ResponseVerification {
    public class Valid(
        public val timestamp: BigInteger,
        public val nodeId: Principal,
    ) : ResponseVerification

    public data class Invalid(public val reason: String) : ResponseVerification
}

/**
 * Checks the node signature a query response carries.
 *
 * Without this, a query answer is whatever replied: the principal in a whoami reply is a
 * string the boundary node could have written itself. The specification defines the check --
 * every signature in the response must verify, under the byte 0x0B followed by ic-response,
 * over a hash of the answer, the timestamp and the request id, using the public key of the
 * answering node read out of a certified subnet state tree.
 *
 * Two things this deliberately does not do. It does not bound the age of the signature: the
 * timestamp is handed back so a caller can decide what is too old, because the specification
 * names no window and a wrong one here would be worse than none. And it does not fetch the
 * certificate; that is a separate request by design, since an answer cannot certify itself.
 */
public class QueryResponseVerifier(
    private val certificates: CertificateVerifier,
    private val nodeSignatures: SignatureVerifier,
) {

    public fun verify(
        canisterId: Principal,
        exchange: QueryExchange,
        subnetCertificate: ByteArray,
    ): ResponseVerification {
        val tree = when (val checked = certificates.verify(subnetCertificate, canisterId.bytes)) {
            is CertificateVerification.Valid -> checked.tree
            is CertificateVerification.Invalid ->
                return ResponseVerification.Invalid("the subnet certificate: " + checked.reason)
        }
        val subnetId = subnetIdOf(subnetCertificate, tree)
            ?: return ResponseVerification.Invalid("the certificate does not name one subnet")

        val signatures = exchange.response.signatures
        if (signatures.isEmpty()) {
            // An answer nobody signed is an answer from nobody in particular.
            return ResponseVerification.Invalid("the response carries no signature")
        }

        val covered = try {
            coveredFields(exchange)
        } catch (e: IcAgentException) {
            return ResponseVerification.Invalid(e.message ?: "the response cannot be hashed")
        }

        // The specification quantifies over every signature, not over one of them.
        for (signature in signatures) {
            val key = tree.lookupPath(
                listOf(SUBNET, subnetId, NODE, signature.nodeId.bytes, PUBLIC_KEY),
            )
            val der = when (key) {
                is Lookup.Found -> key.value
                Lookup.Absent ->
                    return ResponseVerification.Invalid(
                        "the subnet does not have node " + signature.nodeId.toText(),
                    )
                Lookup.Unknown ->
                    return ResponseVerification.Invalid(
                        "the key of node " + signature.nodeId.toText() + " was pruned away",
                    )
                Lookup.Error ->
                    return ResponseVerification.Invalid("the certificate tree has the wrong shape")
            }
            val message = RESPONSE_DOMAIN_SEPARATOR + hashOf(covered, signature, exchange)
            when (nodeSignatures.verify(der, message, signature.signature)) {
                SignatureCheck.VALID -> Unit
                SignatureCheck.INVALID ->
                    return ResponseVerification.Invalid(
                        "node " + signature.nodeId.toText() + " did not sign this answer",
                    )
                SignatureCheck.UNSUPPORTED_KEY ->
                    return ResponseVerification.Invalid(
                        "the key of node " + signature.nodeId.toText() +
                            " is of a scheme this verifier does not have",
                    )
            }
        }
        return ResponseVerification.Valid(signatures[0].timestamp, signatures[0].nodeId)
    }

    /**
     * The answer, in the shape the signature covers.
     *
     * Named field by field rather than by hashing whatever came back: the specification lists
     * exactly these, so a field the replica adds later must not change the hash. The
     * error_code field is optional and is hashed when it is present -- measured against a
     * live rejection on 2026-09-10, which refuses the signature when it is left out.
     */
    private fun coveredFields(exchange: QueryExchange): Map<String, ReprHash.Value> {
        val body = exchange.response.body
        val fields = LinkedHashMap<String, ReprHash.Value>()
        val status = (body["status"] as? CborItem.Text)
            ?: throw IcAgentException("the response carries no status")
        fields["status"] = ReprHash.Value.Text(status.value)
        when (status.value) {
            "replied" ->
                fields["reply"] = (body["reply"] ?: throw IcAgentException("no reply")).toReprValue()
            "rejected" -> {
                fields["reject_code"] =
                    (body["reject_code"] ?: throw IcAgentException("no reject_code")).toReprValue()
                fields["reject_message"] =
                    (body["reject_message"] ?: throw IcAgentException("no reject_message")).toReprValue()
                body["error_code"]?.let { fields["error_code"] = it.toReprValue() }
            }
            else -> throw IcAgentException("unknown status: " + status.value)
        }
        return fields
    }

    /** The digest the signature covers. Internal so a test can pin it on its own. */
    internal fun coveredHash(exchange: QueryExchange, signature: NodeSignature): ByteArray =
        hashOf(coveredFields(exchange), signature, exchange)

    private fun hashOf(
        covered: Map<String, ReprHash.Value>,
        signature: NodeSignature,
        exchange: QueryExchange,
    ): ByteArray = ReprHash.ofMap(
        covered + mapOf(
            "timestamp" to ReprHash.Value.Nat(signature.timestamp),
            "request_id" to ReprHash.Value.Blob(exchange.request.requestId),
        ),
    )

    private fun subnetIdOf(certificateCbor: ByteArray, tree: HashTree): ByteArray? {
        val delegated = Certificate.fromCbor(certificateCbor).delegation?.subnetId
        if (delegated != null) return delegated
        // A canister on the root subnet gets an undelegated certificate, which names no
        // subnet. The tree then has to name exactly one, or there is nothing to choose by.
        val subtree = subtreeAt(tree, listOf(SUBNET)) ?: return null
        return labelsOf(subtree).singleOrNull()
    }

    private fun subtreeAt(tree: HashTree, path: List<ByteArray>): HashTree? =
        when (val found = tree.lookupSubtree(path)) {
            is SubtreeLookup.Found -> found.subtree
            SubtreeLookup.Absent, SubtreeLookup.Unknown -> null
        }

    private fun labelsOf(tree: HashTree): List<ByteArray> = when (tree) {
        is HashTree.Labeled -> listOf(tree.label)
        is HashTree.Fork -> labelsOf(tree.left) + labelsOf(tree.right)
        else -> emptyList()
    }

    public companion object {
        /**
         * The byte 0x0B followed by ic-response. The leading byte is the length of the string
         * that follows, per the domain separator convention in the specification.
         */
        public val RESPONSE_DOMAIN_SEPARATOR: ByteArray
            get() = byteArrayOf(0x0B) + "ic-response".toByteArray(Charsets.UTF_8)

        private val SUBNET = "subnet".toByteArray(Charsets.UTF_8)
        private val NODE = "node".toByteArray(Charsets.UTF_8)
        private val PUBLIC_KEY = "public_key".toByteArray(Charsets.UTF_8)
    }
}
