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
import io.github.yasumorishima.icrc167.certificate.lookupPath
import io.github.yasumorishima.icrc167.systemNanos
import java.math.BigInteger

/** Whether a query response really came from a node allowed to answer for that subnet. */
public sealed interface ResponseVerification {
    /** Every signature the response carried verified. */
    public class Valid(public val signatures: List<NodeSignature>) : ResponseVerification

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
 * The certificate has to come from a separate read_state, by design: an answer cannot
 * certify itself.
 *
 * Recency is part of the check and not an afterthought: without it a captured answer replays
 * for ever and a stale certificate keeps a rotated-out node authoritative. The specification
 * leaves the windows to the client and says what is reasonable -- five minutes for the
 * signatures and the certificate, matching the ingress expiry mainnet enforces, and **at
 * least a week** for a delegation, because mainnet only refreshes those when replicas are
 * upgraded. Hence two windows. Measured on 2026-09-10, live delegations were 37 to 204
 * seconds old, so five minutes would have started refusing honest answers within the hour.
 */
public class QueryResponseVerifier(
    private val certificates: CertificateVerifier,
    private val nodeSignatures: SignatureVerifier,
    private val maxAge: BigInteger = FIVE_MINUTES,
    private val maxDelegationAge: BigInteger = ONE_WEEK,
    private val rootSubnetId: Principal? = MAINNET_ROOT_SUBNET,
    private val clock: () -> BigInteger = { systemNanos() },
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
        val certificate = Certificate.fromCbor(subnetCertificate)
        val subnetId = when (val delegation = certificate.delegation) {
            // A delegated certificate names its subnet, and CertificateVerifier has already
            // held that subnet to the canister ranges the root gave it.
            null -> {
                // An undelegated one names nothing, and the root state tree carries the node
                // keys of every subnet -- so without this the answer could be signed by a
                // node of any subnet at all. Pruning is free, so choosing the one label left
                // standing would be choosing whatever the sender wanted.
                val root = rootSubnetId
                    ?: return ResponseVerification.Invalid(
                        "this certificate has no delegation and no root subnet id was configured",
                    )
                when (val ranges = tree.lookupPath(listOf(SUBNET, root.bytes, CANISTER_RANGES))) {
                    is Lookup.Found ->
                        if (!coversCanister(ranges.value, canisterId.bytes)) {
                            return ResponseVerification.Invalid(
                                "the root subnet does not cover " + canisterId.toText(),
                            )
                        }
                    else ->
                        return ResponseVerification.Invalid(
                            "the certificate does not carry the canister ranges of the root subnet",
                        )
                }
                root.bytes
            }
            else -> delegation.subnetId
        }

        val now = clock()
        certificateTime(tree)?.let { stamped ->
            if (!fresh(stamped, now)) {
                return ResponseVerification.Invalid("the certificate is not recent enough")
            }
        } ?: return ResponseVerification.Invalid("the certificate carries no time")
        certificate.delegation?.let { delegation ->
            val inner = Certificate.fromCbor(delegation.certificate)
            val stamped = certificateTime(inner.tree)
                ?: return ResponseVerification.Invalid("the delegation carries no time")
            // A week, not five minutes: mainnet refreshes a delegation only when replicas are
            // upgraded, so a delegation minutes old is the exception and not the rule.
            if (!fresh(stamped, now, maxDelegationAge)) {
                return ResponseVerification.Invalid("the delegation is not recent enough")
            }
        }

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
            if (!fresh(signature.timestamp, now)) {
                return ResponseVerification.Invalid("a signature is not recent enough")
            }
            val der = when (val key = tree.lookupPath(
                listOf(SUBNET, subnetId, NODE, signature.nodeId.bytes, PUBLIC_KEY),
            )) {
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
        return ResponseVerification.Valid(signatures)
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

    /** Skew in either direction is bounded: a timestamp from the future is not fresher. */
    private fun fresh(nanos: BigInteger, now: BigInteger, window: BigInteger = maxAge): Boolean =
        (now - nanos).abs() <= window

    private fun certificateTime(tree: HashTree): BigInteger? =
        when (val found = tree.lookupPath(listOf(TIME))) {
            is Lookup.Found -> decodeLeb128(found.value)
            else -> null
        }

    /**
     * The time leaf is a LEB128 nat, the same encoding the request id hash uses.
     *
     * Trailing bytes are refused by *position*, not by value: comparing the terminating byte
     * to the last byte lets 01 02 01 decode as 1, because the two are equal as numbers.
     */
    internal fun decodeLeb128(bytes: ByteArray): BigInteger? {
        var result = BigInteger.ZERO
        var shift = 0
        for ((index, byte) in bytes.withIndex()) {
            val value = byte.toInt() and 0x7F
            result = result.or(BigInteger.valueOf(value.toLong()).shiftLeft(shift))
            if (byte.toInt() and 0x80 == 0) {
                return if (index == bytes.lastIndex) result else null
            }
            shift += 7
            if (shift > 140) return null
        }
        return null
    }

    /** Ranges are tagged<[[start, end]]>, inclusive at both ends, ordered as unsigned bytes. */
    private fun coversCanister(blob: ByteArray, canisterId: ByteArray): Boolean {
        val items = (AgentCbor.untag(AgentCbor.decode(blob)) as? CborItem.Arr)?.items ?: return false
        return items.any { item ->
            val pair = (item as? CborItem.Arr)?.items ?: return false
            if (pair.size != 2) return false
            val start = (pair[0] as? CborItem.Blob)?.bytes ?: return false
            val end = (pair[1] as? CborItem.Blob)?.bytes ?: return false
            compareUnsigned(start, canisterId) <= 0 && compareUnsigned(canisterId, end) <= 0
        }
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        val shared = minOf(a.size, b.size)
        for (i in 0 until shared) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }

    public companion object {
        /**
         * The byte 0x0B followed by ic-response. The leading byte is the length of the string
         * that follows, per the domain separator convention in the specification.
         */
        public val RESPONSE_DOMAIN_SEPARATOR: ByteArray
            get() = byteArrayOf(0x0B) + "ic-response".toByteArray(Charsets.UTF_8)

        /** What the specification calls reasonable for a signature and a certificate. */
        public val FIVE_MINUTES: BigInteger = BigInteger.valueOf(5L * 60 * 1_000_000_000L)

        /** The floor the specification names for a delegation, which mainnet refreshes weekly. */
        public val ONE_WEEK: BigInteger = BigInteger.valueOf(7L * 24 * 60 * 60 * 1_000_000_000L)

        /**
         * The subnet an undelegated certificate speaks for.
         *
         * Derived rather than remembered: an undelegated certificate fetched on 2026-09-10
         * for the NNS ledger carries canister_ranges for exactly one subnet, and those ranges
         * contain that canister.
         */
        public val MAINNET_ROOT_SUBNET: Principal =
            Principal.fromText("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")

        private val SUBNET = "subnet".toByteArray(Charsets.UTF_8)
        private val NODE = "node".toByteArray(Charsets.UTF_8)
        private val PUBLIC_KEY = "public_key".toByteArray(Charsets.UTF_8)
        private val CANISTER_RANGES = "canister_ranges".toByteArray(Charsets.UTF_8)
        private val TIME = "time".toByteArray(Charsets.UTF_8)
    }
}
