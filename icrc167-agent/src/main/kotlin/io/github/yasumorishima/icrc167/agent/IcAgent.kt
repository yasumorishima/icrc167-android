package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.ReprHash
import io.github.yasumorishima.icrc167.SignedDelegation
import io.github.yasumorishima.icrc167.systemNanos
import java.math.BigInteger

/** A request as it goes on the wire, next to the id its signature covers. */
public class SignedRequest(requestId: ByteArray, body: ByteArray) {
    private val idBytes = requestId.copyOf()
    private val bodyBytes = body.copyOf()

    public val requestId: ByteArray get() = idBytes.copyOf()
    public val body: ByteArray get() = bodyBytes.copyOf()
}

/** What a canister answered a query with. */
public sealed interface QueryReply {
    public class Replied(arg: ByteArray) : QueryReply {
        private val argBytes = arg.copyOf()
        public val arg: ByteArray get() = argBytes.copyOf()
    }

    public class Rejected(
        public val rejectCode: BigInteger,
        public val message: String,
        public val errorCode: String?,
    ) : QueryReply
}

/** One node's signature over a query response. */
public class NodeSignature(
    public val timestamp: BigInteger,
    signature: ByteArray,
    public val nodeId: Principal,
) {
    private val signatureBytes = signature.copyOf()
    public val signature: ByteArray get() = signatureBytes.copyOf()
}

/**
 * A parsed query response, including what it takes to check it.
 *
 * [body] is kept because the signature covers a hash of the response *as sent*: rebuilding
 * that map from the parsed fields would mean hashing this library's idea of the answer rather
 * than the answer.
 */
public class QueryResponse internal constructor(
    public val reply: QueryReply,
    public val signatures: List<NodeSignature>,
    internal val body: Map<String, CborItem>,
)

/** A request and the answer it got, kept together because verifying needs both. */
public class QueryExchange(
    public val request: SignedRequest,
    public val response: QueryResponse,
)

public class IcAgentException(message: String) : RuntimeException(message)

public class HttpResponse(public val status: Int, body: ByteArray) {
    private val bodyBytes = body.copyOf()
    public val body: ByteArray get() = bodyBytes.copyOf()
}

/** Everything the agent needs from the network, so a test can stand in for it. */
public fun interface Transport {
    public fun post(url: String, body: ByteArray): HttpResponse
}

/**
 * Calls a canister as [Identity].
 *
 * This sends the request and reads the answer. It does not decide whether the answer is
 * trustworthy: a query response carries a node signature, and checking that is
 * [QueryResponseVerifier]'s job, with the subnet certificate [subnetCertificate] fetches.
 * Nothing here refuses an unsigned or wrongly signed answer, so a caller that skips the
 * verifier is trusting whatever replied.
 */
public class IcAgent(
    private val host: String = MAINNET,
    private val transport: Transport = JdkTransport(),
    private val ingressExpiry: BigInteger = FOUR_MINUTES,
    private val apiVersion: String = CURRENT_API_VERSION,
    private val clock: () -> BigInteger = { systemNanos() },
) {

    /** Builds the query request without sending it. Exposed so its bytes can be measured. */
    public fun queryRequest(
        canisterId: Principal,
        method: String,
        arg: ByteArray,
        identity: Identity,
        expiryNanos: BigInteger = clock() + ingressExpiry,
    ): SignedRequest = signedRequest(
        CborItem.Dict(
            listOf(
                text("request_type") to text("query"),
                text("sender") to blob(identity.sender.bytes),
                text("canister_id") to blob(canisterId.bytes),
                text("method_name") to text(method),
                text("arg") to blob(arg),
                text("ingress_expiry") to CborItem.Uint(expiryNanos),
            ),
        ),
        identity,
    )

    /**
     * Builds a `read_state` request.
     *
     * The canister id is in the URL and not in the content, which is not an oversight: the
     * specification puts the effective canister id in the path for this endpoint.
     */
    public fun readStateRequest(
        paths: List<List<ByteArray>>,
        identity: Identity,
        expiryNanos: BigInteger = clock() + ingressExpiry,
    ): SignedRequest = signedRequest(
        CborItem.Dict(
            listOf(
                text("request_type") to text("read_state"),
                text("sender") to blob(identity.sender.bytes),
                text("paths") to CborItem.Arr(
                    paths.map { path -> CborItem.Arr(path.map { blob(it) }) },
                ),
                text("ingress_expiry") to CborItem.Uint(expiryNanos),
            ),
        ),
        identity,
    )

    private fun signedRequest(content: CborItem.Dict, identity: Identity): SignedRequest {
        // One source for both maps. The request id has to hash exactly what goes on the wire,
        // and a second hand-written copy of the same fields is how that quietly stops being
        // true.
        val requestId = ReprHash.ofMap(content.toReprFields())
        val envelope = ArrayList<Pair<CborItem, CborItem>>()
        envelope.add(text("content") to content)
        val auth = identity.authenticate(requestId)
        if (auth != null) {
            envelope.add(text("sender_pubkey") to blob(auth.senderPublicKey))
            envelope.add(text("sender_sig") to blob(auth.signature))
            if (auth.delegations.isNotEmpty()) {
                envelope.add(text("sender_delegation") to CborItem.Arr(auth.delegations.map(::encodeDelegation)))
            }
        }
        return SignedRequest(requestId, AgentCbor.encode(CborItem.Dict(envelope)))
    }

    /** Sends a query and returns the request and the answer together. */
    public fun exchange(
        canisterId: Principal,
        method: String,
        arg: ByteArray,
        identity: Identity,
    ): QueryExchange {
        val request = queryRequest(canisterId, method, arg, identity)
        val body = send("canister/" + canisterId.toText() + "/query", request.body)
        return QueryExchange(request, parseResponse(body))
    }

    /** Sends a query and returns whatever the canister answered, unchecked. */
    public fun query(
        canisterId: Principal,
        method: String,
        arg: ByteArray,
        identity: Identity,
    ): QueryReply = exchange(canisterId, method, arg, identity).response.reply

    /**
     * Fetches the certificate that proves which nodes may speak for the subnet [canisterId]
     * lives on, which is what a response signature is checked against.
     *
     * The specification requires this to be a separate request: the answer being checked
     * cannot also carry the thing that certifies it.
     */
    public fun subnetCertificate(
        canisterId: Principal,
        identity: Identity = AnonymousIdentity,
    ): ByteArray {
        val request = readStateRequest(listOf(listOf(SUBNET_LABEL)), identity)
        val body = send("canister/" + canisterId.toText() + "/read_state", request.body)
        val fields = AgentCbor.textMap(AgentCbor.untag(AgentCbor.decode(body)))
            ?: throw IcAgentException("the read_state answer is not a map with text keys")
        return (fields["certificate"] as? CborItem.Blob)?.bytes
            ?: throw IcAgentException("the read_state answer carries no certificate")
    }

    /**
     * Asks a canister which principal it attributes the call to.
     *
     * The canister has to export whoami as a query returning a principal. The one DFINITY
     * runs at kvusz-kaaaa-aaaad-aabwa-cai does. The answer is not checked -- see the class
     * comment, and [verifiedWhoami].
     */
    public fun whoami(canisterId: Principal, identity: Identity): Principal =
        principalOf(query(canisterId, "whoami", Candid.EMPTY_ARGS, identity))

    /** [whoami], with the node signature checked against the subnet certificate. */
    public fun verifiedWhoami(
        canisterId: Principal,
        identity: Identity,
        verifier: QueryResponseVerifier,
    ): Principal {
        val exchange = exchange(canisterId, "whoami", Candid.EMPTY_ARGS, identity)
        val certificate = subnetCertificate(canisterId)
        val check = verifier.verify(canisterId, exchange, certificate)
        if (check is ResponseVerification.Invalid) {
            throw IcAgentException("the answer is not signed for this subnet: " + check.reason)
        }
        return principalOf(exchange.response.reply)
    }

    private fun principalOf(reply: QueryReply): Principal = when (reply) {
        is QueryReply.Replied -> Candid.decodePrincipal(reply.arg)
        is QueryReply.Rejected ->
            throw IcAgentException("whoami was rejected (" + reply.rejectCode + "): " + reply.message)
    }

    private fun send(path: String, body: ByteArray): ByteArray {
        val url = host + "/api/" + apiVersion + "/" + path
        val response = transport.post(url, body)
        if (response.status != 200) {
            // The replica answers a malformed or badly signed request with plain text, and
            // it names what it disliked. Passing that through is the difference between a
            // fixable failure and a silent one.
            throw IcAgentException(
                "the replica answered " + response.status + ": " + describe(response.body),
            )
        }
        return response.body
    }

    /** Parses a query response body. Public so recorded answers can be replayed against it. */
    public fun parseResponse(bytes: ByteArray): QueryResponse {
        val body = AgentCbor.textMap(AgentCbor.untag(AgentCbor.decode(bytes)))
            ?: throw IcAgentException("the reply is not a map with text keys")
        val status = (body["status"] as? CborItem.Text)?.value
            ?: throw IcAgentException("the reply carries no status")
        val reply = when (status) {
            "replied" -> {
                val replied = AgentCbor.textMap(
                    body["reply"] ?: throw IcAgentException("replied without a reply"),
                ) ?: throw IcAgentException("the reply field is not a map")
                val arg = (replied["arg"] as? CborItem.Blob)?.bytes
                    ?: throw IcAgentException("the reply carries no arg blob")
                QueryReply.Replied(arg)
            }
            "rejected" -> QueryReply.Rejected(
                rejectCode = (body["reject_code"] as? CborItem.Uint)?.value
                    ?: throw IcAgentException("a rejection without a reject_code"),
                // Required by the specification. An empty default here would turn a
                // malformed rejection into a plausible-looking one.
                message = (body["reject_message"] as? CborItem.Text)?.value
                    ?: throw IcAgentException("a rejection without a reject_message"),
                errorCode = (body["error_code"] as? CborItem.Text)?.value,
            )
            else -> throw IcAgentException("unknown status: " + status)
        }
        return QueryResponse(reply, parseSignatures(body["signatures"]), body)
    }

    /** [parseResponse], keeping only the answer. */
    public fun parseReply(bytes: ByteArray): QueryReply = parseResponse(bytes).reply

    private fun parseSignatures(item: CborItem?): List<NodeSignature> {
        if (item == null) return emptyList()
        val entries = (item as? CborItem.Arr)?.items
            ?: throw IcAgentException("signatures is not an array")
        return entries.map { entry ->
            val fields = AgentCbor.textMap(entry)
                ?: throw IcAgentException("a signature entry is not a map with text keys")
            NodeSignature(
                timestamp = (fields["timestamp"] as? CborItem.Uint)?.value
                    ?: throw IcAgentException("a signature without a timestamp"),
                signature = (fields["signature"] as? CborItem.Blob)?.bytes
                    ?: throw IcAgentException("a signature without a signature"),
                nodeId = Principal.ofBytes(
                    (fields["identity"] as? CborItem.Blob)?.bytes
                        ?: throw IcAgentException("a signature without an identity"),
                ),
            )
        }
    }

    private fun encodeDelegation(signed: SignedDelegation): CborItem {
        val delegation = signed.delegation
        val fields = ArrayList<Pair<CborItem, CborItem>>()
        fields.add(text("pubkey") to blob(delegation.pubkey))
        fields.add(text("expiration") to CborItem.Uint(delegation.expiration))
        // Absent, not empty, when the delegation is unscoped: the signature was made over a
        // map without the field, so putting an empty array here would invalidate it.
        delegation.targets?.let { targets ->
            fields.add(text("targets") to CborItem.Arr(targets.map { blob(it.bytes) }))
        }
        return CborItem.Dict(
            listOf(
                text("delegation") to CborItem.Dict(fields),
                text("signature") to blob(signed.signature),
            ),
        )
    }

    private fun text(value: String): CborItem = CborItem.Text(value)

    private fun blob(value: ByteArray): CborItem = CborItem.Blob(value)

    private fun describe(body: ByteArray): String =
        String(body, Charsets.UTF_8).filter { it.code in 32..126 }.take(500)

    public companion object {
        /** The public API boundary node. */
        public const val MAINNET: String = "https://icp-api.io"

        /**
         * The v2 query path still answers -- measured on 2026-09-10 -- but the interface
         * specification marks it deprecated in favour of v3.
         */
        public const val CURRENT_API_VERSION: String = "v3"

        public val FOUR_MINUTES: BigInteger = BigInteger.valueOf(4L * 60 * 1_000_000_000L)

        internal val SUBNET_LABEL: ByteArray = "subnet".toByteArray(Charsets.UTF_8)
    }
}
